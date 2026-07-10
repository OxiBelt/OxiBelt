//! Cross-worker shared state containers.
//! Optional backends are hidden behind stable runtime handles so callers keep the same semantics.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Pool, Postgres};
use tokio::io::BufReader;
use tokio::net::TcpStream;
use tracing::warn;
use url::Url;

use crate::config::{Config, DatabaseTlsMode, SharedStateBackendConfig, SharedStateBackendKind};
use crate::limits::ParsedRate;
use crate::metrics::Metrics;

mod cache_store;
mod feature_flags;
mod person_proof;
mod rate_limits;
mod redis_protocol;
mod runtime;
mod sticky_sessions;

use redis_protocol::{Resp, expect_ok, read_resp, write_resp_command};
use runtime::{BackendRuntime, CleanupDispatcher};

pub use cache_store::{SharedCacheLock, shared_header_values};
pub use person_proof::{
  PersonProofSharedClearance, PersonProofSharedClearancePage, PersonProofSharedStatus,
};

#[derive(Clone, Debug)]
pub struct SharedState {
  namespace: Arc<str>,
  instance_id: Arc<str>,
  connection_lease: Duration,
  cache_lock: Duration,
  cache_chunk_bytes: usize,
  rate_limits: Option<Arc<Backend>>,
  connection_limits: Option<Arc<Backend>>,
  person_proof: Option<Arc<Backend>>,
  upstream_health: Option<Arc<Backend>>,
  sticky_sessions: Option<Arc<Backend>>,
  cache: Option<Arc<Backend>>,
  reload: Option<Arc<Backend>>,
  cleanup: Arc<CleanupDispatcher>,
}

#[derive(Clone, Debug)]
enum Backend {
  Redis(RedisBackend),
  Postgres(PostgresBackend),
  #[cfg(test)]
  Memory(MemoryBackend),
}

#[derive(Clone, Debug)]
struct RedisBackend {
  url: Url,
  runtime: BackendRuntime,
}

#[derive(Clone, Debug)]
struct PostgresBackend {
  pool: Pool<Postgres>,
  runtime: BackendRuntime,
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct MemoryBackend {
  values: Arc<Mutex<HashMap<String, MemoryValue>>>,
  counters: Arc<Mutex<HashMap<String, MemoryCounter>>>,
  rate_indexes: Arc<Mutex<HashMap<String, HashMap<String, i64>>>>,
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct MemoryValue {
  value: Vec<u8>,
  expires_at_ms: Option<i64>,
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct MemoryCounter {
  counter: i64,
  expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
pub struct ConnectionScope<'a> {
  pub key: &'a str,
  pub limit: usize,
  pub status: StatusCode,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SharedRateLimitOutcome {
  Allowed,
  RateLimited,
  BucketCapExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedCacheEntry {
  pub policy: String,
  #[serde(default)]
  pub partition: String,
  pub base_key: String,
  pub variant_key: String,
  pub scheme: String,
  pub host: String,
  pub uri: String,
  pub status: u16,
  pub headers: Vec<(String, Vec<u8>)>,
  #[serde(default)]
  pub security_headers_neutral: bool,
  #[serde(default)]
  pub body: Vec<u8>,
  #[serde(default)]
  pub body_len: usize,
  #[serde(default)]
  pub body_chunks: Vec<String>,
  #[serde(default = "shared_cache_entry_now_ms")]
  pub stored_at_ms: i64,
  pub expires_at_ms: i64,
  pub stale_if_error_until_ms: Option<i64>,
  pub stale_while_revalidate_until_ms: Option<i64>,
  pub must_revalidate: bool,
  pub vary: Vec<SharedVaryMatcher>,
  #[serde(default)]
  pub tags: Vec<String>,
}

fn shared_cache_entry_now_ms() -> i64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
    .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedVaryMatcher {
  pub name: String,
  pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HealthRecord {
  healthy: bool,
  consecutive_successes: u32,
  consecutive_failures: u32,
}

impl Default for HealthRecord {
  fn default() -> Self {
    Self {
      healthy: true,
      consecutive_successes: 0,
      consecutive_failures: 0,
    }
  }
}

impl SharedState {
  pub async fn new(config: &Config, metrics: Arc<Metrics>) -> anyhow::Result<Option<Arc<Self>>> {
    let shared = &config.shared_state;
    if !shared.enabled {
      return Ok(None);
    }

    metrics.configure_shared_state_metrics(&config.metrics.histogram_buckets_ms);

    let mut backends = HashMap::new();
    for backend in &shared.backends {
      let name = backend.name.clone();
      let built = Backend::connect(backend, shared.operation_timeout_ms, metrics.clone()).await?;
      backends.insert(name, Arc::new(built));
    }

    let default = shared
      .default_backend
      .as_deref()
      .or_else(|| shared.backends.first().map(|backend| backend.name.as_str()));
    let pick = |feature: &Option<String>| -> Option<Arc<Backend>> {
      feature
        .as_deref()
        .or(default)
        .and_then(|name| backends.get(name).cloned())
    };
    let instance_id = std::env::var(&shared.instance_id_env)
      .ok()
      .filter(|value| !value.trim().is_empty())
      .unwrap_or_else(|| format!("{}-{}", std::process::id(), now_unix_ms()));
    let state = Arc::new(Self {
      namespace: Arc::from(shared.namespace.as_str()),
      instance_id: Arc::from(instance_id),
      connection_lease: Duration::from_millis(shared.connection_lease_ms),
      cache_lock: Duration::from_millis(shared.cache_lock_ms),
      cache_chunk_bytes: config.cache.stream_chunk_bytes,
      rate_limits: pick(&shared.rate_limits_backend),
      connection_limits: pick(&shared.connection_limits_backend),
      person_proof: pick(&shared.person_proof_backend),
      upstream_health: pick(&shared.upstream_health_backend),
      sticky_sessions: pick(&shared.sticky_sessions_backend),
      cache: pick(&shared.cache_backend),
      reload: pick(&shared.reload_backend),
      cleanup: CleanupDispatcher::new(),
    });
    state.record_reload_generation(config).await;
    Ok(Some(state))
  }

  #[cfg(test)]
  pub fn test_memory(namespace: &str) -> Arc<Self> {
    let backend = Arc::new(Backend::Memory(MemoryBackend::default()));
    Arc::new(Self {
      namespace: Arc::from(namespace),
      instance_id: Arc::from("test-instance"),
      connection_lease: Duration::from_secs(30),
      cache_lock: Duration::from_secs(5),
      cache_chunk_bytes: 1_048_576,
      rate_limits: Some(backend.clone()),
      connection_limits: Some(backend.clone()),
      person_proof: Some(backend.clone()),
      upstream_health: Some(backend.clone()),
      sticky_sessions: Some(backend.clone()),
      cache: Some(backend.clone()),
      reload: Some(backend),
      cleanup: CleanupDispatcher::new(),
    })
  }

  #[cfg(test)]
  pub fn test_cache_raw_keys(&self, suffix_prefix: &str) -> Vec<String> {
    let Some(Backend::Memory(memory)) = self.cache.as_deref() else {
      return Vec::new();
    };
    memory
      .raw_entries(&self.key(suffix_prefix))
      .unwrap_or_default()
      .into_iter()
      .map(|(key, _)| key)
      .collect()
  }

  #[cfg(test)]
  pub fn test_delete_raw_key(&self, key: &str) {
    if let Some(Backend::Memory(memory)) = self.cache.as_deref() {
      let _ = memory.delete(key);
    }
  }

  pub fn instance_id(&self) -> &str {
    &self.instance_id
  }

  pub async fn take_rate_token(
    &self,
    name: &str,
    key: &str,
    rate: ParsedRate,
    burst: u32,
    max_buckets: usize,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    let Some(backend) = &self.rate_limits else {
      return Ok(SharedRateLimitOutcome::Allowed);
    };
    let bucket_key = self.key(&format!("rate:{name}:{key}"));
    let index_key = self.key(&format!("rate-index:{name}"));
    backend
      .rate_take(
        &index_key,
        &bucket_key,
        rate.per_second(),
        burst.max(1),
        max_buckets.max(1),
        rate_bucket_ttl(rate, burst),
      )
      .await
  }

  pub async fn take_rate_token_bucket(
    &self,
    bucket: &str,
    rate: ParsedRate,
    burst: u32,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    let Some(backend) = &self.rate_limits else {
      return Ok(SharedRateLimitOutcome::Allowed);
    };
    let key = self.key(&format!("rate:{bucket}"));
    backend
      .rate_take_bucket(
        &key,
        rate.per_second(),
        burst.max(1),
        rate_bucket_ttl(rate, burst),
      )
      .await
  }

  pub async fn acquire_connections(
    &self,
    scopes: &[ConnectionScope<'_>],
  ) -> anyhow::Result<Option<StatusCode>> {
    let Some(backend) = &self.connection_limits else {
      return Ok(None);
    };
    let keys = scopes
      .iter()
      .map(|scope| self.key(&format!("conn:{}", scope.key)))
      .collect::<Vec<_>>();
    let limits = scopes.iter().map(|scope| scope.limit).collect::<Vec<_>>();
    let denied = backend
      .connection_acquire(&keys, &limits, self.connection_lease)
      .await?;
    Ok(denied.map(|index| scopes[index].status))
  }

  pub async fn release_connections(&self, scopes: &[String]) {
    let Some(backend) = &self.connection_limits else {
      return;
    };
    let keys = scopes
      .iter()
      .map(|scope| self.key(&format!("conn:{scope}")))
      .collect::<Vec<_>>();
    if let Err(error) = backend.connection_release(&keys).await {
      warn!(error = %error, "failed to release shared connection limits");
    }
  }

  pub async fn pool_health(&self, upstream_name: &str) -> anyhow::Result<Option<bool>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:health:{upstream_name}"));
    Ok(backend.health_get(&key).await?.map(|record| record.healthy))
  }

  pub async fn pool_report(
    &self,
    upstream_name: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<Option<bool>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:health:{upstream_name}"));
    Ok(Some(
      backend
        .health_report(
          &key,
          success,
          enabled,
          healthy_threshold,
          unhealthy_threshold,
        )
        .await?,
    ))
  }

  pub async fn pool_active(&self, upstream_name: &str) -> anyhow::Result<Option<usize>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:active:{upstream_name}"));
    Ok(Some(backend.counter_get(&key).await?))
  }

  pub async fn pool_active_add(
    &self,
    upstream_name: &str,
    delta: i64,
  ) -> anyhow::Result<Option<usize>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:active:{upstream_name}"));
    Ok(Some(
      backend
        .counter_add(&key, delta, Some(self.connection_lease))
        .await?,
    ))
  }

  pub async fn record_reload_generation(&self, config: &Config) {
    let Some(backend) = &self.reload else {
      return;
    };
    let key = self.key(&format!("reload:instance:{}", self.instance_id));
    let hash = config_hash(config);
    let value = format!("{}:{}", now_unix_ms(), hash);
    if let Err(error) = backend
      .put(&key, value.as_bytes(), Some(Duration::from_secs(300)))
      .await
    {
      warn!(error = %error, "failed to write shared reload generation heartbeat");
    }
  }

  pub(crate) fn defer_connection_release(&self, scopes: &[String]) {
    let Some(backend) = &self.connection_limits else {
      return;
    };
    let keys = scopes
      .iter()
      .map(|scope| self.key(&format!("conn:{scope}")))
      .collect();
    self.cleanup.defer_connection_release(backend.clone(), keys);
  }

  pub(crate) fn defer_pool_active_add(&self, upstream_name: &str, delta: i64) {
    let Some(backend) = &self.upstream_health else {
      return;
    };
    self.cleanup.defer_counter_add(
      backend.clone(),
      self.key(&format!("pool:active:{upstream_name}")),
      delta,
      Some(self.connection_lease),
    );
  }

  fn key(&self, suffix: &str) -> String {
    format!("{}:{suffix}", self.namespace)
  }
}

impl Backend {
  async fn connect(
    config: &SharedStateBackendConfig,
    timeout_ms: u64,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    let operation_timeout = Duration::from_millis(timeout_ms);
    match config.kind {
      SharedStateBackendKind::Redis => {
        let url = Url::parse(
          &config.connection_url_with_prefix(&format!("shared_state.backends.{}", config.name))?,
        )
        .with_context(|| format!("failed to parse shared_state Redis URL {}", config.name))?;
        Ok(Self::Redis(RedisBackend {
          url,
          runtime: BackendRuntime::new(config, "redis", operation_timeout, metrics),
        }))
      }
      SharedStateBackendKind::Postgres => {
        let connection_url =
          config.connection_url_with_prefix(&format!("shared_state.backends.{}", config.name))?;
        let runtime = BackendRuntime::new(config, "postgres", operation_timeout, metrics);
        let pool = runtime
          .connect(|| connect_postgres_pool(config, &connection_url, runtime.connect_timeout))
          .await
          .with_context(|| {
            format!(
              "failed to connect shared_state PostgreSQL backend {}",
              config.name
            )
          })?;
        runtime.execute("startup", || init_postgres(&pool)).await?;
        Ok(Self::Postgres(PostgresBackend { pool, runtime }))
      }
    }
  }

  fn runtime(&self) -> Option<&BackendRuntime> {
    match self {
      Self::Redis(redis) => Some(&redis.runtime),
      Self::Postgres(postgres) => Some(&postgres.runtime),
      #[cfg(test)]
      Self::Memory(_) => None,
    }
  }

  fn operation_timeout(&self) -> Option<Duration> {
    self.runtime().map(|runtime| runtime.operation_timeout)
  }

  fn record_cleanup_drop(&self) {
    if let Some(runtime) = self.runtime() {
      runtime
        .metrics
        .record_shared_state_deferred_cleanup_dropped(runtime.name.as_ref(), runtime.kind);
    }
  }

  async fn rate_take(
    &self,
    limit_name: &str,
    key: &str,
    rate_per_second: f64,
    burst: u32,
    max_buckets: usize,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("rate_limit", || {
            redis.rate_take(
              limit_name,
              key,
              rate_per_second,
              burst,
              max_buckets,
              bucket_ttl,
            )
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("rate_limit", || {
            pg.rate_take(
              limit_name,
              key,
              rate_per_second,
              burst,
              max_buckets,
              bucket_ttl,
            )
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.rate_take(
        limit_name,
        key,
        rate_per_second,
        burst,
        max_buckets,
        bucket_ttl,
      ),
    }
  }

  async fn rate_take_bucket(
    &self,
    key: &str,
    rate_per_second: f64,
    burst: u32,
    bucket_ttl: Duration,
  ) -> anyhow::Result<SharedRateLimitOutcome> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("rate_limit", || {
            redis.rate_take_bucket(key, rate_per_second, burst, bucket_ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("rate_limit", || {
            pg.rate_take_bucket(key, rate_per_second, burst, bucket_ttl)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.rate_take_bucket(key, rate_per_second, burst, bucket_ttl),
    }
  }

  async fn connection_acquire(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
  ) -> anyhow::Result<Option<usize>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("connection_acquire", || {
            redis.connection_acquire(keys, limits, ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("connection_acquire", || {
            pg.connection_acquire(keys, limits, ttl)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.connection_acquire(keys, limits, ttl),
    }
  }

  async fn connection_release(&self, keys: &[String]) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("connection_release", || redis.connection_release(keys))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("connection_release", || pg.connection_release(keys))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.connection_release(keys),
    }
  }

  async fn get_or_init_bytes(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_get_or_init", || {
            redis.get_or_init_bytes(key, len, ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_get_or_init", || pg.get_or_init_bytes(key, len, ttl))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.get_or_init_bytes(key, len, ttl),
    }
  }

  async fn put_if_absent(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_put_if_absent", || {
            redis.put_if_absent(key, value, ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_put_if_absent", || pg.put_if_absent(key, value, ttl))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.put_if_absent(key, value, ttl),
    }
  }

  async fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_take", || redis.take_key(key))
          .await
      }
      Self::Postgres(pg) => pg.runtime.execute("value_take", || pg.take_key(key)).await,
      #[cfg(test)]
      Self::Memory(memory) => memory.take_key(key),
    }
  }

  async fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_put", || redis.put(key, value, ttl))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_put", || pg.put(key, value, ttl))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.put(key, value, ttl),
    }
  }

  async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match self {
      Self::Redis(redis) => redis.runtime.execute("value_get", || redis.get(key)).await,
      Self::Postgres(pg) => pg.runtime.execute("value_get", || pg.get(key)).await,
      #[cfg(test)]
      Self::Memory(memory) => memory.get(key),
    }
  }

  async fn delete(&self, key: &str) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_delete", || redis.delete(key))
          .await
      }
      Self::Postgres(pg) => pg.runtime.execute("value_delete", || pg.delete(key)).await,
      #[cfg(test)]
      Self::Memory(memory) => memory.delete(key),
    }
  }

  async fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("cache_unlock", || redis.unlock(key, token))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("cache_unlock", || pg.unlock(key, token))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.unlock(key, token),
    }
  }

  async fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("health_read", || redis.health_get(key))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("health_read", || pg.health_get(key))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.health_get(key),
    }
  }

  async fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("health_update", || {
            redis.health_report(
              key,
              success,
              enabled,
              healthy_threshold,
              unhealthy_threshold,
            )
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("health_update", || {
            pg.health_report(
              key,
              success,
              enabled,
              healthy_threshold,
              unhealthy_threshold,
            )
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.health_report(
        key,
        success,
        enabled,
        healthy_threshold,
        unhealthy_threshold,
      ),
    }
  }

  async fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("counter_read", || redis.counter_get(key))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("counter_read", || pg.counter_get(key))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.counter_get(key),
    }
  }

  async fn counter_add(
    &self,
    key: &str,
    delta: i64,
    ttl: Option<Duration>,
  ) -> anyhow::Result<usize> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("counter_update", || redis.counter_add(key, delta, ttl))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("counter_update", || pg.counter_add(key, delta, ttl))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.counter_add(key, delta, ttl),
    }
  }

  async fn cache_entries(&self, prefix: &str) -> anyhow::Result<Vec<SharedCacheEntry>> {
    Ok(
      self
        .cache_entries_with_keys(prefix)
        .await?
        .into_iter()
        .map(|(_, entry)| entry)
        .collect(),
    )
  }

  async fn cache_entries_with_keys(
    &self,
    prefix: &str,
  ) -> anyhow::Result<Vec<(String, SharedCacheEntry)>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("cache_lookup", || redis.cache_entries(prefix))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("cache_lookup", || pg.cache_entries(prefix))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.cache_entries(prefix),
    }
  }

  async fn raw_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("cache_lookup", || redis.raw_entries(prefix))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("cache_lookup", || pg.raw_entries(prefix))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.raw_entries(prefix),
    }
  }
}

#[cfg(test)]
impl MemoryBackend {
  fn connection_acquire(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
  ) -> anyhow::Result<Option<usize>> {
    let mut counters = self
      .counters
      .lock()
      .expect("memory shared counter lock poisoned");
    let now = now_unix_ms();
    purge_expired_counters(&mut counters, now);
    for (index, key) in keys.iter().enumerate() {
      if counters.get(key).map(|item| item.counter).unwrap_or(0) >= limits[index] as i64 {
        return Ok(Some(index));
      }
    }
    let expires_at_ms = Some(now + ttl.as_millis().min(i64::MAX as u128) as i64);
    for key in keys {
      let entry = counters.entry(key.clone()).or_insert(MemoryCounter {
        counter: 0,
        expires_at_ms,
      });
      entry.counter += 1;
      entry.expires_at_ms = expires_at_ms;
    }
    Ok(None)
  }

  fn connection_release(&self, keys: &[String]) -> anyhow::Result<()> {
    let mut counters = self
      .counters
      .lock()
      .expect("memory shared counter lock poisoned");
    for key in keys {
      if let Some(entry) = counters.get_mut(key) {
        entry.counter = entry.counter.saturating_sub(1);
        if entry.counter == 0 {
          counters.remove(key);
        }
      }
    }
    Ok(())
  }

  fn get_or_init_bytes(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    let mut random = vec![0u8; len];
    crate::crypto::random_fill(&mut random)
      .map_err(|_| anyhow!("failed to generate shared state random bytes"))?;
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    let value = values
      .entry(key.to_string())
      .or_insert_with(|| MemoryValue {
        value: random,
        expires_at_ms: ttl.map(|ttl| now + ttl.as_millis().min(i64::MAX as u128) as i64),
      });
    Ok(value.value.clone())
  }

  fn put_if_absent(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<bool> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    if values.contains_key(key) {
      return Ok(false);
    }
    values.insert(
      key.to_string(),
      MemoryValue {
        value: value.to_vec(),
        expires_at_ms: ttl.map(|ttl| now + ttl.as_millis().min(i64::MAX as u128) as i64),
      },
    );
    Ok(true)
  }

  fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    Ok(values.remove(key).is_some())
  }

  fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<()> {
    self
      .values
      .lock()
      .expect("memory shared state lock poisoned")
      .insert(
        key.to_string(),
        MemoryValue {
          value: value.to_vec(),
          expires_at_ms: ttl
            .map(|ttl| now_unix_ms() + ttl.as_millis().min(i64::MAX as u128) as i64),
        },
      );
    Ok(())
  }

  fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    purge_expired_values(&mut values, now_unix_ms());
    Ok(values.get(key).map(|value| value.value.clone()))
  }

  fn delete(&self, key: &str) -> anyhow::Result<()> {
    self
      .values
      .lock()
      .expect("memory shared state lock poisoned")
      .remove(key);
    Ok(())
  }

  fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    if values
      .get(key)
      .map(|value| value.value == token.as_bytes())
      .unwrap_or(false)
    {
      values.remove(key);
    }
    Ok(())
  }

  fn update_bytes<F>(&self, key: &str, ttl: Option<Duration>, update: F) -> anyhow::Result<Vec<u8>>
  where
    F: FnOnce(Option<&[u8]>) -> anyhow::Result<Vec<u8>>,
  {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    let current = values.get(key).map(|value| value.value.as_slice());
    let next = update(current)?;
    values.insert(
      key.to_string(),
      MemoryValue {
        value: next.clone(),
        expires_at_ms: ttl.map(|ttl| now + ttl.as_millis().min(i64::MAX as u128) as i64),
      },
    );
    Ok(next)
  }

  fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    let mut counters = self
      .counters
      .lock()
      .expect("memory shared counter lock poisoned");
    purge_expired_counters(&mut counters, now_unix_ms());
    Ok(
      counters
        .get(key)
        .map(|item| item.counter.max(0) as usize)
        .unwrap_or(0),
    )
  }

  fn counter_add(&self, key: &str, delta: i64, ttl: Option<Duration>) -> anyhow::Result<usize> {
    let mut counters = self
      .counters
      .lock()
      .expect("memory shared counter lock poisoned");
    let now = now_unix_ms();
    purge_expired_counters(&mut counters, now);
    let entry = counters.entry(key.to_string()).or_insert(MemoryCounter {
      counter: 0,
      expires_at_ms: None,
    });
    entry.counter = (entry.counter + delta).max(0);
    if let Some(ttl) = ttl {
      entry.expires_at_ms = Some(now + ttl.as_millis().min(i64::MAX as u128) as i64);
    }
    Ok(entry.counter as usize)
  }

  fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    Ok(
      self
        .get(key)?
        .and_then(|value| serde_json::from_slice(&value).ok()),
    )
  }

  fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    let value = self.update_bytes(key, None, |current| {
      let mut record: HealthRecord = current
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .unwrap_or_default();
      if !enabled {
        record.healthy = true;
        record.consecutive_successes = 0;
        record.consecutive_failures = 0;
      } else if success {
        record.consecutive_successes = record.consecutive_successes.saturating_add(1);
        record.consecutive_failures = 0;
        if record.consecutive_successes >= healthy_threshold.max(1) {
          record.healthy = true;
        }
      } else {
        record.consecutive_failures = record.consecutive_failures.saturating_add(1);
        record.consecutive_successes = 0;
        if record.consecutive_failures >= unhealthy_threshold.max(1) {
          record.healthy = false;
        }
      }
      serde_json::to_vec(&record).map_err(Into::into)
    })?;
    let record: HealthRecord = serde_json::from_slice(&value)?;
    Ok(record.healthy)
  }

  fn cache_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, SharedCacheEntry)>> {
    Ok(
      self
        .raw_entries(prefix)?
        .into_iter()
        .filter_map(|(key, value)| {
          serde_json::from_slice(&value)
            .ok()
            .map(|entry| (key, entry))
        })
        .collect(),
    )
  }

  fn raw_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    Ok(
      values
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .map(|(key, value)| (key.clone(), value.value.clone()))
        .collect(),
    )
  }
}

impl RedisBackend {
  async fn command(&self, args: &[Vec<u8>]) -> anyhow::Result<Resp> {
    let host = self
      .url
      .host_str()
      .ok_or_else(|| anyhow!("Redis URL is missing host"))?;
    let port = self.url.port().unwrap_or(6379);
    let stream = self
      .runtime
      .connect(|| async move {
        TcpStream::connect((host, port))
          .await
          .with_context(|| format!("failed to connect Redis backend {host}:{port}"))
      })
      .await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    if let Some(password) = self.url.password()
      && !password.is_empty()
    {
      let username = self.url.username();
      let auth = if username.is_empty() {
        vec![b"AUTH".to_vec(), password.as_bytes().to_vec()]
      } else {
        vec![
          b"AUTH".to_vec(),
          username.as_bytes().to_vec(),
          password.as_bytes().to_vec(),
        ]
      };
      write_resp_command(&mut writer, &auth).await?;
      expect_ok(read_resp(&mut reader).await?)?;
    }
    if let Some(db) = self
      .url
      .path()
      .strip_prefix('/')
      .filter(|value| !value.is_empty())
    {
      let select = vec![b"SELECT".to_vec(), db.as_bytes().to_vec()];
      write_resp_command(&mut writer, &select).await?;
      expect_ok(read_resp(&mut reader).await?)?;
    }

    write_resp_command(&mut writer, args).await?;
    read_resp(&mut reader)
      .await
      .context("failed to read Redis response")
  }

  async fn connection_acquire(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
  ) -> anyhow::Result<Option<usize>> {
    let script = r#"
for i = 1, #KEYS do
  local current = tonumber(redis.call('GET', KEYS[i]) or '0')
  local limit = tonumber(ARGV[i])
  if current >= limit then
    return i
  end
end
local ttl = tonumber(ARGV[#ARGV])
for i = 1, #KEYS do
  redis.call('INCR', KEYS[i])
  redis.call('PEXPIRE', KEYS[i], ttl)
end
return 0
"#;
    let mut args = vec![
      b"EVAL".to_vec(),
      script.as_bytes().to_vec(),
      keys.len().to_string().into_bytes(),
    ];
    args.extend(keys.iter().map(|key| key.as_bytes().to_vec()));
    args.extend(limits.iter().map(|limit| limit.to_string().into_bytes()));
    args.push(
      ttl
        .as_millis()
        .min(i64::MAX as u128)
        .to_string()
        .into_bytes(),
    );
    let value = self.command(&args).await?.into_i64()?;
    Ok((value > 0).then_some(value as usize - 1))
  }

  async fn connection_release(&self, keys: &[String]) -> anyhow::Result<()> {
    let script = r#"
for i = 1, #KEYS do
  local current = tonumber(redis.call('GET', KEYS[i]) or '0')
  if current <= 1 then
    redis.call('DEL', KEYS[i])
  else
    redis.call('DECR', KEYS[i])
  end
end
return 1
"#;
    let mut args = vec![
      b"EVAL".to_vec(),
      script.as_bytes().to_vec(),
      keys.len().to_string().into_bytes(),
    ];
    args.extend(keys.iter().map(|key| key.as_bytes().to_vec()));
    let _ = self.command(&args).await?;
    Ok(())
  }

  async fn get_or_init_bytes(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    let mut value = vec![0u8; len];
    crate::crypto::random_fill(&mut value)
      .map_err(|_| anyhow!("failed to generate shared state random bytes"))?;
    let _ = self.put_if_absent(key, &value, ttl).await?;
    match self
      .command(&[b"GET".to_vec(), key.as_bytes().to_vec()])
      .await?
    {
      Resp::Bulk(Some(bytes)) => Ok(bytes),
      _ => bail!("shared Redis key {key} did not contain bytes"),
    }
  }

  async fn put_if_absent(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    let mut args = vec![
      b"SET".to_vec(),
      key.as_bytes().to_vec(),
      value.to_vec(),
      b"NX".to_vec(),
    ];
    if let Some(ttl) = ttl {
      args.push(b"PX".to_vec());
      args.push(
        ttl
          .as_millis()
          .min(i64::MAX as u128)
          .to_string()
          .into_bytes(),
      );
    }
    match self.command(&args).await? {
      Resp::Simple(value) if value == "OK" => Ok(true),
      Resp::Bulk(None) => Ok(false),
      Resp::Nil => Ok(false),
      other => bail!("unexpected Redis SET NX response: {other:?}"),
    }
  }

  async fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    let script = "local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]); return 1; end; return 0";
    Ok(
      self
        .command(&[
          b"EVAL".to_vec(),
          script.as_bytes().to_vec(),
          b"1".to_vec(),
          key.as_bytes().to_vec(),
        ])
        .await?
        .into_i64()?
        == 1,
    )
  }

  async fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<()> {
    let args = if let Some(ttl) = ttl {
      vec![
        b"PSETEX".to_vec(),
        key.as_bytes().to_vec(),
        ttl
          .as_millis()
          .min(i64::MAX as u128)
          .to_string()
          .into_bytes(),
        value.to_vec(),
      ]
    } else {
      vec![b"SET".to_vec(), key.as_bytes().to_vec(), value.to_vec()]
    };
    expect_ok(self.command(&args).await?)
  }

  async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    match self
      .command(&[b"GET".to_vec(), key.as_bytes().to_vec()])
      .await?
    {
      Resp::Bulk(Some(value)) => Ok(Some(value)),
      Resp::Bulk(None) | Resp::Nil => Ok(None),
      other => bail!("unexpected Redis GET response: {other:?}"),
    }
  }

  async fn delete(&self, key: &str) -> anyhow::Result<()> {
    let _ = self
      .command(&[b"DEL".to_vec(), key.as_bytes().to_vec()])
      .await?;
    Ok(())
  }

  async fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    let script = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]); end; return 0";
    let _ = self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"1".to_vec(),
        key.as_bytes().to_vec(),
        token.as_bytes().to_vec(),
      ])
      .await?;
    Ok(())
  }

  async fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    match self
      .command(&[b"GET".to_vec(), key.as_bytes().to_vec()])
      .await?
    {
      Resp::Bulk(Some(bytes)) => Ok(Some(serde_json::from_slice(&bytes)?)),
      Resp::Bulk(None) | Resp::Nil => Ok(None),
      other => bail!("unexpected Redis health response: {other:?}"),
    }
  }

  async fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    let mut record = self.health_get(key).await?.unwrap_or_default();
    if success {
      record.consecutive_failures = 0;
      record.consecutive_successes = record.consecutive_successes.saturating_add(1);
      if !enabled || record.consecutive_successes >= healthy_threshold {
        record.healthy = true;
      }
    } else {
      record.consecutive_successes = 0;
      record.consecutive_failures = record.consecutive_failures.saturating_add(1);
      if enabled && record.consecutive_failures >= unhealthy_threshold {
        record.healthy = false;
      }
    }
    self
      .put(
        key,
        &serde_json::to_vec(&record)?,
        Some(Duration::from_secs(3600)),
      )
      .await?;
    Ok(record.healthy)
  }

  async fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    match self
      .command(&[b"GET".to_vec(), key.as_bytes().to_vec()])
      .await?
    {
      Resp::Bulk(Some(bytes)) => Ok(
        String::from_utf8_lossy(&bytes)
          .parse::<usize>()
          .unwrap_or(0),
      ),
      Resp::Bulk(None) | Resp::Nil => Ok(0),
      other => bail!("unexpected Redis counter response: {other:?}"),
    }
  }

  async fn counter_add(
    &self,
    key: &str,
    delta: i64,
    ttl: Option<Duration>,
  ) -> anyhow::Result<usize> {
    let value = self
      .command(&[
        b"INCRBY".to_vec(),
        key.as_bytes().to_vec(),
        delta.to_string().into_bytes(),
      ])
      .await?
      .into_i64()?
      .max(0) as usize;
    if let Some(ttl) = ttl {
      let _ = self
        .command(&[
          b"PEXPIRE".to_vec(),
          key.as_bytes().to_vec(),
          ttl
            .as_millis()
            .min(i64::MAX as u128)
            .to_string()
            .into_bytes(),
        ])
        .await?;
    }
    Ok(value)
  }

  async fn cache_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, SharedCacheEntry)>> {
    Ok(
      self
        .raw_entries(prefix)
        .await?
        .into_iter()
        .filter_map(|(key, value)| {
          serde_json::from_slice(&value)
            .ok()
            .map(|entry| (key, entry))
        })
        .collect(),
    )
  }

  async fn raw_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let pattern = format!("{prefix}*");
    let keys = match self
      .command(&[b"KEYS".to_vec(), pattern.as_bytes().to_vec()])
      .await?
    {
      Resp::Array(items) => items
        .into_iter()
        .filter_map(|item| match item {
          Resp::Bulk(Some(bytes)) => String::from_utf8(bytes).ok(),
          _ => None,
        })
        .collect::<Vec<_>>(),
      other => bail!("unexpected Redis KEYS response: {other:?}"),
    };
    let mut entries = Vec::new();
    for key in keys {
      if let Resp::Bulk(Some(bytes)) = self
        .command(&[b"GET".to_vec(), key.as_bytes().to_vec()])
        .await?
      {
        entries.push((key, bytes));
      }
    }
    Ok(entries)
  }

  async fn scan_keys(
    &self,
    pattern: &str,
    cursor: &str,
    count: usize,
  ) -> anyhow::Result<(Vec<String>, Option<String>)> {
    let response = self
      .command(&[
        b"SCAN".to_vec(),
        cursor.as_bytes().to_vec(),
        b"MATCH".to_vec(),
        pattern.as_bytes().to_vec(),
        b"COUNT".to_vec(),
        count.max(1).to_string().into_bytes(),
      ])
      .await?;
    let Resp::Array(items) = response else {
      bail!("unexpected Redis SCAN response");
    };
    if items.len() != 2 {
      bail!("unexpected Redis SCAN item count");
    }
    let next_cursor = match &items[0] {
      Resp::Bulk(Some(bytes)) => String::from_utf8(bytes.clone())?,
      Resp::Simple(value) => value.clone(),
      other => bail!("unexpected Redis SCAN cursor response: {other:?}"),
    };
    let keys = match &items[1] {
      Resp::Array(keys) => keys
        .iter()
        .filter_map(|item| match item {
          Resp::Bulk(Some(bytes)) => String::from_utf8(bytes.clone()).ok(),
          Resp::Simple(value) => Some(value.clone()),
          _ => None,
        })
        .collect::<Vec<_>>(),
      other => bail!("unexpected Redis SCAN keys response: {other:?}"),
    };
    let next_cursor = (next_cursor != "0").then_some(next_cursor);
    Ok((keys, next_cursor))
  }

  async fn expires_at_ms(&self, key: &str) -> anyhow::Result<Option<i64>> {
    match self
      .command(&[b"PTTL".to_vec(), key.as_bytes().to_vec()])
      .await?
    {
      Resp::Int(ttl) if ttl >= 0 => Ok(Some(now_unix_ms().saturating_add(ttl))),
      Resp::Int(-1) => Ok(None),
      Resp::Int(-2) => Ok(Some(0)),
      other => bail!("unexpected Redis PTTL response: {other:?}"),
    }
  }
}

impl PostgresBackend {
  async fn connection_acquire(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
  ) -> anyhow::Result<Option<usize>> {
    let mut tx = self.pool.begin().await?;
    let now = now_unix_ms();
    let expires = now + ttl.as_millis().min(i64::MAX as u128) as i64;
    for (index, key) in keys.iter().enumerate() {
      let current: Option<i64> = sqlx::query_scalar(
        "SELECT counter FROM oxibelt_shared_counters WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2) FOR UPDATE",
      )
      .bind(key)
      .bind(now)
      .fetch_optional(&mut *tx)
      .await?;
      if current.unwrap_or(0) >= limits[index] as i64 {
        tx.rollback().await?;
        return Ok(Some(index));
      }
    }
    for key in keys {
      sqlx::query(
        "INSERT INTO oxibelt_shared_counters (key, counter, expires_at_ms) VALUES ($1, 1, $2)
         ON CONFLICT (key) DO UPDATE SET counter = oxibelt_shared_counters.counter + 1, expires_at_ms = EXCLUDED.expires_at_ms",
      )
      .bind(key)
      .bind(expires)
      .execute(&mut *tx)
      .await?;
    }
    tx.commit().await?;
    Ok(None)
  }

  async fn connection_release(&self, keys: &[String]) -> anyhow::Result<()> {
    for key in keys {
      sqlx::query(
        "UPDATE oxibelt_shared_counters SET counter = GREATEST(counter - 1, 0) WHERE key = $1",
      )
      .bind(key)
      .execute(&self.pool)
      .await?;
    }
    Ok(())
  }

  async fn get_or_init_bytes(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    let mut random = vec![0u8; len];
    crate::crypto::random_fill(&mut random)
      .map_err(|_| anyhow!("failed to generate shared state random bytes"))?;
    let _ = self.put_if_absent(key, &random, ttl).await?;
    sqlx::query_scalar::<_, Vec<u8>>(
      "SELECT value FROM oxibelt_shared_state WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(key)
    .bind(now_unix_ms())
    .fetch_one(&self.pool)
    .await
    .map_err(Into::into)
  }

  async fn put_if_absent(
    &self,
    key: &str,
    value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<bool> {
    let expires = ttl.map(|ttl| now_unix_ms() + ttl.as_millis().min(i64::MAX as u128) as i64);
    let result = sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO NOTHING",
    )
    .bind(key)
    .bind(value)
    .bind(expires)
    .execute(&self.pool)
    .await?;
    Ok(result.rows_affected() == 1)
  }

  async fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    let result = sqlx::query(
      "DELETE FROM oxibelt_shared_state WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(key)
    .bind(now_unix_ms())
    .execute(&self.pool)
    .await?;
    Ok(result.rows_affected() > 0)
  }

  async fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<()> {
    let expires = ttl.map(|ttl| now_unix_ms() + ttl.as_millis().min(i64::MAX as u128) as i64);
    sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at_ms = EXCLUDED.expires_at_ms",
    )
    .bind(key)
    .bind(value)
    .bind(expires)
    .execute(&self.pool)
    .await?;
    Ok(())
  }

  async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let value: Option<Vec<u8>> = sqlx::query_scalar(
      "SELECT value FROM oxibelt_shared_state WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(key)
    .bind(now_unix_ms())
    .fetch_optional(&self.pool)
    .await?;
    Ok(value)
  }

  async fn delete(&self, key: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = $1")
      .bind(key)
      .execute(&self.pool)
      .await?;
    Ok(())
  }

  async fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = $1 AND value = $2")
      .bind(key)
      .bind(token.as_bytes())
      .execute(&self.pool)
      .await?;
    Ok(())
  }

  async fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    let raw: Option<Vec<u8>> =
      sqlx::query_scalar("SELECT value FROM oxibelt_shared_state WHERE key = $1")
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
    raw
      .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
      .transpose()
  }

  async fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    let mut tx = self.pool.begin().await?;
    let raw: Option<Vec<u8>> =
      sqlx::query_scalar("SELECT value FROM oxibelt_shared_state WHERE key = $1 FOR UPDATE")
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?;
    let mut record: HealthRecord = raw
      .as_deref()
      .and_then(|bytes| serde_json::from_slice(bytes).ok())
      .unwrap_or_default();
    if success {
      record.consecutive_failures = 0;
      record.consecutive_successes = record.consecutive_successes.saturating_add(1);
      if !enabled || record.consecutive_successes >= healthy_threshold {
        record.healthy = true;
      }
    } else {
      record.consecutive_successes = 0;
      record.consecutive_failures = record.consecutive_failures.saturating_add(1);
      if enabled && record.consecutive_failures >= unhealthy_threshold {
        record.healthy = false;
      }
    }
    let value = serde_json::to_vec(&record)?;
    sqlx::query(
      "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, NULL)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at_ms = NULL",
    )
    .bind(key)
    .bind(value)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(record.healthy)
  }

  async fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    let value: Option<i64> = sqlx::query_scalar(
      "SELECT counter FROM oxibelt_shared_counters WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(key)
    .bind(now_unix_ms())
    .fetch_optional(&self.pool)
    .await?;
    Ok(value.unwrap_or(0).max(0) as usize)
  }

  async fn counter_add(
    &self,
    key: &str,
    delta: i64,
    ttl: Option<Duration>,
  ) -> anyhow::Result<usize> {
    let expires = ttl.map(|ttl| now_unix_ms() + ttl.as_millis().min(i64::MAX as u128) as i64);
    let value: i64 = sqlx::query_scalar(
      "INSERT INTO oxibelt_shared_counters (key, counter, expires_at_ms) VALUES ($1, GREATEST($2, 0), $3)
       ON CONFLICT (key) DO UPDATE SET counter = GREATEST(oxibelt_shared_counters.counter + $2, 0), expires_at_ms = COALESCE(EXCLUDED.expires_at_ms, oxibelt_shared_counters.expires_at_ms)
       RETURNING counter",
    )
    .bind(key)
    .bind(delta)
    .bind(expires)
    .fetch_one(&self.pool)
    .await?;
    Ok(value.max(0) as usize)
  }

  async fn cache_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, SharedCacheEntry)>> {
    Ok(
      self
        .raw_entries(prefix)
        .await?
        .into_iter()
        .filter_map(|(key, value)| {
          serde_json::from_slice(&value)
            .ok()
            .map(|entry| (key, entry))
        })
        .collect(),
    )
  }

  async fn raw_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let pattern = format!("{prefix}%");
    let rows = sqlx::query_as(
      "SELECT key, value FROM oxibelt_shared_state WHERE key LIKE $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(pattern)
    .bind(now_unix_ms())
    .fetch_all(&self.pool)
    .await?;
    Ok(rows)
  }
}

async fn connect_postgres_pool(
  config: &SharedStateBackendConfig,
  connection_url: &str,
  connect_timeout: Duration,
) -> anyhow::Result<Pool<Postgres>> {
  let mut options = PgConnectOptions::from_str(connection_url)?
    .application_name("oxibelt-shared-state")
    .ssl_mode(match config.tls.mode {
      DatabaseTlsMode::Off => PgSslMode::Disable,
      DatabaseTlsMode::VerifyFull => PgSslMode::VerifyFull,
    });
  if let Some(ca_cert) = &config.tls.ca_cert {
    options = options.ssl_root_cert(ca_cert);
  }
  if let (Some(client_cert), Some(client_key)) = (&config.tls.client_cert, &config.tls.client_key) {
    options = options
      .ssl_client_cert(client_cert)
      .ssl_client_key(client_key);
  }
  PgPoolOptions::new()
    .max_connections(config.max_connections)
    .acquire_timeout(connect_timeout)
    .connect_with(options)
    .await
    .map_err(Into::into)
}

async fn init_postgres(pool: &Pool<Postgres>) -> anyhow::Result<()> {
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_state (
       key text PRIMARY KEY,
       value bytea NOT NULL,
       expires_at_ms bigint NULL
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_counters (
       key text PRIMARY KEY,
       counter bigint NOT NULL,
       expires_at_ms bigint NULL
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_rate_limit_locks (
       limit_name text PRIMARY KEY
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_rate_buckets (
       limit_name text NOT NULL,
       bucket_key text NOT NULL,
       expires_at_ms bigint NOT NULL,
       PRIMARY KEY (limit_name, bucket_key)
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_shared_rate_buckets_expires
     ON oxibelt_shared_rate_buckets (limit_name, expires_at_ms)",
  )
  .execute(pool)
  .await?;
  Ok(())
}

#[cfg(test)]
fn purge_expired_values(values: &mut HashMap<String, MemoryValue>, now: i64) {
  values.retain(|_, value| value.expires_at_ms.is_none_or(|expires| expires > now));
}

#[cfg(test)]
fn purge_expired_counters(counters: &mut HashMap<String, MemoryCounter>, now: i64) {
  counters.retain(|_, value| value.expires_at_ms.is_none_or(|expires| expires > now));
}

fn parse_rate_bucket(raw: &[u8]) -> Option<(f64, i64)> {
  let raw = std::str::from_utf8(raw).ok()?;
  let (tokens, last) = raw.split_once(':')?;
  Some((tokens.parse().ok()?, last.parse().ok()?))
}

fn ttl_from_expires_ms(expires_at_ms: i64) -> Option<Duration> {
  let now = now_unix_ms();
  (expires_at_ms > now).then_some(Duration::from_millis((expires_at_ms - now) as u64))
}

fn rate_bucket_ttl(rate: ParsedRate, burst: u32) -> Duration {
  let seconds = f64::from(burst.max(1)) / rate.per_second();
  let millis = (seconds * 1000.0).ceil().max(1000.0);
  let millis = if millis.is_finite() && millis < i64::MAX as f64 {
    millis as u64
  } else {
    i64::MAX as u64
  };
  Duration::from_millis(millis)
}

pub fn now_unix_ms() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis()
    .min(i64::MAX as u128) as i64
}

fn random_hex(bytes: usize) -> anyhow::Result<String> {
  let mut value = vec![0u8; bytes];
  crate::crypto::random_fill(&mut value)
    .map_err(|_| anyhow!("failed to generate shared cache lock token"))?;
  Ok(hex_encode(&value))
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

fn config_hash(config: &Config) -> String {
  hex_encode(&crate::crypto::sha256(format!("{config:?}").as_bytes()))
}
