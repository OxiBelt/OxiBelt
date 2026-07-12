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
use tracing::warn;

use crate::config::{
  Config, CryptoConfig, DatabaseTlsMode, RedisPlaintextPolicy, SharedStateBackendConfig,
  SharedStateBackendKind,
};
use crate::limits::ParsedRate;
use crate::metrics::Metrics;

mod atomic_updates;
mod cache_store;
mod enumeration;
mod feature_flags;
mod person_proof;
mod rate_limits;
mod redis_connection;
mod redis_pool;
mod redis_protocol;
#[cfg(test)]
#[path = "shared_state/redis_tls_tests.rs"]
mod redis_tls_tests;
mod runtime;
mod sticky_sessions;
#[cfg(test)]
mod test_support;

use redis_pool::RedisPool;
use redis_protocol::{Resp, expect_ok};
use runtime::{BackendRuntime, CleanupDispatcher, SharedPoolWarningLimiter};

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
  operation_timeout: Duration,
  enumeration: enumeration::EnumerationLimits,
  backends: HashMap<String, Arc<Backend>>,
  rate_limits: Option<Arc<Backend>>,
  connection_limits: Option<Arc<Backend>>,
  person_proof: Option<Arc<Backend>>,
  upstream_health: Option<Arc<Backend>>,
  pool_warning_limiter: Arc<SharedPoolWarningLimiter>,
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
  pool: RedisPool,
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
  leases: Arc<Mutex<HashMap<String, MemoryLease>>>,
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

#[cfg(test)]
#[derive(Clone, Debug)]
struct MemoryLease {
  fingerprint: String,
  expires_at_ms: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct ConnectionScope<'a> {
  pub key: &'a str,
  pub limit: usize,
  pub status: StatusCode,
}

/// An opaque, backend-bound counter lease.  A lease marker makes a release
/// idempotent and prevents a stale permit from decrementing a newer counter
/// generation after its own TTL has elapsed.
#[derive(Debug, Clone)]
pub(crate) struct SharedCounterLease {
  marker_key: String,
  fingerprint: String,
  keys: Vec<String>,
}

impl SharedCounterLease {
  fn new(marker_key: String, fingerprint: String, keys: Vec<String>) -> Self {
    Self {
      marker_key,
      fingerprint,
      keys,
    }
  }
}

#[derive(Debug)]
pub(crate) enum SharedConnectionAcquire {
  Acquired(SharedCounterLease),
  Denied(StatusCode),
}

/// The durable portion of a Person-proof clearance revocation response.
///
/// This is deliberately small and contains only hash-derived state, so it is
/// safe to retain for the lifetime of an optional idempotency record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct PersonProofRevocationResult {
  pub(crate) removed_active: bool,
  pub(crate) expires_at_ms: i64,
}

/// Digest-only idempotency material for the narrow Person-proof Admin
/// mutation. Raw header values never reach storage or log fields.
#[derive(Debug, Clone)]
pub(crate) struct PersonProofRevocationIdempotency {
  pub(crate) key_digest: String,
  pub(crate) request_fingerprint: String,
}

impl PersonProofRevocationIdempotency {
  pub(crate) fn new(key: &str, clearance_hash: &str, supplied_ttl_seconds: Option<u64>) -> Self {
    let key_digest = hex_encode(&crate::crypto::sha256(key.as_bytes()));
    let supplied_ttl = supplied_ttl_seconds
      .map(|ttl| format!("ttl:{ttl}"))
      .unwrap_or_else(|| "ttl:omitted".to_string());
    let request_fingerprint = hex_encode(&crate::crypto::sha256(
      format!("person-proof-revoke:v1\0{clearance_hash}\0{supplied_ttl}").as_bytes(),
    ));
    Self {
      key_digest,
      request_fingerprint,
    }
  }
}

#[derive(Debug)]
pub(crate) struct PersonProofIdempotencyConflict;

impl std::fmt::Display for PersonProofIdempotencyConflict {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("person proof idempotency key was reused with a different request")
  }
}

impl std::error::Error for PersonProofIdempotencyConflict {}

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
    Self::new_with_previous(config, metrics, None).await
  }

  pub(crate) async fn new_with_previous(
    config: &Config,
    metrics: Arc<Metrics>,
    previous: Option<&SharedState>,
  ) -> anyhow::Result<Option<Arc<Self>>> {
    let shared = &config.shared_state;
    if !shared.enabled {
      return Ok(None);
    }

    metrics.configure_shared_state_metrics(&config.metrics.histogram_buckets_ms);

    let mut backends = HashMap::new();
    for backend in &shared.backends {
      let name = backend.name.clone();
      let previous_backend = previous.and_then(|state| state.backends.get(&name));
      let built = Backend::connect(
        backend,
        shared.operation_timeout_ms,
        &config.crypto,
        shared.redis_plaintext_policy,
        metrics.clone(),
        previous_backend,
      )
      .await?;
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
    let rate_limits = pick(&shared.rate_limits_backend);
    let connection_limits = pick(&shared.connection_limits_backend);
    let person_proof = pick(&shared.person_proof_backend);
    let upstream_health = pick(&shared.upstream_health_backend);
    let sticky_sessions = pick(&shared.sticky_sessions_backend);
    let cache = pick(&shared.cache_backend);
    let reload = pick(&shared.reload_backend);
    let state = Arc::new(Self {
      namespace: Arc::from(shared.namespace.as_str()),
      instance_id: Arc::from(instance_id),
      connection_lease: Duration::from_millis(shared.connection_lease_ms),
      cache_lock: Duration::from_millis(shared.cache_lock_ms),
      cache_chunk_bytes: config.cache.stream_chunk_bytes,
      operation_timeout: Duration::from_millis(shared.operation_timeout_ms),
      enumeration: enumeration::EnumerationLimits {
        page_size: shared.enumeration_page_size,
        max_items: shared.enumeration_max_items_per_operation,
      },
      backends,
      rate_limits,
      connection_limits,
      person_proof,
      upstream_health,
      pool_warning_limiter: Self::inherited_pool_warning_limiter(previous),
      sticky_sessions,
      cache,
      reload,
      cleanup: CleanupDispatcher::new(),
    });
    state.record_reload_generation(config).await;
    Ok(Some(state))
  }

  fn inherited_pool_warning_limiter(
    previous: Option<&SharedState>,
  ) -> Arc<SharedPoolWarningLimiter> {
    previous
      .map(|state| state.pool_warning_limiter.clone())
      .unwrap_or_default()
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

  #[cfg(test)]
  pub(crate) fn test_redis_pool_identity(&self, name: &str) -> Option<usize> {
    match self.backends.get(name).map(Arc::as_ref) {
      Some(Backend::Redis(redis)) => Some(redis.pool.test_identity()),
      _ => None,
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

  pub(crate) async fn acquire_connections(
    &self,
    scopes: &[ConnectionScope<'_>],
  ) -> anyhow::Result<SharedConnectionAcquire> {
    let Some(backend) = &self.connection_limits else {
      return Ok(SharedConnectionAcquire::Acquired(SharedCounterLease::new(
        String::new(),
        String::new(),
        Vec::new(),
      )));
    };
    let keys = scopes
      .iter()
      .map(|scope| self.key(&format!("conn:{}", scope.key)))
      .collect::<Vec<_>>();
    let limits = scopes.iter().map(|scope| scope.limit).collect::<Vec<_>>();
    let lease = SharedCounterLease::new(
      self.key(&format!("lease:connection:{}", random_hex(16)?)),
      connection_lease_fingerprint(&keys, &limits, self.connection_lease),
      keys,
    );
    match backend
      .connection_acquire(&lease.keys, &limits, self.connection_lease, &lease)
      .await
    {
      Ok(Some(index)) => Ok(SharedConnectionAcquire::Denied(scopes[index].status)),
      Ok(None) => Ok(SharedConnectionAcquire::Acquired(lease)),
      Err(error) => {
        self
          .cleanup
          .defer_connection_release(backend.clone(), lease);
        Err(error)
      }
    }
  }

  pub(crate) async fn release_connections(&self, lease: SharedCounterLease) {
    if lease.marker_key.is_empty() {
      return;
    }
    let Some(backend) = &self.connection_limits else {
      return;
    };
    if let Err(error) = backend.connection_release(&lease).await {
      warn!(error = %error, "failed to release shared connection limits");
      self
        .cleanup
        .defer_connection_release(backend.clone(), lease);
    }
  }

  pub async fn pool_health(&self, upstream_name: &str) -> anyhow::Result<Option<bool>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:health:{upstream_name}"));
    Ok(backend.health_get(&key).await?.map(|record| record.healthy))
  }

  pub(crate) fn should_log_pool_warning(&self) -> bool {
    self.pool_warning_limiter.should_emit()
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

  /// Acquires one lease-backed shared active-count slot for an upstream.
  ///
  /// Pool selection intentionally remains available when the optional shared
  /// backend is unavailable.  If an acquire timed out after the backend may
  /// have committed it, queue an idempotent release for the marker rather than
  /// retrying the mutation.
  pub(crate) async fn pool_active_acquire(
    &self,
    upstream_name: &str,
  ) -> anyhow::Result<Option<SharedCounterLease>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:active:{upstream_name}"));
    let lease = SharedCounterLease::new(
      self.key(&format!("lease:pool-active:{}", random_hex(16)?)),
      counter_lease_fingerprint(&key, self.connection_lease),
      vec![key.clone()],
    );
    match backend
      .counter_lease_acquire(&key, self.connection_lease, &lease)
      .await
    {
      Ok(()) => Ok(Some(lease)),
      Err(error) => {
        self.cleanup.defer_counter_lease_release(
          backend.clone(),
          lease,
          self.pool_warning_limiter.clone(),
        );
        Err(error)
      }
    }
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

  pub(crate) fn defer_connection_release(&self, lease: SharedCounterLease) {
    if lease.marker_key.is_empty() {
      return;
    }
    let Some(backend) = &self.connection_limits else {
      return;
    };
    self
      .cleanup
      .defer_connection_release(backend.clone(), lease);
  }

  pub(crate) fn defer_pool_active_release(&self, lease: SharedCounterLease) {
    if lease.marker_key.is_empty() {
      return;
    }
    let Some(backend) = &self.upstream_health else {
      return;
    };
    self.cleanup.defer_counter_lease_release(
      backend.clone(),
      lease,
      self.pool_warning_limiter.clone(),
    );
  }

  fn key(&self, suffix: &str) -> String {
    format!("{}:{suffix}", self.namespace)
  }
}

fn connection_lease_fingerprint(keys: &[String], limits: &[usize], ttl: Duration) -> String {
  let mut entries = keys
    .iter()
    .zip(limits)
    .map(|(key, limit)| (key.as_str(), *limit))
    .collect::<Vec<_>>();
  entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
  let mut material = format!("connection-lease:{}\n", atomic_updates::ttl_millis(ttl));
  for (key, limit) in entries {
    material.push_str(key);
    material.push(':');
    material.push_str(&limit.to_string());
    material.push('\n');
  }
  hex_encode(&crate::crypto::sha256(material.as_bytes()))
}

fn counter_lease_fingerprint(key: &str, ttl: Duration) -> String {
  let material = format!("counter-lease:{}:{key}", atomic_updates::ttl_millis(ttl));
  hex_encode(&crate::crypto::sha256(material.as_bytes()))
}

/// Runs a one-shot Redis health probe through the same URL validation,
/// authentication, TLS, and server-verification path used by the runtime.
pub(crate) async fn probe_redis_backend(
  config: &Config,
  backend: &SharedStateBackendConfig,
) -> anyhow::Result<()> {
  let pool = RedisPool::new(
    backend,
    Duration::from_millis(config.shared_state.operation_timeout_ms),
    &config.crypto,
    config.shared_state.redis_plaintext_policy,
    Metrics::new(),
  )?;
  match pool.command(&[b"PING".to_vec()]).await? {
    Resp::Simple(value) if value == "PONG" => Ok(()),
    _ => bail!("unexpected Redis PING response"),
  }
}

impl Backend {
  async fn connect(
    config: &SharedStateBackendConfig,
    timeout_ms: u64,
    crypto: &CryptoConfig,
    plaintext_policy: RedisPlaintextPolicy,
    metrics: Arc<Metrics>,
    previous: Option<&Arc<Backend>>,
  ) -> anyhow::Result<Self> {
    let operation_timeout = Duration::from_millis(timeout_ms);
    match config.kind {
      SharedStateBackendKind::Redis => {
        let runtime = BackendRuntime::new(config, "redis", operation_timeout, metrics.clone());
        let reused = if let Some(Self::Redis(previous)) = previous.map(Arc::as_ref) {
          previous
            .pool
            .matches_config(config, operation_timeout, crypto, plaintext_policy)?
            .then(|| previous.pool.clone())
        } else {
          None
        };
        let pool = if let Some(pool) = reused {
          pool
        } else {
          RedisPool::new(config, operation_timeout, crypto, plaintext_policy, metrics)?
        };
        // A positive minimum-idle setting is an activation requirement even
        // when an unchanged pool is retained over reload.
        pool.prewarm().await?;
        Ok(Self::Redis(RedisBackend { pool, runtime }))
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
    lease: &SharedCounterLease,
  ) -> anyhow::Result<Option<usize>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("connection_acquire", || {
            redis.connection_acquire_atomic(keys, limits, ttl, lease)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("connection_acquire", || {
            pg.connection_acquire_atomic(keys, limits, ttl, lease)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.connection_acquire_atomic(keys, limits, ttl, lease),
    }
  }

  async fn connection_release(&self, lease: &SharedCounterLease) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("connection_release", || {
            redis.connection_release_atomic(lease)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("connection_release", || pg.connection_release_atomic(lease))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.connection_release_atomic(lease),
    }
  }

  async fn counter_lease_acquire(
    &self,
    key: &str,
    ttl: Duration,
    lease: &SharedCounterLease,
  ) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("counter_update", || {
            redis.counter_lease_acquire_atomic(key, ttl, lease)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("counter_update", || {
            pg.counter_lease_acquire_atomic(key, ttl, lease)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.counter_lease_acquire_atomic(key, ttl, lease),
    }
  }

  async fn counter_lease_release(&self, lease: &SharedCounterLease) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("counter_update", || redis.connection_release_atomic(lease))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("counter_update", || pg.connection_release_atomic(lease))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.connection_release_atomic(lease),
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
            redis.get_or_init_bytes_atomic(key, len, ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_get_or_init", || {
            pg.get_or_init_bytes_atomic(key, len, ttl)
          })
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
          .execute("value_put_if_absent", || {
            pg.put_if_absent_atomic(key, value, ttl)
          })
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
            redis.health_report_atomic(
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
            pg.health_report_atomic(
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
          .execute("counter_update", || {
            redis.counter_add_atomic(key, delta, ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("counter_update", || pg.counter_add_atomic(key, delta, ttl))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.counter_add(key, delta, ttl),
    }
  }
}

#[cfg(test)]
impl MemoryBackend {
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
        expires_at_ms: ttl.map(|ttl| atomic_updates::expiry_after(now, ttl)),
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
        expires_at_ms: ttl.map(|ttl| atomic_updates::expiry_after(now, ttl)),
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
          expires_at_ms: ttl.map(|ttl| atomic_updates::expiry_after(now_unix_ms(), ttl)),
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
        expires_at_ms: ttl.map(|ttl| atomic_updates::expiry_after(now, ttl)),
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
      entry.expires_at_ms = Some(atomic_updates::expiry_after(now, ttl));
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
      let record: HealthRecord = current
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .unwrap_or_default();
      let record = atomic_updates::apply_health_report(
        record,
        success,
        enabled,
        healthy_threshold,
        unhealthy_threshold,
      );
      serde_json::to_vec(&record).map_err(Into::into)
    })?;
    let record: HealthRecord = serde_json::from_slice(&value)?;
    Ok(record.healthy)
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
    self.pool.command(args).await
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
}

impl PostgresBackend {
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
    let now = now_unix_ms();
    let expires = ttl.map(|ttl| atomic_updates::expiry_after(now, ttl));
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
    "CREATE TABLE IF NOT EXISTS oxibelt_shared_idempotency (
       record_key text PRIMARY KEY,
       fingerprint bytea NOT NULL,
       result bytea NOT NULL,
       expires_at_ms bigint NOT NULL
     )",
  )
  .execute(pool)
  .await?;
  sqlx::query(
    "CREATE INDEX IF NOT EXISTS oxibelt_shared_idempotency_expires
     ON oxibelt_shared_idempotency (expires_at_ms)",
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
