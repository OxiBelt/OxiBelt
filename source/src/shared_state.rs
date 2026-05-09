use std::collections::HashMap;
use std::future::Future;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{Pool, Postgres};
use tokio::runtime::Handle;
use tracing::warn;
use url::Url;

use crate::cache::{CacheEntry, CacheLookup, Revalidation, StaleEntry};
use crate::config::{Config, DatabaseTlsMode, SharedStateBackendConfig, SharedStateBackendKind};
use crate::limits::ParsedRate;

#[derive(Clone, Debug)]
pub struct SharedState {
  namespace: Arc<str>,
  instance_id: Arc<str>,
  operation_timeout: Duration,
  connection_lease: Duration,
  cache_lock: Duration,
  rate_limits: Option<Arc<Backend>>,
  connection_limits: Option<Arc<Backend>>,
  person_proof: Option<Arc<Backend>>,
  upstream_health: Option<Arc<Backend>>,
  cache: Option<Arc<Backend>>,
  reload: Option<Arc<Backend>>,
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
  timeout: Duration,
}

#[derive(Clone, Debug)]
struct PostgresBackend {
  pool: Pool<Postgres>,
  timeout: Duration,
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct MemoryBackend {
  values: Arc<Mutex<HashMap<String, MemoryValue>>>,
  counters: Arc<Mutex<HashMap<String, MemoryCounter>>>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedCacheEntry {
  pub policy: String,
  pub base_key: String,
  pub variant_key: String,
  pub scheme: String,
  pub host: String,
  pub uri: String,
  pub status: u16,
  pub headers: Vec<(String, Vec<u8>)>,
  pub body: Vec<u8>,
  pub expires_at_ms: i64,
  pub stale_if_error_until_ms: Option<i64>,
  pub stale_while_revalidate_until_ms: Option<i64>,
  pub must_revalidate: bool,
  pub vary: Vec<SharedVaryMatcher>,
  #[serde(default)]
  pub tags: Vec<String>,
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
  pub async fn new(config: &Config) -> anyhow::Result<Option<Arc<Self>>> {
    let shared = &config.shared_state;
    if !shared.enabled {
      return Ok(None);
    }

    let mut backends = HashMap::new();
    for backend in &shared.backends {
      let name = backend.name.clone();
      let built = Backend::connect(backend, shared.operation_timeout_ms).await?;
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
      operation_timeout: Duration::from_millis(shared.operation_timeout_ms),
      connection_lease: Duration::from_millis(shared.connection_lease_ms),
      cache_lock: Duration::from_millis(shared.cache_lock_ms),
      rate_limits: pick(&shared.rate_limits_backend),
      connection_limits: pick(&shared.connection_limits_backend),
      person_proof: pick(&shared.person_proof_backend),
      upstream_health: pick(&shared.upstream_health_backend),
      cache: pick(&shared.cache_backend),
      reload: pick(&shared.reload_backend),
    });
    state.record_reload_generation(config);
    Ok(Some(state))
  }

  #[cfg(test)]
  pub fn test_memory(namespace: &str) -> Arc<Self> {
    let backend = Arc::new(Backend::Memory(MemoryBackend::default()));
    Arc::new(Self {
      namespace: Arc::from(namespace),
      instance_id: Arc::from("test-instance"),
      operation_timeout: Duration::from_millis(500),
      connection_lease: Duration::from_secs(30),
      cache_lock: Duration::from_secs(5),
      rate_limits: Some(backend.clone()),
      connection_limits: Some(backend.clone()),
      person_proof: Some(backend.clone()),
      upstream_health: Some(backend.clone()),
      cache: Some(backend.clone()),
      reload: Some(backend),
    })
  }

  pub fn has_rate_limits(&self) -> bool {
    self.rate_limits.is_some()
  }

  pub fn has_connection_limits(&self) -> bool {
    self.connection_limits.is_some()
  }

  pub fn has_person_proof(&self) -> bool {
    self.person_proof.is_some()
  }

  pub fn has_upstream_health(&self) -> bool {
    self.upstream_health.is_some()
  }

  pub fn has_cache(&self) -> bool {
    self.cache.is_some()
  }

  pub fn instance_id(&self) -> &str {
    &self.instance_id
  }

  pub fn take_rate_token(
    &self,
    name: &str,
    key: &str,
    rate: ParsedRate,
    burst: u32,
  ) -> anyhow::Result<bool> {
    let Some(backend) = &self.rate_limits else {
      return Ok(true);
    };
    let key = self.key(&format!("rate:{name}:{key}"));
    backend.rate_take(
      &key,
      rate.per_second(),
      burst.max(1),
      self.operation_timeout,
    )
  }

  pub fn acquire_connections(
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
    let denied = backend.connection_acquire(&keys, &limits, self.connection_lease)?;
    Ok(denied.map(|index| scopes[index].status))
  }

  pub fn release_connections(&self, scopes: &[String]) {
    let Some(backend) = &self.connection_limits else {
      return;
    };
    let keys = scopes
      .iter()
      .map(|scope| self.key(&format!("conn:{scope}")))
      .collect::<Vec<_>>();
    if let Err(error) = backend.connection_release(&keys) {
      warn!(error = %error, "failed to release shared connection limits");
    }
  }

  pub fn person_proof_secret(&self) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(backend) = &self.person_proof else {
      return Ok(None);
    };
    let key = self.key("person-proof:secret:v1");
    let secret = backend.get_or_init_bytes(&key, 32, None)?;
    let bytes: [u8; 32] = secret
      .as_slice()
      .try_into()
      .map_err(|_| anyhow!("shared person proof secret has invalid length"))?;
    Ok(Some(bytes))
  }

  pub fn person_proof_remember(&self, key: &str, expires_at_ms: i64) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(true);
    };
    let ttl = ttl_from_expires_ms(expires_at_ms);
    backend.put_if_absent(&self.key(&format!("person-proof:reuse:{key}")), b"1", ttl)
  }

  pub fn person_proof_consume(&self, key: &str) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(false);
    };
    backend.take_key(&self.key(&format!("person-proof:reuse:{key}")))
  }

  pub fn pool_health(&self, upstream_name: &str) -> anyhow::Result<Option<bool>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:health:{upstream_name}"));
    Ok(backend.health_get(&key)?.map(|record| record.healthy))
  }

  pub fn pool_report(
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
    Ok(Some(backend.health_report(
      &key,
      success,
      enabled,
      healthy_threshold,
      unhealthy_threshold,
    )?))
  }

  pub fn pool_active(&self, upstream_name: &str) -> anyhow::Result<Option<usize>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:active:{upstream_name}"));
    Ok(Some(backend.counter_get(&key)?))
  }

  pub fn pool_active_add(&self, upstream_name: &str, delta: i64) -> anyhow::Result<Option<usize>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:active:{upstream_name}"));
    Ok(Some(backend.counter_add(
      &key,
      delta,
      Some(self.connection_lease),
    )?))
  }

  #[allow(clippy::too_many_arguments)]
  pub fn cache_lookup(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    base_key: &str,
    uri: &str,
    method: &Method,
    request_headers: &HeaderMap,
    request_no_cache: bool,
  ) -> anyhow::Result<Option<CacheLookup>> {
    let Some(backend) = &self.cache else {
      return Ok(None);
    };
    let entries = backend.cache_entries(&self.key("cache:entry:"))?;
    let now = now_unix_ms();
    for entry in entries {
      if entry.policy != policy
        || entry.scheme != scheme
        || entry.host != host
        || entry.base_key != base_key
        || entry.uri != uri
        || !shared_vary_matches(&entry.vary, request_headers)
      {
        continue;
      }
      if entry.stale_if_error_until_ms.unwrap_or(entry.expires_at_ms) <= now {
        let _ = backend.delete(&self.key(&format!("cache:entry:{}", entry.variant_key)));
        continue;
      }
      let Some(cache_entry) = entry.to_cache_entry() else {
        continue;
      };
      if method == Method::HEAD {
        return Ok(Some(CacheLookup::Fresh(CacheEntry {
          body: bytes::Bytes::new(),
          ..cache_entry
        })));
      }
      if request_no_cache || entry.must_revalidate || entry.expires_at_ms <= now {
        let validators = validator_headers(&cache_entry.headers);
        if !request_no_cache
          && !entry.must_revalidate
          && entry
            .stale_while_revalidate_until_ms
            .is_some_and(|until| until > now)
        {
          return Ok(Some(CacheLookup::Stale(StaleEntry {
            entry: cache_entry,
            request_headers: validators,
            serve_stale_on_error: entry
              .stale_if_error_until_ms
              .is_some_and(|until| until > now),
            background_refresh: true,
          })));
        }
        if validators.is_empty() {
          if entry
            .stale_while_revalidate_until_ms
            .is_some_and(|until| until > now)
          {
            return Ok(Some(CacheLookup::Stale(StaleEntry {
              entry: cache_entry,
              request_headers: HeaderMap::new(),
              serve_stale_on_error: entry
                .stale_if_error_until_ms
                .is_some_and(|until| until > now),
              background_refresh: entry
                .stale_while_revalidate_until_ms
                .is_some_and(|until| until > now),
            })));
          }
          if entry
            .stale_if_error_until_ms
            .is_some_and(|until| until > now)
          {
            return Ok(Some(CacheLookup::Revalidate(Revalidation {
              entry: cache_entry,
              request_headers: HeaderMap::new(),
              serve_stale_on_error: true,
            })));
          }
          return Ok(None);
        }
        return Ok(Some(CacheLookup::Revalidate(Revalidation {
          entry: cache_entry,
          request_headers: validators,
          serve_stale_on_error: entry
            .stale_if_error_until_ms
            .is_some_and(|until| until > now),
        })));
      }
      return Ok(Some(CacheLookup::Fresh(cache_entry)));
    }
    Ok(None)
  }

  pub fn cache_put(&self, entry: &SharedCacheEntry) {
    let Some(backend) = &self.cache else {
      return;
    };
    let ttl = ttl_from_expires_ms(
      entry
        .stale_if_error_until_ms
        .unwrap_or(entry.expires_at_ms)
        .max(entry.expires_at_ms),
    );
    let key = self.key(&format!("cache:entry:{}", entry.variant_key));
    match serde_json::to_vec(entry)
      .map_err(Into::into)
      .and_then(|value| backend.put(&key, &value, ttl))
    {
      Ok(()) => {}
      Err(error) => warn!(error = %error, "failed to write shared cache entry"),
    }
  }

  pub fn cache_try_lock(&self, fill_key: &str) -> Option<SharedCacheLock> {
    let backend = self.cache.as_ref()?.clone();
    let key = self.key(&format!("cache:lock:{fill_key}"));
    let token = random_hex(16).ok()?;
    match backend.put_if_absent(&key, token.as_bytes(), Some(self.cache_lock)) {
      Ok(true) => Some(SharedCacheLock {
        backend,
        key,
        token,
      }),
      Ok(false) => None,
      Err(error) => {
        warn!(error = %error, "failed to acquire shared cache fill lock");
        None
      }
    }
  }

  pub fn cache_purge_exact(&self, policy: &str, scheme: &str, host: &str, uri: &str) -> usize {
    self.cache_purge(|entry| {
      entry.policy == policy && entry.scheme == scheme && entry.host == host && entry.uri == uri
    })
  }

  pub fn cache_purge_prefix(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    path_prefix: &str,
  ) -> usize {
    self.cache_purge(|entry| {
      entry.policy == policy
        && entry.scheme == scheme
        && entry.host == host
        && entry
          .uri
          .parse::<Uri>()
          .ok()
          .is_some_and(|uri| uri.path().starts_with(path_prefix))
    })
  }

  pub fn cache_purge_tag(
    &self,
    policy: &str,
    tag: &str,
    scheme: Option<&str>,
    host: Option<&str>,
  ) -> usize {
    self.cache_purge(|entry| {
      entry.policy == policy
        && scheme.is_none_or(|scheme| entry.scheme == scheme)
        && host.is_none_or(|host| entry.host == host)
        && entry.tags.iter().any(|candidate| candidate == tag)
    })
  }

  fn cache_purge(&self, matches: impl Fn(&SharedCacheEntry) -> bool) -> usize {
    let Some(backend) = &self.cache else {
      return 0;
    };
    let Ok(entries) = backend.cache_entries_with_keys(&self.key("cache:entry:")) else {
      return 0;
    };
    let mut purged = 0;
    for (key, entry) in entries {
      if matches(&entry) && backend.delete(&key).is_ok() {
        purged += 1;
      }
    }
    purged
  }

  pub fn record_reload_generation(&self, config: &Config) {
    let Some(backend) = &self.reload else {
      return;
    };
    let key = self.key(&format!("reload:instance:{}", self.instance_id));
    let hash = config_hash(config);
    let value = format!("{}:{}", now_unix_ms(), hash);
    if let Err(error) = backend.put(&key, value.as_bytes(), Some(Duration::from_secs(300))) {
      warn!(error = %error, "failed to write shared reload generation heartbeat");
    }
  }

  fn key(&self, suffix: &str) -> String {
    format!("{}:{suffix}", self.namespace)
  }
}

#[derive(Debug)]
pub struct SharedCacheLock {
  backend: Arc<Backend>,
  key: String,
  token: String,
}

impl Drop for SharedCacheLock {
  fn drop(&mut self) {
    if let Err(error) = self.backend.unlock(&self.key, &self.token) {
      warn!(error = %error, "failed to release shared cache fill lock");
    }
  }
}

impl SharedCacheEntry {
  pub fn to_cache_entry(&self) -> Option<CacheEntry> {
    let mut headers = HeaderMap::new();
    for (name, value) in &self.headers {
      let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
      let value = HeaderValue::from_bytes(value).ok()?;
      headers.append(name, value);
    }
    Some(CacheEntry {
      status: StatusCode::from_u16(self.status).ok()?,
      headers,
      body: bytes::Bytes::from(self.body.clone()),
    })
  }
}

impl Backend {
  async fn connect(config: &SharedStateBackendConfig, timeout_ms: u64) -> anyhow::Result<Self> {
    let timeout = Duration::from_millis(timeout_ms);
    match config.kind {
      SharedStateBackendKind::Redis => {
        let url = Url::parse(
          &config.connection_url_with_prefix(&format!("shared_state.backends.{}", config.name))?,
        )
        .with_context(|| format!("failed to parse shared_state Redis URL {}", config.name))?;
        Ok(Self::Redis(RedisBackend { url, timeout }))
      }
      SharedStateBackendKind::Postgres => {
        let connection_url =
          config.connection_url_with_prefix(&format!("shared_state.backends.{}", config.name))?;
        let pool = connect_postgres_pool(config, &connection_url)
          .await
          .with_context(|| {
            format!(
              "failed to connect shared_state PostgreSQL backend {}",
              config.name
            )
          })?;
        init_postgres(&pool).await?;
        Ok(Self::Postgres(PostgresBackend { pool, timeout }))
      }
    }
  }

  fn rate_take(
    &self,
    key: &str,
    rate_per_second: f64,
    burst: u32,
    timeout: Duration,
  ) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => redis.rate_take(key, rate_per_second, burst, timeout),
      Self::Postgres(pg) => pg.rate_take(key, rate_per_second, burst),
      #[cfg(test)]
      Self::Memory(memory) => memory.rate_take(key, rate_per_second, burst, timeout),
    }
  }

  fn connection_acquire(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
  ) -> anyhow::Result<Option<usize>> {
    match self {
      Self::Redis(redis) => redis.connection_acquire(keys, limits, ttl),
      Self::Postgres(pg) => pg.connection_acquire(keys, limits, ttl),
      #[cfg(test)]
      Self::Memory(memory) => memory.connection_acquire(keys, limits, ttl),
    }
  }

  fn connection_release(&self, keys: &[String]) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => redis.connection_release(keys),
      Self::Postgres(pg) => pg.connection_release(keys),
      #[cfg(test)]
      Self::Memory(memory) => memory.connection_release(keys),
    }
  }

  fn get_or_init_bytes(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    match self {
      Self::Redis(redis) => redis.get_or_init_bytes(key, len, ttl),
      Self::Postgres(pg) => pg.get_or_init_bytes(key, len, ttl),
      #[cfg(test)]
      Self::Memory(memory) => memory.get_or_init_bytes(key, len, ttl),
    }
  }

  fn put_if_absent(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => redis.put_if_absent(key, value, ttl),
      Self::Postgres(pg) => pg.put_if_absent(key, value, ttl),
      #[cfg(test)]
      Self::Memory(memory) => memory.put_if_absent(key, value, ttl),
    }
  }

  fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => redis.take_key(key),
      Self::Postgres(pg) => pg.take_key(key),
      #[cfg(test)]
      Self::Memory(memory) => memory.take_key(key),
    }
  }

  fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => redis.put(key, value, ttl),
      Self::Postgres(pg) => pg.put(key, value, ttl),
      #[cfg(test)]
      Self::Memory(memory) => memory.put(key, value, ttl),
    }
  }

  fn delete(&self, key: &str) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => redis.delete(key),
      Self::Postgres(pg) => pg.delete(key),
      #[cfg(test)]
      Self::Memory(memory) => memory.delete(key),
    }
  }

  fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    match self {
      Self::Redis(redis) => redis.unlock(key, token),
      Self::Postgres(pg) => pg.unlock(key, token),
      #[cfg(test)]
      Self::Memory(memory) => memory.unlock(key, token),
    }
  }

  fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    match self {
      Self::Redis(redis) => redis.health_get(key),
      Self::Postgres(pg) => pg.health_get(key),
      #[cfg(test)]
      Self::Memory(memory) => memory.health_get(key),
    }
  }

  fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => redis.health_report(
        key,
        success,
        enabled,
        healthy_threshold,
        unhealthy_threshold,
      ),
      Self::Postgres(pg) => pg.health_report(
        key,
        success,
        enabled,
        healthy_threshold,
        unhealthy_threshold,
      ),
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

  fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    match self {
      Self::Redis(redis) => redis.counter_get(key),
      Self::Postgres(pg) => pg.counter_get(key),
      #[cfg(test)]
      Self::Memory(memory) => memory.counter_get(key),
    }
  }

  fn counter_add(&self, key: &str, delta: i64, ttl: Option<Duration>) -> anyhow::Result<usize> {
    match self {
      Self::Redis(redis) => redis.counter_add(key, delta, ttl),
      Self::Postgres(pg) => pg.counter_add(key, delta, ttl),
      #[cfg(test)]
      Self::Memory(memory) => memory.counter_add(key, delta, ttl),
    }
  }

  fn cache_entries(&self, prefix: &str) -> anyhow::Result<Vec<SharedCacheEntry>> {
    Ok(
      self
        .cache_entries_with_keys(prefix)?
        .into_iter()
        .map(|(_, entry)| entry)
        .collect(),
    )
  }

  fn cache_entries_with_keys(
    &self,
    prefix: &str,
  ) -> anyhow::Result<Vec<(String, SharedCacheEntry)>> {
    match self {
      Self::Redis(redis) => redis.cache_entries(prefix),
      Self::Postgres(pg) => pg.cache_entries(prefix),
      #[cfg(test)]
      Self::Memory(memory) => memory.cache_entries(prefix),
    }
  }
}

#[cfg(test)]
impl MemoryBackend {
  fn rate_take(&self, key: &str, rate: f64, burst: u32, timeout: Duration) -> anyhow::Result<bool> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    let (mut tokens, last) = values
      .get(key)
      .and_then(|value| parse_rate_bucket(&value.value))
      .unwrap_or((f64::from(burst), now));
    tokens = (tokens + ((now - last).max(0) as f64 / 1000.0) * rate).min(f64::from(burst));
    let allowed = tokens >= 1.0;
    if allowed {
      tokens -= 1.0;
    }
    values.insert(
      key.to_string(),
      MemoryValue {
        value: format!("{tokens}:{now}").into_bytes(),
        expires_at_ms: Some(now + timeout.as_millis().min(i64::MAX as u128) as i64),
      },
    );
    Ok(allowed)
  }

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
    SystemRandom::new()
      .fill(&mut random)
      .map_err(|_| anyhow!("failed to generate shared state random bytes"))?;
    let _ = self.put_if_absent(key, &random, ttl)?;
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    values
      .get(key)
      .map(|value| value.value.clone())
      .ok_or_else(|| anyhow!("memory shared state key {key} did not contain bytes"))
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
    let now = now_unix_ms();
    self
      .values
      .lock()
      .expect("memory shared state lock poisoned")
      .insert(
        key.to_string(),
        MemoryValue {
          value: value.to_vec(),
          expires_at_ms: ttl.map(|ttl| now + ttl.as_millis().min(i64::MAX as u128) as i64),
        },
      );
    Ok(())
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
      .is_some_and(|value| value.value == token.as_bytes())
    {
      values.remove(key);
    }
    Ok(())
  }

  fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    values
      .get(key)
      .map(|value| serde_json::from_slice(&value.value).map_err(Into::into))
      .transpose()
  }

  fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    let mut record = self.health_get(key)?.unwrap_or_default();
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
    self.put(
      key,
      &serde_json::to_vec(&record)?,
      Some(Duration::from_secs(3600)),
    )?;
    Ok(record.healthy)
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
        .map(|item| item.counter)
        .unwrap_or(0)
        .max(0) as usize,
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

  fn cache_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, SharedCacheEntry)>> {
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
        .filter_map(|(key, value)| {
          serde_json::from_slice(&value.value)
            .ok()
            .map(|entry| (key.clone(), entry))
        })
        .collect(),
    )
  }
}

impl RedisBackend {
  fn command(&self, args: &[Vec<u8>]) -> anyhow::Result<Resp> {
    let host = self
      .url
      .host_str()
      .ok_or_else(|| anyhow!("Redis URL is missing host"))?;
    let port = self.url.port().unwrap_or(6379);
    let mut stream = TcpStream::connect((host, port))
      .with_context(|| format!("failed to connect Redis backend {host}:{port}"))?;
    stream.set_read_timeout(Some(self.timeout))?;
    stream.set_write_timeout(Some(self.timeout))?;

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
      write_resp_command(&mut stream, &auth)?;
      expect_ok(read_resp(&mut BufReader::new(stream.try_clone()?))?)?;
    }
    if let Some(db) = self
      .url
      .path()
      .strip_prefix('/')
      .filter(|value| !value.is_empty())
    {
      let select = vec![b"SELECT".to_vec(), db.as_bytes().to_vec()];
      write_resp_command(&mut stream, &select)?;
      expect_ok(read_resp(&mut BufReader::new(stream.try_clone()?))?)?;
    }

    write_resp_command(&mut stream, args)?;
    read_resp(&mut BufReader::new(stream)).context("failed to read Redis response")
  }

  fn rate_take(&self, key: &str, rate: f64, burst: u32, timeout: Duration) -> anyhow::Result<bool> {
    let script = r#"
local raw = redis.call('GET', KEYS[1])
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local tokens = burst
local last = now
if raw then
  local sep = string.find(raw, ':')
  if sep then
    tokens = tonumber(string.sub(raw, 1, sep - 1)) or burst
    last = tonumber(string.sub(raw, sep + 1)) or now
  end
end
tokens = math.min(burst, tokens + ((now - last) / 1000.0) * rate)
if tokens < 1.0 then
  redis.call('PSETEX', KEYS[1], ttl, tostring(tokens) .. ':' .. tostring(now))
  return 0
end
tokens = tokens - 1.0
redis.call('PSETEX', KEYS[1], ttl, tostring(tokens) .. ':' .. tostring(now))
return 1
"#;
    let ttl = timeout
      .max(Duration::from_secs(1))
      .as_millis()
      .min(i64::MAX as u128) as i64;
    let resp = self.command(&[
      b"EVAL".to_vec(),
      script.as_bytes().to_vec(),
      b"1".to_vec(),
      key.as_bytes().to_vec(),
      now_unix_ms().to_string().into_bytes(),
      rate.to_string().into_bytes(),
      burst.to_string().into_bytes(),
      ttl.to_string().into_bytes(),
    ])?;
    Ok(resp.into_i64()? == 1)
  }

  fn connection_acquire(
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
    let value = self.command(&args)?.into_i64()?;
    Ok((value > 0).then_some(value as usize - 1))
  }

  fn connection_release(&self, keys: &[String]) -> anyhow::Result<()> {
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
    let _ = self.command(&args)?;
    Ok(())
  }

  fn get_or_init_bytes(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    let mut value = vec![0u8; len];
    SystemRandom::new()
      .fill(&mut value)
      .map_err(|_| anyhow!("failed to generate shared state random bytes"))?;
    let _ = self.put_if_absent(key, &value, ttl)?;
    match self.command(&[b"GET".to_vec(), key.as_bytes().to_vec()])? {
      Resp::Bulk(Some(bytes)) => Ok(bytes),
      _ => bail!("shared Redis key {key} did not contain bytes"),
    }
  }

  fn put_if_absent(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<bool> {
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
    match self.command(&args)? {
      Resp::Simple(value) if value == "OK" => Ok(true),
      Resp::Bulk(None) => Ok(false),
      Resp::Nil => Ok(false),
      other => bail!("unexpected Redis SET NX response: {other:?}"),
    }
  }

  fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    let script = "local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]); return 1; end; return 0";
    Ok(
      self
        .command(&[
          b"EVAL".to_vec(),
          script.as_bytes().to_vec(),
          b"1".to_vec(),
          key.as_bytes().to_vec(),
        ])?
        .into_i64()?
        == 1,
    )
  }

  fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<()> {
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
    expect_ok(self.command(&args)?)
  }

  fn delete(&self, key: &str) -> anyhow::Result<()> {
    let _ = self.command(&[b"DEL".to_vec(), key.as_bytes().to_vec()])?;
    Ok(())
  }

  fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    let script = "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]); end; return 0";
    let _ = self.command(&[
      b"EVAL".to_vec(),
      script.as_bytes().to_vec(),
      b"1".to_vec(),
      key.as_bytes().to_vec(),
      token.as_bytes().to_vec(),
    ])?;
    Ok(())
  }

  fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    match self.command(&[b"GET".to_vec(), key.as_bytes().to_vec()])? {
      Resp::Bulk(Some(bytes)) => Ok(Some(serde_json::from_slice(&bytes)?)),
      Resp::Bulk(None) | Resp::Nil => Ok(None),
      other => bail!("unexpected Redis health response: {other:?}"),
    }
  }

  fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    let mut record = self.health_get(key)?.unwrap_or_default();
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
    self.put(
      key,
      &serde_json::to_vec(&record)?,
      Some(Duration::from_secs(3600)),
    )?;
    Ok(record.healthy)
  }

  fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    match self.command(&[b"GET".to_vec(), key.as_bytes().to_vec()])? {
      Resp::Bulk(Some(bytes)) => Ok(
        String::from_utf8_lossy(&bytes)
          .parse::<usize>()
          .unwrap_or(0),
      ),
      Resp::Bulk(None) | Resp::Nil => Ok(0),
      other => bail!("unexpected Redis counter response: {other:?}"),
    }
  }

  fn counter_add(&self, key: &str, delta: i64, ttl: Option<Duration>) -> anyhow::Result<usize> {
    let value = self
      .command(&[
        b"INCRBY".to_vec(),
        key.as_bytes().to_vec(),
        delta.to_string().into_bytes(),
      ])?
      .into_i64()?
      .max(0) as usize;
    if let Some(ttl) = ttl {
      let _ = self.command(&[
        b"PEXPIRE".to_vec(),
        key.as_bytes().to_vec(),
        ttl
          .as_millis()
          .min(i64::MAX as u128)
          .to_string()
          .into_bytes(),
      ]);
    }
    Ok(value)
  }

  fn cache_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, SharedCacheEntry)>> {
    let pattern = format!("{prefix}*");
    let keys = match self.command(&[b"KEYS".to_vec(), pattern.as_bytes().to_vec()])? {
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
      if let Resp::Bulk(Some(bytes)) = self.command(&[b"GET".to_vec(), key.as_bytes().to_vec()])?
        && let Ok(entry) = serde_json::from_slice::<SharedCacheEntry>(&bytes)
      {
        entries.push((key, entry));
      }
    }
    Ok(entries)
  }
}

impl PostgresBackend {
  fn rate_take(&self, key: &str, rate: f64, burst: u32) -> anyhow::Result<bool> {
    block_on_timeout(self.timeout, async {
      let mut tx = self.pool.begin().await?;
      let now = now_unix_ms();
      let raw: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT value FROM oxibelt_shared_state WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2) FOR UPDATE",
      )
      .bind(key)
      .bind(now)
      .fetch_optional(&mut *tx)
      .await?;
      let (mut tokens, last) = raw
        .as_deref()
        .and_then(parse_rate_bucket)
        .unwrap_or((f64::from(burst), now));
      tokens = (tokens + ((now - last).max(0) as f64 / 1000.0) * rate).min(f64::from(burst));
      let allowed = tokens >= 1.0;
      if allowed {
        tokens -= 1.0;
      }
      let value = format!("{tokens}:{now}").into_bytes();
      sqlx::query(
        "INSERT INTO oxibelt_shared_state (key, value, expires_at_ms) VALUES ($1, $2, $3)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires_at_ms = EXCLUDED.expires_at_ms",
      )
      .bind(key)
      .bind(value)
      .bind(now + 60_000)
      .execute(&mut *tx)
      .await?;
      tx.commit().await?;
      Ok(allowed)
    })
  }

  fn connection_acquire(
    &self,
    keys: &[String],
    limits: &[usize],
    ttl: Duration,
  ) -> anyhow::Result<Option<usize>> {
    block_on_timeout(self.timeout, async {
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
    })
  }

  fn connection_release(&self, keys: &[String]) -> anyhow::Result<()> {
    block_on_timeout(self.timeout, async {
      for key in keys {
        sqlx::query(
          "UPDATE oxibelt_shared_counters SET counter = GREATEST(counter - 1, 0) WHERE key = $1",
        )
        .bind(key)
        .execute(&self.pool)
        .await?;
      }
      Ok(())
    })
  }

  fn get_or_init_bytes(
    &self,
    key: &str,
    len: usize,
    ttl: Option<Duration>,
  ) -> anyhow::Result<Vec<u8>> {
    let mut random = vec![0u8; len];
    SystemRandom::new()
      .fill(&mut random)
      .map_err(|_| anyhow!("failed to generate shared state random bytes"))?;
    let _ = self.put_if_absent(key, &random, ttl)?;
    block_on_timeout(self.timeout, async {
      sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT value FROM oxibelt_shared_state WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
      )
      .bind(key)
      .bind(now_unix_ms())
      .fetch_one(&self.pool)
      .await
      .map_err(Into::into)
    })
  }

  fn put_if_absent(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<bool> {
    let expires = ttl.map(|ttl| now_unix_ms() + ttl.as_millis().min(i64::MAX as u128) as i64);
    block_on_timeout(self.timeout, async {
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
    })
  }

  fn take_key(&self, key: &str) -> anyhow::Result<bool> {
    block_on_timeout(self.timeout, async {
      let result = sqlx::query(
        "DELETE FROM oxibelt_shared_state WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
      )
      .bind(key)
      .bind(now_unix_ms())
      .execute(&self.pool)
      .await?;
      Ok(result.rows_affected() > 0)
    })
  }

  fn put(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> anyhow::Result<()> {
    let expires = ttl.map(|ttl| now_unix_ms() + ttl.as_millis().min(i64::MAX as u128) as i64);
    block_on_timeout(self.timeout, async {
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
    })
  }

  fn delete(&self, key: &str) -> anyhow::Result<()> {
    block_on_timeout(self.timeout, async {
      sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = $1")
        .bind(key)
        .execute(&self.pool)
        .await?;
      Ok(())
    })
  }

  fn unlock(&self, key: &str, token: &str) -> anyhow::Result<()> {
    block_on_timeout(self.timeout, async {
      sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = $1 AND value = $2")
        .bind(key)
        .bind(token.as_bytes())
        .execute(&self.pool)
        .await?;
      Ok(())
    })
  }

  fn health_get(&self, key: &str) -> anyhow::Result<Option<HealthRecord>> {
    block_on_timeout(self.timeout, async {
      let raw: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM oxibelt_shared_state WHERE key = $1")
          .bind(key)
          .fetch_optional(&self.pool)
          .await?;
      raw
        .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .transpose()
    })
  }

  fn health_report(
    &self,
    key: &str,
    success: bool,
    enabled: bool,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
  ) -> anyhow::Result<bool> {
    block_on_timeout(self.timeout, async {
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
    })
  }

  fn counter_get(&self, key: &str) -> anyhow::Result<usize> {
    block_on_timeout(self.timeout, async {
      let value: Option<i64> = sqlx::query_scalar(
        "SELECT counter FROM oxibelt_shared_counters WHERE key = $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
      )
      .bind(key)
      .bind(now_unix_ms())
      .fetch_optional(&self.pool)
      .await?;
      Ok(value.unwrap_or(0).max(0) as usize)
    })
  }

  fn counter_add(&self, key: &str, delta: i64, ttl: Option<Duration>) -> anyhow::Result<usize> {
    let expires = ttl.map(|ttl| now_unix_ms() + ttl.as_millis().min(i64::MAX as u128) as i64);
    block_on_timeout(self.timeout, async {
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
    })
  }

  fn cache_entries(&self, prefix: &str) -> anyhow::Result<Vec<(String, SharedCacheEntry)>> {
    let pattern = format!("{prefix}%");
    block_on_timeout(self.timeout, async {
      let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT key, value FROM oxibelt_shared_state WHERE key LIKE $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
      )
      .bind(pattern)
      .bind(now_unix_ms())
      .fetch_all(&self.pool)
      .await?;
      Ok(
        rows
          .into_iter()
          .filter_map(|(key, value)| {
            serde_json::from_slice(&value)
              .ok()
              .map(|entry| (key, entry))
          })
          .collect(),
      )
    })
  }
}

async fn connect_postgres_pool(
  config: &SharedStateBackendConfig,
  connection_url: &str,
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
    .acquire_timeout(Duration::from_millis(config.connect_timeout_ms))
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
  Ok(())
}

fn block_on_timeout<F, T>(timeout: Duration, future: F) -> anyhow::Result<T>
where
  F: Future<Output = anyhow::Result<T>>,
{
  let handle = Handle::try_current().context("shared state operation requires a Tokio runtime")?;
  tokio::task::block_in_place(|| {
    handle
      .block_on(tokio::time::timeout(timeout, future))
      .context("shared state operation timed out")?
  })
}

#[derive(Debug)]
enum Resp {
  Simple(String),
  Error(String),
  Int(i64),
  Bulk(Option<Vec<u8>>),
  Array(Vec<Resp>),
  Nil,
}

impl Resp {
  fn into_i64(self) -> anyhow::Result<i64> {
    match self {
      Resp::Int(value) => Ok(value),
      Resp::Bulk(Some(bytes)) => String::from_utf8(bytes)?.parse().map_err(Into::into),
      other => bail!("expected Redis integer response, got {other:?}"),
    }
  }
}

fn write_resp_command(stream: &mut TcpStream, args: &[Vec<u8>]) -> anyhow::Result<()> {
  write!(stream, "*{}\r\n", args.len())?;
  for arg in args {
    write!(stream, "${}\r\n", arg.len())?;
    stream.write_all(arg)?;
    stream.write_all(b"\r\n")?;
  }
  stream.flush()?;
  Ok(())
}

fn read_resp(reader: &mut BufReader<TcpStream>) -> anyhow::Result<Resp> {
  let mut prefix = [0u8; 1];
  reader.read_exact(&mut prefix)?;
  match prefix[0] {
    b'+' => Ok(Resp::Simple(read_line(reader)?)),
    b'-' => Ok(Resp::Error(read_line(reader)?)),
    b':' => Ok(Resp::Int(read_line(reader)?.parse()?)),
    b'$' => {
      let len = read_line(reader)?.parse::<isize>()?;
      if len < 0 {
        return Ok(Resp::Nil);
      }
      let mut bytes = vec![0u8; len as usize];
      reader.read_exact(&mut bytes)?;
      read_crlf(reader)?;
      Ok(Resp::Bulk(Some(bytes)))
    }
    b'*' => {
      let len = read_line(reader)?.parse::<isize>()?;
      if len < 0 {
        return Ok(Resp::Nil);
      }
      let mut items = Vec::with_capacity(len as usize);
      for _ in 0..len {
        items.push(read_resp(reader)?);
      }
      Ok(Resp::Array(items))
    }
    other => bail!("unsupported Redis response prefix {}", other as char),
  }
}

fn read_line(reader: &mut BufReader<TcpStream>) -> anyhow::Result<String> {
  let mut line = String::new();
  reader.read_line(&mut line)?;
  Ok(line.trim_end_matches("\r\n").to_string())
}

fn read_crlf(reader: &mut BufReader<TcpStream>) -> anyhow::Result<()> {
  let mut crlf = [0u8; 2];
  reader.read_exact(&mut crlf)?;
  if crlf != *b"\r\n" {
    bail!("invalid Redis bulk terminator");
  }
  Ok(())
}

fn expect_ok(resp: Resp) -> anyhow::Result<()> {
  match resp {
    Resp::Simple(value) if value == "OK" => Ok(()),
    Resp::Int(_) => Ok(()),
    Resp::Error(error) => bail!("Redis error: {error}"),
    other => bail!("unexpected Redis response: {other:?}"),
  }
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

fn validator_headers(headers: &HeaderMap) -> HeaderMap {
  let mut validators = HeaderMap::new();
  if let Some(etag) = headers.get(http::header::ETAG) {
    validators.insert(http::header::IF_NONE_MATCH, etag.clone());
  }
  if let Some(last_modified) = headers.get(http::header::LAST_MODIFIED) {
    validators.insert(http::header::IF_MODIFIED_SINCE, last_modified.clone());
  }
  validators
}

fn shared_vary_matches(vary: &[SharedVaryMatcher], request_headers: &HeaderMap) -> bool {
  vary
    .iter()
    .all(|item| header_values(request_headers, &item.name) == item.value)
}

pub fn shared_header_values(headers: &HeaderMap, name: &str) -> String {
  header_values(headers, name)
}

fn header_values(headers: &HeaderMap, name: &str) -> String {
  HeaderName::from_bytes(name.as_bytes())
    .ok()
    .map(|name| {
      headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
    })
    .unwrap_or_default()
}

fn ttl_from_expires_ms(expires_at_ms: i64) -> Option<Duration> {
  let now = now_unix_ms();
  (expires_at_ms > now).then_some(Duration::from_millis((expires_at_ms - now) as u64))
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
  SystemRandom::new()
    .fill(&mut value)
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
  let digest = ring::digest::digest(&ring::digest::SHA256, format!("{config:?}").as_bytes());
  hex_encode(digest.as_ref())
}
