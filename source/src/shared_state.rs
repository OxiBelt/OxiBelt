//! Cross-worker shared state containers.
//! Optional backends are hidden behind stable runtime handles so callers keep the same semantics.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use base64::Engine as _;
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
mod backend_dispatch;
#[cfg(test)]
mod backend_memory;
mod backend_postgres;
mod backend_redis;
mod cache_lock;
mod cache_store;
mod enumeration;
mod failure_epoch;
mod failure_policy;
mod feature_flags;
mod helpers;
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
mod udp_flows;

use failure_policy::{BackendFailureBinding, BackendFailureRegistry};
use redis_pool::RedisPool;
use redis_protocol::{Resp, expect_ok};
use runtime::{BackendRuntime, CleanupDispatcher, SharedPoolWarningLimiter};

pub(crate) use backend_dispatch::probe_redis_backend;
use backend_dispatch::{connection_lease_fingerprint, counter_lease_fingerprint};
use backend_postgres::{connect_postgres_pool, init_postgres};
pub use cache_lock::SharedCacheLock;
pub use cache_store::shared_header_values;
#[cfg(feature = "admin-runtime")]
pub(crate) use failure_policy::BackendFeatureFailureStatus;
pub(crate) use failure_policy::SharedStateFeature;
pub use helpers::now_unix_ms;
use helpers::{
  config_hash, hex_encode, parse_rate_bucket, random_hex, rate_bucket_ttl, ttl_from_expires_ms,
};
#[cfg(test)]
use helpers::{purge_expired_counters, purge_expired_values};
#[cfg(feature = "admin-runtime")]
pub use person_proof::{
  PersonProofSharedClearance, PersonProofSharedClearancePage, PersonProofSharedStatus,
};
pub(crate) use udp_flows::{
  UdpFlowClaimOutcome, UdpFlowClaimRequest, UdpFlowConnectionMarker, UdpFlowLease,
  UdpFlowLookupOutcome, UdpFlowOwner, UdpFlowRateLimit, UdpFlowReleaseOutcome, UdpFlowStore,
  UdpFlowTarget, UdpFlowTokenOutcome, UdpFlowTokenRequest, UdpFlowTouchOutcome,
  UdpFlowTouchRequest,
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
  udp_flows: Option<UdpFlowStore>,
  udp_flow_boot_generation: Arc<[u8; 32]>,
  person_proof: Option<Arc<Backend>>,
  upstream_health: Option<Arc<Backend>>,
  pool_warning_limiter: Arc<SharedPoolWarningLimiter>,
  sticky_sessions: Option<Arc<Backend>>,
  cache: Option<Arc<Backend>>,
  reload: Option<Arc<Backend>>,
  failure_registry: Arc<BackendFailureRegistry>,
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
  udp_flows: Arc<Mutex<HashMap<String, udp_flows::MemoryUdpFlowScope>>>,
  fail_next_operation: Arc<AtomicBool>,
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
  configuration_fingerprint: String,
  adoptable: bool,
  keys: Vec<String>,
}

impl SharedCounterLease {
  fn new(marker_key: String, fingerprint: String, keys: Vec<String>) -> Self {
    Self {
      marker_key,
      configuration_fingerprint: fingerprint.clone(),
      fingerprint,
      adoptable: false,
      keys,
    }
  }

  fn new_adoptable(
    marker_key: String,
    configuration_fingerprint: String,
    holder_fingerprint: String,
    keys: Vec<String>,
  ) -> anyhow::Result<Self> {
    if !is_lower_hex_digest(&configuration_fingerprint) || !is_lower_hex_digest(&holder_fingerprint)
    {
      bail!("adoptable shared connection lease fingerprints must be SHA-256 hex digests");
    }
    Ok(Self {
      marker_key,
      fingerprint: format!("{configuration_fingerprint}:{holder_fingerprint}"),
      configuration_fingerprint,
      adoptable: true,
      keys,
    })
  }

  fn stored_configuration_fingerprint(value: &[u8]) -> Option<&[u8]> {
    (value.len() == 129
      && value.get(64) == Some(&b':')
      && is_lower_hex_bytes(&value[..64])
      && is_lower_hex_bytes(&value[65..]))
    .then_some(&value[..64])
  }
}

fn is_lower_hex_digest(value: &str) -> bool {
  value.len() == 64 && is_lower_hex_bytes(value.as_bytes())
}

fn is_lower_hex_bytes(value: &[u8]) -> bool {
  value
    .iter()
    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct PersonProofRevocationResult {
  pub(crate) removed_active: bool,
  pub(crate) expires_at_ms: i64,
}

/// Digest-only idempotency material for the narrow Person-proof Admin
/// mutation. Raw header values never reach storage or log fields.
#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone)]
pub(crate) struct PersonProofRevocationIdempotency {
  pub(crate) key_digest: String,
  pub(crate) request_fingerprint: String,
}

#[cfg(feature = "admin-runtime")]
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

#[cfg(feature = "admin-runtime")]
#[derive(Debug)]
pub(crate) struct PersonProofIdempotencyConflict;

#[cfg(feature = "admin-runtime")]
impl std::fmt::Display for PersonProofIdempotencyConflict {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("person proof idempotency key was reused with a different request")
  }
}

#[cfg(feature = "admin-runtime")]
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

fn load_udp_flow_identity_secret(env_name: &str) -> anyhow::Result<[u8; 32]> {
  let encoded = zeroize::Zeroizing::new(std::env::var(env_name).with_context(|| {
    format!("failed to read shared_state.udp_flow_identity_key_env {env_name}")
  })?);
  let decoded = zeroize::Zeroizing::new(
    base64::engine::general_purpose::STANDARD
      .decode(encoded.trim())
      .context("shared_state.udp_flow_identity_key_env must contain base64")?,
  );
  decoded
    .as_slice()
    .try_into()
    .map_err(|_| anyhow!("shared_state.udp_flow_identity_key_env must contain exactly 32 bytes"))
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
    let udp_flow_backend = shared
      .udp_flows_backend
      .as_deref()
      .and_then(|name| backends.get(name).cloned());
    let udp_flow_boot_generation = match previous {
      Some(state) => state.udp_flow_boot_generation.clone(),
      None => {
        let mut generation = [0_u8; 32];
        crate::crypto::random_fill(&mut generation)
          .context("failed to generate durable UDP flow boot generation")?;
        Arc::new(generation)
      }
    };
    let namespace: Arc<str> = Arc::from(shared.namespace.as_str());
    let person_proof = pick(&shared.person_proof_backend);
    let upstream_health = pick(&shared.upstream_health_backend);
    let sticky_sessions = pick(&shared.sticky_sessions_backend);
    let cache = pick(&shared.cache_backend);
    let reload = pick(&shared.reload_backend);
    let failure_registry = Arc::new(BackendFailureRegistry::new(
      &shared.failure_policies,
      [
        BackendFailureBinding::from_backend(rate_limits.as_deref()),
        BackendFailureBinding::from_backend(connection_limits.as_deref()),
        BackendFailureBinding::from_backend(udp_flow_backend.as_deref()),
        BackendFailureBinding::from_backend(person_proof.as_deref()),
        BackendFailureBinding::from_backend(upstream_health.as_deref()),
        BackendFailureBinding::from_backend(sticky_sessions.as_deref()),
        BackendFailureBinding::from_backend(cache.as_deref()),
        BackendFailureBinding::from_backend(reload.as_deref()),
      ],
      metrics,
    ));
    let udp_flows = udp_flow_backend
      .as_ref()
      .map(|backend| {
        load_udp_flow_identity_secret(&shared.udp_flow_identity_key_env).map(|secret| {
          UdpFlowStore::new(
            namespace.clone(),
            backend.clone(),
            secret,
            udp_flow_boot_generation.clone(),
            failure_registry.clone(),
          )
        })
      })
      .transpose()?;
    let state = Arc::new(Self {
      namespace,
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
      udp_flows,
      udp_flow_boot_generation,
      person_proof,
      upstream_health,
      pool_warning_limiter: Self::inherited_pool_warning_limiter(previous),
      sticky_sessions,
      cache,
      reload,
      failure_registry,
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

  pub(crate) fn backend_failure_mode(
    &self,
    feature: SharedStateFeature,
  ) -> crate::config::BackendFailureMode {
    self.failure_registry.mode(feature)
  }

  pub(crate) fn record_backend_local_fallback(&self, feature: SharedStateFeature) {
    self.failure_registry.record_local_fallback(feature);
  }

  pub(crate) fn record_backend_stale_snapshot(&self, feature: SharedStateFeature) {
    self.failure_registry.record_stale_snapshot(feature);
  }

  pub(crate) fn backend_failure_status(&self) -> &'static str {
    if self.failure_registry.is_degraded() {
      "degraded"
    } else {
      "healthy"
    }
  }

  #[cfg(feature = "admin-runtime")]
  pub(crate) fn backend_failure_statuses(&self) -> Vec<BackendFeatureFailureStatus> {
    self.failure_registry.statuses()
  }

  fn observe_backend_result<T>(&self, feature: SharedStateFeature, result: &anyhow::Result<T>) {
    if result.is_ok() {
      self.failure_registry.record_success(feature);
    } else {
      self.failure_registry.record_failure(feature);
    }
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
    let result = backend
      .rate_take(
        &index_key,
        &bucket_key,
        rate.per_second(),
        burst.max(1),
        max_buckets.max(1),
        rate_bucket_ttl(rate, burst),
      )
      .await;
    self.observe_backend_result(SharedStateFeature::RateLimits, &result);
    result
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
    let result = backend
      .rate_take_bucket(
        &key,
        rate.per_second(),
        burst.max(1),
        rate_bucket_ttl(rate, burst),
      )
      .await;
    self.observe_backend_result(SharedStateFeature::RateLimits, &result);
    result
  }

  pub(crate) async fn acquire_connections(
    &self,
    scopes: &[ConnectionScope<'_>],
  ) -> anyhow::Result<SharedConnectionAcquire> {
    self.acquire_connections_inner(scopes, None).await
  }

  pub(crate) async fn acquire_connections_with_udp_marker(
    &self,
    scopes: &[ConnectionScope<'_>],
    marker: &UdpFlowConnectionMarker,
  ) -> anyhow::Result<SharedConnectionAcquire> {
    self.acquire_connections_inner(scopes, Some(marker)).await
  }

  async fn acquire_connections_inner(
    &self,
    scopes: &[ConnectionScope<'_>],
    udp_marker: Option<&UdpFlowConnectionMarker>,
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
    let configuration_fingerprint =
      connection_lease_fingerprint(&keys, &limits, self.connection_lease);
    let lease = if let Some(marker) = udp_marker {
      SharedCounterLease::new_adoptable(
        self.key(&format!("lease:connection:udp:{}", marker.marker_hex())),
        configuration_fingerprint,
        marker.holder_hex(),
        keys,
      )?
    } else {
      SharedCounterLease::new(
        self.key(&format!("lease:connection:{}", random_hex(16)?)),
        configuration_fingerprint,
        keys,
      )
    };
    let result = match backend
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
    };
    self.observe_backend_result(SharedStateFeature::ConnectionLimits, &result);
    result
  }

  pub(crate) async fn release_connections(&self, lease: SharedCounterLease) {
    if lease.marker_key.is_empty() {
      return;
    }
    let Some(backend) = &self.connection_limits else {
      return;
    };
    let result = backend.connection_release(&lease).await;
    self.observe_backend_result(SharedStateFeature::ConnectionLimits, &result);
    if let Err(error) = result {
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
    let result = backend.health_get(&key).await;
    self.observe_backend_result(SharedStateFeature::UpstreamHealth, &result);
    Ok(result?.map(|record| record.healthy))
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
    let result = backend
      .health_report(
        &key,
        success,
        enabled,
        healthy_threshold,
        unhealthy_threshold,
      )
      .await;
    self.observe_backend_result(SharedStateFeature::UpstreamHealth, &result);
    Ok(Some(result?))
  }

  pub async fn pool_active(&self, upstream_name: &str) -> anyhow::Result<Option<usize>> {
    let Some(backend) = &self.upstream_health else {
      return Ok(None);
    };
    let key = self.key(&format!("pool:active:{upstream_name}"));
    let result = backend.counter_get(&key).await;
    self.observe_backend_result(SharedStateFeature::UpstreamHealth, &result);
    Ok(Some(result?))
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
    let result = backend
      .counter_add(&key, delta, Some(self.connection_lease))
      .await;
    self.observe_backend_result(SharedStateFeature::UpstreamHealth, &result);
    Ok(Some(result?))
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
    let result = match backend
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
    };
    self.observe_backend_result(SharedStateFeature::UpstreamHealth, &result);
    result
  }

  pub async fn record_reload_generation(&self, config: &Config) {
    let Some(backend) = &self.reload else {
      return;
    };
    let key = self.key(&format!("reload:instance:{}", self.instance_id));
    let hash = config_hash(config);
    let value = format!("{}:{}", now_unix_ms(), hash);
    let result = backend
      .put(&key, value.as_bytes(), Some(Duration::from_secs(300)))
      .await;
    self.observe_backend_result(SharedStateFeature::Reload, &result);
    if let Err(error) = result {
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
