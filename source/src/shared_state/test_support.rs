//! Test-only shared-state backends for focused runtime validation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::failure_policy::{BackendFailureBinding, BackendFailureRegistry};
use super::redis_pool::RedisPool;
use super::runtime::{BackendRuntime, CleanupDispatcher};
use super::{Backend, MemoryBackend, RedisBackend, SharedState};
use crate::config::{
  CryptoConfig, RedisPlaintextPolicy, SharedStateBackendConfig, SharedStateBackendKind,
  SharedStateFailurePolicies,
};
use crate::metrics::Metrics;

impl SharedState {
  pub fn test_memory(namespace: &str) -> Arc<Self> {
    Self::test_memory_with_failure_policies(namespace, SharedStateFailurePolicies::default())
  }

  pub(crate) fn test_memory_with_failure_policies(
    namespace: &str,
    policies: SharedStateFailurePolicies,
  ) -> Arc<Self> {
    let backend = Arc::new(Backend::Memory(MemoryBackend::default()));
    let failure_registry = Arc::new(BackendFailureRegistry::new(
      &policies,
      [
        BackendFailureBinding::from_backend(Some(backend.as_ref())),
        BackendFailureBinding::from_backend(Some(backend.as_ref())),
        BackendFailureBinding::from_backend(Some(backend.as_ref())),
        BackendFailureBinding::from_backend(Some(backend.as_ref())),
        BackendFailureBinding::from_backend(Some(backend.as_ref())),
        BackendFailureBinding::from_backend(Some(backend.as_ref())),
        BackendFailureBinding::from_backend(Some(backend.as_ref())),
      ],
      Metrics::new(),
    ));
    Arc::new(Self {
      namespace: Arc::from(namespace),
      instance_id: Arc::from("test-instance"),
      connection_lease: Duration::from_secs(30),
      cache_lock: Duration::from_secs(5),
      cache_chunk_bytes: 1_048_576,
      operation_timeout: Duration::from_millis(500),
      enumeration: super::enumeration::EnumerationLimits {
        page_size: 128,
        max_items: 4_096,
      },
      backends: HashMap::new(),
      rate_limits: Some(backend.clone()),
      connection_limits: Some(backend.clone()),
      person_proof: Some(backend.clone()),
      upstream_health: Some(backend.clone()),
      pool_warning_limiter: Arc::default(),
      sticky_sessions: Some(backend.clone()),
      cache: Some(backend.clone()),
      reload: Some(backend),
      failure_registry,
      cleanup: CleanupDispatcher::new(),
    })
  }

  pub(crate) fn test_fail_next_rate_limit(&self) {
    if let Some(Backend::Memory(memory)) = self.rate_limits.as_deref() {
      memory.inject_failure_once();
    }
  }

  pub(crate) fn test_fail_next_connection_limit(&self) {
    if let Some(Backend::Memory(memory)) = self.connection_limits.as_deref() {
      memory.inject_failure_once();
    }
  }

  pub(crate) fn test_memory_with_enumeration_limits(
    namespace: &str,
    page_size: usize,
    max_items: usize,
  ) -> Arc<Self> {
    let mut state = Self::test_memory(namespace);
    Arc::get_mut(&mut state)
      .expect("test shared state should have one owner")
      .enumeration = super::enumeration::EnumerationLimits {
      page_size,
      max_items,
    };
    state
  }

  pub(crate) fn test_redis(namespace: &str, url: &str, metrics: Arc<Metrics>) -> Arc<Self> {
    Self::test_redis_with_features(namespace, url, metrics, false, false)
  }

  pub(crate) fn test_redis_with_features(
    namespace: &str,
    url: &str,
    metrics: Arc<Metrics>,
    person_proof: bool,
    cache: bool,
  ) -> Arc<Self> {
    let config = SharedStateBackendConfig {
      name: "pool-warning-test".to_string(),
      kind: SharedStateBackendKind::Redis,
      connection_url: Some(url.to_string()),
      connection_url_env: None,
      max_connections: 64,
      connect_timeout_ms: 100,
      redis_pool: None,
      redis_tls: Default::default(),
      redis_auth: Default::default(),
      tls: Default::default(),
    };
    let backend = Arc::new(Backend::Redis(RedisBackend {
      pool: RedisPool::new(
        &config,
        Duration::from_millis(250),
        &CryptoConfig::default(),
        RedisPlaintextPolicy::Allow,
        metrics.clone(),
      )
      .expect("test Redis pool should build"),
      runtime: BackendRuntime::new(
        &config,
        "redis",
        Duration::from_millis(250),
        metrics.clone(),
      ),
    }));
    let mut backends = HashMap::new();
    backends.insert(config.name.clone(), backend.clone());
    let failure_registry = Arc::new(BackendFailureRegistry::new(
      &SharedStateFailurePolicies::default(),
      [
        BackendFailureBinding::from_backend(None),
        BackendFailureBinding::from_backend(None),
        BackendFailureBinding::from_backend(person_proof.then_some(backend.as_ref())),
        BackendFailureBinding::from_backend(Some(backend.as_ref())),
        BackendFailureBinding::from_backend(None),
        BackendFailureBinding::from_backend(cache.then_some(backend.as_ref())),
        BackendFailureBinding::from_backend(None),
      ],
      metrics,
    ));
    Arc::new(Self {
      namespace: Arc::from(namespace),
      instance_id: Arc::from("test-instance"),
      connection_lease: Duration::from_secs(30),
      cache_lock: Duration::from_secs(5),
      cache_chunk_bytes: 1_048_576,
      operation_timeout: Duration::from_millis(250),
      enumeration: super::enumeration::EnumerationLimits {
        page_size: 128,
        max_items: 4_096,
      },
      backends,
      rate_limits: None,
      connection_limits: None,
      person_proof: person_proof.then_some(backend.clone()),
      upstream_health: Some(backend.clone()),
      pool_warning_limiter: Arc::default(),
      sticky_sessions: None,
      cache: cache.then_some(backend.clone()),
      reload: None,
      failure_registry,
      cleanup: CleanupDispatcher::new(),
    })
  }
}
