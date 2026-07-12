//! Metrics façade used by the asynchronous shared-state runtime.

use super::Metrics;

#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedStatePoolStatus {
  pub(crate) active: usize,
  pub(crate) idle: usize,
  pub(crate) waiting: usize,
  pub(crate) max_connections: usize,
  pub(crate) circuit_state: &'static str,
}

impl Metrics {
  pub(crate) fn shared_state_waiters(&self) -> u64 {
    self.shared_state.waiters()
  }

  pub(crate) fn configure_shared_state_metrics(&self, buckets_ms: &[u64]) {
    self.shared_state.configure(buckets_ms);
  }

  pub(crate) fn shared_state_queue_started(&self, backend: &str, kind: &'static str) {
    self.shared_state.queue_started(backend, kind);
  }

  pub(crate) fn shared_state_queue_finished(
    &self,
    backend: &str,
    kind: &'static str,
    operation: &'static str,
    outcome: &'static str,
    duration_ms: u64,
  ) {
    self
      .shared_state
      .queue_finished(backend, kind, operation, outcome, duration_ms);
  }

  pub(crate) fn shared_state_operation_started(&self, backend: &str, kind: &'static str) {
    self.shared_state.operation_started(backend, kind);
  }

  pub(crate) fn shared_state_operation_finished(
    &self,
    backend: &str,
    kind: &'static str,
    operation: &'static str,
    outcome: &'static str,
    duration_ms: u64,
  ) {
    self
      .shared_state
      .operation_finished(backend, kind, operation, outcome, duration_ms);
  }

  pub(crate) fn record_shared_state_deferred_cleanup_dropped(
    &self,
    backend: &str,
    kind: &'static str,
  ) {
    self.shared_state.deferred_cleanup_dropped(backend, kind);
  }

  pub(crate) fn record_shared_state_pool_status(
    &self,
    backend: &str,
    kind: &'static str,
    status: SharedStatePoolStatus,
  ) {
    self.shared_state.pool_status(backend, kind, status);
  }

  pub(crate) fn record_shared_state_pool_acquisition(
    &self,
    backend: &str,
    kind: &'static str,
    outcome: &'static str,
  ) {
    self.shared_state.pool_acquisition(backend, kind, outcome);
  }

  pub(crate) fn record_shared_state_pool_connection_event(
    &self,
    backend: &str,
    kind: &'static str,
    event: &'static str,
  ) {
    self
      .shared_state
      .pool_connection_event(backend, kind, event);
  }

  pub(crate) fn record_shared_state_enumeration(
    &self,
    backend: &str,
    kind: &'static str,
    scope: &'static str,
    event: &'static str,
    count: usize,
  ) {
    self
      .shared_state
      .enumeration(backend, kind, scope, event, count);
  }

  pub(crate) fn register_backend_failure_feature(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
  ) {
    self.backend_failure.register(backend, kind, feature, mode);
  }

  pub(crate) fn record_backend_failure_policy(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
    failure_kind: &'static str,
  ) {
    self
      .backend_failure
      .policy_applied(backend, kind, feature, mode, failure_kind);
  }

  pub(crate) fn record_backend_feature_recovery(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
  ) {
    self.backend_failure.recovered(backend, kind, feature, mode);
  }

  pub(crate) fn record_backend_local_fallback(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
  ) {
    self
      .backend_failure
      .local_fallback_entered(backend, kind, feature, mode);
  }

  pub(crate) fn record_backend_stale_snapshot_age(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
    age_seconds: u64,
  ) {
    self
      .backend_failure
      .stale_snapshot_age(backend, kind, feature, mode, age_seconds);
  }

  pub(super) fn append_shared_state_prometheus(&self, output: &mut String) {
    self.shared_state.append_prometheus(output);
  }
}
