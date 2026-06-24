//! Crate-visible typed fast-path metric APIs.

use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{
  DirectH1IoBackend, DirectH1IoBackendOutcome, DirectH1PoolEvent, FastPathMetricOutcome,
  FastPathMetricPath, FastPathMetricProtocol, FastPathMetricStage, FastPathPlainProxyMissReason,
  FastPathRequestBodyOutcome, FastPathTransportMissReason,
};

impl Metrics {
  pub(crate) fn record_plain_proxy_fast_path_decision_hit_id(
    &self,
    protocol: FastPathMetricProtocol,
  ) {
    self.fast_path.record_plain_proxy_decision_hit_id(protocol);
  }

  pub(crate) fn record_plain_proxy_fast_path_decision_miss_id(
    &self,
    protocol: FastPathMetricProtocol,
    reason: FastPathPlainProxyMissReason,
  ) {
    self
      .fast_path
      .record_plain_proxy_decision_miss_id(protocol, reason);
  }

  pub(crate) fn record_fast_path_request_body_id(
    &self,
    protocol: FastPathMetricProtocol,
    outcome: FastPathRequestBodyOutcome,
  ) {
    self.fast_path.record_request_body_id(protocol, outcome);
  }

  pub(crate) fn record_fast_path_stage_duration_ns_id(
    &self,
    path: FastPathMetricPath,
    protocol: FastPathMetricProtocol,
    stage: FastPathMetricStage,
    outcome: FastPathMetricOutcome,
    duration_ns: u64,
  ) {
    self
      .fast_path
      .record_stage_duration_ns_id(path, protocol, stage, outcome, duration_ns);
  }

  pub(crate) fn record_direct_h1_transport_hit_id(&self, protocol: FastPathMetricProtocol) {
    self.fast_path.record_direct_h1_transport_hit_id(protocol);
  }

  pub(crate) fn record_direct_h1_transport_miss_id(
    &self,
    protocol: FastPathMetricProtocol,
    reason: FastPathTransportMissReason,
  ) {
    self
      .fast_path
      .record_direct_h1_transport_miss_id(protocol, reason);
  }

  pub(crate) fn record_direct_h2_transport_hit_id(&self, protocol: FastPathMetricProtocol) {
    self.fast_path.record_direct_h2_transport_hit_id(protocol);
  }

  pub(crate) fn record_direct_h2_transport_miss_id(
    &self,
    protocol: FastPathMetricProtocol,
    reason: FastPathTransportMissReason,
  ) {
    self
      .fast_path
      .record_direct_h2_transport_miss_id(protocol, reason);
  }

  pub(crate) fn record_direct_h1_pool_event_id(&self, event: DirectH1PoolEvent) {
    self.fast_path.record_direct_h1_pool_event_id(event);
  }

  pub(crate) fn record_direct_h1_io_backend_id(
    &self,
    backend: DirectH1IoBackend,
    protocol: FastPathMetricProtocol,
    outcome: DirectH1IoBackendOutcome,
  ) {
    self
      .fast_path
      .record_direct_h1_io_backend_id(backend, protocol, outcome);
  }
}
