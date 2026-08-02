//! Typed fast-path metric recorders used by hot call sites.

use super::labels::{
  DirectH1IoBackend, DirectH1IoBackendOutcome, DirectH1PoolEvent, DirectH1ResponseProtocolFailure,
  DirectH2PoolEvent, FastPathMetricOutcome, FastPathMetricPath, FastPathMetricProtocol,
  FastPathMetricStage, FastPathMetricTransport, FastPathPlainProxyMissReason,
  FastPathRequestBodyOutcome, FastPathTransportMissReason,
};
use super::{
  FastPathMetrics, OUTCOMES_PER_PROTOCOL, direct_h1_io, direct_h1_response_protocol_counter_index,
  transport_counter_index_by_parts,
};

impl FastPathMetrics {
  pub(super) fn record_plain_proxy_decision_hit_id(&self, protocol: FastPathMetricProtocol) {
    self.decision_counters[protocol.index() * OUTCOMES_PER_PROTOCOL].increment();
  }

  pub(super) fn record_plain_proxy_decision_miss_id(
    &self,
    protocol: FastPathMetricProtocol,
    reason: FastPathPlainProxyMissReason,
  ) {
    self.decision_counters[protocol.index() * OUTCOMES_PER_PROTOCOL + 1 + reason.index()]
      .increment();
  }

  pub(super) fn record_request_body_id(
    &self,
    protocol: FastPathMetricProtocol,
    outcome: FastPathRequestBodyOutcome,
  ) {
    self.request_body_counters
      [protocol.index() * FastPathRequestBodyOutcome::COUNT + outcome.index()]
    .increment();
  }

  pub(super) fn record_direct_h1_transport_hit_id(&self, protocol: FastPathMetricProtocol) {
    self.record_transport_hit_id(FastPathMetricTransport::DirectH1, protocol);
  }

  pub(super) fn record_direct_h1_transport_miss_id(
    &self,
    protocol: FastPathMetricProtocol,
    reason: FastPathTransportMissReason,
  ) {
    self.record_transport_miss_id(FastPathMetricTransport::DirectH1, protocol, reason);
  }

  pub(super) fn record_direct_h2_transport_hit_id(&self, protocol: FastPathMetricProtocol) {
    self.record_transport_hit_id(FastPathMetricTransport::DirectH2, protocol);
  }

  pub(super) fn record_direct_h2_transport_miss_id(
    &self,
    protocol: FastPathMetricProtocol,
    reason: FastPathTransportMissReason,
  ) {
    self.record_transport_miss_id(FastPathMetricTransport::DirectH2, protocol, reason);
  }

  pub(super) fn record_direct_h1_pool_event_id(&self, event: DirectH1PoolEvent) {
    self.direct_h1_pool_counters[event.index()].increment();
  }

  pub(super) fn record_direct_h2_pool_event_id(&self, event: DirectH2PoolEvent) {
    self.direct_h2_pool_counters[event.index()].increment();
  }

  pub(super) fn record_direct_h1_response_protocol_failure_id(
    &self,
    protocol: FastPathMetricProtocol,
    reason: DirectH1ResponseProtocolFailure,
  ) {
    self.direct_h1_response_protocol_counters
      [direct_h1_response_protocol_counter_index(protocol, reason)]
    .increment();
  }

  pub(super) fn record_direct_h1_io_backend_id(
    &self,
    backend: DirectH1IoBackend,
    protocol: FastPathMetricProtocol,
    outcome: DirectH1IoBackendOutcome,
  ) {
    let index = direct_h1_io::counter_index_id(backend, protocol, outcome);
    self.direct_h1_io_backend_counters[index].increment();
  }

  pub(super) fn record_stage_duration_ns_id(
    &self,
    path: FastPathMetricPath,
    protocol: FastPathMetricProtocol,
    stage: FastPathMetricStage,
    outcome: FastPathMetricOutcome,
    duration_ns: u64,
  ) {
    self
      .stage
      .record_duration_ns_id(path, protocol, stage, outcome, duration_ns);
  }

  fn record_transport_hit_id(
    &self,
    transport: FastPathMetricTransport,
    protocol: FastPathMetricProtocol,
  ) {
    self.transport_counters
      [transport_counter_index_by_parts(transport.index(), protocol.index(), 0)]
    .increment();
  }

  fn record_transport_miss_id(
    &self,
    transport: FastPathMetricTransport,
    protocol: FastPathMetricProtocol,
    reason: FastPathTransportMissReason,
  ) {
    self.transport_counters
      [transport_counter_index_by_parts(transport.index(), protocol.index(), 1 + reason.index())]
    .increment();
  }
}

#[cfg(test)]
mod tests {
  use super::super::{counter_index, request_body_counter_index};
  use super::*;

  #[test]
  fn specialized_gate_recorders_use_fixed_indexes() {
    let metrics = FastPathMetrics::default();
    metrics.record_plain_proxy_decision_hit_id(FastPathMetricProtocol::H2);
    metrics.record_plain_proxy_decision_miss_id(
      FastPathMetricProtocol::H3,
      FastPathPlainProxyMissReason::CachePolicy,
    );
    metrics.record_request_body_id(
      FastPathMetricProtocol::H2,
      FastPathRequestBodyOutcome::VerifiedEmpty,
    );
    metrics.record_request_body_id(
      FastPathMetricProtocol::H3,
      FastPathRequestBodyOutcome::ProbeEof,
    );

    assert_eq!(
      metrics.decision_counters[counter_index("h2", "hit", "eligible").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.decision_counters[counter_index("h3", "miss", "cache_policy").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.request_body_counters[request_body_counter_index("h2", "verified_empty").unwrap()]
        .load(),
      1
    );
    assert_eq!(
      metrics.request_body_counters[request_body_counter_index("h3", "probe_eof").unwrap()].load(),
      1
    );
  }
}
