//! Typed fast-path metric recorders used by hot call sites.

use super::labels::{
  DirectH1PoolEvent, FastPathMetricOutcome, FastPathMetricPath, FastPathMetricProtocol,
  FastPathMetricStage, FastPathMetricTransport, FastPathTransportMissReason,
};
use super::{FastPathMetrics, transport_counter_index_by_parts};

impl FastPathMetrics {
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
