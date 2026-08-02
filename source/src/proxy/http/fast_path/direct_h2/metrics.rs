use std::sync::Arc;

use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{
  DirectH2PoolEvent, FastPathMetricProtocol, FastPathTransportMissReason,
};

use super::DirectH2Pool;

pub(super) fn pool_event(metrics: &Arc<Metrics>, enabled: bool, event: DirectH2PoolEvent) {
  if enabled {
    metrics.record_direct_h2_pool_event_id(event);
  }
}

pub(super) fn upstream_pool_miss(pool: &DirectH2Pool, metrics: &Arc<Metrics>, enabled: bool) {
  if enabled {
    metrics.record_http_upstream_client_pool_miss(
      pool.metric_version(),
      pool.origin.scheme,
      "primary",
    );
  }
}

pub(super) fn upstream_connection_created(
  pool: &DirectH2Pool,
  metrics: &Arc<Metrics>,
  enabled: bool,
) {
  if enabled {
    metrics.record_http_upstream_client_connection_created(
      pool.metric_version(),
      pool.origin.scheme,
      "primary",
    );
  }
}

pub(super) fn upstream_request(pool: &DirectH2Pool, metrics: &Arc<Metrics>, enabled: bool) {
  if enabled {
    metrics.record_http_upstream_client_request(
      pool.metric_version(),
      pool.origin.scheme,
      "primary",
    );
  }
}

pub(super) fn transport_hit(
  metrics: &Arc<Metrics>,
  enabled: bool,
  protocol: FastPathMetricProtocol,
) {
  if enabled {
    metrics.record_direct_h2_transport_hit_id(protocol);
    metrics.record_fast_path_selection("direct_h2", protocol.as_str(), "selected", "used");
  }
}

pub(super) fn transport_miss(
  metrics: &Metrics,
  enabled: bool,
  protocol: FastPathMetricProtocol,
  reason: FastPathTransportMissReason,
) {
  if enabled {
    metrics.record_direct_h2_transport_miss_id(protocol, reason);
  }
}
