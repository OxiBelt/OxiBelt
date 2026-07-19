//! Generic stream proxy metric counters.
//! Stream metrics avoid target labels because stream origins can be private infrastructure.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{Metrics, append_metric};

#[derive(Debug, Default)]
pub(super) struct StreamMetrics {
  tcp_sessions_total: AtomicU64,
  udp_sessions_total: AtomicU64,
  session_errors_total: AtomicU64,
  tcp_bytes_total: AtomicU64,
  udp_bytes_total: AtomicU64,
  udp_rate_limited_total: AtomicU64,
  udp_flows_active: AtomicU64,
  udp_flows_created_total: AtomicU64,
  udp_flows_expired_total: AtomicU64,
  udp_flows_evicted_total: AtomicU64,
  udp_flow_admission_rejections_total: AtomicU64,
  udp_flows_forced_shutdown_total: AtomicU64,
  udp_datagrams_dropped_total: AtomicU64,
}

impl Metrics {
  pub fn record_stream_session_end(
    &self,
    network: &str,
    _listener: &str,
    _route: &str,
    success: bool,
  ) {
    match network {
      "udp" => self
        .stream
        .udp_sessions_total
        .fetch_add(1, Ordering::Relaxed),
      _ => self
        .stream
        .tcp_sessions_total
        .fetch_add(1, Ordering::Relaxed),
    };
    if !success {
      self
        .stream
        .session_errors_total
        .fetch_add(1, Ordering::Relaxed);
    }
  }

  pub fn add_stream_bytes(&self, network: &str, bytes: u64) {
    match network {
      "udp" => &self.stream.udp_bytes_total,
      _ => &self.stream.tcp_bytes_total,
    }
    .fetch_add(bytes, Ordering::Relaxed);
  }

  pub fn record_stream_udp_rate_limited(&self, _listener: &str) {
    self
      .stream
      .udp_rate_limited_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_stream_udp_flow_created(&self, _listener: &str) {
    self.stream.udp_flows_active.fetch_add(1, Ordering::Relaxed);
    self
      .stream
      .udp_flows_created_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_stream_udp_flow_expired(&self, _listener: &str) {
    self.record_stream_udp_flow_ended(&self.stream.udp_flows_expired_total);
  }

  pub fn record_stream_udp_flow_evicted(&self, _listener: &str) {
    self.record_stream_udp_flow_ended(&self.stream.udp_flows_evicted_total);
  }

  pub fn record_stream_udp_flows_forced_shutdown(&self, _listener: &str, count: usize) {
    let count = u64::try_from(count).unwrap_or(u64::MAX);
    let _ =
      self
        .stream
        .udp_flows_active
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
          Some(active.saturating_sub(count))
        });
    self
      .stream
      .udp_flows_forced_shutdown_total
      .fetch_add(count, Ordering::Relaxed);
  }

  pub fn record_stream_udp_flow_admission_rejection(&self, _listener: &str) {
    self
      .stream
      .udp_flow_admission_rejections_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_stream_udp_datagram_dropped(&self, _listener: &str) {
    self
      .stream
      .udp_datagrams_dropped_total
      .fetch_add(1, Ordering::Relaxed);
  }

  fn record_stream_udp_flow_ended(&self, counter: &AtomicU64) {
    let _ =
      self
        .stream
        .udp_flows_active
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
          Some(active.saturating_sub(1))
        });
    counter.fetch_add(1, Ordering::Relaxed);
  }

  pub(super) fn append_stream_prometheus(&self, output: &mut String) {
    append_metric(
      output,
      "oxibelt_stream_tcp_sessions_total",
      "counter",
      self.stream.tcp_sessions_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_sessions_total",
      "counter",
      self.stream.udp_sessions_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_session_errors_total",
      "counter",
      self.stream.session_errors_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_tcp_bytes_total",
      "counter",
      self.stream.tcp_bytes_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_bytes_total",
      "counter",
      self.stream.udp_bytes_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_rate_limited_total",
      "counter",
      self.stream.udp_rate_limited_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_flows_active",
      "gauge",
      self.stream.udp_flows_active.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_flows_created_total",
      "counter",
      self.stream.udp_flows_created_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_flows_expired_total",
      "counter",
      self.stream.udp_flows_expired_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_flows_evicted_total",
      "counter",
      self.stream.udp_flows_evicted_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_flow_admission_rejections_total",
      "counter",
      self
        .stream
        .udp_flow_admission_rejections_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_flows_forced_shutdown_total",
      "counter",
      self
        .stream
        .udp_flows_forced_shutdown_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_stream_udp_datagrams_dropped_total",
      "counter",
      self
        .stream
        .udp_datagrams_dropped_total
        .load(Ordering::Relaxed),
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn udp_lifecycle_metrics_are_aggregate_and_saturating() {
    let metrics = Metrics::default();
    metrics.record_stream_udp_flow_created("listener-a");
    metrics.record_stream_udp_flow_created("listener-b");
    metrics.record_stream_udp_flow_expired("listener-a");
    metrics.record_stream_udp_flow_evicted("listener-b");
    metrics.record_stream_udp_flow_created("listener-a");
    metrics.record_stream_udp_flow_created("listener-b");
    metrics.record_stream_udp_flows_forced_shutdown("listener-a", 2);
    metrics.record_stream_udp_flow_admission_rejection("listener-a");
    metrics.record_stream_udp_datagram_dropped("listener-b");

    let mut output = String::new();
    metrics.append_stream_prometheus(&mut output);

    assert!(output.contains("oxibelt_stream_udp_flows_active 0\n"));
    assert!(output.contains("oxibelt_stream_udp_flows_created_total 4\n"));
    assert!(output.contains("oxibelt_stream_udp_flows_expired_total 1\n"));
    assert!(output.contains("oxibelt_stream_udp_flows_evicted_total 1\n"));
    assert!(output.contains("oxibelt_stream_udp_flow_admission_rejections_total 1\n"));
    assert!(output.contains("oxibelt_stream_udp_flows_forced_shutdown_total 2\n"));
    assert!(output.contains("oxibelt_stream_udp_datagrams_dropped_total 1\n"));
    assert!(!output.contains("listener-a"));
    assert!(!output.contains("listener-b"));
  }
}
