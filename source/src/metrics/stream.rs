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
  }
}
