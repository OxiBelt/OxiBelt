//! SNI forwarding metric counters.
//! Counters track routing and session outcomes without storing peer payload data.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::MetricsConfig;

use super::{Metrics, append_metric};

#[derive(Debug, Default)]
pub(super) struct SniForwardMetrics {
  decisions_total: AtomicU64,
  parse_failures_total: AtomicU64,
  sessions_total: AtomicU64,
  session_errors_total: AtomicU64,
  active_quic_sessions: AtomicU64,
  tcp_bytes_total: AtomicU64,
  udp_bytes_total: AtomicU64,
}

impl Metrics {
  pub fn record_sni_forward_decision(
    &self,
    protocol: &str,
    decision: &str,
    rule: &str,
    target: &str,
  ) {
    self
      .sni_forward
      .decisions_total
      .fetch_add(1, Ordering::Relaxed);
    self.record_sni_forward_decision_detail(protocol, decision, rule, target);
  }

  pub fn record_sni_forward_parse_failure(&self, protocol: &str) {
    self
      .sni_forward
      .parse_failures_total
      .fetch_add(1, Ordering::Relaxed);
    self.record_sni_forward_decision_detail(protocol, "parse_failure", "none", "none");
  }

  pub fn record_sni_forward_session_end(
    &self,
    config: &MetricsConfig,
    protocol: &str,
    rule: &str,
    target: &str,
    outcome: &str,
    duration_ms: u64,
  ) {
    self
      .sni_forward
      .sessions_total
      .fetch_add(1, Ordering::Relaxed);
    if outcome != "closed" {
      self
        .sni_forward
        .session_errors_total
        .fetch_add(1, Ordering::Relaxed);
    }
    self.record_sni_forward_session_detail(config, protocol, rule, target, outcome, duration_ms);
  }

  pub fn add_sni_forward_tcp_bytes(&self, bytes: u64) {
    self
      .sni_forward
      .tcp_bytes_total
      .fetch_add(bytes, Ordering::Relaxed);
  }

  pub fn add_sni_forward_udp_bytes(&self, bytes: u64) {
    self
      .sni_forward
      .udp_bytes_total
      .fetch_add(bytes, Ordering::Relaxed);
  }

  pub fn add_sni_forward_active_quic_session(&self, delta: i64) {
    if delta >= 0 {
      self
        .sni_forward
        .active_quic_sessions
        .fetch_add(delta as u64, Ordering::Relaxed);
    } else {
      self
        .sni_forward
        .active_quic_sessions
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
          Some(current.saturating_sub(delta.unsigned_abs()))
        })
        .ok();
    }
  }

  pub(super) fn append_sni_forward_prometheus(&self, output: &mut String) {
    append_metric(
      output,
      "oxibelt_sni_forward_decisions_total",
      "counter",
      self.sni_forward.decisions_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_sni_forward_parse_failures_total",
      "counter",
      self
        .sni_forward
        .parse_failures_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_sni_forward_sessions_total",
      "counter",
      self.sni_forward.sessions_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_sni_forward_session_errors_total",
      "counter",
      self
        .sni_forward
        .session_errors_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_sni_forward_active_quic_sessions",
      "gauge",
      self
        .sni_forward
        .active_quic_sessions
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_sni_forward_tcp_bytes_total",
      "counter",
      self.sni_forward.tcp_bytes_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_sni_forward_udp_bytes_total",
      "counter",
      self.sni_forward.udp_bytes_total.load(Ordering::Relaxed),
    );
  }
}
