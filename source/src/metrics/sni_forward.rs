//! SNI forwarding metric counters.
//! Counters track routing and session outcomes without storing peer payload data.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::MetricsConfig;

use super::{Metrics, append_metric};

const QUIC_INITIAL_REASSEMBLY_OUTCOMES: &[&str] = &[
  "pending",
  "completed",
  "expired",
  "capacity_rejected",
  "limit_rejected",
  "overlap_conflict",
  "local_replay_queue_full",
  "forward_replay_send_failed",
];

#[derive(Clone, Copy, Debug)]
pub(crate) enum QuicInitialReassemblyOutcome {
  Pending,
  Completed,
  Expired,
  CapacityRejected,
  LimitRejected,
  OverlapConflict,
  LocalReplayQueueFull,
  ForwardReplaySendFailed,
}

impl QuicInitialReassemblyOutcome {
  const fn index(self) -> usize {
    match self {
      Self::Pending => 0,
      Self::Completed => 1,
      Self::Expired => 2,
      Self::CapacityRejected => 3,
      Self::LimitRejected => 4,
      Self::OverlapConflict => 5,
      Self::LocalReplayQueueFull => 6,
      Self::ForwardReplaySendFailed => 7,
    }
  }
}

#[derive(Debug, Default)]
pub(super) struct SniForwardMetrics {
  decisions_total: AtomicU64,
  parse_failures_total: AtomicU64,
  sessions_total: AtomicU64,
  session_errors_total: AtomicU64,
  active_quic_sessions: AtomicU64,
  tcp_bytes_total: AtomicU64,
  udp_bytes_total: AtomicU64,
  quic_initial_reassembly: [AtomicU64; QUIC_INITIAL_REASSEMBLY_OUTCOMES.len()],
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

  /// Records a bounded QUIC Initial reassembly lifecycle outcome. This is a
  /// fixed low-cardinality taxonomy, never a parser or transport error string.
  pub(crate) fn record_sni_forward_quic_initial_reassembly(
    &self,
    outcome: QuicInitialReassemblyOutcome,
  ) {
    self.sni_forward.quic_initial_reassembly[outcome.index()].fetch_add(1, Ordering::Relaxed);
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
    output.push_str("# TYPE oxibelt_sni_forward_quic_initial_reassembly_total counter\n");
    for (index, outcome) in QUIC_INITIAL_REASSEMBLY_OUTCOMES.iter().enumerate() {
      let _ = writeln!(
        output,
        "oxibelt_sni_forward_quic_initial_reassembly_total{{outcome=\"{outcome}\"}} {}",
        self.sni_forward.quic_initial_reassembly[index].load(Ordering::Relaxed),
      );
    }
  }
}
