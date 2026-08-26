//! Fixed-cardinality downstream certificate-transparency metrics.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Metrics, append_metric};

#[derive(Debug, Default)]
pub(super) struct DownstreamCtMetrics {
  checks_compliant: AtomicU64,
  checks_noncompliant: AtomicU64,
  checks_error: AtomicU64,
  scts_valid: AtomicU64,
  scts_invalid: AtomicU64,
  enabled: AtomicU64,
  noncompliant_certificates: AtomicU64,
  log_list_age_seconds: AtomicU64,
  refresh_success_total: AtomicU64,
  refresh_errors_total: AtomicU64,
  handshake_rejects_total: AtomicU64,
}

impl Metrics {
  pub(crate) fn record_downstream_ct_check(&self, compliant: bool) {
    if compliant {
      self
        .downstream_ct
        .checks_compliant
        .fetch_add(1, Ordering::Relaxed);
    } else {
      self
        .downstream_ct
        .checks_noncompliant
        .fetch_add(1, Ordering::Relaxed);
    }
  }

  pub(crate) fn record_downstream_ct_error(&self) {
    self
      .downstream_ct
      .checks_error
      .fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn record_downstream_ct_sct_verification(&self, valid: u64, invalid: u64) {
    self
      .downstream_ct
      .scts_valid
      .fetch_add(valid, Ordering::Relaxed);
    self
      .downstream_ct
      .scts_invalid
      .fetch_add(invalid, Ordering::Relaxed);
  }

  pub(crate) fn set_downstream_ct_enabled(&self, enabled: bool) {
    self
      .downstream_ct
      .enabled
      .store(u64::from(enabled), Ordering::Relaxed);
  }

  pub(crate) fn set_downstream_ct_noncompliant_certificates(&self, count: u64) {
    self
      .downstream_ct
      .noncompliant_certificates
      .store(count, Ordering::Relaxed);
  }

  pub(crate) fn set_downstream_ct_log_list_age(&self, seconds: u64) {
    self
      .downstream_ct
      .log_list_age_seconds
      .store(seconds, Ordering::Relaxed);
  }

  pub(crate) fn record_downstream_ct_log_list_refresh_success(&self) {
    self
      .downstream_ct
      .refresh_success_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn record_downstream_ct_log_list_refresh_error(&self) {
    self
      .downstream_ct
      .refresh_errors_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn record_downstream_ct_handshake_reject(&self) {
    self
      .downstream_ct
      .handshake_rejects_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub(super) fn append_downstream_ct_prometheus(&self, output: &mut String) {
    output.push_str("# TYPE oxibelt_tls_ct_checks_total counter\n");
    for (result, value) in [
      (
        "compliant",
        self.downstream_ct.checks_compliant.load(Ordering::Relaxed),
      ),
      (
        "noncompliant",
        self
          .downstream_ct
          .checks_noncompliant
          .load(Ordering::Relaxed),
      ),
      (
        "error",
        self.downstream_ct.checks_error.load(Ordering::Relaxed),
      ),
    ] {
      let _ = writeln!(
        output,
        "oxibelt_tls_ct_checks_total{{result=\"{result}\"}} {value}"
      );
    }
    output.push_str("# TYPE oxibelt_tls_ct_sct_verification_total counter\n");
    for (result, value) in [
      (
        "valid",
        self.downstream_ct.scts_valid.load(Ordering::Relaxed),
      ),
      (
        "invalid",
        self.downstream_ct.scts_invalid.load(Ordering::Relaxed),
      ),
    ] {
      let _ = writeln!(
        output,
        "oxibelt_tls_ct_sct_verification_total{{result=\"{result}\"}} {value}"
      );
    }
    append_metric(
      output,
      "oxibelt_tls_ct_enabled",
      "gauge",
      self.downstream_ct.enabled.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_ct_noncompliant_certificates",
      "gauge",
      self
        .downstream_ct
        .noncompliant_certificates
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_ct_log_list_age_seconds",
      "gauge",
      self
        .downstream_ct
        .log_list_age_seconds
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_ct_log_list_refresh_success_total",
      "counter",
      self
        .downstream_ct
        .refresh_success_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_ct_log_list_refresh_errors_total",
      "counter",
      self
        .downstream_ct
        .refresh_errors_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_ct_handshake_rejects_total",
      "counter",
      self
        .downstream_ct
        .handshake_rejects_total
        .load(Ordering::Relaxed),
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cache::CacheStats;
  use crate::config::MetricsConfig;
  use crate::tls::TlsServerSessionStorageStats;

  #[test]
  fn public_metrics_have_only_bounded_result_labels() {
    let metrics = Metrics::new();
    metrics.record_downstream_ct_check(true);
    metrics.record_downstream_ct_check(false);
    metrics.record_downstream_ct_error();
    metrics.record_downstream_ct_sct_verification(2, 1);
    metrics.record_downstream_ct_handshake_reject();
    let body = metrics.prometheus(
      &MetricsConfig::default(),
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );
    assert!(body.contains("oxibelt_tls_ct_checks_total{result=\"compliant\"} 1"));
    assert!(body.contains("oxibelt_tls_ct_sct_verification_total{result=\"valid\"} 2"));
    assert!(body.contains("oxibelt_tls_ct_handshake_rejects_total 1"));
    assert!(!body.contains("log_id"));
    assert!(!body.contains("server_name"));
  }
}
