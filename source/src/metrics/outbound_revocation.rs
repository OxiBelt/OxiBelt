use std::sync::atomic::{AtomicU64, Ordering};

use super::{Metrics, append_metric};

#[derive(Debug, Default)]
pub(super) struct OutboundRevocationMetrics {
  ocsp_success_total: AtomicU64,
  ocsp_errors_total: AtomicU64,
  crlite_checks_total: AtomicU64,
  crlite_revoked_total: AtomicU64,
  crlite_errors_total: AtomicU64,
}

impl Metrics {
  pub fn record_outbound_revocation_ocsp_success(&self) {
    self
      .outbound_revocation
      .ocsp_success_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_outbound_revocation_ocsp_error(&self) {
    self
      .outbound_revocation
      .ocsp_errors_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_outbound_revocation_crlite_check(&self) {
    self
      .outbound_revocation
      .crlite_checks_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_outbound_revocation_crlite_revoked(&self) {
    self
      .outbound_revocation
      .crlite_revoked_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_outbound_revocation_crlite_error(&self) {
    self
      .outbound_revocation
      .crlite_errors_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub(super) fn append_outbound_revocation_prometheus(&self, output: &mut String) {
    append_metric(
      output,
      "oxibelt_tls_upstream_ocsp_success_total",
      "counter",
      self
        .outbound_revocation
        .ocsp_success_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_upstream_ocsp_errors_total",
      "counter",
      self
        .outbound_revocation
        .ocsp_errors_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_upstream_crlite_checks_total",
      "counter",
      self
        .outbound_revocation
        .crlite_checks_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_upstream_crlite_revoked_total",
      "counter",
      self
        .outbound_revocation
        .crlite_revoked_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_upstream_crlite_errors_total",
      "counter",
      self
        .outbound_revocation
        .crlite_errors_total
        .load(Ordering::Relaxed),
    );
  }
}

#[cfg(test)]
mod tests {
  use crate::cache::CacheStats;
  use crate::config::MetricsConfig;
  use crate::metrics::Metrics;
  use crate::tls::TlsServerSessionStorageStats;

  #[test]
  fn prometheus_output_includes_bounded_upstream_revocation_metrics() {
    let metrics = Metrics::new();
    let config = MetricsConfig::default();
    metrics.record_outbound_revocation_ocsp_success();
    metrics.record_outbound_revocation_ocsp_error();
    metrics.record_outbound_revocation_crlite_check();
    metrics.record_outbound_revocation_crlite_revoked();
    metrics.record_outbound_revocation_crlite_error();

    let body = metrics.prometheus(
      &config,
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );

    assert!(body.contains("oxibelt_tls_upstream_ocsp_success_total 1"));
    assert!(body.contains("oxibelt_tls_upstream_ocsp_errors_total 1"));
    assert!(body.contains("oxibelt_tls_upstream_crlite_checks_total 1"));
    assert!(body.contains("oxibelt_tls_upstream_crlite_revoked_total 1"));
    assert!(body.contains("oxibelt_tls_upstream_crlite_errors_total 1"));
    assert!(!body.contains("responder_url"));
    assert!(!body.contains("issuer"));
    assert!(!body.contains("serial"));
    assert!(!body.contains("fingerprint"));
    assert!(!body.contains("filter_file"));
  }
}
