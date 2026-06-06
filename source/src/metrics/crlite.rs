use std::sync::atomic::{AtomicU64, Ordering};

use super::{Metrics, append_metric};

#[derive(Debug, Default)]
pub(super) struct CrliteMetrics {
  checks_total: AtomicU64,
  revoked_total: AtomicU64,
  errors_total: AtomicU64,
  enabled: AtomicU64,
  filter_stale: AtomicU64,
}

impl Metrics {
  pub fn record_crlite_check(&self) {
    self.crlite.checks_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_crlite_revoked(&self) {
    self.crlite.revoked_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_crlite_error(&self) {
    self.crlite.errors_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn set_crlite_enabled(&self, enabled: bool) {
    self
      .crlite
      .enabled
      .store(u64::from(enabled), Ordering::Relaxed);
  }

  pub fn set_crlite_filter_stale(&self, stale: bool) {
    self
      .crlite
      .filter_stale
      .store(u64::from(stale), Ordering::Relaxed);
  }

  pub(super) fn append_crlite_prometheus(&self, output: &mut String) {
    append_metric(
      output,
      "oxibelt_tls_crlite_checks_total",
      "counter",
      self.crlite.checks_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_crlite_revoked_total",
      "counter",
      self.crlite.revoked_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_crlite_errors_total",
      "counter",
      self.crlite.errors_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_crlite_enabled",
      "gauge",
      self.crlite.enabled.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_crlite_filter_stale",
      "gauge",
      self.crlite.filter_stale.load(Ordering::Relaxed),
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
  fn prometheus_output_includes_bounded_crlite_metrics() {
    let metrics = Metrics::new();
    metrics.record_crlite_check();
    metrics.record_crlite_revoked();
    metrics.record_crlite_error();
    metrics.set_crlite_enabled(true);
    metrics.set_crlite_filter_stale(true);

    let body = metrics.prometheus(
      &MetricsConfig::default(),
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );

    assert!(body.contains("oxibelt_tls_crlite_checks_total 1"));
    assert!(body.contains("oxibelt_tls_crlite_revoked_total 1"));
    assert!(body.contains("oxibelt_tls_crlite_errors_total 1"));
    assert!(body.contains("oxibelt_tls_crlite_enabled 1"));
    assert!(body.contains("oxibelt_tls_crlite_filter_stale 1"));
    assert!(!body.contains("issuer"));
    assert!(!body.contains("serial"));
    assert!(!body.contains("fingerprint"));
    assert!(!body.contains("crlite.filter"));
  }
}
