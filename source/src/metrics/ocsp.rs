use std::sync::atomic::{AtomicU64, Ordering};

use super::{Metrics, append_metric};

#[derive(Debug, Default)]
pub(super) struct OcspMetrics {
  fetch_success_total: AtomicU64,
  fetch_errors_total: AtomicU64,
  staple_present: AtomicU64,
  next_update_timestamp: AtomicU64,
  stale_drops_total: AtomicU64,
}

impl Metrics {
  pub fn record_ocsp_fetch_success(&self) {
    self
      .ocsp
      .fetch_success_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_ocsp_fetch_error(&self) {
    self.ocsp.fetch_errors_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn set_ocsp_staple_present(&self, present: bool) {
    self
      .ocsp
      .staple_present
      .store(u64::from(present), Ordering::Relaxed);
  }

  pub fn set_ocsp_next_update_timestamp(&self, timestamp: u64) {
    self
      .ocsp
      .next_update_timestamp
      .store(timestamp, Ordering::Relaxed);
  }

  pub fn record_ocsp_stale_drop(&self) {
    self.ocsp.stale_drops_total.fetch_add(1, Ordering::Relaxed);
  }

  pub(super) fn append_ocsp_prometheus(&self, output: &mut String) {
    append_metric(
      output,
      "oxibelt_tls_ocsp_fetch_success_total",
      "counter",
      self.ocsp.fetch_success_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_ocsp_fetch_errors_total",
      "counter",
      self.ocsp.fetch_errors_total.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_ocsp_staple_present",
      "gauge",
      self.ocsp.staple_present.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_ocsp_next_update_timestamp_seconds",
      "gauge",
      self.ocsp.next_update_timestamp.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_tls_ocsp_stale_drops_total",
      "counter",
      self.ocsp.stale_drops_total.load(Ordering::Relaxed),
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
  fn prometheus_output_includes_bounded_ocsp_metrics() {
    let metrics = Metrics::new();
    metrics.record_ocsp_fetch_success();
    metrics.record_ocsp_fetch_error();
    metrics.set_ocsp_staple_present(true);
    metrics.set_ocsp_next_update_timestamp(1_767_225_600);
    metrics.record_ocsp_stale_drop();

    let body = metrics.prometheus(
      &MetricsConfig::default(),
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );

    assert!(body.contains("oxibelt_tls_ocsp_fetch_success_total 1"));
    assert!(body.contains("oxibelt_tls_ocsp_fetch_errors_total 1"));
    assert!(body.contains("oxibelt_tls_ocsp_staple_present 1"));
    assert!(body.contains("oxibelt_tls_ocsp_next_update_timestamp_seconds 1767225600"));
    assert!(body.contains("oxibelt_tls_ocsp_stale_drops_total 1"));
    assert!(!body.contains("ocsp.example"));
    assert!(!body.contains("responder"));
    assert!(!body.contains("fingerprint"));
  }
}
