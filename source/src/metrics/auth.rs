use std::sync::atomic::Ordering;

use super::{Metrics, append_metric};

impl Metrics {
  pub fn record_external_auth_allowed(&self) {
    self
      .external_auth_allowed_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_external_auth_denied(&self) {
    self
      .external_auth_denied_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_external_auth_error(&self) {
    self
      .external_auth_errors_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_request_mirror_success(&self) {
    self
      .request_mirror_success_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_request_mirror_error(&self) {
    self
      .request_mirror_errors_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_request_mirror_skip(&self) {
    self
      .request_mirror_skips_total
      .fetch_add(1, Ordering::Relaxed);
  }
}

pub(super) fn append_auth_and_mirror_metrics(output: &mut String, metrics: &Metrics) {
  append_metric(
    output,
    "oxibelt_external_auth_allowed_total",
    "counter",
    metrics.external_auth_allowed_total.load(Ordering::Relaxed),
  );
  append_metric(
    output,
    "oxibelt_external_auth_denied_total",
    "counter",
    metrics.external_auth_denied_total.load(Ordering::Relaxed),
  );
  append_metric(
    output,
    "oxibelt_external_auth_errors_total",
    "counter",
    metrics.external_auth_errors_total.load(Ordering::Relaxed),
  );
  append_metric(
    output,
    "oxibelt_request_mirror_success_total",
    "counter",
    metrics.request_mirror_success_total.load(Ordering::Relaxed),
  );
  append_metric(
    output,
    "oxibelt_request_mirror_errors_total",
    "counter",
    metrics.request_mirror_errors_total.load(Ordering::Relaxed),
  );
  append_metric(
    output,
    "oxibelt_request_mirror_skips_total",
    "counter",
    metrics.request_mirror_skips_total.load(Ordering::Relaxed),
  );
}
