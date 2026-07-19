//! Fixed-cardinality secret-reference activation metrics.

use std::sync::atomic::{AtomicU64, Ordering};

use super::{Metrics, append_metric};

#[derive(Debug, Default)]
pub(super) struct SecretActivationMetrics {
  applied_total: AtomicU64,
  rejected_total: AtomicU64,
  rollback_total: AtomicU64,
}

impl Metrics {
  pub(crate) fn record_secret_reference_activation(&self, outcome: &str) {
    let counter = match outcome {
      "applied" => &self.secret_activation.applied_total,
      "rollback" => &self.secret_activation.rollback_total,
      _ => &self.secret_activation.rejected_total,
    };
    counter.fetch_add(1, Ordering::Relaxed);
  }

  pub(super) fn append_secret_activation_prometheus(&self, output: &mut String) {
    for (name, value) in [
      (
        "oxibelt_secret_reference_activation_applied_total",
        self.secret_activation.applied_total.load(Ordering::Relaxed),
      ),
      (
        "oxibelt_secret_reference_activation_rejected_total",
        self
          .secret_activation
          .rejected_total
          .load(Ordering::Relaxed),
      ),
      (
        "oxibelt_secret_reference_activation_rollback_total",
        self
          .secret_activation
          .rollback_total
          .load(Ordering::Relaxed),
      ),
    ] {
      append_metric(output, name, "counter", value);
    }
  }
}
