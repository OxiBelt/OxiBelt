//! Fixed-cardinality Certificate Transparency operator and gateway metrics.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use super::Metrics;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub(crate) enum CtRejectionReason {
  Malformed = 0,
  Chain = 1,
  Root = 2,
  Shard = 3,
  Expired = 4,
  RateLimit = 5,
  Frozen = 6,
  Dependency = 7,
}

const REJECTION_REASONS: [&str; 8] = [
  "malformed",
  "chain",
  "root",
  "shard",
  "expired",
  "rate_limit",
  "frozen",
  "dependency",
];

#[derive(Debug, Default)]
pub(super) struct CtMetrics {
  submissions_accepted: AtomicU64,
  submissions_rejected: [AtomicU64; REJECTION_REASONS.len()],
  publish_failures: AtomicU64,
  gateway_verification_failures: AtomicU64,
  tree_size: AtomicU64,
  published_tree_size: AtomicU64,
  pending_entries: AtomicU64,
  mmd_age_millis: AtomicU64,
  frozen: AtomicU64,
}

impl Metrics {
  pub(crate) fn record_ct_submission_accepted(&self) {
    self.ct.submissions_accepted.fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn record_ct_submission_rejected(&self, reason: CtRejectionReason) {
    self.ct.submissions_rejected[reason as usize].fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn record_ct_publish_failure(&self) {
    self.ct.publish_failures.fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn record_ct_gateway_verification_failure(&self) {
    self
      .ct
      .gateway_verification_failures
      .fetch_add(1, Ordering::Relaxed);
  }

  pub(crate) fn set_ct_tree_state(
    &self,
    tree_size: u64,
    published_tree_size: u64,
    pending_entries: u64,
    mmd_age_millis: u64,
    frozen: bool,
  ) {
    self.ct.tree_size.store(tree_size, Ordering::Relaxed);
    self
      .ct
      .published_tree_size
      .store(published_tree_size, Ordering::Relaxed);
    self
      .ct
      .pending_entries
      .store(pending_entries, Ordering::Relaxed);
    self
      .ct
      .mmd_age_millis
      .store(mmd_age_millis, Ordering::Relaxed);
    self.ct.frozen.store(u64::from(frozen), Ordering::Relaxed);
  }

  pub(super) fn append_ct_prometheus(&self, output: &mut String) {
    append_metric(
      output,
      "oxibelt_ct_submissions_accepted_total",
      "counter",
      self.ct.submissions_accepted.load(Ordering::Relaxed),
    );
    output.push_str("# TYPE oxibelt_ct_submissions_rejected_total counter\n");
    for (index, reason) in REJECTION_REASONS.iter().enumerate() {
      let _ = writeln!(
        output,
        "oxibelt_ct_submissions_rejected_total{{reason=\"{reason}\"}} {}",
        self.ct.submissions_rejected[index].load(Ordering::Relaxed)
      );
    }
    append_metric(
      output,
      "oxibelt_ct_publish_failures_total",
      "counter",
      self.ct.publish_failures.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_ct_gateway_verification_failures_total",
      "counter",
      self
        .ct
        .gateway_verification_failures
        .load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_ct_tree_size",
      "gauge",
      self.ct.tree_size.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_ct_published_tree_size",
      "gauge",
      self.ct.published_tree_size.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_ct_pending_entries",
      "gauge",
      self.ct.pending_entries.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_ct_mmd_age_milliseconds",
      "gauge",
      self.ct.mmd_age_millis.load(Ordering::Relaxed),
    );
    append_metric(
      output,
      "oxibelt_ct_frozen",
      "gauge",
      self.ct.frozen.load(Ordering::Relaxed),
    );
  }
}

fn append_metric(output: &mut String, name: &str, kind: &str, value: u64) {
  let _ = writeln!(output, "# TYPE {name} {kind}\n{name} {value}");
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rejection_labels_are_bounded_and_rendered() {
    let metrics = Metrics::default();
    metrics.record_ct_submission_rejected(CtRejectionReason::Shard);
    let mut output = String::new();
    metrics.append_ct_prometheus(&mut output);
    assert!(output.contains("reason=\"shard\"} 1"));
    assert_eq!(
      output
        .matches("oxibelt_ct_submissions_rejected_total{")
        .count(),
      8
    );
  }
}
