//! Admin audit metrics with fixed low-cardinality labels.

use std::sync::atomic::{AtomicU64, Ordering};

use super::Metrics;

const WORKLOAD_IDENTITY_AUTH_OUTCOMES: [(&str, &str); 11] = [
  ("accepted", "bound_bearer"),
  ("accepted", "certificate_only"),
  ("accepted", "bound_signed_cache_purge"),
  ("rejected", "missing_certificate"),
  ("rejected", "unparseable_certificate"),
  ("rejected", "revoked_certificate"),
  ("rejected", "unmapped_workload_identity"),
  ("rejected", "ambiguous_workload_identity"),
  ("rejected", "missing_bearer"),
  ("rejected", "invalid_bearer"),
  ("rejected", "principal_mismatch"),
];

#[derive(Debug, Default)]
pub(super) struct AdminAuditMetrics {
  events_applied_postgres: AtomicU64,
  events_rejected_postgres: AtomicU64,
  events_unknown_postgres: AtomicU64,
  events_applied_none: AtomicU64,
  events_rejected_none: AtomicU64,
  events_unknown_none: AtomicU64,
  store_enqueue_full_total: AtomicU64,
  store_enqueue_closed_total: AtomicU64,
  export_access_log_total: AtomicU64,
  dropped_store_queue_full_total: AtomicU64,
  dropped_store_writer_closed_total: AtomicU64,
  workload_identity_authentication: [AtomicU64; WORKLOAD_IDENTITY_AUTH_OUTCOMES.len()],
}

impl Metrics {
  pub fn record_admin_audit_event(&self, outcome: &str, store: &str) {
    let counter = match (outcome, store) {
      ("applied", "postgres") => &self.admin_audit.events_applied_postgres,
      ("rejected", "postgres") => &self.admin_audit.events_rejected_postgres,
      (_, "postgres") => &self.admin_audit.events_unknown_postgres,
      ("applied", _) => &self.admin_audit.events_applied_none,
      ("rejected", _) => &self.admin_audit.events_rejected_none,
      _ => &self.admin_audit.events_unknown_none,
    };
    counter.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_admin_audit_store_enqueue_failure(&self, reason: &str) {
    let counter = match reason {
      "full" => &self.admin_audit.store_enqueue_full_total,
      "closed" => &self.admin_audit.store_enqueue_closed_total,
      _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_admin_audit_export_event(&self, sink: &str) {
    if sink == "access_log" {
      self
        .admin_audit
        .export_access_log_total
        .fetch_add(1, Ordering::Relaxed);
    }
  }

  pub fn record_admin_audit_dropped(&self, reason: &str) {
    let counter = match reason {
      "store_queue_full" => &self.admin_audit.dropped_store_queue_full_total,
      "store_writer_closed" => &self.admin_audit.dropped_store_writer_closed_total,
      _ => return,
    };
    counter.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_admin_workload_identity_authentication(&self, outcome: &str, reason: &str) {
    let Some(index) = WORKLOAD_IDENTITY_AUTH_OUTCOMES
      .iter()
      .position(|candidate| *candidate == (outcome, reason))
    else {
      return;
    };
    self.admin_audit.workload_identity_authentication[index].fetch_add(1, Ordering::Relaxed);
  }

  pub(super) fn append_admin_audit_prometheus(&self, output: &mut String) {
    append_admin_audit_event(
      output,
      "applied",
      "postgres",
      self
        .admin_audit
        .events_applied_postgres
        .load(Ordering::Relaxed),
    );
    append_admin_audit_event(
      output,
      "rejected",
      "postgres",
      self
        .admin_audit
        .events_rejected_postgres
        .load(Ordering::Relaxed),
    );
    append_admin_audit_event(
      output,
      "unknown",
      "postgres",
      self
        .admin_audit
        .events_unknown_postgres
        .load(Ordering::Relaxed),
    );
    append_admin_audit_event(
      output,
      "applied",
      "none",
      self.admin_audit.events_applied_none.load(Ordering::Relaxed),
    );
    append_admin_audit_event(
      output,
      "rejected",
      "none",
      self
        .admin_audit
        .events_rejected_none
        .load(Ordering::Relaxed),
    );
    append_admin_audit_event(
      output,
      "unknown",
      "none",
      self.admin_audit.events_unknown_none.load(Ordering::Relaxed),
    );
    append_labeled_counter(
      output,
      "oxibelt_admin_audit_store_enqueue_failures_total",
      &[("reason", "full")],
      self
        .admin_audit
        .store_enqueue_full_total
        .load(Ordering::Relaxed),
    );
    append_labeled_counter(
      output,
      "oxibelt_admin_audit_store_enqueue_failures_total",
      &[("reason", "closed")],
      self
        .admin_audit
        .store_enqueue_closed_total
        .load(Ordering::Relaxed),
    );
    append_labeled_counter(
      output,
      "oxibelt_admin_audit_export_events_total",
      &[("sink", "access_log")],
      self
        .admin_audit
        .export_access_log_total
        .load(Ordering::Relaxed),
    );
    append_labeled_counter(
      output,
      "oxibelt_admin_audit_dropped_total",
      &[("reason", "store_queue_full")],
      self
        .admin_audit
        .dropped_store_queue_full_total
        .load(Ordering::Relaxed),
    );
    append_labeled_counter(
      output,
      "oxibelt_admin_audit_dropped_total",
      &[("reason", "store_writer_closed")],
      self
        .admin_audit
        .dropped_store_writer_closed_total
        .load(Ordering::Relaxed),
    );
    for (index, (outcome, reason)) in WORKLOAD_IDENTITY_AUTH_OUTCOMES.iter().enumerate() {
      append_labeled_counter(
        output,
        "oxibelt_admin_workload_identity_authentication_total",
        &[("outcome", outcome), ("reason", reason)],
        self.admin_audit.workload_identity_authentication[index].load(Ordering::Relaxed),
      );
    }
  }
}

fn append_admin_audit_event(output: &mut String, outcome: &str, store: &str, value: u64) {
  append_labeled_counter(
    output,
    "oxibelt_admin_audit_events_total",
    &[("outcome", outcome), ("store", store)],
    value,
  );
}

fn append_labeled_counter(output: &mut String, name: &str, labels: &[(&str, &str)], value: u64) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push_str(" counter\n");
  output.push_str(name);
  output.push('{');
  for (index, (key, label_value)) in labels.iter().enumerate() {
    if index > 0 {
      output.push(',');
    }
    output.push_str(key);
    output.push_str("=\"");
    output.push_str(label_value);
    output.push('"');
  }
  output.push_str("} ");
  output.push_str(&value.to_string());
  output.push('\n');
}
