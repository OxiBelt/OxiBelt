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

const AUDIT_EVENT_OUTCOMES: [&str; 5] = [
  "accepted",
  "applied",
  "rejected",
  "indeterminate",
  "unknown",
];
const AUDIT_EVENT_STORES: [&str; 3] = ["postgres", "spool", "none"];
const REQUIRED_REJECTION_REASONS: [&str; 5] = [
  "spool_full",
  "spool_io",
  "postgres_unavailable",
  "event_oversize",
  "integrity_failure",
];
const REPLAY_OUTCOMES: [&str; 2] = ["persisted", "failed"];

#[derive(Debug, Default)]
pub(super) struct AdminAuditMetrics {
  events: [AtomicU64; AUDIT_EVENT_OUTCOMES.len() * AUDIT_EVENT_STORES.len()],
  store_enqueue_full_total: AtomicU64,
  store_enqueue_closed_total: AtomicU64,
  export_access_log_total: AtomicU64,
  dropped_store_queue_full_total: AtomicU64,
  dropped_store_writer_closed_total: AtomicU64,
  required_rejections: [AtomicU64; REQUIRED_REJECTION_REASONS.len()],
  replay: [AtomicU64; REPLAY_OUTCOMES.len()],
  integrity_failures_total: AtomicU64,
  spool_events: AtomicU64,
  spool_bytes: AtomicU64,
  workload_identity_authentication: [AtomicU64; WORKLOAD_IDENTITY_AUTH_OUTCOMES.len()],
}

impl Metrics {
  pub fn record_admin_audit_event(&self, outcome: &str, store: &str) {
    let outcome_index = AUDIT_EVENT_OUTCOMES
      .iter()
      .position(|candidate| *candidate == outcome)
      .unwrap_or(AUDIT_EVENT_OUTCOMES.len() - 1);
    let normalized_store = if store == "postgres_sync" {
      "postgres"
    } else {
      store
    };
    let store_index = AUDIT_EVENT_STORES
      .iter()
      .position(|candidate| *candidate == normalized_store)
      .unwrap_or(AUDIT_EVENT_STORES.len() - 1);
    let index = outcome_index * AUDIT_EVENT_STORES.len() + store_index;
    self.admin_audit.events[index].fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_admin_audit_required_rejection(&self, reason: &str) {
    if let Some(index) = REQUIRED_REJECTION_REASONS
      .iter()
      .position(|candidate| *candidate == reason)
    {
      self.admin_audit.required_rejections[index].fetch_add(1, Ordering::Relaxed);
    }
  }

  pub fn record_admin_audit_replay(&self, outcome: &str) {
    if let Some(index) = REPLAY_OUTCOMES
      .iter()
      .position(|candidate| *candidate == outcome)
    {
      self.admin_audit.replay[index].fetch_add(1, Ordering::Relaxed);
    }
  }

  pub fn record_admin_audit_integrity_failure(&self) {
    self
      .admin_audit
      .integrity_failures_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn set_admin_audit_spool_usage(&self, events: u64, bytes: u64) {
    self
      .admin_audit
      .spool_events
      .store(events, Ordering::Relaxed);
    self.admin_audit.spool_bytes.store(bytes, Ordering::Relaxed);
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
    for (outcome_index, outcome) in AUDIT_EVENT_OUTCOMES.iter().enumerate() {
      for (store_index, store) in AUDIT_EVENT_STORES.iter().enumerate() {
        let index = outcome_index * AUDIT_EVENT_STORES.len() + store_index;
        append_admin_audit_event(
          output,
          outcome,
          store,
          self.admin_audit.events[index].load(Ordering::Relaxed),
        );
      }
    }
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
    for (index, reason) in REQUIRED_REJECTION_REASONS.iter().enumerate() {
      append_labeled_counter(
        output,
        "oxibelt_admin_audit_required_rejections_total",
        &[("reason", reason)],
        self.admin_audit.required_rejections[index].load(Ordering::Relaxed),
      );
    }
    for (index, outcome) in REPLAY_OUTCOMES.iter().enumerate() {
      append_labeled_counter(
        output,
        "oxibelt_admin_audit_replay_total",
        &[("outcome", outcome)],
        self.admin_audit.replay[index].load(Ordering::Relaxed),
      );
    }
    append_counter(
      output,
      "oxibelt_admin_audit_integrity_failures_total",
      self
        .admin_audit
        .integrity_failures_total
        .load(Ordering::Relaxed),
    );
    append_gauge(
      output,
      "oxibelt_admin_audit_spool_events",
      self.admin_audit.spool_events.load(Ordering::Relaxed),
    );
    append_gauge(
      output,
      "oxibelt_admin_audit_spool_bytes",
      self.admin_audit.spool_bytes.load(Ordering::Relaxed),
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

fn append_counter(output: &mut String, name: &str, value: u64) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push_str(" counter\n");
  output.push_str(name);
  output.push(' ');
  output.push_str(&value.to_string());
  output.push('\n');
}

fn append_gauge(output: &mut String, name: &str, value: u64) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push_str(" gauge\n");
  output.push_str(name);
  output.push(' ');
  output.push_str(&value.to_string());
  output.push('\n');
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
