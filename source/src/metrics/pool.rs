use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

const MAX_LABEL_VALUE_CHARS: usize = 128;

#[derive(Debug, Default)]
pub(super) struct PoolMetrics {
  inner: Mutex<PoolMetricsInner>,
}

#[derive(Debug, Default)]
struct PoolMetricsInner {
  server_counts: HashMap<PoolServerCountMetricKey, u64>,
  health_reports: HashMap<PoolHealthReportMetricKey, u64>,
  outlier_ejections: HashMap<PoolOutlierEjectionMetricKey, u64>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct PoolServerCountMetricKey {
  pool: String,
  source: String,
  state: String,
  reason: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct PoolHealthReportMetricKey {
  pool: String,
  source: String,
  outcome: String,
  reason: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct PoolOutlierEjectionMetricKey {
  pool: String,
  source: String,
  reason: String,
}

impl PoolMetrics {
  pub(super) fn set_server_counts(&self, counts: Vec<(String, String, String, String, u64)>) {
    let mut inner = self.lock();
    inner.server_counts.clear();
    for (pool, source, state, reason, count) in counts {
      inner.server_counts.insert(
        PoolServerCountMetricKey {
          pool: sanitize_label(&pool),
          source: sanitize_label(&source),
          state: sanitize_label(&state),
          reason: sanitize_label(&reason),
        },
        count,
      );
    }
  }

  pub(super) fn record_health_report(&self, pool: &str, source: &str, outcome: &str, reason: &str) {
    let key = PoolHealthReportMetricKey {
      pool: sanitize_label(pool),
      source: sanitize_label(source),
      outcome: sanitize_label(outcome),
      reason: sanitize_label(reason),
    };
    let mut inner = self.lock();
    *inner.health_reports.entry(key).or_default() += 1;
  }

  pub(super) fn record_outlier_ejection(&self, pool: &str, source: &str, reason: &str) {
    let key = PoolOutlierEjectionMetricKey {
      pool: sanitize_label(pool),
      source: sanitize_label(source),
      reason: sanitize_label(reason),
    };
    let mut inner = self.lock();
    *inner.outlier_ejections.entry(key).or_default() += 1;
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    let inner = self.lock();
    for (key, value) in &inner.server_counts {
      let labels = [
        ("pool", key.pool.as_str()),
        ("source", key.source.as_str()),
        ("state", key.state.as_str()),
        ("reason", key.reason.as_str()),
      ];
      append_labeled_metric(
        output,
        "oxibelt_upstream_pool_servers",
        "gauge",
        &labels,
        *value,
      );
    }
    for (key, value) in &inner.health_reports {
      let labels = [
        ("pool", key.pool.as_str()),
        ("source", key.source.as_str()),
        ("outcome", key.outcome.as_str()),
        ("reason", key.reason.as_str()),
      ];
      append_labeled_metric(
        output,
        "oxibelt_upstream_pool_health_reports_total",
        "counter",
        &labels,
        *value,
      );
    }
    for (key, value) in &inner.outlier_ejections {
      let labels = [
        ("pool", key.pool.as_str()),
        ("source", key.source.as_str()),
        ("reason", key.reason.as_str()),
      ];
      append_labeled_metric(
        output,
        "oxibelt_upstream_pool_outlier_ejections_total",
        "counter",
        &labels,
        *value,
      );
    }
  }

  fn lock(&self) -> MutexGuard<'_, PoolMetricsInner> {
    self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
  }
}

fn append_labeled_metric(
  output: &mut String,
  name: &str,
  kind: &str,
  labels: &[(&str, &str)],
  value: impl std::fmt::Display,
) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push(' ');
  output.push_str(kind);
  output.push('\n');
  output.push_str(name);
  append_labels(output, labels);
  output.push(' ');
  output.push_str(&value.to_string());
  output.push('\n');
}

fn append_labels(output: &mut String, labels: &[(&str, &str)]) {
  if labels.is_empty() {
    return;
  }
  output.push('{');
  for (index, (key, value)) in labels.iter().enumerate() {
    if index > 0 {
      output.push(',');
    }
    output.push_str(key);
    output.push_str("=\"");
    append_escaped_label_value(output, value);
    output.push('"');
  }
  output.push('}');
}

fn append_escaped_label_value(output: &mut String, value: &str) {
  for ch in value.chars() {
    match ch {
      '\\' => output.push_str("\\\\"),
      '"' => output.push_str("\\\""),
      '\n' => output.push_str("\\n"),
      _ => output.push(ch),
    }
  }
}

fn sanitize_label(value: &str) -> String {
  if value.is_empty() {
    return "none".to_string();
  }
  value.chars().take(MAX_LABEL_VALUE_CHARS).collect()
}
