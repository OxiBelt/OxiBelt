//! Fixed-cardinality metrics for post-activation backend failure policies.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

const MAX_SERIES: usize = 256;
const MAX_LABEL_VALUE_BYTES: usize = 128;

#[derive(Debug, Default)]
pub(super) struct BackendFailureMetrics {
  inner: Mutex<HashMap<BackendFailureKey, BackendFailureSeries>>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct BackendFailureKey {
  backend: String,
  kind: &'static str,
  feature: &'static str,
  mode: &'static str,
}

#[derive(Debug, Default)]
struct BackendFailureSeries {
  degraded: bool,
  policy_applied: HashMap<&'static str, u64>,
  recoveries: u64,
  local_fallback_entries: u64,
  stale_snapshot_age_seconds: u64,
}

impl BackendFailureMetrics {
  pub(super) fn register(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
  ) {
    let mut inner = self.lock();
    if let Some(key) = metric_key(&inner, backend, kind, feature, mode) {
      inner.entry(key).or_default();
    }
  }

  pub(super) fn policy_applied(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
    failure_kind: &'static str,
  ) {
    let mut inner = self.lock();
    let Some(key) = metric_key(&inner, backend, kind, feature, mode) else {
      return;
    };
    let series = inner.entry(key).or_default();
    *series.policy_applied.entry(failure_kind).or_default() += 1;
    series.degraded = true;
  }

  pub(super) fn recovered(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
  ) {
    let mut inner = self.lock();
    let Some(key) = metric_key(&inner, backend, kind, feature, mode) else {
      return;
    };
    let series = inner.entry(key).or_default();
    series.recoveries = series.recoveries.saturating_add(1);
    series.degraded = false;
    series.stale_snapshot_age_seconds = 0;
  }

  pub(super) fn local_fallback_entered(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
  ) {
    let mut inner = self.lock();
    let Some(key) = metric_key(&inner, backend, kind, feature, mode) else {
      return;
    };
    let series = inner.entry(key).or_default();
    series.local_fallback_entries = series.local_fallback_entries.saturating_add(1);
    series.degraded = true;
  }

  pub(super) fn stale_snapshot_age(
    &self,
    backend: &str,
    kind: &'static str,
    feature: &'static str,
    mode: &'static str,
    age_seconds: u64,
  ) {
    let mut inner = self.lock();
    let Some(key) = metric_key(&inner, backend, kind, feature, mode) else {
      return;
    };
    let series = inner.entry(key).or_default();
    series.stale_snapshot_age_seconds = age_seconds;
    series.degraded = true;
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    let inner = self.lock();
    for (key, series) in inner.iter() {
      append_metric(
        output,
        "oxibelt_backend_feature_degraded",
        "gauge",
        labels(key),
        if series.degraded { 1 } else { 0 },
      );
      for (failure_kind, value) in &series.policy_applied {
        append_metric(
          output,
          "oxibelt_backend_failure_policy_applied_total",
          "counter",
          labels_with(key, "failure_kind", failure_kind),
          *value,
        );
      }
      append_metric(
        output,
        "oxibelt_backend_feature_recoveries_total",
        "counter",
        labels(key),
        series.recoveries,
      );
      append_metric(
        output,
        "oxibelt_backend_local_fallback_entries",
        "counter",
        labels(key),
        series.local_fallback_entries,
      );
      append_metric(
        output,
        "oxibelt_backend_stale_snapshot_age_seconds",
        "gauge",
        labels(key),
        series.stale_snapshot_age_seconds,
      );
    }
  }

  fn lock(&self) -> MutexGuard<'_, HashMap<BackendFailureKey, BackendFailureSeries>> {
    self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
  }
}

fn metric_key(
  metrics: &HashMap<BackendFailureKey, BackendFailureSeries>,
  backend: &str,
  kind: &'static str,
  feature: &'static str,
  mode: &'static str,
) -> Option<BackendFailureKey> {
  let sanitized = sanitize_label(backend);
  let candidate = BackendFailureKey {
    backend: sanitized,
    kind,
    feature,
    mode,
  };
  if metrics.contains_key(&candidate) || metrics.len() < MAX_SERIES {
    return Some(candidate);
  }
  let other = BackendFailureKey {
    backend: "other".to_string(),
    kind,
    feature,
    mode,
  };
  if metrics.contains_key(&other) {
    Some(other)
  } else {
    None
  }
}

fn sanitize_label(value: &str) -> String {
  let mut out = String::with_capacity(value.len().min(MAX_LABEL_VALUE_BYTES));
  for byte in value.bytes().take(MAX_LABEL_VALUE_BYTES) {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
      out.push(byte as char);
    } else {
      out.push('_');
    }
  }
  if out.is_empty() {
    "unknown".to_string()
  } else {
    out
  }
}

fn labels(key: &BackendFailureKey) -> [(&'static str, &str); 4] {
  [
    ("feature", key.feature),
    ("backend", key.backend.as_str()),
    ("kind", key.kind),
    ("mode", key.mode),
  ]
}

fn labels_with<'a>(
  key: &'a BackendFailureKey,
  label: &'static str,
  value: &'a str,
) -> [(&'static str, &'a str); 5] {
  [
    ("feature", key.feature),
    ("backend", key.backend.as_str()),
    ("kind", key.kind),
    ("mode", key.mode),
    (label, value),
  ]
}

fn append_metric(
  output: &mut String,
  name: &str,
  kind: &str,
  labels: impl IntoIterator<Item = (&'static str, impl AsRef<str>)>,
  value: impl std::fmt::Display,
) {
  let _ = writeln!(output, "# TYPE {name} {kind}");
  let _ = write!(output, "{name}");
  let mut first = true;
  for (label, value) in labels {
    if first {
      output.push('{');
      first = false;
    } else {
      output.push(',');
    }
    let escaped = value.as_ref().replace('\\', "\\\\").replace('"', "\\\"");
    let _ = write!(output, "{label}=\"{escaped}\"");
  }
  if !first {
    output.push('}');
  }
  let _ = writeln!(output, " {value}");
}

#[cfg(test)]
mod tests {
  use super::BackendFailureMetrics;

  #[test]
  fn series_are_bounded_by_configured_backend_identity() {
    let metrics = BackendFailureMetrics::default();
    for index in 0..(super::MAX_SERIES + 1) {
      let backend = format!("backend-{index}");
      metrics.register(&backend, "redis", "cache", "local_fallback");
    }
    let mut output = String::new();
    metrics.append_prometheus(&mut output);
    assert!(output.contains("backend=\"backend-255\""));
    assert!(!output.contains("backend=\"backend-256\""));
  }
}
