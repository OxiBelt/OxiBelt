//! Bounded telemetry for asynchronous shared-state work.
//! Backend labels are derived from validated configuration only; request data is never exported.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

use super::SharedStatePoolStatus;

const MAX_SERIES: usize = 4096;
const MAX_LABEL_VALUE_BYTES: usize = 128;
const DEFAULT_BUCKETS_MS: &[u64] = &[1, 5, 10, 25, 50, 100, 250, 500, 1_000, 5_000];

#[derive(Debug)]
pub(super) struct SharedStateMetrics {
  inner: Mutex<SharedStateMetricsInner>,
}

#[derive(Debug)]
struct SharedStateMetricsInner {
  buckets_ms: Vec<u64>,
  queue: HashMap<MetricKey, HistogramSeries>,
  operation: HashMap<MetricKey, HistogramSeries>,
  operations_total: HashMap<MetricKey, u64>,
  queued: HashMap<BackendKey, i64>,
  in_flight: HashMap<BackendKey, i64>,
  deferred_cleanup_dropped: HashMap<BackendKey, u64>,
  pool_status: HashMap<BackendKey, SharedStatePoolStatus>,
  pool_acquisitions: HashMap<PoolMetricKey, u64>,
  pool_connection_events: HashMap<PoolMetricKey, u64>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct BackendKey {
  backend: String,
  kind: &'static str,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct MetricKey {
  backend: String,
  kind: &'static str,
  operation: &'static str,
  outcome: &'static str,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct PoolMetricKey {
  backend: String,
  kind: &'static str,
  value: &'static str,
}

#[derive(Debug, Clone)]
struct HistogramSeries {
  count: u64,
  sum_ms: u64,
  buckets_ms: Vec<u64>,
  bucket_counts: Vec<u64>,
}

impl Default for SharedStateMetrics {
  fn default() -> Self {
    Self {
      inner: Mutex::new(SharedStateMetricsInner {
        buckets_ms: DEFAULT_BUCKETS_MS.to_vec(),
        queue: HashMap::new(),
        operation: HashMap::new(),
        operations_total: HashMap::new(),
        queued: HashMap::new(),
        in_flight: HashMap::new(),
        deferred_cleanup_dropped: HashMap::new(),
        pool_status: HashMap::new(),
        pool_acquisitions: HashMap::new(),
        pool_connection_events: HashMap::new(),
      }),
    }
  }
}

impl HistogramSeries {
  fn new(buckets_ms: &[u64]) -> Self {
    Self {
      count: 0,
      sum_ms: 0,
      buckets_ms: buckets_ms.to_vec(),
      bucket_counts: vec![0; buckets_ms.len()],
    }
  }

  fn observe(&mut self, value_ms: u64) {
    self.count = self.count.saturating_add(1);
    self.sum_ms = self.sum_ms.saturating_add(value_ms);
    for (index, bucket) in self.buckets_ms.iter().enumerate() {
      if value_ms <= *bucket {
        self.bucket_counts[index] = self.bucket_counts[index].saturating_add(1);
      }
    }
  }
}

impl SharedStateMetrics {
  pub(super) fn configure(&self, buckets_ms: &[u64]) {
    if buckets_ms.is_empty() {
      return;
    }
    let mut inner = self.lock();
    if inner.buckets_ms != buckets_ms {
      // Histogram bucket changes are a configuration boundary. Existing samples retain
      // their prior series until the next process start instead of being relabeled.
      if inner.queue.is_empty() && inner.operation.is_empty() {
        inner.buckets_ms = buckets_ms.to_vec();
      }
    }
  }

  pub(super) fn queue_started(&self, backend: &str, kind: &'static str) {
    let mut inner = self.lock();
    let key = backend_key(&mut inner, backend, kind);
    *inner.queued.entry(key).or_default() += 1;
  }

  pub(super) fn queue_finished(
    &self,
    backend: &str,
    kind: &'static str,
    operation: &'static str,
    outcome: &'static str,
    duration_ms: u64,
  ) {
    let mut inner = self.lock();
    let backend_key = backend_key(&mut inner, backend, kind);
    decrement_gauge(&mut inner.queued, &backend_key);
    let key = metric_key(&mut inner, backend, kind, operation, outcome);
    let buckets = inner.buckets_ms.clone();
    inner
      .queue
      .entry(key)
      .or_insert_with(|| HistogramSeries::new(&buckets))
      .observe(duration_ms);
  }

  pub(super) fn operation_started(&self, backend: &str, kind: &'static str) {
    let mut inner = self.lock();
    let key = backend_key(&mut inner, backend, kind);
    *inner.in_flight.entry(key).or_default() += 1;
  }

  pub(super) fn operation_finished(
    &self,
    backend: &str,
    kind: &'static str,
    operation: &'static str,
    outcome: &'static str,
    duration_ms: u64,
  ) {
    let mut inner = self.lock();
    let backend_key = backend_key(&mut inner, backend, kind);
    decrement_gauge(&mut inner.in_flight, &backend_key);
    let key = metric_key(&mut inner, backend, kind, operation, outcome);
    let buckets = inner.buckets_ms.clone();
    inner
      .operation
      .entry(key.clone())
      .or_insert_with(|| HistogramSeries::new(&buckets))
      .observe(duration_ms);
    *inner.operations_total.entry(key).or_default() += 1;
  }

  pub(super) fn deferred_cleanup_dropped(&self, backend: &str, kind: &'static str) {
    let mut inner = self.lock();
    let key = backend_key(&mut inner, backend, kind);
    *inner.deferred_cleanup_dropped.entry(key).or_default() += 1;
  }

  pub(super) fn pool_status(
    &self,
    backend: &str,
    kind: &'static str,
    status: SharedStatePoolStatus,
  ) {
    let mut inner = self.lock();
    let key = backend_key(&mut inner, backend, kind);
    inner.pool_status.insert(key, status);
  }

  pub(super) fn pool_acquisition(&self, backend: &str, kind: &'static str, outcome: &'static str) {
    let mut inner = self.lock();
    let key = pool_metric_key(&mut inner, backend, kind, outcome);
    *inner.pool_acquisitions.entry(key).or_default() += 1;
  }

  pub(super) fn pool_connection_event(
    &self,
    backend: &str,
    kind: &'static str,
    event: &'static str,
  ) {
    let mut inner = self.lock();
    let key = pool_metric_key(&mut inner, backend, kind, event);
    *inner.pool_connection_events.entry(key).or_default() += 1;
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    let inner = self.lock();
    for (key, series) in &inner.queue {
      append_histogram(
        output,
        "oxibelt_shared_state_queue_duration_ms",
        key,
        series,
      );
    }
    for (key, series) in &inner.operation {
      append_histogram(
        output,
        "oxibelt_shared_state_operation_duration_ms",
        key,
        series,
      );
    }
    for (key, value) in &inner.operations_total {
      append_metric(
        output,
        "oxibelt_shared_state_operations_total",
        "counter",
        metric_labels(key),
        *value,
      );
    }
    for (key, value) in &inner.queued {
      append_metric(
        output,
        "oxibelt_shared_state_queued_operations",
        "gauge",
        backend_labels(key),
        (*value).max(0),
      );
    }
    for (key, value) in &inner.in_flight {
      append_metric(
        output,
        "oxibelt_shared_state_in_flight_operations",
        "gauge",
        backend_labels(key),
        (*value).max(0),
      );
    }
    for (key, value) in &inner.deferred_cleanup_dropped {
      append_metric(
        output,
        "oxibelt_shared_state_deferred_cleanup_dropped_total",
        "counter",
        backend_labels(key),
        *value,
      );
    }
    for (key, status) in &inner.pool_status {
      append_metric(
        output,
        "oxibelt_shared_state_pool_connections",
        "gauge",
        [
          ("backend", key.backend.as_str()),
          ("kind", key.kind),
          ("state", "active"),
        ],
        status.active,
      );
      append_metric(
        output,
        "oxibelt_shared_state_pool_connections",
        "gauge",
        [
          ("backend", key.backend.as_str()),
          ("kind", key.kind),
          ("state", "idle"),
        ],
        status.idle,
      );
      append_metric(
        output,
        "oxibelt_shared_state_pool_waiters",
        "gauge",
        backend_labels(key),
        status.waiting,
      );
      append_metric(
        output,
        "oxibelt_shared_state_pool_max_connections",
        "gauge",
        backend_labels(key),
        status.max_connections,
      );
      for state in ["closed", "open", "half_open"] {
        append_metric(
          output,
          "oxibelt_shared_state_pool_circuit_state",
          "gauge",
          [
            ("backend", key.backend.as_str()),
            ("kind", key.kind),
            ("state", state),
          ],
          if status.circuit_state == state { 1 } else { 0 },
        );
      }
    }
    for (key, value) in &inner.pool_acquisitions {
      append_metric(
        output,
        "oxibelt_shared_state_pool_acquisitions_total",
        "counter",
        pool_metric_labels(key, "outcome"),
        *value,
      );
    }
    for (key, value) in &inner.pool_connection_events {
      append_metric(
        output,
        "oxibelt_shared_state_pool_connection_events_total",
        "counter",
        pool_metric_labels(key, "event"),
        *value,
      );
    }
  }

  fn lock(&self) -> MutexGuard<'_, SharedStateMetricsInner> {
    self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
  }
}

fn backend_key(
  inner: &mut SharedStateMetricsInner,
  backend: &str,
  kind: &'static str,
) -> BackendKey {
  let backend = bounded_backend_label(inner, backend, kind);
  BackendKey { backend, kind }
}

fn metric_key(
  inner: &mut SharedStateMetricsInner,
  backend: &str,
  kind: &'static str,
  operation: &'static str,
  outcome: &'static str,
) -> MetricKey {
  let backend = bounded_backend_label(inner, backend, kind);
  MetricKey {
    backend,
    kind,
    operation,
    outcome,
  }
}

fn pool_metric_key(
  inner: &mut SharedStateMetricsInner,
  backend: &str,
  kind: &'static str,
  value: &'static str,
) -> PoolMetricKey {
  PoolMetricKey {
    backend: bounded_backend_label(inner, backend, kind),
    kind,
    value,
  }
}

fn bounded_backend_label(
  inner: &SharedStateMetricsInner,
  backend: &str,
  kind: &'static str,
) -> String {
  let backend = sanitize_label(backend);
  let exists = inner
    .queued
    .keys()
    .chain(inner.in_flight.keys())
    .chain(inner.deferred_cleanup_dropped.keys())
    .chain(inner.pool_status.keys())
    .any(|key| key.backend == backend && key.kind == kind)
    || inner
      .operations_total
      .keys()
      .any(|key| key.backend == backend && key.kind == kind)
    || inner
      .pool_acquisitions
      .keys()
      .chain(inner.pool_connection_events.keys())
      .any(|key| key.backend == backend && key.kind == kind);
  let series = inner.queue.len()
    + inner.operation.len()
    + inner.operations_total.len()
    + inner.pool_acquisitions.len()
    + inner.pool_connection_events.len();
  if exists || series < MAX_SERIES {
    backend
  } else {
    "other".to_string()
  }
}

fn decrement_gauge(values: &mut HashMap<BackendKey, i64>, key: &BackendKey) {
  if let Some(value) = values.get_mut(key) {
    *value = value.saturating_sub(1).max(0);
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

fn backend_labels(key: &BackendKey) -> [(&'static str, &str); 2] {
  [("backend", key.backend.as_str()), ("kind", key.kind)]
}

fn metric_labels(key: &MetricKey) -> [(&'static str, &str); 4] {
  [
    ("backend", key.backend.as_str()),
    ("kind", key.kind),
    ("operation", key.operation),
    ("outcome", key.outcome),
  ]
}

fn pool_metric_labels<'a>(
  key: &'a PoolMetricKey,
  label: &'static str,
) -> [(&'static str, &'a str); 3] {
  [
    ("backend", key.backend.as_str()),
    ("kind", key.kind),
    (label, key.value),
  ]
}

fn append_histogram(output: &mut String, name: &str, key: &MetricKey, series: &HistogramSeries) {
  for (index, bucket) in series.buckets_ms.iter().enumerate() {
    let mut labels = metric_labels(key).to_vec();
    let bound = bucket.to_string();
    labels.push(("le", bound.as_str()));
    append_metric(
      output,
      &format!("{name}_bucket"),
      "histogram",
      labels,
      series.bucket_counts[index],
    );
  }
  let mut labels = metric_labels(key).to_vec();
  labels.push(("le", "+Inf"));
  append_metric(
    output,
    &format!("{name}_bucket"),
    "histogram",
    labels,
    series.count,
  );
  append_metric(
    output,
    &format!("{name}_sum"),
    "histogram",
    metric_labels(key),
    series.sum_ms,
  );
  append_metric(
    output,
    &format!("{name}_count"),
    "histogram",
    metric_labels(key),
    series.count,
  );
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
