use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use http::StatusCode;

use super::Metrics;
use crate::config::MetricsConfig;

mod sni_forward;

const MAX_DETAILED_SERIES: usize = 4096;
const MAX_LABEL_VALUE_BYTES: usize = 128;

#[derive(Debug, Default)]
pub(super) struct DetailedMetrics {
  http: HashMap<HttpMetricKey, HistogramSeries>,
  upstream: HashMap<UpstreamMetricKey, HistogramSeries>,
  cache: HashMap<CacheMetricKey, u64>,
  cache_fill_stage: HashMap<CacheFillStageMetricKey, HistogramSeries>,
  tls_handshake: HashMap<TlsHandshakeMetricKey, HistogramSeries>,
  quic_retries: HashMap<QuicRetryMetricKey, u64>,
  sni_forward_decisions: HashMap<sni_forward::SniForwardDecisionMetricKey, u64>,
  sni_forward_sessions: HashMap<sni_forward::SniForwardSessionMetricKey, HistogramSeries>,
  websocket: HashMap<LongSessionMetricKey, LongSessionSeries>,
  webtransport: HashMap<LongSessionMetricKey, LongSessionSeries>,
  turn: HashMap<TurnMetricKey, u64>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct HttpMetricKey {
  route: String,
  upstream: String,
  method: String,
  protocol: String,
  status: u16,
  status_class: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct UpstreamMetricKey {
  route: String,
  upstream: String,
  upstream_protocol: String,
  outcome: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct CacheMetricKey {
  route: String,
  policy: String,
  outcome: String,
  reason: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct CacheFillStageMetricKey {
  route: String,
  policy: String,
  stage: String,
  outcome: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct TlsHandshakeMetricKey {
  network: String,
  alpn: String,
  outcome: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct QuicRetryMetricKey {
  outcome: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct LongSessionMetricKey {
  route: String,
  upstream: String,
  protocol: String,
  outcome: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct TurnMetricKey {
  listener: String,
  transport: String,
  event: String,
}

#[derive(Debug, Clone)]
struct HistogramSeries {
  count: u64,
  sum_ms: u64,
  buckets_ms: Vec<u64>,
  bucket_counts: Vec<u64>,
}

#[derive(Debug, Clone)]
struct LongSessionSeries {
  total: u64,
  active: i64,
  durations: HistogramSeries,
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

  fn observe(&mut self, duration_ms: u64) {
    self.count = self.count.saturating_add(1);
    self.sum_ms = self.sum_ms.saturating_add(duration_ms);
    for (index, bucket) in self.buckets_ms.iter().enumerate() {
      if duration_ms <= *bucket {
        self.bucket_counts[index] = self.bucket_counts[index].saturating_add(1);
      }
    }
  }
}

impl LongSessionSeries {
  fn new(buckets_ms: &[u64]) -> Self {
    Self {
      total: 0,
      active: 0,
      durations: HistogramSeries::new(buckets_ms),
    }
  }
}

impl Metrics {
  #[allow(clippy::too_many_arguments)]
  pub fn record_http_detail(
    &self,
    config: &MetricsConfig,
    route: &str,
    upstream: &str,
    method: &str,
    protocol: &str,
    status: StatusCode,
    duration_ms: u64,
  ) {
    let key = HttpMetricKey {
      route: sanitize_label_value(route),
      upstream: sanitize_label_value(upstream),
      method: sanitize_label_value(method),
      protocol: sanitize_label_value(protocol),
      status: status.as_u16(),
      status_class: status_class(status),
    };
    let mut detailed = lock_detailed(&self.detailed);
    observe_histogram(
      &mut detailed.http,
      key,
      duration_ms,
      &config.histogram_buckets_ms,
    );
  }

  pub fn record_upstream_detail(
    &self,
    config: &MetricsConfig,
    route: &str,
    upstream: &str,
    upstream_protocol: &str,
    outcome: &str,
    duration_ms: u64,
  ) {
    let key = UpstreamMetricKey {
      route: sanitize_label_value(route),
      upstream: sanitize_label_value(upstream),
      upstream_protocol: sanitize_label_value(upstream_protocol),
      outcome: sanitize_label_value(outcome),
    };
    let mut detailed = lock_detailed(&self.detailed);
    observe_histogram(
      &mut detailed.upstream,
      key,
      duration_ms,
      &config.histogram_buckets_ms,
    );
  }

  pub fn record_cache_event(&self, route: &str, policy: Option<&str>, outcome: &str, reason: &str) {
    let key = CacheMetricKey {
      route: sanitize_label_value(route),
      policy: sanitize_label_value(policy.unwrap_or("default")),
      outcome: sanitize_label_value(outcome),
      reason: sanitize_label_value(reason),
    };
    let mut detailed = lock_detailed(&self.detailed);
    if detailed.cache.contains_key(&key) || detailed.cache.len() < MAX_DETAILED_SERIES {
      *detailed.cache.entry(key).or_default() += 1;
    }
  }

  pub fn record_cache_fill_stage(
    &self,
    config: &MetricsConfig,
    route: &str,
    policy: Option<&str>,
    stage: &str,
    outcome: &str,
    duration_ms: u64,
  ) {
    let key = CacheFillStageMetricKey {
      route: sanitize_label_value(route),
      policy: sanitize_label_value(policy.unwrap_or("default")),
      stage: sanitize_label_value(stage),
      outcome: sanitize_label_value(outcome),
    };
    let mut detailed = lock_detailed(&self.detailed);
    observe_histogram(
      &mut detailed.cache_fill_stage,
      key,
      duration_ms,
      &config.histogram_buckets_ms,
    );
  }

  pub fn record_tls_handshake(
    &self,
    config: &MetricsConfig,
    network: &str,
    alpn: &str,
    outcome: &str,
    duration_ms: u64,
  ) {
    let key = TlsHandshakeMetricKey {
      network: sanitize_label_value(network),
      alpn: sanitize_label_value(alpn),
      outcome: sanitize_label_value(outcome),
    };
    let mut detailed = lock_detailed(&self.detailed);
    observe_histogram(
      &mut detailed.tls_handshake,
      key,
      duration_ms,
      &config.histogram_buckets_ms,
    );
  }

  pub fn record_quic_retry(&self, outcome: &str) {
    let key = QuicRetryMetricKey {
      outcome: sanitize_label_value(outcome),
    };
    let mut detailed = lock_detailed(&self.detailed);
    if detailed.quic_retries.contains_key(&key) || detailed.quic_retries.len() < MAX_DETAILED_SERIES
    {
      *detailed.quic_retries.entry(key).or_default() += 1;
    }
  }

  pub fn record_websocket_session_start(
    &self,
    config: &MetricsConfig,
    route: &str,
    upstream: &str,
  ) {
    self.record_long_session_start(config, route, upstream, "websocket", true);
  }

  pub fn record_websocket_session_end(
    &self,
    config: &MetricsConfig,
    route: &str,
    upstream: &str,
    outcome: &str,
    duration_ms: u64,
  ) {
    self.record_long_session_end(config, route, upstream, "websocket", outcome, duration_ms);
  }

  pub fn record_webtransport_session_start(
    &self,
    config: &MetricsConfig,
    route: &str,
    upstream: &str,
  ) {
    self.record_long_session_start(config, route, upstream, "webtransport", false);
  }

  pub fn record_webtransport_session_end(
    &self,
    config: &MetricsConfig,
    route: &str,
    upstream: &str,
    outcome: &str,
    duration_ms: u64,
  ) {
    self.record_long_session_end(
      config,
      route,
      upstream,
      "webtransport",
      outcome,
      duration_ms,
    );
  }

  pub fn record_turn_event(&self, listener: &str, transport: &str, event: &str) {
    let key = TurnMetricKey {
      listener: sanitize_label_value(listener),
      transport: sanitize_label_value(transport),
      event: sanitize_label_value(event),
    };
    let mut detailed = lock_detailed(&self.detailed);
    if detailed.turn.contains_key(&key) || detailed.turn.len() < MAX_DETAILED_SERIES {
      *detailed.turn.entry(key).or_default() += 1;
    }
  }

  fn record_long_session_start(
    &self,
    config: &MetricsConfig,
    route: &str,
    upstream: &str,
    protocol: &str,
    websocket: bool,
  ) {
    let key = LongSessionMetricKey {
      route: sanitize_label_value(route),
      upstream: sanitize_label_value(upstream),
      protocol: sanitize_label_value(protocol),
      outcome: "open".to_string(),
    };
    let mut detailed = lock_detailed(&self.detailed);
    let map = if websocket {
      &mut detailed.websocket
    } else {
      &mut detailed.webtransport
    };
    if map.contains_key(&key) || map.len() < MAX_DETAILED_SERIES {
      let series = map
        .entry(key)
        .or_insert_with(|| LongSessionSeries::new(&config.histogram_buckets_ms));
      series.total = series.total.saturating_add(1);
      series.active = series.active.saturating_add(1);
    }
  }

  fn record_long_session_end(
    &self,
    config: &MetricsConfig,
    route: &str,
    upstream: &str,
    protocol: &str,
    outcome: &str,
    duration_ms: u64,
  ) {
    let open_key = LongSessionMetricKey {
      route: sanitize_label_value(route),
      upstream: sanitize_label_value(upstream),
      protocol: sanitize_label_value(protocol),
      outcome: "open".to_string(),
    };
    let end_key = LongSessionMetricKey {
      outcome: sanitize_label_value(outcome),
      ..open_key.clone()
    };
    let mut detailed = lock_detailed(&self.detailed);
    let map = if protocol == "websocket" {
      &mut detailed.websocket
    } else {
      &mut detailed.webtransport
    };
    if let Some(open) = map.get_mut(&open_key) {
      open.active = open.active.saturating_sub(1);
    }
    if map.contains_key(&end_key) || map.len() < MAX_DETAILED_SERIES {
      let series = map
        .entry(end_key)
        .or_insert_with(|| LongSessionSeries::new(&config.histogram_buckets_ms));
      series.total = series.total.saturating_add(1);
      series.durations.observe(duration_ms);
    }
  }

  pub(super) fn append_detailed_prometheus(&self, output: &mut String) {
    let detailed = lock_detailed(&self.detailed);
    for (key, series) in &detailed.http {
      let status = key.status.to_string();
      let labels = [
        ("route", key.route.as_str()),
        ("upstream", key.upstream.as_str()),
        ("method", key.method.as_str()),
        ("protocol", key.protocol.as_str()),
        ("status", status.as_str()),
        ("status_class", key.status_class.as_str()),
      ];
      append_labeled_metric(
        output,
        "oxibelt_http_requests_total",
        "counter",
        &labels,
        series.count,
      );
      append_histogram(output, "oxibelt_http_request_duration_ms", &labels, series);
    }
    for (key, series) in &detailed.upstream {
      let labels = [
        ("route", key.route.as_str()),
        ("upstream", key.upstream.as_str()),
        ("upstream_protocol", key.upstream_protocol.as_str()),
        ("outcome", key.outcome.as_str()),
      ];
      append_labeled_metric(
        output,
        "oxibelt_upstream_requests_total",
        "counter",
        &labels,
        series.count,
      );
      append_histogram(
        output,
        "oxibelt_upstream_request_duration_ms",
        &labels,
        series,
      );
    }
    for (key, value) in &detailed.cache {
      let labels = [
        ("route", key.route.as_str()),
        ("policy", key.policy.as_str()),
        ("outcome", key.outcome.as_str()),
        ("reason", key.reason.as_str()),
      ];
      append_labeled_metric(
        output,
        "oxibelt_cache_events_total",
        "counter",
        &labels,
        *value,
      );
    }
    for (key, series) in &detailed.cache_fill_stage {
      let labels = [
        ("route", key.route.as_str()),
        ("policy", key.policy.as_str()),
        ("stage", key.stage.as_str()),
        ("outcome", key.outcome.as_str()),
      ];
      append_histogram(
        output,
        "oxibelt_cache_fill_stage_duration_ms",
        &labels,
        series,
      );
    }
    for (key, series) in &detailed.tls_handshake {
      let labels = [
        ("network", key.network.as_str()),
        ("alpn", key.alpn.as_str()),
        ("outcome", key.outcome.as_str()),
      ];
      append_histogram(output, "oxibelt_tls_handshake_duration_ms", &labels, series);
    }
    for (key, value) in &detailed.quic_retries {
      let labels = [("outcome", key.outcome.as_str())];
      append_labeled_metric(
        output,
        "oxibelt_quic_retries_total",
        "counter",
        &labels,
        *value,
      );
    }
    sni_forward::append_prometheus(output, &detailed);
    append_long_session_metrics(output, "oxibelt_websocket", &detailed.websocket);
    append_long_session_metrics(output, "oxibelt_webtransport", &detailed.webtransport);
    for (key, value) in &detailed.turn {
      let labels = [
        ("listener", key.listener.as_str()),
        ("transport", key.transport.as_str()),
        ("event", key.event.as_str()),
      ];
      append_labeled_metric(
        output,
        "oxibelt_turn_events_total",
        "counter",
        &labels,
        *value,
      );
    }
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

fn append_histogram(
  output: &mut String,
  name: &str,
  labels: &[(&str, &str)],
  series: &HistogramSeries,
) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push_str(" histogram\n");
  for (bucket, count) in series.buckets_ms.iter().zip(series.bucket_counts.iter()) {
    let le = bucket.to_string();
    let mut bucket_labels = labels.to_vec();
    bucket_labels.push(("le", le.as_str()));
    output.push_str(name);
    output.push_str("_bucket");
    append_labels(output, &bucket_labels);
    output.push(' ');
    output.push_str(&count.to_string());
    output.push('\n');
  }
  let mut inf_labels = labels.to_vec();
  inf_labels.push(("le", "+Inf"));
  output.push_str(name);
  output.push_str("_bucket");
  append_labels(output, &inf_labels);
  output.push(' ');
  output.push_str(&series.count.to_string());
  output.push('\n');
  output.push_str(name);
  output.push_str("_sum");
  append_labels(output, labels);
  output.push(' ');
  output.push_str(&series.sum_ms.to_string());
  output.push('\n');
  output.push_str(name);
  output.push_str("_count");
  append_labels(output, labels);
  output.push(' ');
  output.push_str(&series.count.to_string());
  output.push('\n');
}

fn append_long_session_metrics(
  output: &mut String,
  prefix: &str,
  map: &HashMap<LongSessionMetricKey, LongSessionSeries>,
) {
  for (key, series) in map {
    let labels = [
      ("route", key.route.as_str()),
      ("upstream", key.upstream.as_str()),
      ("protocol", key.protocol.as_str()),
      ("outcome", key.outcome.as_str()),
    ];
    let total_name = format!("{prefix}_sessions_total");
    append_labeled_metric(output, &total_name, "counter", &labels, series.total);
    let active_name = format!("{prefix}_active_sessions");
    append_labeled_metric(output, &active_name, "gauge", &labels, series.active);
    let duration_name = format!("{prefix}_session_duration_ms");
    append_histogram(output, &duration_name, &labels, &series.durations);
  }
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

fn lock_detailed(detailed: &Mutex<DetailedMetrics>) -> MutexGuard<'_, DetailedMetrics> {
  detailed
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn observe_histogram<K>(
  map: &mut HashMap<K, HistogramSeries>,
  key: K,
  duration_ms: u64,
  buckets_ms: &[u64],
) where
  K: Eq + std::hash::Hash,
{
  if map.contains_key(&key) || map.len() < MAX_DETAILED_SERIES {
    map
      .entry(key)
      .or_insert_with(|| HistogramSeries::new(buckets_ms))
      .observe(duration_ms);
  }
}

fn sanitize_label_value(value: &str) -> String {
  if value.is_empty() {
    return "none".to_string();
  }
  value.chars().take(MAX_LABEL_VALUE_BYTES).collect()
}

fn status_class(status: StatusCode) -> String {
  format!("{}xx", status.as_u16() / 100)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cache::CacheStats;
  use crate::config::MetricsDetail;
  use crate::tls::TlsServerSessionStorageStats;

  #[test]
  fn detailed_prometheus_output_escapes_labels_and_histograms() {
    let metrics = Metrics::new();
    let config = MetricsConfig::default();
    metrics.record_http_detail(
      &config,
      "route\"one",
      "up\\stream",
      "GET",
      "h2",
      StatusCode::OK,
      7,
    );

    let body = metrics.prometheus(
      &config,
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );

    assert!(body.contains("oxibelt_http_requests_total"));
    assert!(body.contains("route=\"route\\\"one\""));
    assert!(body.contains("upstream=\"up\\\\stream\""));
    assert!(body.contains("oxibelt_http_request_duration_ms_bucket"));
    assert!(body.contains("le=\"10\""));
  }

  #[test]
  fn basic_prometheus_output_omits_detailed_series() {
    let metrics = Metrics::new();
    let config = MetricsConfig {
      detail: MetricsDetail::Basic,
      ..MetricsConfig::default()
    };
    metrics.record_cache_event("app", Some("edge"), "miss", "lookup");

    let body = metrics.prometheus(
      &config,
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );

    assert!(!body.contains("oxibelt_cache_events_total"));
  }

  #[test]
  fn detailed_prometheus_output_includes_cache_reasons() {
    let metrics = Metrics::new();
    let config = MetricsConfig::default();
    metrics.record_cache_event("app", Some("edge"), "miss", "fill_lock_timeout");
    metrics.record_cache_event("app", Some("edge"), "miss", "fill_not_stored");
    metrics.record_cache_fill_stage(&config, "app", Some("edge"), "body_collect", "ok", 7);

    let body = metrics.prometheus(
      &config,
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );

    assert!(body.contains("oxibelt_cache_events_total"));
    assert!(body.contains("oxibelt_cache_fill_stage_duration_ms_bucket"));
    assert!(body.contains("stage=\"body_collect\""));
    assert!(body.contains("reason=\"fill_lock_timeout\""));
    assert!(body.contains("reason=\"fill_not_stored\""));
    assert!(!body.contains("rule_name"));
    assert!(!body.contains("rule_id"));
  }
}
