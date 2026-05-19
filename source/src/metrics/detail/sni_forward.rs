use crate::config::MetricsConfig;

use super::{
  DetailedMetrics, MAX_DETAILED_SERIES, Metrics, append_histogram, append_labeled_metric,
  lock_detailed, observe_histogram, sanitize_label_value,
};

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(super) struct SniForwardDecisionMetricKey {
  pub(super) protocol: String,
  pub(super) decision: String,
  pub(super) rule: String,
  pub(super) target: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(super) struct SniForwardSessionMetricKey {
  pub(super) protocol: String,
  pub(super) rule: String,
  pub(super) target: String,
  pub(super) outcome: String,
}

impl Metrics {
  pub fn record_sni_forward_decision_detail(
    &self,
    protocol: &str,
    decision: &str,
    rule: &str,
    target: &str,
  ) {
    let key = SniForwardDecisionMetricKey {
      protocol: sanitize_label_value(protocol),
      decision: sanitize_label_value(decision),
      rule: sanitize_label_value(rule),
      target: sanitize_label_value(target),
    };
    let mut detailed = lock_detailed(&self.detailed);
    if detailed.sni_forward_decisions.contains_key(&key)
      || detailed.sni_forward_decisions.len() < MAX_DETAILED_SERIES
    {
      *detailed.sni_forward_decisions.entry(key).or_default() += 1;
    }
  }

  pub fn record_sni_forward_session_detail(
    &self,
    config: &MetricsConfig,
    protocol: &str,
    rule: &str,
    target: &str,
    outcome: &str,
    duration_ms: u64,
  ) {
    let key = SniForwardSessionMetricKey {
      protocol: sanitize_label_value(protocol),
      rule: sanitize_label_value(rule),
      target: sanitize_label_value(target),
      outcome: sanitize_label_value(outcome),
    };
    let mut detailed = lock_detailed(&self.detailed);
    observe_histogram(
      &mut detailed.sni_forward_sessions,
      key,
      duration_ms,
      &config.histogram_buckets_ms,
    );
  }
}

pub(super) fn append_prometheus(output: &mut String, detailed: &DetailedMetrics) {
  for (key, value) in &detailed.sni_forward_decisions {
    let labels = [
      ("protocol", key.protocol.as_str()),
      ("decision", key.decision.as_str()),
      ("rule", key.rule.as_str()),
      ("target", key.target.as_str()),
    ];
    append_labeled_metric(
      output,
      "oxibelt_sni_forward_decisions_detail_total",
      "counter",
      &labels,
      *value,
    );
  }
  for (key, series) in &detailed.sni_forward_sessions {
    let labels = [
      ("protocol", key.protocol.as_str()),
      ("rule", key.rule.as_str()),
      ("target", key.target.as_str()),
      ("outcome", key.outcome.as_str()),
    ];
    append_labeled_metric(
      output,
      "oxibelt_sni_forward_l4_sessions_total",
      "counter",
      &labels,
      series.count,
    );
    append_histogram(
      output,
      "oxibelt_sni_forward_l4_session_duration_ms",
      &labels,
      series,
    );
  }
}
