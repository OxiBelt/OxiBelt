//! Fixed-label fast-path selection counters.

use super::{FastPathMetrics, PROTOCOLS, append_u64, protocol_index};

const PATHS: [&str; 7] = [
  "static_sendfile_like",
  "plain_proxy_h1",
  "plain_proxy_h2",
  "plain_proxy_h3",
  "direct_h1",
  "direct_h2",
  "cache_hit",
];
const OUTCOMES: [&str; 2] = ["selected", "not_selected"];
const REASONS: [&str; 8] = [
  "used",
  "route_plan",
  "runtime_guard",
  "cache_policy",
  "transport_error",
  "disabled",
  "unsupported",
  "fallback",
];
const COUNTERS_PER_PROTOCOL: usize = OUTCOMES.len() * REASONS.len();
const COUNTERS_PER_PATH: usize = PROTOCOLS.len() * COUNTERS_PER_PROTOCOL;
pub(super) const COUNTER_COUNT: usize = PATHS.len() * COUNTERS_PER_PATH;

pub(super) fn record(
  metrics: &FastPathMetrics,
  path: &str,
  protocol: &str,
  outcome: &str,
  reason: &str,
) {
  let Some(index) = counter_index(path, protocol, outcome, reason) else {
    return;
  };
  metrics.selection_counters[index].increment();
}

pub(super) fn append_prometheus(metrics: &FastPathMetrics, output: &mut String) {
  for path in PATHS {
    for protocol in PROTOCOLS {
      for outcome in OUTCOMES {
        for reason in REASONS {
          append_counter(
            output,
            path,
            protocol,
            outcome,
            reason,
            metrics.selection_counters
              [counter_index(path, protocol, outcome, reason).expect("selection counter exists")]
            .load(),
          );
        }
      }
    }
  }
}

fn counter_index(path: &str, protocol: &str, outcome: &str, reason: &str) -> Option<usize> {
  let path_index = PATHS.iter().position(|candidate| *candidate == path)?;
  let protocol_index = protocol_index(protocol)?;
  let outcome_index = OUTCOMES
    .iter()
    .position(|candidate| *candidate == outcome)?;
  let reason_index = REASONS.iter().position(|candidate| *candidate == reason)?;
  Some(
    path_index * COUNTERS_PER_PATH
      + protocol_index * COUNTERS_PER_PROTOCOL
      + outcome_index * REASONS.len()
      + reason_index,
  )
}

fn append_counter(
  output: &mut String,
  path: &str,
  protocol: &str,
  outcome: &str,
  reason: &str,
  value: u64,
) {
  output.push_str("# TYPE oxibelt_http_fast_path_selections_total counter\n");
  output.push_str("oxibelt_http_fast_path_selections_total{path=\"");
  output.push_str(path);
  output.push_str("\",protocol=\"");
  output.push_str(protocol);
  output.push_str("\",outcome=\"");
  output.push_str(outcome);
  output.push_str("\",reason=\"");
  output.push_str(reason);
  output.push_str("\"} ");
  append_u64(output, value);
  output.push('\n');
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn records_only_known_selection_label_sets() {
    let metrics = FastPathMetrics::default();
    metrics.record_selection("plain_proxy_h1", "h1", "selected", "used");
    metrics.record_selection("cache_hit", "h2", "selected", "used");
    metrics.record_selection("cache_hit", "h9", "selected", "used");
    metrics.record_selection("cache_hit", "h2", "maybe", "used");
    metrics.record_selection("cache_hit", "h2", "selected", "unknown");

    assert_eq!(
      metrics.selection_counters
        [counter_index("plain_proxy_h1", "h1", "selected", "used").unwrap()]
      .load(),
      1
    );
    assert_eq!(
      metrics.selection_counters[counter_index("cache_hit", "h2", "selected", "used").unwrap()]
        .load(),
      1
    );
  }
}
