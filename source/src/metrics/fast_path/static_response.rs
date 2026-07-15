//! Static-file fast-path response counters.

use super::{FastPathMetrics, append_u64};

const SOURCES: [&str; 4] = ["hot_object", "sendfile", "empty", "text"];
const OUTCOMES: [&str; 2] = ["served", "fallback"];
pub(super) const COUNTER_COUNT: usize = SOURCES.len() * OUTCOMES.len();

pub(super) fn record(metrics: &FastPathMetrics, source: &str, outcome: &str) {
  let Some(index) = counter_index(source, outcome) else {
    return;
  };
  metrics.static_fast_path_counters[index].increment();
}

#[allow(
  clippy::expect_used,
  reason = "the nested loops enumerate the same fixed label sets used by counter_index"
)]
pub(super) fn append_prometheus(metrics: &FastPathMetrics, output: &mut String) {
  for source in SOURCES {
    for outcome in OUTCOMES {
      append_counter(
        output,
        source,
        outcome,
        metrics.static_fast_path_counters
          [counter_index(source, outcome).expect("static fast path counter exists")]
        .load(),
      );
    }
  }
}

fn counter_index(source: &str, outcome: &str) -> Option<usize> {
  let source_index = SOURCES.iter().position(|candidate| *candidate == source)?;
  let outcome_index = OUTCOMES
    .iter()
    .position(|candidate| *candidate == outcome)?;
  Some(source_index * OUTCOMES.len() + outcome_index)
}

fn append_counter(output: &mut String, source: &str, outcome: &str, value: u64) {
  output.push_str("# TYPE oxibelt_http_static_fast_path_responses_total counter\n");
  output.push_str("oxibelt_http_static_fast_path_responses_total{source=\"");
  output.push_str(source);
  output.push_str("\",outcome=\"");
  output.push_str(outcome);
  output.push_str("\"} ");
  append_u64(output, value);
  output.push('\n');
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn records_only_known_static_fast_path_responses() {
    let metrics = FastPathMetrics::default();
    metrics.record_static_fast_path_response("hot_object", "served");
    metrics.record_static_fast_path_response("sendfile", "fallback");
    metrics.record_static_fast_path_response("bytes", "served");
    metrics.record_static_fast_path_response("sendfile", "unknown");

    assert_eq!(
      metrics.static_fast_path_counters[counter_index("hot_object", "served").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.static_fast_path_counters[counter_index("sendfile", "fallback").unwrap()].load(),
      1
    );
  }
}
