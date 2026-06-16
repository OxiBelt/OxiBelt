//! Fast-path decision counters with fixed low-cardinality labels.

use super::StripedCounter;

const PATH_PLAIN_PROXY: &str = "plain_proxy";
const HIT_REASON: &str = "eligible";
const PROTOCOLS: [&str; 4] = ["h1", "h2", "h3", "other"];
const MISS_REASONS: [&str; 8] = [
  "plan_disabled",
  "unsupported_version",
  "unsupported_route",
  "person_proof_api",
  "cache_policy",
  "native_grpc",
  "upgrade",
  "connect",
];
const OUTCOMES_PER_PROTOCOL: usize = 1 + MISS_REASONS.len();
const COUNTER_COUNT: usize = PROTOCOLS.len() * OUTCOMES_PER_PROTOCOL;

#[derive(Debug)]
pub(super) struct FastPathMetrics {
  counters: [StripedCounter; COUNTER_COUNT],
}

impl Default for FastPathMetrics {
  fn default() -> Self {
    Self {
      counters: std::array::from_fn(|_| StripedCounter::default()),
    }
  }
}

impl FastPathMetrics {
  pub(super) fn record_plain_proxy_decision(&self, protocol: &str, outcome: &str, reason: &str) {
    let Some(index) = counter_index(protocol, outcome, reason) else {
      return;
    };
    self.counters[index].increment();
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    for protocol in PROTOCOLS {
      append_labeled_counter(
        output,
        protocol,
        "hit",
        HIT_REASON,
        self.counters[counter_index(protocol, "hit", HIT_REASON).expect("hit counter exists")]
          .load(),
      );
      for reason in MISS_REASONS {
        append_labeled_counter(
          output,
          protocol,
          "miss",
          reason,
          self.counters[counter_index(protocol, "miss", reason).expect("miss counter exists")]
            .load(),
        );
      }
    }
  }
}

fn counter_index(protocol: &str, outcome: &str, reason: &str) -> Option<usize> {
  let protocol_index = PROTOCOLS
    .iter()
    .position(|candidate| *candidate == protocol)?;
  let offset = match (outcome, reason) {
    ("hit", HIT_REASON) => 0,
    ("miss", reason) => {
      1 + MISS_REASONS
        .iter()
        .position(|candidate| *candidate == reason)?
    }
    _ => return None,
  };
  Some(protocol_index * OUTCOMES_PER_PROTOCOL + offset)
}

fn append_labeled_counter(
  output: &mut String,
  protocol: &str,
  outcome: &str,
  reason: &str,
  value: u64,
) {
  output.push_str("# TYPE oxibelt_http_fast_path_decisions_total counter\n");
  output.push_str("oxibelt_http_fast_path_decisions_total{path=\"");
  output.push_str(PATH_PLAIN_PROXY);
  output.push_str("\",protocol=\"");
  output.push_str(protocol);
  output.push_str("\",outcome=\"");
  output.push_str(outcome);
  output.push_str("\",reason=\"");
  output.push_str(reason);
  output.push_str("\"} ");
  output.push_str(&value.to_string());
  output.push('\n');
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn records_only_known_fast_path_label_sets() {
    let metrics = FastPathMetrics::default();
    metrics.record_plain_proxy_decision("h1", "hit", "eligible");
    metrics.record_plain_proxy_decision("h1", "miss", "cache_policy");
    metrics.record_plain_proxy_decision("h1", "miss", "unknown");
    metrics.record_plain_proxy_decision("h9", "hit", "eligible");

    assert_eq!(
      metrics.counters[counter_index("h1", "hit", "eligible").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.counters[counter_index("h1", "miss", "cache_policy").unwrap()].load(),
      1
    );
  }
}
