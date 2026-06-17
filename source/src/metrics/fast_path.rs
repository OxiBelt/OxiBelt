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
const DECISION_COUNTER_COUNT: usize = PROTOCOLS.len() * OUTCOMES_PER_PROTOCOL;
const BODY_DISPOSITIONS: [&str; 3] = ["inlined", "streamed", "error"];
const BODY_REASONS: [&str; 6] = [
  "known_small",
  "empty",
  "unknown_length",
  "read_timeout",
  "length_mismatch",
  "body_error",
];
const BODY_COUNTERS_PER_PROTOCOL: usize = BODY_DISPOSITIONS.len() * BODY_REASONS.len();
const BODY_COUNTER_COUNT: usize = PROTOCOLS.len() * BODY_COUNTERS_PER_PROTOCOL;
const TRANSPORT_DIRECT_H1: &str = "direct_h1";
const TRANSPORT_HIT_REASON: &str = "used";
const TRANSPORT_MISS_REASONS: [&str; 8] = [
  "unsupported_request",
  "unsupported_upstream",
  "request_body",
  "connect_error",
  "send_error",
  "response_error",
  "not_reusable",
  "pool_full",
];
const TRANSPORT_OUTCOMES_PER_PROTOCOL: usize = 1 + TRANSPORT_MISS_REASONS.len();
const TRANSPORT_COUNTER_COUNT: usize = PROTOCOLS.len() * TRANSPORT_OUTCOMES_PER_PROTOCOL;

#[derive(Debug)]
pub(super) struct FastPathMetrics {
  decision_counters: [StripedCounter; DECISION_COUNTER_COUNT],
  response_body_counters: [StripedCounter; BODY_COUNTER_COUNT],
  transport_counters: [StripedCounter; TRANSPORT_COUNTER_COUNT],
}

impl Default for FastPathMetrics {
  fn default() -> Self {
    Self {
      decision_counters: std::array::from_fn(|_| StripedCounter::default()),
      response_body_counters: std::array::from_fn(|_| StripedCounter::default()),
      transport_counters: std::array::from_fn(|_| StripedCounter::default()),
    }
  }
}

impl FastPathMetrics {
  pub(super) fn record_plain_proxy_decision(&self, protocol: &str, outcome: &str, reason: &str) {
    let Some(index) = counter_index(protocol, outcome, reason) else {
      return;
    };
    self.decision_counters[index].increment();
  }

  pub(super) fn record_response_body(&self, protocol: &str, disposition: &str, reason: &str) {
    let Some(index) = response_body_counter_index(protocol, disposition, reason) else {
      return;
    };
    self.response_body_counters[index].increment();
  }

  pub(super) fn record_transport(&self, protocol: &str, outcome: &str, reason: &str) {
    let Some(index) = transport_counter_index(protocol, outcome, reason) else {
      return;
    };
    self.transport_counters[index].increment();
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    for protocol in PROTOCOLS {
      append_labeled_counter(
        output,
        protocol,
        "hit",
        HIT_REASON,
        self.decision_counters
          [counter_index(protocol, "hit", HIT_REASON).expect("hit counter exists")]
        .load(),
      );
      for reason in MISS_REASONS {
        append_labeled_counter(
          output,
          protocol,
          "miss",
          reason,
          self.decision_counters
            [counter_index(protocol, "miss", reason).expect("miss counter exists")]
          .load(),
        );
      }
      for disposition in BODY_DISPOSITIONS {
        for reason in BODY_REASONS {
          append_response_body_counter(
            output,
            protocol,
            disposition,
            reason,
            self.response_body_counters[response_body_counter_index(protocol, disposition, reason)
              .expect("response body counter exists")]
            .load(),
          );
        }
      }
      append_transport_counter(
        output,
        protocol,
        "hit",
        TRANSPORT_HIT_REASON,
        self.transport_counters[transport_counter_index(protocol, "hit", TRANSPORT_HIT_REASON)
          .expect("transport hit counter exists")]
        .load(),
      );
      for reason in TRANSPORT_MISS_REASONS {
        append_transport_counter(
          output,
          protocol,
          "miss",
          reason,
          self.transport_counters[transport_counter_index(protocol, "miss", reason)
            .expect("transport miss counter exists")]
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

fn response_body_counter_index(protocol: &str, disposition: &str, reason: &str) -> Option<usize> {
  let protocol_index = PROTOCOLS
    .iter()
    .position(|candidate| *candidate == protocol)?;
  let disposition_index = BODY_DISPOSITIONS
    .iter()
    .position(|candidate| *candidate == disposition)?;
  let reason_index = BODY_REASONS
    .iter()
    .position(|candidate| *candidate == reason)?;
  Some(
    protocol_index * BODY_COUNTERS_PER_PROTOCOL
      + disposition_index * BODY_REASONS.len()
      + reason_index,
  )
}

fn transport_counter_index(protocol: &str, outcome: &str, reason: &str) -> Option<usize> {
  let protocol_index = PROTOCOLS
    .iter()
    .position(|candidate| *candidate == protocol)?;
  let offset = match (outcome, reason) {
    ("hit", TRANSPORT_HIT_REASON) => 0,
    ("miss", reason) => {
      1 + TRANSPORT_MISS_REASONS
        .iter()
        .position(|candidate| *candidate == reason)?
    }
    _ => return None,
  };
  Some(protocol_index * TRANSPORT_OUTCOMES_PER_PROTOCOL + offset)
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

fn append_transport_counter(
  output: &mut String,
  protocol: &str,
  outcome: &str,
  reason: &str,
  value: u64,
) {
  output.push_str("# TYPE oxibelt_http_fast_path_transports_total counter\n");
  output.push_str("oxibelt_http_fast_path_transports_total{transport=\"");
  output.push_str(TRANSPORT_DIRECT_H1);
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

fn append_response_body_counter(
  output: &mut String,
  protocol: &str,
  disposition: &str,
  reason: &str,
  value: u64,
) {
  output.push_str("# TYPE oxibelt_http_fast_path_response_bodies_total counter\n");
  output.push_str("oxibelt_http_fast_path_response_bodies_total{protocol=\"");
  output.push_str(protocol);
  output.push_str("\",disposition=\"");
  output.push_str(disposition);
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
      metrics.decision_counters[counter_index("h1", "hit", "eligible").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.decision_counters[counter_index("h1", "miss", "cache_policy").unwrap()].load(),
      1
    );
  }

  #[test]
  fn records_only_known_response_body_label_sets() {
    let metrics = FastPathMetrics::default();
    metrics.record_response_body("h1", "inlined", "known_small");
    metrics.record_response_body("h1", "inlined", "unknown");
    metrics.record_response_body("h9", "inlined", "known_small");

    assert_eq!(
      metrics.response_body_counters
        [response_body_counter_index("h1", "inlined", "known_small").unwrap()]
      .load(),
      1
    );
  }

  #[test]
  fn records_only_known_transport_label_sets() {
    let metrics = FastPathMetrics::default();
    metrics.record_transport("h1", "hit", "used");
    metrics.record_transport("h1", "miss", "request_body");
    metrics.record_transport("h1", "miss", "unknown");
    metrics.record_transport("h9", "hit", "used");

    assert_eq!(
      metrics.transport_counters[transport_counter_index("h1", "hit", "used").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.transport_counters[transport_counter_index("h1", "miss", "request_body").unwrap()]
        .load(),
      1
    );
  }
}
