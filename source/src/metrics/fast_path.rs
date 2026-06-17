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
const DIRECT_H1_POOL_EVENTS: [&str; 5] = ["hit", "miss", "reconnect", "stale", "drop"];
const STATIC_FAST_PATH_SOURCES: [&str; 4] = ["hot_object", "sendfile", "empty", "text"];
const STATIC_FAST_PATH_OUTCOMES: [&str; 2] = ["served", "fallback"];
const STATIC_FAST_PATH_COUNTER_COUNT: usize =
  STATIC_FAST_PATH_SOURCES.len() * STATIC_FAST_PATH_OUTCOMES.len();

#[derive(Debug)]
pub(super) struct FastPathMetrics {
  decision_counters: [StripedCounter; DECISION_COUNTER_COUNT],
  response_body_counters: [StripedCounter; BODY_COUNTER_COUNT],
  transport_counters: [StripedCounter; TRANSPORT_COUNTER_COUNT],
  direct_h1_pool_counters: [StripedCounter; DIRECT_H1_POOL_EVENTS.len()],
  static_fast_path_counters: [StripedCounter; STATIC_FAST_PATH_COUNTER_COUNT],
}

impl Default for FastPathMetrics {
  fn default() -> Self {
    Self {
      decision_counters: std::array::from_fn(|_| StripedCounter::default()),
      response_body_counters: std::array::from_fn(|_| StripedCounter::default()),
      transport_counters: std::array::from_fn(|_| StripedCounter::default()),
      direct_h1_pool_counters: std::array::from_fn(|_| StripedCounter::default()),
      static_fast_path_counters: std::array::from_fn(|_| StripedCounter::default()),
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

  pub(super) fn record_direct_h1_pool_event(&self, event: &str) {
    let Some(index) = direct_h1_pool_event_index(event) else {
      return;
    };
    self.direct_h1_pool_counters[index].increment();
  }

  pub(super) fn record_static_fast_path_response(&self, source: &str, outcome: &str) {
    let Some(index) = static_fast_path_counter_index(source, outcome) else {
      return;
    };
    self.static_fast_path_counters[index].increment();
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
    for event in DIRECT_H1_POOL_EVENTS {
      append_direct_h1_pool_counter(
        output,
        event,
        self.direct_h1_pool_counters
          [direct_h1_pool_event_index(event).expect("pool event counter exists")]
        .load(),
      );
    }
    for source in STATIC_FAST_PATH_SOURCES {
      for outcome in STATIC_FAST_PATH_OUTCOMES {
        append_static_fast_path_counter(
          output,
          source,
          outcome,
          self.static_fast_path_counters[static_fast_path_counter_index(source, outcome)
            .expect("static fast path counter exists")]
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

fn direct_h1_pool_event_index(event: &str) -> Option<usize> {
  DIRECT_H1_POOL_EVENTS
    .iter()
    .position(|candidate| *candidate == event)
}

fn static_fast_path_counter_index(source: &str, outcome: &str) -> Option<usize> {
  let source_index = STATIC_FAST_PATH_SOURCES
    .iter()
    .position(|candidate| *candidate == source)?;
  let outcome_index = STATIC_FAST_PATH_OUTCOMES
    .iter()
    .position(|candidate| *candidate == outcome)?;
  Some(source_index * STATIC_FAST_PATH_OUTCOMES.len() + outcome_index)
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

fn append_direct_h1_pool_counter(output: &mut String, event: &str, value: u64) {
  output.push_str("# TYPE oxibelt_http_direct_h1_pool_events_total counter\n");
  output.push_str("oxibelt_http_direct_h1_pool_events_total{event=\"");
  output.push_str(event);
  output.push_str("\"} ");
  output.push_str(&value.to_string());
  output.push('\n');
}

fn append_static_fast_path_counter(output: &mut String, source: &str, outcome: &str, value: u64) {
  output.push_str("# TYPE oxibelt_http_static_fast_path_responses_total counter\n");
  output.push_str("oxibelt_http_static_fast_path_responses_total{source=\"");
  output.push_str(source);
  output.push_str("\",outcome=\"");
  output.push_str(outcome);
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

  #[test]
  fn records_only_known_direct_h1_pool_events() {
    let metrics = FastPathMetrics::default();
    metrics.record_direct_h1_pool_event("hit");
    metrics.record_direct_h1_pool_event("reconnect");
    metrics.record_direct_h1_pool_event("unknown");

    assert_eq!(
      metrics.direct_h1_pool_counters[direct_h1_pool_event_index("hit").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.direct_h1_pool_counters[direct_h1_pool_event_index("reconnect").unwrap()].load(),
      1
    );
  }

  #[test]
  fn records_only_known_static_fast_path_responses() {
    let metrics = FastPathMetrics::default();
    metrics.record_static_fast_path_response("hot_object", "served");
    metrics.record_static_fast_path_response("sendfile", "fallback");
    metrics.record_static_fast_path_response("bytes", "served");
    metrics.record_static_fast_path_response("sendfile", "unknown");

    assert_eq!(
      metrics.static_fast_path_counters
        [static_fast_path_counter_index("hot_object", "served").unwrap()]
      .load(),
      1
    );
    assert_eq!(
      metrics.static_fast_path_counters
        [static_fast_path_counter_index("sendfile", "fallback").unwrap()]
      .load(),
      1
    );
  }
}
