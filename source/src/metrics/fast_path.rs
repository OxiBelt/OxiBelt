//! Fast-path decision counters with fixed low-cardinality labels.

use super::StripedCounter;

mod stage;

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
const REQUEST_BODY_OUTCOMES: [&str; 4] =
  ["already_empty", "verified_empty", "probe_eof", "streaming"];
const REQUEST_BODY_COUNTER_COUNT: usize = PROTOCOLS.len() * REQUEST_BODY_OUTCOMES.len();
const TRANSPORTS: [&str; 2] = ["direct_h1", "direct_h2"];
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
const TRANSPORT_COUNTERS_PER_TRANSPORT: usize = PROTOCOLS.len() * TRANSPORT_OUTCOMES_PER_PROTOCOL;
const TRANSPORT_COUNTER_COUNT: usize = TRANSPORTS.len() * TRANSPORT_COUNTERS_PER_TRANSPORT;
const DIRECT_H1_POOL_EVENTS: [&str; 9] = [
  "hit",
  "miss",
  "miss_empty",
  "miss_locked",
  "reconnect",
  "stale",
  "drop",
  "drop_full",
  "drop_locked",
];
const STATIC_FAST_PATH_SOURCES: [&str; 4] = ["hot_object", "sendfile", "empty", "text"];
const STATIC_FAST_PATH_OUTCOMES: [&str; 2] = ["served", "fallback"];
const STATIC_FAST_PATH_COUNTER_COUNT: usize =
  STATIC_FAST_PATH_SOURCES.len() * STATIC_FAST_PATH_OUTCOMES.len();

#[derive(Debug)]
pub(super) struct FastPathMetrics {
  decision_counters: [StripedCounter; DECISION_COUNTER_COUNT],
  response_body_counters: [StripedCounter; BODY_COUNTER_COUNT],
  request_body_counters: [StripedCounter; REQUEST_BODY_COUNTER_COUNT],
  transport_counters: [StripedCounter; TRANSPORT_COUNTER_COUNT],
  direct_h1_pool_counters: [StripedCounter; DIRECT_H1_POOL_EVENTS.len()],
  static_fast_path_counters: [StripedCounter; STATIC_FAST_PATH_COUNTER_COUNT],
  stage: stage::FastPathStageMetrics,
}

impl Default for FastPathMetrics {
  fn default() -> Self {
    Self {
      decision_counters: std::array::from_fn(|_| StripedCounter::default()),
      response_body_counters: std::array::from_fn(|_| StripedCounter::default()),
      request_body_counters: std::array::from_fn(|_| StripedCounter::default()),
      transport_counters: std::array::from_fn(|_| StripedCounter::default()),
      direct_h1_pool_counters: std::array::from_fn(|_| StripedCounter::default()),
      static_fast_path_counters: std::array::from_fn(|_| StripedCounter::default()),
      stage: stage::FastPathStageMetrics::default(),
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

  pub(super) fn record_request_body(&self, protocol: &str, outcome: &str) {
    let Some(index) = request_body_counter_index(protocol, outcome) else {
      return;
    };
    self.request_body_counters[index].increment();
  }

  pub(super) fn record_transport(
    &self,
    transport: &str,
    protocol: &str,
    outcome: &str,
    reason: &str,
  ) {
    let Some(index) = transport_counter_index(transport, protocol, outcome, reason) else {
      return;
    };
    self.transport_counters[index].increment();
  }

  pub(super) fn record_direct_h1_transport_hit(&self, protocol: &str) {
    let Some(protocol_index) = protocol_index(protocol) else {
      return;
    };
    self.transport_counters[transport_counter_index_by_parts(0, protocol_index, 0)].increment();
  }

  pub(super) fn record_direct_h1_transport_miss(&self, protocol: &str, reason: &str) {
    let Some(protocol_index) = protocol_index(protocol) else {
      return;
    };
    let Some(reason_index) = transport_miss_reason_index(reason) else {
      return;
    };
    self.transport_counters[transport_counter_index_by_parts(0, protocol_index, 1 + reason_index)]
      .increment();
  }

  pub(super) fn record_direct_h2_transport_hit(&self, protocol: &str) {
    let Some(protocol_index) = protocol_index(protocol) else {
      return;
    };
    self.transport_counters[transport_counter_index_by_parts(1, protocol_index, 0)].increment();
  }

  pub(super) fn record_direct_h2_transport_miss(&self, protocol: &str, reason: &str) {
    let Some(protocol_index) = protocol_index(protocol) else {
      return;
    };
    let Some(reason_index) = transport_miss_reason_index(reason) else {
      return;
    };
    self.transport_counters[transport_counter_index_by_parts(1, protocol_index, 1 + reason_index)]
      .increment();
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

  pub(super) fn record_stage_duration_ns(
    &self,
    path: &str,
    protocol: &str,
    stage: &str,
    outcome: &str,
    duration_ns: u64,
  ) {
    self
      .stage
      .record_duration_ns(path, protocol, stage, outcome, duration_ns);
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    for transport in TRANSPORTS {
      for protocol in PROTOCOLS {
        append_transport_counter(
          output,
          transport,
          protocol,
          "hit",
          TRANSPORT_HIT_REASON,
          self.transport_counters[transport_counter_index(
            transport,
            protocol,
            "hit",
            TRANSPORT_HIT_REASON,
          )
          .expect("transport hit counter exists")]
          .load(),
        );
        for reason in TRANSPORT_MISS_REASONS {
          append_transport_counter(
            output,
            transport,
            protocol,
            "miss",
            reason,
            self.transport_counters[transport_counter_index(transport, protocol, "miss", reason)
              .expect("transport miss counter exists")]
            .load(),
          );
        }
      }
    }
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
      for outcome in REQUEST_BODY_OUTCOMES {
        append_request_body_counter(
          output,
          protocol,
          outcome,
          self.request_body_counters
            [request_body_counter_index(protocol, outcome).expect("request body counter exists")]
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
    self.stage.append_prometheus(output);
  }
}

fn counter_index(protocol: &str, outcome: &str, reason: &str) -> Option<usize> {
  let protocol_index = protocol_index(protocol)?;
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
  let protocol_index = protocol_index(protocol)?;
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

fn request_body_counter_index(protocol: &str, outcome: &str) -> Option<usize> {
  let protocol_index = protocol_index(protocol)?;
  let outcome_index = REQUEST_BODY_OUTCOMES
    .iter()
    .position(|candidate| *candidate == outcome)?;
  Some(protocol_index * REQUEST_BODY_OUTCOMES.len() + outcome_index)
}

fn transport_counter_index(
  transport: &str,
  protocol: &str,
  outcome: &str,
  reason: &str,
) -> Option<usize> {
  let transport_index = TRANSPORTS
    .iter()
    .position(|candidate| *candidate == transport)?;
  let protocol_index = protocol_index(protocol)?;
  let offset = match (outcome, reason) {
    ("hit", TRANSPORT_HIT_REASON) => 0,
    ("miss", reason) => 1 + transport_miss_reason_index(reason)?,
    _ => return None,
  };
  Some(transport_counter_index_by_parts(
    transport_index,
    protocol_index,
    offset,
  ))
}

fn protocol_index(protocol: &str) -> Option<usize> {
  PROTOCOLS
    .iter()
    .position(|candidate| *candidate == protocol)
}

fn transport_miss_reason_index(reason: &str) -> Option<usize> {
  TRANSPORT_MISS_REASONS
    .iter()
    .position(|candidate| *candidate == reason)
}

fn transport_counter_index_by_parts(
  transport_index: usize,
  protocol_index: usize,
  offset: usize,
) -> usize {
  transport_index * TRANSPORT_COUNTERS_PER_TRANSPORT
    + protocol_index * TRANSPORT_OUTCOMES_PER_PROTOCOL
    + offset
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
  transport: &str,
  protocol: &str,
  outcome: &str,
  reason: &str,
  value: u64,
) {
  output.push_str("# TYPE oxibelt_http_fast_path_transports_total counter\n");
  output.push_str("oxibelt_http_fast_path_transports_total{transport=\"");
  output.push_str(transport);
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

fn append_request_body_counter(output: &mut String, protocol: &str, outcome: &str, value: u64) {
  output.push_str("# TYPE oxibelt_http_fast_path_request_bodies_total counter\n");
  output.push_str("oxibelt_http_fast_path_request_bodies_total{protocol=\"");
  output.push_str(protocol);
  output.push_str("\",outcome=\"");
  output.push_str(outcome);
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
  fn records_only_known_request_body_label_sets() {
    let metrics = FastPathMetrics::default();
    metrics.record_request_body("h2", "verified_empty");
    metrics.record_request_body("h3", "probe_eof");
    metrics.record_request_body("h3", "unknown");
    metrics.record_request_body("h9", "streaming");

    assert_eq!(
      metrics.request_body_counters[request_body_counter_index("h2", "verified_empty").unwrap()]
        .load(),
      1
    );
    assert_eq!(
      metrics.request_body_counters[request_body_counter_index("h3", "probe_eof").unwrap()].load(),
      1
    );
  }

  #[test]
  fn records_only_known_transport_label_sets() {
    let metrics = FastPathMetrics::default();
    metrics.record_transport("direct_h1", "h1", "hit", "used");
    metrics.record_transport("direct_h2", "h2", "hit", "used");
    metrics.record_transport("direct_h1", "h1", "miss", "request_body");
    metrics.record_transport("direct_h1", "h1", "miss", "unknown");
    metrics.record_transport("direct_h3", "h1", "hit", "used");
    metrics.record_transport("direct_h1", "h9", "hit", "used");

    assert_eq!(
      metrics.transport_counters
        [transport_counter_index("direct_h1", "h1", "hit", "used").unwrap()]
      .load(),
      1
    );
    assert_eq!(
      metrics.transport_counters
        [transport_counter_index("direct_h2", "h2", "hit", "used").unwrap()]
      .load(),
      1
    );
    assert_eq!(
      metrics.transport_counters
        [transport_counter_index("direct_h1", "h1", "miss", "request_body").unwrap()]
      .load(),
      1
    );
  }

  #[test]
  fn specialized_transport_recorders_use_fixed_indexes() {
    let metrics = FastPathMetrics::default();
    metrics.record_direct_h1_transport_hit("h1");
    metrics.record_direct_h1_transport_miss("h2", "request_body");
    metrics.record_direct_h2_transport_hit("h2");
    metrics.record_direct_h2_transport_miss("h3", "connect_error");
    metrics.record_direct_h1_transport_hit("h9");
    metrics.record_direct_h1_transport_miss("h1", "unknown");

    assert_eq!(
      metrics.transport_counters
        [transport_counter_index("direct_h1", "h1", "hit", "used").unwrap()]
      .load(),
      1
    );
    assert_eq!(
      metrics.transport_counters
        [transport_counter_index("direct_h1", "h2", "miss", "request_body").unwrap()]
      .load(),
      1
    );
    assert_eq!(
      metrics.transport_counters
        [transport_counter_index("direct_h2", "h2", "hit", "used").unwrap()]
      .load(),
      1
    );
    assert_eq!(
      metrics.transport_counters
        [transport_counter_index("direct_h2", "h3", "miss", "connect_error").unwrap()]
      .load(),
      1
    );
  }

  #[test]
  fn records_only_known_direct_h1_pool_events() {
    let metrics = FastPathMetrics::default();
    metrics.record_direct_h1_pool_event("hit");
    metrics.record_direct_h1_pool_event("miss_locked");
    metrics.record_direct_h1_pool_event("reconnect");
    metrics.record_direct_h1_pool_event("drop_full");
    metrics.record_direct_h1_pool_event("unknown");

    assert_eq!(
      metrics.direct_h1_pool_counters[direct_h1_pool_event_index("hit").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.direct_h1_pool_counters[direct_h1_pool_event_index("miss_locked").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.direct_h1_pool_counters[direct_h1_pool_event_index("reconnect").unwrap()].load(),
      1
    );
    assert_eq!(
      metrics.direct_h1_pool_counters[direct_h1_pool_event_index("drop_full").unwrap()].load(),
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
