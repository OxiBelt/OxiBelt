//! Fixed-label fast-path stage timing counters.

use super::super::StripedCounter;

const PATHS: [&str; 2] = ["plain_proxy", "h3_downstream"];
const PROTOCOLS: [&str; 4] = ["h1", "h2", "h3", "other"];
const STAGES: [&str; 13] = [
  "direct_h1_connect",
  "direct_h1_pool_take",
  "direct_h1_request_build",
  "direct_h1_send_request",
  "fast_path_prepare",
  "request_body_prepare",
  "transport_direct_h1",
  "transport_direct_h2",
  "transport_general",
  "response_body_prepare",
  "response_finalize",
  "h3_ingress_prepare",
  "h3_downstream_send",
];
const OUTCOMES: [&str; 3] = ["ok", "fallback", "error"];
const STAGE_COUNTER_COUNT: usize = PATHS.len() * PROTOCOLS.len() * STAGES.len() * OUTCOMES.len();

#[derive(Debug)]
pub(super) struct FastPathStageMetrics {
  observations: Box<[StripedCounter]>,
  duration_ns: Box<[StripedCounter]>,
}

impl Default for FastPathStageMetrics {
  fn default() -> Self {
    Self {
      observations: striped_counters(),
      duration_ns: striped_counters(),
    }
  }
}

fn striped_counters() -> Box<[StripedCounter]> {
  (0..STAGE_COUNTER_COUNT)
    .map(|_| StripedCounter::default())
    .collect()
}

impl FastPathStageMetrics {
  pub(super) fn record_duration_ns(
    &self,
    path: &str,
    protocol: &str,
    stage: &str,
    outcome: &str,
    duration_ns: u64,
  ) {
    let Some(index) = stage_counter_index(path, protocol, stage, outcome) else {
      return;
    };
    self.observations[index].increment();
    self.duration_ns[index].add(duration_ns);
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    for path in PATHS {
      for protocol in PROTOCOLS {
        for stage in STAGES {
          for outcome in OUTCOMES {
            let index =
              stage_counter_index(path, protocol, stage, outcome).expect("stage counter exists");
            append_stage_counter(
              output,
              "oxibelt_http_fast_path_stage_observations_total",
              path,
              protocol,
              stage,
              outcome,
              self.observations[index].load(),
            );
            append_stage_counter(
              output,
              "oxibelt_http_fast_path_stage_duration_ns_total",
              path,
              protocol,
              stage,
              outcome,
              self.duration_ns[index].load(),
            );
          }
        }
      }
    }
  }
}

fn stage_counter_index(path: &str, protocol: &str, stage: &str, outcome: &str) -> Option<usize> {
  let path_index = PATHS.iter().position(|candidate| *candidate == path)?;
  let protocol_index = PROTOCOLS
    .iter()
    .position(|candidate| *candidate == protocol)?;
  let stage_index = STAGES.iter().position(|candidate| *candidate == stage)?;
  let outcome_index = OUTCOMES
    .iter()
    .position(|candidate| *candidate == outcome)?;
  Some(
    (((path_index * PROTOCOLS.len()) + protocol_index) * STAGES.len() + stage_index)
      * OUTCOMES.len()
      + outcome_index,
  )
}

fn append_stage_counter(
  output: &mut String,
  name: &str,
  path: &str,
  protocol: &str,
  stage: &str,
  outcome: &str,
  value: u64,
) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push_str(" counter\n");
  output.push_str(name);
  output.push_str("{path=\"");
  output.push_str(path);
  output.push_str("\",protocol=\"");
  output.push_str(protocol);
  output.push_str("\",stage=\"");
  output.push_str(stage);
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
  fn records_only_known_stage_label_sets() {
    let metrics = FastPathStageMetrics::default();
    metrics.record_duration_ns("plain_proxy", "h2", "transport_direct_h1", "ok", 37);
    metrics.record_duration_ns("plain_proxy", "h2", "transport_direct_h1", "ok", 5);
    metrics.record_duration_ns("plain_proxy", "h2", "direct_h1_pool_take", "ok", 7);
    metrics.record_duration_ns("plain_proxy", "h2", "unknown", "ok", 11);
    metrics.record_duration_ns("plain_proxy", "h9", "transport_direct_h1", "ok", 13);
    metrics.record_duration_ns("plain_proxy", "h2", "transport_direct_h1", "weird", 17);

    let index = stage_counter_index("plain_proxy", "h2", "transport_direct_h1", "ok").unwrap();
    assert_eq!(metrics.observations[index].load(), 2);
    assert_eq!(metrics.duration_ns[index].load(), 42);
    let pool_take_index =
      stage_counter_index("plain_proxy", "h2", "direct_h1_pool_take", "ok").unwrap();
    assert_eq!(metrics.observations[pool_take_index].load(), 1);
    assert_eq!(metrics.duration_ns[pool_take_index].load(), 7);
  }
}
