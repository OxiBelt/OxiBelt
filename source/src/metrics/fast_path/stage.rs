//! Fixed-label fast-path stage timing counters.

use std::fmt::Write as _;
use std::sync::atomic::Ordering;

use super::super::{COUNTER_STRIPE, StripedCounter};
use super::labels::{
  FastPathMetricOutcome, FastPathMetricPath, FastPathMetricProtocol, FastPathMetricStage,
};

const STAGE_COUNTER_COUNT: usize = FastPathMetricPath::COUNT
  * FastPathMetricProtocol::COUNT
  * FastPathMetricStage::COUNT
  * FastPathMetricOutcome::COUNT;

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
    increment_observation_and_duration(
      &self.observations[index],
      &self.duration_ns[index],
      duration_ns,
    );
  }

  pub(super) fn record_duration_ns_id(
    &self,
    path: FastPathMetricPath,
    protocol: FastPathMetricProtocol,
    stage: FastPathMetricStage,
    outcome: FastPathMetricOutcome,
    duration_ns: u64,
  ) {
    let index = stage_counter_index_id(path, protocol, stage, outcome);
    increment_observation_and_duration(
      &self.observations[index],
      &self.duration_ns[index],
      duration_ns,
    );
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    for path in FastPathMetricPath::ALL {
      for protocol in FastPathMetricProtocol::ALL {
        for stage in FastPathMetricStage::ALL {
          for outcome in FastPathMetricOutcome::ALL {
            let index = stage_counter_index_id(path, protocol, stage, outcome);
            append_stage_counter(
              output,
              "oxibelt_http_fast_path_stage_observations_total",
              path.as_str(),
              protocol.as_str(),
              stage.as_str(),
              outcome.as_str(),
              self.observations[index].load(),
            );
            append_stage_counter(
              output,
              "oxibelt_http_fast_path_stage_duration_ns_total",
              path.as_str(),
              protocol.as_str(),
              stage.as_str(),
              outcome.as_str(),
              self.duration_ns[index].load(),
            );
          }
        }
      }
    }
  }
}

fn stage_counter_index(path: &str, protocol: &str, stage: &str, outcome: &str) -> Option<usize> {
  Some(stage_counter_index_id(
    FastPathMetricPath::from_str(path)?,
    FastPathMetricProtocol::from_str(protocol)?,
    FastPathMetricStage::from_str(stage)?,
    FastPathMetricOutcome::from_str(outcome)?,
  ))
}

fn stage_counter_index_id(
  path: FastPathMetricPath,
  protocol: FastPathMetricProtocol,
  stage: FastPathMetricStage,
  outcome: FastPathMetricOutcome,
) -> usize {
  (((path.index() * FastPathMetricProtocol::COUNT) + protocol.index()) * FastPathMetricStage::COUNT
    + stage.index())
    * FastPathMetricOutcome::COUNT
    + outcome.index()
}

fn increment_observation_and_duration(
  observations: &StripedCounter,
  duration_ns_counter: &StripedCounter,
  duration_ns: u64,
) {
  COUNTER_STRIPE.with(|stripe| {
    observations.stripes[*stripe]
      .value
      .fetch_add(1, Ordering::Relaxed);
    duration_ns_counter.stripes[*stripe]
      .value
      .fetch_add(duration_ns, Ordering::Relaxed);
  });
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
  let _ = write!(output, "{value}");
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
    metrics.record_duration_ns("plain_proxy", "h2", "direct_h1_response_head", "ok", 3);
    metrics.record_duration_ns("plain_proxy", "h2", "route_resolution", "ok", 11);
    metrics.record_duration_ns("plain_proxy", "h2", "fast_path_eligibility", "fallback", 13);
    metrics.record_duration_ns("plain_proxy", "h2", "transport_selection", "ok", 17);
    metrics.record_duration_ns("plain_proxy", "h2", "direct_h2_send_request", "error", 19);
    metrics.record_duration_ns("plain_proxy", "h2", "downstream_protocol_receive", "ok", 31);
    metrics.record_duration_ns("plain_proxy", "h2", "upstream_request_rebuild", "ok", 37);
    metrics.record_duration_ns("plain_proxy", "h2", "h2_response_send", "ok", 41);
    metrics.record_duration_ns(
      "plain_proxy",
      "h2",
      "h2_downstream_response_return",
      "ok",
      2,
    );
    metrics.record_duration_ns("plain_proxy", "h2", "unknown", "ok", 11);
    metrics.record_duration_ns("plain_proxy", "h9", "transport_direct_h1", "ok", 13);
    metrics.record_duration_ns("plain_proxy", "h2", "transport_direct_h1", "weird", 17);
    metrics.record_duration_ns_id(
      FastPathMetricPath::H3Downstream,
      FastPathMetricProtocol::H3,
      FastPathMetricStage::H3DownstreamSend,
      FastPathMetricOutcome::Error,
      19,
    );
    metrics.record_duration_ns_id(
      FastPathMetricPath::H3Downstream,
      FastPathMetricProtocol::H3,
      FastPathMetricStage::H3RequestTaskReap,
      FastPathMetricOutcome::Ok,
      37,
    );
    metrics.record_duration_ns_id(
      FastPathMetricPath::H3Downstream,
      FastPathMetricProtocol::H3,
      FastPathMetricStage::H3RequestPermitAcquire,
      FastPathMetricOutcome::Ok,
      41,
    );
    metrics.record_duration_ns_id(
      FastPathMetricPath::H3Downstream,
      FastPathMetricProtocol::H3,
      FastPathMetricStage::H3RequestTaskSpawn,
      FastPathMetricOutcome::Ok,
      43,
    );
    metrics.record_duration_ns_id(
      FastPathMetricPath::H3Downstream,
      FastPathMetricProtocol::H3,
      FastPathMetricStage::H3KnownSmallFinalize,
      FastPathMetricOutcome::Ok,
      47,
    );
    metrics.record_duration_ns_id(
      FastPathMetricPath::H3Downstream,
      FastPathMetricProtocol::H3,
      FastPathMetricStage::H3ResponseBodyFrame,
      FastPathMetricOutcome::Ok,
      53,
    );
    metrics.record_duration_ns_id(
      FastPathMetricPath::H3Downstream,
      FastPathMetricProtocol::H3,
      FastPathMetricStage::DownstreamProtocolReceive,
      FastPathMetricOutcome::Ok,
      61,
    );
    metrics.record_duration_ns_id(
      FastPathMetricPath::H3Downstream,
      FastPathMetricProtocol::H3,
      FastPathMetricStage::H3StreamFinish,
      FastPathMetricOutcome::Ok,
      59,
    );
    metrics.record_duration_ns_id(
      FastPathMetricPath::H3Downstream,
      FastPathMetricProtocol::H3,
      FastPathMetricStage::H3RequestTaskJoin,
      FastPathMetricOutcome::Ok,
      67,
    );
    metrics.record_duration_ns_id(
      FastPathMetricPath::StaticFiles,
      FastPathMetricProtocol::H1,
      FastPathMetricStage::StaticWriteBody,
      FastPathMetricOutcome::Ok,
      23,
    );
    metrics.record_duration_ns("static_files", "h1", "static_head_prepare", "ok", 29);
    metrics.record_duration_ns("static_files", "h1", "static_mystery", "ok", 31);

    let index = stage_counter_index("plain_proxy", "h2", "transport_direct_h1", "ok").unwrap();
    assert_eq!(metrics.observations[index].load(), 2);
    assert_eq!(metrics.duration_ns[index].load(), 42);
    let pool_take_index =
      stage_counter_index("plain_proxy", "h2", "direct_h1_pool_take", "ok").unwrap();
    assert_eq!(metrics.observations[pool_take_index].load(), 1);
    assert_eq!(metrics.duration_ns[pool_take_index].load(), 7);
    let response_head_index =
      stage_counter_index("plain_proxy", "h2", "direct_h1_response_head", "ok").unwrap();
    assert_eq!(metrics.observations[response_head_index].load(), 1);
    assert_eq!(metrics.duration_ns[response_head_index].load(), 3);
    let route_resolution_index =
      stage_counter_index("plain_proxy", "h2", "route_resolution", "ok").unwrap();
    assert_eq!(metrics.observations[route_resolution_index].load(), 1);
    assert_eq!(metrics.duration_ns[route_resolution_index].load(), 11);
    let eligibility_index =
      stage_counter_index("plain_proxy", "h2", "fast_path_eligibility", "fallback").unwrap();
    assert_eq!(metrics.observations[eligibility_index].load(), 1);
    assert_eq!(metrics.duration_ns[eligibility_index].load(), 13);
    let transport_selection_index =
      stage_counter_index("plain_proxy", "h2", "transport_selection", "ok").unwrap();
    assert_eq!(metrics.observations[transport_selection_index].load(), 1);
    assert_eq!(metrics.duration_ns[transport_selection_index].load(), 17);
    let direct_h2_send_index =
      stage_counter_index("plain_proxy", "h2", "direct_h2_send_request", "error").unwrap();
    assert_eq!(metrics.observations[direct_h2_send_index].load(), 1);
    assert_eq!(metrics.duration_ns[direct_h2_send_index].load(), 19);
    let downstream_receive_index =
      stage_counter_index("plain_proxy", "h2", "downstream_protocol_receive", "ok").unwrap();
    assert_eq!(metrics.observations[downstream_receive_index].load(), 1);
    assert_eq!(metrics.duration_ns[downstream_receive_index].load(), 31);
    let upstream_rebuild_index =
      stage_counter_index("plain_proxy", "h2", "upstream_request_rebuild", "ok").unwrap();
    assert_eq!(metrics.observations[upstream_rebuild_index].load(), 1);
    assert_eq!(metrics.duration_ns[upstream_rebuild_index].load(), 37);
    let h2_send_index = stage_counter_index("plain_proxy", "h2", "h2_response_send", "ok").unwrap();
    assert_eq!(metrics.observations[h2_send_index].load(), 1);
    assert_eq!(metrics.duration_ns[h2_send_index].load(), 41);
    let h2_return_index =
      stage_counter_index("plain_proxy", "h2", "h2_downstream_response_return", "ok").unwrap();
    assert_eq!(metrics.observations[h2_return_index].load(), 1);
    assert_eq!(metrics.duration_ns[h2_return_index].load(), 2);
    let h3_index =
      stage_counter_index("h3_downstream", "h3", "h3_downstream_send", "error").unwrap();
    assert_eq!(metrics.observations[h3_index].load(), 1);
    assert_eq!(metrics.duration_ns[h3_index].load(), 19);
    let h3_reap_index =
      stage_counter_index("h3_downstream", "h3", "h3_request_task_reap", "ok").unwrap();
    assert_eq!(metrics.observations[h3_reap_index].load(), 1);
    assert_eq!(metrics.duration_ns[h3_reap_index].load(), 37);
    let h3_permit_index =
      stage_counter_index("h3_downstream", "h3", "h3_request_permit_acquire", "ok").unwrap();
    assert_eq!(metrics.observations[h3_permit_index].load(), 1);
    assert_eq!(metrics.duration_ns[h3_permit_index].load(), 41);
    let h3_spawn_index =
      stage_counter_index("h3_downstream", "h3", "h3_request_task_spawn", "ok").unwrap();
    assert_eq!(metrics.observations[h3_spawn_index].load(), 1);
    assert_eq!(metrics.duration_ns[h3_spawn_index].load(), 43);
    let h3_known_small_index =
      stage_counter_index("h3_downstream", "h3", "h3_known_small_finalize", "ok").unwrap();
    assert_eq!(metrics.observations[h3_known_small_index].load(), 1);
    assert_eq!(metrics.duration_ns[h3_known_small_index].load(), 47);
    let h3_response_frame_index =
      stage_counter_index("h3_downstream", "h3", "h3_response_body_frame", "ok").unwrap();
    assert_eq!(metrics.observations[h3_response_frame_index].load(), 1);
    assert_eq!(metrics.duration_ns[h3_response_frame_index].load(), 53);
    let h3_stream_finish_index =
      stage_counter_index("h3_downstream", "h3", "h3_stream_finish", "ok").unwrap();
    assert_eq!(metrics.observations[h3_stream_finish_index].load(), 1);
    assert_eq!(metrics.duration_ns[h3_stream_finish_index].load(), 59);
    let h3_receive_index =
      stage_counter_index("h3_downstream", "h3", "downstream_protocol_receive", "ok").unwrap();
    assert_eq!(metrics.observations[h3_receive_index].load(), 1);
    assert_eq!(metrics.duration_ns[h3_receive_index].load(), 61);
    let h3_join_index =
      stage_counter_index("h3_downstream", "h3", "h3_request_task_join", "ok").unwrap();
    assert_eq!(metrics.observations[h3_join_index].load(), 1);
    assert_eq!(metrics.duration_ns[h3_join_index].load(), 67);
    let static_write_body_index =
      stage_counter_index("static_files", "h1", "static_write_body", "ok").unwrap();
    assert_eq!(metrics.observations[static_write_body_index].load(), 1);
    assert_eq!(metrics.duration_ns[static_write_body_index].load(), 23);
    let static_head_prepare_index =
      stage_counter_index("static_files", "h1", "static_head_prepare", "ok").unwrap();
    assert_eq!(metrics.observations[static_head_prepare_index].load(), 1);
    assert_eq!(metrics.duration_ns[static_head_prepare_index].load(), 29);
  }
}
