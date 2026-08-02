//! Low-overhead fast-path stage timing helpers.

use std::time::Instant;

use crate::metrics::fast_path::labels::{
  FastPathMetricOutcome, FastPathMetricPath, FastPathMetricProtocol, FastPathMetricStage,
};
use crate::state::AppSnapshot;

use super::direct_transport::DirectFastPathTransport;

pub(crate) const PATH_H3_DOWNSTREAM: FastPathMetricPath = FastPathMetricPath::H3Downstream;
pub(crate) const PATH_PLAIN_PROXY: FastPathMetricPath = FastPathMetricPath::PlainProxy;
pub(crate) const PATH_STATIC_FILES: FastPathMetricPath = FastPathMetricPath::StaticFiles;
pub(crate) const STAGE_DIRECT_H1_CONNECT: FastPathMetricStage =
  FastPathMetricStage::DirectH1Connect;
pub(crate) const STAGE_DIRECT_H1_POOL_TAKE: FastPathMetricStage =
  FastPathMetricStage::DirectH1PoolTake;
pub(crate) const STAGE_DIRECT_H1_REQUEST_BUILD: FastPathMetricStage =
  FastPathMetricStage::DirectH1RequestBuild;
pub(crate) const STAGE_DIRECT_H1_SEND_REQUEST: FastPathMetricStage =
  FastPathMetricStage::DirectH1SendRequest;
pub(crate) const STAGE_DIRECT_H1_SENDER_READY: FastPathMetricStage =
  FastPathMetricStage::DirectH1SenderReady;
pub(crate) const STAGE_DIRECT_H1_REQUEST_SUBMIT: FastPathMetricStage =
  FastPathMetricStage::DirectH1RequestSubmit;
pub(crate) const STAGE_DIRECT_H1_RESPONSE_HEAD: FastPathMetricStage =
  FastPathMetricStage::DirectH1ResponseHead;
pub(crate) const STAGE_DIRECT_H1_RESPONSE_BODY_FIRST_FRAME: FastPathMetricStage =
  FastPathMetricStage::DirectH1ResponseBodyFirstFrame;
pub(crate) const STAGE_DIRECT_H2_SEND_REQUEST: FastPathMetricStage =
  FastPathMetricStage::DirectH2SendRequest;
pub(crate) const STAGE_DIRECT_H2_POOL_TAKE: FastPathMetricStage =
  FastPathMetricStage::DirectH2PoolTake;
pub(crate) const STAGE_DIRECT_H2_CONNECT: FastPathMetricStage =
  FastPathMetricStage::DirectH2Connect;
pub(crate) const STAGE_DIRECT_H2_CAPACITY_WAIT: FastPathMetricStage =
  FastPathMetricStage::DirectH2CapacityWait;
pub(crate) const STAGE_DOWNSTREAM_PROTOCOL_RECEIVE: FastPathMetricStage =
  FastPathMetricStage::DownstreamProtocolReceive;
pub(crate) const STAGE_FAST_PATH_ELIGIBILITY: FastPathMetricStage =
  FastPathMetricStage::FastPathEligibility;
pub(crate) const STAGE_FAST_PATH_PREPARE: FastPathMetricStage =
  FastPathMetricStage::FastPathPrepare;
pub(crate) const STAGE_H2_DOWNSTREAM_RESPONSE_RETURN: FastPathMetricStage =
  FastPathMetricStage::H2DownstreamResponseReturn;
pub(crate) const STAGE_H2_RESPONSE_SEND: FastPathMetricStage = FastPathMetricStage::H2ResponseSend;
pub(crate) const STAGE_H3_DOWNSTREAM_SEND: FastPathMetricStage =
  FastPathMetricStage::H3DownstreamSend;
pub(crate) const STAGE_H3_INGRESS_PREPARE: FastPathMetricStage =
  FastPathMetricStage::H3IngressPrepare;
pub(crate) const STAGE_H3_KNOWN_SMALL_FINALIZE: FastPathMetricStage =
  FastPathMetricStage::H3KnownSmallFinalize;
pub(crate) const STAGE_H3_REQUEST_PERMIT_ACQUIRE: FastPathMetricStage =
  FastPathMetricStage::H3RequestPermitAcquire;
pub(crate) const STAGE_H3_REQUEST_TASK_REAP: FastPathMetricStage =
  FastPathMetricStage::H3RequestTaskReap;
pub(crate) const STAGE_H3_REQUEST_TASK_SPAWN: FastPathMetricStage =
  FastPathMetricStage::H3RequestTaskSpawn;
pub(crate) const STAGE_H3_REQUEST_TASK_JOIN: FastPathMetricStage =
  FastPathMetricStage::H3RequestTaskJoin;
pub(crate) const STAGE_H3_RESPONSE_BODY_FRAME: FastPathMetricStage =
  FastPathMetricStage::H3ResponseBodyFrame;
pub(crate) const STAGE_H3_STREAM_FINISH: FastPathMetricStage = FastPathMetricStage::H3StreamFinish;
pub(crate) const STAGE_REQUEST_BODY_PREPARE: FastPathMetricStage =
  FastPathMetricStage::RequestBodyPrepare;
pub(crate) const STAGE_RESPONSE_BODY_PREPARE: FastPathMetricStage =
  FastPathMetricStage::ResponseBodyPrepare;
pub(crate) const STAGE_RESPONSE_FINALIZE: FastPathMetricStage =
  FastPathMetricStage::ResponseFinalize;
pub(crate) const STAGE_ROUTE_RESOLUTION: FastPathMetricStage = FastPathMetricStage::RouteResolution;
pub(crate) const STAGE_STATIC_HEAD_PREPARE: FastPathMetricStage =
  FastPathMetricStage::StaticHeadPrepare;
pub(crate) const STAGE_STATIC_HOT_OBJECT_REVALIDATE: FastPathMetricStage =
  FastPathMetricStage::StaticHotObjectRevalidate;
pub(crate) const STAGE_STATIC_PLAN: FastPathMetricStage = FastPathMetricStage::StaticPlan;
pub(crate) const STAGE_STATIC_SENDFILE_BODY: FastPathMetricStage =
  FastPathMetricStage::StaticSendfileBody;
pub(crate) const STAGE_STATIC_WRITE_BODY: FastPathMetricStage =
  FastPathMetricStage::StaticWriteBody;
pub(crate) const STAGE_STATIC_WRITE_HEAD: FastPathMetricStage =
  FastPathMetricStage::StaticWriteHead;
pub(crate) const STAGE_TRANSPORT_SELECTION: FastPathMetricStage =
  FastPathMetricStage::TransportSelection;
pub(crate) const STAGE_UPSTREAM_REQUEST_REBUILD: FastPathMetricStage =
  FastPathMetricStage::UpstreamRequestRebuild;

pub(crate) const OUTCOME_ERROR: FastPathMetricOutcome = FastPathMetricOutcome::Error;
pub(crate) const OUTCOME_FALLBACK: FastPathMetricOutcome = FastPathMetricOutcome::Fallback;
pub(crate) const OUTCOME_OK: FastPathMetricOutcome = FastPathMetricOutcome::Ok;

pub(crate) fn start(enabled: bool) -> Option<Instant> {
  enabled.then(Instant::now)
}

pub(crate) fn record(
  state: &AppSnapshot,
  path: FastPathMetricPath,
  protocol: FastPathMetricProtocol,
  stage: FastPathMetricStage,
  outcome: FastPathMetricOutcome,
  started_at: Option<Instant>,
) {
  let Some(started_at) = started_at else {
    return;
  };
  let duration_ns = started_at.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
  state
    .metrics
    .record_fast_path_stage_duration_ns_id(path, protocol, stage, outcome, duration_ns);
}

pub(crate) fn record_metrics(
  metrics: &crate::metrics::Metrics,
  path: FastPathMetricPath,
  protocol: FastPathMetricProtocol,
  stage: FastPathMetricStage,
  outcome: FastPathMetricOutcome,
  started_at: Option<Instant>,
) {
  let Some(started_at) = started_at else {
    return;
  };
  let duration_ns = started_at.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
  metrics.record_fast_path_stage_duration_ns_id(path, protocol, stage, outcome, duration_ns);
}

pub(crate) fn record_metrics_plain_result(
  metrics: &crate::metrics::Metrics,
  protocol: FastPathMetricProtocol,
  stage: FastPathMetricStage,
  success: bool,
  started_at: Option<Instant>,
) {
  let outcome = if success { OUTCOME_OK } else { OUTCOME_ERROR };
  record_metrics(
    metrics,
    PATH_PLAIN_PROXY,
    protocol,
    stage,
    outcome,
    started_at,
  );
}

pub(crate) fn record_plain_ok(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  stage: FastPathMetricStage,
  started_at: Option<Instant>,
) {
  record(
    state,
    PATH_PLAIN_PROXY,
    protocol,
    stage,
    OUTCOME_OK,
    started_at,
  );
}

pub(crate) fn record_plain_result(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  stage: FastPathMetricStage,
  success: bool,
  started_at: Option<Instant>,
) {
  let outcome = if success { OUTCOME_OK } else { OUTCOME_ERROR };
  record(
    state,
    PATH_PLAIN_PROXY,
    protocol,
    stage,
    outcome,
    started_at,
  );
}

pub(crate) fn record_fast_path_prepare(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  started_at: Option<Instant>,
) {
  record_plain_ok(state, protocol, STAGE_FAST_PATH_PREPARE, started_at);
}

pub(crate) fn record_route_resolution(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  matched: bool,
  started_at: Option<Instant>,
) {
  record_plain_result(state, protocol, STAGE_ROUTE_RESOLUTION, matched, started_at);
}

pub(crate) fn record_fast_path_eligibility(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  eligible: bool,
  started_at: Option<Instant>,
) {
  let outcome = if eligible {
    OUTCOME_OK
  } else {
    OUTCOME_FALLBACK
  };
  record(
    state,
    PATH_PLAIN_PROXY,
    protocol,
    STAGE_FAST_PATH_ELIGIBILITY,
    outcome,
    started_at,
  );
}

pub(crate) fn record_transport_selection(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  transport: Option<DirectFastPathTransport>,
  started_at: Option<Instant>,
) {
  let outcome = if transport.is_some() {
    OUTCOME_OK
  } else {
    OUTCOME_FALLBACK
  };
  record(
    state,
    PATH_PLAIN_PROXY,
    protocol,
    STAGE_TRANSPORT_SELECTION,
    outcome,
    started_at,
  );
}

pub(crate) fn record_request_body_prepare(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  started_at: Option<Instant>,
) {
  record_plain_ok(state, protocol, STAGE_REQUEST_BODY_PREPARE, started_at);
}

pub(crate) fn record_upstream_request_rebuild(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  success: bool,
  started_at: Option<Instant>,
) {
  record_plain_result(
    state,
    protocol,
    STAGE_UPSTREAM_REQUEST_REBUILD,
    success,
    started_at,
  );
}

pub(crate) fn direct_h1_build_ok(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  started_at: Option<Instant>,
) {
  record_direct_h1_request_build(state, protocol, OUTCOME_OK, started_at);
}

pub(crate) fn direct_h1_build_fallback(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  started_at: Option<Instant>,
) {
  record_direct_h1_request_build(state, protocol, OUTCOME_FALLBACK, started_at);
}

fn record_direct_h1_request_build(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  outcome: FastPathMetricOutcome,
  started_at: Option<Instant>,
) {
  record(
    state,
    PATH_PLAIN_PROXY,
    protocol,
    STAGE_DIRECT_H1_REQUEST_BUILD,
    outcome,
    started_at,
  );
}

pub(crate) fn record_response_body_prepare(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  success: bool,
  started_at: Option<Instant>,
) {
  record_plain_result(
    state,
    protocol,
    STAGE_RESPONSE_BODY_PREPARE,
    success,
    started_at,
  );
}

pub(crate) fn response_body_result(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  success: bool,
  started_at: Option<Instant>,
) {
  record_response_body_prepare(state, protocol, success, started_at);
}

pub(crate) fn record_finalize(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  request_version: http::Version,
  started_at: Option<Instant>,
) {
  record_plain_ok(state, protocol, STAGE_RESPONSE_FINALIZE, started_at);
  if request_version == http::Version::HTTP_2 {
    record_plain_ok(
      state,
      protocol,
      STAGE_H2_DOWNSTREAM_RESPONSE_RETURN,
      started_at,
    );
  }
}

pub(crate) fn record_transport_result(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  transport: Option<DirectFastPathTransport>,
  success: bool,
  started_at: Option<Instant>,
) {
  let outcome = if success { OUTCOME_OK } else { OUTCOME_ERROR };
  record_transport(state, protocol, transport, outcome, started_at);
}

pub(crate) fn transport_result(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  transport: Option<DirectFastPathTransport>,
  success: bool,
  started_at: Option<Instant>,
) {
  record_transport_result(state, protocol, transport, success, started_at);
}

pub(crate) fn record_transport_fallback(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  transport: Option<DirectFastPathTransport>,
  started_at: Option<Instant>,
) {
  record_transport(state, protocol, transport, OUTCOME_FALLBACK, started_at);
}

pub(crate) fn transport_fallback(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  transport: Option<DirectFastPathTransport>,
  started_at: Option<Instant>,
) {
  record_transport_fallback(state, protocol, transport, started_at);
}

pub(crate) fn general_start(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  transport: Option<DirectFastPathTransport>,
  started_at: Option<Instant>,
  timing_enabled: bool,
) -> Option<Instant> {
  if transport.is_some() {
    transport_fallback(state, protocol, transport, started_at);
    start(timing_enabled)
  } else {
    started_at
  }
}

pub(crate) fn general_result(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  success: bool,
  started_at: Option<Instant>,
) {
  transport_result(state, protocol, None, success, started_at);
}

fn record_transport(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  transport: Option<DirectFastPathTransport>,
  outcome: FastPathMetricOutcome,
  started_at: Option<Instant>,
) {
  let stage = match transport {
    Some(DirectFastPathTransport::H1) => FastPathMetricStage::TransportDirectH1,
    Some(DirectFastPathTransport::H2) => FastPathMetricStage::TransportDirectH2,
    None => FastPathMetricStage::TransportGeneral,
  };
  record(
    state,
    PATH_PLAIN_PROXY,
    protocol,
    stage,
    outcome,
    started_at,
  );
}

pub(crate) fn protocol(version: http::Version) -> FastPathMetricProtocol {
  match version {
    http::Version::HTTP_10 | http::Version::HTTP_11 => FastPathMetricProtocol::H1,
    http::Version::HTTP_2 => FastPathMetricProtocol::H2,
    http::Version::HTTP_3 => FastPathMetricProtocol::H3,
    _ => FastPathMetricProtocol::Other,
  }
}
