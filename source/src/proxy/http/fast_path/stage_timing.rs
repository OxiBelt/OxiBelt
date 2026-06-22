//! Low-overhead fast-path stage timing helpers.

use std::time::Instant;

use crate::metrics::fast_path::labels::{
  FastPathMetricOutcome, FastPathMetricPath, FastPathMetricProtocol, FastPathMetricStage,
};
use crate::state::AppSnapshot;

use super::direct_transport::DirectFastPathTransport;

pub(crate) const PATH_H3_DOWNSTREAM: FastPathMetricPath = FastPathMetricPath::H3Downstream;
pub(crate) const PATH_PLAIN_PROXY: FastPathMetricPath = FastPathMetricPath::PlainProxy;
pub(crate) const STAGE_DIRECT_H1_CONNECT: FastPathMetricStage =
  FastPathMetricStage::DirectH1Connect;
pub(crate) const STAGE_DIRECT_H1_POOL_TAKE: FastPathMetricStage =
  FastPathMetricStage::DirectH1PoolTake;
pub(crate) const STAGE_DIRECT_H1_REQUEST_BUILD: FastPathMetricStage =
  FastPathMetricStage::DirectH1RequestBuild;
pub(crate) const STAGE_DIRECT_H1_SEND_REQUEST: FastPathMetricStage =
  FastPathMetricStage::DirectH1SendRequest;
pub(crate) const STAGE_FAST_PATH_PREPARE: FastPathMetricStage =
  FastPathMetricStage::FastPathPrepare;
pub(crate) const STAGE_H3_DOWNSTREAM_SEND: FastPathMetricStage =
  FastPathMetricStage::H3DownstreamSend;
pub(crate) const STAGE_H3_INGRESS_PREPARE: FastPathMetricStage =
  FastPathMetricStage::H3IngressPrepare;
pub(crate) const STAGE_REQUEST_BODY_PREPARE: FastPathMetricStage =
  FastPathMetricStage::RequestBodyPrepare;
pub(crate) const STAGE_RESPONSE_BODY_PREPARE: FastPathMetricStage =
  FastPathMetricStage::ResponseBodyPrepare;
pub(crate) const STAGE_RESPONSE_FINALIZE: FastPathMetricStage =
  FastPathMetricStage::ResponseFinalize;

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

pub(crate) fn record_request_body_prepare(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  started_at: Option<Instant>,
) {
  record_plain_ok(state, protocol, STAGE_REQUEST_BODY_PREPARE, started_at);
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

pub(crate) fn record_response_finalize(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  started_at: Option<Instant>,
) {
  record_plain_ok(state, protocol, STAGE_RESPONSE_FINALIZE, started_at);
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
