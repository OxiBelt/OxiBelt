//! Low-overhead fast-path stage timing helpers.

use std::time::Instant;

use crate::state::AppSnapshot;

use super::direct_transport::DirectFastPathTransport;

pub(crate) const PATH_H3_DOWNSTREAM: &str = "h3_downstream";
pub(crate) const PATH_PLAIN_PROXY: &str = "plain_proxy";
pub(crate) const STAGE_FAST_PATH_PREPARE: &str = "fast_path_prepare";
pub(crate) const STAGE_H3_DOWNSTREAM_SEND: &str = "h3_downstream_send";
pub(crate) const STAGE_H3_INGRESS_PREPARE: &str = "h3_ingress_prepare";
pub(crate) const STAGE_REQUEST_BODY_PREPARE: &str = "request_body_prepare";
pub(crate) const STAGE_RESPONSE_BODY_PREPARE: &str = "response_body_prepare";
pub(crate) const STAGE_RESPONSE_FINALIZE: &str = "response_finalize";
pub(crate) const STAGE_TRANSPORT_DIRECT_H1: &str = "transport_direct_h1";
pub(crate) const STAGE_TRANSPORT_DIRECT_H2: &str = "transport_direct_h2";
pub(crate) const STAGE_TRANSPORT_GENERAL: &str = "transport_general";

pub(crate) const OUTCOME_ERROR: &str = "error";
pub(crate) const OUTCOME_FALLBACK: &str = "fallback";
pub(crate) const OUTCOME_OK: &str = "ok";

pub(crate) fn start(enabled: bool) -> Option<Instant> {
  enabled.then(Instant::now)
}

pub(crate) fn record(
  state: &AppSnapshot,
  path: &'static str,
  protocol: &'static str,
  stage: &'static str,
  outcome: &'static str,
  started_at: Option<Instant>,
) {
  let Some(started_at) = started_at else {
    return;
  };
  let duration_ns = started_at.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
  state
    .metrics
    .record_fast_path_stage_duration_ns(path, protocol, stage, outcome, duration_ns);
}

pub(crate) fn record_plain_ok(
  state: &AppSnapshot,
  protocol: &'static str,
  stage: &'static str,
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
  protocol: &'static str,
  stage: &'static str,
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
  protocol: &'static str,
  started_at: Option<Instant>,
) {
  record_plain_ok(state, protocol, STAGE_FAST_PATH_PREPARE, started_at);
}

pub(crate) fn record_request_body_prepare(
  state: &AppSnapshot,
  protocol: &'static str,
  started_at: Option<Instant>,
) {
  record_plain_ok(state, protocol, STAGE_REQUEST_BODY_PREPARE, started_at);
}

pub(crate) fn record_response_body_prepare(
  state: &AppSnapshot,
  protocol: &'static str,
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
  protocol: &'static str,
  success: bool,
  started_at: Option<Instant>,
) {
  record_response_body_prepare(state, protocol, success, started_at);
}

pub(crate) fn record_response_finalize(
  state: &AppSnapshot,
  protocol: &'static str,
  started_at: Option<Instant>,
) {
  record_plain_ok(state, protocol, STAGE_RESPONSE_FINALIZE, started_at);
}

pub(crate) fn record_transport_result(
  state: &AppSnapshot,
  protocol: &'static str,
  transport: Option<DirectFastPathTransport>,
  success: bool,
  started_at: Option<Instant>,
) {
  let outcome = if success { OUTCOME_OK } else { OUTCOME_ERROR };
  record_transport(state, protocol, transport, outcome, started_at);
}

pub(crate) fn transport_result(
  state: &AppSnapshot,
  protocol: &'static str,
  transport: Option<DirectFastPathTransport>,
  success: bool,
  started_at: Option<Instant>,
) {
  record_transport_result(state, protocol, transport, success, started_at);
}

pub(crate) fn record_transport_fallback(
  state: &AppSnapshot,
  protocol: &'static str,
  transport: Option<DirectFastPathTransport>,
  started_at: Option<Instant>,
) {
  record_transport(state, protocol, transport, OUTCOME_FALLBACK, started_at);
}

pub(crate) fn transport_fallback(
  state: &AppSnapshot,
  protocol: &'static str,
  transport: Option<DirectFastPathTransport>,
  started_at: Option<Instant>,
) {
  record_transport_fallback(state, protocol, transport, started_at);
}

pub(crate) fn general_start(
  state: &AppSnapshot,
  protocol: &'static str,
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
  protocol: &'static str,
  success: bool,
  started_at: Option<Instant>,
) {
  transport_result(state, protocol, None, success, started_at);
}

fn record_transport(
  state: &AppSnapshot,
  protocol: &'static str,
  transport: Option<DirectFastPathTransport>,
  outcome: &'static str,
  started_at: Option<Instant>,
) {
  let stage = match transport {
    Some(DirectFastPathTransport::H1) => STAGE_TRANSPORT_DIRECT_H1,
    Some(DirectFastPathTransport::H2) => STAGE_TRANSPORT_DIRECT_H2,
    None => STAGE_TRANSPORT_GENERAL,
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

pub(crate) fn protocol(version: http::Version) -> &'static str {
  match version {
    http::Version::HTTP_10 | http::Version::HTTP_11 => "h1",
    http::Version::HTTP_2 => "h2",
    http::Version::HTTP_3 => "h3",
    _ => "other",
  }
}
