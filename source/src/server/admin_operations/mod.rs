//! Long-running admin operation transports and runtime wiring.
//! All transports share the same operation state so progress and cancellation semantics match.

mod artifact;
mod endpoint;
mod id;
mod runtime;
mod runtime_durable;
mod runtime_durable_prepare;
mod runtime_durable_recovery;
mod runtime_durable_support;
mod runtime_durable_terminal;
mod state_machine;
mod store;
mod stream;
mod types;
mod websocket;
mod webtransport;

pub(super) use artifact::{OperationArtifactBinding, OperationArtifactCipher};
pub(super) use endpoint::{
  AdminOperationRouteContext, accepted_operation_response, admin_operations_response,
  can_access_operation,
};
pub(super) use id::parse_operation_id;
pub(super) use runtime::{
  AdminOperationContext, AdminOperationError, AdminOperationRuntime, AdminOperationSubmission,
  AdminOperationWorkResult, value_result,
};
pub(super) use store::{
  CancelOutcome, InsertOutcome, JournalEvent, JournalOperation, LeaseGuard, NewJournalOperation,
  OperationJournal, TerminalUpdate, WorkerIdentity,
};
pub(super) use stream::encode_ndjson_event;
pub(super) use types::{AdminOperationEvent, AdminOperationKind, AdminOperationRecoveryClass};
pub(super) use webtransport::{
  enqueue_webtransport_drain_operation, enqueue_webtransport_snapshot_operation,
};

use ::http::{Response, StatusCode};

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;

pub(in crate::server) struct AdminOperationRequestMetadata {
  pub request_id: String,
  pub idempotency_key: Option<String>,
}

pub(super) fn prefer_respond_async<B>(request: &::http::Request<B>) -> bool {
  request
    .headers()
    .get(::http::HeaderName::from_static("prefer"))
    .and_then(|value| value.to_str().ok())
    .is_some_and(|value| {
      value
        .split(',')
        .any(|item| item.trim().eq_ignore_ascii_case("respond-async"))
    })
}

/// Reads the optional idempotency key without ever copying it into logs or
/// error responses. Durable submission hashes the returned value before it is
/// persisted.
pub(super) fn idempotency_key<B>(
  request: &::http::Request<B>,
) -> Result<Option<String>, Box<Response<ProxyBody>>> {
  let Some(value) = request
    .headers()
    .get(::http::HeaderName::from_static("idempotency-key"))
  else {
    return Ok(None);
  };
  let bytes = value.as_bytes();
  if !(1..=128).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_graphic) {
    return Err(Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "Idempotency-Key must contain 1 to 128 visible ASCII bytes",
    )));
  }
  value
    .to_str()
    .map(|value| Some(value.to_string()))
    .map_err(|_| {
      Box::new(text_response(
        StatusCode::BAD_REQUEST,
        "Idempotency-Key is invalid",
      ))
    })
}

pub(super) fn enqueue_error_response(error: AdminOperationError) -> Response<ProxyBody> {
  let status = match error {
    AdminOperationError::Disabled => StatusCode::CONFLICT,
    AdminOperationError::QueueFull | AdminOperationError::StoreFull => {
      StatusCode::SERVICE_UNAVAILABLE
    }
    AdminOperationError::NotFound => StatusCode::NOT_FOUND,
    AdminOperationError::AlreadyTerminal => StatusCode::CONFLICT,
    AdminOperationError::IdempotencyConflict => StatusCode::CONFLICT,
    AdminOperationError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    AdminOperationError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
  };
  text_response(status, &error.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn idempotency_key_accepts_only_bounded_visible_ascii() {
    let request = ::http::Request::builder()
      .header("Idempotency-Key", "deploy-2026-07-18:01")
      .body(())
      .unwrap();
    assert_eq!(
      idempotency_key(&request).unwrap().as_deref(),
      Some("deploy-2026-07-18:01")
    );

    let request = ::http::Request::builder()
      .header("Idempotency-Key", "contains space")
      .body(())
      .unwrap();
    assert!(idempotency_key(&request).is_err());

    let request = ::http::Request::builder()
      .header("Idempotency-Key", "x".repeat(129))
      .body(())
      .unwrap();
    assert!(idempotency_key(&request).is_err());
  }
}
