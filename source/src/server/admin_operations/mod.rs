//! Long-running admin operation transports and runtime wiring.
//! All transports share the same operation state so progress and cancellation semantics match.

mod endpoint;
mod id;
mod runtime;
mod stream;
mod types;
mod websocket;
mod webtransport;

pub(super) use endpoint::{
  AdminOperationRouteContext, accepted_operation_response, admin_operations_response,
  can_access_operation,
};
pub(super) use id::parse_operation_id;
pub(super) use runtime::{
  AdminOperationContext, AdminOperationError, AdminOperationRuntime, AdminOperationWorkResult,
  value_result,
};
pub(super) use stream::encode_ndjson_event;
pub(super) use types::{AdminOperationEvent, AdminOperationKind};
pub(super) use webtransport::{
  enqueue_webtransport_drain_operation, enqueue_webtransport_snapshot_operation,
};

use ::http::{Response, StatusCode};

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;

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

pub(super) fn enqueue_error_response(error: AdminOperationError) -> Response<ProxyBody> {
  let status = match error {
    AdminOperationError::Disabled => StatusCode::CONFLICT,
    AdminOperationError::QueueFull | AdminOperationError::StoreFull => {
      StatusCode::SERVICE_UNAVAILABLE
    }
    AdminOperationError::NotFound => StatusCode::NOT_FOUND,
    AdminOperationError::AlreadyTerminal => StatusCode::CONFLICT,
  };
  text_response(status, &error.to_string())
}
