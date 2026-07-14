//! Admin request body parsing helpers.
//! Body limits are applied before deserialization so large control-plane payloads fail early.

use ::http::{Response, StatusCode, request::Parts};
use bytes::Bytes;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::{Body, Incoming};
use serde::Deserialize;

use crate::proxy::http::body::ProxyBody;

use super::admin_control;
use super::admin_error;
use crate::admin_audit::AdminAuditHandle;

pub(super) async fn collect_admin_json<T>(
  request: hyper::Request<Incoming>,
) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> Deserialize<'de>,
{
  collect_admin_json_with_limit(request, admin_control::ADMIN_CONFIG_BODY_LIMIT).await
}

pub(super) async fn collect_admin_json_with_limit<T>(
  request: hyper::Request<Incoming>,
  limit: usize,
) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> Deserialize<'de>,
{
  collect_admin_json_body_with_limit(request, limit).await
}

pub(super) async fn collect_admin_json_body<T, B>(
  request: hyper::Request<B>,
) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> Deserialize<'de>,
  B: Body<Data = Bytes>,
  B::Error: std::error::Error + Send + Sync + 'static,
{
  collect_admin_json_body_with_limit(request, admin_control::ADMIN_CONFIG_BODY_LIMIT).await
}

pub(super) async fn collect_admin_json_body_with_limit<T, B>(
  request: hyper::Request<B>,
  limit: usize,
) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> Deserialize<'de>,
  B: Body<Data = Bytes>,
  B::Error: std::error::Error + Send + Sync + 'static,
{
  let (parts, bytes) = collect_admin_request_bytes(request, limit).await?;
  decode_admin_json(&parts, &bytes)
}

pub(super) async fn collect_admin_request_bytes<B>(
  request: hyper::Request<B>,
  limit: usize,
) -> Result<(Parts, Bytes), Response<ProxyBody>>
where
  B: Body<Data = Bytes>,
  B::Error: std::error::Error + Send + Sync + 'static,
{
  let (parts, body) = request.into_parts();
  let bytes = Limited::new(body, limit)
    .collect()
    .await
    .map_err(|error| {
      if error.downcast_ref::<LengthLimitError>().is_some() {
        admin_error::error_response(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large")
      } else {
        admin_error::error_response(StatusCode::BAD_REQUEST, "failed to read request body")
      }
    })?
    .to_bytes();
  if let Some(audit) = parts.extensions.get::<AdminAuditHandle>() {
    audit.record_json_body(&bytes);
  }
  Ok((parts, bytes))
}

#[allow(clippy::result_large_err)]
pub(super) fn decode_admin_json<T>(_parts: &Parts, bytes: &[u8]) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> Deserialize<'de>,
{
  serde_json::from_slice(bytes)
    .map_err(|_| admin_error::error_response(StatusCode::BAD_REQUEST, "invalid JSON request body"))
}
