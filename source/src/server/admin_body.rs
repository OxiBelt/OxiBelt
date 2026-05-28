use ::http::{Response, StatusCode};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
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
  let audit = AdminAuditHandle::from_request(&request);
  let bytes = Limited::new(request.into_body(), limit)
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
  if let Some(audit) = audit {
    audit.record_json_body(&bytes);
  }
  serde_json::from_slice(&bytes)
    .map_err(|_| admin_error::error_response(StatusCode::BAD_REQUEST, "invalid JSON request body"))
}
