use ::http::{Response, StatusCode};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use serde::Deserialize;

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;

use super::admin_control;

pub(super) async fn collect_admin_json<T>(
  request: hyper::Request<Incoming>,
) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> Deserialize<'de>,
{
  let bytes = Limited::new(request.into_body(), admin_control::ADMIN_CONFIG_BODY_LIMIT)
    .collect()
    .await
    .map_err(|error| {
      if error.downcast_ref::<LengthLimitError>().is_some() {
        text_response(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large")
      } else {
        text_response(StatusCode::BAD_REQUEST, "failed to read request body")
      }
    })?
    .to_bytes();
  serde_json::from_slice(&bytes)
    .map_err(|_| text_response(StatusCode::BAD_REQUEST, "invalid JSON request body"))
}
