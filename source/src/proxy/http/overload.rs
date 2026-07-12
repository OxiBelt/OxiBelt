use http::{HeaderMap, Response, Version};

use crate::overload::RequestLease;
use crate::state::AppSnapshot;

use super::body::{self, ProxyBody};
use super::response::text_response;

pub(super) fn with_overload_request_lease(
  response: Response<ProxyBody>,
  lease: RequestLease,
) -> Response<ProxyBody> {
  let (parts, body) = response.into_parts();
  Response::from_parts(parts, body::with_drop_guard(body, lease))
}

pub(super) fn content_length(headers: &HeaderMap) -> Option<u64> {
  headers
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse().ok())
}

pub(super) fn overload_response(
  snapshot: &AppSnapshot,
  request_version: Version,
) -> Response<ProxyBody> {
  let mut response = text_response(snapshot.overload.response_status(), "overloaded");
  if let Ok(value) =
    http::HeaderValue::from_str(&snapshot.overload.retry_after_seconds().to_string())
  {
    response
      .headers_mut()
      .insert(http::header::RETRY_AFTER, value);
  }
  if matches!(request_version, Version::HTTP_10 | Version::HTTP_11) {
    response.headers_mut().insert(
      http::header::CONNECTION,
      http::HeaderValue::from_static("close"),
    );
  }
  response
}
