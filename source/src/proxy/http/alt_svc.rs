use std::net::SocketAddr;

use http::{HeaderMap, StatusCode};

use crate::state::AppSnapshot;

pub(super) fn apply_alt_svc_header(
  headers: &mut HeaderMap,
  status: StatusCode,
  state: &AppSnapshot,
  downstream_scheme: &str,
  request_version: http::Version,
  listener_bind: Option<SocketAddr>,
) {
  if !should_add_alt_svc(status, state, downstream_scheme, request_version) {
    return;
  }
  if let Some(value) = state.alt_svc_header_values.for_listener_bind(listener_bind) {
    headers.insert(http::header::ALT_SVC, value);
  }
}

pub(super) fn should_add_alt_svc(
  status: StatusCode,
  state: &AppSnapshot,
  downstream_scheme: &str,
  request_version: http::Version,
) -> bool {
  state.alt_svc_header_values.is_some()
    && downstream_scheme == "https"
    && matches!(
      request_version,
      http::Version::HTTP_10 | http::Version::HTTP_11 | http::Version::HTTP_2
    )
    && status != StatusCode::SWITCHING_PROTOCOLS
}
