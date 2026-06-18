use http::{HeaderMap, Response};
use hyper::body::Body;

use crate::config::{PriorityMode, TrailerMode};
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody};
use crate::proxy::http::semantics;
use crate::waf::WafTransportNetwork;

use super::super::with_downstream_response_timeout;
use super::response_body::fast_path_filter_trailers;

pub(super) fn apply_fast_path_priority_policy(headers: &mut HeaderMap, mode: PriorityMode) {
  if mode != PriorityMode::Pass {
    semantics::apply_priority_policy(headers, mode);
  }
}

pub(super) fn fast_path_metric_protocol(version: http::Version) -> &'static str {
  match version {
    http::Version::HTTP_10 | http::Version::HTTP_11 => "h1",
    http::Version::HTTP_2 => "h2",
    http::Version::HTTP_3 => "h3",
    _ => "other",
  }
}

pub(super) fn fast_path_downstream_response_timeout(
  response: Response<ProxyBody>,
  known_small_response_body: bool,
  timeout: std::time::Duration,
  transport_network: WafTransportNetwork,
) -> Response<ProxyBody> {
  if known_small_response_body && transport_network != WafTransportNetwork::Udp {
    return response;
  }
  with_downstream_response_timeout(response, timeout, transport_network)
}

pub(super) fn fast_path_outbound_request_body(
  body: ProxyBody,
  trailer_mode: TrailerMode,
  timeout: std::time::Duration,
) -> ProxyBody {
  if body.is_end_stream() {
    return body;
  }
  let body = fast_path_filter_trailers(body, trailer_mode);
  if body.is_end_stream() {
    return body;
  }
  body::with_send_timeout(body, timeout, BodyTimeoutKind::UpstreamRequestSend)
}
