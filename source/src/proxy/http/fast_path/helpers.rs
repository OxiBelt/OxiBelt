use http::{Extensions, HeaderMap, Request, Response};
use hyper::body::Body;

use crate::config::{HttpVersion, PriorityMode, ProxyProtocolEgressMode, TrailerMode};
use crate::metrics::fast_path::labels::{FastPathMetricProtocol, FastPathRequestBodyOutcome};
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody};
use crate::proxy::http::request_framing::{
  VerifiedContentLengthZeroBody, VerifiedEmptyRequestBody,
};
use crate::proxy::http::route_actions::{self, RouteActionRenderContext};
use crate::proxy::http::semantics;
use crate::proxy::http::uri::{self, UpstreamUriParts};
use crate::proxy::http::version::select_upstream_http_version;
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::waf::WafTransportNetwork;

use super::super::with_downstream_response_timeout;
use super::request_body::fast_path_request_body_is_definitely_empty;
use super::response_body::fast_path_filter_trailers;

pub(super) fn apply_fast_path_priority_policy(headers: &mut HeaderMap, mode: PriorityMode) {
  if mode != PriorityMode::Pass {
    semantics::apply_priority_policy(headers, mode);
  }
}

pub(super) fn fast_path_metric_protocol(version: http::Version) -> FastPathMetricProtocol {
  match version {
    http::Version::HTTP_10 | http::Version::HTTP_11 => FastPathMetricProtocol::H1,
    http::Version::HTTP_2 => FastPathMetricProtocol::H2,
    http::Version::HTTP_3 => FastPathMetricProtocol::H3,
    _ => FastPathMetricProtocol::Other,
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

pub(super) fn fast_path_upstream_timing_required(
  state: &AppSnapshot,
  response_waf_enabled: bool,
  pool_selected: bool,
) -> bool {
  response_waf_enabled
    || pool_selected
    || state.request_path_features.system_access_log
    || state.request_path_features.detailed_metrics
    || state.request_path_features.telemetry
}

pub(super) fn request_body_definitely_empty<B: Body>(request: &Request<B>) -> bool {
  fast_path_request_body_is_definitely_empty(request.version(), request.headers())
    || request.body().is_end_stream()
    || request
      .extensions()
      .get::<VerifiedContentLengthZeroBody>()
      .is_some()
    || request
      .extensions()
      .get::<VerifiedEmptyRequestBody>()
      .is_some()
}

pub(super) fn plain_proxy_fast_path_supported_route(
  state: &AppSnapshot,
  resolved: &ResolvedRoute<'_>,
) -> bool {
  if resolved.route.upstream_pool.is_some() {
    return resolved.route.upstream_http_version != Some(HttpVersion::H3);
  }

  let Some(upstream) = resolved.upstream else {
    return false;
  };
  let upstream_version = resolved.route.upstream_http_version.unwrap_or_else(|| {
    select_upstream_http_version(
      state.config.proxy.auto_upgrade.enabled,
      state.config.proxy.auto_upgrade.max_http_version,
      upstream.max_http_version,
    )
  });
  upstream_version != HttpVersion::H3
    && upstream.proxy_protocol_egress == ProxyProtocolEgressMode::Off
}

pub(super) fn record_empty_request_body(
  state: &AppSnapshot,
  protocol: FastPathMetricProtocol,
  extensions: &Extensions,
) {
  if state.request_path_features.hot_path_metrics {
    let outcome = if extensions.get::<VerifiedContentLengthZeroBody>().is_some()
      || extensions.get::<VerifiedEmptyRequestBody>().is_some()
    {
      FastPathRequestBodyOutcome::VerifiedEmpty
    } else {
      FastPathRequestBodyOutcome::AlreadyEmpty
    };
    state
      .metrics
      .record_fast_path_request_body_id(protocol, outcome);
  }
}

pub(super) fn fast_path_target_uri(
  origin: &UpstreamUriParts,
  resolved: &ResolvedRoute<'_>,
  downstream_scheme: &str,
  downstream_host: &str,
  downstream_uri: &http::Uri,
) -> anyhow::Result<http::Uri> {
  if resolved.route.actions.rewrite.is_none() {
    return uri::rewrite_uri(
      origin,
      resolved.route.effective_path_prefix(),
      resolved.route.replace_prefix_with.as_deref(),
      downstream_uri,
    );
  }

  route_actions::build_upstream_uri(
    origin,
    resolved.route,
    RouteActionRenderContext {
      route_prefix: resolved.route.effective_path_prefix(),
      path_captures: &resolved.path_captures,
      downstream_scheme,
      downstream_host,
      downstream_uri,
    },
  )
}

pub(super) fn fast_path_alt_svc_possible(
  state: &AppSnapshot,
  downstream_scheme: &str,
  request_version: http::Version,
) -> bool {
  state.alt_svc_header_value.is_some()
    && downstream_scheme == "https"
    && matches!(
      request_version,
      http::Version::HTTP_10 | http::Version::HTTP_11 | http::Version::HTTP_2
    )
}
