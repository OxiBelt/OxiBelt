//! Response builders shared by proxy, WAF, and error paths.
//! Centralized builders keep security headers and terminal WAF responses consistent.

use bytes::Bytes;
use http::header::HeaderMap;
use http::{HeaderValue, Method, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};
use std::error::Error;
use std::fmt;
use tracing::warn;

use crate::config::{ErrorResponseMode, RouteConfig, SecurityConfig, SecurityHeadersConfig};
use crate::external_auth::ExternalAuthTerminal;
use crate::state::AppSnapshot;
use crate::waf::{
  EvaluatedPersonProofRequest, HeaderMutation, WafBodyInput, WafHttpTerminal, WafRequestInput,
  WafResponseInput, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork,
  WafUpstreamError, apply_header_mutations,
};

use super::SystemAccessLogContext;
use super::body::{
  BodyTimeoutKind, BoxError, InlinedKnownSmallResponseBody, KnownSmallResponseBody, ProxyBody,
  error_is_body_length_limit, error_is_timeout, is_known_small_response_body_len,
};
use super::buffering;
use super::semantics::{configured_error_response, grpc_upstream_error_response};
use super::upstream::UpstreamSelectionError;

pub(crate) fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
  let body_len = message.len();
  let bytes = Bytes::copy_from_slice(message.as_bytes());
  let body = Full::new(bytes.clone())
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = status;
  if is_known_small_response_body_len(body_len) {
    response.extensions_mut().insert(KnownSmallResponseBody);
    response
      .extensions_mut()
      .insert(InlinedKnownSmallResponseBody::new(bytes, None));
  }
  response
}

pub(crate) fn waf_http_terminal_response_with_route_security(
  terminal: WafHttpTerminal,
  mutations: &[HeaderMutation],
  security: &SecurityConfig,
  route: &RouteConfig,
) -> Response<ProxyBody> {
  match terminal {
    WafHttpTerminal::Response(terminal) => {
      let mut response = text_response(terminal.status, &terminal.body);
      apply_route_security_headers(response.headers_mut(), security, route);
      apply_header_mutations(response.headers_mut(), &terminal.headers);
      apply_header_mutations(response.headers_mut(), mutations);
      response
    }
    WafHttpTerminal::SilentClose => silent_close_response(),
  }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SilentClose;

impl fmt::Display for SilentClose {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("connection silently closed by policy")
  }
}

impl Error for SilentClose {}

#[derive(Debug, Clone, Copy)]
struct SilentCloseResponse;

pub(crate) fn silent_close_response() -> Response<ProxyBody> {
  let mut response = text_response(StatusCode::NO_CONTENT, "");
  response.extensions_mut().insert(SilentCloseResponse);
  response
}

pub(crate) fn is_silent_close_response(response: &Response<ProxyBody>) -> bool {
  response.extensions().get::<SilentCloseResponse>().is_some()
}

pub(crate) fn apply_sticky_cookie(
  response: &mut Response<ProxyBody>,
  sticky_cookie: Option<&HeaderValue>,
) {
  if let Some(value) = sticky_cookie {
    response
      .headers_mut()
      .append(http::header::SET_COOKIE, value.clone());
  }
}

pub(crate) fn draining_response() -> Response<ProxyBody> {
  let mut response = text_response(StatusCode::SERVICE_UNAVAILABLE, "draining");
  response.headers_mut().insert(
    http::header::CONNECTION,
    http::HeaderValue::from_static("close"),
  );
  response
}

pub(super) fn proxy_error_response(
  state: &AppSnapshot,
  access_log: &mut SystemAccessLogContext<'_>,
  status: StatusCode,
  message: &str,
  code: &str,
) -> Response<ProxyBody> {
  if state.config.proxy.http.errors.mode == ErrorResponseMode::Json {
    access_log.ensure_request_id();
    configured_error_response(
      &state.config,
      access_log.request_id(),
      status,
      message,
      code,
    )
  } else {
    configured_error_response(&state.config, "", status, message, code)
  }
}

pub(super) fn upstream_selection_error_response(
  error: UpstreamSelectionError,
) -> Response<ProxyBody> {
  match error {
    UpstreamSelectionError::UnknownWafUpstream(upstream) => {
      warn!(upstream, "WAF selected an unknown upstream");
      text_response(StatusCode::BAD_GATEWAY, "WAF selected an unknown upstream")
    }
    UpstreamSelectionError::PoolUnavailable { pool_name, message } => {
      warn!(error = %message, pool = %pool_name, "failed to select upstream pool server");
      text_response(StatusCode::BAD_GATEWAY, "no available upstream pool server")
    }
    UpstreamSelectionError::MissingRouteUpstream => {
      warn!("route resolved without an upstream");
      text_response(StatusCode::BAD_GATEWAY, "upstream is not configured")
    }
    UpstreamSelectionError::MissingSyntheticUpstream(upstream) => {
      warn!(upstream, "pool selected an unknown synthetic upstream");
      text_response(StatusCode::BAD_GATEWAY, "no available upstream pool server")
    }
  }
}

pub(super) fn external_auth_response(terminal: ExternalAuthTerminal) -> Response<ProxyBody> {
  let body = Full::new(terminal.body)
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = terminal.status;
  *response.headers_mut() = terminal.headers;
  response
}

pub(super) fn with_pending_dynamic_person_proof_response_mutations(
  mut response: Response<ProxyBody>,
  state: &AppSnapshot,
  evaluated_person_proof: Option<&EvaluatedPersonProofRequest>,
  dynamic_person_proof_mutation_added: bool,
  dynamic_challenge_response_mutations: &[HeaderMutation],
) -> Response<ProxyBody> {
  apply_header_mutations(response.headers_mut(), dynamic_challenge_response_mutations);
  if dynamic_person_proof_mutation_added || !dynamic_challenge_response_mutations.is_empty() {
    return response;
  }
  let Some(evaluated) = evaluated_person_proof else {
    return response;
  };
  match state
    .waf
    .person_proof_clearance_response_mutation(evaluated)
  {
    Ok(Some(mutation)) => {
      apply_header_mutations(response.headers_mut(), std::slice::from_ref(&mutation));
    }
    Ok(None) => {}
    Err(error) => {
      warn!(error = %error, "failed to attach dynamic Person proof clearance rotation");
    }
  }
  response
}

pub(super) fn request_buffering_error_response(
  error: buffering::BufferingError,
) -> Response<ProxyBody> {
  match error {
    buffering::BufferingError::TooLarge => {
      text_response(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large")
    }
    buffering::BufferingError::Body(error)
      if error_is_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) =>
    {
      text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out")
    }
    buffering::BufferingError::Body(error) if error_is_body_length_limit(&error) => {
      text_response(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large")
    }
    buffering::BufferingError::Body(error) => {
      warn!(error = %error, "failed to buffer downstream request body");
      text_response(StatusCode::BAD_REQUEST, "failed to read request body")
    }
    buffering::BufferingError::Io(error) => {
      warn!(error = %error, "failed to spool downstream request body");
      text_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to buffer request body",
      )
    }
    buffering::BufferingError::MissingTempDir => {
      warn!("request buffering spool mode is missing temp_dir");
      text_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to buffer request body",
      )
    }
  }
}

pub(super) fn response_buffering_error_response(
  error: buffering::BufferingError,
) -> Response<ProxyBody> {
  match error {
    buffering::BufferingError::TooLarge => text_response(
      StatusCode::BAD_GATEWAY,
      "upstream response body is too large",
    ),
    buffering::BufferingError::Body(error)
      if error_is_timeout(&error, BodyTimeoutKind::UpstreamResponseRead) =>
    {
      text_response(
        StatusCode::GATEWAY_TIMEOUT,
        "upstream response body timed out",
      )
    }
    buffering::BufferingError::Body(error) => {
      warn!(error = %error, "failed to buffer upstream response body");
      text_response(
        StatusCode::BAD_GATEWAY,
        "failed to read upstream response body",
      )
    }
    buffering::BufferingError::Io(error) => {
      warn!(error = %error, "failed to spool upstream response body");
      text_response(
        StatusCode::BAD_GATEWAY,
        "failed to buffer upstream response body",
      )
    }
    buffering::BufferingError::MissingTempDir => {
      warn!("response buffering spool mode is missing temp_dir");
      text_response(
        StatusCode::BAD_GATEWAY,
        "failed to buffer upstream response body",
      )
    }
  }
}

pub(crate) fn apply_security_headers(
  headers: &mut http::HeaderMap,
  config: &SecurityHeadersConfig,
) {
  if !config.hsts
    && config.x_content_type_options.is_none()
    && config.referrer_policy.is_none()
    && config.permissions_policy.is_none()
  {
    return;
  }
  if config.hsts {
    let mut value = format!("max-age={}", config.hsts_max_age_seconds);
    if config.hsts_include_subdomains {
      value.push_str("; includeSubDomains");
    }
    if config.hsts_preload {
      value.push_str("; preload");
    }
    insert_header(headers, "strict-transport-security", &value);
  }
  if let Some(value) = &config.x_content_type_options {
    insert_header(headers, "x-content-type-options", value);
  }
  if let Some(value) = &config.referrer_policy {
    insert_header(headers, "referrer-policy", value);
  }
  if let Some(value) = &config.permissions_policy {
    insert_header(headers, "permissions-policy", value);
  }
}

pub(crate) fn apply_effective_security_headers(
  headers: &mut http::HeaderMap,
  security: &SecurityConfig,
  route_security_headers: Option<&str>,
) {
  if let Some(config) = security.effective_headers_for_route(route_security_headers) {
    apply_security_headers(headers, config);
  }
}

pub(crate) fn apply_route_security_headers(
  headers: &mut http::HeaderMap,
  security: &SecurityConfig,
  route: &RouteConfig,
) {
  apply_effective_security_headers(headers, security, route.security_headers.as_deref());
}

pub(crate) fn reconcile_route_security_headers(
  headers: &mut http::HeaderMap,
  security: &SecurityConfig,
  route: &RouteConfig,
) {
  for name in [
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
  ] {
    headers.remove(name);
  }
  apply_route_security_headers(headers, security, route);
}

pub(crate) fn with_route_security_headers(
  mut response: Response<ProxyBody>,
  security: &SecurityConfig,
  route: &RouteConfig,
) -> Response<ProxyBody> {
  apply_route_security_headers(response.headers_mut(), security, route);
  response
}

pub(crate) struct RouteSecurityHeaders<'a> {
  security: &'a SecurityConfig,
  route: &'a RouteConfig,
}

impl<'a> RouteSecurityHeaders<'a> {
  pub(crate) fn new(security: &'a SecurityConfig, route: &'a RouteConfig) -> Self {
    Self { security, route }
  }

  pub(crate) fn apply(&self, response: Response<ProxyBody>) -> Response<ProxyBody> {
    with_route_security_headers(response, self.security, self.route)
  }

  pub(crate) fn text(&self, status: StatusCode, message: &str) -> Response<ProxyBody> {
    self.apply(text_response(status, message))
  }

  pub(crate) fn waf_http_terminal(
    &self,
    terminal: WafHttpTerminal,
    mutations: &[HeaderMutation],
  ) -> Response<ProxyBody> {
    waf_http_terminal_response_with_route_security(terminal, mutations, self.security, self.route)
  }
}

fn insert_header(headers: &mut http::HeaderMap, name: &'static str, value: &str) {
  if let Ok(value) = http::HeaderValue::from_str(value) {
    headers.insert(http::HeaderName::from_static(name), value);
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn upstream_error_response(
  state: &AppSnapshot,
  route: &RouteConfig,
  request_method: &Method,
  request_uri: &Uri,
  request_version: http::Version,
  request_headers: &HeaderMap,
  peer_addr: std::net::SocketAddr,
  downstream_host: &str,
  tcp_max_hop: Option<u8>,
  tls: &WafTlsMetadata,
  protocol: crate::waf::WafProtocol,
  transport_network: WafTransportNetwork,
  transport_metadata: WafTransportMetadataInput<'_>,
  request_body: Option<WafBodyInput<'_>>,
  tags: &std::collections::HashMap<String, String>,
  upstream_name: &str,
  upstream_scheme: &str,
  upstream_connect_time_ms: Option<u64>,
  upstream_first_byte_time_ms: Option<u64>,
  upstream_error_code: &str,
  error_message: &str,
  request_response_mutations: &[HeaderMutation],
  access_log: &mut SystemAccessLogContext<'_>,
) -> Response<ProxyBody> {
  let route_name = &route.name;
  let status = if upstream_error_code.contains("timeout") {
    StatusCode::GATEWAY_TIMEOUT
  } else {
    StatusCode::BAD_GATEWAY
  };
  let mut response = grpc_upstream_error_response(
    &state.config,
    request_headers,
    upstream_error_code,
    error_message,
  )
  .unwrap_or_else(|| {
    if state.config.proxy.http.errors.mode == ErrorResponseMode::Json {
      access_log.ensure_request_id();
    }
    configured_error_response(
      &state.config,
      if state.config.proxy.http.errors.mode == ErrorResponseMode::Json {
        access_log.request_id()
      } else {
        ""
      },
      status,
      "upstream request failed",
      upstream_error_code,
    )
  });
  apply_route_security_headers(response.headers_mut(), &state.config.security, route);
  apply_header_mutations(response.headers_mut(), request_response_mutations);
  if !state.waf.has_response_rules(route_name) {
    return response;
  }

  access_log.ensure_response_ids();
  let request = WafRequestInput {
    request_id: access_log.request_id(),
    transaction_id: access_log.transaction_id(),
    received_at_unix_ms: access_log.request_received_at_unix_ms,
    method: request_method,
    uri: request_uri,
    version: request_version,
    headers: request_headers,
    body: request_body,
    peer_addr,
    client_asn: state.client_identity.asn.lookup(peer_addr.ip()),
    downstream_host,
    downstream_scheme: access_log.downstream_scheme,
    route_name,
    tcp_max_hop,
    tls,
    protocol,
    transport_network,
    transport_metadata,
    tags,
    dynamic_policy: &access_log.dynamic_policy,
  };
  let response_waf = state.waf.evaluate_response(WafResponseInput {
    request,
    response_id: access_log.response_id(),
    received_at_unix_ms: crate::waf::current_unix_ms(),
    version: http::Version::HTTP_11,
    status,
    headers: response.headers(),
    body: None,
    upstream_name,
    upstream_pool: access_log.upstream_pool.as_deref(),
    upstream_scheme,
    upstream_connect_time_ms,
    upstream_first_byte_time_ms,
    upstream_error: Some(WafUpstreamError {
      code: upstream_error_code,
      message: error_message,
    }),
  });
  for access_log in &response_waf.access_logs {
    state.access_logs.emit(access_log);
  }

  if let Some(terminal) = response_waf.terminal {
    let mut mutations = request_response_mutations.to_vec();
    mutations.extend(response_waf.response_header_mutations);
    return waf_http_terminal_response_with_route_security(
      terminal,
      &mutations,
      &state.config.security,
      route,
    );
  }

  apply_header_mutations(
    response.headers_mut(),
    &response_waf.response_header_mutations,
  );
  response
}

#[allow(dead_code)]
fn empty_response(status: StatusCode) -> Response<ProxyBody> {
  let body = Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = status;
  response.extensions_mut().insert(KnownSmallResponseBody);
  response
    .extensions_mut()
    .insert(InlinedKnownSmallResponseBody::new(Bytes::new(), None));
  response
}
