use bytes::Bytes;
use http::header::HeaderMap;
use http::{HeaderValue, Method, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};

use crate::config::{ErrorResponseMode, SecurityHeadersConfig};
use crate::state::AppSnapshot;
use crate::waf::{
  HeaderMutation, WafBodyInput, WafRequestInput, WafResponseInput, WafTerminalResponse,
  WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork, WafUpstreamError,
  apply_header_mutations,
};

use super::SystemAccessLogContext;
use super::body::{BoxError, KnownSmallResponseBody, ProxyBody, is_known_small_response_body_len};
use super::semantics::{configured_error_response, grpc_upstream_error_response};

pub(crate) fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
  let body_len = message.len();
  let body = Full::new(Bytes::copy_from_slice(message.as_bytes()))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = status;
  if is_known_small_response_body_len(body_len) {
    response.extensions_mut().insert(KnownSmallResponseBody);
  }
  response
}

pub(crate) fn waf_terminal_response(
  terminal: WafTerminalResponse,
  mutations: &[HeaderMutation],
) -> Response<ProxyBody> {
  let mut response = text_response(terminal.status, &terminal.body);
  apply_header_mutations(response.headers_mut(), &terminal.headers);
  apply_header_mutations(response.headers_mut(), mutations);
  response
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

fn insert_header(headers: &mut http::HeaderMap, name: &'static str, value: &str) {
  if let Ok(value) = http::HeaderValue::from_str(value) {
    headers.insert(http::HeaderName::from_static(name), value);
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn upstream_error_response(
  state: &AppSnapshot,
  route_name: &str,
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
    return waf_terminal_response(terminal, &mutations);
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
}
