use bytes::Bytes;
use http::header::HeaderMap;
use http::{Method, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};

use crate::state::AppSnapshot;
use crate::waf::{
  HeaderMutation, WafBodyInput, WafRequestInput, WafResponseInput, WafTerminalResponse,
  WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork, WafUpstreamError,
  apply_header_mutations,
};

use super::SystemAccessLogContext;
use super::body::{BoxError, ProxyBody};
use super::semantics::{configured_error_response, grpc_upstream_error_response};

pub(crate) fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
  let body = Full::new(Bytes::copy_from_slice(message.as_bytes()))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = status;
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
  upstream_pool: Option<&str>,
  upstream_connect_time_ms: Option<u64>,
  upstream_first_byte_time_ms: Option<u64>,
  upstream_error_code: &str,
  error_message: &str,
  request_response_mutations: &[HeaderMutation],
  access_log: &SystemAccessLogContext,
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
    configured_error_response(
      &state.config,
      &access_log.request_id,
      status,
      "upstream request failed",
      upstream_error_code,
    )
  });
  apply_header_mutations(response.headers_mut(), request_response_mutations);
  if !state.waf.has_response_rules(route_name) {
    return response;
  }

  let request = WafRequestInput {
    request_id: &access_log.request_id,
    transaction_id: &access_log.transaction_id,
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
    response_id: &access_log.response_id,
    received_at_unix_ms: crate::waf::current_unix_ms(),
    version: http::Version::HTTP_11,
    status,
    headers: response.headers(),
    body: None,
    upstream_name,
    upstream_pool,
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
  response
}
