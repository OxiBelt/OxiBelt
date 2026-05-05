use bytes::Bytes;
use http::header::HeaderMap;
use http::{Method, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};

use crate::state::AppState;
use crate::waf::{
  HeaderMutation, WafRequestInput, WafResponseInput, WafTerminalResponse, WafTlsMetadata,
  WafTransportNetwork, WafUpstreamError, apply_header_mutations,
};

use super::body::{BoxError, ProxyBody};

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
pub(crate) fn upstream_error_response(
  state: &AppState,
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
  tags: &std::collections::HashMap<String, String>,
  upstream_name: &str,
  error_message: &str,
  request_response_mutations: &[HeaderMutation],
) -> Response<ProxyBody> {
  let mut response = text_response(StatusCode::BAD_GATEWAY, "upstream request failed");
  apply_header_mutations(response.headers_mut(), request_response_mutations);
  if !state.waf.has_response_rules(route_name) {
    return response;
  }

  let request = WafRequestInput {
    method: request_method,
    uri: request_uri,
    version: request_version,
    headers: request_headers,
    peer_addr,
    downstream_host,
    route_name,
    tcp_max_hop,
    tls,
    protocol,
    transport_network,
    tags,
  };
  let response_waf = state.waf.evaluate_response(WafResponseInput {
    request,
    status: StatusCode::BAD_GATEWAY,
    headers: response.headers(),
    upstream_name,
    upstream_error: Some(WafUpstreamError {
      code: "connect_error",
      message: error_message,
    }),
  });

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
