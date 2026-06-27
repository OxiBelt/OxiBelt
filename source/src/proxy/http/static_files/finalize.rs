use std::collections::HashMap;
use std::time::Duration;

use http::{HeaderMap, Method, Response};
use tracing::warn;

use super::super::body::ProxyBody;
use super::super::response::{apply_security_headers, text_response, waf_http_terminal_response};
use super::super::{
  SystemAccessLogContext, apply_alt_svc_header, capture_response_body_for_waf, compression,
  response_body_capture_error_response, waf_body_input, with_downstream_response_timeout,
};
use crate::config::RouteConfig;
use crate::state::AppSnapshot;
use crate::waf::{
  BodyNeed, RequestWafDecision, WafBodyInput, WafProtocol, WafRequestInput, WafResponseInput,
  WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations,
};

#[allow(clippy::too_many_arguments)]
pub(in crate::proxy::http) async fn finalize_response(
  response: Response<ProxyBody>,
  state: &AppSnapshot,
  route: &RouteConfig,
  request_waf: &RequestWafDecision,
  response_waf_enabled: bool,
  response_body_need: BodyNeed,
  request_method: &Method,
  request_uri: &http::Uri,
  request_version: http::Version,
  request_headers: &HeaderMap,
  peer_addr: std::net::SocketAddr,
  downstream_host: &str,
  tcp_max_hop: Option<u8>,
  tls: &WafTlsMetadata,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  transport_metadata: WafTransportMetadataInput<'_>,
  downstream_scheme: &'static str,
  request_body: Option<WafBodyInput<'_>>,
  tags: &HashMap<String, String>,
  access_log: &mut SystemAccessLogContext<'_>,
) -> Response<ProxyBody> {
  let (mut parts, body) = response.into_parts();
  apply_security_headers(&mut parts.headers, &state.config.security.headers);
  apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);

  let response_waf_body_compression_transform =
    crate::waf::route_http_body_compression_transform_enabled(&state.config, route)
      && response_body_need != BodyNeed::None;
  let (body, captured_response_body) = if response_body_need != BodyNeed::None {
    match capture_response_body_for_waf(
      parts.version,
      &mut parts.headers,
      body,
      response_body_need,
      state.config.waf.limits.max_body_inspection_bytes,
      response_waf_body_compression_transform,
      &state.config.waf.http_body_compression,
      &state.waf_body_coding,
    )
    .await
    {
      Ok(result) => result,
      Err(error) => {
        let (status, message) = response_body_capture_error_response(&error);
        warn!(error = %error, route = %route.name, status = status.as_u16(), "failed to read static response body for WAF inspection");
        return text_response(status, message);
      }
    }
  } else {
    (body, None)
  };
  let response_body = captured_response_body.as_ref().map(waf_body_input);

  if response_waf_enabled {
    access_log.ensure_response_ids();
    access_log.response_received_at_unix_ms = crate::waf::current_unix_ms();
    let request_input = WafRequestInput {
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
      downstream_scheme,
      route_name: &route.name,
      tcp_max_hop,
      tls,
      protocol,
      transport_network,
      transport_metadata,
      tags,
      dynamic_policy: &access_log.dynamic_policy,
    };
    let response_waf = state.waf.evaluate_response(WafResponseInput {
      request: request_input,
      response_id: access_log.response_id(),
      received_at_unix_ms: access_log.response_received_at_unix_ms,
      version: parts.version,
      status: parts.status,
      headers: &parts.headers,
      body: response_body,
      upstream_name: "static",
      upstream_pool: None,
      upstream_scheme: "file",
      upstream_connect_time_ms: None,
      upstream_first_byte_time_ms: None,
      upstream_error: None,
    });
    for access_log in &response_waf.access_logs {
      state.access_logs.emit(access_log);
    }
    if let Some(terminal) = response_waf.terminal {
      let mut mutations = request_waf.response_header_mutations.clone();
      mutations.extend(response_waf.response_header_mutations);
      return waf_http_terminal_response(terminal, &mutations);
    }
    apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
  }

  apply_alt_svc_header(
    &mut parts.headers,
    parts.status,
    state,
    downstream_scheme,
    request_version,
  );
  let response = Response::from_parts(parts, body);
  let response = compression::maybe_compress_response(
    response,
    request_method,
    request_headers,
    route.compression.as_deref(),
    &state.config.compression,
    &state.compression,
  );
  let response = with_downstream_response_timeout(
    response,
    static_response_send_timeout(state, route),
    transport_network,
  );
  state.record_hot_path_response(response.status());
  response
}

pub(crate) fn static_response_send_timeout(state: &AppSnapshot, route: &RouteConfig) -> Duration {
  Duration::from_millis(
    route
      .timeouts
      .response_send_timeout_ms
      .unwrap_or(state.config.limits.response_send_timeout_ms),
  )
}
