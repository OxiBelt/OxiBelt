use std::sync::Arc;

use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tracing::{debug, warn};

use crate::config::HttpVersion;
use crate::state::AppState;
use crate::waf::{
  WafRequestInput, WafResponseInput, WafTlsMetadata, apply_header_mutations, request_protocol,
};

mod body;
mod headers;
mod request;
mod response;
mod uri;
mod version;

use self::body::{ProxyBody, boxed_error};
use self::headers::{extract_host, is_upgrade_request, strip_hop_by_hop_headers};
use self::request::{RebuildRequestOptions, rebuild_request};
use self::response::{text_response, upstream_error_response, waf_terminal_response};
use self::uri::rewrite_uri;
use self::version::select_upstream_http_version;

pub async fn handle(
  request: Request<Incoming>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  state: Arc<AppState>,
) -> Response<ProxyBody> {
  if request.method() == Method::CONNECT {
    return text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "CONNECT tunneling is not implemented in this build",
    );
  }

  let host = extract_host(&request).unwrap_or_default();
  let path = request.uri().path().to_string();
  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let request_version = request.version();
  let request_headers = request.headers().clone();
  let protocol = request_protocol(&request_headers);
  let mut tags = std::collections::HashMap::new();

  let Some(resolved) = state.route_table.resolve(&host, &path, &state.upstreams) else {
    return text_response(StatusCode::NOT_FOUND, "no matching route");
  };

  let request_waf = state.waf.evaluate_request(WafRequestInput {
    method: &request_method,
    uri: &request_uri,
    version: request_version,
    headers: &request_headers,
    peer_addr,
    downstream_host: &host,
    route_name: &resolved.route.name,
    tcp_max_hop,
    tls: tls.as_ref(),
    protocol,
    tags: &tags,
  });

  for (key, value) in request_waf.tags {
    tags.insert(key, value);
  }

  if let Some(terminal) = request_waf.terminal {
    return waf_terminal_response(terminal, &request_waf.response_header_mutations);
  }

  if is_upgrade_request(&request) {
    return text_response(
      StatusCode::NOT_IMPLEMENTED,
      "WebSocket and generic HTTP upgrade tunneling are reserved but not implemented yet",
    );
  }

  let upstream = if let Some(upstream_name) = request_waf.upstream_override.as_deref() {
    match state
      .upstreams
      .iter()
      .find(|upstream| upstream.name == upstream_name)
    {
      Some(upstream) => upstream,
      None => {
        warn!(upstream = upstream_name, "WAF selected an unknown upstream");
        return text_response(StatusCode::BAD_GATEWAY, "WAF selected an unknown upstream");
      }
    }
  } else {
    resolved.upstream
  };

  let upstream_version = select_upstream_http_version(
    state.config.proxy.auto_upgrade.enabled,
    state.config.proxy.auto_upgrade.max_http_version,
    upstream.max_http_version,
  );

  if upstream_version == HttpVersion::H3 {
    return text_response(
      StatusCode::NOT_IMPLEMENTED,
      "upstream HTTP/3 forwarding is reserved but not implemented yet",
    );
  }

  let target_uri = match rewrite_uri(
    &upstream.origin,
    resolved.route.path_prefix.as_str(),
    resolved.route.replace_prefix_with.as_deref(),
    request.uri(),
  ) {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
      return text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite");
    }
  };

  let rebuild = RebuildRequestOptions {
    target_uri,
    compression: &state.config.compression,
    peer_addr,
    downstream_host: &host,
    preserve_host: upstream.preserve_host,
    upstream_version,
    waf_mutations: &request_waf.request_header_mutations,
  };
  let outbound = rebuild_request(request, rebuild);

  debug!(
      route = %resolved.route.name,
      upstream = %upstream.name,
      method = %outbound.method(),
      uri = %outbound.uri(),
      "proxying downstream request"
  );

  let Some(client) = state
    .clients
    .for_upstream_version(&upstream.name, upstream_version)
  else {
    warn!(
        upstream = %upstream.name,
        "missing upstream client pool"
    );
    return text_response(StatusCode::BAD_GATEWAY, "upstream client is not configured");
  };
  let upstream_response = match client.request(outbound).await {
    Ok(response) => response,
    Err(error) => {
      warn!(
          error = %error,
          upstream = %upstream.name,
          "upstream request failed"
      );
      return upstream_error_response(
        &state,
        &resolved.route.name,
        &request_method,
        &request_uri,
        request_version,
        &request_headers,
        peer_addr,
        &host,
        tcp_max_hop,
        tls.as_ref(),
        protocol,
        &tags,
        &upstream.name,
        &error.to_string(),
        &request_waf.response_header_mutations,
      );
    }
  };

  let (mut parts, body) = upstream_response.into_parts();
  strip_hop_by_hop_headers(&mut parts.headers);
  apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);

  if state.waf.has_response_rules(&resolved.route.name) {
    let request_input = WafRequestInput {
      method: &request_method,
      uri: &request_uri,
      version: request_version,
      headers: &request_headers,
      peer_addr,
      downstream_host: &host,
      route_name: &resolved.route.name,
      tcp_max_hop,
      tls: tls.as_ref(),
      protocol,
      tags: &tags,
    };
    let response_waf = state.waf.evaluate_response(WafResponseInput {
      request: request_input,
      status: parts.status,
      headers: &parts.headers,
      upstream_name: &upstream.name,
      upstream_error: None,
    });
    if let Some(terminal) = response_waf.terminal {
      let mut mutations = request_waf.response_header_mutations.clone();
      mutations.extend(response_waf.response_header_mutations);
      return waf_terminal_response(terminal, &mutations);
    }
    apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
  }

  Response::from_parts(parts, body.map_err(boxed_error).boxed())
}
