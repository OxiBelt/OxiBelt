use std::sync::Arc;

use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use tracing::{debug, warn};

use crate::config::{HttpVersion, UpstreamConfig};
use crate::state::{AppHandle, AppSnapshot};
use crate::waf::{
  WafBodyInput, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportNetwork, apply_header_mutations, request_protocol,
};

pub(crate) mod body;
pub(crate) mod headers;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod uri;
pub(crate) mod version;

use self::body::{CapturedBody, ProxyBody, boxed_error, capture_prefix};
use self::headers::{
  add_forwarded_headers, extract_host, is_upgrade_request, strip_hop_by_hop_headers,
};
use self::request::{RebuildRequestOptions, rebuild_request};
use self::response::{text_response, upstream_error_response, waf_terminal_response};
use self::uri::{rewrite_uri, validate_downstream_path};
use self::version::select_upstream_http_version;

pub async fn handle(
  request: Request<Incoming>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  state: AppHandle,
) -> Response<ProxyBody> {
  let protocol = request_protocol(request.headers());
  handle_inner(
    request,
    peer_addr,
    tcp_max_hop,
    tls,
    state,
    protocol,
    WafTransportNetwork::Tcp,
    true,
  )
  .await
}

pub(crate) async fn handle_http3(
  request: Request<ProxyBody>,
  peer_addr: std::net::SocketAddr,
  tls: Arc<WafTlsMetadata>,
  state: AppHandle,
) -> Response<ProxyBody> {
  handle_inner(
    request,
    peer_addr,
    None,
    tls,
    state,
    WafProtocol::Http,
    WafTransportNetwork::Udp,
    false,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_inner<B>(
  request: Request<B>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  state: AppHandle,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  reject_connect: bool,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + 'static,
{
  let state = state.snapshot();

  if request.method() == Method::CONNECT {
    if !reject_connect {
      return text_response(
        StatusCode::BAD_REQUEST,
        "unexpected HTTP/3 CONNECT request outside WebTransport handling",
      );
    }
    return text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "CONNECT tunneling is not implemented in this build",
    );
  }

  let host = extract_host(&request).unwrap_or_default();
  let path = request.uri().path().to_string();
  if let Err(error) = validate_downstream_path(&path) {
    warn!(error = %error, path = %path, "rejected unsafe downstream request path");
    return text_response(StatusCode::BAD_REQUEST, "invalid request path");
  }
  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let request_version = request.version();
  let request_headers = request.headers().clone();
  let mut tags = std::collections::HashMap::new();

  let Some(resolved) = state.route_table.resolve(&host, &path, &state.upstreams) else {
    return text_response(StatusCode::NOT_FOUND, "no matching route");
  };

  let (request, captured_body) = if state
    .waf
    .requires_request_body_inspection(&resolved.route.name)
  {
    match capture_prefix(request, state.config.waf.limits.max_body_inspection_bytes).await {
      Ok(result) => {
        let (request, body) = result;
        (request, Some(body))
      }
      Err(error) => {
        warn!(error = %error, "failed to read request body for WAF inspection");
        return text_response(StatusCode::BAD_REQUEST, "failed to read request body");
      }
    }
  } else {
    (request.map(|body| body.map_err(Into::into).boxed()), None)
  };
  let request_body = captured_body.as_ref().map(waf_body_input);

  let request_waf = state.waf.evaluate_request(WafRequestInput {
    method: &request_method,
    uri: &request_uri,
    version: request_version,
    headers: &request_headers,
    body: request_body,
    peer_addr,
    downstream_host: &host,
    route_name: &resolved.route.name,
    tcp_max_hop,
    tls: tls.as_ref(),
    protocol,
    transport_network,
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

  if upstream_version == HttpVersion::H3 && upstream.origin.scheme() != "https" {
    return text_response(
      StatusCode::BAD_GATEWAY,
      "upstream HTTP/3 requires https origin",
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
    forwarded_header_mode: state.config.proxy.forwarded_headers.mode,
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

  let upstream_response = if upstream_version == HttpVersion::H3 {
    match crate::proxy::http3::forward_request(outbound, upstream, state.as_ref()).await {
      Ok(response) => response,
      Err(error) => {
        warn!(
            error = %error,
            upstream = %upstream.name,
            "upstream HTTP/3 request failed"
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
          transport_network,
          request_body,
          &tags,
          &upstream.name,
          &error.to_string(),
          &request_waf.response_header_mutations,
        );
      }
    }
  } else {
    let Some(client) = state.clients.for_upstream_version(
      &upstream.name,
      upstream.origin.scheme(),
      upstream_version,
    ) else {
      warn!(
          upstream = %upstream.name,
          "missing upstream client pool"
      );
      return text_response(StatusCode::BAD_GATEWAY, "upstream client is not configured");
    };
    match client.request(outbound).await {
      Ok(response) => response.map(|body| body.map_err(boxed_error).boxed()),
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
          transport_network,
          request_body,
          &tags,
          &upstream.name,
          &error.to_string(),
          &request_waf.response_header_mutations,
        );
      }
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
      body: request_body,
      peer_addr,
      downstream_host: &host,
      route_name: &resolved.route.name,
      tcp_max_hop,
      tls: tls.as_ref(),
      protocol,
      transport_network,
      tags: &tags,
    };
    let response_waf = state.waf.evaluate_response(WafResponseInput {
      request: request_input,
      status: parts.status,
      headers: &parts.headers,
      upstream_name: &upstream.name,
      upstream_error: None,
    });
    for access_log in &response_waf.access_logs {
      state.access_logs.emit(access_log);
    }
    if let Some(terminal) = response_waf.terminal {
      let mut mutations = request_waf.response_header_mutations.clone();
      mutations.extend(response_waf.response_header_mutations);
      return waf_terminal_response(terminal, &mutations);
    }
    apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
  }

  Response::from_parts(parts, body)
}

pub(crate) struct PreparedWebTransport {
  pub(crate) target_url: url::Url,
  pub(crate) headers: http::HeaderMap,
  pub(crate) protocols: Vec<String>,
  pub(crate) upstream: UpstreamConfig,
}

pub(crate) fn prepare_webtransport(
  request: &Request<()>,
  peer_addr: std::net::SocketAddr,
  tls: &WafTlsMetadata,
  state: &AppSnapshot,
) -> Result<PreparedWebTransport, Box<Response<ProxyBody>>> {
  let host = extract_host(request).unwrap_or_default();
  let path = request.uri().path().to_string();
  if let Err(error) = validate_downstream_path(&path) {
    warn!(error = %error, path = %path, "rejected unsafe downstream WebTransport path");
    return Err(Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "invalid request path",
    )));
  }
  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let request_headers = request.headers().clone();
  let mut tags = std::collections::HashMap::new();

  let Some(resolved) = state.route_table.resolve(&host, &path, &state.upstreams) else {
    return Err(Box::new(text_response(
      StatusCode::NOT_FOUND,
      "no matching route",
    )));
  };

  let request_waf = state.waf.evaluate_request(WafRequestInput {
    method: &request_method,
    uri: &request_uri,
    version: http::Version::HTTP_3,
    headers: &request_headers,
    body: None,
    peer_addr,
    downstream_host: &host,
    route_name: &resolved.route.name,
    tcp_max_hop: None,
    tls,
    protocol: WafProtocol::Webtransport,
    transport_network: WafTransportNetwork::Udp,
    tags: &tags,
  });

  for (key, value) in request_waf.tags {
    tags.insert(key, value);
  }

  if let Some(terminal) = request_waf.terminal {
    return Err(Box::new(waf_terminal_response(
      terminal,
      &request_waf.response_header_mutations,
    )));
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
        return Err(Box::new(text_response(
          StatusCode::BAD_GATEWAY,
          "WAF selected an unknown upstream",
        )));
      }
    }
  } else {
    resolved.upstream
  };

  if !upstream.webtransport {
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "selected upstream does not allow WebTransport",
    )));
  }

  let upstream_version = select_upstream_http_version(
    state.config.proxy.auto_upgrade.enabled,
    state.config.proxy.auto_upgrade.max_http_version,
    upstream.max_http_version,
  );
  if upstream_version != HttpVersion::H3 {
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "WebTransport forwarding requires HTTP/3 upstream",
    )));
  }
  if upstream.origin.scheme() != "https" {
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "WebTransport forwarding requires https upstream origin",
    )));
  }

  let target_uri = rewrite_uri(
    &upstream.origin,
    resolved.route.path_prefix.as_str(),
    resolved.route.replace_prefix_with.as_deref(),
    request.uri(),
  )
  .map_err(|error| {
    warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream WebTransport URI");
    Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "invalid upstream URI rewrite",
    ))
  })?;
  let target_url = url::Url::parse(&target_uri.to_string()).map_err(|error| {
    warn!(error = %error, uri = %target_uri, "failed to convert WebTransport target URI");
    Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "invalid WebTransport target URI",
    ))
  })?;

  let mut headers = request.headers().clone();
  strip_hop_by_hop_headers(&mut headers);
  if !upstream.preserve_host {
    headers.remove(http::header::HOST);
  }
  add_forwarded_headers(
    &mut headers,
    peer_addr,
    &host,
    state.config.proxy.forwarded_headers.mode,
  );
  apply_header_mutations(&mut headers, &request_waf.request_header_mutations);

  let protocols = parse_webtransport_protocols(&headers);
  Ok(PreparedWebTransport {
    target_url,
    headers,
    protocols,
    upstream: upstream.clone(),
  })
}

fn parse_webtransport_protocols(headers: &http::HeaderMap) -> Vec<String> {
  headers
    .get("wt-available-protocols")
    .and_then(|value| value.to_str().ok())
    .map(|value| {
      value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_matches('"').to_string())
        .collect()
    })
    .unwrap_or_default()
}

fn waf_body_input(body: &CapturedBody) -> WafBodyInput<'_> {
  WafBodyInput {
    bytes: body.bytes.as_ref(),
    is_truncated: body.is_truncated,
  }
}
