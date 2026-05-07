use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::{HttpVersion, ProxyProtocolEgressMode, UpstreamConfig};
use crate::pools::PoolSelection;
use crate::state::{AppHandle, AppSnapshot, UpstreamClientRef};
use crate::waf::{
  WafBodyInput, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportNetwork, WafUpstreamError, apply_header_mutations, request_protocol,
};

pub(crate) mod body;
pub(crate) mod compression;
pub(crate) mod grpc_web;
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

struct SystemAccessLogContext {
  request_id: String,
  response_id: String,
  transaction_id: String,
  request_received_at_unix_ms: u64,
  response_received_at_unix_ms: u64,
  method: Method,
  uri: http::Uri,
  version: http::Version,
  headers: HeaderMap,
  client_addr: std::net::SocketAddr,
  downstream_host: String,
  downstream_scheme: &'static str,
  route_name: String,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  tags: std::collections::HashMap<String, String>,
  upstream_name: String,
  upstream_pool: Option<String>,
  upstream_scheme: String,
  upstream_connect_time_ms: Option<u64>,
  upstream_first_byte_time_ms: Option<u64>,
  upstream_error_code: Option<String>,
  upstream_error_message: Option<String>,
}

impl SystemAccessLogContext {
  fn new<B>(
    request: &Request<B>,
    peer_addr: std::net::SocketAddr,
    tcp_max_hop: Option<u8>,
    tls: Arc<WafTlsMetadata>,
    protocol: WafProtocol,
    transport_network: WafTransportNetwork,
    downstream_scheme: &'static str,
  ) -> Self {
    Self {
      request_id: crate::waf::new_access_log_id(),
      response_id: crate::waf::new_access_log_id(),
      transaction_id: crate::waf::new_access_log_id(),
      request_received_at_unix_ms: crate::waf::current_unix_ms(),
      response_received_at_unix_ms: 0,
      method: request.method().clone(),
      uri: request.uri().clone(),
      version: request.version(),
      headers: request.headers().clone(),
      client_addr: peer_addr,
      downstream_host: extract_host(request).unwrap_or_default(),
      downstream_scheme,
      route_name: String::new(),
      tcp_max_hop,
      tls,
      protocol,
      transport_network,
      tags: std::collections::HashMap::new(),
      upstream_name: String::new(),
      upstream_pool: None,
      upstream_scheme: String::new(),
      upstream_connect_time_ms: None,
      upstream_first_byte_time_ms: None,
      upstream_error_code: None,
      upstream_error_message: None,
    }
  }

  fn request_input(&self) -> WafRequestInput<'_> {
    WafRequestInput {
      request_id: &self.request_id,
      transaction_id: &self.transaction_id,
      received_at_unix_ms: self.request_received_at_unix_ms,
      method: &self.method,
      uri: &self.uri,
      version: self.version,
      headers: &self.headers,
      body: None,
      peer_addr: self.client_addr,
      downstream_host: &self.downstream_host,
      downstream_scheme: self.downstream_scheme,
      route_name: &self.route_name,
      tcp_max_hop: self.tcp_max_hop,
      tls: self.tls.as_ref(),
      protocol: self.protocol,
      transport_network: self.transport_network,
      tags: &self.tags,
    }
  }

  fn response_input<'a>(&'a self, response: &'a Response<ProxyBody>) -> WafResponseInput<'a> {
    let upstream_error = self
      .upstream_error_code
      .as_deref()
      .zip(self.upstream_error_message.as_deref())
      .map(|(code, message)| WafUpstreamError { code, message });
    WafResponseInput {
      request: self.request_input(),
      response_id: &self.response_id,
      received_at_unix_ms: self.response_received_at_unix_ms,
      version: response.version(),
      status: response.status(),
      headers: response.headers(),
      upstream_name: &self.upstream_name,
      upstream_pool: self.upstream_pool.as_deref(),
      upstream_scheme: &self.upstream_scheme,
      upstream_connect_time_ms: self.upstream_connect_time_ms,
      upstream_first_byte_time_ms: self.upstream_first_byte_time_ms,
      upstream_error,
    }
  }

  fn record_upstream_error(&mut self, code: &str, message: &str) {
    self.upstream_error_code = Some(code.to_string());
    self.upstream_error_message = Some(message.to_string());
  }
}

fn emit_system_access_log(
  state: &AppSnapshot,
  context: &mut SystemAccessLogContext,
  response: &Response<ProxyBody>,
) {
  if !state.system_access_log.enabled() {
    return;
  }
  if context.response_received_at_unix_ms == 0 {
    context.response_received_at_unix_ms = crate::waf::current_unix_ms();
  }
  let input = context.response_input(response);
  state.system_access_log.emit(&state.waf, input);
}

fn elapsed_ms(started_at: Instant) -> u64 {
  started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

pub async fn handle(
  request: Request<Incoming>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  state: AppHandle,
  downstream_scheme: &'static str,
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
    downstream_scheme,
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
    "https",
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
  _reject_connect: bool,
  downstream_scheme: &'static str,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + 'static,
{
  let state = state.snapshot();
  let mut access_log = SystemAccessLogContext::new(
    &request,
    peer_addr,
    tcp_max_hop,
    tls.clone(),
    protocol,
    transport_network,
    downstream_scheme,
  );
  let response = handle_inner_impl(
    request,
    peer_addr,
    tcp_max_hop,
    tls,
    state.clone(),
    protocol,
    transport_network,
    _reject_connect,
    downstream_scheme,
    &mut access_log,
  )
  .await;
  emit_system_access_log(state.as_ref(), &mut access_log, &response);
  response
}

#[allow(clippy::too_many_arguments)]
async fn handle_inner_impl<B>(
  request: Request<B>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  state: Arc<AppSnapshot>,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  _reject_connect: bool,
  downstream_scheme: &'static str,
  access_log: &mut SystemAccessLogContext,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + 'static,
{
  state.metrics.record_request();

  let host = extract_host(&request).unwrap_or_default();
  access_log.downstream_host = host.clone();
  let path = request.uri().path().to_string();
  if let Err((status, message)) = validate_request_limits(&request, &state.config.limits) {
    return text_response(status, message);
  }
  if let Err(error) = validate_downstream_path(&path) {
    warn!(error = %error, path = %path, "rejected unsafe downstream request path");
    return text_response(StatusCode::BAD_REQUEST, "invalid request path");
  }
  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let request_version = request.version();
  let request_headers = request.headers().clone();
  let mut tags = std::collections::HashMap::new();
  let client_addr = match crate::identity::resolve_client_addr(
    &request_headers,
    peer_addr,
    &state.config.proxy.real_ip,
  ) {
    Ok(addr) => addr,
    Err(error) => {
      warn!(error = %error, peer = %peer_addr, "rejected untrusted real IP metadata");
      return text_response(
        StatusCode::BAD_REQUEST,
        "untrusted forwarded client IP metadata",
      );
    }
  };
  access_log.client_addr = client_addr;

  if let Some(status) = state
    .limits
    .check_rate_limits(client_addr.ip(), &state.config.rate_limits)
  {
    return text_response(status, "rate limit exceeded");
  }

  let Some(resolved) = state.route_table.resolve(&host, &path, &state.upstreams) else {
    return text_response(StatusCode::NOT_FOUND, "no matching route");
  };
  access_log.route_name = resolved.route.name.clone();

  let request = request
    .map(|body| Limited::new(body, state.config.limits.max_request_body_bytes as usize).boxed());

  let (request, captured_body) = if request_method != Method::CONNECT
    && state
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
    (request, None)
  };
  let request_body = captured_body.as_ref().map(waf_body_input);

  let request_waf = state.waf.evaluate_request(WafRequestInput {
    request_id: &access_log.request_id,
    transaction_id: &access_log.transaction_id,
    received_at_unix_ms: access_log.request_received_at_unix_ms,
    method: &request_method,
    uri: &request_uri,
    version: request_version,
    headers: &request_headers,
    body: request_body,
    peer_addr: client_addr,
    downstream_host: &host,
    downstream_scheme,
    route_name: &resolved.route.name,
    tcp_max_hop,
    tls: tls.as_ref(),
    protocol,
    transport_network,
    tags: &tags,
  });

  for (key, value) in &request_waf.tags {
    tags.insert(key.clone(), value.clone());
  }
  access_log.tags = tags.clone();

  if let Some(terminal) = request_waf.terminal {
    return waf_terminal_response(terminal, &request_waf.response_header_mutations);
  }

  if request_method == Method::CONNECT {
    return handle_connect_request(
      request,
      &state,
      &resolved,
      client_addr,
      &host,
      &request_waf,
      request_version,
      access_log,
    )
    .await;
  }

  if is_upgrade_request(&request) {
    if let Some(response) = handle_upgrade_request(
      request,
      &state,
      &resolved,
      client_addr,
      &host,
      downstream_scheme,
      &request_waf,
      access_log,
    )
    .await
    {
      return response;
    }
    return text_response(
      StatusCode::NOT_IMPLEMENTED,
      "unsupported HTTP upgrade request",
    );
  }

  let mut pool_selection = None;
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
  } else if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    match state.pools.select(
      pool_name,
      client_addr.ip(),
      &format!("{host}{}", request.uri()),
      request_waf.load_balancing_policy.as_deref(),
    ) {
      Ok(selection) => {
        let name = selection.upstream_name.clone();
        access_log.upstream_pool = Some(selection.pool_name.clone());
        pool_selection = Some(selection);
        state
          .upstreams
          .iter()
          .find(|upstream| upstream.name == name)
          .expect("pool selected synthetic upstream")
      }
      Err(error) => {
        warn!(error = %error, pool = %pool_name, "failed to select upstream pool server");
        return text_response(StatusCode::BAD_GATEWAY, "no available upstream pool server");
      }
    }
  } else {
    resolved.upstream.expect("validated route upstream")
  };
  access_log.upstream_name = upstream.name.clone();
  access_log.upstream_scheme = upstream.origin.scheme().to_string();

  let mut upstream_version = resolved.route.upstream_http_version.unwrap_or_else(|| {
    select_upstream_http_version(
      state.config.proxy.auto_upgrade.enabled,
      state.config.proxy.auto_upgrade.max_http_version,
      upstream.max_http_version,
    )
  });
  let grpc_web_mode = if state.config.proxy.grpc_web.enabled && resolved.route.grpc_web {
    grpc_web::request_mode(&request_headers)
  } else {
    None
  };
  if grpc_web_mode.is_some() {
    if upstream.max_http_version < HttpVersion::H2 {
      return text_response(
        StatusCode::BAD_GATEWAY,
        "gRPC-Web upstream requires HTTP/2 support",
      );
    }
    upstream_version = HttpVersion::H2;
  }

  if upstream_version == HttpVersion::H3 && upstream.origin.scheme() != "https" {
    return text_response(
      StatusCode::BAD_GATEWAY,
      "upstream HTTP/3 requires https origin",
    );
  }
  if upstream_version == HttpVersion::H3
    && upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return text_response(
      StatusCode::BAD_GATEWAY,
      "PROXY protocol egress is not supported for HTTP/3 upstream",
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
    downstream_scheme,
    downstream_host: &host,
    forwarded_header_mode: state.config.proxy.forwarded_headers.mode,
    preserve_host: upstream.preserve_host,
    upstream_version,
    waf_mutations: &request_waf.request_header_mutations,
  };
  let mut outbound = rebuild_request(request, rebuild);
  if let Some(mode) = grpc_web_mode {
    grpc_web::rewrite_request_headers(outbound.headers_mut(), mode);
    let (parts, body) = outbound.into_parts();
    let body = match grpc_web::decode_request_body(body, mode).await {
      Ok(body) => body,
      Err(error) => {
        warn!(error = %error, "failed to prepare gRPC-Web upstream request");
        return text_response(StatusCode::BAD_REQUEST, "invalid gRPC-Web request body");
      }
    };
    outbound = Request::from_parts(parts, body);
  }

  let cache_enabled_for_route = resolved.route.cache.as_deref() == Some("default")
    && state.cache.enabled()
    && state.cache.is_cacheable_method(&request_method);
  if let Some(response) = cached_response(
    &state,
    resolved.route.cache.as_deref(),
    downstream_scheme,
    &host,
    &request_method,
    &request_uri,
  ) {
    state.metrics.record_cache_hit();
    return compression::maybe_compress_response(
      response,
      &request_method,
      &request_headers,
      resolved.route.compression.as_deref(),
      &state.config.compression,
      &state.compression,
    );
  }
  if cache_enabled_for_route {
    state.metrics.record_cache_miss();
  }

  debug!(
      route = %resolved.route.name,
      upstream = %upstream.name,
      method = %outbound.method(),
      uri = %outbound.uri(),
      "proxying downstream request"
  );

  let upstream_started_at = Instant::now();
  let upstream_response = if upstream_version == HttpVersion::H3 {
    match tokio::time::timeout(
      Duration::from_millis(upstream.request_timeout_ms),
      crate::proxy::http3::forward_request(outbound, upstream, state.as_ref()),
    )
    .await
    {
      Err(_) => {
        state.pools.report_failure(&upstream.name);
        warn!(upstream = %upstream.name, "upstream HTTP/3 request timed out");
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        access_log.record_upstream_error("read_timeout", "upstream request timed out");
        return upstream_error_response(
          &state,
          &resolved.route.name,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          &host,
          tcp_max_hop,
          tls.as_ref(),
          protocol,
          transport_network,
          request_body,
          &tags,
          &upstream.name,
          upstream.origin.scheme(),
          access_log.upstream_pool.as_deref(),
          access_log.upstream_connect_time_ms,
          access_log.upstream_first_byte_time_ms,
          "read_timeout",
          "upstream request timed out",
          &request_waf.response_header_mutations,
          access_log,
        );
      }
      Ok(Ok(response)) => {
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        response
      }
      Ok(Err(error)) => {
        state.pools.report_failure(&upstream.name);
        warn!(
            error = %error,
            upstream = %upstream.name,
            "upstream HTTP/3 request failed"
        );
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        access_log.record_upstream_error("connect_error", &error.to_string());
        return upstream_error_response(
          &state,
          &resolved.route.name,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          &host,
          tcp_max_hop,
          tls.as_ref(),
          protocol,
          transport_network,
          request_body,
          &tags,
          &upstream.name,
          upstream.origin.scheme(),
          access_log.upstream_pool.as_deref(),
          access_log.upstream_connect_time_ms,
          access_log.upstream_first_byte_time_ms,
          "connect_error",
          &error.to_string(),
          &request_waf.response_header_mutations,
          access_log,
        );
      }
    }
  } else {
    let result = if upstream.proxy_protocol_egress == ProxyProtocolEgressMode::Off {
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
      send_with_retry(
        client,
        outbound,
        upstream,
        &state,
        state.config.proxy.retry.enabled && is_idempotent(&request_method),
      )
      .await
    } else {
      send_one_shot_with_proxy_protocol(outbound, upstream, &state, upstream_version, client_addr)
        .await
    };
    match result {
      Ok(response) => {
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        response.map(|body| body.map_err(boxed_error).boxed())
      }
      Err(error) => {
        state.pools.report_failure(&upstream.name);
        warn!(
            error = %error,
            error_debug = ?error,
            upstream = %upstream.name,
            "upstream request failed"
        );
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        let error_message = error.to_string();
        let error_code = if error_message.contains("timed out") {
          "read_timeout"
        } else {
          "connect_error"
        };
        access_log.record_upstream_error(error_code, &error_message);
        return upstream_error_response(
          &state,
          &resolved.route.name,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          &host,
          tcp_max_hop,
          tls.as_ref(),
          protocol,
          transport_network,
          request_body,
          &tags,
          &upstream.name,
          upstream.origin.scheme(),
          access_log.upstream_pool.as_deref(),
          access_log.upstream_connect_time_ms,
          access_log.upstream_first_byte_time_ms,
          error_code,
          &error_message,
          &request_waf.response_header_mutations,
          access_log,
        );
      }
    }
  };
  state.pools.report_success(&upstream.name);
  drop(pool_selection);

  let upstream_response = if let Some(mode) = grpc_web_mode {
    grpc_web::encode_response(upstream_response, mode)
  } else {
    upstream_response
  };
  let (mut parts, body) = upstream_response.into_parts();
  strip_hop_by_hop_headers(&mut parts.headers);
  if state.config.proxy.http.trailers == crate::config::TrailerMode::Drop {
    parts.headers.remove(http::header::TRAILER);
  }
  apply_security_headers(&mut parts.headers, &state.config.security.headers);
  apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);

  if state.waf.has_response_rules(&resolved.route.name) {
    access_log.response_received_at_unix_ms = crate::waf::current_unix_ms();
    let request_input = WafRequestInput {
      request_id: &access_log.request_id,
      transaction_id: &access_log.transaction_id,
      received_at_unix_ms: access_log.request_received_at_unix_ms,
      method: &request_method,
      uri: &request_uri,
      version: request_version,
      headers: &request_headers,
      body: request_body,
      peer_addr: client_addr,
      downstream_host: &host,
      downstream_scheme,
      route_name: &resolved.route.name,
      tcp_max_hop,
      tls: tls.as_ref(),
      protocol,
      transport_network,
      tags: &tags,
    };
    let response_waf = state.waf.evaluate_response(WafResponseInput {
      request: request_input,
      response_id: &access_log.response_id,
      received_at_unix_ms: access_log.response_received_at_unix_ms,
      version: parts.version,
      status: parts.status,
      headers: &parts.headers,
      upstream_name: &upstream.name,
      upstream_pool: access_log.upstream_pool.as_deref(),
      upstream_scheme: upstream.origin.scheme(),
      upstream_connect_time_ms: access_log.upstream_connect_time_ms,
      upstream_first_byte_time_ms: access_log.upstream_first_byte_time_ms,
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
  apply_alt_svc_header(
    &mut parts.headers,
    parts.status,
    state.as_ref(),
    downstream_scheme,
    request_version,
  );

  let response = maybe_cache_response(
    Response::from_parts(parts, body),
    &state,
    resolved.route.cache.as_deref(),
    downstream_scheme,
    &host,
    &request_method,
    &request_uri,
  )
  .await;
  let response = compression::maybe_compress_response(
    response,
    &request_method,
    &request_headers,
    resolved.route.compression.as_deref(),
    &state.config.compression,
    &state.compression,
  );
  state.metrics.record_response(response.status());
  response
}

fn apply_alt_svc_header(
  headers: &mut HeaderMap,
  status: StatusCode,
  state: &AppSnapshot,
  downstream_scheme: &str,
  request_version: http::Version,
) {
  if !should_add_alt_svc(status, state, downstream_scheme, request_version) {
    return;
  }
  if let Ok(value) = HeaderValue::from_str(&alt_svc_header_value(
    state.config.listeners.https_bind.port(),
    &state.config.quic.alt_svc,
  )) {
    headers.insert(http::header::ALT_SVC, value);
  }
}

fn should_add_alt_svc(
  status: StatusCode,
  state: &AppSnapshot,
  downstream_scheme: &str,
  request_version: http::Version,
) -> bool {
  state.config.listeners.http3
    && state.config.quic.alt_svc.enabled
    && downstream_scheme == "https"
    && matches!(
      request_version,
      http::Version::HTTP_10 | http::Version::HTTP_11 | http::Version::HTTP_2
    )
    && status != StatusCode::SWITCHING_PROTOCOLS
}

fn alt_svc_header_value(https_port: u16, config: &crate::config::QuicAltSvcConfig) -> String {
  let mut value = format!("h3=\":{https_port}\"; ma={}", config.max_age_seconds);
  if config.persist {
    value.push_str("; persist=1");
  }
  value
}

struct SelectedUpstream<'a> {
  upstream: &'a UpstreamConfig,
  pool_selection: Option<PoolSelection>,
}

fn select_request_upstream<'a>(
  state: &'a AppSnapshot,
  resolved: &crate::routes::ResolvedRoute<'a>,
  client_addr: std::net::SocketAddr,
  downstream_host: &str,
  uri: &http::Uri,
  request_waf: &crate::waf::RequestWafDecision,
) -> Result<SelectedUpstream<'a>, Box<Response<ProxyBody>>> {
  if let Some(upstream_name) = request_waf.upstream_override.as_deref() {
    return state
      .upstreams
      .iter()
      .find(|upstream| upstream.name == upstream_name)
      .map(|upstream| SelectedUpstream {
        upstream,
        pool_selection: None,
      })
      .ok_or_else(|| {
        Box::new(text_response(
          StatusCode::BAD_GATEWAY,
          "WAF selected an unknown upstream",
        ))
      });
  }

  if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    let selection = state
      .pools
      .select(
        pool_name,
        client_addr.ip(),
        &format!("{downstream_host}{uri}"),
        request_waf.load_balancing_policy.as_deref(),
      )
      .map_err(|_| {
        Box::new(text_response(
          StatusCode::BAD_GATEWAY,
          "no available upstream pool server",
        ))
      })?;
    let name = selection.upstream_name.clone();
    let upstream = state
      .upstreams
      .iter()
      .find(|upstream| upstream.name == name)
      .expect("pool selected synthetic upstream");
    return Ok(SelectedUpstream {
      upstream,
      pool_selection: Some(selection),
    });
  }

  Ok(SelectedUpstream {
    upstream: resolved.upstream.expect("validated route upstream"),
    pool_selection: None,
  })
}

#[allow(clippy::too_many_arguments)]
async fn handle_connect_request(
  mut request: Request<ProxyBody>,
  state: &Arc<AppSnapshot>,
  resolved: &crate::routes::ResolvedRoute<'_>,
  client_addr: std::net::SocketAddr,
  downstream_host: &str,
  request_waf: &crate::waf::RequestWafDecision,
  request_version: http::Version,
  access_log: &mut SystemAccessLogContext,
) -> Response<ProxyBody> {
  if !state.config.proxy.upgrades.connect_tunneling || !resolved.route.connect_tunneling {
    return text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "CONNECT tunneling is disabled for this route",
    );
  }

  let selected = match select_request_upstream(
    state.as_ref(),
    resolved,
    client_addr,
    downstream_host,
    request.uri(),
    request_waf,
  ) {
    Ok(selected) => selected,
    Err(response) => return *response,
  };
  let upstream = selected.upstream.clone();
  access_log.upstream_name = upstream.name.clone();
  access_log.upstream_scheme = upstream.origin.scheme().to_string();
  access_log.upstream_pool = selected
    .pool_selection
    .as_ref()
    .map(|selection| selection.pool_name.clone());
  let pool_report = state.pools.clone();
  let pool_selection = selected.pool_selection;

  if request_version == http::Version::HTTP_11 || request_version == http::Version::HTTP_10 {
    let downstream_upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
      let result = async {
        let downstream = downstream_upgrade.await?;
        let mut downstream = TokioIo::new(downstream);
        let mut upstream_stream = dial_tunnel_upstream(&upstream, client_addr).await?;
        tokio::io::copy_bidirectional(&mut downstream, &mut upstream_stream).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
      }
      .await;
      if result.is_ok() {
        pool_report.report_success(&upstream.name);
      } else {
        pool_report.report_failure(&upstream.name);
      }
      drop(pool_selection);
    });
    return Response::builder()
      .status(StatusCode::OK)
      .body(full_body(bytes::Bytes::new()))
      .expect("CONNECT response should build");
  }

  match dial_tunnel_upstream(&upstream, client_addr).await {
    Ok(upstream_stream) => {
      let body = bridge_connect_body(request.into_body(), upstream_stream);
      drop(pool_selection);
      Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .expect("CONNECT response should build")
    }
    Err(error) => {
      pool_report.report_failure(&upstream.name);
      warn!(upstream = %upstream.name, error = %error, "failed to establish CONNECT tunnel");
      access_log.record_upstream_error("connect_error", &error.to_string());
      text_response(
        StatusCode::BAD_GATEWAY,
        "failed to establish CONNECT tunnel",
      )
    }
  }
}

fn bridge_connect_body(mut downstream_body: ProxyBody, upstream: TcpStream) -> ProxyBody {
  let (body_sender, body) = body::channel_body(16);
  let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

  tokio::spawn(async move {
    while let Some(frame) = downstream_body.frame().await {
      let frame = match frame {
        Ok(frame) => frame,
        Err(_) => break,
      };
      if let Ok(data) = frame.into_data()
        && upstream_writer.write_all(&data).await.is_err()
      {
        break;
      }
    }
    let _ = upstream_writer.shutdown().await;
  });

  tokio::spawn(async move {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
      match upstream_reader.read(&mut buffer).await {
        Ok(0) => break,
        Ok(read) => {
          if body_sender
            .send(Ok(hyper::body::Frame::data(bytes::Bytes::copy_from_slice(
              &buffer[..read],
            ))))
            .await
            .is_err()
          {
            break;
          }
        }
        Err(error) => {
          let _ = body_sender
            .send(Err(boxed_error(std::io::Error::other(format!(
              "failed to read CONNECT upstream: {error}"
            )))))
            .await;
          break;
        }
      }
    }
  });

  body
}

async fn dial_tunnel_upstream(
  upstream: &UpstreamConfig,
  client_addr: std::net::SocketAddr,
) -> anyhow::Result<TcpStream> {
  let remote_addr = resolve_upstream_tcp_addr(&upstream.origin).await?;
  let mut stream = tokio::time::timeout(
    Duration::from_millis(upstream.connect_timeout_ms),
    TcpStream::connect(remote_addr),
  )
  .await
  .context("upstream tunnel connect timed out")??;
  crate::proxy_protocol_egress::write_header(
    &mut stream,
    upstream.proxy_protocol_egress,
    client_addr,
    remote_addr,
  )
  .await
  .context("failed to write upstream PROXY protocol egress header")?;
  Ok(stream)
}

#[allow(clippy::too_many_arguments)]
async fn handle_upgrade_request(
  mut request: Request<ProxyBody>,
  state: &Arc<AppSnapshot>,
  resolved: &crate::routes::ResolvedRoute<'_>,
  client_addr: std::net::SocketAddr,
  downstream_host: &str,
  downstream_scheme: &str,
  request_waf: &crate::waf::RequestWafDecision,
  access_log: &mut SystemAccessLogContext,
) -> Option<Response<ProxyBody>> {
  if request.version() != http::Version::HTTP_11 {
    return Some(text_response(
      StatusCode::NOT_IMPLEMENTED,
      "HTTP upgrade tunneling requires HTTP/1.1 downstream",
    ));
  }

  let websocket_upgrade = is_websocket_upgrade(&request);
  let generic_upgrade = !websocket_upgrade
    && state.config.proxy.upgrades.generic_http_upgrade
    && resolved.route.generic_http_upgrade;
  if websocket_upgrade && !state.config.proxy.upgrades.websocket {
    return None;
  }
  if !websocket_upgrade && !generic_upgrade {
    return None;
  }

  let mut pool_selection = None;
  let upstream = if let Some(upstream_name) = request_waf.upstream_override.as_deref() {
    match state
      .upstreams
      .iter()
      .find(|upstream| upstream.name == upstream_name)
    {
      Some(upstream) => upstream,
      None => {
        return Some(text_response(
          StatusCode::BAD_GATEWAY,
          "WAF selected an unknown upstream",
        ));
      }
    }
  } else if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    match state.pools.select(
      pool_name,
      client_addr.ip(),
      &format!("{downstream_host}{}", request.uri()),
      request_waf.load_balancing_policy.as_deref(),
    ) {
      Ok(selection) => {
        let name = selection.upstream_name.clone();
        access_log.upstream_pool = Some(selection.pool_name.clone());
        pool_selection = Some(selection);
        state
          .upstreams
          .iter()
          .find(|upstream| upstream.name == name)
          .expect("pool selected synthetic upstream")
      }
      Err(_) => {
        return Some(text_response(
          StatusCode::BAD_GATEWAY,
          "no available upstream pool server",
        ));
      }
    }
  } else {
    resolved.upstream.expect("validated route upstream")
  };
  access_log.upstream_name = upstream.name.clone();
  access_log.upstream_scheme = upstream.origin.scheme().to_string();

  if websocket_upgrade && !upstream.websocket {
    return Some(text_response(
      StatusCode::BAD_GATEWAY,
      "selected upstream does not allow WebSocket",
    ));
  }
  let target_uri = match rewrite_uri(
    &upstream.origin,
    resolved.route.path_prefix.as_str(),
    resolved.route.replace_prefix_with.as_deref(),
    request.uri(),
  ) {
    Ok(uri) => uri,
    Err(_) => {
      return Some(text_response(
        StatusCode::BAD_REQUEST,
        "invalid upstream URI rewrite",
      ));
    }
  };
  let downstream_upgrade = hyper::upgrade::on(&mut request);
  let (mut parts, body) = request.into_parts();
  parts.uri = target_uri;
  parts.version = http::Version::HTTP_11;
  if !upstream.preserve_host {
    parts.headers.remove(http::header::HOST);
  }
  add_forwarded_headers(
    &mut parts.headers,
    client_addr,
    downstream_host,
    downstream_scheme,
    state.config.proxy.forwarded_headers.mode,
  );
  apply_header_mutations(&mut parts.headers, &request_waf.request_header_mutations);
  let outbound = Request::from_parts(parts, body);
  let Some(client) =
    state
      .clients
      .for_upstream_version(&upstream.name, upstream.origin.scheme(), HttpVersion::H1)
  else {
    return Some(text_response(
      StatusCode::BAD_GATEWAY,
      "upstream client is not configured",
    ));
  };
  let upstream_started_at = Instant::now();
  let mut upstream_response = match tokio::time::timeout(
    Duration::from_millis(upstream.request_timeout_ms),
    client.request(outbound),
  )
  .await
  {
    Ok(Ok(response)) => {
      access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
      response
    }
    Ok(Err(error)) => {
      state.pools.report_failure(&upstream.name);
      access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
      access_log.record_upstream_error("connect_error", &error.to_string());
      return Some(text_response(
        StatusCode::BAD_GATEWAY,
        &format!("upstream upgrade request failed: {error}"),
      ));
    }
    Err(_) => {
      state.pools.report_failure(&upstream.name);
      access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
      access_log.record_upstream_error("read_timeout", "upstream upgrade request timed out");
      return Some(text_response(
        StatusCode::BAD_GATEWAY,
        "upstream upgrade request timed out",
      ));
    }
  };

  if upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS {
    let response = upstream_response.map(|body| body.map_err(boxed_error).boxed());
    return Some(response);
  }
  let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
  let pool_report = state.pools.clone();
  let upstream_name = upstream.name.clone();
  tokio::spawn(async move {
    let result = async {
      let downstream = downstream_upgrade.await?;
      let upstream = upstream_upgrade.await?;
      let mut downstream = TokioIo::new(downstream);
      let mut upstream = TokioIo::new(upstream);
      tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await?;
      Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    if result.is_ok() {
      pool_report.report_success(&upstream_name);
    } else {
      pool_report.report_failure(&upstream_name);
    }
  });
  drop(pool_selection);
  Some(upstream_response.map(|body| body.map_err(boxed_error).boxed()))
}

fn is_websocket_upgrade<B>(request: &Request<B>) -> bool {
  request
    .headers()
    .get(http::header::UPGRADE)
    .and_then(|value| value.to_str().ok())
    .map(|value| value.eq_ignore_ascii_case("websocket"))
    .unwrap_or(false)
}

async fn send_with_retry(
  client: UpstreamClientRef<'_>,
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  retry_enabled: bool,
) -> anyhow::Result<Response<Incoming>> {
  if retry_enabled
    && request
      .body()
      .size_hint()
      .upper()
      .is_some_and(|upper| upper <= state.config.proxy.buffering.max_memory_body_bytes as u64)
  {
    let (parts, body) = request.into_parts();
    let body = body
      .collect()
      .await
      .map_err(|error| anyhow::anyhow!("failed to buffer retryable request body: {error}"))?
      .to_bytes();
    let tries = state.config.proxy.retry.tries.max(1);
    let mut last_error = None;
    for _ in 0..tries {
      let outbound = Request::from_parts(parts_clone(&parts), full_body(body.clone()));
      match tokio::time::timeout(
        Duration::from_millis(upstream.request_timeout_ms),
        client.request(outbound),
      )
      .await
      {
        Ok(Ok(response)) if retryable_status(response.status(), state) => {
          last_error = Some(anyhow::anyhow!(
            "upstream returned retryable status {}",
            response.status()
          ));
        }
        Ok(Ok(response)) => return Ok(response),
        Ok(Err(error)) => last_error = Some(error.into()),
        Err(_) => {
          last_error = Some(anyhow::anyhow!(
            "upstream request timed out after {}ms",
            upstream.request_timeout_ms
          ));
        }
      }
    }
    return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("upstream retry failed")));
  }
  match tokio::time::timeout(
    Duration::from_millis(upstream.request_timeout_ms),
    client.request(request),
  )
  .await
  {
    Ok(result) => Ok(result?),
    Err(_) => anyhow::bail!(
      "upstream request timed out after {}ms",
      upstream.request_timeout_ms
    ),
  }
}

async fn send_one_shot_with_proxy_protocol(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  upstream_version: HttpVersion,
  client_addr: std::net::SocketAddr,
) -> anyhow::Result<Response<Incoming>> {
  if upstream_version == HttpVersion::H3 {
    anyhow::bail!("PROXY protocol egress is not supported for HTTP/3 upstream");
  }
  let remote_addr = resolve_upstream_tcp_addr(&upstream.origin).await?;
  let mut stream = tokio::time::timeout(
    Duration::from_millis(upstream.connect_timeout_ms),
    TcpStream::connect(remote_addr),
  )
  .await
  .context("upstream connect timed out")??;
  crate::proxy_protocol_egress::write_header(
    &mut stream,
    upstream.proxy_protocol_egress,
    client_addr,
    remote_addr,
  )
  .await
  .context("failed to write upstream PROXY protocol egress header")?;

  if upstream.origin.scheme() == "https" {
    let mut tls_config = crate::tls::build_upstream_client_config(
      &state.config.proxy.trusted_ca_certs,
      &upstream.tls.ech,
    )
    .context("failed to build one-shot upstream TLS config")?;
    tls_config.alpn_protocols = vec![upstream_version.as_alpn().to_vec()];
    let host = upstream
      .origin
      .host_str()
      .ok_or_else(|| anyhow::anyhow!("upstream origin has no host: {}", upstream.origin))?
      .to_string();
    let server_name = rustls::pki_types::ServerName::try_from(host)
      .map_err(|error| anyhow::anyhow!("invalid upstream TLS server name: {error}"))?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls_config))
      .connect(server_name, stream)
      .await
      .context("upstream TLS handshake failed")?;
    send_one_shot_over_io(tls, request, upstream_version).await
  } else {
    send_one_shot_over_io(stream, request, upstream_version).await
  }
}

async fn send_one_shot_over_io<I>(
  io: I,
  request: Request<ProxyBody>,
  upstream_version: HttpVersion,
) -> anyhow::Result<Response<Incoming>>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  match upstream_version {
    HttpVersion::H1 => {
      let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .context("failed to establish one-shot HTTP/1.1 upstream connection")?;
      tokio::spawn(async move {
        if let Err(error) = connection.await {
          warn!(error = %error, "one-shot HTTP/1.1 upstream connection failed");
        }
      });
      sender
        .send_request(request)
        .await
        .context("one-shot HTTP/1.1 upstream request failed")
    }
    HttpVersion::H2 => {
      let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
          .await
          .context("failed to establish one-shot HTTP/2 upstream connection")?;
      tokio::spawn(async move {
        if let Err(error) = connection.await {
          warn!(error = %error, "one-shot HTTP/2 upstream connection failed");
        }
      });
      sender
        .send_request(request)
        .await
        .context("one-shot HTTP/2 upstream request failed")
    }
    HttpVersion::H3 => anyhow::bail!("one-shot HTTP/3 upstream is not supported"),
  }
}

async fn resolve_upstream_tcp_addr(origin: &url::Url) -> anyhow::Result<std::net::SocketAddr> {
  let port = origin
    .port_or_known_default()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no port: {origin}"))?;
  let host = origin
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no host: {origin}"))?;
  tokio::net::lookup_host((host, port))
    .await
    .with_context(|| format!("failed to resolve upstream host {host}:{port}"))?
    .next()
    .ok_or_else(|| anyhow::anyhow!("upstream host resolved no addresses: {host}:{port}"))
}

fn parts_clone(parts: &http::request::Parts) -> http::request::Parts {
  let mut builder = Request::builder()
    .method(parts.method.clone())
    .uri(parts.uri.clone())
    .version(parts.version);
  *builder.headers_mut().expect("request builder headers") = parts.headers.clone();
  builder
    .body(())
    .expect("request parts clone builds")
    .into_parts()
    .0
}

fn retryable_status(status: StatusCode, state: &AppSnapshot) -> bool {
  state.config.proxy.retry.on.iter().any(|condition| {
    matches!(
      (condition, status.as_u16()),
      (crate::config::RetryCondition::Status502, 502)
        | (crate::config::RetryCondition::Status503, 503)
        | (crate::config::RetryCondition::Status504, 504)
    )
  })
}

fn is_idempotent(method: &Method) -> bool {
  matches!(
    *method,
    Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
  )
}

fn validate_request_limits<B>(
  request: &Request<B>,
  limits: &crate::config::LimitsConfig,
) -> Result<(), (StatusCode, &'static str)> {
  if request.uri().to_string().len() > limits.max_uri_bytes {
    return Err((StatusCode::URI_TOO_LONG, "request URI is too large"));
  }
  if request.headers().len() > limits.max_headers {
    return Err((
      StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
      "too many headers",
    ));
  }
  let mut total = 0usize;
  for (name, value) in request.headers() {
    if name.as_str().len() > limits.max_header_name_bytes {
      return Err((
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "header name is too large",
      ));
    }
    if value.as_bytes().len() > limits.max_header_value_bytes {
      return Err((
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "header value is too large",
      ));
    }
    total += name.as_str().len() + value.as_bytes().len();
  }
  if total > limits.max_total_header_bytes {
    return Err((
      StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
      "headers are too large",
    ));
  }
  if let Some(length) = request
    .headers()
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok())
    && length > limits.max_request_body_bytes
  {
    return Err((StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"));
  }
  Ok(())
}

fn apply_security_headers(
  headers: &mut http::HeaderMap,
  config: &crate::config::SecurityHeadersConfig,
) {
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

fn cached_response(
  state: &AppSnapshot,
  route_cache: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
) -> Option<Response<ProxyBody>> {
  if route_cache != Some("default")
    || !state.cache.enabled()
    || !state.cache.is_cacheable_method(method)
  {
    return None;
  }
  let key = state.cache.key(scheme, host, uri);
  state.cache.get(&key).map(|entry| {
    let mut response = Response::new(full_body(entry.body));
    *response.status_mut() = entry.status;
    *response.headers_mut() = entry.headers;
    response
  })
}

async fn maybe_cache_response(
  response: Response<ProxyBody>,
  state: &AppSnapshot,
  route_cache: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
) -> Response<ProxyBody> {
  if route_cache != Some("default")
    || !state.cache.enabled()
    || !state.cache.is_cacheable_method(method)
  {
    return response;
  }
  let (parts, body) = response.into_parts();
  if body
    .size_hint()
    .upper()
    .is_none_or(|upper| upper as usize > state.config.proxy.buffering.max_memory_body_bytes)
  {
    return Response::from_parts(parts, body);
  }
  match body.collect().await {
    Ok(collected) => {
      let bytes = collected.to_bytes();
      let key = state.cache.key(scheme, host, uri);
      state.cache.insert(
        key,
        crate::cache::CacheEntry {
          status: parts.status,
          headers: parts.headers.clone(),
          body: bytes.clone(),
        },
      );
      Response::from_parts(parts, full_body(bytes))
    }
    Err(error) => text_response(
      StatusCode::BAD_GATEWAY,
      &format!("failed to read upstream response body: {error}"),
    ),
  }
}

fn full_body(bytes: bytes::Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> self::body::BoxError { match never {} })
    .boxed()
}

pub(crate) struct PreparedWebTransport {
  pub(crate) target_url: url::Url,
  pub(crate) headers: http::HeaderMap,
  pub(crate) protocols: Vec<String>,
  pub(crate) upstream: UpstreamConfig,
  _pool_selection: Option<PoolSelection>,
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
    request_id: "",
    transaction_id: "",
    received_at_unix_ms: crate::waf::current_unix_ms(),
    method: &request_method,
    uri: &request_uri,
    version: http::Version::HTTP_3,
    headers: &request_headers,
    body: None,
    peer_addr,
    downstream_host: &host,
    downstream_scheme: "https",
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

  let mut pool_selection = None;
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
  } else if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    match state.pools.select(
      pool_name,
      peer_addr.ip(),
      &format!("{host}{}", request.uri()),
      request_waf.load_balancing_policy.as_deref(),
    ) {
      Ok(selection) => {
        let name = selection.upstream_name.clone();
        pool_selection = Some(selection);
        state
          .upstreams
          .iter()
          .find(|upstream| upstream.name == name)
          .expect("pool selected synthetic upstream")
      }
      Err(error) => {
        warn!(error = %error, pool = %pool_name, "failed to select upstream pool server");
        return Err(Box::new(text_response(
          StatusCode::BAD_GATEWAY,
          "no available upstream pool server",
        )));
      }
    }
  } else {
    resolved.upstream.expect("validated route upstream")
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
    "https",
    state.config.proxy.forwarded_headers.mode,
  );
  apply_header_mutations(&mut headers, &request_waf.request_header_mutations);

  let protocols = parse_webtransport_protocols(&headers);
  Ok(PreparedWebTransport {
    target_url,
    headers,
    protocols,
    upstream: upstream.clone(),
    _pool_selection: pool_selection,
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

#[cfg(test)]
mod tests {
  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  use http::header::HOST;
  use pretty_assertions::assert_eq;

  use super::*;
  use crate::config::Config;

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  fn webtransport_request() -> Request<()> {
    Request::builder()
      .method(Method::CONNECT)
      .version(http::Version::HTTP_3)
      .uri("https://example.com/session?token=1")
      .header(HOST, "example.com")
      .header("wt-available-protocols", "\"chat\", data")
      .body(())
      .expect("request should build")
  }

  #[test]
  fn alt_svc_header_value_formats_persist() {
    let config = crate::config::QuicAltSvcConfig {
      enabled: true,
      max_age_seconds: 60,
      persist: true,
    };

    assert_eq!(
      alt_svc_header_value(8443, &config),
      "h3=\":8443\"; ma=60; persist=1"
    );
  }

  #[tokio::test]
  async fn alt_svc_applies_only_to_https_h1_h2_non_switching_responses() {
    let temp_dir = common::TempDir::new("alt-svc-helper");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "alt-svc-helper");
    let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
      "http3 = false",
      "http3 = true\n\n[quic.alt_svc]\nenabled = true\nmax_age_seconds = 120\npersist = false",
    );
    let state = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");

    assert!(should_add_alt_svc(
      StatusCode::OK,
      &state,
      "https",
      http::Version::HTTP_2
    ));
    assert!(!should_add_alt_svc(
      StatusCode::OK,
      &state,
      "https",
      http::Version::HTTP_3
    ));
    assert!(!should_add_alt_svc(
      StatusCode::OK,
      &state,
      "http",
      http::Version::HTTP_2
    ));
    assert!(!should_add_alt_svc(
      StatusCode::SWITCHING_PROTOCOLS,
      &state,
      "https",
      http::Version::HTTP_11
    ));
  }

  #[tokio::test]
  async fn prepare_webtransport_selects_direct_upstream() {
    let temp_dir = common::TempDir::new("direct-webtransport");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "direct-webtransport");
    let raw = format!(
      r#"
[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = true

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[proxy.auto_upgrade]
enabled = true
max_http_version = "h3"

[[upstreams]]
name = "app"
origin = "https://app.example/origin"
max_http_version = "h3"
webtransport = true

[[routes]]
name = "direct-route"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
"#,
      cert = cert_path.display(),
      key = key_path.display(),
    );
    let state = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");

    let prepared = prepare_webtransport(
      &webtransport_request(),
      "203.0.113.10:45678".parse().unwrap(),
      &WafTlsMetadata::default(),
      &state,
    )
    .expect("direct WebTransport route should prepare");

    assert_eq!(prepared.upstream.name, "app");
    assert_eq!(
      prepared.target_url.as_str(),
      "https://app.example/origin/session?token=1"
    );
    assert_eq!(prepared.protocols, vec!["chat", "data"]);
  }

  #[tokio::test]
  async fn prepare_webtransport_pool_route_returns_bad_gateway_without_panicking() {
    let temp_dir = common::TempDir::new("pool-webtransport");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "pool-webtransport");
    let raw = format!(
      r#"
[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = true

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[[upstream_pools]]
name = "app-pool"
algorithm = "round_robin"

[[upstream_pools.servers]]
origin = "https://app-a.example/origin"

[[routes]]
name = "pool-route"
hosts = ["example.com"]
path_prefix = "/"
upstream_pool = "app-pool"
"#,
      cert = cert_path.display(),
      key = key_path.display(),
    );
    let state = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");

    let response = match prepare_webtransport(
      &webtransport_request(),
      "203.0.113.10:45678".parse().unwrap(),
      &WafTlsMetadata::default(),
      &state,
    ) {
      Ok(_) => panic!("pool route should be rejected with a response, not panic"),
      Err(response) => response,
    };

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
  }
}
