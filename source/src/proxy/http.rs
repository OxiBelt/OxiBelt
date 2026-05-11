use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::config::{
  Config, ConnectionLimitIdentityMode, HttpVersion, ProxyProtocolEgressMode, RouteConfig,
  UpstreamConfig,
};
use crate::dynamic_policy::{DynamicPolicyContext, DynamicPolicyRequest};
use crate::lifecycle::ConnectionDrain;
use crate::limits::{ConnectionLimitContext, ConnectionPermit, RateLimitContext};
use crate::pools::PoolSelection;
use crate::proxy::stream_waf::{StreamWafRequestContext, StreamWafRequestSeed};
use crate::state::{AppHandle, AppSnapshot, UpstreamClientRef};
use crate::waf::{
  WafBodyInput, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportNetwork, WafUpstreamError, apply_header_mutations, request_protocol,
};

pub(crate) mod body;
pub(crate) mod buffering;
pub(crate) mod compression;
pub(crate) mod grpc_web;
pub(crate) mod headers;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod semantics;
pub(crate) mod uri;
pub(crate) mod version;

pub(crate) mod warm;
pub(crate) use warm::warm_cache_request;

use self::body::{
  BodyTimeoutKind, CapturedBody, ProxyBody, boxed_error, capture_body_prefix, capture_prefix,
  error_is_timeout,
};
use self::headers::{
  add_forwarded_headers, extract_host, is_upgrade_request, strip_hop_by_hop_headers,
};
use self::request::{RebuildRequestOptions, rebuild_request};
use self::response::{text_response, upstream_error_response, waf_terminal_response};
use self::semantics::{configured_error_response, filter_trailers};
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
  dynamic_policy: DynamicPolicyContext,
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
      dynamic_policy: DynamicPolicyContext::default(),
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
      dynamic_policy: &self.dynamic_policy,
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
      body: None,
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

fn proxy_error_response(
  state: &AppSnapshot,
  access_log: &SystemAccessLogContext,
  status: StatusCode,
  message: &str,
  code: &str,
) -> Response<ProxyBody> {
  configured_error_response(&state.config, &access_log.request_id, status, message, code)
}

fn elapsed_ms(started_at: Instant) -> u64 {
  started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Copy)]
pub(crate) struct EffectiveTimeouts {
  pub(crate) response_send: Duration,
  pub(crate) websocket_idle: Duration,
  pub(crate) webtransport_idle: Duration,
  pub(crate) upstream_connect: Duration,
  pub(crate) upstream_first_byte: Duration,
  pub(crate) upstream_read: Duration,
  pub(crate) upstream_send: Duration,
}

impl EffectiveTimeouts {
  pub(crate) fn new(config: &Config, route: &RouteConfig, upstream: &UpstreamConfig) -> Self {
    let timeouts = &route.timeouts;
    let upstream_request_ms = timeouts
      .upstream_request_timeout_ms
      .unwrap_or(upstream.request_timeout_ms);
    let upstream_first_byte_ms = timeouts
      .upstream_first_byte_timeout_ms
      .unwrap_or(upstream.first_byte_timeout_ms)
      .min(upstream_request_ms);
    Self {
      response_send: Duration::from_millis(
        timeouts
          .response_send_timeout_ms
          .unwrap_or(config.limits.response_send_timeout_ms),
      ),
      websocket_idle: Duration::from_millis(
        timeouts
          .websocket_idle_timeout_ms
          .unwrap_or(config.limits.websocket_idle_timeout_ms),
      ),
      webtransport_idle: Duration::from_millis(
        timeouts
          .webtransport_idle_timeout_ms
          .unwrap_or(config.limits.webtransport_idle_timeout_ms),
      ),
      upstream_connect: Duration::from_millis(
        timeouts
          .upstream_connect_timeout_ms
          .unwrap_or(upstream.connect_timeout_ms),
      ),
      upstream_first_byte: Duration::from_millis(upstream_first_byte_ms),
      upstream_read: Duration::from_millis(
        timeouts
          .upstream_read_timeout_ms
          .unwrap_or(upstream.read_timeout_ms),
      ),
      upstream_send: Duration::from_millis(
        timeouts
          .upstream_send_timeout_ms
          .unwrap_or(upstream.send_timeout_ms),
      ),
    }
  }

  fn route_body_only(config: &Config, route: &RouteConfig) -> Duration {
    Duration::from_millis(
      route
        .timeouts
        .client_body_timeout_ms
        .unwrap_or(config.limits.client_body_timeout_ms),
    )
  }
}

#[derive(Clone, Copy)]
pub(crate) struct DownstreamResponseSendTimeout(pub(crate) Duration);

pub(crate) fn downstream_response_send_timeout(response: &Response<ProxyBody>) -> Option<Duration> {
  response
    .extensions()
    .get::<DownstreamResponseSendTimeout>()
    .map(|timeout| timeout.0)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
  request: Request<Incoming>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: AppHandle,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
) -> Response<ProxyBody> {
  let protocol = request_protocol(request.headers());
  handle_inner(
    request,
    peer_addr,
    tcp_max_hop,
    tls,
    connection_limit_context,
    state,
    protocol,
    WafTransportNetwork::Tcp,
    true,
    downstream_scheme,
    drain,
  )
  .await
}

pub(crate) async fn handle_http3(
  request: Request<ProxyBody>,
  peer_addr: std::net::SocketAddr,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: AppHandle,
  drain: ConnectionDrain,
) -> Response<ProxyBody> {
  handle_inner(
    request,
    peer_addr,
    None,
    tls,
    connection_limit_context,
    state,
    WafProtocol::Http,
    WafTransportNetwork::Udp,
    false,
    "https",
    drain,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_inner<B>(
  request: Request<B>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: AppHandle,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  _reject_connect: bool,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
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
  let mut request_connection_permit = None;
  let response = handle_inner_impl(
    request,
    peer_addr,
    tcp_max_hop,
    tls,
    connection_limit_context,
    state.clone(),
    protocol,
    transport_network,
    _reject_connect,
    downstream_scheme,
    drain,
    &mut access_log,
    &mut request_connection_permit,
  )
  .await;
  let response = if let Some(permit) = request_connection_permit {
    with_connection_permit(response, permit)
  } else {
    response
  };
  emit_system_access_log(state.as_ref(), &mut access_log, &response);
  response
}

#[allow(clippy::too_many_arguments)]
async fn handle_inner_impl<B>(
  request: Request<B>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  _reject_connect: bool,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
  access_log: &mut SystemAccessLogContext,
  request_connection_permit: &mut Option<ConnectionPermit>,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + 'static,
{
  state.metrics.record_request();

  if state.lifecycle.is_draining() {
    return draining_response();
  }

  if let Err(rejection) =
    semantics::validate_expect(request.headers(), state.config.proxy.http.expect_continue)
  {
    return proxy_error_response(
      &state,
      access_log,
      StatusCode::EXPECTATION_FAILED,
      rejection.message(),
      "expect_rejected",
    );
  }

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

  match state.config.limits.connection_limit_identity {
    ConnectionLimitIdentityMode::ProxyProtocol => {}
    ConnectionLimitIdentityMode::FirstRequestRealIp => {
      let acquire = || {
        state.limits.acquire_ip_connection(
          client_addr.ip(),
          &state.config.limits,
          &state.config.connection_limits,
        )
      };
      let result = if let Some(context) = connection_limit_context.as_ref() {
        context.bind_first_request(acquire)
      } else {
        acquire().map(|permit| {
          *request_connection_permit = Some(permit);
        })
      };
      if let Err(status) = result {
        return text_response(status, "connection limit exceeded");
      }
    }
    ConnectionLimitIdentityMode::PerRequestRealIp => {
      match state.limits.acquire_ip_connection(
        client_addr.ip(),
        &state.config.limits,
        &state.config.connection_limits,
      ) {
        Ok(permit) => *request_connection_permit = Some(permit),
        Err(status) => return text_response(status, "connection limit exceeded"),
      }
    }
  }

  if let Some(status) = state
    .limits
    .check_pre_route_rate_limits(client_addr.ip(), &state.config.rate_limits)
  {
    return text_response(status, "rate limit exceeded");
  }

  let Some(resolved) = state.route_table.resolve(&host, &path, &state.upstreams) else {
    return text_response(StatusCode::NOT_FOUND, "no matching route");
  };
  access_log.route_name = resolved.route.name.clone();
  let effective_buffering = buffering::EffectiveBuffering::new(&state.config, resolved.route);

  let rate_limit_context = RateLimitContext::route(
    client_addr.ip(),
    &resolved.route.name,
    request_uri.path(),
    &request_headers,
  );
  if let Some(status) = state
    .limits
    .check_route_rate_limits(rate_limit_context, &state.config.rate_limits)
  {
    return text_response(status, "rate limit exceeded");
  }

  let dynamic_policy = state.dynamic_policy.evaluate(
    DynamicPolicyRequest {
      client_ip: client_addr.ip(),
      route_name: &resolved.route.name,
      method: &request_method,
      path: request_uri.path(),
    },
    &state.limits,
  );
  access_log.dynamic_policy = dynamic_policy.context;
  if let Some(terminal) = dynamic_policy.terminal {
    return text_response(terminal.status, &terminal.body);
  }

  let client_body_timeout = EffectiveTimeouts::route_body_only(&state.config, resolved.route);
  let request = request.map(|body| {
    body::with_read_timeout(
      Limited::new(body, state.config.limits.max_request_body_bytes as usize).boxed(),
      client_body_timeout,
      BodyTimeoutKind::DownstreamRequestRead,
    )
  });

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
        if error_is_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
          return text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out");
        }
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
    dynamic_policy: &access_log.dynamic_policy,
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
      connection_limit_context.as_ref(),
      request_connection_permit,
      drain,
      access_log,
    )
    .await;
  }

  if is_upgrade_request(&request) {
    let stream_waf = StreamWafRequestContext::from_seed(
      state.as_ref(),
      StreamWafRequestSeed {
        request_id: access_log.request_id.clone(),
        transaction_id: access_log.transaction_id.clone(),
        received_at_unix_ms: access_log.request_received_at_unix_ms,
        method: request_method.clone(),
        uri: request_uri.clone(),
        version: request_version,
        headers: request_headers.clone(),
        peer_addr: client_addr,
        downstream_host: host.clone(),
        downstream_scheme,
        route_name: resolved.route.name.clone(),
        tcp_max_hop,
        tls: tls.clone(),
        protocol,
        transport_network,
        tags: tags.clone(),
        dynamic_policy: access_log.dynamic_policy.clone(),
      },
    );
    if let Some(response) = handle_upgrade_request(
      request,
      &state,
      &resolved,
      client_addr,
      &host,
      downstream_scheme,
      &request_waf,
      stream_waf,
      connection_limit_context.as_ref(),
      request_connection_permit,
      drain,
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
  let native_grpc_request = semantics::is_native_grpc_request(&request_headers, &state.config);
  let mut timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
  let mut grpc_timeout_caps = semantics::GrpcTimeoutCaps::default();
  if native_grpc_request {
    (timeouts, grpc_timeout_caps) = semantics::cap_timeouts_for_grpc(
      timeouts,
      &request_headers,
      state.config.proxy.http.grpc.respect_grpc_timeout,
    );
  }

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

  let request = match buffer_request_body(request, &effective_buffering).await {
    Ok(request) => request,
    Err(error) => return request_buffering_error_response(error),
  };

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
  semantics::strip_accepted_expect(outbound.headers_mut());
  semantics::apply_priority_policy(outbound.headers_mut(), state.config.proxy.http.priority);
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
  let outbound = outbound
    .map(|body| filter_trailers(body, state.config.proxy.http.trailers, native_grpc_request));
  let mut outbound = outbound.map(|body| {
    body::with_send_timeout(
      body,
      timeouts.upstream_send,
      BodyTimeoutKind::UpstreamRequestSend,
    )
  });

  let cache_enabled_for_route = state
    .cache
    .policy_enabled(resolved.route.cache.as_deref(), &request_method);
  let mut revalidation_entry = None;
  let mut stale_on_error = None;
  let mut _cache_fill_guard = None;
  if let Some(lookup) = state.cache.lookup(crate::cache::CacheLookupContext {
    policy_name: resolved.route.cache.as_deref(),
    scheme: downstream_scheme,
    host: &host,
    method: &request_method,
    uri: &request_uri,
    request_headers: &request_headers,
  }) {
    match lookup {
      crate::cache::CacheLookup::Fresh(entry) => {
        state.metrics.record_cache_hit();
        let response = cached_entry_response(entry, &request_method, &request_headers);
        let response = compression::maybe_compress_response(
          response,
          &request_method,
          &request_headers,
          resolved.route.compression.as_deref(),
          &state.config.compression,
          &state.compression,
        );
        return with_downstream_response_timeout(response, timeouts.response_send);
      }
      crate::cache::CacheLookup::Stale(stale) => {
        if stale.background_refresh
          && can_background_refresh(&state, &resolved.route.name, upstream, upstream_version)
          && spawn_background_refresh(
            state.clone(),
            &outbound,
            upstream,
            upstream_version,
            timeouts,
            resolved.route.cache.as_deref(),
            downstream_scheme,
            host.clone(),
            request_method.clone(),
            request_uri.clone(),
            request_headers.clone(),
            request_version,
            stale.clone(),
          )
        {
          state.metrics.record_cache_stale();
          let response = cached_entry_response(stale.entry, &request_method, &request_headers);
          let response = compression::maybe_compress_response(
            response,
            &request_method,
            &request_headers,
            resolved.route.compression.as_deref(),
            &state.config.compression,
            &state.compression,
          );
          return with_downstream_response_timeout(response, timeouts.response_send);
        }
        if !stale.request_headers.is_empty() {
          state.metrics.record_cache_revalidation();
          for (name, value) in &stale.request_headers {
            outbound.headers_mut().insert(name.clone(), value.clone());
          }
          if stale.serve_stale_on_error {
            stale_on_error = Some(stale.entry.clone());
          }
          revalidation_entry = Some(stale.entry);
        } else {
          state.metrics.record_cache_hit();
          let response = cached_entry_response(stale.entry, &request_method, &request_headers);
          let response = compression::maybe_compress_response(
            response,
            &request_method,
            &request_headers,
            resolved.route.compression.as_deref(),
            &state.config.compression,
            &state.compression,
          );
          return with_downstream_response_timeout(response, timeouts.response_send);
        }
      }
      crate::cache::CacheLookup::Revalidate(revalidation) => {
        state.metrics.record_cache_revalidation();
        for (name, value) in &revalidation.request_headers {
          outbound.headers_mut().insert(name.clone(), value.clone());
        }
        if revalidation.serve_stale_on_error {
          stale_on_error = Some(revalidation.entry.clone());
        }
        revalidation_entry = Some(revalidation.entry);
      }
    }
  } else if cache_enabled_for_route {
    state.metrics.record_cache_miss();
  }

  if cache_enabled_for_route {
    loop {
      let Some(permit) = state.cache.begin_fill(crate::cache::CacheLookupContext {
        policy_name: resolved.route.cache.as_deref(),
        scheme: downstream_scheme,
        host: &host,
        method: &request_method,
        uri: &request_uri,
        request_headers: &request_headers,
      }) else {
        break;
      };
      match permit {
        crate::cache::CacheFillPermit::Leader(guard) => {
          _cache_fill_guard = Some(guard);
          if let Some(lookup) = state.cache.lookup(crate::cache::CacheLookupContext {
            policy_name: resolved.route.cache.as_deref(),
            scheme: downstream_scheme,
            host: &host,
            method: &request_method,
            uri: &request_uri,
            request_headers: &request_headers,
          }) {
            match lookup {
              crate::cache::CacheLookup::Fresh(entry) => {
                state.metrics.record_cache_hit();
                let response = cached_entry_response(entry, &request_method, &request_headers);
                let response = compression::maybe_compress_response(
                  response,
                  &request_method,
                  &request_headers,
                  resolved.route.compression.as_deref(),
                  &state.config.compression,
                  &state.compression,
                );
                return with_downstream_response_timeout(response, timeouts.response_send);
              }
              crate::cache::CacheLookup::Stale(stale) => {
                if stale.background_refresh
                  && can_background_refresh(
                    &state,
                    &resolved.route.name,
                    upstream,
                    upstream_version,
                  )
                  && spawn_background_refresh(
                    state.clone(),
                    &outbound,
                    upstream,
                    upstream_version,
                    timeouts,
                    resolved.route.cache.as_deref(),
                    downstream_scheme,
                    host.clone(),
                    request_method.clone(),
                    request_uri.clone(),
                    request_headers.clone(),
                    request_version,
                    stale.clone(),
                  )
                {
                  state.metrics.record_cache_stale();
                  let response =
                    cached_entry_response(stale.entry, &request_method, &request_headers);
                  let response = compression::maybe_compress_response(
                    response,
                    &request_method,
                    &request_headers,
                    resolved.route.compression.as_deref(),
                    &state.config.compression,
                    &state.compression,
                  );
                  return with_downstream_response_timeout(response, timeouts.response_send);
                }
                if !stale.request_headers.is_empty() {
                  state.metrics.record_cache_revalidation();
                  for (name, value) in &stale.request_headers {
                    outbound.headers_mut().insert(name.clone(), value.clone());
                  }
                  if stale.serve_stale_on_error {
                    stale_on_error = Some(stale.entry.clone());
                  }
                  revalidation_entry = Some(stale.entry);
                } else {
                  state.metrics.record_cache_hit();
                  let response =
                    cached_entry_response(stale.entry, &request_method, &request_headers);
                  let response = compression::maybe_compress_response(
                    response,
                    &request_method,
                    &request_headers,
                    resolved.route.compression.as_deref(),
                    &state.config.compression,
                    &state.compression,
                  );
                  return with_downstream_response_timeout(response, timeouts.response_send);
                }
              }
              crate::cache::CacheLookup::Revalidate(revalidation) => {
                state.metrics.record_cache_revalidation();
                for (name, value) in &revalidation.request_headers {
                  outbound.headers_mut().insert(name.clone(), value.clone());
                }
                if revalidation.serve_stale_on_error {
                  stale_on_error = Some(revalidation.entry.clone());
                }
                revalidation_entry = Some(revalidation.entry);
              }
            }
          }
          break;
        }
        crate::cache::CacheFillPermit::Follower(waiter) => {
          state.metrics.record_cache_fill_waiter();
          if !waiter
            .wait_timeout(
              state
                .cache
                .lock_wait_timeout(resolved.route.cache.as_deref()),
            )
            .await
          {
            state.metrics.record_cache_fill_lock_timeout();
            break;
          }
          if let Some(lookup) = state.cache.lookup(crate::cache::CacheLookupContext {
            policy_name: resolved.route.cache.as_deref(),
            scheme: downstream_scheme,
            host: &host,
            method: &request_method,
            uri: &request_uri,
            request_headers: &request_headers,
          }) {
            match lookup {
              crate::cache::CacheLookup::Fresh(entry) => {
                state.metrics.record_cache_hit();
                let response = cached_entry_response(entry, &request_method, &request_headers);
                let response = compression::maybe_compress_response(
                  response,
                  &request_method,
                  &request_headers,
                  resolved.route.compression.as_deref(),
                  &state.config.compression,
                  &state.compression,
                );
                return with_downstream_response_timeout(response, timeouts.response_send);
              }
              crate::cache::CacheLookup::Stale(stale) => {
                if stale.background_refresh
                  && can_background_refresh(
                    &state,
                    &resolved.route.name,
                    upstream,
                    upstream_version,
                  )
                  && spawn_background_refresh(
                    state.clone(),
                    &outbound,
                    upstream,
                    upstream_version,
                    timeouts,
                    resolved.route.cache.as_deref(),
                    downstream_scheme,
                    host.clone(),
                    request_method.clone(),
                    request_uri.clone(),
                    request_headers.clone(),
                    request_version,
                    stale.clone(),
                  )
                {
                  state.metrics.record_cache_stale();
                  let response =
                    cached_entry_response(stale.entry, &request_method, &request_headers);
                  let response = compression::maybe_compress_response(
                    response,
                    &request_method,
                    &request_headers,
                    resolved.route.compression.as_deref(),
                    &state.config.compression,
                    &state.compression,
                  );
                  return with_downstream_response_timeout(response, timeouts.response_send);
                }
                if !stale.request_headers.is_empty() {
                  state.metrics.record_cache_revalidation();
                  for (name, value) in &stale.request_headers {
                    outbound.headers_mut().insert(name.clone(), value.clone());
                  }
                  if stale.serve_stale_on_error {
                    stale_on_error = Some(stale.entry.clone());
                  }
                  revalidation_entry = Some(stale.entry);
                } else {
                  state.metrics.record_cache_hit();
                  let response =
                    cached_entry_response(stale.entry, &request_method, &request_headers);
                  let response = compression::maybe_compress_response(
                    response,
                    &request_method,
                    &request_headers,
                    resolved.route.compression.as_deref(),
                    &state.config.compression,
                    &state.compression,
                  );
                  return with_downstream_response_timeout(response, timeouts.response_send);
                }
              }
              crate::cache::CacheLookup::Revalidate(revalidation) => {
                state.metrics.record_cache_revalidation();
                for (name, value) in &revalidation.request_headers {
                  outbound.headers_mut().insert(name.clone(), value.clone());
                }
                if revalidation.serve_stale_on_error {
                  stale_on_error = Some(revalidation.entry.clone());
                }
                revalidation_entry = Some(revalidation.entry);
              }
            }
          } else {
            state.metrics.record_cache_miss();
          }
        }
        crate::cache::CacheFillPermit::SharedConflict => {
          state.metrics.record_cache_fill_lock_conflict();
          break;
        }
      }
    }
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
      timeouts.upstream_first_byte,
      crate::proxy::http3::forward_request(outbound, upstream, state.as_ref(), timeouts),
    )
    .await
    {
      Err(_) => {
        if should_report_upstream_request_failure(true, grpc_timeout_caps) {
          state.pools.report_failure(&upstream.name);
        }
        warn!(upstream = %upstream.name, "upstream HTTP/3 request timed out");
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        access_log.record_upstream_error("read_timeout", "upstream request timed out");
        if let Some(entry) = stale_on_error.clone()
          && state
            .cache
            .stale_if_error_allows_read_timeout(resolved.route.cache.as_deref())
        {
          state.metrics.record_cache_stale();
          return cached_entry_response(entry, &request_method, &request_headers);
        }
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
        if let Some(entry) = stale_on_error.clone()
          && state
            .cache
            .stale_if_error_allows_connect(resolved.route.cache.as_deref())
        {
          state.metrics.record_cache_stale();
          return cached_entry_response(entry, &request_method, &request_headers);
        }
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
      let early_hints_capture =
        semantics::attach_early_hints_capture(&mut outbound, state.config.proxy.http.early_hints);
      send_with_retry(
        client,
        outbound,
        timeouts,
        &state,
        if native_grpc_request {
          semantics::should_retry_grpc(&state.config)
        } else {
          state.config.proxy.retry.enabled && is_idempotent(&request_method)
        },
      )
      .await
      .map(|mut response| {
        if let Some(capture) = early_hints_capture {
          semantics::attach_interim_responses(&mut response, capture.take());
        }
        response
      })
    } else {
      send_one_shot_with_proxy_protocol(
        outbound,
        upstream,
        &state,
        upstream_version,
        client_addr,
        timeouts,
      )
      .await
    };
    match result {
      Ok(response) => {
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        response.map(|body| body.map_err(boxed_error).boxed())
      }
      Err(error) => {
        if error_indicates_body_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
          return text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out");
        }
        let upstream_first_byte_timeout = error_is_upstream_first_byte_timeout(&error);
        if should_report_upstream_request_failure(upstream_first_byte_timeout, grpc_timeout_caps) {
          state.pools.report_failure(&upstream.name);
        }
        warn!(
            error = %error,
            error_debug = ?error,
            upstream = %upstream.name,
            "upstream request failed"
        );
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        let error_message = error.to_string();
        let error_code = if upstream_first_byte_timeout || error_message.contains("timed out") {
          "read_timeout"
        } else {
          "connect_error"
        };
        access_log.record_upstream_error(error_code, &error_message);
        if let Some(entry) = stale_on_error.clone()
          && if error_code == "read_timeout" {
            state
              .cache
              .stale_if_error_allows_read_timeout(resolved.route.cache.as_deref())
          } else {
            state
              .cache
              .stale_if_error_allows_connect(resolved.route.cache.as_deref())
          }
        {
          state.metrics.record_cache_stale();
          return cached_entry_response(entry, &request_method, &request_headers);
        }
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
  if let Some(entry) = stale_on_error.clone()
    && state
      .cache
      .stale_if_error_allows_status(resolved.route.cache.as_deref(), parts.status)
  {
    state.metrics.record_cache_stale();
    return cached_entry_response(entry, &request_method, &request_headers);
  }
  if parts.status == StatusCode::NOT_MODIFIED
    && let Some(entry) = revalidation_entry.clone()
  {
    let mut headers = entry.headers.clone();
    merge_not_modified_headers(&mut headers, &parts.headers);
    state.cache.update_from_not_modified(
      crate::cache::CacheInsertContext {
        policy_name: resolved.route.cache.as_deref(),
        scheme: downstream_scheme,
        host: &host,
        method: &request_method,
        uri: &request_uri,
        request_headers: &request_headers,
      },
      &entry,
      &parts.headers,
    );
    state.metrics.record_cache_hit();
    let response = cached_entry_response(
      crate::cache::CacheEntry {
        status: entry.status,
        headers,
        body: entry.body,
      },
      &request_method,
      &request_headers,
    );
    let response = compression::maybe_compress_response(
      response,
      &request_method,
      &request_headers,
      resolved.route.compression.as_deref(),
      &state.config.compression,
      &state.compression,
    );
    return with_downstream_response_timeout(response, timeouts.response_send);
  }
  let body = body::with_read_timeout(
    body,
    timeouts.upstream_read,
    BodyTimeoutKind::UpstreamResponseRead,
  );
  strip_hop_by_hop_headers(&mut parts.headers);
  if state.config.proxy.http.trailers == crate::config::TrailerMode::Drop && !native_grpc_request {
    parts.headers.remove(http::header::TRAILER);
  }
  semantics::apply_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
  apply_security_headers(&mut parts.headers, &state.config.security.headers);
  apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);

  let (body, captured_response_body) = if state
    .waf
    .requires_response_body_inspection(&resolved.route.name)
  {
    let content_length = parts
      .headers
      .get(http::header::CONTENT_LENGTH)
      .and_then(|value| value.to_str().ok())
      .and_then(|value| value.parse::<u64>().ok());
    match capture_body_prefix(
      body,
      state.config.waf.limits.max_body_inspection_bytes,
      content_length,
    )
    .await
    {
      Ok((body, captured)) => (body, Some(captured)),
      Err(error) => {
        if error_is_timeout(&error, BodyTimeoutKind::UpstreamResponseRead) {
          return text_response(
            StatusCode::GATEWAY_TIMEOUT,
            "upstream response body timed out",
          );
        }
        warn!(error = %error, "failed to read upstream response body for WAF inspection");
        return text_response(
          StatusCode::BAD_GATEWAY,
          "failed to read upstream response body",
        );
      }
    }
  } else {
    (body, None)
  };
  let response_body = captured_response_body.as_ref().map(waf_body_input);

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
      dynamic_policy: &access_log.dynamic_policy,
    };
    let response_waf = state.waf.evaluate_response(WafResponseInput {
      request: request_input,
      response_id: &access_log.response_id,
      received_at_unix_ms: access_log.response_received_at_unix_ms,
      version: parts.version,
      status: parts.status,
      headers: &parts.headers,
      body: response_body,
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
  let mut response_buffering = effective_buffering.response;
  if state.config.proxy.http.sse_auto_streaming && semantics::is_sse(&parts.headers) {
    response_buffering.mode = crate::config::BufferingMode::Streaming;
  }
  let body = filter_trailers(body, state.config.proxy.http.trailers, native_grpc_request);
  let body = match buffering::buffer_body(
    body,
    response_buffering,
    effective_buffering.temp_dir.as_deref(),
  )
  .await
  {
    Ok(body) => body,
    Err(error) => return response_buffering_error_response(error),
  };

  let response = maybe_cache_response(
    Response::from_parts(parts, body),
    &state,
    resolved.route.cache.as_deref(),
    downstream_scheme,
    &host,
    &request_method,
    &request_uri,
    &request_headers,
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
  let response = with_downstream_response_timeout(response, timeouts.response_send);
  state.metrics.record_response(response.status());
  response
}

fn draining_response() -> Response<ProxyBody> {
  let mut response = text_response(StatusCode::SERVICE_UNAVAILABLE, "draining");
  response.headers_mut().insert(
    http::header::CONNECTION,
    http::HeaderValue::from_static("close"),
  );
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

fn with_downstream_response_timeout(
  response: Response<ProxyBody>,
  timeout: Duration,
) -> Response<ProxyBody> {
  let (mut parts, body) = response.into_parts();
  parts
    .extensions
    .insert(DownstreamResponseSendTimeout(timeout));
  let body = body::with_send_timeout(body, timeout, BodyTimeoutKind::DownstreamResponseSend);
  Response::from_parts(parts, body)
}

async fn buffer_request_body(
  request: Request<ProxyBody>,
  effective: &buffering::EffectiveBuffering,
) -> Result<Request<ProxyBody>, buffering::BufferingError> {
  if effective.request.is_streaming() {
    return Ok(request);
  }
  let (parts, body) = request.into_parts();
  let body = buffering::buffer_body(body, effective.request, effective.temp_dir.as_deref()).await?;
  Ok(Request::from_parts(parts, body))
}

fn request_buffering_error_response(error: buffering::BufferingError) -> Response<ProxyBody> {
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

fn response_buffering_error_response(error: buffering::BufferingError) -> Response<ProxyBody> {
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

fn error_is_body_length_limit(error: &body::BoxError) -> bool {
  let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error.as_ref());
  while let Some(error) = current {
    let message = error.to_string();
    if message.contains("length limit")
      || message.contains("body length")
      || message.contains("body is too large")
    {
      return true;
    }
    current = error.source();
  }
  false
}

fn with_connection_permit(
  response: Response<ProxyBody>,
  permit: ConnectionPermit,
) -> Response<ProxyBody> {
  let (parts, body) = response.into_parts();
  Response::from_parts(parts, body::with_drop_guard(body, permit))
}

struct TunnelConnectionLimitHold {
  _request_permit: Option<ConnectionPermit>,
  _first_request_context: Option<ConnectionLimitContext>,
}

impl TunnelConnectionLimitHold {
  fn capture(
    request_permit: &mut Option<ConnectionPermit>,
    first_request_context: Option<&ConnectionLimitContext>,
  ) -> Self {
    Self {
      _request_permit: request_permit.take(),
      _first_request_context: first_request_context.cloned(),
    }
  }
}

fn error_indicates_body_timeout(error: &anyhow::Error, kind: BodyTimeoutKind) -> bool {
  error.chain().any(|cause| {
    cause
      .downcast_ref::<body::BodyTimeoutError>()
      .is_some_and(|timeout| timeout.kind() == kind)
      || cause.to_string().contains(body::timeout_message(kind))
  })
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
  connection_limit_context: Option<&ConnectionLimitContext>,
  request_connection_permit: &mut Option<ConnectionPermit>,
  drain: ConnectionDrain,
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
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, &upstream);
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
    let connection_limit_hold =
      TunnelConnectionLimitHold::capture(request_connection_permit, connection_limit_context);
    tokio::spawn(async move {
      let _connection_limit_hold = connection_limit_hold;
      let result = async {
        let downstream = downstream_upgrade.await?;
        let downstream = TokioIo::new(downstream);
        let upstream_stream = dial_tunnel_upstream(&upstream, client_addr, timeouts).await?;
        copy_bidirectional_with_idle(downstream, upstream_stream, timeouts.websocket_idle, drain)
          .await?;
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

  match dial_tunnel_upstream(&upstream, client_addr, timeouts).await {
    Ok(upstream_stream) => {
      let body = bridge_connect_body(request.into_body(), upstream_stream, timeouts, drain);
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

fn bridge_connect_body(
  mut downstream_body: ProxyBody,
  upstream: TcpStream,
  timeouts: EffectiveTimeouts,
  mut drain: ConnectionDrain,
) -> ProxyBody {
  let (body_sender, body) = body::channel_body(16);
  let (mut upstream_reader, mut upstream_writer) = upstream.into_split();

  let mut downstream_to_upstream = tokio::spawn(async move {
    while let Some(frame) = downstream_body.frame().await {
      let frame = match frame {
        Ok(frame) => frame,
        Err(_) => break,
      };
      if let Ok(data) = frame.into_data() {
        let write_result =
          tokio::time::timeout(timeouts.upstream_send, upstream_writer.write_all(&data)).await;
        if !matches!(write_result, Ok(Ok(()))) {
          break;
        }
      }
    }
    let _ = upstream_writer.shutdown().await;
  });

  let mut upstream_to_downstream = tokio::spawn(async move {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
      match tokio::time::timeout(timeouts.upstream_read, upstream_reader.read(&mut buffer)).await {
        Err(_) => {
          let _ = body_sender
            .send(Err(boxed_error(std::io::Error::new(
              std::io::ErrorKind::TimedOut,
              "CONNECT upstream read timed out",
            ))))
            .await;
          break;
        }
        Ok(Ok(0)) => break,
        Ok(Ok(read)) => {
          let frame = Ok(hyper::body::Frame::data(bytes::Bytes::copy_from_slice(
            &buffer[..read],
          )));
          let send_result =
            tokio::time::timeout(timeouts.response_send, body_sender.send(frame)).await;
          if !matches!(send_result, Ok(Ok(()))) {
            break;
          }
        }
        Ok(Err(error)) => {
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

  tokio::spawn(async move {
    let drain_close = drain.close_delay_elapsed();
    tokio::pin!(drain_close);
    let mut downstream_done = false;
    let mut upstream_done = false;

    loop {
      tokio::select! {
        _ = &mut drain_close => {
          if !downstream_done {
            downstream_to_upstream.abort();
          }
          if !upstream_done {
            upstream_to_downstream.abort();
          }
          return;
        }
        _ = &mut downstream_to_upstream, if !downstream_done => {
          downstream_done = true;
          if upstream_done {
            return;
          }
        }
        _ = &mut upstream_to_downstream, if !upstream_done => {
          upstream_done = true;
          if downstream_done {
            return;
          }
        }
      }
    }
  });

  body
}

async fn copy_bidirectional_with_idle<D, U>(
  downstream: D,
  upstream: U,
  idle_timeout: Duration,
  mut drain: ConnectionDrain,
) -> anyhow::Result<()>
where
  D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let (downstream_read, downstream_write) = tokio::io::split(downstream);
  let (upstream_read, upstream_write) = tokio::io::split(upstream);
  let (activity_tx, mut activity_rx) = mpsc::channel(16);
  let mut downstream_to_upstream = tokio::spawn(copy_one_way_with_activity(
    downstream_read,
    upstream_write,
    activity_tx.clone(),
  ));
  let mut upstream_to_downstream = tokio::spawn(copy_one_way_with_activity(
    upstream_read,
    downstream_write,
    activity_tx,
  ));
  let idle = tokio::time::sleep(idle_timeout);
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);

  loop {
    tokio::select! {
      result = &mut downstream_to_upstream => {
        upstream_to_downstream.abort();
        return result.context("upgrade copy task panicked")?;
      }
      result = &mut upstream_to_downstream => {
        downstream_to_upstream.abort();
        return result.context("upgrade copy task panicked")?;
      }
      activity = activity_rx.recv() => {
        if activity.is_none() {
          return Ok(());
        }
        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
      }
      _ = &mut idle => {
        downstream_to_upstream.abort();
        upstream_to_downstream.abort();
        return Err(anyhow::anyhow!("upgrade tunnel idle timeout elapsed"));
      }
      _ = &mut drain_close => {
        downstream_to_upstream.abort();
        upstream_to_downstream.abort();
        return Ok(());
      }
    }
  }
}

async fn copy_one_way_with_activity<R, W>(
  mut reader: R,
  mut writer: W,
  activity: mpsc::Sender<()>,
) -> anyhow::Result<()>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let mut buffer = vec![0u8; 16 * 1024];
  loop {
    let read = reader.read(&mut buffer).await?;
    if read == 0 {
      writer.shutdown().await?;
      return Ok(());
    }
    writer.write_all(&buffer[..read]).await?;
    let _ = activity.try_send(());
  }
}

async fn dial_tunnel_upstream(
  upstream: &UpstreamConfig,
  client_addr: std::net::SocketAddr,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<TcpStream> {
  let remote_addr = resolve_upstream_tcp_addr(&upstream.origin).await?;
  let mut stream = tokio::time::timeout(timeouts.upstream_connect, TcpStream::connect(remote_addr))
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
  stream_waf: Option<StreamWafRequestContext>,
  connection_limit_context: Option<&ConnectionLimitContext>,
  request_connection_permit: &mut Option<ConnectionPermit>,
  drain: ConnectionDrain,
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
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);

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
  let outbound = outbound.map(|body| {
    body::with_send_timeout(
      body,
      timeouts.upstream_send,
      BodyTimeoutKind::UpstreamRequestSend,
    )
  });
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
  let mut upstream_response =
    match tokio::time::timeout(timeouts.upstream_first_byte, client.request(outbound)).await {
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
  let stream_waf_state = state.clone();
  let websocket_stream_waf = if websocket_upgrade { stream_waf } else { None };
  let connection_limit_hold =
    TunnelConnectionLimitHold::capture(request_connection_permit, connection_limit_context);
  tokio::spawn(async move {
    let _connection_limit_hold = connection_limit_hold;
    let result = async {
      let downstream = downstream_upgrade.await?;
      let upstream = upstream_upgrade.await?;
      if let Some(stream_waf) = websocket_stream_waf {
        crate::proxy::stream_waf::bridge_websocket(
          TokioIo::new(downstream),
          TokioIo::new(upstream),
          stream_waf_state,
          stream_waf,
          timeouts.websocket_idle,
          drain,
        )
        .await?;
      } else {
        copy_bidirectional_with_idle(
          TokioIo::new(downstream),
          TokioIo::new(upstream),
          timeouts.websocket_idle,
          drain,
        )
        .await?;
      }
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
  timeouts: EffectiveTimeouts,
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
      match tokio::time::timeout(timeouts.upstream_first_byte, client.request(outbound)).await {
        Ok(Ok(response)) if retryable_status(response.status(), state) => {
          last_error = Some(anyhow::anyhow!(
            "upstream returned retryable status {}",
            response.status()
          ));
        }
        Ok(Ok(response)) => return Ok(response),
        Ok(Err(error)) => last_error = Some(error.into()),
        Err(_) => {
          last_error = Some(UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte).into());
        }
      }
    }
    return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("upstream retry failed")));
  }
  match tokio::time::timeout(timeouts.upstream_first_byte, client.request(request)).await {
    Ok(result) => Ok(result?),
    Err(_) => Err(UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte).into()),
  }
}

async fn send_one_shot_with_proxy_protocol(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  upstream_version: HttpVersion,
  client_addr: std::net::SocketAddr,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<Incoming>> {
  let upstream_version = TcpUpstreamHttpVersion::from_http_version(upstream_version)?;
  let remote_addr = resolve_upstream_tcp_addr(&upstream.origin).await?;
  let mut stream = tokio::time::timeout(timeouts.upstream_connect, TcpStream::connect(remote_addr))
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
    let tls = tokio::time::timeout(
      timeouts.upstream_connect,
      tokio_rustls::TlsConnector::from(Arc::new(tls_config)).connect(server_name, stream),
    )
    .await
    .context("upstream TLS handshake timed out")?
    .context("upstream TLS handshake failed")?;
    tokio::time::timeout(
      timeouts.upstream_first_byte,
      send_one_shot_over_tcp_io(tls, request, upstream_version),
    )
    .await
    .map_err(|_| UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte))?
  } else {
    tokio::time::timeout(
      timeouts.upstream_first_byte,
      send_one_shot_over_tcp_io(stream, request, upstream_version),
    )
    .await
    .map_err(|_| UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte))?
  }
}

#[derive(Clone, Copy)]
enum TcpUpstreamHttpVersion {
  H1,
  H2,
}

impl TcpUpstreamHttpVersion {
  fn from_http_version(version: HttpVersion) -> anyhow::Result<Self> {
    match version {
      HttpVersion::H1 => Ok(Self::H1),
      HttpVersion::H2 => Ok(Self::H2),
      HttpVersion::H3 => {
        anyhow::bail!("PROXY protocol egress is not supported for HTTP/3 upstream")
      }
    }
  }

  fn as_alpn(self) -> &'static [u8] {
    match self {
      Self::H1 => b"http/1.1",
      Self::H2 => b"h2",
    }
  }
}

#[derive(Debug)]
struct UpstreamFirstByteTimeout {
  timeout: Duration,
}

impl UpstreamFirstByteTimeout {
  fn new(timeout: Duration) -> Self {
    Self { timeout }
  }
}

impl std::fmt::Display for UpstreamFirstByteTimeout {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "upstream request timed out after {}ms",
      self.timeout.as_millis()
    )
  }
}

impl std::error::Error for UpstreamFirstByteTimeout {}

fn error_is_upstream_first_byte_timeout(error: &anyhow::Error) -> bool {
  error.downcast_ref::<UpstreamFirstByteTimeout>().is_some()
}

fn should_report_upstream_request_failure(
  upstream_first_byte_timeout: bool,
  grpc_timeout_caps: semantics::GrpcTimeoutCaps,
) -> bool {
  !(upstream_first_byte_timeout && grpc_timeout_caps.upstream_first_byte)
}

async fn send_one_shot_over_tcp_io<I>(
  io: I,
  request: Request<ProxyBody>,
  upstream_version: TcpUpstreamHttpVersion,
) -> anyhow::Result<Response<Incoming>>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  match upstream_version {
    TcpUpstreamHttpVersion::H1 => {
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
    TcpUpstreamHttpVersion::H2 => {
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

fn cached_entry_response(
  entry: crate::cache::CacheEntry,
  method: &Method,
  request_headers: &HeaderMap,
) -> Response<ProxyBody> {
  let entry = crate::cache::range_entry(entry, method, request_headers);
  let mut response = Response::new(full_body(entry.body));
  *response.status_mut() = entry.status;
  *response.headers_mut() = entry.headers;
  response
}

fn can_background_refresh(
  state: &AppSnapshot,
  route_name: &str,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
) -> bool {
  upstream_version != HttpVersion::H3
    && upstream.proxy_protocol_egress == ProxyProtocolEgressMode::Off
    && !state.waf.has_response_rules(route_name)
    && !state.waf.requires_response_body_inspection(route_name)
}

#[allow(clippy::too_many_arguments)]
fn spawn_background_refresh(
  state: Arc<AppSnapshot>,
  outbound: &Request<ProxyBody>,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  timeouts: EffectiveTimeouts,
  route_cache: Option<&str>,
  scheme: &'static str,
  host: String,
  method: Method,
  uri: http::Uri,
  request_headers: HeaderMap,
  request_version: http::Version,
  stale: crate::cache::StaleEntry,
) -> bool {
  let Some(permit) = state.cache.try_background_refresh_permit(route_cache) else {
    state.metrics.record_cache_background_refresh_skip();
    return false;
  };
  let Some(fill_permit) = state.cache.begin_fill(crate::cache::CacheLookupContext {
    policy_name: route_cache,
    scheme,
    host: &host,
    method: &method,
    uri: &uri,
    request_headers: &request_headers,
  }) else {
    state.metrics.record_cache_background_refresh_skip();
    return false;
  };
  let guard = match fill_permit {
    crate::cache::CacheFillPermit::Leader(guard) => guard,
    crate::cache::CacheFillPermit::Follower(_) => {
      state.metrics.record_cache_background_refresh_skip();
      return false;
    }
    crate::cache::CacheFillPermit::SharedConflict => {
      state.metrics.record_cache_fill_lock_conflict();
      state.metrics.record_cache_background_refresh_skip();
      return false;
    }
  };
  let route_cache = route_cache.map(str::to_string);
  let upstream = upstream.clone();
  let mut outbound = empty_request_from(outbound);
  for (name, value) in &stale.request_headers {
    outbound.headers_mut().insert(name.clone(), value.clone());
  }
  tokio::spawn(async move {
    let _guard = guard;
    let _permit = permit;
    if let Err(error) = background_refresh(
      state.clone(),
      outbound,
      upstream,
      upstream_version,
      timeouts,
      route_cache,
      scheme,
      host,
      method,
      uri,
      request_headers,
      request_version,
      stale.entry,
    )
    .await
    {
      state.metrics.record_cache_background_refresh_error();
      warn!(error = %error, "cache background refresh failed");
    }
  });
  true
}

#[allow(clippy::too_many_arguments)]
async fn background_refresh(
  state: Arc<AppSnapshot>,
  outbound: Request<ProxyBody>,
  upstream: UpstreamConfig,
  upstream_version: HttpVersion,
  timeouts: EffectiveTimeouts,
  route_cache: Option<String>,
  scheme: &'static str,
  host: String,
  method: Method,
  uri: http::Uri,
  request_headers: HeaderMap,
  request_version: http::Version,
  cached_entry: crate::cache::CacheEntry,
) -> anyhow::Result<()> {
  let Some(client) =
    state
      .clients
      .for_upstream_version(&upstream.name, upstream.origin.scheme(), upstream_version)
  else {
    state.metrics.record_cache_background_refresh_skip();
    return Ok(());
  };
  let response = send_with_retry(client, outbound, timeouts, &state, false).await?;
  let (mut parts, body) = response.into_parts();
  if parts.status == StatusCode::NOT_MODIFIED {
    state.cache.update_from_not_modified(
      crate::cache::CacheInsertContext {
        policy_name: route_cache.as_deref(),
        scheme,
        host: &host,
        method: &method,
        uri: &uri,
        request_headers: &request_headers,
      },
      &cached_entry,
      &parts.headers,
    );
    state.metrics.record_cache_background_refresh_success();
    return Ok(());
  }
  strip_hop_by_hop_headers(&mut parts.headers);
  semantics::apply_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
  apply_security_headers(&mut parts.headers, &state.config.security.headers);
  apply_alt_svc_header(
    &mut parts.headers,
    parts.status,
    state.as_ref(),
    scheme,
    request_version,
  );
  if body
    .size_hint()
    .upper()
    .is_none_or(|upper| upper as usize > state.config.proxy.buffering.max_memory_body_bytes)
  {
    state.metrics.record_cache_background_refresh_skip();
    return Ok(());
  }
  let body = body::with_read_timeout(
    body.map_err(boxed_error).boxed(),
    timeouts.upstream_read,
    BodyTimeoutKind::UpstreamResponseRead,
  );
  let bytes = body
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!("failed to read background refresh body: {error}"))?
    .to_bytes();
  match state.cache.insert(
    crate::cache::CacheInsertContext {
      policy_name: route_cache.as_deref(),
      scheme,
      host: &host,
      method: &method,
      uri: &uri,
      request_headers: &request_headers,
    },
    crate::cache::CacheEntry {
      status: parts.status,
      headers: parts.headers,
      body: bytes,
    },
  ) {
    crate::cache::CacheInsertOutcome::Stored => {
      state.metrics.record_cache_background_refresh_success();
    }
    crate::cache::CacheInsertOutcome::Rejected => {
      state.metrics.record_cache_admission_rejection();
      state.metrics.record_cache_background_refresh_skip();
    }
    crate::cache::CacheInsertOutcome::StoreFailed => {
      state.metrics.record_cache_fill_error();
      state.metrics.record_cache_background_refresh_error();
    }
    crate::cache::CacheInsertOutcome::NotCacheable => {
      state.metrics.record_cache_background_refresh_skip();
    }
  }
  Ok(())
}

fn empty_request_from<B>(request: &Request<B>) -> Request<ProxyBody> {
  let mut builder = Request::builder()
    .method(request.method().clone())
    .uri(request.uri().clone())
    .version(request.version());
  *builder.headers_mut().expect("request builder headers") = request.headers().clone();
  builder
    .body(full_body(bytes::Bytes::new()))
    .expect("request clone builds")
}

#[allow(clippy::too_many_arguments)]
async fn maybe_cache_response(
  response: Response<ProxyBody>,
  state: &AppSnapshot,
  route_cache: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
  request_headers: &HeaderMap,
) -> Response<ProxyBody> {
  if !state.cache.policy_enabled(route_cache, method) {
    return response;
  }
  let (mut parts, body) = response.into_parts();
  let collect_limit = cache_response_collect_limit(&state.config);
  if body
    .size_hint()
    .upper()
    .is_none_or(|upper| upper as usize > collect_limit)
  {
    if state.cache.strip_surrogate_control(route_cache) {
      parts.headers.remove("surrogate-control");
    }
    return Response::from_parts(parts, body);
  }
  match collect_cache_response_body(body, collect_limit).await {
    Ok(bytes) => {
      let cache_headers = parts.headers.clone();
      if state.cache.strip_surrogate_control(route_cache) {
        parts.headers.remove("surrogate-control");
      }
      match state.cache.insert(
        crate::cache::CacheInsertContext {
          policy_name: route_cache,
          scheme,
          host,
          method,
          uri,
          request_headers,
        },
        crate::cache::CacheEntry {
          status: parts.status,
          headers: cache_headers,
          body: bytes.clone(),
        },
      ) {
        crate::cache::CacheInsertOutcome::Rejected => {
          state.metrics.record_cache_admission_rejection();
        }
        crate::cache::CacheInsertOutcome::StoreFailed => {
          state.metrics.record_cache_fill_error();
        }
        crate::cache::CacheInsertOutcome::Stored
        | crate::cache::CacheInsertOutcome::NotCacheable => {}
      }
      Response::from_parts(parts, full_body(bytes))
    }
    Err(error) if error_is_timeout(&error, BodyTimeoutKind::UpstreamResponseRead) => {
      state.metrics.record_cache_fill_error();
      text_response(
        StatusCode::GATEWAY_TIMEOUT,
        "upstream response body timed out",
      )
    }
    Err(error) => {
      state.metrics.record_cache_fill_error();
      text_response(
        StatusCode::BAD_GATEWAY,
        &format!("failed to read upstream response body: {error}"),
      )
    }
  }
}

fn cache_response_collect_limit(config: &Config) -> usize {
  config
    .cache
    .max_size_bytes
    .min(config.proxy.buffering.max_memory_body_bytes)
}

async fn collect_cache_response_body(
  mut body: ProxyBody,
  limit: usize,
) -> Result<bytes::Bytes, self::body::BoxError> {
  let mut chunks = Vec::new();
  let mut total = 0usize;
  while let Some(frame) = body.frame().await {
    let frame = frame?;
    let Ok(data) = frame.into_data() else {
      continue;
    };
    total = total
      .checked_add(data.len())
      .ok_or_else(|| boxed_error(std::io::Error::other("cache fill body length overflow")))?;
    if total > limit {
      return Err(boxed_error(std::io::Error::other(
        "cache fill body exceeds memory limit",
      )));
    }
    chunks.push(data);
  }

  let mut bytes = bytes::BytesMut::with_capacity(total);
  for chunk in chunks {
    bytes.extend_from_slice(&chunk);
  }
  Ok(bytes.freeze())
}

fn merge_not_modified_headers(headers: &mut HeaderMap, not_modified: &HeaderMap) {
  for (name, value) in not_modified {
    if matches!(
      name.as_str().to_ascii_lowercase().as_str(),
      "cache-control" | "expires" | "etag" | "last-modified" | "vary"
    ) {
      headers.insert(name.clone(), value.clone());
    }
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
  pub(crate) timeouts: EffectiveTimeouts,
  pub(crate) connection_limit_permit: Option<ConnectionPermit>,
  pub(crate) stream_waf: Option<StreamWafRequestContext>,
  _pool_selection: Option<PoolSelection>,
}

pub(crate) fn prepare_webtransport(
  request: &Request<()>,
  peer_addr: std::net::SocketAddr,
  tls: &WafTlsMetadata,
  connection_limit_context: Option<ConnectionLimitContext>,
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
  let request_id = crate::waf::new_access_log_id();
  let transaction_id = crate::waf::new_access_log_id();
  let received_at_unix_ms = crate::waf::current_unix_ms();
  let mut tags = std::collections::HashMap::new();
  let client_addr = match crate::identity::resolve_client_addr(
    &request_headers,
    peer_addr,
    &state.config.proxy.real_ip,
  ) {
    Ok(addr) => addr,
    Err(error) => {
      warn!(error = %error, peer = %peer_addr, "rejected untrusted real IP metadata");
      return Err(Box::new(text_response(
        StatusCode::BAD_REQUEST,
        "untrusted forwarded client IP metadata",
      )));
    }
  };
  let connection_limit_permit = match state.config.limits.connection_limit_identity {
    ConnectionLimitIdentityMode::ProxyProtocol => None,
    ConnectionLimitIdentityMode::FirstRequestRealIp => {
      let acquire = || {
        state.limits.acquire_ip_connection(
          client_addr.ip(),
          &state.config.limits,
          &state.config.connection_limits,
        )
      };
      if let Some(context) = connection_limit_context.as_ref() {
        if let Err(status) = context.bind_first_request(acquire) {
          return Err(Box::new(text_response(status, "connection limit exceeded")));
        }
        None
      } else {
        match acquire() {
          Ok(permit) => Some(permit),
          Err(status) => {
            return Err(Box::new(text_response(status, "connection limit exceeded")));
          }
        }
      }
    }
    ConnectionLimitIdentityMode::PerRequestRealIp => match state.limits.acquire_ip_connection(
      client_addr.ip(),
      &state.config.limits,
      &state.config.connection_limits,
    ) {
      Ok(permit) => Some(permit),
      Err(status) => {
        return Err(Box::new(text_response(status, "connection limit exceeded")));
      }
    },
  };

  let Some(resolved) = state.route_table.resolve(&host, &path, &state.upstreams) else {
    return Err(Box::new(text_response(
      StatusCode::NOT_FOUND,
      "no matching route",
    )));
  };

  let dynamic_policy = state.dynamic_policy.evaluate(
    DynamicPolicyRequest {
      client_ip: client_addr.ip(),
      route_name: &resolved.route.name,
      method: &request_method,
      path: request_uri.path(),
    },
    &state.limits,
  );
  if let Some(terminal) = dynamic_policy.terminal {
    return Err(Box::new(text_response(terminal.status, &terminal.body)));
  }
  let dynamic_policy_context = dynamic_policy.context;

  let request_waf = state.waf.evaluate_request(WafRequestInput {
    request_id: &request_id,
    transaction_id: &transaction_id,
    received_at_unix_ms,
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
    dynamic_policy: &dynamic_policy_context,
  });

  for (key, value) in request_waf.tags {
    tags.insert(key, value);
  }

  let stream_waf = StreamWafRequestContext::from_seed(
    state,
    StreamWafRequestSeed {
      request_id,
      transaction_id,
      received_at_unix_ms,
      method: request_method.clone(),
      uri: request_uri.clone(),
      version: http::Version::HTTP_3,
      headers: request_headers.clone(),
      peer_addr,
      downstream_host: host.clone(),
      downstream_scheme: "https",
      route_name: resolved.route.name.clone(),
      tcp_max_hop: None,
      tls: Arc::new(tls.clone()),
      protocol: WafProtocol::Webtransport,
      transport_network: WafTransportNetwork::Udp,
      tags: tags.clone(),
      dynamic_policy: dynamic_policy_context.clone(),
    },
  );

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
      client_addr.ip(),
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
    client_addr,
    &host,
    "https",
    state.config.proxy.forwarded_headers.mode,
  );
  apply_header_mutations(&mut headers, &request_waf.request_header_mutations);

  let protocols = parse_webtransport_protocols(&headers);
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
  Ok(PreparedWebTransport {
    target_url,
    headers,
    protocols,
    upstream: upstream.clone(),
    timeouts,
    connection_limit_permit,
    stream_waf,
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
mod cache_tests;

#[cfg(test)]
mod webtransport_tests;

#[cfg(test)]
mod tests {
  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  use pretty_assertions::assert_eq;

  use super::*;
  use crate::config::Config;

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
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

  #[test]
  fn tunnel_connection_limit_hold_keeps_request_permit_until_drop() {
    let limits = crate::config::LimitsConfig {
      max_connections: 10,
      max_connections_per_ip: 1,
      ..crate::config::LimitsConfig::default()
    };
    let limit_state = crate::limits::LimitState::new(None);
    let ip = "203.0.113.10".parse().unwrap();
    let mut request_permit = Some(
      limit_state
        .acquire_ip_connection(ip, &limits, &[])
        .expect("initial request permit should be acquired"),
    );

    let hold = TunnelConnectionLimitHold::capture(&mut request_permit, None);

    assert!(request_permit.is_none());
    assert_eq!(
      limit_state.acquire_ip_connection(ip, &limits, &[]).err(),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
    drop(hold);
    assert!(limit_state.acquire_ip_connection(ip, &limits, &[]).is_ok());
  }

  #[test]
  fn tunnel_connection_limit_hold_keeps_first_request_context_until_drop() {
    let limits = crate::config::LimitsConfig {
      max_connections: 10,
      max_connections_per_ip: 1,
      ..crate::config::LimitsConfig::default()
    };
    let limit_state = crate::limits::LimitState::new(None);
    let ip = "203.0.113.11".parse().unwrap();
    let context = ConnectionLimitContext::default();
    context
      .bind_first_request(|| limit_state.acquire_ip_connection(ip, &limits, &[]))
      .expect("first request context should bind");
    let mut request_permit = None;

    let hold = TunnelConnectionLimitHold::capture(&mut request_permit, Some(&context));
    drop(context);

    assert_eq!(
      limit_state.acquire_ip_connection(ip, &limits, &[]).err(),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
    drop(hold);
    assert!(limit_state.acquire_ip_connection(ip, &limits, &[]).is_ok());
  }

  #[test]
  fn effective_timeouts_prefer_route_overrides() {
    let temp_dir = common::TempDir::new("effective-timeouts");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "effective-timeouts");
    let raw = format!(
      r#"
{}

[limits]
client_body_timeout_ms = 31000
response_send_timeout_ms = 61000
websocket_idle_timeout_ms = 71000
webtransport_idle_timeout_ms = 81000

[[routes]]
name = "timeout-route"
hosts = ["timeouts.example.com"]
path_prefix = "/timeouts"
upstream = "app"

[routes.timeouts]
client_body_timeout_ms = 15000
response_send_timeout_ms = 30000
websocket_idle_timeout_ms = 60000
webtransport_idle_timeout_ms = 65000
upstream_connect_timeout_ms = 1000
upstream_request_timeout_ms = 15000
upstream_first_byte_timeout_ms = 2000
upstream_read_timeout_ms = 10000
upstream_send_timeout_ms = 11000
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    let config = parse_config(&raw);
    let route = config
      .routes
      .iter()
      .find(|route| route.name == "timeout-route")
      .expect("route should exist");
    let upstream = &config.upstreams[0];

    let timeouts = EffectiveTimeouts::new(&config, route, upstream);

    assert_eq!(timeouts.response_send, Duration::from_millis(30_000));
    assert_eq!(timeouts.websocket_idle, Duration::from_millis(60_000));
    assert_eq!(timeouts.webtransport_idle, Duration::from_millis(65_000));
    assert_eq!(timeouts.upstream_connect, Duration::from_millis(1_000));
    assert_eq!(timeouts.upstream_first_byte, Duration::from_millis(2_000));
    assert_eq!(timeouts.upstream_read, Duration::from_millis(10_000));
    assert_eq!(timeouts.upstream_send, Duration::from_millis(11_000));
  }

  #[test]
  fn effective_first_byte_timeout_is_capped_by_request_timeout() {
    let temp_dir = common::TempDir::new("first-byte-cap");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "first-byte-cap");
    let raw = format!(
      r#"
{}

[routes.timeouts]
upstream_request_timeout_ms = 1000
upstream_first_byte_timeout_ms = 5000
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    let config = parse_config(&raw);
    let timeouts = EffectiveTimeouts::new(&config, &config.routes[0], &config.upstreams[0]);

    assert_eq!(timeouts.upstream_first_byte, Duration::from_millis(1_000));
  }

  #[test]
  fn client_grpc_deadline_first_byte_timeout_is_not_pool_health_failure() {
    let caps = semantics::GrpcTimeoutCaps {
      upstream_first_byte: true,
    };

    assert!(!should_report_upstream_request_failure(true, caps));
  }

  #[test]
  fn configured_first_byte_timeout_still_reports_pool_health_failure() {
    assert!(should_report_upstream_request_failure(
      true,
      semantics::GrpcTimeoutCaps::default()
    ));
  }

  #[test]
  fn non_timeout_upstream_error_still_reports_pool_health_failure() {
    let caps = semantics::GrpcTimeoutCaps {
      upstream_first_byte: true,
    };

    assert!(should_report_upstream_request_failure(false, caps));
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
}
