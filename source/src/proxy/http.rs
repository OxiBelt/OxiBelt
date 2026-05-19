use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::Context;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Either, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::config::{
  Config, ConnectionLimitIdentityMode, ErrorResponseMode, HttpVersion, ProxyHttp2Config,
  ProxyProtocolEgressMode, RouteConfig, UpstreamConfig,
};
use crate::dynamic_policy::DynamicPolicyRequest;
use crate::lifecycle::ConnectionDrain;
use crate::limits::{ConnectionLimitContext, ConnectionPermit, RateLimitContext};
use crate::pools::PoolSelection;
use crate::proxy::stream_waf::{StreamWafRequestContext, StreamWafRequestSeed};
use crate::state::{AppSnapshot, UpstreamClientRef};
use crate::waf::{
  BodyNeed, WafBodyInput, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations, request_protocol,
};

pub(crate) mod access_log;
pub(crate) mod body;
pub(crate) mod buffering;
pub(crate) mod compression;
pub(crate) mod fast_path;
pub(crate) mod grpc_web;
pub(crate) mod headers;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod semantics;
pub(crate) mod static_files;
pub(crate) mod uri;
pub(crate) mod version;
pub(crate) mod webtransport;

pub(crate) mod warm;
pub(crate) use warm::warm_cache_request;

pub(crate) use self::access_log::SystemAccessLogContext;
use self::body::{
  BodyTimeoutKind, CapturedBody, ProxyBody, boxed_error, capture_body_prefix, capture_prefix,
  error_is_timeout,
};
use self::headers::{
  add_forwarded_headers, extract_host, is_upgrade_request, strip_hop_by_hop_headers,
};
use self::request::{RebuildRequestOptions, rebuild_request};
use self::response::{
  apply_security_headers, text_response, upstream_error_response, waf_terminal_response,
};
use self::semantics::{configured_error_response, filter_trailers};
use self::uri::{rewrite_uri, validate_downstream_path};
use self::version::select_upstream_http_version;
pub(crate) use self::webtransport::{PreparedWebTransport, prepare_webtransport};

static EMPTY_TAGS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);

fn tags_ref(tags: &Option<HashMap<String, String>>) -> &HashMap<String, String> {
  tags.as_ref().unwrap_or(&EMPTY_TAGS)
}

fn emit_system_access_log(
  state: &AppSnapshot,
  context: &mut SystemAccessLogContext<'_>,
  response: &Response<ProxyBody>,
) {
  if !state.system_access_log.enabled() {
    return;
  }
  if let Some(input) = context.response_input(response) {
    state.system_access_log.emit(&state.waf, input);
  }
}

fn proxy_error_response(
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
  transport_metadata: WafTransportMetadataInput<'static>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
) -> Response<ProxyBody> {
  let protocol = request_protocol(request.headers());
  handle_inner(
    request,
    peer_addr,
    tcp_max_hop,
    transport_metadata,
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
  udp_connection_id: &str,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  drain: ConnectionDrain,
) -> Response<ProxyBody> {
  handle_inner(
    request,
    peer_addr,
    None,
    WafTransportMetadataInput {
      udp_connection_id: Some(udp_connection_id),
      ..WafTransportMetadataInput::default()
    },
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
  transport_metadata: WafTransportMetadataInput<'_>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
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
  let system_access_log_enabled = state.system_access_log.enabled();
  let mut access_log = SystemAccessLogContext::new(
    &request,
    peer_addr,
    tcp_max_hop,
    system_access_log_enabled.then(|| tls.clone()),
    protocol,
    transport_network,
    transport_metadata,
    downstream_scheme,
    system_access_log_enabled,
  );
  let mut request_connection_permit = None;
  let response = handle_inner_impl(
    request,
    peer_addr,
    tcp_max_hop,
    transport_metadata,
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
  transport_metadata: WafTransportMetadataInput<'_>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  _reject_connect: bool,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
  access_log: &mut SystemAccessLogContext<'_>,
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
  access_log.set_downstream_host(&host);
  let path = request.uri().path();
  if let Err((status, message)) = validate_request_limits(&request, &state.config.limits) {
    return text_response(status, message);
  }
  if let Err(error) = validate_downstream_path(path) {
    warn!(error = %error, path = %path, "rejected unsafe downstream request path");
    return text_response(StatusCode::BAD_REQUEST, "invalid request path");
  }
  let request_version = request.version();
  let mut tags: Option<HashMap<String, String>> = None;
  let client_addr = match crate::identity::resolve_client_addr(
    request.headers(),
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
      let acquire = |ip| {
        state.limits.acquire_ip_connection(
          ip,
          &state.config.limits,
          &state.config.connection_limits,
        )
      };
      let result = if let Some(context) = connection_limit_context.as_ref() {
        context.bind_first_request(client_addr.ip(), acquire)
      } else {
        acquire(client_addr.ip()).map(|permit| {
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

  if !state.config.rate_limits.is_empty()
    && let Some(status) = state
      .limits
      .check_pre_route_rate_limits(client_addr.ip(), &state.config.rate_limits)
  {
    return text_response(status, "rate limit exceeded");
  }

  let Some(resolved) = state
    .route_table
    .resolve_normalized_host(&host, path, &state.upstreams)
  else {
    return text_response(StatusCode::NOT_FOUND, "no matching route");
  };
  access_log.set_route_name(&resolved.route.name);

  if matches!(
    request_version,
    http::Version::HTTP_10 | http::Version::HTTP_11
  ) && fast_path::PlainProxyFastPath::eligible(&request, &state, &resolved)
  {
    let fast_path_waf = match fast_path::prepare_plain_fast_path_waf(
      &request,
      state.as_ref(),
      &resolved,
      client_addr,
      &host,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      transport_network,
      transport_metadata,
      downstream_scheme,
      access_log,
    ) {
      Ok(waf) => waf,
      Err(response) => return *response,
    };
    return fast_path::PlainProxyFastPath::handle(
      request,
      state.clone(),
      &resolved,
      peer_addr,
      client_addr,
      &host,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      downstream_scheme,
      request_version,
      transport_network,
      transport_metadata,
      fast_path_waf.request,
      fast_path_waf.request_headers,
      fast_path_waf.tags,
      access_log,
    )
    .await;
  }

  let client_body_timeout = EffectiveTimeouts::route_body_only(&state.config, resolved.route);
  let request =
    match reject_content_length_zero_data(request, client_body_timeout, request_version).await {
      Ok(request) => request,
      Err(response) => return response,
    };

  if fast_path::PlainProxyFastPath::eligible(&request, &state, &resolved) {
    let fast_path_waf = match fast_path::prepare_plain_fast_path_waf(
      &request,
      state.as_ref(),
      &resolved,
      client_addr,
      &host,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      transport_network,
      transport_metadata,
      downstream_scheme,
      access_log,
    ) {
      Ok(waf) => waf,
      Err(response) => return *response,
    };
    return fast_path::PlainProxyFastPath::handle(
      request,
      state.clone(),
      &resolved,
      peer_addr,
      client_addr,
      &host,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      downstream_scheme,
      request_version,
      transport_network,
      transport_metadata,
      fast_path_waf.request,
      fast_path_waf.request_headers,
      fast_path_waf.tags,
      access_log,
    )
    .await;
  }

  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let request_waf_enabled = state.waf.has_request_rules(&resolved.route.name);
  let response_waf_enabled = state.waf.has_response_rules(&resolved.route.name);
  let request_body_need = state.waf.request_body_need(&resolved.route.name);
  let response_body_need = state.waf.response_body_need(&resolved.route.name);
  let effective_buffering = buffering::EffectiveBuffering::new(&state.config, resolved.route);

  if !state.config.rate_limits.is_empty() {
    let rate_limit_context = RateLimitContext::route(
      client_addr.ip(),
      &resolved.route.name,
      request_uri.path(),
      request.headers(),
    );
    if let Some(status) = state
      .limits
      .check_route_rate_limits(rate_limit_context, &state.config.rate_limits)
    {
      return text_response(status, "rate limit exceeded");
    }
  }

  let dynamic_policy = if state.dynamic_policy.enabled() {
    state.dynamic_policy.evaluate(
      DynamicPolicyRequest {
        client_ip: client_addr.ip(),
        route_name: &resolved.route.name,
        method: &request_method,
        path: request_uri.path(),
      },
      &state.limits,
    )
  } else {
    Default::default()
  };
  access_log.dynamic_policy = dynamic_policy.context;
  if let Some(terminal) = dynamic_policy.terminal {
    return text_response(terminal.status, &terminal.body);
  }

  let request = request.map(|body| {
    body::with_read_timeout(
      Limited::new(body, state.config.limits.max_request_body_bytes as usize).boxed(),
      client_body_timeout,
      BodyTimeoutKind::DownstreamRequestRead,
    )
  });

  let (request, captured_body) = if request_method != Method::CONNECT {
    match capture_request_body_for_waf(
      request,
      request_body_need,
      state.config.waf.limits.max_body_inspection_bytes,
    )
    .await
    {
      Ok(result) => result,
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

  let request_waf = if request_waf_enabled {
    access_log.ensure_request_ids();
    state.waf.evaluate_request(WafRequestInput {
      request_id: access_log.request_id(),
      transaction_id: access_log.transaction_id(),
      received_at_unix_ms: access_log.request_received_at_unix_ms,
      method: &request_method,
      uri: &request_uri,
      version: request_version,
      headers: request.headers(),
      body: request_body,
      peer_addr: client_addr,
      downstream_host: &host,
      downstream_scheme,
      route_name: &resolved.route.name,
      tcp_max_hop,
      tls: tls.as_ref(),
      protocol,
      transport_network,
      transport_metadata,
      tags: tags_ref(&tags),
      dynamic_policy: &access_log.dynamic_policy,
    })
  } else {
    Default::default()
  };

  if !request_waf.tags.is_empty() {
    let tags = tags.get_or_insert_with(HashMap::new);
    for (key, value) in &request_waf.tags {
      tags.insert(key.clone(), value.clone());
    }
  }
  access_log.set_tags(tags.clone());

  if let Some(terminal) = request_waf.terminal {
    return waf_terminal_response(terminal, &request_waf.response_header_mutations);
  }

  if let Some(static_root) = resolved.route.static_root.as_deref() {
    if request_waf.upstream_override.is_some() || request_waf.upstream_pool_override.is_some() {
      warn!(
        route = %resolved.route.name,
        "WAF selected an upstream target for a static route"
      );
      return text_response(
        StatusCode::BAD_GATEWAY,
        "WAF selected an upstream target for a static route",
      );
    }
    access_log.set_upstream("static", "file");
    let response = static_files::serve(
      &request,
      &resolved.route.name,
      &resolved.route.path_prefix,
      static_root,
      &state.static_files,
      state.config.proxy.static_files.inline_max_bytes,
    )
    .await;
    return static_files::finalize_response(
      response,
      state.as_ref(),
      resolved.route,
      &request_waf,
      response_waf_enabled,
      response_body_need,
      &request_method,
      &request_uri,
      request_version,
      request.headers(),
      client_addr,
      &host,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      transport_network,
      transport_metadata,
      downstream_scheme,
      request_body,
      tags_ref(&tags),
      access_log,
    )
    .await;
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
    let stream_waf = if state.waf.requires_stream_inspection(&resolved.route.name) {
      access_log.ensure_request_ids();
      StreamWafRequestContext::from_seed(
        state.as_ref(),
        StreamWafRequestSeed {
          request_id: access_log.request_id().to_string(),
          transaction_id: access_log.transaction_id().to_string(),
          received_at_unix_ms: access_log.request_received_at_unix_ms,
          method: request_method.clone(),
          uri: request_uri.clone(),
          version: request_version,
          headers: request.headers().clone(),
          peer_addr: client_addr,
          downstream_host: host.clone(),
          downstream_scheme,
          route_name: resolved.route.name.clone(),
          tcp_max_hop,
          tls: tls.clone(),
          protocol,
          transport_network,
          tcp_mss: transport_metadata.tcp_mss,
          tcp_rtt_ms: transport_metadata.tcp_rtt_ms,
          udp_datagram_size: transport_metadata.udp_datagram_size,
          udp_connection_id: transport_metadata.udp_connection_id.map(str::to_string),
          tags: tags.clone().unwrap_or_default(),
          dynamic_policy: access_log.dynamic_policy.clone(),
        },
      )
    } else {
      None
    };
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
        if response_waf_enabled {
          access_log.upstream_pool = Some(selection.pool_name.clone());
        } else {
          access_log.set_upstream_pool(selection.pool_name.clone());
        }
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
  access_log.set_upstream(&upstream.name, upstream.origin.scheme());
  let native_grpc_request = semantics::is_native_grpc_request(request.headers(), &state.config);
  let mut timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
  let mut grpc_timeout_caps = semantics::GrpcTimeoutCaps::default();
  if native_grpc_request {
    (timeouts, grpc_timeout_caps) = semantics::cap_timeouts_for_grpc(
      timeouts,
      request.headers(),
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
    grpc_web::request_mode(request.headers())
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
  let cache_enabled_for_route = state
    .cache
    .policy_enabled(resolved.route.cache.as_deref(), &request_method);
  let request_headers = if cache_enabled_for_route || response_waf_enabled || native_grpc_request {
    request.headers().clone()
  } else if state.config.compression.enabled {
    compression::request_header_subset(request.headers())
  } else {
    HeaderMap::new()
  };

  let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
    warn!(upstream = %upstream.name, "missing precomputed upstream URI parts");
    return text_response(StatusCode::BAD_GATEWAY, "upstream URI is not configured");
  };
  let target_uri = match rewrite_uri(
    upstream_uri,
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
  let mut outbound = if upstream_version == HttpVersion::H3 {
    outbound
  } else {
    outbound.map(|body| {
      body::with_send_timeout(
        body,
        timeouts.upstream_send,
        BodyTimeoutKind::UpstreamRequestSend,
      )
    })
  };

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
        return with_downstream_response_timeout(
          response,
          timeouts.response_send,
          transport_network,
        );
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
          return with_downstream_response_timeout(
            response,
            timeouts.response_send,
            transport_network,
          );
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
          return with_downstream_response_timeout(
            response,
            timeouts.response_send,
            transport_network,
          );
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
                return with_downstream_response_timeout(
                  response,
                  timeouts.response_send,
                  transport_network,
                );
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
                  return with_downstream_response_timeout(
                    response,
                    timeouts.response_send,
                    transport_network,
                  );
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
                  return with_downstream_response_timeout(
                    response,
                    timeouts.response_send,
                    transport_network,
                  );
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
                return with_downstream_response_timeout(
                  response,
                  timeouts.response_send,
                  transport_network,
                );
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
                  return with_downstream_response_timeout(
                    response,
                    timeouts.response_send,
                    transport_network,
                  );
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
                  return with_downstream_response_timeout(
                    response,
                    timeouts.response_send,
                    transport_network,
                  );
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
          transport_metadata,
          request_body,
          tags_ref(&tags),
          &upstream.name,
          upstream.origin.scheme(),
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
          transport_metadata,
          request_body,
          tags_ref(&tags),
          &upstream.name,
          upstream.origin.scheme(),
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
          transport_metadata,
          request_body,
          tags_ref(&tags),
          &upstream.name,
          upstream.origin.scheme(),
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
    return with_downstream_response_timeout(response, timeouts.response_send, transport_network);
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

  let (body, captured_response_body) =
    match response_body_capture_decision(parts.version, &parts.headers, response_body_need) {
      WafBodyCaptureDecision::Skip => (body, None),
      WafBodyCaptureDecision::Empty => (body, Some(empty_captured_body())),
      WafBodyCaptureDecision::Prefix => {
        match capture_body_prefix(
          body,
          state.config.waf.limits.max_body_inspection_bytes,
          positive_content_length(&parts.headers),
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
      }
    };
  let response_body = captured_response_body.as_ref().map(waf_body_input);

  if response_waf_enabled {
    access_log.ensure_response_ids();
    access_log.response_received_at_unix_ms = crate::waf::current_unix_ms();
    let request_input = WafRequestInput {
      request_id: access_log.request_id(),
      transaction_id: access_log.transaction_id(),
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
      transport_metadata,
      tags: tags_ref(&tags),
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
  let response =
    with_downstream_response_timeout(response, timeouts.response_send, transport_network);
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

pub(super) fn apply_alt_svc_header(
  headers: &mut HeaderMap,
  status: StatusCode,
  state: &AppSnapshot,
  downstream_scheme: &str,
  request_version: http::Version,
) {
  if !should_add_alt_svc(status, state, downstream_scheme, request_version) {
    return;
  }
  if let Some(value) = state.alt_svc_header_value.clone() {
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

pub(super) fn with_downstream_response_timeout(
  response: Response<ProxyBody>,
  timeout: Duration,
  transport_network: WafTransportNetwork,
) -> Response<ProxyBody> {
  if transport_network == WafTransportNetwork::Udp {
    return mark_downstream_response_timeout(response, timeout);
  }

  let response = mark_downstream_response_timeout(response, timeout);
  let (parts, body) = response.into_parts();
  if parts
    .extensions
    .get::<body::KnownSmallResponseBody>()
    .is_some()
  {
    return Response::from_parts(parts, body);
  }
  let body = body::with_send_timeout(body, timeout, BodyTimeoutKind::DownstreamResponseSend);
  Response::from_parts(parts, body)
}

fn mark_downstream_response_timeout(
  response: Response<ProxyBody>,
  timeout: Duration,
) -> Response<ProxyBody> {
  let (mut parts, body) = response.into_parts();
  parts
    .extensions
    .insert(DownstreamResponseSendTimeout(timeout));
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

pub(super) fn error_indicates_body_timeout(error: &anyhow::Error, kind: BodyTimeoutKind) -> bool {
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
  access_log: &mut SystemAccessLogContext<'_>,
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
  access_log.set_upstream(&upstream.name, upstream.origin.scheme());
  if let Some(selection) = selected.pool_selection.as_ref() {
    access_log.set_upstream_pool(selection.pool_name.clone());
  }
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
  crate::tcp_socket::enable_tcp_nodelay(&stream, remote_addr, "upstream tunnel");
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
  access_log: &mut SystemAccessLogContext<'_>,
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
        access_log.set_upstream_pool(selection.pool_name.clone());
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
  access_log.set_upstream(&upstream.name, upstream.origin.scheme());
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);

  if websocket_upgrade && !upstream.websocket {
    return Some(text_response(
      StatusCode::BAD_GATEWAY,
      "selected upstream does not allow WebSocket",
    ));
  }
  let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
    warn!(upstream = %upstream.name, "missing precomputed upstream URI parts");
    return Some(text_response(
      StatusCode::BAD_GATEWAY,
      "upstream URI is not configured",
    ));
  };
  let target_uri = match rewrite_uri(
    upstream_uri,
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

pub(super) async fn send_with_retry(
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
  crate::tcp_socket::enable_tcp_nodelay(&stream, remote_addr, "one-shot upstream");
  crate::proxy_protocol_egress::write_header(
    &mut stream,
    upstream.proxy_protocol_egress,
    client_addr,
    remote_addr,
  )
  .await
  .context("failed to write upstream PROXY protocol egress header")?;

  if upstream.origin.scheme() == "https" {
    let mut tls_config = crate::tls::build_upstream_client_config_with_resumption(
      &state.config.proxy.trusted_ca_certs,
      &upstream.tls.ech,
      &upstream.tls.resumption,
      Some(&state.tls_resumption),
      &upstream.name,
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
      send_one_shot_over_tcp_io(tls, request, upstream_version, &state.config.proxy.http2),
    )
    .await
    .map_err(|_| UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte))?
  } else {
    tokio::time::timeout(
      timeouts.upstream_first_byte,
      send_one_shot_over_tcp_io(stream, request, upstream_version, &state.config.proxy.http2),
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
  http2_config: &ProxyHttp2Config,
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
      let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
      crate::h2_tuning::apply_client_conn_defaults(&mut builder, http2_config);
      let (mut sender, connection) = builder
        .handshake(TokioIo::new(io))
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

pub(super) fn is_idempotent(method: &Method) -> bool {
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
  if request.headers().contains_key(http::header::CONTENT_LENGTH)
    && request
      .headers()
      .contains_key(http::header::TRANSFER_ENCODING)
  {
    return Err((StatusCode::BAD_REQUEST, "ambiguous request body framing"));
  }
  if request
    .headers()
    .get_all(http::header::CONTENT_LENGTH)
    .iter()
    .count()
    > 1
  {
    return Err((StatusCode::BAD_REQUEST, "ambiguous request body framing"));
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

async fn reject_content_length_zero_data<B>(
  request: Request<B>,
  timeout: Duration,
  version: http::Version,
) -> Result<Request<Either<B, ProxyBody>>, Response<ProxyBody>>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + 'static,
{
  if !content_length_zero_guard_required(request.headers(), version) {
    let (parts, body) = request.into_parts();
    return Ok(Request::from_parts(parts, Either::Left(body)));
  }

  let request = request.map(|body| body.map_err(Into::into).boxed());
  let (parts, body) = request.into_parts();
  let mut body = body::with_read_timeout(body, timeout, BodyTimeoutKind::DownstreamRequestRead);
  while let Some(frame) = body.frame().await {
    let frame = match frame {
      Ok(frame) => frame,
      Err(error) => {
        if error_is_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
          return Err(text_response(
            StatusCode::REQUEST_TIMEOUT,
            "request body timed out",
          ));
        }
        warn!(error = %error, "failed to read Content-Length: 0 request body");
        return Err(text_response(
          StatusCode::BAD_REQUEST,
          "failed to read request body",
        ));
      }
    };
    if frame.data_ref().is_some_and(|data| !data.is_empty()) {
      return Err(text_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "request body is too large",
      ));
    }
  }

  Ok(Request::from_parts(
    parts,
    Either::Right(full_body(bytes::Bytes::new())),
  ))
}

fn cached_entry_response(
  entry: crate::cache::CacheEntry,
  method: &Method,
  request_headers: &HeaderMap,
) -> Response<ProxyBody> {
  let entry = crate::cache::range_entry(entry, method, request_headers);
  let body_len = entry.body.len();
  let mut response = Response::new(full_body(entry.body));
  *response.status_mut() = entry.status;
  *response.headers_mut() = entry.headers;
  if body::is_known_small_response_body_len(body_len) {
    response
      .extensions_mut()
      .insert(body::KnownSmallResponseBody);
  }
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
  let content_length = exact_response_content_length(&parts.headers);
  match state.cache.response_head_decision(
    crate::cache::CacheInsertContext {
      policy_name: route_cache,
      scheme,
      host,
      method,
      uri,
      request_headers,
    },
    parts.status,
    &parts.headers,
    content_length,
  ) {
    crate::cache::CacheResponseHeadDecision::Cacheable => {}
    crate::cache::CacheResponseHeadDecision::Rejected => {
      state.metrics.record_cache_admission_rejection();
      if state.cache.strip_surrogate_control(route_cache) {
        parts.headers.remove("surrogate-control");
      }
      return Response::from_parts(parts, body);
    }
    crate::cache::CacheResponseHeadDecision::NotCacheable => {
      if state.cache.strip_surrogate_control(route_cache) {
        parts.headers.remove("surrogate-control");
      }
      return Response::from_parts(parts, body);
    }
  }
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
      let body_len = bytes.len();
      let mut response = Response::from_parts(parts, full_body(bytes));
      if body::is_known_small_response_body_len(body_len) {
        response
          .extensions_mut()
          .insert(body::KnownSmallResponseBody);
      }
      response
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

fn exact_response_content_length(headers: &HeaderMap) -> Option<usize> {
  let mut values = headers.get_all(http::header::CONTENT_LENGTH).iter();
  let value = values.next()?;
  if values.next().is_some() {
    return None;
  }
  value.to_str().ok()?.trim().parse().ok()
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

fn waf_body_input(body: &CapturedBody) -> WafBodyInput<'_> {
  WafBodyInput {
    bytes: body.bytes.as_ref(),
    is_truncated: body.is_truncated,
  }
}

async fn capture_request_body_for_waf(
  request: Request<ProxyBody>,
  body_need: BodyNeed,
  limit: usize,
) -> Result<(Request<ProxyBody>, Option<CapturedBody>), self::body::BoxError> {
  match request_body_capture_decision(request.version(), request.headers(), body_need) {
    WafBodyCaptureDecision::Skip => Ok((request, None)),
    WafBodyCaptureDecision::Empty => Ok((request, Some(empty_captured_body()))),
    WafBodyCaptureDecision::Prefix => capture_prefix(request, limit)
      .await
      .map(|(request, captured)| (request, Some(captured))),
  }
}

fn empty_captured_body() -> CapturedBody {
  CapturedBody {
    bytes: bytes::Bytes::new(),
    is_truncated: false,
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WafBodyCaptureDecision {
  Skip,
  Empty,
  Prefix,
}

fn request_body_capture_decision(
  version: http::Version,
  headers: &HeaderMap,
  body_need: BodyNeed,
) -> WafBodyCaptureDecision {
  body_capture_decision(
    version,
    headers,
    body_need,
    request_body_is_definitely_empty,
  )
}

fn response_body_capture_decision(
  version: http::Version,
  headers: &HeaderMap,
  body_need: BodyNeed,
) -> WafBodyCaptureDecision {
  body_capture_decision(
    version,
    headers,
    body_need,
    response_body_is_definitely_empty,
  )
}

fn body_capture_decision(
  version: http::Version,
  headers: &HeaderMap,
  body_need: BodyNeed,
  body_is_definitely_empty: fn(http::Version, &HeaderMap) -> bool,
) -> WafBodyCaptureDecision {
  match body_need {
    BodyNeed::None => WafBodyCaptureDecision::Skip,
    BodyNeed::SizeOnly => {
      if body_is_definitely_empty(version, headers) {
        WafBodyCaptureDecision::Empty
      } else if positive_content_length(headers).is_some() {
        WafBodyCaptureDecision::Skip
      } else {
        WafBodyCaptureDecision::Prefix
      }
    }
    BodyNeed::PrefixBytes => {
      if body_is_definitely_empty(version, headers) {
        WafBodyCaptureDecision::Empty
      } else {
        WafBodyCaptureDecision::Prefix
      }
    }
  }
}

fn request_body_is_definitely_empty(version: http::Version, headers: &HeaderMap) -> bool {
  http1_body_is_definitely_empty(version, headers)
}

fn response_body_is_definitely_empty(version: http::Version, headers: &HeaderMap) -> bool {
  http1_body_is_definitely_empty(version, headers)
}

fn http1_body_is_definitely_empty(version: http::Version, headers: &HeaderMap) -> bool {
  matches!(version, http::Version::HTTP_10 | http::Version::HTTP_11)
    && content_length_is_exact_zero(headers)
    && !headers.contains_key(http::header::TRANSFER_ENCODING)
}

fn content_length_zero_guard_required(headers: &HeaderMap, version: http::Version) -> bool {
  matches!(version, http::Version::HTTP_2 | http::Version::HTTP_3)
    && content_length_is_exact_zero(headers)
}

fn content_length_is_exact_zero(headers: &HeaderMap) -> bool {
  let mut values = headers.get_all(http::header::CONTENT_LENGTH).iter();
  let Some(value) = values.next() else {
    return false;
  };
  values.next().is_none() && value.to_str().ok().is_some_and(|value| value.trim() == "0")
}

fn positive_content_length(headers: &HeaderMap) -> Option<u64> {
  if headers.contains_key(http::header::TRANSFER_ENCODING) {
    return None;
  }
  let mut values = headers.get_all(http::header::CONTENT_LENGTH).iter();
  let value = values.next()?;
  if values.next().is_some() {
    return None;
  }
  let length = value.to_str().ok()?.trim().parse::<u64>().ok()?;
  (length > 0).then_some(length)
}

#[cfg(test)]
mod cache_tests;

#[cfg(test)]
mod webtransport_tests;

#[cfg(test)]
mod body_capture_tests;

#[cfg(test)]
mod tests;
