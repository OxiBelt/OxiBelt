//! HTTP data-plane forwarding for downstream requests and upstream responses.
//! Security-sensitive framing, header, body, and WAF decisions stay explicit in this module tree.

use std::collections::HashMap;
use std::sync::Arc;
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
  Config, ConnectionLimitIdentityMode, HttpVersion, ProxyHttp2Config, ProxyProtocolEgressMode,
  RouteConfig, UpstreamConfig,
};
use crate::dynamic_policy::{DynamicPolicyRequest, DynamicPolicyTerminal};
use crate::external_auth::ExternalAuthOutcome;
use crate::ipm::{IpmDecision, IpmRequestContext, resource as ipm_resource};
use crate::lifecycle::ConnectionDrain;
use crate::limits::{ConnectionLimitContext, ConnectionPermit, RateLimitContext};
use crate::proxy::stream_waf::{StreamWafRequestContext, StreamWafRequestSeed};
use crate::routes::{RouteMatchContext, RouteRequestProtocol};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::AppSnapshot;
use crate::telemetry::{TelemetryRuntime, TraceContext};
use crate::waf::{
  BodyNeed, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations, request_protocol,
};

pub(crate) mod access_log;
mod alt_svc;
pub(crate) mod body;
mod body_capture;
pub(crate) mod buffering;
mod cache_status;
mod cache_streaming;
mod cache_wait;
pub(crate) mod compression;
pub(crate) mod fast_path;
mod flow_helpers;
pub(crate) mod grpc_web;
pub(crate) mod headers;
pub(crate) mod observability;
pub(crate) mod person_proof;
pub(crate) mod request;
pub(crate) mod request_framing;
mod request_mirror;
pub(crate) mod response;
mod retry;
mod route_action_runtime;
mod route_actions;
pub(crate) mod semantics;
pub(crate) mod static_files;
pub(crate) mod upstream;
pub(crate) mod uri;
pub(crate) mod version;
mod waf_body_capture;
pub(crate) mod waf_body_coding;
pub(crate) mod webtransport;

pub(crate) mod warm;
pub(crate) use warm::warm_cache_request;

pub(crate) use self::access_log::SystemAccessLogContext;
use self::alt_svc::apply_alt_svc_header;
#[cfg(test)]
use self::alt_svc::should_add_alt_svc;
use self::body::{
  BodyTimeoutKind, ProxyBody, boxed_error, error_indicates_body_timeout, error_is_timeout,
};
use self::cache_status::{CacheHeaderOutcome as CacheOutcome, CacheHeaderReason as CacheReason};
use self::flow_helpers::{
  elapsed_ms, emit_system_access_log, record_route_cache_event, record_route_cache_fill_stage,
  select_forwarded_client_addr, tags_ref,
};
use self::headers::{
  add_forwarded_headers, extract_host_snapshot, is_upgrade_request, set_effective_host_header,
  strip_hop_by_hop_headers, validate_authority_host_consistency,
};
use self::observability::{
  record_request_observability, record_websocket_session_end, request_observability_start,
};
use self::person_proof::handle_person_proof_api;
use self::request::{RebuildRequestOptions, rebuild_request};
use self::request_framing::{
  RequestBodyFraming, VerifiedContentLengthZeroBody, h2_or_h3_content_length_zero_guard_required,
  positive_content_length, request_body_framing,
};
use self::response::{
  apply_security_headers, apply_sticky_cookie, draining_response, external_auth_response,
  proxy_error_response, request_buffering_error_response, response_buffering_error_response,
  silent_close_response, text_response, upstream_error_response, upstream_selection_error_response,
  waf_http_terminal_response, with_pending_dynamic_person_proof_response_mutations,
};
use self::retry::{EffectiveRetryPolicy, send_one_shot, send_pool_with_retry, send_with_retry};
use self::route_action_runtime as route_runtime;
use self::semantics::filter_trailers;
use self::upstream::select_request_upstream;
use self::uri::validate_downstream_path;
use self::version::select_upstream_http_version;
pub(crate) use self::waf_body_capture::{
  capture_request_body_for_waf, capture_response_body_for_waf, request_body_capture_error_response,
  response_body_capture_error_response, waf_body_input,
};
use self::waf_body_coding::has_non_identity_content_encoding;
pub(crate) use self::webtransport::{PreparedWebTransport, prepare_webtransport};

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
  handle_with_forwarded_header_cache(
    request,
    peer_addr,
    tcp_max_hop,
    transport_metadata,
    tls,
    connection_limit_context,
    None,
    state,
    downstream_scheme,
    drain,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_with_forwarded_header_cache(
  request: Request<Incoming>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  transport_metadata: WafTransportMetadataInput<'static>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  forwarded_header_cache: Option<headers::ForwardedHeaderCache>,
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
    forwarded_header_cache,
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
    None,
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
  forwarded_header_cache: Option<headers::ForwardedHeaderCache>,
  state: Arc<AppSnapshot>,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  _reject_connect: bool,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + Unpin + 'static,
{
  let system_access_log_enabled = state.request_path_features.system_access_log;
  let trace_context = if state.request_path_features.telemetry {
    state.telemetry.context_from_headers(request.headers())
  } else {
    None
  };
  let telemetry_start = request_observability_start(&state, trace_context);
  let access_log_metadata_enabled = system_access_log_enabled || telemetry_start.is_some();
  let mut access_log = SystemAccessLogContext::new(
    &request,
    peer_addr,
    tcp_max_hop,
    system_access_log_enabled.then(|| tls.clone()),
    protocol,
    transport_network,
    transport_metadata,
    downstream_scheme,
    access_log_metadata_enabled,
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
    forwarded_header_cache,
    &state,
    protocol,
    transport_network,
    _reject_connect,
    downstream_scheme,
    drain,
    &mut access_log,
    &mut request_connection_permit,
    trace_context,
  )
  .await;
  let response = if let Some(permit) = request_connection_permit {
    with_connection_permit(response, permit)
  } else {
    response
  };
  emit_system_access_log(state.as_ref(), &mut access_log, &response);
  record_request_observability(
    &state,
    &access_log,
    &response,
    trace_context,
    telemetry_start,
  );
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
  forwarded_header_cache: Option<headers::ForwardedHeaderCache>,
  state: &Arc<AppSnapshot>,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  _reject_connect: bool,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
  access_log: &mut SystemAccessLogContext<'_>,
  request_connection_permit: &mut Option<ConnectionPermit>,
  trace_context: Option<TraceContext>,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + Unpin + 'static,
{
  state.record_hot_path_request();

  if state.lifecycle.is_draining() {
    return draining_response();
  }

  if let Err(rejection) =
    semantics::validate_expect(request.headers(), state.config.proxy.http.expect_continue)
  {
    return proxy_error_response(
      state,
      access_log,
      StatusCode::EXPECTATION_FAILED,
      rejection.message(),
      "expect_rejected",
    );
  }

  if validate_authority_host_consistency(&request).is_err() {
    warn!("rejected ambiguous downstream host metadata");
    return text_response(StatusCode::BAD_REQUEST, "ambiguous host header");
  }

  let host_snapshot = extract_host_snapshot(&request);
  let host = host_snapshot.as_str();
  let downstream_port = host_snapshot.downstream_port(downstream_scheme);
  access_log.set_downstream_host(host);
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
  let forwarded_client_addr = select_forwarded_client_addr(
    peer_addr,
    client_addr,
    state.config.proxy.forwarded_headers.client_ip_source,
  );
  let forwarded_header_cache = forwarded_header_cache.as_ref();
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

  if state.request_path_features.rate_limits
    && let Some(status) = state
      .limits
      .check_pre_route_rate_limits(client_addr.ip(), &state.config.rate_limits)
  {
    return text_response(status, "rate limit exceeded");
  }

  let resolved = state
    .route_table
    .try_resolve_simple_exact_host(host, path, &state.upstreams)
    .or_else(|| {
      state.route_table.resolve_normalized_host_with_context(
        host,
        RouteMatchContext {
          path,
          method: Some(request.method()),
          headers: Some(request.headers()),
          query: request.uri().query(),
          source_ip: Some(client_addr.ip()),
          protocol: Some(RouteRequestProtocol::from_http(request_version, protocol)),
          tls: Some(tls.as_ref()),
        },
        &state.upstreams,
      )
    });
  let Some(resolved) = resolved else {
    return text_response(StatusCode::NOT_FOUND, "no matching route");
  };
  access_log.set_route_name(&resolved.route.name);
  let max_request_body_bytes = resolved
    .route
    .effective_max_request_body_bytes(&state.config.limits);
  if let Err((status, message)) = validate_request_body_size_limit(&request, max_request_body_bytes)
  {
    return text_response(status, message);
  }

  if let Some(response) =
    route_runtime::cors_preflight_response(resolved.route, request.method(), request.headers())
  {
    return response;
  }

  if resolved.execution_plan.features.ipm {
    let Some(actor) = state.ipm.actor_from_headers(request.headers()) else {
      return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let action = resolved
      .route
      .ipm
      .action
      .as_deref()
      .unwrap_or("route:Invoke");
    let resource = ipm_resource(state.ipm.namespace(), "route", &resolved.route.name);
    let context = IpmRequestContext {
      source_ip: Some(client_addr.ip()),
      method: Some(request.method().as_str().to_string()),
      host: Some(host.to_string()),
      path: Some(path.to_string()),
      route: Some(resolved.route.name.clone()),
      protocol: Some(format!("{:?}", request_version)),
      claims: std::collections::HashMap::new(),
    };
    if state.ipm.authorize(&actor, action, &resource, &context) != IpmDecision::Allow {
      return text_response(StatusCode::FORBIDDEN, "forbidden");
    }
  }

  let cl0_guard_required =
    h2_or_h3_content_length_zero_guard_required(request_version, request.headers());
  let request = if !cl0_guard_required {
    match fast_path::try_handle_plain_proxy(
      request,
      state,
      &resolved,
      forwarded_client_addr,
      forwarded_header_cache,
      client_addr,
      host,
      downstream_port,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      downstream_scheme,
      request_version,
      transport_network,
      transport_metadata,
      access_log,
      trace_context,
    )
    .await
    {
      Ok(response) => return response,
      Err(request) => request,
    }
  } else {
    request
  };
  let client_body_timeout = EffectiveTimeouts::route_body_only(&state.config, resolved.route);
  let request =
    match reject_content_length_zero_data(request, client_body_timeout, request_version).await {
      Ok(request) => request,
      Err(response) => return response,
    };
  let mut request = if cl0_guard_required {
    match fast_path::try_handle_plain_proxy(
      request,
      state,
      &resolved,
      forwarded_client_addr,
      forwarded_header_cache,
      client_addr,
      host,
      downstream_port,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      downstream_scheme,
      request_version,
      transport_network,
      transport_metadata,
      access_log,
      trace_context,
    )
    .await
    {
      Ok(response) => return response,
      Err(request) => request,
    }
  } else {
    request
  };
  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let client_asn = state.client_identity.asn.lookup(client_addr.ip());
  let request_waf_enabled = resolved.execution_plan.waf.request.enabled();
  let response_waf_enabled = resolved.execution_plan.waf.response.enabled();
  let request_body_need = resolved.execution_plan.waf.request.body_need();
  let response_body_need = resolved.execution_plan.waf.response.body_need();
  let effective_buffering = buffering::EffectiveBuffering::new(&state.config, resolved.route);
  if state.request_path_features.rate_limits {
    let rate_limit_context = RateLimitContext::route(
      client_addr.ip(),
      &resolved.route.name,
      request_uri.path(),
      request.headers(),
    )
    .with_tls_fingerprint(tls.fingerprint.as_deref())
    .with_client_asn(client_asn)
    .with_tcp_max_hop(tcp_max_hop);
    if let Some(status) = state
      .limits
      .check_route_rate_limits(rate_limit_context, &state.config.rate_limits)
    {
      return text_response(status, "rate limit exceeded");
    }
  }
  let mut evaluated_person_proof = None;
  if state.request_path_features.dynamic_policy
    && state
      .dynamic_policy
      .needs_person_proof_clearance_for_request(DynamicPolicyRequest {
        client_ip: client_addr.ip(),
        route_name: &resolved.route.name,
        method: &request_method,
        path: request_uri.path(),
        headers: Some(request.headers()),
        tls_fingerprint: tls.fingerprint.as_deref(),
        client_asn,
        tcp_max_hop,
        person_proof_clearance_hash: None,
      })
  {
    access_log.ensure_request_ids();
    evaluated_person_proof = Some(state.waf.evaluate_person_proof_request(WafRequestInput {
      request_id: access_log.request_id(),
      transaction_id: access_log.transaction_id(),
      received_at_unix_ms: access_log.request_received_at_unix_ms,
      method: &request_method,
      uri: &request_uri,
      version: request_version,
      headers: request.headers(),
      body: None,
      peer_addr: client_addr,
      client_asn,
      downstream_host: host,
      downstream_scheme,
      route_name: &resolved.route.name,
      tcp_max_hop,
      tls: tls.as_ref(),
      protocol,
      transport_network,
      transport_metadata,
      tags: tags_ref(&tags),
      dynamic_policy: &access_log.dynamic_policy,
    }));
  }
  let person_proof_clearance_hash = evaluated_person_proof
    .as_ref()
    .and_then(|status| status.clearance_hash());
  let dynamic_policy = if state.request_path_features.dynamic_policy {
    state.dynamic_policy.evaluate(
      DynamicPolicyRequest {
        client_ip: client_addr.ip(),
        route_name: &resolved.route.name,
        method: &request_method,
        path: request_uri.path(),
        headers: Some(request.headers()),
        tls_fingerprint: tls.fingerprint.as_deref(),
        client_asn,
        tcp_max_hop,
        person_proof_clearance_hash,
      },
      &state.limits,
    )
  } else {
    Default::default()
  };
  access_log.dynamic_policy = dynamic_policy.context;
  let mut dynamic_challenge_response_mutations = Vec::new();
  let mut dynamic_person_proof_mutation_added = false;
  if let Some(terminal) = dynamic_policy.terminal {
    match terminal {
      DynamicPolicyTerminal::Text { status, body } => {
        return with_pending_dynamic_person_proof_response_mutations(
          text_response(status, &body),
          state.as_ref(),
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        );
      }
      DynamicPolicyTerminal::SilentClose => {
        return silent_close_response();
      }
      DynamicPolicyTerminal::Challenge { status } => {
        let person_proof_api_path = state.request_path_features.person_proof_api
          && state.waf.has_person_proof_api_path(request_uri.path());
        if !person_proof_api_path {
          access_log.ensure_request_ids();
          let decision = match state
            .waf
            .evaluate_dynamic_person_proof_challenge_with_status(
              WafRequestInput {
                request_id: access_log.request_id(),
                transaction_id: access_log.transaction_id(),
                received_at_unix_ms: access_log.request_received_at_unix_ms,
                method: &request_method,
                uri: &request_uri,
                version: request_version,
                headers: request.headers(),
                body: None,
                peer_addr: client_addr,
                client_asn,
                downstream_host: host,
                downstream_scheme,
                route_name: &resolved.route.name,
                tcp_max_hop,
                tls: tls.as_ref(),
                protocol,
                transport_network,
                transport_metadata,
                tags: tags_ref(&tags),
                dynamic_policy: &access_log.dynamic_policy,
              },
              status,
              &mut evaluated_person_proof,
            ) {
            Ok(decision) => decision,
            Err(error) => {
              warn!(error = %error, "failed to evaluate dynamic Person proof challenge");
              return with_pending_dynamic_person_proof_response_mutations(
                text_response(StatusCode::FORBIDDEN, "person proof challenge failed"),
                state.as_ref(),
                evaluated_person_proof.as_ref(),
                dynamic_person_proof_mutation_added,
                &dynamic_challenge_response_mutations,
              );
            }
          };
          if let Some(terminal) = decision.terminal {
            return waf_http_terminal_response(terminal, &decision.response_header_mutations);
          }
          dynamic_person_proof_mutation_added = !decision.response_header_mutations.is_empty();
          dynamic_challenge_response_mutations.extend(decision.response_header_mutations);
        }
      }
    }
  }
  let person_proof_api_path = state.request_path_features.person_proof_api
    && state.waf.has_person_proof_api_path(request_uri.path());
  if person_proof_api_path {
    access_log.ensure_request_ids();
    let response = handle_person_proof_api(
      request,
      state.as_ref(),
      request_method,
      request_uri,
      client_body_timeout,
      request_version,
      client_addr,
      host,
      downstream_scheme,
      &resolved.route.name,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      transport_network,
      transport_metadata,
      tags_ref(&tags),
      &access_log.dynamic_policy,
      access_log.request_id().to_string(),
      access_log.transaction_id().to_string(),
      access_log.request_received_at_unix_ms,
    )
    .await;
    return with_pending_dynamic_person_proof_response_mutations(
      response,
      state.as_ref(),
      evaluated_person_proof.as_ref(),
      dynamic_person_proof_mutation_added,
      &dynamic_challenge_response_mutations,
    );
  }
  match route_actions::resolved_redirect_response(&resolved, downstream_scheme, host, &request_uri)
  {
    Ok(Some(response)) => {
      return with_pending_dynamic_person_proof_response_mutations(
        response,
        state.as_ref(),
        evaluated_person_proof.as_ref(),
        dynamic_person_proof_mutation_added,
        &dynamic_challenge_response_mutations,
      );
    }
    Ok(None) => {}
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to build route redirect response");
      return with_pending_dynamic_person_proof_response_mutations(
        text_response(StatusCode::BAD_REQUEST, "invalid route redirect"),
        state.as_ref(),
        evaluated_person_proof.as_ref(),
        dynamic_person_proof_mutation_added,
        &dynamic_challenge_response_mutations,
      );
    }
  }
  if resolved.execution_plan.features.external_auth
    && let Some(provider) = resolved.route.external_auth.as_deref()
  {
    match state
      .external_auth
      .authorize(
        provider,
        &mut request,
        client_addr.ip(),
        host,
        downstream_scheme,
        &resolved.route.name,
      )
      .await
    {
      ExternalAuthOutcome::Allowed => {}
      ExternalAuthOutcome::Denied(terminal) => {
        return with_pending_dynamic_person_proof_response_mutations(
          external_auth_response(terminal),
          state.as_ref(),
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        );
      }
    }
  }
  let waf_body_compression_transform =
    crate::waf::route_http_body_compression_transform_enabled(&state.config, resolved.route);
  let request_waf_body_compression_transform =
    waf_body_compression_transform && request_body_need != BodyNeed::None;
  let response_waf_body_compression_transform =
    waf_body_compression_transform && response_body_need != BodyNeed::None;
  let request = request.map(|body| {
    body::with_read_timeout(
      Limited::new(body, max_request_body_bytes as usize).boxed(),
      client_body_timeout,
      BodyTimeoutKind::DownstreamRequestRead,
    )
  });
  let (request, captured_body) =
    if request_method != Method::CONNECT && request_body_need != BodyNeed::None {
      match capture_request_body_for_waf(
        request,
        request_body_need,
        state.config.waf.limits.max_body_inspection_bytes,
        request_waf_body_compression_transform,
        &state.config.waf.http_body_compression,
        &state.waf_body_coding,
      )
      .await
      {
        Ok(result) => result,
        Err(error) => {
          warn!(error = %error, "failed to read request body for WAF inspection");
          let (status, message) = request_body_capture_error_response(&error);
          return with_pending_dynamic_person_proof_response_mutations(
            text_response(status, message),
            state.as_ref(),
            evaluated_person_proof.as_ref(),
            dynamic_person_proof_mutation_added,
            &dynamic_challenge_response_mutations,
          );
        }
      }
    } else {
      (request, None)
    };
  let request_body = captured_body.as_ref().map(waf_body_input);

  let mut request_waf = if request_waf_enabled {
    access_log.ensure_request_ids();
    state.waf.evaluate_request_with_person_proof(
      WafRequestInput {
        request_id: access_log.request_id(),
        transaction_id: access_log.transaction_id(),
        received_at_unix_ms: access_log.request_received_at_unix_ms,
        method: &request_method,
        uri: &request_uri,
        version: request_version,
        headers: request.headers(),
        body: request_body,
        peer_addr: client_addr,
        client_asn,
        downstream_host: host,
        downstream_scheme,
        route_name: &resolved.route.name,
        tcp_max_hop,
        tls: tls.as_ref(),
        protocol,
        transport_network,
        transport_metadata,
        tags: tags_ref(&tags),
        dynamic_policy: &access_log.dynamic_policy,
      },
      evaluated_person_proof.as_ref(),
      dynamic_person_proof_mutation_added,
    )
  } else {
    if !dynamic_person_proof_mutation_added
      && let Some(evaluated) = evaluated_person_proof.as_ref()
      && let Ok(Some(mutation)) = state
        .waf
        .person_proof_clearance_response_mutation(evaluated)
    {
      dynamic_challenge_response_mutations.push(mutation);
    }
    Default::default()
  };
  request_waf
    .response_header_mutations
    .extend(dynamic_challenge_response_mutations);

  if !request_waf.tags.is_empty() {
    let tags = tags.get_or_insert_with(HashMap::new);
    for (key, value) in &request_waf.tags {
      tags.insert(key.clone(), value.clone());
    }
  }
  access_log.set_tags(&tags);

  if let Some(terminal) = request_waf.terminal {
    return waf_http_terminal_response(terminal, &request_waf.response_header_mutations);
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
      resolved.route.effective_path_prefix(),
      static_root,
      &resolved.route.static_files,
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
      host,
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
      state,
      &resolved,
      client_addr,
      host,
      &request_waf,
      request_version,
      connection_limit_context.as_ref(),
      request_connection_permit,
      drain,
      access_log,
      trace_context,
    )
    .await;
  }

  if is_upgrade_request(&request) {
    let stream_waf = if resolved.execution_plan.waf.stream_enabled {
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
          downstream_host: host.to_string(),
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
      state,
      &resolved,
      forwarded_client_addr,
      client_addr,
      host,
      downstream_scheme,
      downstream_port,
      &request_waf,
      stream_waf,
      connection_limit_context.as_ref(),
      request_connection_permit,
      drain,
      access_log,
      trace_context,
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

  let pool_cookie_header = if request_waf.upstream_override.is_none()
    && (request_waf.upstream_pool_override.is_some() || resolved.route.upstream_pool.is_some())
  {
    request.headers().get(http::header::COOKIE)
  } else {
    None
  };
  let selected = match select_request_upstream(
    state.as_ref(),
    &resolved,
    client_addr,
    host,
    request.uri(),
    pool_cookie_header,
    &request_waf,
  ) {
    Ok(selected) => selected,
    Err(error) => return upstream_selection_error_response(error),
  };
  let mut upstream = selected.upstream;
  let mut upstream_index = selected.upstream_index;
  let pool_retry_cookie = selected
    .pool_name()
    .and_then(|_| pool_cookie_header.cloned());
  if let Some(pool_name) = selected.pool_name() {
    if response_waf_enabled {
      access_log.upstream_pool = Some(pool_name.to_string());
    } else {
      access_log.set_upstream_pool(pool_name);
    }
  }
  let mut sticky_cookie = selected.sticky_cookie();
  let mut pool_selection = selected.into_pool_selection();
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
  let cache_enabled_for_route = resolved.execution_plan.features.cache
    && state
      .cache
      .policy_enabled(resolved.route.cache.as_deref(), &request_method);
  let response_actions_need_request_headers =
    resolved.route.actions.response_headers.has_actions() || resolved.route.actions.cors.is_some();
  let request_headers = if cache_enabled_for_route
    || response_waf_enabled
    || native_grpc_request
    || response_actions_need_request_headers
  {
    request.headers().clone()
  } else if resolved.execution_plan.features.compression {
    compression::request_header_subset(request.headers())
  } else {
    HeaderMap::new()
  };

  let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
    warn!(upstream = %upstream.name, "missing precomputed upstream URI parts");
    return text_response(StatusCode::BAD_GATEWAY, "upstream URI is not configured");
  };
  let target_uri = match route_actions::build_resolved_upstream_uri(
    upstream_uri,
    &resolved,
    downstream_scheme,
    host,
    &request_uri,
  ) {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
      return text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite");
    }
  };
  let route_request_mutations = route_runtime::request_header_mutations(resolved.route);

  let rebuild = RebuildRequestOptions {
    target_uri,
    compression: &state.config.compression,
    route_compression: resolved.route.compression.as_deref(),
    forwarded_client_addr,
    downstream_scheme,
    downstream_host: host,
    downstream_port,
    forwarded_header_mode: state.config.proxy.forwarded_headers.mode,
    forwarded_header_cache,
    forwarded_request_header_values: None,
    preserve_host: upstream.preserve_host,
    upstream_version,
    waf_mutations: &request_waf.request_header_mutations,
    route_mutations: &route_request_mutations,
    force_strip_accept_encoding: response_waf_body_compression_transform,
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
  state
    .telemetry
    .inject_trace_context(outbound.headers_mut(), trace_context);
  request_mirror::spawn_request_mirrors(
    state.clone(),
    resolved.route,
    &outbound,
    &request_uri,
    client_addr,
    host,
    downstream_scheme,
  );

  let mut revalidation_entry = None;
  let mut stale_on_error = None;
  let mut _cache_fill_guard = None;
  let mut cache_store_allowed = !cache_enabled_for_route || !state.config.cache.lock;
  let initial_cache_lookup = crate::cache::CacheLookupContext {
    policy_name: resolved.route.cache.as_deref(),
    scheme: downstream_scheme,
    host,
    method: &request_method,
    uri: &request_uri,
    request_headers: &request_headers,
  };
  let lookup = match state.cache.lookup(initial_cache_lookup.clone()) {
    Some(lookup) => Some(lookup),
    None => {
      state
        .cache
        .lookup_external(
          initial_cache_lookup,
          state.config.proxy.buffering.temp_dir.as_deref(),
        )
        .await
    }
  };
  if let Some(lookup) = lookup {
    if let Some(response) = handle_cache_lookup_result(
      state,
      &resolved,
      lookup,
      &mut outbound,
      upstream,
      upstream_version,
      timeouts,
      downstream_scheme,
      host,
      &request_method,
      &request_uri,
      &request_headers,
      request_version,
      transport_network,
      &mut stale_on_error,
      &mut revalidation_entry,
      true,
    ) {
      return response;
    }
  } else if cache_enabled_for_route {
    state.metrics.record_cache_miss();
    record_route_cache_event(state, resolved.route, "miss", "lookup");
  }

  if cache_enabled_for_route {
    loop {
      let Some(permit) = state
        .cache
        .begin_fill_decision(crate::cache::CacheLookupContext {
          policy_name: resolved.route.cache.as_deref(),
          scheme: downstream_scheme,
          host,
          method: &request_method,
          uri: &request_uri,
          request_headers: &request_headers,
        })
      else {
        break;
      };
      match permit {
        crate::cache::CacheFillDecision::Leader(guard) => {
          _cache_fill_guard = Some(guard);
          cache_store_allowed = true;
          if let Some(response) = state
            .cache
            .lookup(crate::cache::CacheLookupContext {
              policy_name: resolved.route.cache.as_deref(),
              scheme: downstream_scheme,
              host,
              method: &request_method,
              uri: &request_uri,
              request_headers: &request_headers,
            })
            .and_then(|lookup| {
              handle_cache_lookup_result(
                state,
                &resolved,
                lookup,
                &mut outbound,
                upstream,
                upstream_version,
                timeouts,
                downstream_scheme,
                host,
                &request_method,
                &request_uri,
                &request_headers,
                request_version,
                transport_network,
                &mut stale_on_error,
                &mut revalidation_entry,
                false,
              )
            })
          {
            return response;
          }
          break;
        }
        crate::cache::CacheFillDecision::Follower(waiter) => {
          state.metrics.record_cache_fill_waiter();
          let lock_wait_started = Instant::now();
          if !waiter
            .wait_timeout(
              state
                .cache
                .lock_wait_timeout(resolved.route.cache.as_deref()),
            )
            .await
          {
            record_route_cache_fill_stage(
              state,
              resolved.route,
              "lock_wait",
              "timeout",
              lock_wait_started,
            );
            state.metrics.record_cache_fill_lock_timeout();
            record_route_cache_event(state, resolved.route, "miss", "fill_lock_timeout");
            break;
          }
          record_route_cache_fill_stage(
            state,
            resolved.route,
            "lock_wait",
            "notified",
            lock_wait_started,
          );
          if let Some(lookup) = state.cache.lookup(crate::cache::CacheLookupContext {
            policy_name: resolved.route.cache.as_deref(),
            scheme: downstream_scheme,
            host,
            method: &request_method,
            uri: &request_uri,
            request_headers: &request_headers,
          }) {
            if let Some(response) = handle_cache_lookup_result(
              state,
              &resolved,
              lookup,
              &mut outbound,
              upstream,
              upstream_version,
              timeouts,
              downstream_scheme,
              host,
              &request_method,
              &request_uri,
              &request_headers,
              request_version,
              transport_network,
              &mut stale_on_error,
              &mut revalidation_entry,
              false,
            ) {
              return response;
            }
          } else {
            state.metrics.record_cache_miss();
            record_route_cache_event(state, resolved.route, "miss", "fill_not_stored");
            break;
          }
        }
        crate::cache::CacheFillDecision::SharedConflict => {
          if let Some(response) = cache_wait::wait_for_shared_fill(
            state,
            &resolved,
            &mut outbound,
            upstream,
            upstream_version,
            timeouts,
            downstream_scheme,
            host,
            &request_method,
            &request_uri,
            &request_headers,
            request_version,
            transport_network,
            &mut stale_on_error,
            &mut revalidation_entry,
          )
          .await
          {
            return response;
          }
          break;
        }
        crate::cache::CacheFillDecision::Suppressed(reason) => {
          record_route_cache_event(state, resolved.route, "miss", reason.as_str());
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
  let mut report_pool_success = true;
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
          return cache_status::stale_if_error_response(entry, &request_method, &request_headers);
        }
        return upstream_error_response(
          state,
          &resolved.route.name,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          host,
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
          return cache_status::stale_if_error_response(entry, &request_method, &request_headers);
        }
        return upstream_error_response(
          state,
          &resolved.route.name,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          host,
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
    let mut pool_failures_reported = false;
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
      let retry_policy = if native_grpc_request {
        EffectiveRetryPolicy::for_grpc_request(
          &state.config,
          resolved.route,
          semantics::should_retry_grpc(&state.config),
        )
      } else if pool_selection.is_some() {
        EffectiveRetryPolicy::for_http_request(&state.config, resolved.route, &request_method)
      } else {
        EffectiveRetryPolicy::for_direct_http_request(
          &state.config,
          resolved.route,
          &request_method,
        )
      };
      if let Some(selection) = pool_selection.take() {
        pool_failures_reported = true;
        send_pool_with_retry(
          state.as_ref(),
          outbound,
          upstream_index,
          selection,
          resolved.route,
          &request_uri,
          &resolved.path_captures,
          client_addr,
          host,
          downstream_scheme,
          pool_retry_cookie.as_ref(),
          &request_waf,
          timeouts,
          &retry_policy,
        )
        .await
        .map(|success| {
          upstream_index = success.upstream_index;
          upstream = &state.upstreams[upstream_index];
          access_log.set_upstream(&upstream.name, upstream.origin.scheme());
          report_pool_success = success.report_success;
          sticky_cookie = success.pool_selection.sticky_cookie();
          pool_selection = Some(success.pool_selection);
          let mut response = success.response;
          if let Some(capture) = early_hints_capture {
            semantics::attach_interim_responses(&mut response, capture.take());
          }
          response
        })
      } else {
        let result = if retry_policy.enabled {
          send_with_retry(client, outbound, timeouts, state, &retry_policy).await
        } else {
          send_one_shot(client, outbound, timeouts).await
        };
        result.map(|mut response| {
          if let Some(capture) = early_hints_capture {
            semantics::attach_interim_responses(&mut response, capture.take());
          }
          response
        })
      }
    } else {
      send_one_shot_with_proxy_protocol(
        outbound,
        upstream,
        state,
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
        if !pool_failures_reported
          && should_report_upstream_request_failure(upstream_first_byte_timeout, grpc_timeout_caps)
        {
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
          return cache_status::stale_if_error_response(entry, &request_method, &request_headers);
        }
        return upstream_error_response(
          state,
          &resolved.route.name,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          host,
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
  if report_pool_success {
    if let Some(latency_ms) = access_log.upstream_first_byte_time_ms {
      state
        .pools
        .report_success_latency(&upstream.name, latency_ms);
    } else {
      state.pools.report_success(&upstream.name);
    }
  }
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
    return cache_status::stale_if_error_response(entry, &request_method, &request_headers);
  }
  if parts.status == StatusCode::NOT_MODIFIED
    && let Some(entry) = revalidation_entry.clone()
  {
    if cache_store_allowed {
      state.cache.update_from_not_modified(
        crate::cache::CacheInsertContext {
          policy_name: resolved.route.cache.as_deref(),
          scheme: downstream_scheme,
          host,
          method: &request_method,
          uri: &request_uri,
          request_headers: &request_headers,
        },
        &entry,
        &parts.headers,
      );
    }
    let mut cached_entry = entry;
    let mut headers = cached_entry.headers.clone();
    merge_not_modified_headers(&mut headers, &parts.headers);
    cached_entry.headers = headers;
    state.metrics.record_cache_hit();
    let mut response =
      cache_status::cached_entry_response(cached_entry, &request_method, &request_headers);
    route_runtime::apply_response_actions(response.headers_mut(), resolved.route, &request_headers);
    cache_status::apply(
      &mut response,
      CacheOutcome::Revalidated,
      CacheReason::NotModified,
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
        warn!(error = %error, status = status.as_u16(), "failed to read upstream response body for WAF inspection");
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
      method: &request_method,
      uri: &request_uri,
      version: request_version,
      headers: &request_headers,
      body: request_body,
      peer_addr: client_addr,
      client_asn,
      downstream_host: host,
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
      return waf_http_terminal_response(terminal, &mutations);
    }
    apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
  }
  route_runtime::apply_response_actions(&mut parts.headers, resolved.route, &request_headers);
  cache_status::strip_headers(&mut parts.headers);
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

  let response = maybe_cache_response_with_store_permission(
    Response::from_parts(parts, body),
    state,
    resolved.route.cache.as_deref(),
    downstream_scheme,
    host,
    &request_method,
    &request_uri,
    &request_headers,
    Some(resolved.route),
    cache_store_allowed,
    _cache_fill_guard.take(),
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
  let mut response =
    with_downstream_response_timeout(response, timeouts.response_send, transport_network);
  apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
  state.record_hot_path_response(response.status());
  response
}

pub(super) fn with_downstream_response_timeout(
  response: Response<ProxyBody>,
  timeout: Duration,
  transport_network: WafTransportNetwork,
) -> Response<ProxyBody> {
  if transport_network == WafTransportNetwork::Udp {
    return mark_downstream_response_timeout(response, timeout);
  }

  let (mut parts, body) = response.into_parts();
  if parts
    .extensions
    .get::<body::KnownSmallResponseBody>()
    .is_some()
  {
    return Response::from_parts(parts, body);
  }
  parts
    .extensions
    .insert(DownstreamResponseSendTimeout(timeout));
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
  _trace_context: Option<TraceContext>,
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
    request.headers().get(http::header::COOKIE),
    request_waf,
  ) {
    Ok(selected) => selected,
    Err(error) => return upstream_selection_error_response(error),
  };
  let upstream = selected.upstream.clone();
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, &upstream);
  access_log.set_upstream(&upstream.name, upstream.origin.scheme());
  if let Some(pool_name) = selected.pool_name() {
    access_log.set_upstream_pool(pool_name);
  }
  let sticky_cookie = selected.sticky_cookie();
  let pool_report = state.pools.clone();
  let pool_selection = selected.into_pool_selection();
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
    let mut response = Response::builder()
      .status(StatusCode::OK)
      .body(full_body(bytes::Bytes::new()))
      .expect("CONNECT response should build");
    apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
    return response;
  }

  match dial_tunnel_upstream(&upstream, client_addr, timeouts).await {
    Ok(upstream_stream) => {
      let body = bridge_connect_body(request.into_body(), upstream_stream, timeouts, drain);
      drop(pool_selection);
      let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .expect("CONNECT response should build");
      apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
      response
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
  forwarded_client_addr: std::net::SocketAddr,
  client_addr: std::net::SocketAddr,
  downstream_host: &str,
  downstream_scheme: &str,
  downstream_port: u16,
  request_waf: &crate::waf::RequestWafDecision,
  stream_waf: Option<StreamWafRequestContext>,
  connection_limit_context: Option<&ConnectionLimitContext>,
  request_connection_permit: &mut Option<ConnectionPermit>,
  drain: ConnectionDrain,
  access_log: &mut SystemAccessLogContext<'_>,
  trace_context: Option<TraceContext>,
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

  let selected = match select_request_upstream(
    state.as_ref(),
    resolved,
    client_addr,
    downstream_host,
    request.uri(),
    request.headers().get(http::header::COOKIE),
    request_waf,
  ) {
    Ok(selected) => selected,
    Err(error) => return Some(upstream_selection_error_response(error)),
  };
  let upstream = selected.upstream;
  if let Some(pool_name) = selected.pool_name() {
    access_log.set_upstream_pool(pool_name);
  }
  let sticky_cookie = selected.sticky_cookie();
  let pool_selection = selected.into_pool_selection();
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
  let target_uri = match route_actions::build_resolved_upstream_uri(
    upstream_uri,
    resolved,
    downstream_scheme,
    downstream_host,
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
  if upstream.preserve_host {
    set_effective_host_header(&mut parts.headers, downstream_host);
  } else {
    parts.headers.remove(http::header::HOST);
  }
  add_forwarded_headers(
    &mut parts.headers,
    forwarded_client_addr,
    downstream_host,
    downstream_scheme,
    downstream_port,
    state.config.proxy.forwarded_headers.mode,
    None,
  );
  apply_header_mutations(&mut parts.headers, &request_waf.request_header_mutations);
  state
    .telemetry
    .inject_trace_context(&mut parts.headers, trace_context);
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
  let route_name = resolved.route.name.clone();
  let stream_waf_state = state.clone();
  let websocket_metrics_state = state.clone();
  let websocket_started_at = TelemetryRuntime::start();
  if websocket_upgrade {
    state.metrics.record_websocket_session_start(
      &state.config.metrics,
      &route_name,
      &upstream_name,
    );
  }
  let websocket_stream_waf = if websocket_upgrade { stream_waf } else { None };
  let connection_limit_hold =
    TunnelConnectionLimitHold::capture(request_connection_permit, connection_limit_context);
  let websocket_guard = websocket_upgrade.then(|| {
    state
      .runtime_introspection
      .guard(RuntimeCounter::WebSocketTunnel)
  });
  tokio::spawn(async move {
    let _websocket_guard = websocket_guard;
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
    if websocket_upgrade {
      record_websocket_session_end(
        &websocket_metrics_state,
        &route_name,
        &upstream_name,
        trace_context,
        websocket_started_at,
        if result.is_ok() { "closed" } else { "error" },
      );
    }
  });
  drop(pool_selection);
  let mut response = upstream_response.map(|body| body.map_err(boxed_error).boxed());
  apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
  Some(response)
}

fn is_websocket_upgrade<B>(request: &Request<B>) -> bool {
  request
    .headers()
    .get(http::header::UPGRADE)
    .and_then(|value| value.to_str().ok())
    .map(|value| value.eq_ignore_ascii_case("websocket"))
    .unwrap_or(false)
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
    let revocation_policy = state.outbound_revocation.policy_for_upstream(upstream);
    let revocation = Some((&state.outbound_revocation, revocation_policy));
    let mut tls_config = crate::tls::build_upstream_client_config_with_resumption_and_revocation(
      &state.config.proxy.trusted_ca_certs,
      &upstream.tls.ech,
      &upstream.tls.resumption,
      Some(&state.tls_resumption),
      &upstream.name,
      revocation,
    )
    .context("failed to build one-shot upstream TLS config")?;
    tls_config.alpn_protocols = vec![upstream_version.as_alpn().to_vec()];
    let Some(host) = upstream.origin.host_str() else {
      anyhow::bail!("upstream origin has no host");
    };
    let host = host.to_string();
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

pub(super) fn is_idempotent(method: &Method) -> bool {
  matches!(
    *method,
    Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
  )
}

pub(crate) fn validate_request_limits<B>(
  request: &Request<B>,
  limits: &crate::config::LimitsConfig,
) -> Result<(), (StatusCode, &'static str)> {
  if uri_wire_len(request.uri()) > limits.max_uri_bytes {
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
  match request_body_framing(request.headers()) {
    RequestBodyFraming::Ambiguous => {
      return Err((StatusCode::BAD_REQUEST, "ambiguous request body framing"));
    }
    RequestBodyFraming::InvalidContentLength => {
      return Err((StatusCode::BAD_REQUEST, "invalid request body framing"));
    }
    _ => {}
  }
  Ok(())
}

pub(crate) fn validate_request_body_size_limit<B>(
  request: &Request<B>,
  max_request_body_bytes: u64,
) -> Result<(), (StatusCode, &'static str)> {
  if positive_content_length(request.headers())
    .is_some_and(|length| length > max_request_body_bytes)
  {
    return Err((StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"));
  }
  Ok(())
}

fn uri_wire_len(uri: &http::Uri) -> usize {
  let mut len = 0usize;
  let has_scheme = uri.scheme_str().is_some();
  if let Some(scheme) = uri.scheme_str() {
    len += scheme.len() + 1;
  }
  if let Some(authority) = uri.authority() {
    if has_scheme {
      len += 2;
    }
    len += authority.as_str().len();
  }
  if let Some(path_and_query) = uri.path_and_query() {
    len += path_and_query.as_str().len();
  }
  len
}

async fn reject_content_length_zero_data<B>(
  request: Request<B>,
  timeout: Duration,
  version: http::Version,
) -> Result<Request<Either<B, ProxyBody>>, Response<ProxyBody>>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + Unpin + 'static,
{
  if !h2_or_h3_content_length_zero_guard_required(version, request.headers()) {
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

  let mut request = Request::from_parts(parts, Either::Right(full_body(bytes::Bytes::new())));
  request
    .extensions_mut()
    .insert(VerifiedContentLengthZeroBody);
  Ok(request)
}

#[allow(clippy::too_many_arguments)]
fn handle_cache_lookup_result(
  state: &Arc<AppSnapshot>,
  resolved: &crate::routes::ResolvedRoute<'_>,
  lookup: crate::cache::CacheLookup,
  outbound: &mut Request<ProxyBody>,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  timeouts: EffectiveTimeouts,
  downstream_scheme: &'static str,
  host: &str,
  request_method: &Method,
  request_uri: &http::Uri,
  request_headers: &HeaderMap,
  request_version: http::Version,
  transport_network: WafTransportNetwork,
  stale_on_error: &mut Option<crate::cache::CacheEntry>,
  revalidation_entry: &mut Option<crate::cache::CacheEntry>,
  record_events: bool,
) -> Option<Response<ProxyBody>> {
  match lookup {
    crate::cache::CacheLookup::Fresh(entry) => {
      if cache_entry_blocked_by_waf_body_transform(state.as_ref(), resolved, &entry) {
        return None;
      }
      state.metrics.record_cache_hit();
      if record_events {
        record_route_cache_event(state, resolved.route, "hit", "fresh");
      }
      let mut response = cache_status::cached_downstream_response(
        state,
        resolved.route,
        entry,
        request_method,
        request_headers,
        timeouts,
        transport_network,
        CacheOutcome::Hit,
        CacheReason::Fresh,
      );
      route_runtime::apply_response_actions(
        response.headers_mut(),
        resolved.route,
        request_headers,
      );
      Some(response)
    }
    crate::cache::CacheLookup::Stale(stale) => {
      let stale_blocked_by_transform =
        cache_entry_blocked_by_waf_body_transform(state.as_ref(), resolved, &stale.entry);
      if stale.background_refresh
        && !stale_blocked_by_transform
        && can_background_refresh(resolved.execution_plan.waf, upstream, upstream_version)
        && spawn_background_refresh(
          state.clone(),
          outbound,
          upstream,
          upstream_version,
          timeouts,
          resolved.route.cache.as_deref(),
          downstream_scheme,
          host.to_string(),
          request_method.clone(),
          request_uri.clone(),
          request_headers.clone(),
          request_version,
          stale.clone(),
        )
      {
        state.metrics.record_cache_stale();
        if record_events {
          record_route_cache_event(state, resolved.route, "stale", "background_refresh");
        }
        let mut response = cache_status::cached_downstream_response(
          state,
          resolved.route,
          stale.entry,
          request_method,
          request_headers,
          timeouts,
          transport_network,
          CacheOutcome::Stale,
          CacheReason::BackgroundRefresh,
        );
        route_runtime::apply_response_actions(
          response.headers_mut(),
          resolved.route,
          request_headers,
        );
        return Some(response);
      }
      if !stale.request_headers.is_empty() {
        state.metrics.record_cache_revalidation();
        if record_events {
          record_route_cache_event(state, resolved.route, "revalidate", "stale_validators");
        }
        for (name, value) in &stale.request_headers {
          outbound.headers_mut().insert(name.clone(), value.clone());
        }
        if !stale_blocked_by_transform {
          if stale.serve_stale_on_error {
            *stale_on_error = Some(stale.entry.clone());
          }
          *revalidation_entry = Some(stale.entry);
        }
        None
      } else {
        if stale_blocked_by_transform {
          return None;
        }
        state.metrics.record_cache_hit();
        if record_events {
          record_route_cache_event(state, resolved.route, "hit", "stale_without_validators");
        }
        let mut response = cache_status::cached_downstream_response(
          state,
          resolved.route,
          stale.entry,
          request_method,
          request_headers,
          timeouts,
          transport_network,
          CacheOutcome::Stale,
          CacheReason::StaleWithoutValidators,
        );
        route_runtime::apply_response_actions(
          response.headers_mut(),
          resolved.route,
          request_headers,
        );
        Some(response)
      }
    }
    crate::cache::CacheLookup::Revalidate(revalidation) => {
      let revalidation_blocked_by_transform =
        cache_entry_blocked_by_waf_body_transform(state.as_ref(), resolved, &revalidation.entry);
      state.metrics.record_cache_revalidation();
      if record_events {
        record_route_cache_event(state, resolved.route, "revalidate", "explicit");
      }
      for (name, value) in &revalidation.request_headers {
        outbound.headers_mut().insert(name.clone(), value.clone());
      }
      if !revalidation_blocked_by_transform {
        if revalidation.serve_stale_on_error {
          *stale_on_error = Some(revalidation.entry.clone());
        }
        *revalidation_entry = Some(revalidation.entry);
      }
      None
    }
  }
}

fn can_background_refresh(
  waf: crate::routes::RouteWafExecutionPlan,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
) -> bool {
  upstream_version != HttpVersion::H3
    && upstream.proxy_protocol_egress == ProxyProtocolEgressMode::Off
    && !waf.response.enabled()
}

fn cache_entry_blocked_by_waf_body_transform(
  state: &AppSnapshot,
  resolved: &crate::routes::ResolvedRoute<'_>,
  entry: &crate::cache::CacheEntry,
) -> bool {
  crate::waf::route_http_body_compression_transform_enabled(&state.config, resolved.route)
    && resolved.execution_plan.waf.response.body_need() != BodyNeed::None
    && has_non_identity_content_encoding(&entry.headers)
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
  let retry_policy = EffectiveRetryPolicy::disabled_direct();
  let response = send_with_retry(client, outbound, timeouts, &state, &retry_policy).await?;
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
    crate::cache::CacheEntry::memory(parts.status, parts.headers, bytes),
  ) {
    crate::cache::CacheInsertOutcome::Stored => {
      state.metrics.record_cache_background_refresh_success();
    }
    crate::cache::CacheInsertOutcome::Rejected => {
      state.metrics.record_cache_admission_rejection();
      state.metrics.record_cache_background_refresh_skip();
    }
    crate::cache::CacheInsertOutcome::AdmissionWarming => {
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

#[cfg(test)]
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
  route: Option<&RouteConfig>,
) -> Response<ProxyBody> {
  maybe_cache_response_with_store_permission(
    response,
    state,
    route_cache,
    scheme,
    host,
    method,
    uri,
    request_headers,
    route,
    true,
    None,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
async fn maybe_cache_response_with_store_permission(
  response: Response<ProxyBody>,
  state: &AppSnapshot,
  route_cache: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
  request_headers: &HeaderMap,
  route: Option<&RouteConfig>,
  allow_store: bool,
  mut cache_fill_guard: Option<crate::cache::CacheFillGuard>,
) -> Response<ProxyBody> {
  if !state.request_path_features.cache || !state.cache.policy_enabled(route_cache, method) {
    let mut response = response;
    cache_status::strip_headers(response.headers_mut());
    return response;
  }
  let (mut parts, mut body) = response.into_parts();
  cache_status::strip_headers(&mut parts.headers);
  if !allow_store {
    if state.cache.strip_surrogate_control(route_cache) {
      parts.headers.remove("surrogate-control");
    }
    let mut response = Response::from_parts(parts, body);
    cache_status::apply(
      &mut response,
      CacheOutcome::Miss,
      CacheReason::StoreNotAllowed,
    );
    return response;
  }
  let content_length = cache_streaming::exact_response_content_length(&parts.headers);
  let insert_ctx = || crate::cache::CacheInsertContext {
    policy_name: route_cache,
    scheme,
    host,
    method,
    uri,
    request_headers,
  };
  let record_fill_stage = |stage: &str, outcome: &str, started: Instant| {
    if let Some(route) = route {
      record_route_cache_fill_stage(state, route, stage, outcome, started);
    }
  };
  let head_started = Instant::now();
  let prepared =
    match state
      .cache
      .prepare_insert(insert_ctx(), parts.status, &parts.headers, content_length)
    {
      crate::cache::CachePreparedInsertDecision::Cacheable(prepared) => {
        record_fill_stage("head_decision", "cacheable", head_started);
        prepared
      }
      crate::cache::CachePreparedInsertDecision::Rejected(reason) => {
        record_fill_stage("head_decision", reason.as_str(), head_started);
        state.metrics.record_cache_admission_rejection();
        state
          .cache
          .note_fill_not_stored_reason(insert_ctx(), reason);
        if state.cache.strip_surrogate_control(route_cache) {
          parts.headers.remove("surrogate-control");
        }
        let mut response = Response::from_parts(parts, body);
        cache_status::apply(
          &mut response,
          CacheOutcome::Miss,
          CacheReason::from_rejection(reason),
        );
        return response;
      }
      crate::cache::CachePreparedInsertDecision::NotCacheable(reason) => {
        record_fill_stage("head_decision", reason.as_str(), head_started);
        state
          .cache
          .note_fill_not_stored_reason(insert_ctx(), reason);
        if state.cache.strip_surrogate_control(route_cache) {
          parts.headers.remove("surrogate-control");
        }
        let mut response = Response::from_parts(parts, body);
        cache_status::apply(
          &mut response,
          CacheOutcome::Miss,
          CacheReason::from_rejection(reason),
        );
        return response;
      }
    };
  let collect_limit = cache_streaming::response_collect_limit(&state.config);
  let body_size_hint = body.size_hint();
  let known_body_len =
    content_length.or_else(|| cache_streaming::exact_body_size_hint_len(&body_size_hint));
  if known_body_len.is_none_or(|len| len > collect_limit) {
    if let Some(expected_body_len) = known_body_len {
      match cache_streaming::maybe_stream_cache_response(
        state,
        route_cache,
        scheme,
        host,
        method,
        uri,
        request_headers,
        route,
        parts,
        body,
        prepared,
        expected_body_len,
        cache_fill_guard.take(),
      ) {
        Ok(response) => return response,
        Err(returned) => {
          let (returned_parts, returned_body) = *returned;
          parts = returned_parts;
          body = returned_body;
        }
      }
    }
    record_fill_stage("body_collect", "too_large", Instant::now());
    state.cache.note_fill_not_stored_reason(
      insert_ctx(),
      crate::cache::CacheFillSuppressionReason::TooLarge,
    );
    if state.cache.strip_surrogate_control(route_cache) {
      parts.headers.remove("surrogate-control");
    }
    let mut response = Response::from_parts(parts, body);
    cache_status::apply(&mut response, CacheOutcome::Miss, CacheReason::TooLarge);
    return response;
  }
  let collect_started = Instant::now();
  match collect_cache_response_body(body, collect_limit).await {
    Ok(bytes) => {
      record_fill_stage("body_collect", "ok", collect_started);
      if state.cache.strip_surrogate_control(route_cache) {
        parts.headers.remove("surrogate-control");
      }
      let store_started = Instant::now();
      let reason = match state.cache.insert_prepared(
        *prepared,
        crate::cache::CacheEntry::memory(parts.status, parts.headers.clone(), bytes.clone()),
      ) {
        crate::cache::CacheInsertOutcome::Rejected => {
          record_fill_stage("local_store", "rejected", store_started);
          state.metrics.record_cache_admission_rejection();
          state.cache.note_fill_not_stored_reason(
            insert_ctx(),
            crate::cache::CacheFillSuppressionReason::AdmissionRejected,
          );
          CacheReason::AdmissionRejected
        }
        crate::cache::CacheInsertOutcome::AdmissionWarming => {
          record_fill_stage("local_store", "admission_warming", store_started);
          state.metrics.record_cache_admission_rejection();
          CacheReason::AdmissionWarming
        }
        crate::cache::CacheInsertOutcome::StoreFailed => {
          record_fill_stage("local_store", "store_failed", store_started);
          state.metrics.record_cache_fill_error();
          state.cache.note_fill_not_stored_reason(
            insert_ctx(),
            crate::cache::CacheFillSuppressionReason::StoreFailed,
          );
          CacheReason::StoreFailed
        }
        crate::cache::CacheInsertOutcome::NotCacheable => {
          record_fill_stage("local_store", "not_cacheable", store_started);
          state.cache.note_fill_not_stored(insert_ctx());
          CacheReason::NotCacheable
        }
        crate::cache::CacheInsertOutcome::Stored => {
          record_fill_stage("local_store", "stored", store_started);
          if state.cache.shared_cache_enabled() {
            record_fill_stage("shared_store", "submitted", Instant::now());
          }
          CacheReason::Stored
        }
      };
      let body_len = bytes.len();
      let mut response = Response::from_parts(parts, full_body(bytes));
      cache_status::apply(&mut response, CacheOutcome::Miss, reason);
      if body::is_known_small_response_body_len(body_len) {
        response
          .extensions_mut()
          .insert(body::KnownSmallResponseBody);
      }
      response
    }
    Err(error) if error_is_timeout(&error, BodyTimeoutKind::UpstreamResponseRead) => {
      record_fill_stage("body_collect", "timeout", collect_started);
      state.metrics.record_cache_fill_error();
      cache_status::store_failed_response(text_response(
        StatusCode::GATEWAY_TIMEOUT,
        "upstream response body timed out",
      ))
    }
    Err(error) => {
      record_fill_stage("body_collect", "error", collect_started);
      state.metrics.record_cache_fill_error();
      cache_status::store_failed_response(text_response(
        StatusCode::BAD_GATEWAY,
        &format!("failed to read upstream response body: {error}"),
      ))
    }
  }
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

  if chunks.len() == 1 {
    return Ok(chunks.pop().unwrap_or_default());
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
      name.as_str(),
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

#[cfg(test)]
mod cache_tests;

#[cfg(test)]
mod webtransport_tests;

#[cfg(test)]
mod body_capture_tests;

#[cfg(test)]
mod tests;
