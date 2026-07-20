//! HTTP data-plane forwarding for downstream requests and upstream responses.
//! Security-sensitive framing, header, body, and WAF decisions stay explicit in this module tree.

use std::collections::HashMap;
use std::net::SocketAddr;
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
  ConnectionLimitIdentityMode, HttpVersion, ProxyHttp2Config, ProxyProtocolEgressMode, RouteConfig,
  UpstreamConfig,
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
  WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations,
};

pub(crate) mod access_log;
mod alt_svc;
pub(crate) mod body;
mod body_capture;
pub(crate) mod buffering;
mod cache_operations;
mod cache_refresh;
mod cache_status;
mod cache_streaming;
mod cache_wait;
mod circuit_breakers;
pub(crate) mod compression;
pub(crate) mod early_data;
mod entry;
pub(crate) mod fast_path;
mod flow_helpers;
pub(crate) mod grpc_web;
pub(crate) mod headers;
pub(crate) mod observability;
mod overload;
pub(crate) mod person_proof;
mod pipeline;
mod priority_admission;
pub(crate) mod request;
pub(crate) mod request_framing;
mod request_mirror;
mod request_validation;
pub(crate) mod response;
mod response_timeout;
mod retry;
mod route_action_runtime;
mod route_actions;
pub(crate) mod semantics;
pub(crate) mod static_files;
mod tcp_exchange;
mod timeouts;
mod tls_policy;
mod tunnel;
pub(crate) mod upstream;
pub(crate) mod uri;
pub(crate) mod version;
mod waf_body_capture;
pub(crate) mod waf_body_coding;
pub(crate) mod webtransport;

#[cfg(feature = "admin-runtime")]
pub(crate) mod warm;
#[cfg(feature = "admin-runtime")]
pub(crate) use warm::warm_cache_request;

pub(crate) use self::access_log::SystemAccessLogContext;
#[cfg(test)]
use self::alt_svc::should_add_alt_svc;
use self::alt_svc::{apply_alt_svc_header, apply_response_alt_svc};
use self::body::{
  BodyTimeoutKind, ProxyBody, boxed_error, error_indicates_body_timeout, error_is_timeout,
  with_connection_permit,
};
use self::cache_status::{CacheHeaderOutcome as CacheOutcome, CacheHeaderReason as CacheReason};
use self::circuit_breakers::{
  rejection_response as circuit_breaker_rejection_response,
  with_request_lease as with_circuit_breaker_request_lease,
};
#[cfg(feature = "admin-runtime")]
pub(crate) use self::entry::handle_inner;
pub(crate) use self::entry::{handle, handle_http3, handle_with_forwarded_header_cache};
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
use self::overload::{content_length, overload_response, with_overload_request_lease};
use self::person_proof::handle_person_proof_api;
use self::request::{RebuildRequestOptions, rebuild_request};
use self::request_framing::{
  RequestBodyFraming, VerifiedContentLengthZeroBody, h2_or_h3_content_length_zero_guard_required,
  positive_content_length, request_body_framing,
};
use self::response::{
  AppliedRouteSecurityHeaders, RouteSecurityHeaders, apply_route_security_headers_with_snapshot,
  apply_sticky_cookie, draining_response, external_auth_response,
  neutralize_applied_route_security_headers, proxy_error_response,
  request_buffering_error_response, response_buffering_error_response, silent_close_response,
  text_response, upstream_error_response, upstream_selection_error_response,
  with_pending_dynamic_person_proof_response_mutations,
};
#[cfg(test)]
pub(crate) use self::response_timeout::{
  DownstreamResponseSendTimeout, DownstreamResponseTimeoutSelected,
  DownstreamResponseTimeoutSelection,
};
pub(crate) use self::response_timeout::{
  downstream_response_send_timeout, with_downstream_response_timeout,
};
use self::retry::{
  EffectiveRetryPolicy, RetryAdmissionContext, send_one_shot_with_state, send_pool_with_retry,
  send_with_retry,
};
use self::route_action_runtime as route_runtime;
use self::semantics::filter_trailers;
use self::upstream::select_request_upstream;
use self::uri::validate_downstream_path;
use cache_operations::*;
use request_validation::*;
pub(crate) use request_validation::{validate_request_body_size_limit, validate_request_limits};
pub(super) use tcp_exchange::is_idempotent;
use tcp_exchange::*;
use tunnel::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct DownstreamListenerBind(pub(crate) SocketAddr);
pub(crate) use self::timeouts::EffectiveTimeouts;
use self::version::select_upstream_http_version;
pub(crate) use self::waf_body_capture::{
  capture_request_body_for_waf, capture_response_body_for_waf, request_body_capture_error_response,
  response_body_capture_error_response, waf_body_input,
};
use self::waf_body_coding::has_non_identity_content_encoding;
pub(crate) use self::webtransport::{PreparedWebTransport, prepare_webtransport};
pub(crate) use tls_policy::route_matches_selected_tls_negotiation_policy;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_inner_impl<B>(
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

  if state
    .overload
    .reject_large_request_body(content_length(request.headers()))
  {
    return overload_response(state.as_ref(), request.version());
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
  let listener_bind = request
    .extensions()
    .get::<DownstreamListenerBind>()
    .map(|bind| bind.0);
  let tags: Option<HashMap<String, String>> = None;
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
        state.limits.acquire_ip_connection_async(
          ip,
          &state.config.limits,
          &state.config.connection_limits,
        )
      };
      let result = if let Some(context) = connection_limit_context.as_ref() {
        context.bind_first_request(client_addr.ip(), acquire).await
      } else {
        match acquire(client_addr.ip()).await {
          Ok(permit) => {
            *request_connection_permit = Some(permit);
            Ok(())
          }
          Err(status) => Err(status),
        }
      };
      if let Err(status) = result {
        return text_response(status, "connection limit exceeded");
      }
    }
    ConnectionLimitIdentityMode::PerRequestRealIp => {
      match state
        .limits
        .acquire_ip_connection_async(
          client_addr.ip(),
          &state.config.limits,
          &state.config.connection_limits,
        )
        .await
      {
        Ok(permit) => *request_connection_permit = Some(permit),
        Err(status) => return text_response(status, "connection limit exceeded"),
      }
    }
  }

  if state.request_path_features.rate_limits
    && let Some(status) = state
      .limits
      .check_pre_route_rate_limits_async(client_addr.ip(), &state.config.rate_limits)
      .await
  {
    return text_response(status, "rate limit exceeded");
  }

  let route_resolution_started =
    fast_path::stage_timing::start(state.request_path_features.stage_timing_metrics);
  let metric_protocol = fast_path::stage_timing::protocol(request_version);
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
  fast_path::stage_timing::record_route_resolution(
    state.as_ref(),
    metric_protocol,
    resolved.is_some(),
    route_resolution_started,
  );
  let Some(resolved) = resolved else {
    return text_response(StatusCode::NOT_FOUND, "no matching route");
  };
  let route_security = RouteSecurityHeaders::new(&state.config.security, resolved.route);
  if state
    .overload
    .reject_priority(resolved.route.priority_class)
  {
    return route_security.apply(overload_response(state.as_ref(), request_version));
  }
  if !route_matches_selected_tls_negotiation_policy(state.as_ref(), tls.as_ref(), resolved.route) {
    warn!(
      sni = ?tls.sni,
      host = %host,
      route = %resolved.route.name,
      "rejected downstream request with mismatched SNI-selected TLS policy"
    );
    return route_security.text(StatusCode::MISDIRECTED_REQUEST, "misdirected request");
  }
  if let Some(response) = early_data::reject_if_disallowed(&request, &state.config, resolved.route)
  {
    return route_security.apply(response);
  }
  access_log.set_route_name(&resolved.route.name);
  let route_circuit_breaker_lease = match state
    .circuit_breakers
    .admit_route_scope_request(&resolved.route.name, None)
    .await
  {
    Ok(lease) => lease,
    Err(rejection) => {
      return route_security.apply(circuit_breaker_rejection_response(state, rejection));
    }
  };
  let max_request_body_bytes = resolved
    .route
    .effective_max_request_body_bytes(&state.config.limits);
  if let Err((status, message)) = validate_request_body_size_limit(&request, max_request_body_bytes)
  {
    return route_security.text(status, message);
  }

  if let Some(response) =
    route_runtime::cors_preflight_response(resolved.route, request.method(), request.headers())
  {
    return route_security.apply(response);
  }

  if resolved.execution_plan.features.ipm {
    let Some(actor) = state.ipm.actor_from_headers(request.headers()) else {
      return route_security.text(StatusCode::UNAUTHORIZED, "unauthorized");
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
      return route_security.text(StatusCode::FORBIDDEN, "forbidden");
    }
  }

  let verified_early_data = early_data::is_verified(&request);
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
      Ok(response) => {
        return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
      }
      Err(request) => request,
    }
  } else {
    request
  };
  let client_body_timeout = EffectiveTimeouts::route_body_only(&state.config, resolved.route);
  let request =
    match reject_content_length_zero_data(request, client_body_timeout, request_version).await {
      Ok(request) => request,
      Err(response) => {
        return route_security.apply(response);
      }
    };
  let request = if cl0_guard_required {
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
      Ok(response) => {
        return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
      }
      Err(request) => request,
    }
  } else {
    request
  };
  pipeline::run(pipeline::InitialContext {
    request,
    state,
    resolved,
    host,
    downstream_port,
    client_addr,
    forwarded_client_addr,
    forwarded_header_cache,
    tcp_max_hop,
    tls: &tls,
    protocol,
    transport_network,
    transport_metadata,
    downstream_scheme,
    request_version,
    listener_bind,
    connection_limit_context: connection_limit_context.as_ref(),
    drain,
    access_log,
    request_connection_permit,
    trace_context,
    route_circuit_breaker_lease,
    tags,
    client_body_timeout,
    max_request_body_bytes,
    verified_early_data,
  })
  .await
}

#[cfg(test)]
mod body_capture_tests;
#[cfg(test)]
mod cache_tests;
#[cfg(test)]
mod early_data_rate_limit_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod webtransport_tests;
