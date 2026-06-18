//! Optimized HTTP forwarding paths that are only used when policy permits bypassing slower work.
//! Each shortcut keeps WAF, body, cache, and protocol preconditions explicit.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use http::header::COOKIE;
use http::{HeaderMap, Request, Response, StatusCode};
use hyper::body::Body;
use tracing::warn;

use crate::config::{HttpVersion, ProxyProtocolEgressMode};
use crate::proxy::http::SystemAccessLogContext;
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody, error_indicates_body_timeout};
use crate::proxy::http::headers::{
  ForwardedHeaderCache, ForwardedRequestHeaderValues, strip_hop_by_hop_headers,
};
use crate::proxy::http::request::{RebuildRequestOptions, rebuild_request_parts};
use crate::proxy::http::request_framing::VerifiedContentLengthZeroBody;
use crate::proxy::http::response::{
  apply_security_headers, apply_sticky_cookie, text_response, waf_terminal_response,
};
use crate::proxy::http::route_actions::{self, RouteActionRenderContext};
use crate::proxy::http::semantics::{self, configured_error_response};
use crate::proxy::http::upstream::select_request_upstream;
use crate::proxy::http::uri::{self, UpstreamUriParts};
use crate::proxy::http::version::select_upstream_http_version;
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::telemetry::TraceContext;
use crate::waf::{
  RequestWafDecision, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations,
};

use super::{
  EffectiveRetryPolicy, EffectiveTimeouts, apply_alt_svc_header, send_one_shot,
  send_pool_with_retry, send_with_retry,
};

mod decision;
mod direct;
pub(crate) mod direct_h1;
pub(crate) mod direct_h2;
mod direct_transport;
mod helpers;
mod request_body;
mod response_body;
mod small_response;
mod waf;
#[cfg(test)]
use self::decision::PlainProxyFastPathMissReason;
use self::decision::{plain_proxy_fast_path_decision, record_plain_proxy_fast_path_decision};
use self::direct::{direct_http_retry_enabled, select_direct_fast_path_upstream};
pub(crate) use self::direct_h1::DirectH1Pools;
use self::direct_h1::{DirectH1SendResult, recycle_response_body, try_send_direct_h1};
pub(crate) use self::direct_h2::DirectH2Pools;
use self::direct_h2::{DirectH2SendResult, try_send_direct_h2};
use self::direct_transport::{DirectFastPathTransport, direct_fast_path_transport};
use self::helpers::{
  apply_fast_path_priority_policy, fast_path_downstream_response_timeout,
  fast_path_metric_protocol, fast_path_outbound_request_body,
};
#[cfg(test)]
use self::request_body::fast_path_empty_request_body;
use self::request_body::{
  FastPathRequestBody, fast_path_request_body, fast_path_request_body_empty_probe_allowed,
  fast_path_request_body_is_definitely_empty,
};
use self::response_body::{
  FastPathResponseBody, fast_path_filter_trailers, fast_path_response_body,
};
use self::waf::{PlainFastPathWaf, plain_fast_path_waf_required, prepare_plain_fast_path_waf};

static EMPTY_TAGS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);

fn tags_ref(tags: &Option<HashMap<String, String>>) -> &HashMap<String, String> {
  tags.as_ref().unwrap_or(&EMPTY_TAGS)
}

fn fast_path_upstream_timing_required(
  state: &AppSnapshot,
  response_waf_enabled: bool,
  pool_selected: bool,
) -> bool {
  response_waf_enabled
    || pool_selected
    || state.request_path_features.system_access_log
    || state.request_path_features.detailed_metrics
    || state.request_path_features.telemetry
}

fn elapsed_ms(started_at: Instant) -> u64 {
  started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn request_body_definitely_empty<B: hyper::body::Body>(request: &Request<B>) -> bool {
  fast_path_request_body_is_definitely_empty(request.version(), request.headers())
    || request.body().is_end_stream()
    || request
      .extensions()
      .get::<VerifiedContentLengthZeroBody>()
      .is_some()
}

fn fast_path_target_uri(
  origin: &UpstreamUriParts,
  resolved: &ResolvedRoute<'_>,
  downstream_scheme: &str,
  downstream_host: &str,
  downstream_uri: &http::Uri,
) -> anyhow::Result<http::Uri> {
  if resolved.route.actions.rewrite.is_none() {
    return uri::rewrite_uri(
      origin,
      resolved.route.effective_path_prefix(),
      resolved.route.replace_prefix_with.as_deref(),
      downstream_uri,
    );
  }

  route_actions::build_upstream_uri(
    origin,
    resolved.route,
    RouteActionRenderContext {
      route_prefix: resolved.route.effective_path_prefix(),
      path_captures: &resolved.path_captures,
      downstream_scheme,
      downstream_host,
      downstream_uri,
    },
  )
}

pub(crate) struct PlainProxyFastPath;

enum DirectTransportAttempt {
  Sent(anyhow::Result<Response<hyper::body::Incoming>>),
  Fallback(Request<ProxyBody>),
}

impl PlainProxyFastPath {
  #[cfg(test)]
  pub(crate) fn eligible<B>(
    request: &Request<B>,
    state: &AppSnapshot,
    resolved: &ResolvedRoute<'_>,
  ) -> bool
  where
    B: Body,
  {
    plain_proxy_fast_path_decision(request, state, resolved).is_ok()
  }

  fn supported_route(state: &AppSnapshot, resolved: &ResolvedRoute<'_>) -> bool {
    if resolved.route.upstream_pool.is_some() {
      return resolved.route.upstream_http_version != Some(HttpVersion::H3);
    }

    let Some(upstream) = resolved.upstream else {
      return false;
    };
    let upstream_version = resolved.route.upstream_http_version.unwrap_or_else(|| {
      select_upstream_http_version(
        state.config.proxy.auto_upgrade.enabled,
        state.config.proxy.auto_upgrade.max_http_version,
        upstream.max_http_version,
      )
    });
    upstream_version != HttpVersion::H3
      && upstream.proxy_protocol_egress == ProxyProtocolEgressMode::Off
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn handle<B>(
    request: Request<B>,
    state: &Arc<AppSnapshot>,
    resolved: &ResolvedRoute<'_>,
    forwarded_client_addr: SocketAddr,
    forwarded_header_cache: Option<&ForwardedHeaderCache>,
    client_addr: SocketAddr,
    host: &str,
    downstream_port: u16,
    tcp_max_hop: Option<u8>,
    tls: &WafTlsMetadata,
    protocol: WafProtocol,
    downstream_scheme: &'static str,
    request_version: http::Version,
    transport_network: WafTransportNetwork,
    transport_metadata: WafTransportMetadataInput<'_>,
    request_waf: RequestWafDecision,
    request_headers: Option<HeaderMap>,
    tags: Option<HashMap<String, String>>,
    access_log: &mut SystemAccessLogContext<'_>,
    trace_context: Option<TraceContext>,
  ) -> Response<ProxyBody>
  where
    B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
    B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
  {
    let direct_retry_enabled =
      direct_http_retry_enabled(state.as_ref(), resolved.route, request.method());
    let direct_selection = select_direct_fast_path_upstream(
      state.as_ref(),
      resolved,
      &request_waf,
      direct_retry_enabled,
    );
    let direct_candidate = direct_selection.is_some();
    let (
      mut upstream,
      mut upstream_index,
      upstream_version,
      retry_policy,
      pool_retry_context,
      mut sticky_cookie,
      mut pool_selection,
    ) = if let Some(selected) = direct_selection {
      (
        selected.upstream,
        selected.upstream_index,
        selected.upstream_version,
        EffectiveRetryPolicy::disabled_direct(),
        None,
        None,
        None,
      )
    } else {
      let pool_cookie_header = if request_waf.upstream_override.is_none()
        && (request_waf.upstream_pool_override.is_some() || resolved.route.upstream_pool.is_some())
      {
        request.headers().get(COOKIE)
      } else {
        None
      };
      let selected = match select_request_upstream(
        state.as_ref(),
        resolved,
        client_addr,
        host,
        request.uri(),
        pool_cookie_header,
        &request_waf,
      ) {
        Ok(selected) => selected,
        Err(error) => return super::upstream_selection_error_response(error),
      };
      let upstream = selected.upstream;
      let upstream_index = selected.upstream_index;
      let upstream_version = resolved.route.upstream_http_version.unwrap_or_else(|| {
        select_upstream_http_version(
          state.config.proxy.auto_upgrade.enabled,
          state.config.proxy.auto_upgrade.max_http_version,
          upstream.max_http_version,
        )
      });
      let pool_retry_context = if let Some(pool_name) = selected.pool_name() {
        access_log.set_upstream_pool(pool_name.to_string());
        Some((request.uri().clone(), pool_cookie_header.cloned()))
      } else {
        None
      };
      let sticky_cookie = selected.sticky_cookie();
      let pool_selection = selected.into_pool_selection();
      let retry_policy = if pool_selection.is_some() {
        EffectiveRetryPolicy::for_http_request(&state.config, resolved.route, request.method())
      } else if direct_retry_enabled {
        EffectiveRetryPolicy::for_direct_http_request(
          &state.config,
          resolved.route,
          request.method(),
        )
      } else {
        EffectiveRetryPolicy::disabled_direct()
      };
      (
        upstream,
        upstream_index,
        upstream_version,
        retry_policy,
        pool_retry_context,
        sticky_cookie,
        pool_selection,
      )
    };
    if upstream_version == HttpVersion::H3
      || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
    {
      return text_response(StatusCode::BAD_GATEWAY, "unsupported fast-path upstream");
    }
    access_log.set_upstream(&upstream.name, upstream.origin.scheme());
    let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
    let response_waf_enabled = resolved.execution_plan.waf.response.enabled();
    let request_context =
      response_waf_enabled.then(|| (request.method().clone(), request.uri().clone()));
    let request_body_definitely_empty = request_body_definitely_empty(&request);
    let (mut parts, body) = request.into_parts();
    let forwarded_request_header_values = ForwardedRequestHeaderValues::new(host, downstream_port);

    let Some(upstream_uri) = state.upstream_uri_parts_by_index.get(upstream_index) else {
      warn!(
        upstream = %upstream.name,
        upstream_index,
        "missing precomputed upstream URI parts"
      );
      return text_response(StatusCode::BAD_GATEWAY, "upstream URI is not configured");
    };
    let target_uri =
      match fast_path_target_uri(upstream_uri, resolved, downstream_scheme, host, &parts.uri) {
        Ok(uri) => uri,
        Err(error) => {
          warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
          return text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite");
        }
      };

    let rebuild = RebuildRequestOptions {
      target_uri,
      compression: &state.config.compression,
      forwarded_client_addr,
      downstream_scheme,
      downstream_host: host,
      downstream_port,
      forwarded_header_mode: state.config.proxy.forwarded_headers.mode,
      forwarded_header_cache,
      forwarded_request_header_values: Some(&forwarded_request_header_values),
      preserve_host: upstream.preserve_host,
      upstream_version,
      waf_mutations: &request_waf.request_header_mutations,
      route_mutations: &[],
      remove_accept_encoding: false,
    };
    rebuild_request_parts(&mut parts, rebuild);
    semantics::strip_accepted_expect(&mut parts.headers);
    apply_fast_path_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
    state
      .telemetry
      .inject_trace_context(&mut parts.headers, trace_context);
    let request_body = if request_body_definitely_empty {
      FastPathRequestBody::empty()
    } else {
      let client_body_timeout = EffectiveTimeouts::route_body_only(&state.config, resolved.route);
      let request_body_empty_probe_allowed =
        fast_path_request_body_empty_probe_allowed(&parts.method, request_version, &parts.headers);
      fast_path_request_body(
        body,
        state.config.limits.max_request_body_bytes as usize,
        client_body_timeout,
        false,
        request_body_empty_probe_allowed,
      )
      .await
    };
    let request_body_proven_empty = request_body.proven_empty();
    let outbound = Request::from_parts(parts, request_body.into_body()).map(|body| {
      fast_path_outbound_request_body(
        body,
        state.config.proxy.http.trailers,
        timeouts.upstream_send,
      )
    });

    let upstream_started_at = fast_path_upstream_timing_required(
      state.as_ref(),
      response_waf_enabled,
      pool_selection.is_some(),
    )
    .then(Instant::now);
    let mut report_pool_success = false;
    let mut direct_h1_lease = None;
    let direct_attempt = match direct_fast_path_transport(upstream_version, direct_candidate) {
      Some(DirectFastPathTransport::H1) => match try_send_direct_h1(
        &state.direct_h1_pools,
        &state.metrics,
        upstream_index,
        upstream,
        upstream_version,
        request_version,
        true,
        request_body_proven_empty,
        outbound,
        timeouts,
      )
      .await
      {
        DirectH1SendResult::Sent(result) => {
          DirectTransportAttempt::Sent(result.map(|mut direct| {
            direct_h1_lease = direct.take_lease();
            direct.response
          }))
        }
        DirectH1SendResult::Fallback(outbound) => DirectTransportAttempt::Fallback(outbound),
      },
      Some(DirectFastPathTransport::H2) => match try_send_direct_h2(
        &state.direct_h2_pools,
        &state.metrics,
        upstream_index,
        upstream,
        upstream_version,
        request_version,
        true,
        request_body_proven_empty,
        outbound,
        timeouts,
      )
      .await
      {
        DirectH2SendResult::Sent(result) => DirectTransportAttempt::Sent(result),
        DirectH2SendResult::Fallback(outbound) => DirectTransportAttempt::Fallback(outbound),
      },
      None => DirectTransportAttempt::Fallback(outbound),
    };
    let upstream_response_result = match direct_attempt {
      DirectTransportAttempt::Sent(result) => result,
      DirectTransportAttempt::Fallback(outbound) => {
        let Some(client) = state.clients.for_upstream_index(
          upstream_index,
          upstream.origin.scheme(),
          upstream_version,
        ) else {
          warn!(upstream = %upstream.name, "missing upstream client pool");
          return text_response(StatusCode::BAD_GATEWAY, "upstream client is not configured");
        };
        if let Some(selection) = pool_selection.take() {
          let (original_uri, pool_retry_cookie) = pool_retry_context
            .as_ref()
            .expect("pool retry context should exist for pool selections");
          send_pool_with_retry(
            state.as_ref(),
            outbound,
            upstream_index,
            selection,
            resolved.route,
            original_uri,
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
            success.response
          })
        } else if retry_policy.enabled {
          send_with_retry(client, outbound, timeouts, state.as_ref(), &retry_policy).await
        } else {
          send_one_shot(client, outbound, timeouts).await
        }
      }
    };
    let upstream_response = match upstream_response_result {
      Ok(response) => response,
      Err(error) => {
        if error_indicates_body_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
          return text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out");
        }
        warn!(error = %error, upstream = %upstream.name, "upstream fast-path request failed");
        let message = error.to_string();
        let code = if message.contains("timed out") {
          "read_timeout"
        } else {
          "connect_error"
        };
        if let Some(upstream_first_byte_time_ms) = upstream_started_at.map(elapsed_ms) {
          access_log.set_upstream_first_byte_time_ms(upstream_first_byte_time_ms);
        }
        access_log.record_upstream_error(code, &message);
        let status = if code == "read_timeout" {
          StatusCode::GATEWAY_TIMEOUT
        } else {
          StatusCode::BAD_GATEWAY
        };
        let response =
          configured_error_response(&state.config, "", status, "upstream request failed", code);
        state.record_hot_path_response(response.status());
        return response;
      }
    };
    if report_pool_success && let Some(latency_ms) = upstream_started_at.map(elapsed_ms) {
      state
        .pools
        .report_success_latency(&upstream.name, latency_ms);
    }

    let upstream_first_byte_time_ms = upstream_started_at.map(elapsed_ms);
    if let Some(upstream_first_byte_time_ms) = upstream_first_byte_time_ms {
      access_log.set_upstream_first_byte_time_ms(upstream_first_byte_time_ms);
    }
    let (mut parts, response_body) = upstream_response.into_parts();
    let FastPathResponseBody {
      body: mut response_body,
      known_small_response_body,
      inlined_known_small_body,
      trailers_handled,
      disposition: response_body_disposition,
      reason: response_body_reason,
    } = match fast_path_response_body(
      &parts.headers,
      response_body,
      timeouts.upstream_read,
      state.config.proxy.http.trailers,
      request_version,
    )
    .await
    {
      Ok(response_body) => response_body,
      Err(error) => {
        if state.request_path_features.hot_path_metrics {
          state.metrics.record_fast_path_response_body(
            fast_path_metric_protocol(request_version),
            "error",
            error.reason,
          );
        }
        let response = error.response;
        state.record_hot_path_response(response.status());
        return response;
      }
    };
    if state.request_path_features.hot_path_metrics {
      state.metrics.record_fast_path_response_body(
        fast_path_metric_protocol(request_version),
        response_body_disposition,
        response_body_reason,
      );
    }
    if let Some(lease) = direct_h1_lease.take() {
      response_body = recycle_response_body(response_body, lease, known_small_response_body);
    }
    strip_hop_by_hop_headers(&mut parts.headers);
    apply_fast_path_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
    if state.request_path_features.security_response_headers {
      apply_security_headers(&mut parts.headers, &state.config.security.headers);
    }
    if !request_waf.response_header_mutations.is_empty() {
      apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);
    }
    if response_waf_enabled {
      let (request_method, request_uri) = request_context
        .as_ref()
        .expect("response WAF context should be captured when response WAF is enabled");
      let request_headers = request_headers
        .as_ref()
        .expect("request headers should be captured when response WAF is enabled");
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
        body: None,
        peer_addr: client_addr,
        client_asn: state.client_identity.asn.lookup(client_addr.ip()),
        downstream_host: host,
        downstream_scheme,
        route_name: &resolved.route.name,
        tcp_max_hop,
        tls,
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
        body: None,
        upstream_name: &upstream.name,
        upstream_pool: pool_selection
          .as_ref()
          .map(|selection| selection.pool_name.as_str()),
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
        let response = waf_terminal_response(terminal, &mutations);
        state.record_hot_path_response(response.status());
        return response;
      }
      if !response_waf.response_header_mutations.is_empty() {
        apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
      }
    }
    if fast_path_alt_svc_possible(state.as_ref(), downstream_scheme, request_version) {
      apply_alt_svc_header(
        &mut parts.headers,
        parts.status,
        state.as_ref(),
        downstream_scheme,
        request_version,
      );
    }
    tracing::debug!(
      upstream_first_byte_time_ms,
      route = %resolved.route.name,
      upstream = %upstream.name,
      "fast-path proxy response received"
    );

    let response_body = if trailers_handled {
      response_body
    } else {
      fast_path_filter_trailers(response_body, state.config.proxy.http.trailers)
    };
    let mut response = Response::from_parts(parts, response_body);
    if known_small_response_body {
      response
        .extensions_mut()
        .insert(body::KnownSmallResponseBody);
    }
    if let Some(inlined) = inlined_known_small_body {
      response.extensions_mut().insert(inlined);
    }
    let mut response = fast_path_downstream_response_timeout(
      response,
      known_small_response_body,
      timeouts.response_send,
      transport_network,
    );
    apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
    state.record_hot_path_response(response.status());
    drop(pool_selection);
    response
  }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_handle_plain_proxy<B>(
  request: Request<B>,
  state: &Arc<AppSnapshot>,
  resolved: &ResolvedRoute<'_>,
  forwarded_client_addr: SocketAddr,
  forwarded_header_cache: Option<&ForwardedHeaderCache>,
  client_addr: SocketAddr,
  host: &str,
  downstream_port: u16,
  tcp_max_hop: Option<u8>,
  tls: &WafTlsMetadata,
  protocol: WafProtocol,
  downstream_scheme: &'static str,
  request_version: http::Version,
  transport_network: WafTransportNetwork,
  transport_metadata: WafTransportMetadataInput<'_>,
  access_log: &mut SystemAccessLogContext<'_>,
  trace_context: Option<TraceContext>,
) -> Result<Response<ProxyBody>, Request<B>>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  match plain_proxy_fast_path_decision(&request, state.as_ref(), resolved) {
    Ok(()) => record_plain_proxy_fast_path_decision(state.as_ref(), request_version, None),
    Err(reason) => {
      record_plain_proxy_fast_path_decision(state.as_ref(), request_version, Some(reason));
      return Err(request);
    }
  }
  let fast_path_waf = if plain_fast_path_waf_required(resolved) {
    match prepare_plain_fast_path_waf(
      &request,
      state.as_ref(),
      resolved,
      client_addr,
      host,
      tcp_max_hop,
      tls,
      protocol,
      transport_network,
      transport_metadata,
      downstream_scheme,
      access_log,
    ) {
      Ok(waf) => waf,
      Err(response) => return Ok(*response),
    }
  } else {
    PlainFastPathWaf::disabled()
  };
  Ok(
    PlainProxyFastPath::handle(
      request,
      state,
      resolved,
      forwarded_client_addr,
      forwarded_header_cache,
      client_addr,
      host,
      downstream_port,
      tcp_max_hop,
      tls,
      protocol,
      downstream_scheme,
      request_version,
      transport_network,
      transport_metadata,
      fast_path_waf.request,
      fast_path_waf.request_headers,
      fast_path_waf.tags,
      access_log,
      trace_context,
    )
    .await,
  )
}

fn fast_path_alt_svc_possible(
  state: &AppSnapshot,
  downstream_scheme: &str,
  request_version: http::Version,
) -> bool {
  state.alt_svc_header_value.is_some()
    && downstream_scheme == "https"
    && matches!(
      request_version,
      http::Version::HTTP_10 | http::Version::HTTP_11 | http::Version::HTTP_2
    )
}

#[cfg(test)]
mod tests;
