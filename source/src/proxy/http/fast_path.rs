use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Body;
use tracing::warn;

use crate::config::{
  HttpVersion, PriorityMode, ProxyProtocolEgressMode, TrailerMode, UpstreamConfig,
};
use crate::proxy::http::SystemAccessLogContext;
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody, boxed_error};
use crate::proxy::http::headers::{is_upgrade_request, strip_hop_by_hop_headers};
use crate::proxy::http::request::{RebuildRequestOptions, proxy_body, rebuild_request_parts};
use crate::proxy::http::response::{apply_security_headers, text_response, waf_terminal_response};
use crate::proxy::http::semantics::{self, configured_error_response, filter_trailers};
use crate::proxy::http::uri::rewrite_uri;
use crate::proxy::http::version::select_upstream_http_version;
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::telemetry::TraceContext;
use crate::waf::{
  RequestWafDecision, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations,
};

use super::{
  EffectiveTimeouts, apply_alt_svc_header, error_indicates_body_timeout, is_idempotent,
  send_with_retry, with_downstream_response_timeout,
};

mod small_response;
mod waf;
use self::small_response::{SmallResponseDisposition, try_inline_response_body};
pub(crate) use self::waf::prepare_plain_fast_path_waf;

static EMPTY_TAGS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);

fn tags_ref(tags: &Option<HashMap<String, String>>) -> &HashMap<String, String> {
  tags.as_ref().unwrap_or(&EMPTY_TAGS)
}

pub(crate) struct PlainProxyFastPath;

impl PlainProxyFastPath {
  pub(crate) fn eligible<B>(
    request: &Request<B>,
    state: &AppSnapshot,
    resolved: &ResolvedRoute<'_>,
  ) -> bool
  where
    B: Body,
  {
    plain_proxy_fast_path_enabled_for_version(request, resolved)
      && Self::supported_upstream(state, resolved).is_some()
      && !state
        .cache
        .policy_enabled(resolved.route.cache.as_deref(), request.method())
      && !semantics::is_native_grpc_request(request.headers(), &state.config)
      && !is_upgrade_request(request)
      && request.method() != Method::CONNECT
  }

  fn supported_upstream<'a>(
    state: &AppSnapshot,
    resolved: &ResolvedRoute<'a>,
  ) -> Option<(&'a UpstreamConfig, usize, HttpVersion)> {
    let upstream = resolved.upstream?;
    let upstream_index = resolved.upstream_index?;
    let upstream_version = resolved.route.upstream_http_version.unwrap_or_else(|| {
      select_upstream_http_version(
        state.config.proxy.auto_upgrade.enabled,
        state.config.proxy.auto_upgrade.max_http_version,
        upstream.max_http_version,
      )
    });
    if upstream_version == HttpVersion::H3
      || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
    {
      return None;
    }
    Some((upstream, upstream_index, upstream_version))
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn handle<B>(
    request: Request<B>,
    state: Arc<AppSnapshot>,
    resolved: &ResolvedRoute<'_>,
    forwarded_client_addr: SocketAddr,
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
    B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
    B::Error: Into<body::BoxError> + Send + Sync + 'static,
  {
    let Some((upstream, upstream_index, upstream_version)) =
      Self::supported_upstream(&state, resolved)
    else {
      return text_response(StatusCode::BAD_GATEWAY, "unsupported fast-path upstream");
    };
    access_log.set_upstream(&upstream.name, upstream.origin.scheme());
    let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
    let client_body_timeout = EffectiveTimeouts::route_body_only(&state.config, resolved.route);
    let retry_enabled = state.config.proxy.retry.enabled && is_idempotent(request.method());
    let response_waf_enabled = resolved.execution_plan.waf.response.enabled();
    let request_context =
      response_waf_enabled.then(|| (request.method().clone(), request.uri().clone()));
    let request_body_definitely_empty =
      fast_path_request_body_is_definitely_empty(request.version(), request.headers());
    let (mut parts, body) = request.into_parts();

    let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
      warn!(upstream = %upstream.name, "missing precomputed upstream URI parts");
      return text_response(StatusCode::BAD_GATEWAY, "upstream URI is not configured");
    };
    let target_uri = match rewrite_uri(
      upstream_uri,
      resolved.route.path_prefix.as_str(),
      resolved.route.replace_prefix_with.as_deref(),
      &parts.uri,
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
      forwarded_client_addr,
      downstream_scheme,
      downstream_host: host,
      downstream_port,
      forwarded_header_mode: state.config.proxy.forwarded_headers.mode,
      preserve_host: upstream.preserve_host,
      upstream_version,
      waf_mutations: &request_waf.request_header_mutations,
    };
    rebuild_request_parts(&mut parts, rebuild);
    semantics::strip_accepted_expect(&mut parts.headers);
    apply_fast_path_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
    state
      .telemetry
      .inject_trace_context(&mut parts.headers, trace_context);
    let body = fast_path_request_body(
      body,
      state.config.limits.max_request_body_bytes as usize,
      client_body_timeout,
      request_body_definitely_empty,
    );
    let outbound = Request::from_parts(parts, body).map(|body| {
      fast_path_outbound_request_body(
        body,
        state.config.proxy.http.trailers,
        timeouts.upstream_send,
      )
    });

    let Some(client) =
      state
        .clients
        .for_upstream_index(upstream_index, upstream.origin.scheme(), upstream_version)
    else {
      warn!(upstream = %upstream.name, "missing upstream client pool");
      return text_response(StatusCode::BAD_GATEWAY, "upstream client is not configured");
    };
    let upstream_started_at = Instant::now();
    let upstream_response =
      match send_with_retry(client, outbound, timeouts, &state, retry_enabled).await {
        Ok(response) => response,
        Err(error) => {
          if error_indicates_body_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
            return text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out");
          }
          state.pools.report_failure(&upstream.name);
          warn!(error = %error, upstream = %upstream.name, "upstream fast-path request failed");
          let message = error.to_string();
          let code = if message.contains("timed out") {
            "read_timeout"
          } else {
            "connect_error"
          };
          let upstream_first_byte_time_ms = upstream_started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
          access_log.upstream_first_byte_time_ms = Some(upstream_first_byte_time_ms);
          access_log.record_upstream_error(code, &message);
          let status = if code == "read_timeout" {
            StatusCode::GATEWAY_TIMEOUT
          } else {
            StatusCode::BAD_GATEWAY
          };
          let response =
            configured_error_response(&state.config, "", status, "upstream request failed", code);
          state.metrics.record_response(response.status());
          return response;
        }
      };
    state.pools.report_success(&upstream.name);

    let upstream_first_byte_time_ms = upstream_started_at
      .elapsed()
      .as_millis()
      .min(u128::from(u64::MAX)) as u64;
    access_log.upstream_first_byte_time_ms = Some(upstream_first_byte_time_ms);
    let (mut parts, response_body) = upstream_response
      .map(|body| body.map_err(boxed_error).boxed())
      .into_parts();
    let (response_body, known_small_response_body, trailers_handled) =
      match try_inline_response_body(
        &parts.headers,
        response_body,
        timeouts.upstream_read,
        state.config.proxy.http.trailers,
      )
      .await
      {
        SmallResponseDisposition::Inlined(body) => (body, true, true),
        SmallResponseDisposition::Streaming(body) => (
          body::with_read_timeout(
            body,
            timeouts.upstream_read,
            BodyTimeoutKind::UpstreamResponseRead,
          ),
          false,
          false,
        ),
        SmallResponseDisposition::Error(response) => {
          state.metrics.record_response(response.status());
          return response;
        }
      };
    strip_hop_by_hop_headers(&mut parts.headers);
    if state.config.proxy.http.trailers == TrailerMode::Drop {
      parts.headers.remove(http::header::TRAILER);
    }
    apply_fast_path_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
    apply_security_headers(&mut parts.headers, &state.config.security.headers);
    apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);
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
        upstream_pool: None,
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
        state.metrics.record_response(response.status());
        return response;
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
    let response =
      with_downstream_response_timeout(response, timeouts.response_send, transport_network);
    state.metrics.record_response(response.status());
    response
  }
}

fn plain_proxy_fast_path_enabled_for_version<B>(
  request: &Request<B>,
  resolved: &ResolvedRoute<'_>,
) -> bool {
  match request.version() {
    http::Version::HTTP_10 | http::Version::HTTP_11 => {
      resolved.execution_plan.fast_path.plain_proxy_h1
    }
    http::Version::HTTP_2 => resolved.execution_plan.fast_path.plain_proxy_h2,
    _ => false,
  }
}

fn apply_fast_path_priority_policy(headers: &mut HeaderMap, mode: PriorityMode) {
  if mode != PriorityMode::Pass {
    semantics::apply_priority_policy(headers, mode);
  }
}

fn fast_path_outbound_request_body(
  body: ProxyBody,
  trailer_mode: TrailerMode,
  timeout: std::time::Duration,
) -> ProxyBody {
  let body = fast_path_filter_trailers(body, trailer_mode);
  body::with_send_timeout(body, timeout, BodyTimeoutKind::UpstreamRequestSend)
}

fn fast_path_filter_trailers(body: ProxyBody, mode: TrailerMode) -> ProxyBody {
  if mode == TrailerMode::Pass {
    return body;
  }
  filter_trailers(body, mode, false)
}

fn fast_path_request_body<B>(
  body: B,
  max_body_bytes: usize,
  timeout: std::time::Duration,
  definitely_empty: bool,
) -> ProxyBody
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  if definitely_empty {
    return empty_body();
  }

  if body.is_end_stream() {
    return proxy_body(body);
  }

  body::with_read_timeout(
    Limited::new(body, max_body_bytes),
    timeout,
    BodyTimeoutKind::DownstreamRequestRead,
  )
}

fn fast_path_request_body_is_definitely_empty(version: http::Version, headers: &HeaderMap) -> bool {
  if !matches!(version, http::Version::HTTP_10 | http::Version::HTTP_11)
    || headers.contains_key(TRANSFER_ENCODING)
  {
    return false;
  }

  let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
  let Some(content_length) = content_lengths.next() else {
    return true;
  };
  content_lengths.next().is_none()
    && content_length
      .to_str()
      .ok()
      .is_some_and(|value| value.trim() == "0")
}

fn empty_body() -> ProxyBody {
  Empty::<bytes::Bytes>::new()
    .map_err(|never| -> body::BoxError { match never {} })
    .boxed()
}

#[cfg(test)]
mod tests;
