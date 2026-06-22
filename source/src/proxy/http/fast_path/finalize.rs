//! Response finalization for the plain-proxy fast path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use http::response::Parts;
use http::{HeaderMap, HeaderValue, Method, Response, Uri};

use crate::config::UpstreamConfig;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::pools::PoolSelection;
use crate::proxy::http::SystemAccessLogContext;
use crate::proxy::http::body::{self, ProxyBody};
use crate::proxy::http::headers::strip_hop_by_hop_headers;
use crate::proxy::http::response::{
  apply_security_headers, apply_sticky_cookie, waf_terminal_response,
};
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::waf::{
  RequestWafDecision, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations,
};

use super::super::apply_alt_svc_header;
use super::super::flow_helpers::tags_ref;
use super::compiled::SelectedCompiledProxyAction;
use super::direct_h1::{DirectH1Lease, recycle_response_body};
use super::direct_h2::{DirectH2Lease, release_response_body as release_direct_h2_response_body};
use super::helpers::{
  apply_fast_path_priority_policy, fast_path_alt_svc_possible,
  fast_path_downstream_response_timeout,
};
use super::response_body::fast_path_filter_trailers;
use super::stage_timing as timing;

#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_response(
  state: &AppSnapshot,
  resolved: &ResolvedRoute<'_>,
  request_version: http::Version,
  transport_network: WafTransportNetwork,
  downstream_scheme: &'static str,
  client_addr: SocketAddr,
  host: &str,
  tcp_max_hop: Option<u8>,
  tls: &WafTlsMetadata,
  protocol: WafProtocol,
  transport_metadata: WafTransportMetadataInput<'_>,
  upstream: &UpstreamConfig,
  upstream_first_byte_time_ms: Option<u64>,
  request_waf: &RequestWafDecision,
  response_waf_enabled: bool,
  request_context: Option<&(Method, Uri)>,
  request_headers: Option<&HeaderMap>,
  tags: &Option<HashMap<String, String>>,
  pool_selection: Option<&PoolSelection>,
  sticky_cookie: Option<&HeaderValue>,
  access_log: &mut SystemAccessLogContext<'_>,
  compiled_proxy: Option<&SelectedCompiledProxyAction<'_>>,
  metric_protocol: FastPathMetricProtocol,
  finalize_started: Option<Instant>,
  direct_h1_lease: Option<DirectH1Lease>,
  direct_h2_lease: Option<DirectH2Lease>,
  mut parts: Parts,
  mut response_body: ProxyBody,
  request_body_proven_empty: bool,
  known_small_response_body: bool,
  known_no_trailers: bool,
  inlined_known_small_body: Option<body::InlinedKnownSmallResponseBody>,
  trailers_handled: bool,
  response_send_timeout: Duration,
) -> Response<ProxyBody> {
  if let Some(lease) = direct_h1_lease {
    response_body = recycle_response_body(response_body, lease, known_small_response_body);
  }
  if let Some(lease) = direct_h2_lease {
    response_body =
      release_direct_h2_response_body(response_body, lease, known_small_response_body);
  }
  strip_hop_by_hop_headers(&mut parts.headers);

  if can_use_compiled_known_small_noop_response(
    state,
    compiled_proxy,
    request_version,
    downstream_scheme,
    transport_network,
    request_waf,
    pool_selection,
    sticky_cookie,
    request_body_proven_empty,
    known_small_response_body,
    known_no_trailers,
    trailers_handled,
  ) {
    debug_assert!(matches!(
      request_version,
      http::Version::HTTP_2 | http::Version::HTTP_3
    ));
    debug_assert!(known_small_response_body);
    debug_assert!(known_no_trailers);
    debug_assert!(trailers_handled);
    tracing::debug!(
      upstream_first_byte_time_ms,
      route = %resolved.route.name,
      upstream = %upstream.name,
      "fast-path proxy response received"
    );
    let response = finalize_known_small_noop_response(
      parts,
      response_body,
      inlined_known_small_body,
      response_send_timeout,
      transport_network,
    );
    state.record_hot_path_response(response.status());
    timing::record_finalize(state, metric_protocol, request_version, finalize_started);
    return response;
  }

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
      tags: tags_ref(tags),
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
      upstream_pool: pool_selection.map(|selection| selection.pool_name.as_str()),
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
  if fast_path_alt_svc_possible(state, downstream_scheme, request_version) {
    apply_alt_svc_header(
      &mut parts.headers,
      parts.status,
      state,
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
  mark_known_small_response_extensions(
    &mut response,
    known_small_response_body,
    inlined_known_small_body,
  );
  let mut response = fast_path_downstream_response_timeout(
    response,
    known_small_response_body,
    response_send_timeout,
    transport_network,
  );
  apply_sticky_cookie(&mut response, sticky_cookie);
  state.record_hot_path_response(response.status());
  timing::record_finalize(state, metric_protocol, request_version, finalize_started);
  response
}

#[allow(clippy::too_many_arguments)]
fn can_use_compiled_known_small_noop_response(
  state: &AppSnapshot,
  compiled_proxy: Option<&SelectedCompiledProxyAction<'_>>,
  request_version: http::Version,
  downstream_scheme: &str,
  transport_network: WafTransportNetwork,
  request_waf: &RequestWafDecision,
  pool_selection: Option<&PoolSelection>,
  sticky_cookie: Option<&HeaderValue>,
  request_body_proven_empty: bool,
  known_small_response_body: bool,
  known_no_trailers: bool,
  trailers_handled: bool,
) -> bool {
  let Some(compiled) = compiled_proxy else {
    return false;
  };
  let Some(plan) = compiled.finalize_fast_path else {
    return false;
  };
  if !plan.can_skip_known_small_noop_work() {
    return false;
  }
  matches!(
    request_version,
    http::Version::HTTP_2 | http::Version::HTTP_3
  ) && request_body_proven_empty
    && known_small_response_body
    && known_no_trailers
    && trailers_handled
    && request_waf.request_header_mutations.is_empty()
    && request_waf.response_header_mutations.is_empty()
    && pool_selection.is_none()
    && sticky_cookie.is_none()
    && !state.request_path_features.security_response_headers
    && (plan.alt_svc_noop || !fast_path_alt_svc_possible(state, downstream_scheme, request_version))
    && (transport_network != WafTransportNetwork::Udp || request_version == http::Version::HTTP_3)
}

fn finalize_known_small_noop_response(
  parts: Parts,
  response_body: ProxyBody,
  inlined_known_small_body: Option<body::InlinedKnownSmallResponseBody>,
  response_send_timeout: Duration,
  transport_network: WafTransportNetwork,
) -> Response<ProxyBody> {
  let mut response = Response::from_parts(parts, response_body);
  mark_known_small_response_extensions(&mut response, true, inlined_known_small_body);
  fast_path_downstream_response_timeout(response, true, response_send_timeout, transport_network)
}

fn mark_known_small_response_extensions(
  response: &mut Response<ProxyBody>,
  known_small_response_body: bool,
  inlined_known_small_body: Option<body::InlinedKnownSmallResponseBody>,
) {
  if known_small_response_body {
    response
      .extensions_mut()
      .insert(body::KnownSmallResponseBody);
  }
  if let Some(inlined) = inlined_known_small_body {
    response.extensions_mut().insert(inlined);
  }
}

#[cfg(test)]
mod tests {
  use bytes::Bytes;
  use http::header::HeaderName;
  use http::{HeaderValue, Request};
  use http_body_util::{BodyExt, Full};

  use crate::config::Config;
  use crate::proxy::http::body::{self, ProxyBody};
  use crate::state::AppSnapshot;
  use crate::waf::{HeaderMutation, RequestWafDecision};

  use super::super::compiled::select_compiled_proxy_action;
  use super::*;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  async fn h2_direct_h1_state(extra: &str) -> AppSnapshot {
    let temp_dir = common::TempDir::new("h2-known-small-finalize");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "h2-known-small-finalize");
    let mut raw = common::minimal_config_toml(&cert_path, &key_path)
      .replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      )
      .replace(
        "origin = \"https://app.internal.example\"\nmax_http_version = \"h2\"",
        "origin = \"http://app.internal.example\"\nmax_http_version = \"h1\"",
      );
    raw.push_str(extra);
    AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize")
  }

  fn h2_request() -> Request<ProxyBody> {
    Request::builder()
      .method(http::Method::GET)
      .version(http::Version::HTTP_2)
      .uri("https://example.com/perf/h2?body=ok")
      .body(
        Full::new(Bytes::new())
          .map_err(|never| -> body::BoxError { match never {} })
          .boxed(),
      )
      .expect("request should build")
  }

  fn can_use_h2_known_small_noop(
    state: &AppSnapshot,
    request_waf: &RequestWafDecision,
    request_body_proven_empty: bool,
    known_small_response_body: bool,
    known_no_trailers: bool,
    trailers_handled: bool,
  ) -> bool {
    let request = h2_request();
    let resolved = state
      .route_table
      .resolve("example.com", request.uri().path(), &state.upstreams)
      .expect("route should resolve");
    let actions = state
      .compiled_fast_path_actions(resolved.route_index)
      .expect("compiled actions should exist");
    let selected =
      select_compiled_proxy_action(state, Some(actions), &request, http::Version::HTTP_2, false)
        .expect("compiled selection should not fail")
        .expect("H2 compiled action should be selected");

    can_use_compiled_known_small_noop_response(
      state,
      Some(&selected),
      http::Version::HTTP_2,
      "https",
      WafTransportNetwork::Tcp,
      request_waf,
      None,
      None,
      request_body_proven_empty,
      known_small_response_body,
      known_no_trailers,
      trailers_handled,
    )
  }

  #[tokio::test]
  async fn h2_known_small_noop_guard_accepts_compiled_safe_case() {
    let state = h2_direct_h1_state("").await;

    assert!(can_use_h2_known_small_noop(
      &state,
      &RequestWafDecision::default(),
      true,
      true,
      true,
      true,
    ));
  }

  #[tokio::test]
  async fn h2_known_small_noop_guard_rejects_uncertain_runtime_facts() {
    let state = h2_direct_h1_state("").await;
    let request_waf = RequestWafDecision::default();

    for (request_empty, known_small, no_trailers, trailers_handled) in [
      (false, true, true, true),
      (true, false, true, true),
      (true, true, false, true),
      (true, true, true, false),
    ] {
      assert!(!can_use_h2_known_small_noop(
        &state,
        &request_waf,
        request_empty,
        known_small,
        no_trailers,
        trailers_handled,
      ));
    }
  }

  #[tokio::test]
  async fn h2_known_small_noop_guard_rejects_response_mutations() {
    let state = h2_direct_h1_state("").await;
    let request_waf = RequestWafDecision {
      response_header_mutations: vec![HeaderMutation::Set {
        name: HeaderName::from_static("x-test"),
        value: HeaderValue::from_static("1"),
      }],
      ..RequestWafDecision::default()
    };

    assert!(!can_use_h2_known_small_noop(
      &state,
      &request_waf,
      true,
      true,
      true,
      true,
    ));
  }

  #[tokio::test]
  async fn h2_known_small_noop_guard_rejects_security_header_config() {
    let state = h2_direct_h1_state(
      r#"

[security.headers]
x_content_type_options = "nosniff"
"#,
    )
    .await;

    assert!(!can_use_h2_known_small_noop(
      &state,
      &RequestWafDecision::default(),
      true,
      true,
      true,
      true,
    ));
  }
}
