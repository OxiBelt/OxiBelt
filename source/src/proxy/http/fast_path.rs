use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Body;
use tracing::warn;

use crate::config::{HttpVersion, ProxyProtocolEgressMode};
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody, boxed_error};
use crate::proxy::http::headers::{is_upgrade_request, strip_hop_by_hop_headers};
use crate::proxy::http::request::{RebuildRequestOptions, rebuild_request};
use crate::proxy::http::response::text_response;
use crate::proxy::http::semantics::{self, configured_error_response, filter_trailers};
use crate::proxy::http::uri::rewrite_uri;
use crate::proxy::http::version::select_upstream_http_version;
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::waf::{HeaderMutation, WafTransportNetwork};

use super::{
  EffectiveTimeouts, apply_alt_svc_header, error_indicates_body_timeout, is_idempotent,
  send_with_retry, with_downstream_response_timeout,
};

const EMPTY_MUTATIONS: &[HeaderMutation] = &[];

pub(crate) struct PlainProxyFastPath;

impl PlainProxyFastPath {
  pub(crate) fn eligible<B>(
    request: &Request<B>,
    state: &AppSnapshot,
    resolved: &ResolvedRoute<'_>,
    method: &Method,
  ) -> bool
  where
    B: Body,
  {
    resolved.execution_plan.can_plain_proxy_fast_path
      && !state
        .cache
        .policy_enabled(resolved.route.cache.as_deref(), method)
      && !semantics::is_native_grpc_request(request.headers(), &state.config)
      && !is_upgrade_request(request)
      && method != Method::CONNECT
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn handle<B>(
    request: Request<B>,
    state: Arc<AppSnapshot>,
    resolved: &ResolvedRoute<'_>,
    peer_addr: SocketAddr,
    _client_addr: SocketAddr,
    host: &str,
    downstream_scheme: &'static str,
    request_version: http::Version,
    transport_network: WafTransportNetwork,
  ) -> Response<ProxyBody>
  where
    B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
    B::Error: Into<body::BoxError> + Send + Sync + 'static,
  {
    let Some(upstream) = resolved.upstream else {
      return text_response(StatusCode::BAD_GATEWAY, "upstream is not configured");
    };
    let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
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
      return text_response(StatusCode::BAD_GATEWAY, "unsupported fast-path upstream");
    }

    let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
      warn!(upstream = %upstream.name, "missing precomputed upstream URI parts");
      return text_response(StatusCode::BAD_GATEWAY, "upstream URI is not configured");
    };
    let request_method = request.method().clone();
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
      downstream_host: host,
      forwarded_header_mode: state.config.proxy.forwarded_headers.mode,
      preserve_host: upstream.preserve_host,
      upstream_version,
      waf_mutations: EMPTY_MUTATIONS,
    };
    let mut outbound = rebuild_request(request, rebuild);
    semantics::strip_accepted_expect(outbound.headers_mut());
    semantics::apply_priority_policy(outbound.headers_mut(), state.config.proxy.http.priority);
    let outbound =
      outbound.map(|body| filter_trailers(body, state.config.proxy.http.trailers, false));
    let outbound = outbound.map(|body| {
      body::with_send_timeout(
        body,
        timeouts.upstream_send,
        BodyTimeoutKind::UpstreamRequestSend,
      )
    });

    let Some(client) = state.clients.for_upstream_version(
      &upstream.name,
      upstream.origin.scheme(),
      upstream_version,
    ) else {
      warn!(upstream = %upstream.name, "missing upstream client pool");
      return text_response(StatusCode::BAD_GATEWAY, "upstream client is not configured");
    };
    let upstream_started_at = Instant::now();
    let upstream_response = match send_with_retry(
      client,
      outbound,
      timeouts,
      &state,
      state.config.proxy.retry.enabled && is_idempotent(&request_method),
    )
    .await
    {
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
    let (mut parts, body) = upstream_response
      .map(|body| body.map_err(boxed_error).boxed())
      .into_parts();
    let body = body::with_read_timeout(
      body,
      timeouts.upstream_read,
      BodyTimeoutKind::UpstreamResponseRead,
    );
    strip_hop_by_hop_headers(&mut parts.headers);
    if state.config.proxy.http.trailers == crate::config::TrailerMode::Drop {
      parts.headers.remove(http::header::TRAILER);
    }
    semantics::apply_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
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

    let body = filter_trailers(body, state.config.proxy.http.trailers, false);
    let response = Response::from_parts(parts, body);
    let response =
      with_downstream_response_timeout(response, timeouts.response_send, transport_network);
    state.metrics.record_response(response.status());
    response
  }
}

#[cfg(test)]
mod tests {
  use bytes::Bytes;
  use http_body_util::{BodyExt, Full};

  use super::*;
  use crate::config::Config;

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

  fn request() -> Request<ProxyBody> {
    Request::builder()
      .uri("https://example.com/")
      .body(
        Full::new(Bytes::new())
          .map_err(|never| -> body::BoxError { match never {} })
          .boxed(),
      )
      .expect("request should build")
  }

  fn resolved_route(state: &AppSnapshot) -> ResolvedRoute<'_> {
    state
      .route_table
      .resolve("example.com", "/", &state.upstreams)
      .expect("route should resolve")
  }

  fn plain_fast_path_plan(config: &Config) -> bool {
    let table = crate::routes::RouteTable::new(config);
    table
      .resolve("example.com", "/", &config.upstreams)
      .expect("route should resolve")
      .execution_plan
      .can_plain_proxy_fast_path
  }

  #[tokio::test]
  async fn plain_route_is_eligible_when_optional_features_are_off() {
    let temp_dir = common::TempDir::new("plain-fast-path");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "plain-fast-path");
    let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    );
    let state = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");
    let resolved = resolved_route(&state);

    assert!(resolved.execution_plan.can_plain_proxy_fast_path);
    assert!(PlainProxyFastPath::eligible(
      &request(),
      &state,
      &resolved,
      &Method::GET
    ));
  }

  #[tokio::test]
  async fn feature_flags_force_general_proxy_path() {
    let temp_dir = common::TempDir::new("plain-fast-path-disabled");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-disabled");
    let base = common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    );
    for raw in [
      common::minimal_config_toml(&cert_path, &key_path),
      format!(
        "{base}{}",
        r#"

[waf]
enabled = true
"#
      ),
      format!(
        "{base}{}",
        r#"

[logging.access_log]
enabled = true
"#
      ),
      format!(
        "{base}{}",
        r#"

[[rate_limits]]
name = "ip"
key = "client-ip"
rate = "1r/s"
burst = 1
"#
      ),
    ] {
      let state = AppSnapshot::new(parse_config(&raw))
        .await
        .expect("snapshot should initialize");
      let resolved = resolved_route(&state);
      assert!(!resolved.execution_plan.can_plain_proxy_fast_path);
      assert!(!PlainProxyFastPath::eligible(
        &request(),
        &state,
        &resolved,
        &Method::GET
      ));
    }
  }

  #[tokio::test]
  async fn route_capabilities_force_general_proxy_path() {
    let temp_dir = common::TempDir::new("plain-fast-path-route-disabled");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-route-disabled");
    let base = common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    );
    let mut config = parse_config(&base);
    assert!(plain_fast_path_plan(&config));

    config.routes[0].upstream_pool = Some("app-pool".to_string());
    assert!(!plain_fast_path_plan(&config));
    config.routes[0].upstream_pool = None;

    config.routes[0].grpc_web = true;
    assert!(!plain_fast_path_plan(&config));
    config.routes[0].grpc_web = false;

    config.routes[0].generic_http_upgrade = true;
    assert!(!plain_fast_path_plan(&config));
    config.routes[0].generic_http_upgrade = false;

    config.routes[0].buffering.request = Some(crate::config::BufferingMode::Memory);
    assert!(!plain_fast_path_plan(&config));
  }

  #[tokio::test]
  async fn cache_buffering_and_upgrade_requests_force_general_proxy_path() {
    let temp_dir = common::TempDir::new("plain-fast-path-cache-disabled");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-cache-disabled");
    let base = common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    );

    let cached = format!(
      "{base}{}",
      r#"
cache = "default"

[cache]
enabled = true
store = "memory"
max_size_bytes = 1048576
default_ttl_seconds = 60
cache_methods = ["GET"]
"#
    );
    let state = AppSnapshot::new(parse_config(&cached))
      .await
      .expect("snapshot should initialize");
    let resolved = resolved_route(&state);
    assert!(resolved.execution_plan.can_plain_proxy_fast_path);
    assert!(!PlainProxyFastPath::eligible(
      &request(),
      &state,
      &resolved,
      &Method::GET
    ));

    let buffered = format!(
      "{base}{}",
      r#"

[proxy.buffering]
request = "memory"
"#
    );
    let state = AppSnapshot::new(parse_config(&buffered))
      .await
      .expect("snapshot should initialize");
    let resolved = resolved_route(&state);
    assert!(!resolved.execution_plan.can_plain_proxy_fast_path);
    assert!(!PlainProxyFastPath::eligible(
      &request(),
      &state,
      &resolved,
      &Method::GET
    ));

    let state = AppSnapshot::new(parse_config(&base))
      .await
      .expect("snapshot should initialize");
    let resolved = resolved_route(&state);
    assert!(resolved.execution_plan.can_plain_proxy_fast_path);
    let upgrade = Request::builder()
      .uri("https://example.com/")
      .header(http::header::CONNECTION, "upgrade")
      .header(http::header::UPGRADE, "websocket")
      .body(
        Full::new(Bytes::new())
          .map_err(|never| -> body::BoxError { match never {} })
          .boxed(),
      )
      .expect("request should build");
    assert!(!PlainProxyFastPath::eligible(
      &upgrade,
      &state,
      &resolved,
      &Method::GET
    ));
  }
}
