use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};

use super::*;
use crate::config::{Config, HttpVersion, ProxyProtocolEgressMode};

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

struct PanicBody;

impl Body for PanicBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    panic!("body should not be polled");
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

struct TrailerOnlyBody {
  yielded: bool,
}

impl Body for TrailerOnlyBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.yielded {
      return Poll::Ready(None);
    }
    self.yielded = true;
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-trailer", "kept".parse().unwrap());
    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::with_exact(0)
  }
}

fn resolved_route(state: &AppSnapshot) -> ResolvedRoute<'_> {
  state
    .route_table
    .resolve("example.com", "/", &state.upstreams)
    .expect("route should resolve")
}

fn plain_fast_path_plan(config: &Config) -> bool {
  let waf = crate::waf::WafEngine::new(config).expect("WAF engine should build");
  let table = crate::routes::RouteTable::new_with_waf(config, &waf);
  table
    .resolve("example.com", "/", &config.upstreams)
    .expect("route should resolve")
    .execution_plan
    .fast_path
    .plain_proxy_h1
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

  assert!(resolved.execution_plan.fast_path.plain_proxy_h1);
  assert!(PlainProxyFastPath::eligible(&request(), &state, &resolved));
}

#[tokio::test]
async fn h2_request_without_content_length_zero_is_fast_path_eligible_before_guard() {
  let temp_dir = common::TempDir::new("plain-fast-path-h2-no-cl0");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-h2-no-cl0");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);
  let request = Request::builder()
    .version(http::Version::HTTP_2)
    .uri("https://example.com/perf/h2?body=ok")
    .body(PanicBody)
    .expect("request should build");

  assert!(!super::super::content_length_zero_guard_required(
    request.headers(),
    request.version()
  ));
  assert!(resolved.execution_plan.fast_path.plain_proxy_h2);
  assert!(PlainProxyFastPath::eligible(&request, &state, &resolved));
}

#[tokio::test]
async fn h1_definitely_empty_request_body_shortcut_does_not_poll_body() {
  for request in [
    Request::builder()
      .version(http::Version::HTTP_11)
      .uri("http://example.com/perf/h1")
      .body(PanicBody)
      .expect("request should build"),
    Request::builder()
      .version(http::Version::HTTP_11)
      .uri("http://example.com/perf/h1")
      .header(http::header::CONTENT_LENGTH, "0")
      .body(PanicBody)
      .expect("request should build"),
  ] {
    assert!(fast_path_request_body_is_definitely_empty(
      request.version(),
      request.headers()
    ));
    let body = fast_path_request_body(
      request.into_body(),
      1024,
      Duration::from_millis(100),
      true,
      true,
    );
    let bytes = body
      .collect()
      .await
      .expect("empty fast-path body should collect")
      .to_bytes();
    assert!(bytes.is_empty());
  }
}

#[tokio::test]
async fn h2_zero_size_hint_is_empty_only_when_trailers_are_dropped() {
  let dropped = fast_path_request_body(
    TrailerOnlyBody { yielded: false },
    1024,
    Duration::from_millis(100),
    false,
    true,
  )
  .collect()
  .await
  .expect("dropped trailer-only body should collect");
  assert!(dropped.trailers().is_none());
  assert!(dropped.to_bytes().is_empty());

  let passed = fast_path_request_body(
    TrailerOnlyBody { yielded: false },
    1024,
    Duration::from_millis(100),
    false,
    false,
  )
  .collect()
  .await
  .expect("passed trailer-only body should collect");
  assert_eq!(passed.trailers().unwrap()["x-trailer"], "kept");
}

#[tokio::test]
async fn soft_features_keep_plain_proxy_fast_path() {
  let temp_dir = common::TempDir::new("plain-fast-path-soft-features");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-soft-features");
  let base = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
  );

  for raw in [
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

[security.headers]
hsts = true
hsts_max_age_seconds = 63072000
hsts_preload = true
x_content_type_options = "nosniff"
referrer_policy = "no-referrer"
permissions_policy = "geolocation=(), camera=()"
"#
    ),
  ] {
    let state = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");
    let resolved = resolved_route(&state);
    assert!(resolved.execution_plan.fast_path.plain_proxy_h1);
    assert!(PlainProxyFastPath::eligible(&request(), &state, &resolved));
  }
}

#[tokio::test]
async fn hard_global_features_force_general_proxy_path() {
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

[[rate_limits]]
name = "ip"
key = "client-ip"
rate = "1r/s"
burst = 1
"#
    ),
    format!(
      "{base}{}",
      r#"

[shared_state]
enabled = true
namespace = "test-dynamic"
default_backend = "cluster"
dynamic_policy_backend = "cluster"

[[shared_state.backends]]
name = "cluster"
kind = "postgres"
connection_url = "postgres://oxibelt:oxibelt@postgres.invalid:5432/oxibelt"

[dynamic_policy]
enabled = true
backend = "cluster"
"#
    ),
  ] {
    let config = parse_config(&raw);
    assert!(!plain_fast_path_plan(&config));
  }
}

#[tokio::test]
async fn route_compression_off_allows_fast_path_with_global_compression_enabled() {
  let temp_dir = common::TempDir::new("plain-fast-path-compression-off");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-compression-off");
  let raw = format!(
    "{}{}",
    common::minimal_config_toml(&cert_path, &key_path),
    r#"
compression = "off"
"#
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);

  assert!(resolved.execution_plan.fast_path.plain_proxy_h1);
  assert!(PlainProxyFastPath::eligible(&request(), &state, &resolved));
}

#[tokio::test]
async fn header_only_waf_keeps_plain_proxy_fast_path_eligible() {
  let temp_dir = common::TempDir::new("plain-fast-path-header-waf");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-header-waf");
  let raw = format!(
    "{}{}",
    common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    ),
    r#"

[waf]
enabled = true

[[waf.rules]]
name = "header-only"
phase = "request"
priority = 10
when = "Request.Http.Path == '/blocked'"

[[waf.rules.actions]]
type = "reject"
status = 403
"#
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);

  assert_eq!(
    resolved.execution_plan.waf.request,
    crate::routes::WafExecutionPlan::HeaderOnly
  );
  assert!(resolved.execution_plan.fast_path.plain_proxy_h1);
  assert!(PlainProxyFastPath::eligible(&request(), &state, &resolved));
}

#[tokio::test]
async fn safe_upstream_pool_route_keeps_h2_plain_proxy_fast_path() {
  let temp_dir = common::TempDir::new("plain-fast-path-pool");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-pool");
  let raw = format!(
    "{}{}",
    common::minimal_config_toml(&cert_path, &key_path)
      .replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false"
      )
      .replace("upstream = \"app\"\n", "upstream_pool = \"app-pool\"\n"),
    r#"

[[upstream_pools]]
name = "app-pool"
algorithm = "power_of_two_choices"

[[upstream_pools.servers]]
origin = "https://app.internal.example"
"#
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);
  let request = Request::builder()
    .version(http::Version::HTTP_2)
    .uri("https://example.com/perf/h2?body=ok")
    .body(
      Full::new(Bytes::new())
        .map_err(|never| -> body::BoxError { match never {} })
        .boxed(),
    )
    .expect("request should build");

  assert!(resolved.execution_plan.fast_path.plain_proxy_h2);
  assert!(PlainProxyFastPath::eligible(&request, &state, &resolved));
}

#[test]
fn enabled_compression_policies_force_general_proxy_plan() {
  let temp_dir = common::TempDir::new("plain-fast-path-compression-enabled");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-compression-enabled");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  let named = format!(
    "{}{}",
    base.replace(
      "upstream = \"app\"\n",
      "upstream = \"app\"\ncompression = \"json-only\"\n",
    ),
    r#"

[[compression.policies]]
name = "json-only"
"#
  );

  assert!(!plain_fast_path_plan(&parse_config(&base)));
  assert!(!plain_fast_path_plan(&parse_config(&named)));
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

  let static_root = temp_dir.path().join("public");
  std::fs::create_dir_all(&static_root).expect("static root should be created");
  config.routes[0].upstream = None;
  config.routes[0].static_root = Some(static_root);
  assert!(!plain_fast_path_plan(&config));
  config.routes[0].static_root = None;
  config.routes[0].upstream = Some("app".to_string());

  config.routes[0].grpc_web = true;
  assert!(!plain_fast_path_plan(&config));
  config.routes[0].grpc_web = false;

  config.routes[0].generic_http_upgrade = true;
  assert!(!plain_fast_path_plan(&config));
  config.routes[0].generic_http_upgrade = false;

  config.routes[0].connect_tunneling = true;
  assert!(!plain_fast_path_plan(&config));
  config.routes[0].connect_tunneling = false;

  config.routes[0].buffering.request = Some(crate::config::BufferingMode::Memory);
  assert!(!plain_fast_path_plan(&config));
  config.routes[0].buffering.request = None;

  config.routes[0].buffering.response = Some(crate::config::BufferingMode::Memory);
  assert!(!plain_fast_path_plan(&config));
}

#[tokio::test]
async fn cache_buffering_errors_and_upgrade_requests_force_general_proxy_path() {
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
  assert!(resolved.execution_plan.fast_path.plain_proxy_h1);
  assert!(!PlainProxyFastPath::eligible(&request(), &state, &resolved));

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
  assert!(!resolved.execution_plan.fast_path.plain_proxy_h1);
  assert!(!PlainProxyFastPath::eligible(&request(), &state, &resolved));

  let response_buffered = format!(
    "{base}{}",
    r#"

[proxy.buffering]
response = "memory"
"#
  );
  let state = AppSnapshot::new(parse_config(&response_buffered))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);
  assert!(!resolved.execution_plan.fast_path.plain_proxy_h1);
  assert!(!PlainProxyFastPath::eligible(&request(), &state, &resolved));

  let json_errors = format!(
    "{base}{}",
    r#"

[proxy.http.errors]
mode = "json"
"#
  );
  let state = AppSnapshot::new(parse_config(&json_errors))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);
  assert!(!resolved.execution_plan.fast_path.plain_proxy_h1);
  assert!(!PlainProxyFastPath::eligible(&request(), &state, &resolved));

  let state = AppSnapshot::new(parse_config(&base))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);
  assert!(resolved.execution_plan.fast_path.plain_proxy_h1);
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
  assert!(!PlainProxyFastPath::eligible(&upgrade, &state, &resolved));
  let connect = Request::builder()
    .method(Method::CONNECT)
    .uri("https://example.com/")
    .body(
      Full::new(Bytes::new())
        .map_err(|never| -> body::BoxError { match never {} })
        .boxed(),
    )
    .expect("request should build");
  assert!(!PlainProxyFastPath::eligible(&connect, &state, &resolved));
}

#[tokio::test]
async fn unsupported_upstream_modes_force_general_proxy_path_at_runtime() {
  let temp_dir = common::TempDir::new("plain-fast-path-upstream-disabled");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-upstream-disabled");
  let base = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[compression]\nenabled = true",
    "[compression]\nenabled = false",
  );

  let mut h3_config = parse_config(&base);
  h3_config.upstreams[0].max_http_version = HttpVersion::H3;
  h3_config.routes[0].upstream_http_version = Some(HttpVersion::H3);
  let h3_state = AppSnapshot::new(h3_config)
    .await
    .expect("snapshot should initialize");
  let h3_resolved = resolved_route(&h3_state);
  assert!(h3_resolved.execution_plan.fast_path.plain_proxy_h1);
  assert!(!PlainProxyFastPath::eligible(
    &request(),
    &h3_state,
    &h3_resolved
  ));

  let mut proxy_protocol_config = parse_config(&base);
  proxy_protocol_config.upstreams[0].proxy_protocol_egress = ProxyProtocolEgressMode::V1;
  let proxy_protocol_state = AppSnapshot::new(proxy_protocol_config)
    .await
    .expect("snapshot should initialize");
  let proxy_protocol_resolved = resolved_route(&proxy_protocol_state);
  assert!(
    proxy_protocol_resolved
      .execution_plan
      .fast_path
      .plain_proxy_h1
  );
  assert!(!PlainProxyFastPath::eligible(
    &request(),
    &proxy_protocol_state,
    &proxy_protocol_resolved
  ));
}
