use super::*;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
use crate::state::AppSnapshot;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn retry_config(raw_retry: &str, route_retry: &str) -> Config {
  let raw = format!(
    r#"
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "/tmp/cert.pem"
private_key = "/tmp/key.pem"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

{raw_retry}

[[upstreams]]
name = "app"
origin = "http://app.example"

[[routes]]
name = "app"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
{route_retry}
"#
  );
  toml::from_str(&raw).expect("config should parse")
}

fn retry_policy(raw_retry: &str, route_retry: &str, method: Method) -> EffectiveRetryPolicy {
  let config = retry_config(raw_retry, route_retry);
  EffectiveRetryPolicy::for_http_request(&config, &config.routes[0], &method)
}

async fn h3_retry_status_server(
  server_config: h3_quinn::quinn::ServerConfig,
  expected_method: Method,
) -> std::net::SocketAddr {
  let endpoint = h3_quinn::quinn::Endpoint::server(
    server_config,
    "127.0.0.1:0".parse().expect("loopback address"),
  )
  .expect("HTTP/3 status server binds");
  let address = endpoint.local_addr().expect("HTTP/3 status server address");
  tokio::spawn(async move {
    let incoming = endpoint
      .accept()
      .await
      .expect("HTTP/3 status server accepts a connection");
    let connection = incoming.await.expect("HTTP/3 status handshake succeeds");
    let mut connection = h3::server::builder()
      .build::<_, Bytes>(h3_quinn::Connection::new(connection))
      .await
      .expect("HTTP/3 status server initializes");
    for status in [StatusCode::SERVICE_UNAVAILABLE, StatusCode::OK] {
      let resolver = connection
        .accept()
        .await
        .expect("HTTP/3 status server accepts a request")
        .expect("HTTP/3 status server request is present");
      let (request, mut stream) = resolver
        .resolve_request()
        .await
        .expect("HTTP/3 status server resolves a request");
      assert_eq!(request.method(), expected_method);
      stream
        .send_response(
          http::Response::builder()
            .status(status)
            .body(())
            .expect("HTTP/3 status response builds"),
        )
        .await
        .expect("HTTP/3 status response sends");
      stream
        .finish()
        .await
        .expect("HTTP/3 status response finishes");
    }
    // Continue driving QUIC while the client receives the final response.
    let _ = connection.accept().await;
  });
  address
}

async fn h1_retry_success_server(
  received: tokio::sync::oneshot::Sender<(Bytes, Option<http::HeaderMap>)>,
) -> std::net::SocketAddr {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
    .await
    .expect("HTTP/1 retry server binds");
  let address = listener.local_addr().expect("HTTP/1 retry server address");
  let received = Arc::new(std::sync::Mutex::new(Some(received)));
  tokio::spawn(async move {
    let (stream, _) = listener
      .accept()
      .await
      .expect("HTTP/1 retry server accepts");
    let service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
      let received = Arc::clone(&received);
      async move {
        assert_eq!(request.method(), Method::QUERY);
        let collected = request.into_body().collect().await.expect("body collects");
        let trailers = collected.trailers().cloned();
        let sender = received
          .lock()
          .unwrap_or_else(|poisoned| poisoned.into_inner())
          .take()
          .expect("HTTP/1 retry server receives only one request");
        sender
          .send((collected.to_bytes(), trailers))
          .expect("HTTP/1 retry observer remains available");
        Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::new())))
      }
    });
    hyper::server::conn::http1::Builder::new()
      .serve_connection(TokioIo::new(stream), service)
      .await
      .expect("HTTP/1 retry server serves");
  });
  address
}

async fn h3_retry_state(
  certificate: &std::path::Path,
  key: &std::path::Path,
  trusted_ca: &std::path::Path,
  address: std::net::SocketAddr,
  retry_non_idempotent: bool,
) -> Arc<AppSnapshot> {
  let mut raw = common::minimal_config_toml(certificate, key);
  raw = raw.replace(
    "trusted_ca_certs = []",
    &format!("trusted_ca_certs = [\"{}\"]", trusted_ca.display()),
  );
  raw = raw.replace(
    "origin = \"https://app.internal.example\"",
    &format!("origin = \"https://localhost:{}\"", address.port()),
  );
  raw = raw.replace("max_http_version = \"h2\"", "max_http_version = \"h3\"");
  raw.push_str(&format!(
    r#"

[proxy.retry]
enabled = true
tries = 2
on = ["503"]
backoff_base_ms = 0
backoff_max_ms = 0
jitter = false
retry_non_idempotent = {retry_non_idempotent}

[circuit_breakers.global]
max_streams = 1

[circuit_breakers.route_defaults]
max_streams = 1
"#,
  ));
  let config: Config = toml::from_str(&raw).expect("H3 retry configuration parses");
  config.validate().expect("H3 retry configuration validates");
  Arc::new(
    AppSnapshot::new(config)
      .await
      .expect("H3 retry snapshot initializes"),
  )
}

fn direct_retry_policy(raw_retry: &str, route_retry: &str, method: Method) -> EffectiveRetryPolicy {
  let config = retry_config(raw_retry, route_retry);
  EffectiveRetryPolicy::for_direct_http_request(&config, &config.routes[0], &method)
}

#[test]
fn retry_on_applies_to_status_connect_and_timeout() {
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
"#,
    "",
    Method::GET,
  );

  assert!(policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
  assert!(!policy.matches_failure(AttemptFailure::ConnectError));
  assert!(!policy.matches_failure(AttemptFailure::ReadTimeout));
}

#[test]
fn retry_non_idempotent_gates_http_methods() {
  let disabled = retry_policy(
    r#"
	[proxy.retry]
enabled = true
"#,
    "",
    Method::POST,
  );
  assert!(!disabled.enabled);

  let enabled = retry_policy(
    r#"
[proxy.retry]
enabled = true
retry_non_idempotent = true
"#,
    "",
    Method::POST,
  );
  assert!(enabled.enabled);
}

#[test]
fn query_uses_the_safe_method_retry_policy() {
  let method = Method::from_bytes(b"QUERY").expect("QUERY method");
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
"#,
    "",
    method,
  );
  assert!(policy.enabled);
}

#[test]
fn h3_uses_the_existing_status_connect_and_timeout_retry_conditions() {
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503", "connect_error", "read_timeout"]
"#,
    "",
    Method::GET,
  );

  assert!(policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
  assert!(policy.matches_failure(AttemptFailure::ConnectError));
  assert!(policy.matches_failure(AttemptFailure::ReadTimeout));
}

#[tokio::test]
async fn h3_status_retry_releases_a_discarded_stream_before_the_next_attempt() {
  let temporary = common::TempDir::new("h3-retry-status");
  let (ca_certificate, ca_key) = common::create_self_signed_cert(temporary.path(), "retry-ca");
  let (certificate, key) =
    common::create_ca_signed_server_cert(temporary.path(), "localhost", &ca_certificate, &ca_key);
  let server_config: Config = toml::from_str(&common::minimal_config_toml(&certificate, &key))
    .expect("HTTP/3 retry server configuration parses");
  let address = h3_retry_status_server(
    crate::tls::build_quic_server_config(&server_config.tls, &server_config.quic, None)
      .expect("HTTP/3 retry server TLS initializes"),
    Method::GET,
  )
  .await;
  let state = h3_retry_state(&certificate, &key, &ca_certificate, address, false).await;
  let route = &state.config.routes[0];
  let policy = EffectiveRetryPolicy::for_http_request(&state.config, route, &Method::GET);
  let upstream = &state.upstreams[0];
  let request = http::Request::builder()
    .method(Method::GET)
    .uri(format!("https://localhost:{}/retry", address.port()))
    .body(super::super::full_body(Bytes::new()))
    .expect("HTTP/3 retry request builds");

  let response = tokio::time::timeout(
    Duration::from_secs(5),
    send_h3_with_retry(
      request,
      upstream,
      EffectiveTimeouts::new(&state.config, route, upstream),
      state.as_ref(),
      &policy,
      Some(RetryAdmissionContext {
        route_name: &route.name,
        pool_name: None,
      }),
    ),
  )
  .await
  .expect("HTTP/3 retry should stay bounded")
  .expect("HTTP/3 retry should return the second response");
  assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn h3_post_retries_a_status_only_when_retry_non_idempotent_is_enabled() {
  let temporary = common::TempDir::new("h3-retry-post");
  let (ca_certificate, ca_key) = common::create_self_signed_cert(temporary.path(), "retry-ca");
  let (certificate, key) =
    common::create_ca_signed_server_cert(temporary.path(), "localhost", &ca_certificate, &ca_key);
  let server_config: Config = toml::from_str(&common::minimal_config_toml(&certificate, &key))
    .expect("HTTP/3 retry server configuration parses");
  let address = h3_retry_status_server(
    crate::tls::build_quic_server_config(&server_config.tls, &server_config.quic, None)
      .expect("HTTP/3 retry server TLS initializes"),
    Method::POST,
  )
  .await;
  let state = h3_retry_state(&certificate, &key, &ca_certificate, address, true).await;
  let route = &state.config.routes[0];
  let policy = EffectiveRetryPolicy::for_http_request(&state.config, route, &Method::POST);
  assert!(policy.enabled);
  let response = send_h3_with_retry(
    http::Request::builder()
      .method(Method::POST)
      .uri(format!("https://localhost:{}/retry", address.port()))
      .header("upload-draft-interop-version", "9")
      .header("upload-offset", "invalid")
      .body(super::super::full_body(Bytes::new()))
      .expect("HTTP/3 retry request builds"),
    &state.upstreams[0],
    EffectiveTimeouts::new(&state.config, route, &state.upstreams[0]),
    state.as_ref(),
    &policy,
    None,
  )
  .await
  .expect("opted-in POST H3 status retry returns the second response");
  assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn pool_retry_reselects_h3_to_h1_and_replays_query_data_and_trailers() {
  let temporary = common::TempDir::new("pool-h3-h1-retry");
  let (ca_certificate, ca_key) = common::create_self_signed_cert(temporary.path(), "retry-ca");
  let (certificate, key) =
    common::create_ca_signed_server_cert(temporary.path(), "localhost", &ca_certificate, &ca_key);
  let server_config: Config = toml::from_str(&common::minimal_config_toml(&certificate, &key))
    .expect("HTTP/3 retry server configuration parses");
  let h3_address = h3_retry_status_server(
    crate::tls::build_quic_server_config(&server_config.tls, &server_config.quic, None)
      .expect("HTTP/3 retry server TLS initializes"),
    Method::QUERY,
  )
  .await;
  let (received_tx, received_rx) = tokio::sync::oneshot::channel();
  let h1_address = h1_retry_success_server(received_tx).await;
  let mut raw = common::minimal_config_toml(&certificate, &key);
  raw = raw.replace(
    "trusted_ca_certs = []",
    &format!("trusted_ca_certs = [\"{}\"]", ca_certificate.display()),
  );
  raw = raw.replace(
    "origin = \"https://app.internal.example\"",
    &format!("origin = \"https://localhost:{}\"", h3_address.port()),
  );
  raw = raw.replace("max_http_version = \"h2\"", "max_http_version = \"h3\"");
  raw = raw.replace("upstream = \"app\"", "upstream_pool = \"mixed\"");
  raw.push_str(&format!(
    r#"

[proxy.retry]
enabled = true
tries = 2
on = ["503"]
reselect_pool_on_retry = true
exclude_failed_pool_upstreams = true
backoff_base_ms = 0
backoff_max_ms = 0
jitter = false

[[upstream_pools]]
name = "mixed"
algorithm = "rendezvous_hash"

[[upstream_pools.servers]]
id = "h1"
origin = "http://{}"
"#,
    h1_address
  ));
  let config: Config = toml::from_str(&raw).expect("mixed pool configuration parses");
  config
    .validate()
    .expect("mixed pool configuration validates");
  let state = Arc::new(
    AppSnapshot::new(config)
      .await
      .expect("mixed pool snapshot initializes"),
  );
  let client_addr: std::net::SocketAddr = "127.0.0.1:34567".parse().unwrap();
  let mut selected = None;
  for suffix in 0..128 {
    let candidate = super::super::upstream::select_pool_upstream(
      state.as_ref(),
      "mixed",
      client_addr,
      &format!("mixed-{suffix}"),
      None,
      None,
    )
    .await
    .expect("pool selects an upstream");
    if selected.is_none() {
      selected = Some((candidate, format!("mixed-{suffix}")));
      break;
    }
  }
  let (selected, _) = selected.expect("a deterministic rendezvous key selects H1");
  let route = &state.config.routes[0];
  let policy = EffectiveRetryPolicy::for_http_request(&state.config, route, &Method::QUERY);
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-query-checksum", "present".parse().expect("trailer"));
  let body = Full::new(Bytes::from_static(b"query-body"))
    .with_trailers(std::future::ready(Some(Ok::<_, Infallible>(trailers))))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let request = http::Request::builder()
    .method(Method::QUERY)
    .uri("https://example.com/retry")
    .body(body)
    .expect("QUERY request builds");
  let original_uri: http::Uri = "/retry".parse().expect("original URI parses");
  let initial_index = state
    .clients
    .upstream_index("app")
    .expect("H3 client index");
  let initial_upstream = &state.upstreams[initial_index];
  let response = send_pool_with_retry(
    state.as_ref(),
    request,
    initial_index,
    selected.pool_selection.expect("pool selection"),
    route,
    &original_uri,
    &[],
    client_addr,
    "example.com",
    "https",
    None,
    &crate::waf::RequestWafDecision::default(),
    EffectiveTimeouts::new(&state.config, route, initial_upstream),
    &policy,
  )
  .await
  .expect("H3 pool retry falls back to H1");
  assert_eq!(response.response.status(), StatusCode::OK);
  let (body, trailers) = tokio::time::timeout(Duration::from_secs(5), received_rx)
    .await
    .expect("H1 receive stays bounded")
    .expect("H1 receives retry");
  assert_eq!(body, Bytes::from_static(b"query-body"));
  assert_eq!(
    trailers
      .as_ref()
      .and_then(|headers| headers.get("x-query-checksum")),
    Some(&"present".parse().unwrap())
  );
  assert!(!response.cache_identity_unchanged);
}

#[test]
fn pooled_transport_adapter_keeps_hyper_and_h3_attempts_separate() {
  assert_eq!(
    upstream_attempt_transport(HttpVersion::H1),
    UpstreamAttemptTransport::Hyper
  );
  assert_eq!(
    upstream_attempt_transport(HttpVersion::H2),
    UpstreamAttemptTransport::Hyper
  );
  assert_eq!(
    upstream_attempt_transport(HttpVersion::H3),
    UpstreamAttemptTransport::H3
  );
}

#[test]
fn pool_reselection_clears_revalidation_validators() {
  use http::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};

  let mut retry_headers = http::HeaderMap::new();
  retry_headers.insert(
    IF_NONE_MATCH,
    "\"cache-injected\"".parse().expect("validator"),
  );
  retry_headers.insert(
    IF_MODIFIED_SINCE,
    "Tue, 02 Jan 2024 00:00:00 GMT".parse().expect("validator"),
  );

  clear_revalidation_validators(&mut retry_headers);

  assert!(retry_headers.get_all(IF_NONE_MATCH).iter().next().is_none());
  assert!(retry_headers.get(IF_MODIFIED_SINCE).is_none());
}

#[tokio::test]
async fn replayable_body_preserves_data_and_trailers() {
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-retry-trailer", "kept".parse().expect("header"));
  let body = Full::new(Bytes::from_static(b"query"))
    .with_trailers(std::future::ready(Some(Ok::<_, Infallible>(trailers))))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let replay =
    ReplayableBody::capture(body, 1024, 1024, 8, Instant::now() + Duration::from_secs(1))
      .await
      .expect("capture replay body");
  assert!(!replay.is_completely_empty());
  let collected = replay
    .replay_body()
    .collect()
    .await
    .expect("collect replay");
  let trailers = collected.trailers().cloned();
  assert_eq!(collected.to_bytes(), Bytes::from_static(b"query"));
  assert_eq!(
    trailers
      .as_ref()
      .and_then(|headers| headers.get("x-retry-trailer"))
      .expect("replayed trailer"),
    "kept"
  );
}

#[tokio::test]
async fn trailer_only_body_is_replayed_but_never_retried_after_a_transport_error() {
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-retry-trailer", "kept".parse().expect("header"));
  let body = StreamBody::new(futures_util::stream::iter(vec![Ok::<_, BoxError>(
    hyper::body::Frame::trailers(trailers),
  )]))
  .boxed();
  let replay =
    ReplayableBody::capture(body, 1024, 1024, 8, Instant::now() + Duration::from_secs(1))
      .await
      .expect("capture trailer-only body");
  assert!(!replay.is_completely_empty());
  let collected = replay
    .replay_body()
    .collect()
    .await
    .expect("collect replay");
  assert_eq!(
    collected
      .trailers()
      .and_then(|headers| headers.get("x-retry-trailer"))
      .expect("replayed trailer"),
    "kept"
  );

  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
tries = 2
on = ["connect_error", "read_timeout"]
"#,
    "",
    Method::GET,
  );
  assert!(!can_retry_transport_error(
    &replay,
    &policy,
    AttemptFailure::ConnectError,
    0,
  ));
  assert!(!can_retry_transport_error(
    &replay,
    &policy,
    AttemptFailure::ReadTimeout,
    0,
  ));
}

#[tokio::test]
async fn replay_capture_rejects_trailers_outside_the_configured_header_bound() {
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-retry-trailer", "too-large".parse().expect("header"));
  let body = StreamBody::new(futures_util::stream::iter(vec![Ok::<_, BoxError>(
    hyper::body::Frame::trailers(trailers),
  )]))
  .boxed();

  let error = ReplayableBody::capture(body, 1024, 4, 8, Instant::now() + Duration::from_secs(1))
    .await
    .expect_err("trailer metadata must fit the configured header bound");
  assert!(error.to_string().contains("trailers exceed memory bound"));
}

#[tokio::test]
async fn zero_length_data_framing_is_not_retried_after_a_transport_error() {
  let body = StreamBody::new(futures_util::stream::iter(vec![Ok::<_, BoxError>(
    hyper::body::Frame::data(Bytes::new()),
  )]))
  .boxed();
  let replay =
    ReplayableBody::capture(body, 1024, 1024, 8, Instant::now() + Duration::from_secs(1))
      .await
      .expect("capture zero-length data frame");
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
tries = 2
on = ["connect_error"]
"#,
    "",
    Method::GET,
  );

  assert!(!can_retry_transport_error(
    &replay,
    &policy,
    AttemptFailure::ConnectError,
    0,
  ));
}

#[test]
fn transport_retry_requires_an_empty_body_and_a_remaining_configured_attempt() {
  let empty = ReplayableBody {
    data: Bytes::new(),
    trailers: None,
    bytes: 0,
    trailer_bytes: 0,
    has_data_frame: false,
  };
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
tries = 2
on = ["connect_error"]
"#,
    "",
    Method::GET,
  );

  assert!(can_retry_transport_error(
    &empty,
    &policy,
    AttemptFailure::ConnectError,
    0,
  ));
  assert!(!can_retry_transport_error(
    &empty,
    &policy,
    AttemptFailure::ReadTimeout,
    0,
  ));
  assert!(!can_retry_transport_error(
    &empty,
    &policy,
    AttemptFailure::ConnectError,
    1,
  ));
}

#[test]
fn direct_retry_policy_skips_disabled_retry_metadata() {
  let policy = direct_retry_policy(
    r#"
[proxy.retry]
enabled = false
on = ["503"]
"#,
    "",
    Method::GET,
  );

  assert!(!policy.enabled);
  assert!(!policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
}

#[test]
fn direct_retry_policy_keeps_enabled_retry_conditions() {
  let policy = direct_retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
"#,
    "",
    Method::GET,
  );

  assert!(policy.enabled);
  assert!(policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
}

#[test]
fn direct_retry_policy_honors_route_enable_override() {
  let policy = direct_retry_policy(
    r#"
[proxy.retry]
enabled = false
on = ["502"]
"#,
    r#"

[routes.retry]
enabled = true
on = ["503"]
"#,
    Method::GET,
  );

  assert!(policy.enabled);
  assert!(policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
  assert!(!policy.matches_failure(AttemptFailure::Status(StatusCode::BAD_GATEWAY)));
}

#[test]
fn direct_retry_policy_keeps_non_idempotent_gate() {
  let policy = direct_retry_policy(
    r#"
[proxy.retry]
enabled = false
"#,
    r#"

[routes.retry]
enabled = true
on = ["503"]
"#,
    Method::POST,
  );

  assert!(!policy.enabled);
  assert!(!policy.matches_failure(AttemptFailure::Status(StatusCode::SERVICE_UNAVAILABLE)));
}

#[test]
fn route_retry_overrides_global_policy() {
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = false
tries = 2
total_budget_ms = 5000
"#,
    r#"

[routes.retry]
enabled = true
tries = 4
total_budget_ms = 250
per_attempt_timeout_ms = 100
"#,
    Method::GET,
  );

  assert!(policy.enabled);
  assert_eq!(policy.tries, 4);
  assert_eq!(policy.total_budget, Duration::from_millis(250));
  assert_eq!(policy.per_attempt_timeout, Some(Duration::from_millis(100)));
}

#[test]
fn enabled_breakers_supply_bounded_jittered_retry_defaults() {
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
"#,
    "",
    Method::GET,
  );
  assert_eq!(policy.backoff_base, Duration::from_millis(25));
  assert_eq!(policy.backoff_max, Duration::from_millis(250));
  assert!(policy.jitter);
}

#[test]
fn pool_passive_health_reporting_requires_retry_enabled_policy() {
  let route_disabled = retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
"#,
    r#"

[routes.retry]
enabled = false
"#,
    Method::GET,
  );
  assert!(!route_disabled.enabled);
  assert!(!should_report_pool_passive_failure(&route_disabled));
  assert!(!should_report_pool_response_success(
    &route_disabled,
    StatusCode::SERVICE_UNAVAILABLE
  ));
  assert!(should_report_pool_response_success(
    &route_disabled,
    StatusCode::OK
  ));

  let method_disabled = retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
"#,
    "",
    Method::POST,
  );
  assert!(!method_disabled.enabled);
  assert!(!should_report_pool_passive_failure(&method_disabled));
}

#[test]
fn pool_passive_health_reporting_honors_report_flag() {
  let policy = retry_policy(
    r#"
[proxy.retry]
enabled = true
on = ["503"]
report_passive_health = false
"#,
    "",
    Method::GET,
  );

  assert!(policy.enabled);
  assert!(!should_report_pool_passive_failure(&policy));
  assert!(!should_report_pool_response_success(
    &policy,
    StatusCode::SERVICE_UNAVAILABLE
  ));
}
