use super::*;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::lifecycle::ConnectionDrain;
use crate::waf::WafTlsMetadata;
use http_body_util::{BodyExt, Full};
use tokio::sync::watch;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn full_test_body(bytes: Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> crate::proxy::http::body::BoxError { match never {} })
    .boxed()
}

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

async fn inline_candidate_context(
  extra: &str,
  plain_proxy_fast_path_enabled: bool,
) -> H3DownstreamRequestContext {
  let temp_dir = common::TempDir::new("h3-inline-candidate");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "h3-inline");
  let mut raw = common::minimal_config_toml(&cert_path, &key_path);
  if plain_proxy_fast_path_enabled {
    raw = raw.replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    );
  }
  raw.push_str(extra);
  let state = Arc::new(
    AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize"),
  );
  let (_listener_tx, listener_rx) = watch::channel(false);
  let (_lifecycle_tx, lifecycle_rx) = watch::channel(false);
  H3DownstreamRequestContext {
    peer_addr: "127.0.0.1:44443".parse().unwrap(),
    udp_connection_id: Arc::from("test-h3"),
    tls_metadata: Arc::new(WafTlsMetadata::default()),
    connection_limit_context: None,
    state,
    drain: ConnectionDrain::new(listener_rx, lifecycle_rx, Duration::ZERO),
  }
}

enum InlineStopSignal {
  Shutdown,
  DataPlaneDrain,
}

async fn assert_inline_stop_releases_permit(signal: InlineStopSignal) {
  let mut request_tasks = request_tasks::RequestTaskSet::with_active_limit(1);
  let held_permit = request_tasks
    .try_acquire_permit()
    .expect("held permit should be available");
  assert!(
    request_tasks.try_acquire_permit().is_none(),
    "held permit should saturate the active request limiter"
  );
  let (shutdown_tx, mut shutdown) = watch::channel(false);
  let (drain_tx, mut data_plane_drain) = watch::channel(false);
  match signal {
    InlineStopSignal::Shutdown => shutdown_tx.send(true).unwrap(),
    InlineStopSignal::DataPlaneDrain => drain_tx.send(true).unwrap(),
  }
  let inline = async move {
    let _permit = held_permit;
    futures_util::future::pending::<()>().await;
  };

  assert!(
    !run_h3_inline_until_blocked_or_stop(
      inline,
      &mut request_tasks,
      &mut shutdown,
      &mut data_plane_drain,
    )
    .await
  );
  assert!(
    request_tasks.try_acquire_permit().is_some(),
    "stopped inline request should release its active permit"
  );
}

#[tokio::test]
async fn h3_inline_request_hands_off_pending_future() {
  let mut request_tasks = request_tasks::RequestTaskSet::with_active_limit(1);
  let held_permit = request_tasks
    .try_acquire_permit()
    .expect("held permit should be available");
  let (_shutdown_tx, mut shutdown) = watch::channel(false);
  let (_drain_tx, mut data_plane_drain) = watch::channel(false);
  let inline = async move {
    let _permit = held_permit;
    futures_util::future::pending::<()>().await;
  };

  assert!(
    run_h3_inline_until_blocked_or_stop(
      inline,
      &mut request_tasks,
      &mut shutdown,
      &mut data_plane_drain,
    )
    .await
  );
  assert!(
    request_tasks.try_acquire_permit().is_none(),
    "pending inline future should continue in the request task set"
  );
  request_tasks.abort_all().await;
  assert!(
    request_tasks.try_acquire_permit().is_some(),
    "aborting handed-off inline future should release its active permit"
  );
}

fn h3_request(method: Method) -> Request<()> {
  Request::builder()
    .method(method)
    .version(http::Version::HTTP_3)
    .uri("https://example.com/read")
    .body(())
    .unwrap()
}

fn assert_h3_inline_route_would_match_without_prevalidation(
  request: &Request<()>,
  context: &H3DownstreamRequestContext,
) {
  let client_addr = crate::identity::resolve_client_addr(
    request.headers(),
    context.peer_addr,
    &context.state.config.proxy.real_ip,
  )
  .expect("test request should resolve client identity");
  let host_snapshot = http_proxy::headers::extract_host_snapshot(request);
  let host = host_snapshot.as_str();
  let path = request.uri().path();
  let resolved = context
    .state
    .route_table
    .try_resolve_simple_exact_host(host, path, &context.state.upstreams)
    .or_else(|| {
      context
        .state
        .route_table
        .resolve_normalized_host_with_context(
          host,
          RouteMatchContext {
            path,
            method: Some(request.method()),
            headers: Some(request.headers()),
            query: request.uri().query(),
            source_ip: Some(client_addr.ip()),
            protocol: Some(RouteRequestProtocol::from_http(
              http::Version::HTTP_3,
              WafProtocol::Http,
            )),
            tls: Some(context.tls_metadata.as_ref()),
          },
          &context.state.upstreams,
        )
    })
    .expect("test request should route without the pre-validation guard");
  http_proxy::fast_path::plain_proxy_fast_path_decision(request, context.state.as_ref(), &resolved)
    .expect("test request should be fast-path eligible without the pre-validation guard");
}

#[test]
fn detects_webtransport_extended_connect() {
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .uri("https://example.com/session")
    .body(())
    .unwrap();
  request.extensions_mut().insert(Protocol::WEB_TRANSPORT);

  assert!(is_webtransport_request(&request));
}

#[test]
fn plain_connect_is_not_webtransport() {
  let request = Request::builder()
    .method(Method::CONNECT)
    .uri("https://example.com/session")
    .body(())
    .unwrap();

  assert!(!is_webtransport_request(&request));
}

#[test]
fn h3_field_section_size_uses_the_configured_header_budget() {
  assert_eq!(h3_field_section_size(65_536), 65_536);
}

#[test]
fn h3_field_section_size_stays_within_the_http3_setting_range() {
  assert_eq!(
    h3_field_section_size(usize::MAX),
    (usize::MAX as u64).min(H3_MAX_FIELD_SECTION_SIZE)
  );
}

#[test]
fn zero_rtt_policy_rejects_non_safe_early_data_methods() {
  let request = Request::builder()
    .method(Method::POST)
    .uri("https://example.com/upload")
    .body(())
    .unwrap();

  assert!(rejects_unsafe_early_data(
    &request,
    crate::config::QuicZeroRttMode::SafeMethods,
    true
  ));
}

#[test]
fn zero_rtt_policy_allows_safe_early_data_methods() {
  for method in [Method::GET, Method::HEAD] {
    let request = Request::builder()
      .method(method)
      .uri("https://example.com/read")
      .body(())
      .unwrap();

    assert!(!rejects_unsafe_early_data(
      &request,
      crate::config::QuicZeroRttMode::SafeMethods,
      true
    ));
  }
}

#[test]
fn zero_rtt_policy_ignores_spoofed_early_data_header_after_handshake() {
  let request = Request::builder()
    .method(Method::POST)
    .uri("https://example.com/upload")
    .header("early-data", "1")
    .body(())
    .unwrap();

  assert!(!rejects_unsafe_early_data(
    &request,
    crate::config::QuicZeroRttMode::SafeMethods,
    false
  ));
}

#[test]
fn zero_rtt_policy_is_disabled_when_zero_rtt_is_off() {
  let request = Request::builder()
    .method(Method::POST)
    .uri("https://example.com/upload")
    .body(())
    .unwrap();

  assert!(!rejects_unsafe_early_data(
    &request,
    crate::config::QuicZeroRttMode::Off,
    true
  ));
}

#[test]
fn h3_accept_normal_close_messages_are_not_warnable() {
  for message in [
    "Remote error: ApplicationClose: H3_NO_ERROR",
    "connection closed before request headers completed",
    "connection closed",
    "graceful shutdown",
  ] {
    assert!(downstream_h3_accept_message_is_normal_close(message));
  }
}

#[test]
fn h3_accept_protocol_errors_remain_warnable() {
  for message in [
    "Local error: Application { code: H3_MESSAGE_ERROR, reason: \"bad frame\" }",
    "Remote error: ApplicationClose: H3_FRAME_UNEXPECTED",
    "Timeout",
  ] {
    assert!(!downstream_h3_accept_message_is_normal_close(message));
  }
}

#[tokio::test]
async fn h3_inline_fast_path_requires_config_gate() {
  let context = inline_candidate_context("", true).await;
  let request = h3_request(Method::GET);

  assert!(!h3_inline_fast_path_candidate(&request, &context));
}

#[tokio::test]
async fn h3_inline_fast_path_rejects_uri_limits_before_route_matchers() {
  let context = inline_candidate_context(
    r#"
[routes.match]

[[routes.match.queries]]
name = "token"
exact = "ok"

[limits]
max_uri_bytes = 64

[proxy.http3]
inline_bodyless_fast_path = true
"#,
    true,
  )
  .await;
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_3)
    .uri(format!(
      "https://example.com/read?token=ok&padding={}",
      "a".repeat(96)
    ))
    .body(())
    .unwrap();

  assert_eq!(
    http_proxy::validate_request_limits(&request, &context.state.config.limits),
    Err((StatusCode::URI_TOO_LONG, "request URI is too large"))
  );
  assert_h3_inline_route_would_match_without_prevalidation(&request, &context);
  assert!(!h3_inline_fast_path_candidate(&request, &context));
}

#[tokio::test]
async fn h3_inline_fast_path_rejects_header_limits_before_route_matchers() {
  let header_value = "route-value-that-exceeds-the-configured-header-limit";
  let context = inline_candidate_context(
    &format!(
      r#"
[routes.match]

[[routes.match.headers]]
name = "x-route"
exact = "{header_value}"

[limits]
max_header_value_bytes = 8

[proxy.http3]
inline_bodyless_fast_path = true
"#
    ),
    true,
  )
  .await;
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_3)
    .uri("https://example.com/read")
    .header("x-route", header_value)
    .body(())
    .unwrap();

  assert_eq!(
    http_proxy::validate_request_limits(&request, &context.state.config.limits),
    Err((
      StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
      "header value is too large"
    ))
  );
  assert_h3_inline_route_would_match_without_prevalidation(&request, &context);
  assert!(!h3_inline_fast_path_candidate(&request, &context));
}

#[tokio::test]
async fn h3_inline_fast_path_rejects_unsafe_path_before_route_lookup() {
  let context = inline_candidate_context(
    r#"
[proxy.http3]
inline_bodyless_fast_path = true
"#,
    true,
  )
  .await;
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_3)
    .uri("https://example.com/safe/%2fadmin")
    .body(())
    .unwrap();

  assert!(http_proxy::uri::validate_downstream_path(request.uri().path()).is_err());
  assert_h3_inline_route_would_match_without_prevalidation(&request, &context);
  assert!(!h3_inline_fast_path_candidate(&request, &context));
}

#[tokio::test]
async fn h3_inline_fast_path_allows_safe_get_and_head() {
  let context = inline_candidate_context(
    r#"
[proxy.http3]
inline_bodyless_fast_path = true
"#,
    true,
  )
  .await;

  for method in [Method::GET, Method::HEAD] {
    let request = h3_request(method);
    assert!(h3_inline_fast_path_candidate(&request, &context));
  }
}

#[tokio::test]
async fn h3_inline_fast_path_rejects_bodyful_or_framed_requests() {
  let context = inline_candidate_context(
    r#"
[proxy.http3]
inline_bodyless_fast_path = true
"#,
    true,
  )
  .await;
  let post = h3_request(Method::POST);
  let framed_get = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_3)
    .uri("https://example.com/read")
    .header(http::header::CONTENT_LENGTH, "0")
    .body(())
    .unwrap();

  assert!(!h3_inline_fast_path_candidate(&post, &context));
  assert!(!h3_inline_fast_path_candidate(&framed_get, &context));
}

#[tokio::test]
async fn h3_inline_fast_path_rejects_non_fast_path_routes() {
  let context = inline_candidate_context(
    r#"
[proxy.http3]
inline_bodyless_fast_path = true
"#,
    false,
  )
  .await;
  let request = h3_request(Method::GET);

  assert!(!h3_inline_fast_path_candidate(&request, &context));
}

#[tokio::test]
async fn h3_inline_request_stops_on_shutdown_and_releases_permit() {
  assert_inline_stop_releases_permit(InlineStopSignal::Shutdown).await;
}

#[tokio::test]
async fn h3_inline_request_stops_on_data_plane_drain_and_releases_permit() {
  assert_inline_stop_releases_permit(InlineStopSignal::DataPlaneDrain).await;
}

#[test]
fn h3_known_small_path_requires_marker_and_small_upper_bound() {
  let small = full_test_body(Bytes::from_static(b"ok"));
  assert!(use_h3_known_small_body_path(true, &small));
  assert!(!use_h3_known_small_body_path(false, &small));

  let (_sender, unknown_upper) = crate::proxy::http::body::channel_body(1);
  assert!(!use_h3_known_small_body_path(true, &unknown_upper));

  let large = full_test_body(Bytes::from(vec![0; KNOWN_SMALL_BODY_MAX_BYTES + 1]));
  assert!(!use_h3_known_small_body_path(true, &large));
}

#[test]
fn h3_known_small_plan_selects_compiled_noop_no_trailer_branch() {
  let mut extensions = http::Extensions::new();
  extensions.insert(crate::proxy::http::body::CompiledKnownSmallNoopResponse);
  extensions.insert(InlinedKnownSmallResponseBody::new(
    Bytes::from_static(b"ok"),
    None,
  ));

  match take_h3_known_small_body_plan(&mut extensions) {
    H3KnownSmallBodyPlan::CompiledNoopNoTrailers(data) => {
      assert_eq!(data, Bytes::from_static(b"ok"));
    }
    plan => panic!("expected compiled no-trailer branch, got {plan:?}"),
  }
}

#[test]
fn h3_known_small_plan_keeps_unmarked_inlined_body_on_fallback_branch() {
  let mut extensions = http::Extensions::new();
  extensions.insert(InlinedKnownSmallResponseBody::new(
    Bytes::from_static(b"ok"),
    None,
  ));

  match take_h3_known_small_body_plan(&mut extensions) {
    H3KnownSmallBodyPlan::Inlined(inlined) => {
      let (data, trailers) = inlined.into_parts();
      assert_eq!(data, Bytes::from_static(b"ok"));
      assert!(trailers.is_none());
    }
    plan => panic!("expected generic inlined branch, got {plan:?}"),
  }
}

#[test]
fn h3_known_small_plan_keeps_trailer_body_on_fallback_branch() {
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-trailer", "kept".parse().unwrap());
  let mut extensions = http::Extensions::new();
  extensions.insert(crate::proxy::http::body::CompiledKnownSmallNoopResponse);
  extensions.insert(InlinedKnownSmallResponseBody::new(
    Bytes::from_static(b"ok"),
    Some(trailers),
  ));

  match take_h3_known_small_body_plan(&mut extensions) {
    H3KnownSmallBodyPlan::Inlined(inlined) => {
      let (data, trailers) = inlined.into_parts();
      assert_eq!(data, Bytes::from_static(b"ok"));
      assert_eq!(
        trailers.expect("trailers should remain available")["x-trailer"],
        "kept"
      );
    }
    plan => panic!("expected generic inlined branch, got {plan:?}"),
  }
}

#[test]
fn h3_known_small_plan_ignores_marker_without_inlined_body() {
  let mut extensions = http::Extensions::new();
  extensions.insert(crate::proxy::http::body::CompiledKnownSmallNoopResponse);

  match take_h3_known_small_body_plan(&mut extensions) {
    H3KnownSmallBodyPlan::None => {}
    plan => panic!("expected no known-small body plan, got {plan:?}"),
  }
}

#[tokio::test]
async fn h3_known_small_collect_rejects_body_over_limit() {
  let body = full_test_body(Bytes::from(vec![0; KNOWN_SMALL_BODY_MAX_BYTES + 1]));
  let error = collect_h3_known_small_body(body)
    .await
    .expect_err("known-small body over the limit should fail closed");

  assert!(
    error
      .to_string()
      .contains("known-small response body exceeded")
  );
}
