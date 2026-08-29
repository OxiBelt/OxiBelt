use super::*;
use crate::bandwidth::{BandwidthPolicy, BandwidthRate};
use crate::config::{CapacitySetting, Config, PriorityClass};
use crate::proxy::http::response::{silent_close_response, text_response};
use std::num::NonZeroU64;
use tokio::io::AsyncReadExt;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[tokio::test]
async fn prepare_fast_proxy_request_rejects_tls_policy_mismatch() {
  let temp_dir = common::TempDir::new("h1-fast-proxy-route-tls-policy");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "h1-fast-proxy-route-tls-policy");
  let base = common::minimal_config_toml(&cert_path, &key_path)
    .replace(
      "hosts = [\"example.com\"]",
      "hosts = [\"secure.example.com\"]",
    )
    .replace(
      "origin = \"https://app.internal.example\"\nmax_http_version = \"h2\"",
      "origin = \"http://app.internal.example\"\nmax_http_version = \"h1\"",
    )
    .replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    );
  let raw = format!(
    r#"{base}

[[routes]]
name = "legacy-root"
hosts = ["legacy.example.com"]
path_prefix = "/"
upstream = "app"

[routes.tls]
min_version = "tls1.2"
max_version = "tls1.2"
"#
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let peer_addr = "203.0.113.10:49152".parse().unwrap();
  let legacy_tls = WafTlsMetadata {
    enabled: true,
    sni: Some("legacy.example.com".to_string()),
    ..WafTlsMetadata::default()
  };
  let secure_tls = WafTlsMetadata {
    enabled: true,
    sni: Some("secure.example.com".to_string()),
    ..WafTlsMetadata::default()
  };

  assert!(
    prepare_fast_proxy_request(
      &parsed_get("secure.example.com"),
      &snapshot,
      peer_addr,
      &legacy_tls
    )
    .is_none()
  );
  assert!(
    prepare_fast_proxy_request(
      &parsed_get("secure.example.com"),
      &snapshot,
      peer_addr,
      &secure_tls
    )
    .is_some()
  );
}

#[tokio::test]
async fn guarded_fast_path_holds_priority_and_route_admission_leases() {
  let temp_dir = common::TempDir::new("h1-fast-proxy-priority-admission");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "h1-fast-proxy-priority-admission");
  let mut config: Config = toml::from_str(&common::minimal_config_toml(&cert_path, &key_path))
    .expect("config should parse");
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(2);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(0);
  config.validate().expect("config should validate");
  let route = config.routes[0].name.clone();
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");

  let first = admission::admit(&snapshot, PriorityClass::Default, &route)
    .await
    .expect("first fast-path request should acquire both leases");
  assert!(
    admission::admit(&snapshot, PriorityClass::Default, &route)
      .await
      .is_none(),
    "route capacity must reject fast-path work even while global capacity remains"
  );
  drop(first);
  assert!(
    admission::admit(&snapshot, PriorityClass::Default, &route)
      .await
      .is_some(),
    "dropping fast-path leases must restore both priority and route capacity"
  );
}

#[test]
fn silent_close_response_stops_before_h1_fast_writer() {
  let response = silent_close_response();

  assert!(
    response_write_plan(&response, &Method::GET, false, Duration::from_secs(1)).is_none(),
    "silent_close sentinel must close before serializing a 204 response"
  );
}

#[test]
fn ordinary_no_content_response_is_still_serialized_without_body() {
  let response = text_response(StatusCode::NO_CONTENT, "");

  let write_plan = response_write_plan(&response, &Method::GET, false, Duration::from_secs(1))
    .expect("ordinary 204 should still be serialized");

  assert!(write_plan.keep_alive);
  assert!(write_plan.skip_body);
  assert_eq!(write_plan.response_send_timeout, Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn tls_h1_fast_response_observes_mid_response_unlimited_to_limited_reload() {
  let limiter = crate::bandwidth::RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED);
  let (source_tx, source) = proxy_http::body::channel_body(1);
  let mut response = Response::new(source);
  response
    .headers_mut()
    .insert(CONTENT_LENGTH, HeaderValue::from_static("8"));
  let response = proxy_http::with_final_response_bandwidth(
    response,
    limiter.clone(),
    crate::metrics::Metrics::new(),
    WafTransportNetwork::Tcp,
  );
  let (mut downstream, mut client) = tokio::io::duplex(4096);
  let writer = tokio::spawn(async move {
    let mut head = Vec::new();
    write_response(
      &mut downstream,
      response,
      true,
      false,
      Duration::from_secs(5),
      &mut head,
    )
    .await
  });

  source_tx
    .send(Ok(hyper::body::Frame::data(Bytes::from_static(b"open"))))
    .await
    .unwrap();
  let head = read_response_head(&mut client).await;
  assert!(head.ends_with(b"\r\n\r\n"));
  let mut open = [0u8; 4];
  client.read_exact(&mut open).await.unwrap();
  assert_eq!(&open, b"open");

  let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(4).unwrap());
  limiter
    .update(BandwidthPolicy::new(BandwidthRate::Unlimited, rate))
    .unwrap();
  source_tx
    .send(Ok(hyper::body::Frame::data(Bytes::from_static(b"slow"))))
    .await
    .unwrap();
  let first = client.read_u8();
  tokio::pin!(first);
  assert!(futures_util::poll!(first.as_mut()).is_pending());
  tokio::time::advance(Duration::from_millis(249)).await;
  assert!(futures_util::poll!(first.as_mut()).is_pending());
  tokio::time::advance(Duration::from_millis(1)).await;
  assert_eq!(first.await.unwrap(), b's');

  writer.abort();
}

async fn read_response_head(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
  let mut head = Vec::new();
  while !head.ends_with(b"\r\n\r\n") {
    head.push(stream.read_u8().await.unwrap());
  }
  head
}

fn parsed_get(host: &str) -> ParsedPlainRequest {
  let mut headers = HeaderMap::new();
  headers.insert(HOST, HeaderValue::from_str(host).unwrap());
  ParsedPlainRequest {
    method: Method::GET,
    target: "/".to_string(),
    version: 1,
    headers,
    raw: Vec::new(),
    remaining: Vec::new(),
  }
}
