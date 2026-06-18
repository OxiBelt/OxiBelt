use http::Request;

use super::*;

#[test]
fn guard_accepts_direct_empty_get_to_h2c_upstream() {
  let upstream = upstream("http://backend.internal:18082");
  let request = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();

  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      true,
      &request,
    ),
    None
  );
}

#[test]
fn guard_accepts_direct_empty_head_to_tls_h2_upstream() {
  let upstream = upstream("https://backend.internal:18444");
  let request = Request::builder()
    .method(Method::HEAD)
    .uri("https://backend.internal/perf/h2?body=ok")
    .body(empty_body())
    .unwrap();

  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_3,
      true,
      true,
      &request,
    ),
    None
  );
}

#[test]
fn guard_rejects_non_h2_upstream_or_unproven_body() {
  let mut upstream = upstream("http://backend.internal:18082");
  let request = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();

  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H1,
      http::Version::HTTP_2,
      true,
      true,
      &request,
    ),
    Some("unsupported_upstream")
  );
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      false,
      &request,
    ),
    Some("request_body")
  );

  upstream.proxy_protocol_egress = ProxyProtocolEgressMode::V1;
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      true,
      &request,
    ),
    Some("unsupported_upstream")
  );
}

#[test]
fn guard_rejects_method_or_non_direct_selection() {
  let upstream = upstream("http://backend.internal:18082");
  let post = Request::builder()
    .method(Method::POST)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      true,
      &post,
    ),
    Some("unsupported_request")
  );

  let get = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      false,
      true,
      &get,
    ),
    Some("unsupported_request")
  );
}

#[test]
fn prepared_request_requires_absolute_uri_and_sets_h2_version() {
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_11)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();
  let prepared = PreparedDirectH2Request::from_request(request).unwrap();
  assert_eq!(prepared.request.version(), http::Version::HTTP_2);
  assert_eq!(
    prepared.request.uri().to_string(),
    "http://backend.internal/perf/h2c?body=ok"
  );

  let relative = Request::builder()
    .method(Method::GET)
    .uri("/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();
  assert!(PreparedDirectH2Request::from_request(relative).is_err());
}

fn upstream(origin: &str) -> UpstreamConfig {
  UpstreamConfig {
    name: "backend".to_string(),
    origin: Url::parse(origin).unwrap(),
    max_http_version: HttpVersion::H2,
    connect_timeout_ms: 100,
    request_timeout_ms: 100,
    first_byte_timeout_ms: 100,
    read_timeout_ms: 100,
    send_timeout_ms: 100,
    idle_timeout_ms: 100,
    pool_max_idle_per_host: 1,
    preserve_host: false,
    websocket: false,
    webrtc: false,
    webtransport: false,
    proxy_protocol_egress: ProxyProtocolEgressMode::Off,
    tls: Default::default(),
    extra_trusted_ca_certs: Vec::new(),
  }
}
