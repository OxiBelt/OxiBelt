use http::{HeaderMap, Request};

use super::*;

#[test]
fn authority_host_consistency_rejects_absolute_form_mismatch() {
  let request = Request::builder()
    .uri("http://absolute.example/path")
    .header(HOST, "header.example")
    .body(())
    .expect("request should build");

  assert_eq!(
    validate_authority_host_consistency(&request),
    Err(HostConsistencyError)
  );
}

#[test]
fn authority_host_consistency_accepts_matching_normalized_hosts() {
  let request = Request::builder()
    .uri("http://example.test:8443/path")
    .header(HOST, "Example.Test:8443")
    .body(())
    .expect("request should build");

  assert!(validate_authority_host_consistency(&request).is_ok());
}

#[test]
fn authority_host_consistency_rejects_absolute_form_port_mismatch() {
  let request = Request::builder()
    .uri("http://example.test:8443/path")
    .header(HOST, "example.test:9443")
    .body(())
    .expect("request should build");

  assert_eq!(
    validate_authority_host_consistency(&request),
    Err(HostConsistencyError)
  );
}

#[test]
fn authority_host_consistency_accepts_default_port_equivalence() {
  let request = Request::builder()
    .uri("http://example.test/path")
    .header(HOST, "example.test:80")
    .body(())
    .expect("request should build");

  assert!(validate_authority_host_consistency(&request).is_ok());
}

#[test]
fn authority_host_consistency_rejects_duplicate_host_headers() {
  let mut request = Request::builder()
    .uri("http://example.test/path")
    .header(HOST, "example.test")
    .body(())
    .expect("request should build");
  request
    .headers_mut()
    .append(HOST, HeaderValue::from_static("example.test"));

  assert_eq!(
    validate_authority_host_consistency(&request),
    Err(HostConsistencyError)
  );
}

#[test]
fn forwarded_headers_overwrite_spoofed_inbound_values() {
  let mut headers = HeaderMap::new();
  headers.insert(
    "forwarded",
    HeaderValue::from_static("for=198.51.100.1;proto=http"),
  );
  headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
  headers.insert("x-forwarded-host", HeaderValue::from_static("evil.test"));
  headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
  headers.insert("x-forwarded-port", HeaderValue::from_static("80"));

  add_forwarded_headers(
    &mut headers,
    "203.0.113.10:5443".parse().unwrap(),
    "example.test",
    "https",
    443,
    ForwardedHeaderMode::Overwrite,
    None,
  );

  assert!(!headers.contains_key(FORWARDED));
  assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
  assert_eq!(headers["x-forwarded-host"], "example.test");
  assert_eq!(headers["x-forwarded-proto"], "https");
  assert_eq!(headers["x-forwarded-port"], "443");
}

#[test]
fn forwarded_header_cache_reuses_xff_and_proto_only() {
  let peer_addr = "203.0.113.10:5443".parse().unwrap();
  let cache = build_forwarded_header_cache(
    peer_addr,
    "https",
    &ForwardedHeadersConfig::default(),
    &RealIpConfig::default(),
  )
  .expect("default overwrite headers without real IP can be cached");

  let mut headers = HeaderMap::new();
  add_forwarded_headers(
    &mut headers,
    peer_addr,
    "example.test",
    "https",
    443,
    ForwardedHeaderMode::Overwrite,
    Some(&cache),
  );
  assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
  assert_eq!(headers["x-forwarded-proto"], "https");
  assert_eq!(headers["x-forwarded-host"], "example.test");
  assert_eq!(headers["x-forwarded-port"], "443");

  add_forwarded_headers(
    &mut headers,
    peer_addr,
    "other.test",
    "https",
    8443,
    ForwardedHeaderMode::Overwrite,
    Some(&cache),
  );
  assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
  assert_eq!(headers["x-forwarded-proto"], "https");
  assert_eq!(headers["x-forwarded-host"], "other.test");
  assert_eq!(headers["x-forwarded-port"], "8443");
}

#[test]
fn forwarded_header_cache_is_disabled_when_forwarded_client_can_vary() {
  let peer_addr = "203.0.113.10:5443".parse().unwrap();
  let append = ForwardedHeadersConfig {
    mode: ForwardedHeaderMode::Append,
    ..ForwardedHeadersConfig::default()
  };
  assert!(
    build_forwarded_header_cache(peer_addr, "https", &append, &RealIpConfig::default()).is_none()
  );

  let real_ip = RealIpConfig {
    enabled: true,
    ..RealIpConfig::default()
  };
  assert!(
    build_forwarded_header_cache(
      peer_addr,
      "https",
      &ForwardedHeadersConfig::default(),
      &real_ip
    )
    .is_none()
  );

  let direct_peer = ForwardedHeadersConfig {
    client_ip_source: ForwardedClientIpSource::DirectPeer,
    ..ForwardedHeadersConfig::default()
  };
  assert!(build_forwarded_header_cache(peer_addr, "https", &direct_peer, &real_ip).is_some());
}

#[test]
fn forwarded_headers_append_preserves_only_x_forwarded_for_chain() {
  let mut headers = HeaderMap::new();
  headers.insert(
    "forwarded",
    HeaderValue::from_static("for=198.51.100.1;proto=http"),
  );
  headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
  headers.insert("x-forwarded-host", HeaderValue::from_static("evil.test"));
  headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
  headers.insert("x-forwarded-port", HeaderValue::from_static("80"));

  add_forwarded_headers(
    &mut headers,
    "203.0.113.10:5443".parse().unwrap(),
    "example.test",
    "https",
    8443,
    ForwardedHeaderMode::Append,
    None,
  );

  assert!(!headers.contains_key(FORWARDED));
  assert_eq!(headers["x-forwarded-for"], "198.51.100.1, 203.0.113.10");
  assert_eq!(headers["x-forwarded-host"], "example.test");
  assert_eq!(headers["x-forwarded-proto"], "https");
  assert_eq!(headers["x-forwarded-port"], "8443");
}

#[test]
fn forwarded_headers_drop_inbound_host_when_effective_host_is_invalid() {
  let mut headers = HeaderMap::new();
  headers.insert("x-forwarded-host", HeaderValue::from_static("evil.test"));

  add_forwarded_headers(
    &mut headers,
    "203.0.113.10:5443".parse().unwrap(),
    "bad\nhost",
    "https",
    443,
    ForwardedHeaderMode::Overwrite,
    None,
  );

  assert!(!headers.contains_key("x-forwarded-host"));
  assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
  assert_eq!(headers["x-forwarded-proto"], "https");
  assert_eq!(headers["x-forwarded-port"], "443");
}

#[test]
fn forwarded_headers_format_ipv6_client_ip() {
  let mut headers = HeaderMap::new();

  add_forwarded_headers(
    &mut headers,
    "[2001:db8::10]:5443".parse().unwrap(),
    "example.test",
    "https",
    443,
    ForwardedHeaderMode::Overwrite,
    None,
  );

  assert_eq!(headers["x-forwarded-for"], "2001:db8::10");
}

#[test]
fn hop_by_hop_stripping_removes_connection_tokens_and_fixed_headers() {
  let mut headers = HeaderMap::new();
  headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, x-hop"));
  headers.insert("x-hop", HeaderValue::from_static("remove"));
  headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
  headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
  headers.insert(UPGRADE, HeaderValue::from_static("websocket"));

  strip_hop_by_hop_headers(&mut headers);

  assert!(!headers.contains_key(CONNECTION));
  assert!(!headers.contains_key("x-hop"));
  assert!(!headers.contains_key("keep-alive"));
  assert!(!headers.contains_key(TRANSFER_ENCODING));
  assert!(!headers.contains_key(UPGRADE));
}

#[test]
fn hop_by_hop_stripping_keeps_ordinary_headers_on_empty_fast_path() {
  let mut headers = HeaderMap::new();
  headers.insert("content-length", HeaderValue::from_static("2"));
  headers.insert("content-type", HeaderValue::from_static("text/plain"));

  strip_hop_by_hop_headers(&mut headers);

  assert_eq!(headers["content-length"], "2");
  assert_eq!(headers["content-type"], "text/plain");
}

#[test]
fn hop_by_hop_stripping_handles_common_fixed_connection_tokens() {
  let mut headers = HeaderMap::new();
  headers.insert(
    CONNECTION,
    HeaderValue::from_static("keep-alive, close, upgrade"),
  );
  headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
  headers.insert("close", HeaderValue::from_static("remove"));
  headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
  headers.insert("x-hop", HeaderValue::from_static("preserve"));

  strip_hop_by_hop_headers(&mut headers);

  assert!(!headers.contains_key(CONNECTION));
  assert!(!headers.contains_key("keep-alive"));
  assert!(!headers.contains_key("close"));
  assert!(!headers.contains_key(UPGRADE));
  assert_eq!(headers["x-hop"], "preserve");
}

#[test]
fn hop_by_hop_stripping_preserves_only_te_trailers() {
  let mut trailers = HeaderMap::new();
  trailers.insert(TE, HeaderValue::from_static("trailers"));
  strip_hop_by_hop_headers(&mut trailers);
  assert_eq!(trailers.get(TE).unwrap(), "trailers");

  let mut gzip = HeaderMap::new();
  gzip.insert(TE, HeaderValue::from_static("gzip"));
  strip_hop_by_hop_headers(&mut gzip);
  assert!(!gzip.contains_key(TE));
}

#[test]
fn hop_by_hop_stripping_removes_te_when_connection_lists_te() {
  let mut headers = HeaderMap::new();
  headers.insert(CONNECTION, HeaderValue::from_static("te"));
  headers.insert(TE, HeaderValue::from_static("trailers"));

  strip_hop_by_hop_headers(&mut headers);

  assert!(!headers.contains_key(CONNECTION));
  assert!(!headers.contains_key(TE));
}

#[test]
fn request_trailer_sanitization_removes_sensitive_and_hop_by_hop_fields() {
  let mut trailers = HeaderMap::new();
  trailers.insert("x-request-checksum", HeaderValue::from_static("ok"));
  trailers.insert(TE, HeaderValue::from_static("trailers"));
  trailers.insert(FORWARDED, HeaderValue::from_static("for=203.0.113.66"));
  trailers.insert(HOST, HeaderValue::from_static("admin.internal"));
  trailers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer attacker"));
  trailers.insert(COOKIE, HeaderValue::from_static("session=attacker"));
  trailers.insert(X_FORWARDED_FOR, HeaderValue::from_static("203.0.113.66"));
  trailers.insert(X_FORWARDED_HOST, HeaderValue::from_static("admin.internal"));
  trailers.insert(X_FORWARDED_PORT, HeaderValue::from_static("80"));
  trailers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
  trailers.insert(X_REAL_IP, HeaderValue::from_static("203.0.113.66"));
  trailers.insert(CONNECTION, HeaderValue::from_static("x-trailer-control"));
  trailers.insert("x-trailer-control", HeaderValue::from_static("remove-me"));
  trailers.insert(
    PROXY_AUTHORIZATION,
    HeaderValue::from_static("Basic attacker"),
  );

  sanitize_request_trailers_for_upstream(&mut trailers);

  assert_eq!(trailers["x-request-checksum"], "ok");
  assert_eq!(trailers[TE], "trailers");
  for stripped in [
    "forwarded",
    "host",
    "authorization",
    "cookie",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-real-ip",
    "connection",
    "x-trailer-control",
    "proxy-authorization",
  ] {
    assert!(
      !trailers.contains_key(stripped),
      "request trailers should strip {stripped}"
    );
  }
}
