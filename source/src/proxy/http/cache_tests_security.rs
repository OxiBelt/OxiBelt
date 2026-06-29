use std::path::Path;
use std::time::Duration;

use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use pretty_assertions::assert_eq;

use crate::state::AppSnapshot;

fn security_header_cache_config(
  cert_path: &Path,
  key_path: &Path,
  route_security_headers: &str,
) -> String {
  format!(
    r#"
{}
security_headers = "{route_security_headers}"

[security.headers]
hsts = true
hsts_max_age_seconds = 1
hsts_include_subdomains = false
x_content_type_options = "global-nosniff"
referrer_policy = "origin"
permissions_policy = "camera=()"

[[security.header_policies]]
name = "api"
hsts = true
hsts_max_age_seconds = 15768000
hsts_include_subdomains = false
x_content_type_options = "api-nosniff"
referrer_policy = "same-origin"
permissions_policy = "microphone=()"
"#,
    super::common::minimal_config_toml(cert_path, key_path)
  )
}

fn test_timeouts() -> super::super::EffectiveTimeouts {
  super::super::EffectiveTimeouts {
    response_send: Duration::from_secs(30),
    websocket_idle: Duration::from_secs(30),
    webtransport_idle: Duration::from_secs(30),
    upstream_connect: Duration::from_secs(30),
    upstream_first_byte: Duration::from_secs(30),
    upstream_read: Duration::from_secs(30),
    upstream_send: Duration::from_secs(30),
  }
}

#[tokio::test]
async fn cached_downstream_response_reconciles_named_route_security_headers() {
  let temp_dir = super::common::TempDir::new("cache-hit-route-security-named");
  let (cert_path, key_path) =
    super::common::create_self_signed_cert(temp_dir.path(), "cache-hit-route-security-named");
  let state = AppSnapshot::new(super::parse_config(&security_header_cache_config(
    &cert_path, &key_path, "api",
  )))
  .await
  .expect("snapshot should initialize");
  let route = &state.config.routes[0];
  let method = Method::GET;
  let request_headers = HeaderMap::new();
  let body = bytes::Bytes::from_static(b"cached");
  let mut headers = HeaderMap::new();
  headers.insert(
    "strict-transport-security",
    HeaderValue::from_static("max-age=1"),
  );
  headers.insert(
    "x-content-type-options",
    HeaderValue::from_static("stored-nosniff"),
  );
  headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
  headers.insert(
    "permissions-policy",
    HeaderValue::from_static("geolocation=()"),
  );

  let response = super::super::cache_status::cached_downstream_response(
    &state,
    route,
    crate::cache::CacheEntry::memory(StatusCode::OK, headers, body.clone()),
    &method,
    &request_headers,
    test_timeouts(),
    crate::waf::WafTransportNetwork::Tcp,
    super::super::cache_status::CacheHeaderOutcome::Hit,
    super::super::cache_status::CacheHeaderReason::Fresh,
  );

  super::assert_cache_status(&response, "hit", "fresh");
  assert_eq!(
    response.headers().get("strict-transport-security").unwrap(),
    "max-age=15768000"
  );
  assert_eq!(
    response.headers().get("x-content-type-options").unwrap(),
    "api-nosniff"
  );
  assert_eq!(
    response.headers().get("referrer-policy").unwrap(),
    "same-origin"
  );
  assert_eq!(
    response.headers().get("permissions-policy").unwrap(),
    "microphone=()"
  );
  let delivered = response
    .into_body()
    .collect()
    .await
    .expect("cached body should collect")
    .to_bytes();
  assert_eq!(delivered, body);
}

#[tokio::test]
async fn cached_downstream_response_strips_security_headers_when_route_disables_policy() {
  let temp_dir = super::common::TempDir::new("cache-hit-route-security-off");
  let (cert_path, key_path) =
    super::common::create_self_signed_cert(temp_dir.path(), "cache-hit-route-security-off");
  let state = AppSnapshot::new(super::parse_config(&security_header_cache_config(
    &cert_path, &key_path, "off",
  )))
  .await
  .expect("snapshot should initialize");
  let route = &state.config.routes[0];
  let method = Method::GET;
  let request_headers = HeaderMap::new();
  let mut headers = HeaderMap::new();
  headers.insert(
    "strict-transport-security",
    HeaderValue::from_static("max-age=1"),
  );
  headers.insert(
    "x-content-type-options",
    HeaderValue::from_static("stored-nosniff"),
  );
  headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
  headers.insert(
    "permissions-policy",
    HeaderValue::from_static("geolocation=()"),
  );

  let response = super::super::cache_status::cached_downstream_response(
    &state,
    route,
    crate::cache::CacheEntry::memory(
      StatusCode::OK,
      headers,
      bytes::Bytes::from_static(b"cached"),
    ),
    &method,
    &request_headers,
    test_timeouts(),
    crate::waf::WafTransportNetwork::Tcp,
    super::super::cache_status::CacheHeaderOutcome::Hit,
    super::super::cache_status::CacheHeaderReason::Fresh,
  );

  super::assert_cache_status(&response, "hit", "fresh");
  assert!(!response.headers().contains_key("strict-transport-security"));
  assert!(!response.headers().contains_key("x-content-type-options"));
  assert!(!response.headers().contains_key("referrer-policy"));
  assert!(!response.headers().contains_key("permissions-policy"));
}

#[tokio::test]
async fn stale_if_error_route_response_reconciles_security_headers() {
  let temp_dir = super::common::TempDir::new("cache-stale-if-error-route-security");
  let (cert_path, key_path) =
    super::common::create_self_signed_cert(temp_dir.path(), "cache-stale-if-error-route-security");
  let state = AppSnapshot::new(super::parse_config(&security_header_cache_config(
    &cert_path, &key_path, "api",
  )))
  .await
  .expect("snapshot should initialize");
  let route = &state.config.routes[0];
  let mut headers = HeaderMap::new();
  headers.insert(
    "strict-transport-security",
    HeaderValue::from_static("max-age=1"),
  );
  headers.insert(
    "x-content-type-options",
    HeaderValue::from_static("stored-nosniff"),
  );

  let response = super::super::cache_status::stale_if_error_response(
    &state,
    route,
    crate::cache::CacheEntry::memory(
      StatusCode::OK,
      headers,
      bytes::Bytes::from_static(b"cached"),
    ),
    &Method::GET,
    &HeaderMap::new(),
  );

  super::assert_cache_status(&response, "stale", "stale_if_error");
  assert_eq!(
    response.headers().get("strict-transport-security").unwrap(),
    "max-age=15768000"
  );
  assert_eq!(
    response.headers().get("x-content-type-options").unwrap(),
    "api-nosniff"
  );
  assert_eq!(
    response.headers().get("referrer-policy").unwrap(),
    "same-origin"
  );
  assert_eq!(
    response.headers().get("permissions-policy").unwrap(),
    "microphone=()"
  );
}
