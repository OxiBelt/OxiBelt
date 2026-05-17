mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Response};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use pretty_assertions::assert_eq;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::{full_body, maybe_cache_response};
use crate::config::Config;
use crate::state::AppSnapshot;

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

struct PanicBody;

impl Body for PanicBody {
  type Data = bytes::Bytes;
  type Error = super::body::BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    panic!("cache head rejection should not poll the response body");
  }

  fn size_hint(&self) -> SizeHint {
    let mut hint = SizeHint::new();
    hint.set_exact(4);
    hint
  }
}

fn panic_body() -> super::body::ProxyBody {
  PanicBody.boxed()
}

#[tokio::test]
async fn cache_fill_skips_collecting_no_store_response_body() {
  let temp_dir = common::TempDir::new("cache-no-store-head-skip");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-no-store-head-skip");
  let raw = format!(
    r#"
{}

[cache]
enabled = true
store = "memory"
max_size_bytes = 1024
default_ttl_seconds = 60
cache_methods = ["GET"]
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let method = Method::GET;
  let uri: http::Uri = "/no-store".parse().expect("URI should parse");
  let request_headers = HeaderMap::new();
  let mut response = Response::new(panic_body());
  response
    .headers_mut()
    .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

  let response = maybe_cache_response(
    response,
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &uri,
    &request_headers,
  )
  .await;

  assert_eq!(response.status(), http::StatusCode::OK);
  assert_eq!(state.cache.stats().memory_entries, 0);
}

#[tokio::test]
async fn cache_fill_skips_collecting_admission_rejected_response_body() {
  let temp_dir = common::TempDir::new("cache-admission-head-skip");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-admission-head-skip");
  let raw = format!(
    r#"
{}

[cache]
enabled = true
store = "memory"
max_size_bytes = 1024
default_ttl_seconds = 60
cache_methods = ["GET"]

[cache.admission]
content_types = ["text/css"]
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let method = Method::GET;
  let uri: http::Uri = "/html".parse().expect("URI should parse");
  let request_headers = HeaderMap::new();
  let mut response = Response::new(panic_body());
  response
    .headers_mut()
    .insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));

  let response = maybe_cache_response(
    response,
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &uri,
    &request_headers,
  )
  .await;

  assert_eq!(response.status(), http::StatusCode::OK);
  assert_eq!(state.cache.stats().memory_entries, 0);
}

#[tokio::test]
async fn cache_fill_skips_body_above_proxy_memory_limit_when_large_object_streaming_enabled() {
  let temp_dir = common::TempDir::new("cache-fill-memory-limit");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-fill-memory-limit");
  let raw = format!(
    r#"
{}

[proxy.buffering]
max_memory_body_bytes = 16

[cache]
enabled = true
store = "memory"
max_size_bytes = 1024
default_ttl_seconds = 60
cache_methods = ["GET"]
respect_cache_control = true
stream_large_objects = true
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let method = Method::GET;
  let uri: http::Uri = "/large?item=1".parse().expect("URI should parse");
  let request_headers = HeaderMap::new();
  let body = bytes::Bytes::from(vec![b'L'; 64]);
  let mut response = Response::new(full_body(body.clone()));
  response.headers_mut().insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  response
    .headers_mut()
    .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));

  let response = maybe_cache_response(
    response,
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &uri,
    &request_headers,
  )
  .await;

  let delivered = response
    .into_body()
    .collect()
    .await
    .expect("response body should stream")
    .to_bytes();
  assert_eq!(delivered, body);
  assert_eq!(state.cache.stats().memory_entries, 0);
  assert!(
    state
      .cache
      .lookup(crate::cache::CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.com",
        method: &method,
        uri: &uri,
        request_headers: &request_headers,
      })
      .is_none()
  );
}

#[tokio::test]
async fn cache_fill_still_stores_body_within_proxy_memory_limit() {
  let temp_dir = common::TempDir::new("cache-fill-small-body");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-fill-small-body");
  let raw = format!(
    r#"
{}

[proxy.buffering]
max_memory_body_bytes = 64

[cache]
enabled = true
store = "memory"
max_size_bytes = 1024
default_ttl_seconds = 60
cache_methods = ["GET"]
respect_cache_control = true
stream_large_objects = true
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let method = Method::GET;
  let uri: http::Uri = "/small?item=1".parse().expect("URI should parse");
  let request_headers = HeaderMap::new();
  let body = bytes::Bytes::from_static(b"cacheable body");
  let mut response = Response::new(full_body(body.clone()));
  response.headers_mut().insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  response
    .headers_mut()
    .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));

  let response = maybe_cache_response(
    response,
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &uri,
    &request_headers,
  )
  .await;

  let delivered = response
    .into_body()
    .collect()
    .await
    .expect("response body should collect")
    .to_bytes();
  assert_eq!(delivered, body);
  assert_eq!(state.cache.stats().memory_entries, 1);
  match state.cache.lookup(crate::cache::CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.com",
    method: &method,
    uri: &uri,
    request_headers: &request_headers,
  }) {
    Some(crate::cache::CacheLookup::Fresh(entry)) => assert_eq!(entry.body, body),
    other => panic!("expected fresh cache hit, got {other:?}"),
  }
}
