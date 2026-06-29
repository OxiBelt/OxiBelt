mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[path = "cache_tests_security.rs"]
mod security;
#[path = "cache_tests_streaming.rs"]
mod streaming;

use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use pretty_assertions::assert_eq;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::{full_body, maybe_cache_response, maybe_cache_response_with_store_permission};
use crate::config::Config;
use crate::state::AppSnapshot;

fn assert_cache_status<B>(response: &Response<B>, outcome: &str, reason: &str) {
  assert_eq!(response.headers().get("x-oxibelt-cache").unwrap(), outcome);
  assert_eq!(
    response.headers().get("x-oxibelt-cache-reason").unwrap(),
    reason
  );
}

fn assert_no_cache_status_headers(headers: &HeaderMap) {
  assert!(!headers.contains_key("x-oxibelt-cache"));
  assert!(!headers.contains_key("x-oxibelt-cache-reason"));
}

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

struct ErrorBody;

impl Body for ErrorBody {
  type Data = bytes::Bytes;
  type Error = super::body::BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    Poll::Ready(Some(Err(Box::new(std::io::Error::other(
      "cache body error",
    )))))
  }

  fn size_hint(&self) -> SizeHint {
    let mut hint = SizeHint::new();
    hint.set_exact(4);
    hint
  }
}

fn error_body() -> super::body::ProxyBody {
  ErrorBody.boxed()
}

#[tokio::test]
async fn cache_fill_store_permission_false_skips_body_collection() {
  let temp_dir = common::TempDir::new("cache-fill-store-not-allowed");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-fill-store-not-allowed");
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
  let uri: http::Uri = "/suppressed-fill".parse().expect("URI should parse");
  let request_headers = HeaderMap::new();

  let response = maybe_cache_response_with_store_permission(
    Response::new(panic_body()),
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &uri,
    &request_headers,
    None,
    false,
    None,
  )
  .await;

  assert_eq!(response.status(), http::StatusCode::OK);
  assert_cache_status(&response, "miss", "store_not_allowed");
  assert_eq!(state.cache.stats().memory_entries, 0);
}

#[tokio::test]
async fn cache_fill_body_error_reports_store_failed_reason() {
  let temp_dir = common::TempDir::new("cache-fill-body-error");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "cache-body-error");
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
  let uri: http::Uri = "/body-error".parse().expect("URI should parse");
  let request_headers = HeaderMap::new();
  let mut response = Response::new(error_body());
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
    None,
  )
  .await;

  assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
  assert_cache_status(&response, "miss", "store_failed");
  assert_eq!(state.cache.stats().memory_entries, 0);
}

#[tokio::test]
async fn cache_fill_min_hits_warming_does_not_suppress_next_store() {
  let temp_dir = common::TempDir::new("cache-fill-min-hits-warming");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-fill-min-hits-warming");
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
min_hits = 2
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let method = Method::GET;
  let uri: http::Uri = "/admit-after-warmup".parse().expect("URI should parse");
  let request_headers = HeaderMap::new();

  let first = maybe_cache_response(
    Response::new(full_body(bytes::Bytes::from_static(b"admitted"))),
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &uri,
    &request_headers,
    None,
  )
  .await;
  assert_eq!(first.status(), http::StatusCode::OK);
  assert_eq!(state.cache.stats().memory_entries, 0);

  let second = maybe_cache_response(
    Response::new(full_body(bytes::Bytes::from_static(b"admitted"))),
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &uri,
    &request_headers,
    None,
  )
  .await;
  assert_eq!(second.status(), http::StatusCode::OK);
  assert_eq!(state.cache.stats().memory_entries, 1);
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
      .is_some()
  );
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
    None,
  )
  .await;

  assert_eq!(response.status(), http::StatusCode::OK);
  assert_cache_status(&response, "miss", "not_cacheable");
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
    None,
  )
  .await;

  assert_eq!(response.status(), http::StatusCode::OK);
  assert_cache_status(&response, "miss", "admission_rejected");
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
    None,
  )
  .await;

  let delivered = response.headers().clone();
  assert_eq!(delivered.get("x-oxibelt-cache").unwrap(), "miss");
  assert_eq!(
    delivered.get("x-oxibelt-cache-reason").unwrap(),
    "too_large"
  );
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
  response
    .headers_mut()
    .insert("x-oxibelt-cache", HeaderValue::from_static("hit"));
  response
    .headers_mut()
    .insert("x-oxibelt-cache-reason", HeaderValue::from_static("forged"));
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
    None,
  )
  .await;

  assert_cache_status(&response, "miss", "stored");
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
    Some(crate::cache::CacheLookup::Fresh(entry)) => {
      assert_eq!(entry.body, body);
      assert_no_cache_status_headers(&entry.headers);
    }
    other => panic!("expected fresh cache hit, got {other:?}"),
  }
}

#[test]
fn cached_status_response_marks_hit_stale_and_revalidated() {
  let request_headers = HeaderMap::new();
  for (outcome, reason, expected_outcome, expected_reason) in [
    (
      super::cache_status::CacheHeaderOutcome::Hit,
      super::cache_status::CacheHeaderReason::Fresh,
      "hit",
      "fresh",
    ),
    (
      super::cache_status::CacheHeaderOutcome::Stale,
      super::cache_status::CacheHeaderReason::BackgroundRefresh,
      "stale",
      "background_refresh",
    ),
    (
      super::cache_status::CacheHeaderOutcome::Revalidated,
      super::cache_status::CacheHeaderReason::NotModified,
      "revalidated",
      "not_modified",
    ),
  ] {
    let mut headers = HeaderMap::new();
    headers.insert("x-oxibelt-cache", HeaderValue::from_static("miss"));
    headers.insert("x-oxibelt-cache-reason", HeaderValue::from_static("forged"));
    let response = super::cache_status::cached_status_response(
      crate::cache::CacheEntry::memory(
        StatusCode::OK,
        headers,
        bytes::Bytes::from_static(b"cached"),
      ),
      &Method::GET,
      &request_headers,
      outcome,
      reason,
    );
    assert_cache_status(&response, expected_outcome, expected_reason);
  }
}

#[tokio::test]
async fn cache_fill_preserves_single_chunk_bytes_without_copy() {
  let temp_dir = common::TempDir::new("cache-fill-single-chunk");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-fill-single-chunk");
  let raw = format!(
    r#"
{}

[proxy.buffering]
max_memory_body_bytes = 128

[cache]
enabled = true
store = "memory"
max_size_bytes = 1024
default_ttl_seconds = 60
cache_methods = ["GET"]
respect_cache_control = true
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let method = Method::GET;
  let uri: http::Uri = "/single-chunk?item=1".parse().expect("URI should parse");
  let request_headers = HeaderMap::new();
  let body = bytes::Bytes::from(vec![b'S'; 32]);
  let body_ptr = body.as_ptr();
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
    None,
  )
  .await;

  let delivered = response
    .into_body()
    .collect()
    .await
    .expect("response body should collect")
    .to_bytes();
  assert_eq!(delivered, body);
  assert_eq!(delivered.as_ptr(), body_ptr);
  match state.cache.lookup(crate::cache::CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.com",
    method: &method,
    uri: &uri,
    request_headers: &request_headers,
  }) {
    Some(crate::cache::CacheLookup::Fresh(entry)) => {
      assert_eq!(entry.body, body);
      assert_eq!(entry.body.as_ptr(), body_ptr);
    }
    other => panic!("expected fresh cache hit, got {other:?}"),
  }
}
