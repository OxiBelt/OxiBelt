use super::*;
use crate::config::TrailerMode;
use crate::proxy::http::integrity_digest::{self, DigestRequest};
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

fn digest(bytes: &[u8]) -> String {
  format!(
    "sha-256=:{}:",
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes))
  )
}

fn entry() -> CacheEntry {
  let mut headers = HeaderMap::new();
  headers.insert(ETAG, HeaderValue::from_static("\"digest-fixture\""));
  headers.insert(
    "content-digest",
    HeaderValue::from_str(&digest(b"0123456789")).unwrap(),
  );
  CacheEntry::memory(
    StatusCode::OK,
    headers,
    bytes::Bytes::from_static(b"0123456789"),
  )
}

fn wants() -> HeaderMap {
  let mut headers = HeaderMap::new();
  for name in [
    "want-content-digest",
    "want-repr-digest",
    "want-unencoded-digest",
  ] {
    headers.insert(name, HeaderValue::from_static("sha-256=10"));
  }
  headers
}

#[tokio::test]
async fn cached_ranges_hash_content_separately_from_available_representation() {
  for range in ["bytes=2-4", "bytes=0-1,8-9"] {
    let mut headers = wants();
    headers.insert(http::header::RANGE, HeaderValue::from_str(range).unwrap());
    let context = DigestRequest::new(
      &Method::GET,
      http::Version::HTTP_2,
      &headers,
      TrailerMode::Pass,
    );
    let response = integrity_digest::finalize(
      cached_entry_response(entry(), &Method::GET, &headers),
      &context,
    );
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let response_headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(response_headers["content-digest"], digest(&body));
    assert_eq!(response_headers["repr-digest"], digest(b"0123456789"));
    assert_eq!(response_headers["unencoded-digest"], digest(b"0123456789"));
  }
}

#[tokio::test]
async fn cached_head_and_304_do_not_hash_empty_content_as_the_resource() {
  for method in [Method::HEAD, Method::GET] {
    let mut headers = wants();
    if method == Method::GET {
      headers.insert(
        IF_NONE_MATCH,
        HeaderValue::from_static("\"digest-fixture\""),
      );
    }
    let context = DigestRequest::new(&method, http::Version::HTTP_2, &headers, TrailerMode::Pass);
    let response =
      integrity_digest::finalize(cached_entry_response(entry(), &method, &headers), &context);
    assert_eq!(response.headers()["content-digest"], digest(b""));
    assert_eq!(response.headers()["repr-digest"], digest(b"0123456789"));
    assert_eq!(
      response.headers()["unencoded-digest"],
      digest(b"0123456789")
    );
    assert!(
      response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .is_empty()
    );
  }
}

#[test]
fn negotiated_generation_does_not_mutate_the_cached_entry() {
  let entry = entry();
  let headers = wants();
  let context = DigestRequest::new(
    &Method::GET,
    http::Version::HTTP_2,
    &headers,
    TrailerMode::Pass,
  );
  let negotiated = integrity_digest::finalize(
    cached_entry_response(entry.clone(), &Method::GET, &headers),
    &context,
  );
  assert!(negotiated.headers().contains_key("repr-digest"));
  let ordinary = cached_entry_response(entry, &Method::GET, &HeaderMap::new());
  assert!(!ordinary.headers().contains_key("repr-digest"));
  assert!(!ordinary.headers().contains_key("unencoded-digest"));
}
