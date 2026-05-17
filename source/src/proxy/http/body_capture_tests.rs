use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http::{HeaderMap, Request};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use pretty_assertions::assert_eq;

use super::*;

struct PanicBody;

impl Body for PanicBody {
  type Data = bytes::Bytes;
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

fn panic_body() -> ProxyBody {
  PanicBody.boxed()
}

#[test]
fn http2_content_length_zero_is_not_definitive_until_end_stream() {
  let mut headers = HeaderMap::new();
  headers.insert(
    http::header::CONTENT_LENGTH,
    http::HeaderValue::from_static("0"),
  );

  assert!(request_body_is_definitely_empty(
    http::Version::HTTP_11,
    &headers
  ));
  assert!(!request_body_is_definitely_empty(
    http::Version::HTTP_2,
    &headers
  ));
  assert!(!response_body_is_definitely_empty(
    http::Version::HTTP_2,
    &headers
  ));
}

#[tokio::test]
async fn size_only_request_body_capture_uses_positive_content_length_without_polling() {
  let request = Request::builder()
    .uri("https://example.com/upload")
    .header(http::header::CONTENT_LENGTH, "9")
    .body(panic_body())
    .expect("request should build");

  let (_request, captured) = capture_request_body_for_waf(request, BodyNeed::SizeOnly, 8)
    .await
    .expect("size-only capture with known length should be skipped");

  assert!(captured.is_none());
}

#[tokio::test]
async fn size_only_request_body_capture_reads_unknown_length_body() {
  let request = Request::builder()
    .uri("https://example.com/upload")
    .body(full_body(bytes::Bytes::from_static(b"abcdef")))
    .expect("request should build");

  let (request, captured) = capture_request_body_for_waf(request, BodyNeed::SizeOnly, 8)
    .await
    .expect("size-only capture should read unknown length body");
  let captured = captured.expect("unknown length body should be captured");

  assert_eq!(captured.bytes.as_ref(), b"abcdef");
  assert!(!captured.is_truncated);
  let replayed = request
    .into_body()
    .collect()
    .await
    .expect("captured body should replay")
    .to_bytes();
  assert_eq!(replayed.as_ref(), b"abcdef");
}

#[tokio::test]
async fn prefix_request_body_capture_reads_body() {
  let request = Request::builder()
    .uri("https://example.com/upload")
    .body(full_body(bytes::Bytes::from_static(b"abc")))
    .expect("request should build");

  let (_request, captured) = capture_request_body_for_waf(request, BodyNeed::PrefixBytes, 8)
    .await
    .expect("prefix capture should succeed");

  assert_eq!(
    captured.expect("body should be captured").bytes.as_ref(),
    b"abc"
  );
}

#[tokio::test]
async fn exact_empty_request_body_uses_empty_capture_without_polling() {
  let request = Request::builder()
    .uri("https://example.com/upload")
    .header(http::header::CONTENT_LENGTH, "0")
    .body(panic_body())
    .expect("request should build");

  let (_request, captured) = capture_request_body_for_waf(request, BodyNeed::PrefixBytes, 8)
    .await
    .expect("empty capture should succeed");
  let captured = captured.expect("empty body should be captured");

  assert!(captured.bytes.is_empty());
  assert!(!captured.is_truncated);
}

#[tokio::test]
async fn size_only_exact_empty_request_body_uses_empty_capture_without_polling() {
  let request = Request::builder()
    .uri("https://example.com/upload")
    .header(http::header::CONTENT_LENGTH, "0")
    .body(panic_body())
    .expect("request should build");

  let (_request, captured) = capture_request_body_for_waf(request, BodyNeed::SizeOnly, 8)
    .await
    .expect("empty size-only capture should succeed");
  let captured = captured.expect("empty body should be captured");

  assert!(captured.bytes.is_empty());
  assert!(!captured.is_truncated);
}

#[tokio::test]
async fn h2_and_h3_content_length_zero_data_is_rejected() {
  for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
    let request = Request::builder()
      .version(version)
      .header(http::header::CONTENT_LENGTH, "0")
      .body(full_body(bytes::Bytes::from_static(b"x")))
      .expect("request should build");

    let result = reject_content_length_zero_data(request, Duration::from_secs(1), version).await;
    let response = match result {
      Ok(_) => panic!("Content-Length: 0 DATA should be rejected for {version:?}"),
      Err(response) => response,
    };
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
  }
}
