use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use flate2::Compression as FlateCompression;
use flate2::read::GzEncoder;
use http::{HeaderMap, Request};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use pretty_assertions::assert_eq;

use super::body::CapturedBody;
use super::waf_body_capture::{
  WafBodyCaptureError, capture_request_body_for_waf, capture_response_body_for_waf,
  request_body_is_definitely_empty, response_body_is_definitely_empty,
};
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

struct DropTrackedBytes {
  bytes: Vec<u8>,
  drops: Arc<AtomicUsize>,
}

impl DropTrackedBytes {
  fn new(bytes: Vec<u8>, drops: Arc<AtomicUsize>) -> Self {
    Self { bytes, drops }
  }
}

impl AsRef<[u8]> for DropTrackedBytes {
  fn as_ref(&self) -> &[u8] {
    &self.bytes
  }
}

impl Drop for DropTrackedBytes {
  fn drop(&mut self) {
    self.drops.fetch_add(1, Ordering::SeqCst);
  }
}

fn gzip_bytes(bytes: &'static [u8]) -> bytes::Bytes {
  let mut encoder = GzEncoder::new(bytes, FlateCompression::default());
  let mut encoded = Vec::new();
  encoder
    .read_to_end(&mut encoded)
    .expect("gzip encoding should succeed");
  bytes::Bytes::from(encoded)
}

async fn capture_request_body_without_transform(
  request: Request<ProxyBody>,
  body_need: BodyNeed,
  limit: usize,
) -> Result<(Request<ProxyBody>, Option<CapturedBody>), WafBodyCaptureError> {
  let config = crate::waf::WafHttpBodyCompressionConfig::default();
  let state = waf_body_coding::WafBodyCodingState::new(&config);
  capture_request_body_for_waf(request, body_need, limit, false, &config, &state).await
}

#[tokio::test]
async fn size_only_transform_decodes_compressed_body_even_with_content_length() {
  let config = crate::waf::WafHttpBodyCompressionConfig {
    mode: crate::waf::WafHttpBodyCompressionMode::Transform,
    ..crate::waf::WafHttpBodyCompressionConfig::default()
  };
  let state = waf_body_coding::WafBodyCodingState::new(&config);
  let encoded = gzip_bytes(b"abcdef");
  let request = Request::builder()
    .uri("https://example.com/upload")
    .header(http::header::CONTENT_ENCODING, "gzip")
    .header(http::header::CONTENT_LENGTH, encoded.len().to_string())
    .body(full_body(encoded))
    .expect("request should build");

  let (request, captured) =
    capture_request_body_for_waf(request, BodyNeed::SizeOnly, 8, true, &config, &state)
      .await
      .expect("compressed size-only body should transform");
  let captured = captured.expect("decoded size-only body should be captured");

  assert_eq!(captured.bytes.as_ref(), b"abcdef");
  assert!(!captured.is_truncated);
  assert!(!request.headers().contains_key(http::header::CONTENT_LENGTH));
  assert_eq!(request.headers()[http::header::CONTENT_ENCODING], "gzip");
}

#[tokio::test]
async fn none_request_body_capture_skips_compressed_body_without_polling() {
  let config = crate::waf::WafHttpBodyCompressionConfig {
    mode: crate::waf::WafHttpBodyCompressionMode::Transform,
    ..crate::waf::WafHttpBodyCompressionConfig::default()
  };
  let state = waf_body_coding::WafBodyCodingState::new(&config);
  let request = Request::builder()
    .uri("https://example.com/upload")
    .header(http::header::CONTENT_ENCODING, "gzip")
    .body(panic_body())
    .expect("request should build");

  let (_request, captured) =
    capture_request_body_for_waf(request, BodyNeed::None, 8, true, &config, &state)
      .await
      .expect("none body capture should skip");

  assert!(captured.is_none());
}

#[tokio::test]
async fn none_response_body_capture_skips_compressed_body_without_polling() {
  let config = crate::waf::WafHttpBodyCompressionConfig {
    mode: crate::waf::WafHttpBodyCompressionMode::Transform,
    ..crate::waf::WafHttpBodyCompressionConfig::default()
  };
  let state = waf_body_coding::WafBodyCodingState::new(&config);
  let mut headers = HeaderMap::new();
  headers.insert(
    http::header::CONTENT_ENCODING,
    http::HeaderValue::from_static("gzip"),
  );

  let (_body, captured) = capture_response_body_for_waf(
    http::Version::HTTP_11,
    &mut headers,
    panic_body(),
    BodyNeed::None,
    8,
    true,
    &config,
    &state,
  )
  .await
  .expect("none response capture should skip");

  assert!(captured.is_none());
  assert_eq!(headers[http::header::CONTENT_ENCODING], "gzip");
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

  let (_request, captured) = capture_request_body_without_transform(request, BodyNeed::SizeOnly, 8)
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

  let (request, captured) = capture_request_body_without_transform(request, BodyNeed::SizeOnly, 8)
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

  let (_request, captured) =
    capture_request_body_without_transform(request, BodyNeed::PrefixBytes, 8)
      .await
      .expect("prefix capture should succeed");

  assert_eq!(
    captured.expect("body should be captured").bytes.as_ref(),
    b"abc"
  );
}

#[tokio::test]
async fn truncated_request_prefix_capture_does_not_retain_oversized_frame_owner() {
  let drops = Arc::new(AtomicUsize::new(0));
  let owner = DropTrackedBytes::new(vec![b'x'; 1024 * 1024], Arc::clone(&drops));
  let request = Request::builder()
    .uri("https://example.com/upload")
    .body(full_body(bytes::Bytes::from_owner(owner)))
    .expect("request should build");

  let (request, captured) =
    capture_request_body_without_transform(request, BodyNeed::PrefixBytes, 8)
      .await
      .expect("prefix capture should succeed");
  let captured = captured.expect("body should be captured");

  assert_eq!(captured.bytes.len(), 8);
  assert!(captured.is_truncated);
  assert_eq!(drops.load(Ordering::SeqCst), 0);
  drop(request);
  assert_eq!(
    drops.load(Ordering::SeqCst),
    1,
    "captured prefix must not retain the oversized original frame owner"
  );
  assert_eq!(captured.bytes.as_ref(), &[b'x'; 8]);
}

#[tokio::test]
async fn truncated_response_prefix_capture_does_not_retain_oversized_frame_owner() {
  let drops = Arc::new(AtomicUsize::new(0));
  let owner = DropTrackedBytes::new(vec![b'y'; 1024 * 1024], Arc::clone(&drops));
  let config = crate::waf::WafHttpBodyCompressionConfig::default();
  let state = waf_body_coding::WafBodyCodingState::new(&config);
  let mut headers = HeaderMap::new();

  let (body, captured) = capture_response_body_for_waf(
    http::Version::HTTP_11,
    &mut headers,
    full_body(bytes::Bytes::from_owner(owner)),
    BodyNeed::PrefixBytes,
    8,
    false,
    &config,
    &state,
  )
  .await
  .expect("response prefix capture should succeed");
  let captured = captured.expect("body should be captured");

  assert_eq!(captured.bytes.len(), 8);
  assert!(captured.is_truncated);
  assert_eq!(drops.load(Ordering::SeqCst), 0);
  drop(body);
  assert_eq!(
    drops.load(Ordering::SeqCst),
    1,
    "captured prefix must not retain the oversized original frame owner"
  );
  assert_eq!(captured.bytes.as_ref(), &[b'y'; 8]);
}

#[tokio::test]
async fn exact_empty_request_body_uses_empty_capture_without_polling() {
  let request = Request::builder()
    .uri("https://example.com/upload")
    .header(http::header::CONTENT_LENGTH, "0")
    .body(panic_body())
    .expect("request should build");

  let (_request, captured) =
    capture_request_body_without_transform(request, BodyNeed::PrefixBytes, 8)
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

  let (_request, captured) = capture_request_body_without_transform(request, BodyNeed::SizeOnly, 8)
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
