use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use http_body_util::{BodyExt, Full};
use pretty_assertions::assert_eq;

use super::test_support::counted_body;
use super::*;

fn config_for_tests() -> WafHttpBodyCompressionConfig {
  WafHttpBodyCompressionConfig {
    mode: crate::waf::WafHttpBodyCompressionMode::Transform,
    max_decoded_body_bytes: 1024,
    max_expansion_ratio: 100,
    decode_timeout_ms: 1000,
    ..WafHttpBodyCompressionConfig::default()
  }
}

fn body(bytes: impl Into<Bytes>) -> ProxyBody {
  Full::new(bytes.into())
    .map_err(|never| -> body::BoxError { match never {} })
    .boxed()
}

fn single_permit_config() -> WafHttpBodyCompressionConfig {
  WafHttpBodyCompressionConfig {
    max_concurrent_bodies: 1,
    ..config_for_tests()
  }
}

async fn encoded_bytes(
  bytes: &'static [u8],
  encoding: WafHttpBodyEncoding,
) -> Result<Bytes, WafBodyCodingError> {
  encode_body_sync(Bytes::from_static(bytes), encoding)
}

fn large_window_fuzz_regression() -> Vec<u8> {
  base64::engine::general_purpose::STANDARD
    .decode(
      include_str!(
        "../../../../../tests/fixtures/fuzz-regressions/http_body_coding/large-window.txt"
      )
      .trim(),
    )
    .expect("reviewed Brotli fuzz regression should be valid base64")
}

#[tokio::test]
async fn request_transform_waits_for_permit_before_collecting_body() {
  let config = single_permit_config();
  let state = WafBodyCodingState::new(&config);
  let held_permit = state.acquire().await;
  let poll_count = Arc::new(AtomicUsize::new(0));
  let encoded = encoded_bytes(b"bounded request body", WafHttpBodyEncoding::Gzip)
    .await
    .expect("gzip encode should succeed");
  let request = Request::builder()
    .header(CONTENT_ENCODING, "gzip")
    .body(counted_body(encoded, poll_count.clone()))
    .expect("request should build");
  let transform = transform_request_body_for_waf(request, config.clone(), state.clone(), 8);
  tokio::pin!(transform);
  assert!(
    tokio::time::timeout(Duration::from_millis(25), &mut transform)
      .await
      .is_err()
  );
  assert_eq!(poll_count.load(Ordering::SeqCst), 0);
  drop(held_permit);
  let (request, captured) = transform
    .await
    .expect("request transform should succeed")
    .expect("encoded request should transform");
  assert!(poll_count.load(Ordering::SeqCst) > 0);
  assert_eq!(captured.bytes.as_ref(), b"bounded ");
  assert!(captured.is_truncated);
  let replayed = request
    .into_body()
    .collect()
    .await
    .expect("replayed body should collect")
    .to_bytes();
  let decoded =
    decode_body_sync(replayed, WafHttpBodyEncoding::Gzip, 1024).expect("request should decode");
  assert_eq!(decoded.as_ref(), b"bounded request body");
}

#[tokio::test]
async fn response_transform_waits_for_permit_before_collecting_body() {
  let config = single_permit_config();
  let state = WafBodyCodingState::new(&config);
  let held_permit = state.acquire().await;
  let poll_count = Arc::new(AtomicUsize::new(0));
  let encoded = encoded_bytes(b"bounded response body", WafHttpBodyEncoding::Gzip)
    .await
    .expect("gzip encode should succeed");
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_ENCODING, http::HeaderValue::from_static("gzip"));
  headers.insert(CONTENT_LENGTH, http::HeaderValue::from_static("42"));
  let (body, captured) = {
    let transform = transform_response_body_for_waf(
      &mut headers,
      counted_body(encoded, poll_count.clone()),
      config,
      state,
      8,
    );
    tokio::pin!(transform);
    assert!(
      tokio::time::timeout(Duration::from_millis(25), &mut transform)
        .await
        .is_err()
    );
    assert_eq!(poll_count.load(Ordering::SeqCst), 0);
    drop(held_permit);
    transform
      .await
      .expect("response transform should succeed")
      .expect("encoded response should transform")
  };
  assert!(poll_count.load(Ordering::SeqCst) > 0);
  assert_eq!(captured.bytes.as_ref(), b"bounded ");
  assert!(captured.is_truncated);
  assert!(!headers.contains_key(CONTENT_ENCODING));
  assert!(!headers.contains_key(CONTENT_LENGTH));
  let decoded = body
    .collect()
    .await
    .expect("decoded response should collect")
    .to_bytes();
  assert_eq!(decoded.as_ref(), b"bounded response body");
}

#[tokio::test]
async fn supported_encodings_roundtrip_and_preserve_decoded_capture() {
  for encoding in [
    WafHttpBodyEncoding::Gzip,
    WafHttpBodyEncoding::Deflate,
    WafHttpBodyEncoding::Br,
    WafHttpBodyEncoding::Zstd,
  ] {
    let config = config_for_tests();
    let state = WafBodyCodingState::new(&config);
    let encoded = encoded_bytes(b"prefix secret suffix", encoding)
      .await
      .expect("encode should succeed");
    let request = Request::builder()
      .header(CONTENT_ENCODING, encoding.as_content_encoding())
      .header(CONTENT_LENGTH, encoded.len().to_string())
      .body(body(encoded.clone()))
      .expect("request should build");
    let (request, captured) = transform_request_body_for_waf(request, config, state, 8)
      .await
      .expect("request transform should succeed")
      .expect("encoded request should transform");
    assert_eq!(captured.bytes.as_ref(), b"prefix s");
    assert!(captured.is_truncated);
    assert!(!request.headers().contains_key(CONTENT_LENGTH));
    assert_eq!(
      request.headers()[CONTENT_ENCODING],
      encoding.as_content_encoding()
    );
    let replayed = request
      .into_body()
      .collect()
      .await
      .expect("replayed body should collect")
      .to_bytes();
    let decoded = decode_body_sync(replayed, encoding, 1024).expect("replayed body should decode");
    assert_eq!(decoded.as_ref(), b"prefix secret suffix");
  }
}

#[test]
fn brotli_large_window_fuzz_regression_fails_closed() {
  let encoded = large_window_fuzz_regression();
  assert_eq!(encoded.first().copied().unwrap_or_default() % 4, 2);

  let error = decode_body_sync(
    Bytes::copy_from_slice(&encoded[1..]),
    WafHttpBodyEncoding::Br,
    64 * 1024,
  )
  .expect_err("non-standard Large Window Brotli must fail closed");
  assert_eq!(error.kind(), WafBodyCodingErrorKind::Malformed);
}

#[test]
fn brotli_strict_decoder_accepts_standard_maximum_window() {
  let original = Bytes::from(vec![b'a'; 8192]);
  let encoded = read_encoded_sync(CompressorReader::new(
    Cursor::new(original.clone()),
    4096,
    5,
    24,
  ))
  .expect("standard Brotli with lgwin 24 should encode");
  let decoded = decode_body_sync(encoded, WafHttpBodyEncoding::Br, original.len())
    .expect("standard Brotli with lgwin 24 should decode");
  assert_eq!(decoded, original);
}

#[tokio::test]
async fn request_transform_rejects_large_window_brotli_as_malformed() {
  let encoded = large_window_fuzz_regression();
  let config = config_for_tests();
  let state = WafBodyCodingState::new(&config);
  let request = Request::builder()
    .header(CONTENT_ENCODING, "br")
    .body(body(Bytes::copy_from_slice(&encoded[1..])))
    .expect("request should build");

  let error = transform_request_body_for_waf(request, config, state, 8)
    .await
    .expect_err("Large Window Brotli request must fail closed");
  assert_eq!(error.kind(), WafBodyCodingErrorKind::Malformed);
}

#[tokio::test]
async fn unsupported_content_encoding_is_rejected() {
  let config = config_for_tests();
  let state = WafBodyCodingState::new(&config);
  let request = Request::builder()
    .header(CONTENT_ENCODING, "compress")
    .body(body(Bytes::from_static(b"data")))
    .expect("request should build");
  let error = transform_request_body_for_waf(request, config, state, 8)
    .await
    .expect_err("unsupported coding should fail");
  assert_eq!(error.kind(), WafBodyCodingErrorKind::Unsupported);
}

#[tokio::test]
async fn decoded_limit_rejects_compression_bomb() {
  let mut config = config_for_tests();
  config.max_decoded_body_bytes = 8;
  config.max_expansion_ratio = 1000;
  let state = WafBodyCodingState::new(&config);
  let encoded = encoded_bytes(b"0123456789abcdef", WafHttpBodyEncoding::Gzip)
    .await
    .expect("gzip encode should succeed");
  let request = Request::builder()
    .header(CONTENT_ENCODING, "gzip")
    .body(body(encoded))
    .expect("request should build");
  let error = transform_request_body_for_waf(request, config, state, 8)
    .await
    .expect_err("decoded body over limit should fail");
  assert_eq!(error.kind(), WafBodyCodingErrorKind::TooLarge);
}

#[tokio::test]
async fn expansion_ratio_limit_rejects_bomb_shape() {
  let mut config = config_for_tests();
  config.max_decoded_body_bytes = 4096;
  config.max_expansion_ratio = 1;
  let state = WafBodyCodingState::new(&config);
  let encoded = encoded_bytes(
    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    WafHttpBodyEncoding::Gzip,
  )
  .await
  .expect("gzip encode should succeed");
  let request = Request::builder()
    .header(CONTENT_ENCODING, "gzip")
    .body(body(encoded))
    .expect("request should build");
  let error = transform_request_body_for_waf(request, config, state, 8)
    .await
    .expect_err("expansion ratio should fail");
  assert_eq!(error.kind(), WafBodyCodingErrorKind::TooLarge);
}
