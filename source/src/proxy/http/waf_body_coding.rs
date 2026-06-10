//! HTTP body content-coding transforms used only for opt-in WAF inspection.
//! Bodies are attacker controlled, so decode work is bounded by byte, ratio, timeout, and concurrency limits.

use std::fmt;
use std::io::{self, Cursor, Read};
use std::sync::Arc;
use std::time::Duration;

use brotli::{CompressorReader, Decompressor};
use bytes::{Bytes, BytesMut};
use flate2::Compression as FlateCompression;
use flate2::read::{GzDecoder, GzEncoder, ZlibDecoder, ZlibEncoder};
use http::header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, ETAG};
use http::{HeaderMap, Request};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::waf::{WafHttpBodyCompressionConfig, WafHttpBodyEncoding};

use super::body::{self, BodyTimeoutKind, CapturedBody, ProxyBody, error_is_timeout};

#[derive(Debug)]
pub(crate) struct WafBodyCodingState {
  semaphore: Arc<Semaphore>,
}

impl WafBodyCodingState {
  pub(crate) fn new(config: &WafHttpBodyCompressionConfig) -> Arc<Self> {
    let limit = if config.max_concurrent_bodies == 0 {
      std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().saturating_mul(2))
        .unwrap_or(2)
    } else {
      config.max_concurrent_bodies
    }
    .max(1);
    Arc::new(Self {
      semaphore: Arc::new(Semaphore::new(limit)),
    })
  }

  async fn acquire(&self) -> OwnedSemaphorePermit {
    self
      .semaphore
      .clone()
      .acquire_owned()
      .await
      .expect("WAF body coding semaphore is never closed")
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum WafBodyCodingErrorKind {
  Unsupported,
  UnsafeTransform,
  Malformed,
  TooLarge,
  DecodeTimeout,
  BodyReadTimeout,
  BodyRead,
}

#[derive(Debug)]
pub(crate) struct WafBodyCodingError {
  kind: WafBodyCodingErrorKind,
  message: String,
}

impl WafBodyCodingError {
  pub(crate) fn new(kind: WafBodyCodingErrorKind, message: impl Into<String>) -> Self {
    Self {
      kind,
      message: message.into(),
    }
  }

  pub(crate) fn kind(&self) -> WafBodyCodingErrorKind {
    self.kind
  }
}

impl fmt::Display for WafBodyCodingError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::error::Error for WafBodyCodingError {}

struct CollectedBody {
  bytes: Bytes,
  trailers: Option<HeaderMap>,
}

pub(crate) async fn transform_request_body_for_waf(
  request: Request<ProxyBody>,
  config: WafHttpBodyCompressionConfig,
  state: Arc<WafBodyCodingState>,
  inspection_limit: usize,
) -> Result<Option<(Request<ProxyBody>, CapturedBody)>, WafBodyCodingError> {
  let Some(encoding) = selected_content_encoding(request.headers(), &config)? else {
    return Ok(None);
  };

  let (mut parts, body) = request.into_parts();
  let collected = collect_limited_body(
    body,
    config.max_decoded_body_bytes,
    BodyTimeoutKind::DownstreamRequestRead,
  )
  .await?;
  let decoded = decode_body(
    collected.bytes,
    encoding,
    config.max_decoded_body_bytes,
    config.max_expansion_ratio,
    config.decode_timeout_ms,
    state,
  )
  .await?;
  let captured = captured_decoded_body(&decoded, inspection_limit);
  let reencoded = encode_body(decoded, encoding).await?;
  parts.headers.remove(CONTENT_LENGTH);
  let body = body_from_bytes_and_trailers(reencoded, collected.trailers);
  Ok(Some((Request::from_parts(parts, body), captured)))
}

pub(crate) async fn transform_response_body_for_waf(
  headers: &mut HeaderMap,
  body: ProxyBody,
  config: WafHttpBodyCompressionConfig,
  state: Arc<WafBodyCodingState>,
  inspection_limit: usize,
) -> Result<Option<(ProxyBody, CapturedBody)>, WafBodyCodingError> {
  let Some(encoding) = selected_content_encoding(headers, &config)? else {
    return Ok(None);
  };
  ensure_response_transform_safe(headers)?;

  let collected = collect_limited_body(
    body,
    config.max_decoded_body_bytes,
    BodyTimeoutKind::UpstreamResponseRead,
  )
  .await?;
  let decoded = decode_body(
    collected.bytes,
    encoding,
    config.max_decoded_body_bytes,
    config.max_expansion_ratio,
    config.decode_timeout_ms,
    state,
  )
  .await?;
  let captured = captured_decoded_body(&decoded, inspection_limit);
  headers.remove(CONTENT_ENCODING);
  headers.remove(CONTENT_LENGTH);
  weaken_strong_etag(headers);
  let body = body_from_bytes_and_trailers(decoded, collected.trailers);
  Ok(Some((body, captured)))
}

pub(crate) fn has_non_identity_content_encoding(headers: &HeaderMap) -> bool {
  headers.get_all(CONTENT_ENCODING).iter().any(|value| {
    value
      .to_str()
      .map(|value| {
        value
          .split(',')
          .map(str::trim)
          .filter(|token| !token.is_empty())
          .any(|token| !token.eq_ignore_ascii_case("identity"))
      })
      .unwrap_or(true)
  })
}

fn selected_content_encoding(
  headers: &HeaderMap,
  config: &WafHttpBodyCompressionConfig,
) -> Result<Option<WafHttpBodyEncoding>, WafBodyCodingError> {
  let mut tokens = Vec::new();
  for value in headers.get_all(CONTENT_ENCODING) {
    let value = value.to_str().map_err(|_| {
      WafBodyCodingError::new(
        WafBodyCodingErrorKind::Unsupported,
        "invalid Content-Encoding header",
      )
    })?;
    for item in value.split(',') {
      let token = item.trim();
      if !token.is_empty() {
        tokens.push(token.to_ascii_lowercase());
      }
    }
  }
  if tokens.is_empty() || (tokens.len() == 1 && tokens[0].eq_ignore_ascii_case("identity")) {
    return Ok(None);
  }
  if tokens.len() != 1 || tokens[0].eq_ignore_ascii_case("identity") {
    return Err(WafBodyCodingError::new(
      WafBodyCodingErrorKind::Unsupported,
      "multiple Content-Encoding values are not supported for WAF body transform",
    ));
  }
  let encoding = match tokens[0].as_str() {
    "gzip" => WafHttpBodyEncoding::Gzip,
    "deflate" => WafHttpBodyEncoding::Deflate,
    "br" => WafHttpBodyEncoding::Br,
    "zstd" => WafHttpBodyEncoding::Zstd,
    _ => {
      return Err(WafBodyCodingError::new(
        WafBodyCodingErrorKind::Unsupported,
        "unsupported Content-Encoding for WAF body transform",
      ));
    }
  };
  if !config.allows_encoding(encoding.as_content_encoding()) {
    return Err(WafBodyCodingError::new(
      WafBodyCodingErrorKind::Unsupported,
      "Content-Encoding is disabled for WAF body transform",
    ));
  }
  Ok(Some(encoding))
}

fn ensure_response_transform_safe(headers: &HeaderMap) -> Result<(), WafBodyCodingError> {
  if headers.contains_key(CONTENT_RANGE) || has_cache_control_directive(headers, "no-transform") {
    return Err(WafBodyCodingError::new(
      WafBodyCodingErrorKind::UnsafeTransform,
      "response content coding cannot be transformed safely for WAF inspection",
    ));
  }
  Ok(())
}

async fn collect_limited_body(
  body: ProxyBody,
  max_encoded_body_bytes: usize,
  timeout_kind: BodyTimeoutKind,
) -> Result<CollectedBody, WafBodyCodingError> {
  let mut body = Box::pin(body);
  let mut bytes = BytesMut::new();
  let mut trailers = None;
  while let Some(frame) = body.as_mut().frame().await {
    let frame = frame.map_err(|error| transform_body_read_error(error, timeout_kind))?;
    match frame.into_data() {
      Ok(data) => {
        if bytes.len().saturating_add(data.len()) > max_encoded_body_bytes {
          return Err(WafBodyCodingError::new(
            WafBodyCodingErrorKind::TooLarge,
            "encoded body exceeds WAF body transform limit",
          ));
        }
        bytes.extend_from_slice(&data);
      }
      Err(frame) => {
        if let Ok(frame_trailers) = frame.into_trailers() {
          trailers = Some(frame_trailers);
          break;
        }
      }
    }
  }
  Ok(CollectedBody {
    bytes: bytes.freeze(),
    trailers,
  })
}

fn transform_body_read_error(
  error: body::BoxError,
  timeout_kind: BodyTimeoutKind,
) -> WafBodyCodingError {
  if error_is_timeout(&error, timeout_kind) {
    WafBodyCodingError::new(
      WafBodyCodingErrorKind::BodyReadTimeout,
      "body read timed out during WAF body transform",
    )
  } else {
    WafBodyCodingError::new(
      WafBodyCodingErrorKind::BodyRead,
      format!("failed to read body for WAF body transform: {error}"),
    )
  }
}

async fn decode_body(
  encoded: Bytes,
  encoding: WafHttpBodyEncoding,
  max_decoded_body_bytes: usize,
  max_expansion_ratio: usize,
  decode_timeout_ms: u64,
  state: Arc<WafBodyCodingState>,
) -> Result<Bytes, WafBodyCodingError> {
  let permit = state.acquire().await;
  let encoded_len = encoded.len();
  let max_bytes = max_decoded_body_bytes;
  let timeout = Duration::from_millis(decode_timeout_ms);
  let decoded = tokio::time::timeout(
    timeout,
    tokio::task::spawn_blocking(move || {
      let _permit = permit;
      decode_body_sync(encoded, encoding, max_bytes)
    }),
  )
  .await
  .map_err(|_| {
    WafBodyCodingError::new(
      WafBodyCodingErrorKind::DecodeTimeout,
      "WAF body transform decode timed out",
    )
  })?
  .map_err(|error| {
    WafBodyCodingError::new(
      WafBodyCodingErrorKind::BodyRead,
      format!("WAF body transform worker failed: {error}"),
    )
  })??;
  if expansion_ratio_exceeded(encoded_len, decoded.len(), max_expansion_ratio) {
    return Err(WafBodyCodingError::new(
      WafBodyCodingErrorKind::TooLarge,
      "decoded body exceeds WAF body transform expansion ratio",
    ));
  }
  Ok(decoded)
}

async fn encode_body(
  decoded: Bytes,
  encoding: WafHttpBodyEncoding,
) -> Result<Bytes, WafBodyCodingError> {
  tokio::task::spawn_blocking(move || encode_body_sync(decoded, encoding))
    .await
    .map_err(|error| {
      WafBodyCodingError::new(
        WafBodyCodingErrorKind::BodyRead,
        format!("WAF body transform worker failed: {error}"),
      )
    })?
}

fn decode_body_sync(
  encoded: Bytes,
  encoding: WafHttpBodyEncoding,
  max_bytes: usize,
) -> Result<Bytes, WafBodyCodingError> {
  match encoding {
    WafHttpBodyEncoding::Gzip => read_decoded_sync(GzDecoder::new(Cursor::new(encoded)), max_bytes),
    WafHttpBodyEncoding::Deflate => {
      read_decoded_sync(ZlibDecoder::new(Cursor::new(encoded)), max_bytes)
    }
    WafHttpBodyEncoding::Br => {
      read_decoded_sync(Decompressor::new(Cursor::new(encoded), 4096), max_bytes)
    }
    WafHttpBodyEncoding::Zstd => {
      let decoder = zstd::stream::Decoder::new(Cursor::new(encoded)).map_err(decode_io_error)?;
      read_decoded_sync(decoder, max_bytes)
    }
  }
}

fn encode_body_sync(
  decoded: Bytes,
  encoding: WafHttpBodyEncoding,
) -> Result<Bytes, WafBodyCodingError> {
  match encoding {
    WafHttpBodyEncoding::Gzip => read_encoded_sync(GzEncoder::new(
      Cursor::new(decoded),
      FlateCompression::default(),
    )),
    WafHttpBodyEncoding::Deflate => read_encoded_sync(ZlibEncoder::new(
      Cursor::new(decoded),
      FlateCompression::default(),
    )),
    WafHttpBodyEncoding::Br => {
      read_encoded_sync(CompressorReader::new(Cursor::new(decoded), 4096, 5, 22))
    }
    WafHttpBodyEncoding::Zstd => zstd::stream::encode_all(Cursor::new(decoded), 0)
      .map(Bytes::from)
      .map_err(encode_io_error),
  }
}

fn read_decoded_sync<R: Read>(reader: R, max_bytes: usize) -> Result<Bytes, WafBodyCodingError> {
  let mut decoded = Vec::new();
  let mut limited = reader.take(max_bytes.saturating_add(1) as u64);
  limited.read_to_end(&mut decoded).map_err(decode_io_error)?;
  if decoded.len() > max_bytes {
    return Err(WafBodyCodingError::new(
      WafBodyCodingErrorKind::TooLarge,
      "decoded body exceeds WAF body transform limit",
    ));
  }
  Ok(Bytes::from(decoded))
}

fn read_encoded_sync<R: Read>(mut reader: R) -> Result<Bytes, WafBodyCodingError> {
  let mut encoded = Vec::new();
  reader.read_to_end(&mut encoded).map_err(encode_io_error)?;
  Ok(Bytes::from(encoded))
}

fn decode_io_error(error: io::Error) -> WafBodyCodingError {
  WafBodyCodingError::new(
    WafBodyCodingErrorKind::Malformed,
    format!("failed to decode body for WAF inspection: {error}"),
  )
}

fn encode_io_error(error: io::Error) -> WafBodyCodingError {
  WafBodyCodingError::new(
    WafBodyCodingErrorKind::Malformed,
    format!("failed to re-encode body after WAF inspection: {error}"),
  )
}

fn expansion_ratio_exceeded(encoded_len: usize, decoded_len: usize, max_ratio: usize) -> bool {
  if encoded_len == 0 {
    return decoded_len > 0;
  }
  decoded_len > encoded_len.saturating_mul(max_ratio)
}

pub(crate) fn captured_decoded_body(decoded: &Bytes, inspection_limit: usize) -> CapturedBody {
  let keep = decoded.len().min(inspection_limit);
  CapturedBody {
    bytes: decoded.slice(..keep),
    is_truncated: decoded.len() > keep,
  }
}

fn body_from_bytes_and_trailers(bytes: Bytes, trailers: Option<HeaderMap>) -> ProxyBody {
  let mut frames: Vec<Result<Frame<Bytes>, body::BoxError>> = Vec::new();
  if !bytes.is_empty() || trailers.is_none() {
    frames.push(Ok(Frame::data(bytes)));
  }
  if let Some(trailers) = trailers {
    frames.push(Ok(Frame::trailers(trailers)));
  }
  let stream = futures_util::stream::iter(frames);
  BodyExt::boxed(StreamBody::new(stream))
}

fn has_cache_control_directive(headers: &HeaderMap, name: &str) -> bool {
  headers
    .get_all(CACHE_CONTROL)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .any(|directive| {
      directive
        .split_once('=')
        .map(|(name, _)| name.trim())
        .unwrap_or(directive)
        .eq_ignore_ascii_case(name)
    })
}

fn weaken_strong_etag(headers: &mut HeaderMap) {
  let Some(etag) = headers.get(ETAG).and_then(|value| value.to_str().ok()) else {
    return;
  };
  if !etag.starts_with('"') {
    return;
  }
  let weak = format!("W/{etag}");
  if let Ok(value) = http::HeaderValue::from_str(&weak) {
    headers.insert(ETAG, value);
  }
}

#[cfg(test)]
mod tests {
  use http_body_util::{BodyExt, Full};
  use pretty_assertions::assert_eq;

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

  async fn encoded_bytes(
    bytes: &'static [u8],
    encoding: WafHttpBodyEncoding,
  ) -> Result<Bytes, WafBodyCodingError> {
    encode_body(Bytes::from_static(bytes), encoding).await
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

      let (request, captured) =
        transform_request_body_for_waf(request, config.clone(), state.clone(), 8)
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
      let decoded =
        decode_body_sync(replayed, encoding, 1024).expect("replayed body should decode");
      assert_eq!(decoded.as_ref(), b"prefix secret suffix");
    }
  }

  #[tokio::test]
  async fn unsupported_content_encoding_is_rejected() {
    let config = config_for_tests();
    let state = WafBodyCodingState::new(&config);
    let request = Request::builder()
      .header(CONTENT_ENCODING, "compress")
      .body(body(Bytes::from_static(b"data")))
      .expect("request should build");

    let error = transform_request_body_for_waf(request, config.clone(), state.clone(), 8)
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
      .body(body(encoded.clone()))
      .expect("request should build");

    let error = transform_request_body_for_waf(request, config.clone(), state.clone(), 8)
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
      .body(body(encoded.clone()))
      .expect("request should build");

    let error = transform_request_body_for_waf(request, config.clone(), state.clone(), 8)
      .await
      .expect_err("expansion ratio should fail");
    assert_eq!(error.kind(), WafBodyCodingErrorKind::TooLarge);
  }
}
