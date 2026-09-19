//! gRPC-Web request and response adaptation.
//! Framing conversion stays explicit so HTTP semantics and body limits remain enforceable.

use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Response, header};
use http_body_util::BodyExt;
use hyper::body::Frame;
use tracing::warn;

use super::body::{ProxyBody, ProxyBodyFrame, boxed_error, channel_body};

const GRPC_STATUS: &str = "grpc-status";
const GRPC_MESSAGE: &str = "grpc-message";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum GrpcWebMode {
  Binary,
  Text,
}

pub(crate) fn request_mode(headers: &HeaderMap) -> Option<GrpcWebMode> {
  let content_type = headers
    .get(header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())?;
  if strip_ascii_prefix(content_type, "application/grpc-web-text").is_some() {
    Some(GrpcWebMode::Text)
  } else if strip_ascii_prefix(content_type, "application/grpc-web").is_some() {
    Some(GrpcWebMode::Binary)
  } else {
    None
  }
}

pub(crate) fn rewrite_request_headers(headers: &mut HeaderMap, mode: GrpcWebMode) {
  if mode == GrpcWebMode::Text {
    super::integrity_digest::invalidate(headers, false);
  }
  let content_type = grpc_content_type(headers, mode);
  headers.insert(header::CONTENT_TYPE, content_type);
  headers.insert(header::TE, HeaderValue::from_static("trailers"));
  headers.remove(header::ACCEPT);
  headers.remove(HeaderName::from_static("x-grpc-web"));
}

fn grpc_content_type(headers: &HeaderMap, mode: GrpcWebMode) -> HeaderValue {
  let suffix = headers
    .get(header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| {
      strip_ascii_prefix(
        value,
        match mode {
          GrpcWebMode::Binary => "application/grpc-web",
          GrpcWebMode::Text => "application/grpc-web-text",
        },
      )
    })
    .unwrap_or_default();
  HeaderValue::from_str(&format!("application/grpc{suffix}"))
    .unwrap_or_else(|_| HeaderValue::from_static("application/grpc"))
}

fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
  let head = value.get(..prefix.len())?;
  head
    .eq_ignore_ascii_case(prefix)
    .then(|| &value[prefix.len()..])
}

pub(crate) async fn decode_request_body(
  body: ProxyBody,
  mode: GrpcWebMode,
  incremental: bool,
) -> anyhow::Result<ProxyBody> {
  match mode {
    GrpcWebMode::Binary => Ok(body),
    GrpcWebMode::Text => {
      let (sender, decoded) = channel_body(16);
      tokio::spawn(async move {
        let mut decoder = TextDecoder::new(incremental);
        let mut body = super::integrity_digest::invalidate_body(body, false);
        loop {
          let frame = tokio::select! {
            biased;
            () = sender.closed() => return,
            frame = body.frame() => frame,
          };
          let Some(frame) = frame else { break };
          let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
              let _ = sender
                .send(Err(boxed_error(std::io::Error::other(format!(
                  "failed to read grpc-web-text request body: {error}"
                )))))
                .await;
              return;
            }
          };
          match frame.into_data() {
            Ok(data) => match decoder.push(&data) {
              Ok(Some(decoded)) => {
                if sender.send(Ok(Frame::data(decoded))).await.is_err() {
                  return;
                }
              }
              Ok(None) => {}
              Err(error) => {
                let _ = sender
                  .send(Err(boxed_error(std::io::Error::other(format!(
                    "failed to decode grpc-web-text request body: {error}"
                  )))))
                  .await;
                return;
              }
            },
            Err(frame) => {
              if let Ok(trailers) = frame.into_trailers()
                && sender.send(Ok(Frame::trailers(trailers))).await.is_err()
              {
                return;
              }
            }
          }
        }
        match decoder.finish() {
          Ok(Some(decoded)) => {
            let _ = sender.send(Ok(Frame::data(decoded))).await;
          }
          Ok(None) => {}
          Err(error) => {
            let _ = sender
              .send(Err(boxed_error(std::io::Error::other(format!(
                "failed to decode grpc-web-text request body: {error}"
              )))))
              .await;
          }
        }
      });
      Ok(decoded)
    }
  }
}

pub(crate) fn encode_response(
  mut response: Response<ProxyBody>,
  mode: GrpcWebMode,
  incremental: bool,
) -> Response<ProxyBody> {
  super::integrity_digest::invalidate(response.headers_mut(), false);
  response
    .extensions_mut()
    .remove::<super::integrity_digest::UnencodedDigestState>();
  response
    .extensions_mut()
    .remove::<super::body::CompiledKnownSmallNoopResponse>();
  response
    .extensions_mut()
    .remove::<super::integrity_digest::AvailableRepresentation>();
  response
    .extensions_mut()
    .remove::<super::body::InlinedKnownSmallResponseBody>();
  response
    .extensions_mut()
    .remove::<super::body::KnownSmallResponseBody>();
  response.headers_mut().insert(
    header::CONTENT_TYPE,
    match mode {
      GrpcWebMode::Binary => HeaderValue::from_static("application/grpc-web"),
      GrpcWebMode::Text => HeaderValue::from_static("application/grpc-web-text"),
    },
  );
  response.headers_mut().remove(header::TRAILER);
  let fallback_trailers = fallback_trailers(response.headers_mut());
  let (parts, body) = response.into_parts();
  let (sender, encoded) = channel_body(16);
  tokio::spawn(async move {
    let mut encoder = TextEncoder::default();
    let mut body = super::integrity_digest::invalidate_body(body, false);
    let mut saw_trailers = false;
    loop {
      let frame = tokio::select! {
        biased;
        () = sender.closed() => return,
        frame = body.frame() => frame,
      };
      let Some(frame) = frame else { break };
      let frame = match frame {
        Ok(frame) => frame,
        Err(error) => {
          let _ = sender
            .send(Err(boxed_error(std::io::Error::other(format!(
              "failed to read upstream gRPC response body: {error}"
            )))))
            .await;
          return;
        }
      };
      match frame.into_data() {
        Ok(data) => {
          if send_data(&sender, mode, incremental, &mut encoder, data)
            .await
            .is_err()
          {
            return;
          }
        }
        Err(frame) => {
          if let Ok(trailers) = frame.into_trailers() {
            saw_trailers = true;
            let frame = encode_trailer_frame(&trailers);
            if send_data(&sender, mode, incremental, &mut encoder, frame)
              .await
              .is_err()
            {
              return;
            }
          }
        }
      }
    }
    if !saw_trailers {
      let frame = encode_trailer_frame(&fallback_trailers);
      if send_data(&sender, mode, incremental, &mut encoder, frame)
        .await
        .is_err()
      {
        return;
      }
    }
    if mode == GrpcWebMode::Text
      && !incremental
      && let Some(data) = encoder.finish()
    {
      let _ = sender.send(Ok(Frame::data(data))).await;
    }
  });
  Response::from_parts(parts, encoded)
}

async fn send_data(
  sender: &tokio::sync::mpsc::Sender<ProxyBodyFrame>,
  mode: GrpcWebMode,
  incremental: bool,
  encoder: &mut TextEncoder,
  data: Bytes,
) -> Result<(), ()> {
  let data = match mode {
    GrpcWebMode::Binary => data,
    GrpcWebMode::Text if incremental => {
      Bytes::from(base64::engine::general_purpose::STANDARD.encode(data))
    }
    GrpcWebMode::Text => encoder.push(&data),
  };
  if data.is_empty() {
    return Ok(());
  }
  sender.send(Ok(Frame::data(data))).await.map_err(|_| ())
}

fn fallback_trailers(headers: &mut HeaderMap) -> HeaderMap {
  let mut trailers = HeaderMap::new();
  let status_name = HeaderName::from_static(GRPC_STATUS);
  let message_name = HeaderName::from_static(GRPC_MESSAGE);
  if let Some(status) = headers.remove(&status_name) {
    trailers.insert(status_name, status);
  } else {
    trailers.insert(status_name, HeaderValue::from_static("0"));
  }
  if let Some(message) = headers.remove(&message_name) {
    trailers.insert(message_name, message);
  }
  trailers
}

fn encode_trailer_frame(trailers: &HeaderMap) -> Bytes {
  let mut payload = BytesMut::new();
  for (name, value) in trailers {
    match value.to_str() {
      Ok(value) => {
        payload.extend_from_slice(name.as_str().as_bytes());
        payload.extend_from_slice(b": ");
        payload.extend_from_slice(value.as_bytes());
        payload.extend_from_slice(b"\r\n");
      }
      Err(error) => {
        warn!(header = %name, error = %error, "skipped non-UTF8 gRPC trailer");
      }
    }
  }

  let mut frame = BytesMut::with_capacity(5 + payload.len());
  frame.put_u8(0x80);
  frame.put_u32(payload.len() as u32);
  frame.extend_from_slice(&payload);
  frame.freeze()
}

#[derive(Default)]
struct TextEncoder {
  carry: Vec<u8>,
}

impl TextEncoder {
  fn push(&mut self, data: &[u8]) -> Bytes {
    self.carry.extend_from_slice(data);
    let encode_len = self.carry.len() / 3 * 3;
    if encode_len == 0 {
      return Bytes::new();
    }
    let chunk = self.carry[..encode_len].to_vec();
    self.carry.drain(..encode_len);
    Bytes::from(base64::engine::general_purpose::STANDARD.encode(chunk))
  }

  fn finish(&mut self) -> Option<Bytes> {
    if self.carry.is_empty() {
      None
    } else {
      Some(Bytes::from(
        base64::engine::general_purpose::STANDARD.encode(std::mem::take(&mut self.carry)),
      ))
    }
  }
}

struct TextDecoder {
  carry: Vec<u8>,
  incremental: bool,
}

impl TextDecoder {
  fn new(incremental: bool) -> Self {
    Self {
      carry: Vec::with_capacity(3),
      incremental,
    }
  }

  fn push(&mut self, data: &[u8]) -> Result<Option<Bytes>, TextDecodeError> {
    if self.incremental {
      return self.push_incremental(data);
    }
    self.carry.extend_from_slice(data);
    let decode_len = self.carry.len() / 4 * 4;
    if decode_len == 0 {
      return Ok(None);
    }
    let chunk = self.carry[..decode_len].to_vec();
    self.carry.drain(..decode_len);
    base64::engine::general_purpose::STANDARD
      .decode(chunk)
      .map(Bytes::from)
      .map(Some)
      .map_err(TextDecodeError::Invalid)
  }

  fn push_incremental(&mut self, data: &[u8]) -> Result<Option<Bytes>, TextDecodeError> {
    let mut decoded = BytesMut::new();
    for &encoded in data {
      if !encoded.is_ascii_alphanumeric() && encoded != b'+' && encoded != b'/' && encoded != b'=' {
        return Err(TextDecodeError::InvalidByte(encoded));
      }
      if encoded == b'=' && self.carry.len() < 2 {
        return Err(TextDecodeError::InvalidPadding);
      }
      self.carry.push(encoded);
      if self.carry.len() == 4 {
        let quartet = std::mem::take(&mut self.carry);
        let bytes = base64::engine::general_purpose::STANDARD
          .decode(quartet)
          .map_err(TextDecodeError::Invalid)?;
        decoded.extend_from_slice(&bytes);
      }
    }
    if decoded.is_empty() {
      Ok(None)
    } else {
      Ok(Some(decoded.freeze()))
    }
  }

  fn finish(&mut self) -> Result<Option<Bytes>, TextDecodeError> {
    if self.incremental && !self.carry.is_empty() {
      return Err(TextDecodeError::Truncated);
    }
    if self.carry.is_empty() {
      Ok(None)
    } else {
      base64::engine::general_purpose::STANDARD
        .decode(std::mem::take(&mut self.carry))
        .map(Bytes::from)
        .map(Some)
        .map_err(TextDecodeError::Invalid)
    }
  }
}

#[derive(Debug)]
enum TextDecodeError {
  Invalid(base64::DecodeError),
  InvalidByte(u8),
  InvalidPadding,
  Truncated,
}

impl std::fmt::Display for TextDecodeError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Invalid(error) => write!(formatter, "invalid base64: {error}"),
      Self::InvalidByte(byte) => write!(formatter, "invalid base64 byte 0x{byte:02x}"),
      Self::InvalidPadding => formatter.write_str("invalid base64 padding"),
      Self::Truncated => formatter.write_str("truncated base64 quartet"),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn grpc_web_conversions_remove_digests_for_the_original_bytes() {
    let mut fields = HeaderMap::new();
    for name in ["content-digest", "repr-digest", "unencoded-digest"] {
      fields.insert(name, HeaderValue::from_static("sha-256=:AA==:"));
    }
    fields.insert("grpc-status", HeaderValue::from_static("0"));
    let mut headers = fields.clone();
    rewrite_request_headers(&mut headers, GrpcWebMode::Text);
    assert!(!headers.contains_key("content-digest"));
    assert!(!headers.contains_key("repr-digest"));
    assert!(!headers.contains_key("unencoded-digest"));
    let request = http_body_util::Full::new(Bytes::from_static(b"YQ=="))
      .with_trailers(std::future::ready(Some(Ok::<_, std::convert::Infallible>(
        fields.clone(),
      ))))
      .map_err(|never| -> super::super::body::BoxError { match never {} })
      .boxed();
    let decoded = decode_request_body(request, GrpcWebMode::Text, false)
      .await
      .unwrap()
      .collect()
      .await
      .unwrap();
    let trailers = decoded.trailers().unwrap();
    for name in ["content-digest", "repr-digest", "unencoded-digest"] {
      assert!(!trailers.contains_key(name));
    }
    assert_eq!(decoded.to_bytes(), "a");

    let body = http_body_util::Full::new(Bytes::from_static(b"\0\0\0\0\0"))
      .with_trailers(std::future::ready(Some(Ok::<_, std::convert::Infallible>(
        fields.clone(),
      ))))
      .map_err(|never| -> super::super::body::BoxError { match never {} })
      .boxed();
    let mut response = Response::new(body);
    *response.headers_mut() = fields;
    let response = encode_response(response, GrpcWebMode::Binary, false);
    for name in ["content-digest", "repr-digest", "unencoded-digest"] {
      assert!(!response.headers().contains_key(name));
    }
    let encoded = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
      !encoded
        .windows(b"digest".len())
        .any(|window| window == b"digest")
    );
    assert!(
      encoded
        .windows(b"grpc-status: 0".len())
        .any(|window| window == b"grpc-status: 0")
    );
  }

  #[tokio::test]
  async fn incremental_codecs_cancel_pending_sources() {
    let (request_tx, request) = channel_body(1);
    let decoded = decode_request_body(request, GrpcWebMode::Text, true)
      .await
      .unwrap();
    tokio::task::yield_now().await;
    drop(decoded);
    tokio::time::timeout(std::time::Duration::from_secs(1), request_tx.closed())
      .await
      .expect("decoder must drop cancelled pending upload");

    let (response_tx, response) = channel_body(1);
    let encoded = encode_response(Response::new(response), GrpcWebMode::Text, true);
    tokio::task::yield_now().await;
    drop(encoded);
    tokio::time::timeout(std::time::Duration::from_secs(1), response_tx.closed())
      .await
      .expect("encoder must drop cancelled pending response");
  }

  #[test]
  fn detects_grpc_web_modes() {
    let mut headers = HeaderMap::new();
    headers.insert(
      header::CONTENT_TYPE,
      HeaderValue::from_static("application/grpc-web+proto"),
    );
    assert_eq!(request_mode(&headers), Some(GrpcWebMode::Binary));
    headers.insert(
      header::CONTENT_TYPE,
      HeaderValue::from_static("application/grpc-web-text+proto"),
    );
    assert_eq!(request_mode(&headers), Some(GrpcWebMode::Text));
  }

  #[test]
  fn encodes_trailer_frame() {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    let frame = encode_trailer_frame(&trailers);
    assert_eq!(frame[0], 0x80);
    assert_eq!(&frame[1..5], &16u32.to_be_bytes());
    assert_eq!(&frame[5..], b"grpc-status: 0\r\n");
  }

  #[test]
  fn ordinary_text_encoder_preserves_base64_boundaries() {
    let mut encoder = TextEncoder::default();
    let mut out = Vec::new();
    out.extend_from_slice(&encoder.push(b"ab"));
    out.extend_from_slice(&encoder.push(b"cde"));
    if let Some(rest) = encoder.finish() {
      out.extend_from_slice(&rest);
    }
    assert_eq!(String::from_utf8(out).unwrap(), "YWJjZGU=");
  }

  #[test]
  fn incremental_text_decoder_accepts_fragmented_concatenated_padded_chunks() {
    let mut decoder = TextDecoder::new(true);
    assert!(
      decoder
        .push(b"TQ=")
        .expect("partial quartet is buffered")
        .is_none()
    );
    assert_eq!(decoder.push(b"=T").unwrap(), Some(Bytes::from_static(b"M")));
    assert_eq!(
      decoder.push(b"g==").unwrap(),
      Some(Bytes::from_static(b"N"))
    );
    assert_eq!(decoder.finish().unwrap(), None);
  }

  #[test]
  fn incremental_text_decoder_rejects_invalid_or_truncated_input() {
    let mut decoder = TextDecoder::new(true);
    assert!(decoder.push(b"T!").is_err());

    let mut decoder = TextDecoder::new(true);
    assert!(decoder.push(b"A===").is_err());

    let mut decoder = TextDecoder::new(true);
    assert!(decoder.push(b"TQ=").is_ok());
    assert!(matches!(decoder.finish(), Err(TextDecodeError::Truncated)));
  }

  #[tokio::test]
  async fn incremental_text_response_chunks_are_independently_padded() {
    let (sender, body) = channel_body(4);
    sender
      .send(Ok(Frame::data(Bytes::from_static(b"M"))))
      .await
      .unwrap();
    let mut trailers = HeaderMap::new();
    trailers.insert(GRPC_STATUS, HeaderValue::from_static("0"));
    sender.send(Ok(Frame::trailers(trailers))).await.unwrap();
    drop(sender);
    let mut body = encode_response(Response::new(body), GrpcWebMode::Text, true).into_body();
    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let last = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(first, Bytes::from_static(b"TQ=="));
    assert_eq!(
      last,
      Bytes::from(
        base64::engine::general_purpose::STANDARD.encode(encode_trailer_frame(&{
          let mut trailers = HeaderMap::new();
          trailers.insert(GRPC_STATUS, HeaderValue::from_static("0"));
          trailers
        }))
      )
    );
    assert!(body.frame().await.is_none());
  }

  #[tokio::test]
  async fn incremental_text_request_decodes_fragmented_padded_chunks() {
    let (sender, body) = channel_body(4);
    sender
      .send(Ok(Frame::data(Bytes::from_static(b"TQ="))))
      .await
      .unwrap();
    sender
      .send(Ok(Frame::data(Bytes::from_static(b"=Tg=="))))
      .await
      .unwrap();
    drop(sender);
    let decoded = decode_request_body(body, GrpcWebMode::Text, true)
      .await
      .unwrap()
      .collect()
      .await
      .unwrap()
      .to_bytes();
    assert_eq!(decoded, Bytes::from_static(b"MN"));
  }
}
