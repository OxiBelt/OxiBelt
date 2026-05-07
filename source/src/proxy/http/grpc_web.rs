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
    .and_then(|value| value.to_str().ok())?
    .to_ascii_lowercase();
  if content_type.starts_with("application/grpc-web-text") {
    Some(GrpcWebMode::Text)
  } else if content_type.starts_with("application/grpc-web") {
    Some(GrpcWebMode::Binary)
  } else {
    None
  }
}

pub(crate) fn rewrite_request_headers(headers: &mut HeaderMap, mode: GrpcWebMode) {
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
      let lower = value.to_ascii_lowercase();
      lower
        .strip_prefix(match mode {
          GrpcWebMode::Binary => "application/grpc-web",
          GrpcWebMode::Text => "application/grpc-web-text",
        })
        .map(str::to_string)
    })
    .unwrap_or_default();
  HeaderValue::from_str(&format!("application/grpc{suffix}"))
    .unwrap_or_else(|_| HeaderValue::from_static("application/grpc"))
}

pub(crate) async fn decode_request_body(
  body: ProxyBody,
  mode: GrpcWebMode,
) -> anyhow::Result<ProxyBody> {
  match mode {
    GrpcWebMode::Binary => Ok(body),
    GrpcWebMode::Text => {
      let (sender, decoded) = channel_body(16);
      tokio::spawn(async move {
        let mut decoder = TextDecoder::default();
        let mut body = body;
        while let Some(frame) = body.frame().await {
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
) -> Response<ProxyBody> {
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
    let mut body = body;
    let mut saw_trailers = false;
    while let Some(frame) = body.frame().await {
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
          if send_data(&sender, mode, &mut encoder, data).await.is_err() {
            return;
          }
        }
        Err(frame) => {
          if let Ok(trailers) = frame.into_trailers() {
            saw_trailers = true;
            let frame = encode_trailer_frame(&trailers);
            if send_data(&sender, mode, &mut encoder, frame).await.is_err() {
              return;
            }
          }
        }
      }
    }
    if !saw_trailers {
      let frame = encode_trailer_frame(&fallback_trailers);
      if send_data(&sender, mode, &mut encoder, frame).await.is_err() {
        return;
      }
    }
    if mode == GrpcWebMode::Text
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
  encoder: &mut TextEncoder,
  data: Bytes,
) -> Result<(), ()> {
  let data = match mode {
    GrpcWebMode::Binary => data,
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

#[derive(Default)]
struct TextDecoder {
  carry: Vec<u8>,
}

impl TextDecoder {
  fn push(&mut self, data: &[u8]) -> Result<Option<Bytes>, base64::DecodeError> {
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
  }

  fn finish(&mut self) -> Result<Option<Bytes>, base64::DecodeError> {
    if self.carry.is_empty() {
      Ok(None)
    } else {
      base64::engine::general_purpose::STANDARD
        .decode(std::mem::take(&mut self.carry))
        .map(Bytes::from)
        .map(Some)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

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
  fn text_encoder_preserves_base64_boundaries() {
    let mut encoder = TextEncoder::default();
    let mut out = Vec::new();
    out.extend_from_slice(&encoder.push(b"ab"));
    out.extend_from_slice(&encoder.push(b"cde"));
    if let Some(rest) = encoder.finish() {
      out.extend_from_slice(&rest);
    }
    assert_eq!(String::from_utf8(out).unwrap(), "YWJjZGU=");
  }
}
