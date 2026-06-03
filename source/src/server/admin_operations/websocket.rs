//! WebSocket transport for admin operations.
//! The socket mirrors operation events without becoming the source of operation truth.

use ::http::{HeaderMap, HeaderName, Response, StatusCode};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use ring::digest;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;

use crate::proxy::http::body::{BoxError, ProxyBody};
use crate::proxy::http::response::text_response;

use super::types::AdminOperationEvent;

const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub(super) fn websocket_response(
  mut request: hyper::Request<Incoming>,
  history: Vec<AdminOperationEvent>,
  mut receiver: broadcast::Receiver<AdminOperationEvent>,
) -> Response<ProxyBody> {
  let Some(accept) = websocket_accept_key(&request) else {
    return text_response(StatusCode::BAD_REQUEST, "invalid WebSocket upgrade request");
  };
  tokio::spawn(async move {
    match hyper::upgrade::on(&mut request).await {
      Ok(upgraded) => {
        let _ = send_events(upgraded, history, &mut receiver).await;
      }
      Err(error) => {
        tracing::warn!(error = %error, "admin operation WebSocket upgrade failed");
      }
    }
  });

  let body = Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
  response.headers_mut().insert(
    ::http::header::UPGRADE,
    ::http::HeaderValue::from_static("websocket"),
  );
  response.headers_mut().insert(
    ::http::header::CONNECTION,
    ::http::HeaderValue::from_static("Upgrade"),
  );
  response.headers_mut().insert(
    ::http::HeaderName::from_static("sec-websocket-accept"),
    accept,
  );
  response
}

fn websocket_accept_key<B>(request: &hyper::Request<B>) -> Option<::http::HeaderValue> {
  if request.method() != ::http::Method::GET {
    return None;
  }
  let headers = request.headers();
  if !header_has_token(headers, ::http::header::UPGRADE, "websocket")
    || !header_has_token(headers, ::http::header::CONNECTION, "upgrade")
  {
    return None;
  }
  let version = headers
    .get(::http::HeaderName::from_static("sec-websocket-version"))
    .and_then(|value| value.to_str().ok())?;
  if version != "13" {
    return None;
  }
  let key = headers
    .get(::http::HeaderName::from_static("sec-websocket-key"))
    .and_then(|value| value.to_str().ok())?
    .trim();
  base64::engine::general_purpose::STANDARD
    .decode(key)
    .ok()
    .filter(|decoded| decoded.len() == 16)
    .map(|_| ())?;
  let mut input = Vec::with_capacity(key.len() + WEBSOCKET_GUID.len());
  input.extend_from_slice(key.as_bytes());
  input.extend_from_slice(WEBSOCKET_GUID);
  let digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
  let encoded = base64::engine::general_purpose::STANDARD.encode(digest.as_ref());
  ::http::HeaderValue::from_str(&encoded).ok()
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
  headers.get_all(name).iter().any(|value| {
    value.to_str().ok().is_some_and(|value| {
      value
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case(expected))
    })
  })
}

async fn send_events(
  upgraded: Upgraded,
  history: Vec<AdminOperationEvent>,
  receiver: &mut broadcast::Receiver<AdminOperationEvent>,
) -> anyhow::Result<()> {
  let mut io = TokioIo::new(upgraded);
  for event in history {
    let terminal = event.operation.state.is_terminal();
    write_text_frame(&mut io, &serde_json::to_vec(&event)?).await?;
    if terminal {
      let _ = write_close_frame(&mut io).await;
      return Ok(());
    }
  }
  loop {
    match receiver.recv().await {
      Ok(event) => {
        let terminal = event.operation.state.is_terminal();
        write_text_frame(&mut io, &serde_json::to_vec(&event)?).await?;
        if terminal {
          let _ = write_close_frame(&mut io).await;
          return Ok(());
        }
      }
      Err(broadcast::error::RecvError::Lagged(_)) => {
        write_text_frame(
          &mut io,
          br#"{"event":"operation.error","error":"event stream lagged"}"#,
        )
        .await?;
        let _ = write_close_frame(&mut io).await;
        return Ok(());
      }
      Err(broadcast::error::RecvError::Closed) => return Ok(()),
    }
  }
}

async fn write_text_frame<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
  W: tokio::io::AsyncWrite + Unpin,
{
  write_frame(writer, 0x1, payload).await
}

async fn write_close_frame<W>(writer: &mut W) -> std::io::Result<()>
where
  W: tokio::io::AsyncWrite + Unpin,
{
  write_frame(writer, 0x8, &[]).await
}

async fn write_frame<W>(writer: &mut W, opcode: u8, payload: &[u8]) -> std::io::Result<()>
where
  W: tokio::io::AsyncWrite + Unpin,
{
  let mut header = Vec::with_capacity(10);
  header.push(0x80 | opcode);
  match payload.len() {
    len if len < 126 => header.push(len as u8),
    len if len <= u16::MAX as usize => {
      header.push(126);
      header.extend_from_slice(&(len as u16).to_be_bytes());
    }
    len => {
      header.push(127);
      header.extend_from_slice(&(len as u64).to_be_bytes());
    }
  }
  writer.write_all(&header).await?;
  writer.write_all(payload).await?;
  writer.flush().await
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn websocket_accept_requires_full_upgrade_handshake() {
    let valid = websocket_accept_key(&websocket_request([
      (::http::header::UPGRADE.as_str(), "websocket"),
      (::http::header::CONNECTION.as_str(), "keep-alive, Upgrade"),
      ("sec-websocket-version", "13"),
      ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ]));
    assert!(valid.is_some());

    let missing_upgrade = websocket_accept_key(&websocket_request([
      (::http::header::CONNECTION.as_str(), "Upgrade"),
      ("sec-websocket-version", "13"),
      ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ]));
    assert!(missing_upgrade.is_none());

    let missing_connection = websocket_accept_key(&websocket_request([
      (::http::header::UPGRADE.as_str(), "websocket"),
      ("sec-websocket-version", "13"),
      ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ]));
    assert!(missing_connection.is_none());
  }

  #[test]
  fn websocket_accept_rejects_invalid_keys() {
    for key in ["not-base64", "c2hvcnQ=", "AAAAAAAAAAAAAAAAAAAAAAAA"] {
      let accept = websocket_accept_key(&websocket_request([
        (::http::header::UPGRADE.as_str(), "websocket"),
        (::http::header::CONNECTION.as_str(), "Upgrade"),
        ("sec-websocket-version", "13"),
        ("sec-websocket-key", key),
      ]));
      assert!(accept.is_none(), "key should be rejected: {key}");
    }
  }

  fn websocket_request<const N: usize>(
    headers: [(&'static str, &'static str); N],
  ) -> hyper::Request<()> {
    let mut builder = hyper::Request::builder()
      .method(::http::Method::GET)
      .uri("/admin/v1/operations/op_550e8400-e29b-41d4-a716-446655440000/events/ws");
    for (name, value) in headers {
      builder = builder.header(name, value);
    }
    builder.body(()).expect("request should build")
  }
}
