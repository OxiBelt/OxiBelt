//! Dedicated HTTP/3 extended CONNECT transport for upstream WebSocket sessions.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ::http::{HeaderMap, Method, Request, StatusCode, Uri, header};
use anyhow::Context;
use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;

use super::upstream_connection::{ConnectedH3Upstream, H3RequestDeadlines};
use crate::circuit_breakers::AdmissionLease;
use crate::config::UpstreamConfig;
use crate::proxy::http::EffectiveTimeouts;
use crate::state::AppSnapshot;
use crate::waf::metadata::WafCertificateMetadata;

const BRIDGE_CAPACITY: usize = 64 * 1024;
const DATA_CHUNK: usize = 16 * 1024;

/// Owns the dedicated HTTP/3 connection, its admission lease, and both
/// bounded byte-stream pumps for the lifetime of the WebSocket session.
pub(crate) struct UpstreamH3WebSocketConnectionGuard {
  _connected: ConnectedH3Upstream,
  _admission: AdmissionLease,
  send_task: JoinHandle<()>,
  receive_task: JoinHandle<()>,
  failed: Arc<AtomicBool>,
}

impl UpstreamH3WebSocketConnectionGuard {
  pub(crate) fn failed(&self) -> bool {
    self.failed.load(Ordering::Acquire)
  }
}

impl Drop for UpstreamH3WebSocketConnectionGuard {
  fn drop(&mut self) {
    self.send_task.abort();
    self.receive_task.abort();
    // ConnectedH3Upstream closes the QUIC connection and aborts its driver.
  }
}

/// Establish one upstream WebSocket extended CONNECT and expose its DATA frames
/// through a bounded byte stream. The caller must retain the returned guard
/// until the session is complete.
pub(crate) async fn connect_upstream_websocket(
  upstream: &UpstreamConfig,
  target_uri: Uri,
  headers: HeaderMap,
  state: &AppSnapshot,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<(
  HeaderMap,
  DuplexStream,
  UpstreamH3WebSocketConnectionGuard,
  Option<Arc<WafCertificateMetadata>>,
)> {
  if target_uri.scheme_str() != Some("https")
    || target_uri.authority().is_none()
    || !target_uri.path().starts_with('/')
  {
    anyhow::bail!("upstream WebSocket HTTP/3 CONNECT target must be an absolute https URI");
  }

  let client = state
    .h3_clients
    .for_upstream(&upstream.name)
    .with_context(|| {
      format!(
        "missing upstream WebSocket HTTP/3 client for {}",
        upstream.name
      )
    })?;
  let deadlines = H3RequestDeadlines::from_timeouts(timeouts)?;
  let admitted = client
    .connect_websocket_transport(
      upstream,
      &state.config.proxy.trusted_ca_certs,
      deadlines.connect,
      &state.metrics,
    )
    .await?;
  let mut connected = admitted.connected;

  let enabled = tokio::time::timeout_at(
    deadlines.request,
    connected.send_request.wait_for_peer_extended_connect(),
  )
  .await
  .context("upstream HTTP/3 WebSocket SETTINGS wait timed out")?
  .context("upstream HTTP/3 WebSocket SETTINGS wait failed")?;
  if !enabled {
    anyhow::bail!("upstream HTTP/3 peer did not enable extended CONNECT");
  }

  let mut request = Request::builder()
    .method(Method::CONNECT)
    .uri(target_uri)
    .body(())
    .context("failed to build upstream HTTP/3 WebSocket CONNECT")?;
  *request.headers_mut() = websocket_h3_headers(headers);
  request.extensions_mut().insert(Protocol::WEBSOCKET);

  // This is the replay boundary: the selected endpoint sees at most one
  // CONNECT attempt, including failures after request headers are sent.
  let mut stream = tokio::time::timeout_at(
    deadlines.request,
    connected.send_request.send_request(request),
  )
  .await
  .context("upstream HTTP/3 WebSocket CONNECT send timed out")?
  .context("failed to send upstream HTTP/3 WebSocket CONNECT")?;

  let response = loop {
    let response = tokio::time::timeout_at(deadlines.request, stream.recv_response())
      .await
      .context("upstream HTTP/3 WebSocket CONNECT response timed out")?
      .context("failed to receive upstream HTTP/3 WebSocket CONNECT response")?;
    if response.status().is_informational() {
      continue;
    }
    break response;
  };
  if response.status() != StatusCode::OK {
    anyhow::bail!(
      "upstream HTTP/3 WebSocket CONNECT returned {}",
      response.status()
    );
  }

  let response_headers = response.into_parts().0.headers;
  let upstream_certificate = connected.upstream_certificate.clone();
  let (application_stream, bridge_stream) = tokio::io::duplex(BRIDGE_CAPACITY);
  let (application_read, application_write) = tokio::io::split(bridge_stream);
  let (send, receive) = stream.split();
  let failed = Arc::new(AtomicBool::new(false));

  let send_failed = failed.clone();
  let send_task = tokio::spawn(async move {
    pump_application_to_h3(application_read, send, send_failed).await;
  });
  let receive_failed = failed.clone();
  let receive_task = tokio::spawn(async move {
    pump_h3_to_application(receive, application_write, receive_failed).await;
  });

  let guard = UpstreamH3WebSocketConnectionGuard {
    _connected: connected,
    _admission: admitted.admission,
    send_task,
    receive_task,
    failed,
  };
  Ok((
    response_headers,
    application_stream,
    guard,
    upstream_certificate,
  ))
}

fn websocket_h3_headers(mut headers: HeaderMap) -> HeaderMap {
  // H1 handshake and hop-by-hop fields are never valid on H3. The target URI
  // supplies :authority, so an inherited Host field must not contradict it.
  crate::proxy::http::headers::strip_hop_by_hop_headers(&mut headers);
  for name in [
    header::HOST,
    header::CONTENT_LENGTH,
    header::SEC_WEBSOCKET_KEY,
    header::SEC_WEBSOCKET_ACCEPT,
  ] {
    headers.remove(name);
  }
  headers
}

async fn pump_application_to_h3(
  mut application: tokio::io::ReadHalf<DuplexStream>,
  mut upstream: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
  failed: Arc<AtomicBool>,
) {
  let mut chunk = [0_u8; DATA_CHUNK];
  loop {
    match application.read(&mut chunk).await {
      Ok(0) => {
        if upstream.finish().await.is_err() {
          failed.store(true, Ordering::Release);
        }
        return;
      }
      Ok(size) => {
        if upstream
          .send_data(Bytes::copy_from_slice(&chunk[..size]))
          .await
          .is_err()
        {
          failed.store(true, Ordering::Release);
          return;
        }
      }
      Err(_) => {
        failed.store(true, Ordering::Release);
        upstream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        return;
      }
    }
  }
}

async fn pump_h3_to_application(
  mut upstream: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
  mut application: tokio::io::WriteHalf<DuplexStream>,
  failed: Arc<AtomicBool>,
) {
  loop {
    let data = match upstream.recv_data().await {
      Ok(Some(data)) => data,
      Ok(None) => break,
      Err(_) => {
        failed.store(true, Ordering::Release);
        break;
      }
    };
    let mut data = data;
    while data.has_remaining() {
      let size = data.remaining().min(DATA_CHUNK);
      let chunk = data.copy_to_bytes(size);
      if application.write_all(&chunk).await.is_err() {
        failed.store(true, Ordering::Release);
        upstream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        return;
      }
    }
  }
  let _ = application.shutdown().await;
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn websocket_connect_headers_keep_negotiation_but_remove_h1_fields() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "old.example".parse().unwrap());
    headers.insert(header::CONNECTION, "Upgrade, x-local".parse().unwrap());
    headers.insert(header::UPGRADE, "websocket".parse().unwrap());
    headers.insert("x-local", "discard".parse().unwrap());
    headers.insert(header::SEC_WEBSOCKET_KEY, "abc".parse().unwrap());
    headers.insert(header::CONTENT_LENGTH, "0".parse().unwrap());
    headers.insert(header::SEC_WEBSOCKET_VERSION, "13".parse().unwrap());
    headers.insert(header::SEC_WEBSOCKET_PROTOCOL, "chat".parse().unwrap());
    let headers = websocket_h3_headers(headers);
    assert!(!headers.contains_key(header::HOST));
    assert!(!headers.contains_key(header::CONNECTION));
    assert!(!headers.contains_key(header::UPGRADE));
    assert!(!headers.contains_key("x-local"));
    assert!(!headers.contains_key(header::SEC_WEBSOCKET_KEY));
    assert!(!headers.contains_key(header::CONTENT_LENGTH));
    assert_eq!(headers[header::SEC_WEBSOCKET_VERSION], "13");
    assert_eq!(headers[header::SEC_WEBSOCKET_PROTOCOL], "chat");
  }
}
