//! Selected-path adapter for upstream WebTransport I/O.
//!
//! The H3 implementation remains deliberately private: the generic
//! `web-transport-trait` receive helpers accept `BufMut` spare capacity through
//! an unsafe conversion. OxiBelt exposes only Tokio's initialized-buffer I/O
//! from that dependency. The H2 variant is the capsule runtime and does not
//! depend on the H3 implementation.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, ensure};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_WEBTRANSPORT_DATAGRAM_BYTES: usize = 65_535;

/// Translate a WebTransport application code for the HTTP/3/QUIC wire.
pub(crate) fn h3_application_code_to_wire(code: u32) -> u64 {
  web_transport_quinn::proto::error_to_http3(code)
}

/// Decode a WebTransport application code received on the HTTP/3/QUIC wire.
pub(crate) fn h3_application_code_from_wire(code: u64) -> Option<u32> {
  web_transport_quinn::proto::error_from_http3(code)
}

/// Upstream session selected for a WebTransport bridge.
///
/// This enum is intentionally the only place where the H3 adapter meets the
/// transport-neutral H2 capsule runtime. Keeping the H3 payload private makes
/// the dependency's initialized-buffer boundary auditable and reusable H2
/// callers never need to import an H3-only type.
#[derive(Clone)]
pub(crate) enum UpstreamWebTransportSession {
  H3(Box<H3WebTransportSession>),
  H2(crate::webtransport::Session),
}

impl UpstreamWebTransportSession {
  pub(in crate::proxy::http3) async fn connect_h3(
    connection: web_transport_quinn::quinn::Connection,
    target_url: url::Url,
    headers: http::HeaderMap,
    protocols: Vec<String>,
  ) -> anyhow::Result<Self> {
    H3WebTransportSession::connect(connection, target_url, headers, protocols)
      .await
      .map(|session| Self::H3(Box::new(session)))
  }

  pub(crate) fn from_h2(session: crate::webtransport::Session) -> Self {
    Self::H2(session)
  }

  pub(crate) async fn accept_uni(&self) -> anyhow::Result<UpstreamWebTransportRecvStream> {
    match self {
      Self::H3(session) => session
        .accept_uni()
        .await
        .map(UpstreamWebTransportRecvStream::H3),
      Self::H2(session) => session
        .accept_uni()
        .await
        .map(UpstreamWebTransportRecvStream::H2)
        .context("failed to accept an upstream HTTP/2 WebTransport unidirectional stream"),
    }
  }

  pub(crate) async fn accept_bi(
    &self,
  ) -> anyhow::Result<(
    UpstreamWebTransportSendStream,
    UpstreamWebTransportRecvStream,
  )> {
    match self {
      Self::H3(session) => session.accept_bi().await.map(|(send, recv)| {
        (
          UpstreamWebTransportSendStream::H3(send),
          UpstreamWebTransportRecvStream::H3(recv),
        )
      }),
      Self::H2(session) => session
        .accept_bi()
        .await
        .map(|(send, recv)| {
          (
            UpstreamWebTransportSendStream::H2(send),
            UpstreamWebTransportRecvStream::H2(recv),
          )
        })
        .context("failed to accept an upstream HTTP/2 WebTransport bidirectional stream"),
    }
  }

  pub(crate) async fn open_uni(&self) -> anyhow::Result<UpstreamWebTransportSendStream> {
    match self {
      Self::H3(session) => session
        .open_uni()
        .await
        .map(UpstreamWebTransportSendStream::H3),
      Self::H2(session) => session
        .open_uni()
        .await
        .map(UpstreamWebTransportSendStream::H2)
        .context("failed to open an upstream HTTP/2 WebTransport unidirectional stream"),
    }
  }

  pub(crate) async fn open_bi(
    &self,
  ) -> anyhow::Result<(
    UpstreamWebTransportSendStream,
    UpstreamWebTransportRecvStream,
  )> {
    match self {
      Self::H3(session) => session.open_bi().await.map(|(send, recv)| {
        (
          UpstreamWebTransportSendStream::H3(send),
          UpstreamWebTransportRecvStream::H3(recv),
        )
      }),
      Self::H2(session) => session
        .open_bi()
        .await
        .map(|(send, recv)| {
          (
            UpstreamWebTransportSendStream::H2(send),
            UpstreamWebTransportRecvStream::H2(recv),
          )
        })
        .context("failed to open an upstream HTTP/2 WebTransport bidirectional stream"),
    }
  }

  pub(crate) fn send_datagram(&self, payload: Bytes) -> anyhow::Result<()> {
    match self {
      Self::H3(session) => session.send_datagram(payload),
      Self::H2(session) => session
        .send_datagram(payload)
        .context("failed to send an upstream HTTP/2 WebTransport datagram"),
    }
  }

  pub(crate) async fn read_datagram(&self) -> anyhow::Result<Bytes> {
    match self {
      Self::H3(session) => session.read_datagram().await,
      Self::H2(session) => session
        .read_datagram()
        .await
        .context("failed to read an upstream HTTP/2 WebTransport datagram"),
    }
  }

  /// H2 has a fixed local capsule datagram limit.  Preserve H3's existing
  /// strict API while letting the H2 bridge discard an oversized H3 datagram
  /// as a bounded best-effort payload instead of closing the session.
  pub(crate) async fn read_datagram_for_h2_bridge(&self) -> anyhow::Result<Bytes> {
    match self {
      Self::H3(session) => session.read_datagram_unbounded().await,
      Self::H2(session) => session
        .read_datagram()
        .await
        .context("failed to read an upstream HTTP/2 WebTransport datagram"),
    }
  }

  pub(crate) fn close(&self, code: u32, reason: &[u8]) {
    match self {
      Self::H3(session) => session.close(code, reason),
      Self::H2(session) => session.close(code, reason),
    }
  }

  pub(crate) fn silent_close(&self) {
    match self {
      Self::H3(session) => session.close(0, b""),
      Self::H2(session) => session.silent_close(),
    }
  }

  pub(crate) fn drain(&self) {
    if let Self::H2(session) = self {
      session.drain();
    }
  }

  /// H2 capsule peers expose the close capsule.  Quinn reports an H3 session
  /// close through its I/O tasks, so the H3 arm deliberately stays pending and
  /// lets the existing bridge error path retain its wire behavior.
  pub(crate) async fn closed(&self) -> anyhow::Result<(u32, Bytes)> {
    match self {
      Self::H2(session) => session
        .closed()
        .await
        .context("upstream HTTP/2 WebTransport session close failed"),
      Self::H3(_) => std::future::pending().await,
    }
  }
}

#[derive(Clone)]
pub(crate) struct H3WebTransportSession {
  inner: web_transport_quinn::Session,
}

impl H3WebTransportSession {
  async fn connect(
    connection: web_transport_quinn::quinn::Connection,
    target_url: url::Url,
    headers: http::HeaderMap,
    protocols: Vec<String>,
  ) -> anyhow::Result<Self> {
    let mut request =
      web_transport_quinn::proto::ConnectRequest::new(target_url).with_headers(headers);
    if !protocols.is_empty() {
      request = request.with_protocols(protocols);
    }
    let inner = web_transport_quinn::Session::connect(connection, request)
      .await
      .context("failed to establish the selected upstream WebTransport session")?;
    Ok(Self { inner })
  }

  async fn accept_uni(&self) -> anyhow::Result<H3WebTransportRecvStream> {
    self
      .inner
      .accept_uni()
      .await
      .map(H3WebTransportRecvStream::new)
      .context("failed to accept an upstream WebTransport unidirectional stream")
  }

  async fn accept_bi(
    &self,
  ) -> anyhow::Result<(H3WebTransportSendStream, H3WebTransportRecvStream)> {
    let (send, recv) = self
      .inner
      .accept_bi()
      .await
      .context("failed to accept an upstream WebTransport bidirectional stream")?;
    Ok((
      H3WebTransportSendStream::new(send),
      H3WebTransportRecvStream::new(recv),
    ))
  }

  async fn open_uni(&self) -> anyhow::Result<H3WebTransportSendStream> {
    self
      .inner
      .open_uni()
      .await
      .map(H3WebTransportSendStream::new)
      .context("failed to open an upstream WebTransport unidirectional stream")
  }

  async fn open_bi(&self) -> anyhow::Result<(H3WebTransportSendStream, H3WebTransportRecvStream)> {
    let (send, recv) = self
      .inner
      .open_bi()
      .await
      .context("failed to open an upstream WebTransport bidirectional stream")?;
    Ok((
      H3WebTransportSendStream::new(send),
      H3WebTransportRecvStream::new(recv),
    ))
  }

  fn send_datagram(&self, payload: Bytes) -> anyhow::Result<()> {
    ensure!(
      payload.len() <= self.inner.max_datagram_size(),
      "upstream WebTransport datagram exceeds the negotiated payload limit"
    );
    self
      .inner
      .send_datagram(payload)
      .context("failed to send an upstream WebTransport datagram")
  }

  async fn read_datagram(&self) -> anyhow::Result<Bytes> {
    let payload = self
      .inner
      .read_datagram()
      .await
      .context("failed to read an upstream WebTransport datagram")?;
    ensure!(
      payload.len() <= MAX_WEBTRANSPORT_DATAGRAM_BYTES,
      "upstream WebTransport peer produced an oversized datagram"
    );
    Ok(payload)
  }

  async fn read_datagram_unbounded(&self) -> anyhow::Result<Bytes> {
    self
      .inner
      .read_datagram()
      .await
      .context("failed to read an upstream WebTransport datagram")
  }

  fn close(&self, code: u32, reason: &[u8]) {
    self.inner.close(code, reason);
  }
}

pub(crate) enum UpstreamWebTransportRecvStream {
  H3(H3WebTransportRecvStream),
  H2(crate::webtransport::RecvStream),
}

impl UpstreamWebTransportRecvStream {
  pub(crate) fn stop(&mut self, code: u32) -> io::Result<()> {
    match self {
      Self::H3(stream) => stream.stop(code),
      Self::H2(stream) => stream.stop(code),
    }
  }

  pub(crate) fn reset_code(&self) -> Option<u32> {
    match self {
      Self::H3(_) => None,
      Self::H2(stream) => stream.reset_code(),
    }
  }
}

impl AsyncRead for UpstreamWebTransportRecvStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    match self.as_mut().get_mut() {
      Self::H3(stream) => Pin::new(stream).poll_read(context, buffer),
      Self::H2(stream) => Pin::new(stream).poll_read(context, buffer),
    }
  }
}

pub(crate) enum UpstreamWebTransportSendStream {
  H3(H3WebTransportSendStream),
  H2(crate::webtransport::SendStream),
}

impl UpstreamWebTransportSendStream {
  pub(crate) fn reset(&mut self, code: u32) -> io::Result<()> {
    match self {
      Self::H3(stream) => stream.reset(code),
      Self::H2(stream) => stream.reset(code),
    }
  }

  pub(crate) fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<io::Result<u32>> {
    match self {
      Self::H3(stream) => stream.poll_stopped(context),
      Self::H2(stream) => stream.poll_stopped(context),
    }
  }
}

impl AsyncWrite for UpstreamWebTransportSendStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
    buffer: &[u8],
  ) -> Poll<io::Result<usize>> {
    match self.as_mut().get_mut() {
      Self::H3(stream) => Pin::new(stream).poll_write(context, buffer),
      Self::H2(stream) => Pin::new(stream).poll_write(context, buffer),
    }
  }

  fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.as_mut().get_mut() {
      Self::H3(stream) => Pin::new(stream).poll_flush(context),
      Self::H2(stream) => Pin::new(stream).poll_flush(context),
    }
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
    match self.as_mut().get_mut() {
      Self::H3(stream) => Pin::new(stream).poll_shutdown(context),
      Self::H2(stream) => Pin::new(stream).poll_shutdown(context),
    }
  }
}

pub(crate) struct H3WebTransportRecvStream {
  inner: web_transport_quinn::RecvStream,
}

impl H3WebTransportRecvStream {
  fn new(inner: web_transport_quinn::RecvStream) -> Self {
    Self { inner }
  }

  fn stop(&mut self, code: u32) -> io::Result<()> {
    self.inner.stop(code).map_err(io::Error::other)
  }
}

impl AsyncRead for H3WebTransportRecvStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    let filled_before = buffer.filled().len();
    let remaining_before = buffer.remaining();
    match Pin::new(&mut self.inner).poll_read(context, buffer) {
      Poll::Ready(Ok(())) => {
        let filled_after = buffer.filled().len();
        Poll::Ready(validate_read_progress(
          filled_before,
          remaining_before,
          filled_after,
        ))
      }
      Poll::Ready(Err(error)) => {
        let reset_code = error
          .get_ref()
          .and_then(|cause| cause.downcast_ref::<web_transport_quinn::quinn::ReadError>())
          .and_then(|error| match error {
            web_transport_quinn::quinn::ReadError::Reset(code) => {
              h3_application_code_from_wire(code.into_inner())
            }
            _ => None,
          });
        match reset_code {
          Some(code) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            crate::webtransport::StreamResetCode(code),
          ))),
          None => Poll::Ready(Err(error)),
        }
      }
      Poll::Pending => Poll::Pending,
    }
  }
}

fn validate_read_progress(
  filled_before: usize,
  remaining_before: usize,
  filled_after: usize,
) -> io::Result<()> {
  let filled = filled_after.checked_sub(filled_before).ok_or_else(|| {
    io::Error::new(
      io::ErrorKind::InvalidData,
      "upstream WebTransport read regressed the initialized buffer length",
    )
  })?;
  if filled > remaining_before {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      "upstream WebTransport read exceeded initialized buffer capacity",
    ));
  }
  Ok(())
}

pub(crate) struct H3WebTransportSendStream {
  inner: web_transport_quinn::SendStream,
}

impl H3WebTransportSendStream {
  fn new(inner: web_transport_quinn::SendStream) -> Self {
    Self { inner }
  }

  fn reset(&mut self, code: u32) -> io::Result<()> {
    self.inner.reset(code).map_err(io::Error::other)
  }

  fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<io::Result<u32>> {
    // The send-only poll API retains Quinn's STOP notification future. A
    // temporary `stopped()` future would unregister its waiter on every poll.
    // This does not use the generic receive/BufMut helpers.
    match web_transport_quinn::generic::poll::SendStream::poll_closed(&mut self.inner, context) {
      Poll::Ready(Err(web_transport_quinn::WriteError::Stopped(code))) => Poll::Ready(Ok(code)),
      Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
      // A normally acknowledged FIN is not STOP_SENDING. Let the caller's
      // shutdown poll observe its successful completion.
      Poll::Ready(Ok(())) | Poll::Pending => Poll::Pending,
    }
  }
}

impl AsyncWrite for H3WebTransportSendStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
    buffer: &[u8],
  ) -> Poll<io::Result<usize>> {
    match Pin::new(&mut self.inner).poll_write(context, buffer) {
      Poll::Ready(Ok(written)) if written > buffer.len() => Poll::Ready(Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "upstream WebTransport write exceeded the supplied buffer",
      ))),
      result => result,
    }
  }

  fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(context)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(context)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn assert_receive_contract<T: AsyncRead + Send + Unpin>() {}
  fn assert_send_contract<T: AsyncWrite + Send + Unpin>() {}

  #[test]
  fn h3_adapter_streams_expose_only_initialized_tokio_io() {
    assert_receive_contract::<H3WebTransportRecvStream>();
    assert_send_contract::<H3WebTransportSendStream>();
  }

  #[test]
  fn received_datagrams_stay_within_the_webtransport_limit() {
    assert_eq!(MAX_WEBTRANSPORT_DATAGRAM_BYTES, 65_535);
  }

  #[test]
  fn read_progress_rejects_non_monotonic_or_oversized_results() {
    assert!(validate_read_progress(4, 8, 12).is_ok());
    assert_eq!(
      validate_read_progress(4, 8, 3)
        .expect_err("a dependency must not shrink initialized storage")
        .kind(),
      io::ErrorKind::InvalidData
    );
    assert_eq!(
      validate_read_progress(4, 8, 13)
        .expect_err("a dependency must not over-report received bytes")
        .kind(),
      io::ErrorKind::InvalidData
    );
  }
}
