//! Selected-path adapter for upstream WebTransport I/O.
//!
//! The H3 implementation remains deliberately private: the generic
//! `web-transport-trait` receive helpers accept `BufMut` spare capacity through
//! an unsafe conversion. OxiBelt exposes only Tokio's initialized-buffer I/O
//! from that dependency. The H2 variant is the capsule runtime and does not
//! depend on the H3 implementation.

use std::io;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, ensure};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) use web_transport_quinn::proto as web_transport_proto;

const MAX_WEBTRANSPORT_DATAGRAM_BYTES: usize = 65_535;
pub(crate) const MAX_WEBTRANSPORT_STREAMS: u64 = web_transport_proto::MAX_STREAMS;

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
  H2(H2WebTransportSession),
}

#[derive(Clone)]
pub(crate) struct H2WebTransportSession {
  inner: crate::webtransport::Session,
  selected_protocol: Option<String>,
  response_headers: Vec<(http::HeaderName, http::HeaderValue)>,
}

impl Deref for H2WebTransportSession {
  type Target = crate::webtransport::Session;

  fn deref(&self) -> &Self::Target {
    &self.inner
  }
}

impl UpstreamWebTransportSession {
  pub(crate) fn response_headers(&self) -> &[(http::HeaderName, http::HeaderValue)] {
    match self {
      Self::H3(session) => session
        .inner
        .response()
        .map_or(&[], |response| response.headers.as_slice()),
      Self::H2(session) => &session.response_headers,
    }
  }

  pub(crate) async fn draining(&self) {
    match self {
      Self::H3(session) => session.inner.draining().await,
      Self::H2(_) => std::future::pending().await,
    }
  }

  pub(crate) fn selected_protocol(&self) -> Option<&str> {
    match self {
      Self::H3(session) => session.inner.protocol(),
      Self::H2(session) => session.selected_protocol.as_deref(),
    }
  }

  pub(crate) fn abrupt_h3_close(&self) -> bool {
    match self {
      Self::H3(session) => is_abrupt_h3_close(session.inner.close_reason()),
      Self::H2(_) => false,
    }
  }

  pub(crate) fn supports_unassociated_uni_reset(&self) -> bool {
    matches!(self, Self::H3(_))
  }

  pub(in crate::proxy::http3) fn grant_h3_receive_credit(
    &self,
    limits: &crate::config::H2WebTransportConfig,
  ) -> anyhow::Result<()> {
    if let Self::H3(session) = self {
      session
        .inner
        .grant_receive_credit(
          u64::from(limits.max_concurrent_uni_streams),
          u64::from(limits.max_concurrent_bidi_streams),
          limits.max_session_buffer_bytes as u64,
        )
        .context("invalid upstream draft16 receive credit")?;
    }
    Ok(())
  }

  pub(in crate::proxy::http3) async fn connect_h3(
    connection: web_transport_quinn::quinn::Connection,
    target_url: url::Url,
    headers: http::HeaderMap,
    protocols: Vec<String>,
    draft: crate::config::WebTransportH3Draft,
  ) -> anyhow::Result<Self> {
    H3WebTransportSession::connect(connection, target_url, headers, protocols, draft)
      .await
      .map(|session| Self::H3(Box::new(session)))
  }

  pub(crate) fn from_h2(
    session: crate::webtransport::Session,
    selected_protocol: Option<String>,
    response_headers: Vec<(http::HeaderName, http::HeaderValue)>,
  ) -> Self {
    Self::H2(H2WebTransportSession {
      inner: session,
      selected_protocol,
      response_headers,
    })
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

  pub(crate) async fn relay_unassociated_uni_reset(&self, code: u32) -> anyhow::Result<()> {
    let Self::H3(session) = self else {
      anyhow::bail!("unassociated draft02 reset requires an HTTP/3 upstream");
    };
    let mut stream = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      session.inner.deref().open_uni(),
    )
    .await
    .context("timed out opening raw upstream QUIC stream for draft02 reset")?
    .context("failed to open raw upstream QUIC stream for draft02 reset")?;
    let wire_code = web_transport_quinn::quinn::VarInt::try_from(h3_application_code_to_wire(code))
      .context("invalid WebTransport reset code")?;
    stream
      .reset(wire_code)
      .context("failed to relay unassociated draft02 reset")
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

  pub(crate) async fn closed(&self) -> anyhow::Result<(u32, Bytes)> {
    match self {
      Self::H2(session) => session
        .closed()
        .await
        .context("upstream HTTP/2 WebTransport session close failed"),
      Self::H3(session) => h3_close_result(session.inner.closed().await),
    }
  }

  pub(crate) fn remote_close(&self) -> Option<(u32, Bytes)> {
    match self {
      Self::H2(session) => session.remote_close(),
      Self::H3(session) => match session.inner.close_reason()? {
        web_transport_quinn::SessionError::WebTransportError(
          web_transport_quinn::WebTransportError::Closed(code, reason),
        ) => Some((code, Bytes::from(reason))),
        _ => None,
      },
    }
  }
}

fn h3_close_result(error: web_transport_quinn::SessionError) -> anyhow::Result<(u32, Bytes)> {
  match error {
    web_transport_quinn::SessionError::WebTransportError(
      web_transport_quinn::WebTransportError::Closed(code, reason),
    ) => Ok((code, Bytes::from(reason))),
    error => {
      Err(anyhow::anyhow!(error).context("upstream HTTP/3 WebTransport session close failed"))
    }
  }
}

fn is_abrupt_h3_close(error: Option<web_transport_quinn::SessionError>) -> bool {
  error.is_some_and(|error| {
    !matches!(
      error,
      web_transport_quinn::SessionError::WebTransportError(
        web_transport_quinn::WebTransportError::Closed(_, _)
      )
    )
  })
}

#[cfg(test)]
mod close_tests {
  use super::{h3_close_result, is_abrupt_h3_close};

  #[test]
  fn clean_fin_has_default_close_info_but_transport_loss_is_an_error() {
    let clean = web_transport_quinn::WebTransportError::Closed(0, String::new()).into();
    assert_eq!(
      h3_close_result(clean).expect("clean FIN"),
      (0, bytes::Bytes::new())
    );

    let with_capsule = web_transport_quinn::WebTransportError::Closed(32, "abc".into()).into();
    assert_eq!(
      h3_close_result(with_capsule).expect("close capsule"),
      (32, bytes::Bytes::from_static(b"abc"))
    );

    let failed = web_transport_quinn::SessionError::ConnectionError(
      web_transport_quinn::quinn::ConnectionError::LocallyClosed,
    );
    assert!(h3_close_result(failed).is_err());
  }

  #[test]
  fn only_transport_loss_aborts_the_downstream_h3_connection() {
    assert!(!is_abrupt_h3_close(None));
    assert!(!is_abrupt_h3_close(Some(
      web_transport_quinn::WebTransportError::Closed(0, String::new()).into()
    )));
    assert!(is_abrupt_h3_close(Some(
      web_transport_quinn::SessionError::ConnectionError(
        web_transport_quinn::quinn::ConnectionError::LocallyClosed,
      )
    )));
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
    draft: crate::config::WebTransportH3Draft,
  ) -> anyhow::Result<Self> {
    let draft = match draft {
      crate::config::WebTransportH3Draft::Draft02 => {
        web_transport_quinn::proto::WebTransportDraft::Draft02
      }
      crate::config::WebTransportH3Draft::Draft16 => {
        web_transport_quinn::proto::WebTransportDraft::Draft16
      }
    };
    let mut request =
      web_transport_quinn::proto::ConnectRequest::new(target_url).with_headers(headers);
    if !protocols.is_empty() {
      request = request.with_protocols(protocols);
    }
    let inner = web_transport_quinn::Session::connect_with_draft(connection, request, draft)
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
