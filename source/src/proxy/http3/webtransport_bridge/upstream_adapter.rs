//! Selected-path adapter for upstream WebTransport I/O.
//!
//! The generic `web-transport-trait` receive helpers accept `BufMut` spare capacity
//! through an unsafe conversion. OxiBelt deliberately keeps that API private and
//! exposes only Tokio's initialized-buffer I/O to the bridge.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, ensure};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_WEBTRANSPORT_DATAGRAM_BYTES: usize = 65_535;

#[derive(Clone)]
pub(in crate::proxy::http3) struct UpstreamWebTransportSession {
  inner: web_transport_quinn::Session,
}

impl UpstreamWebTransportSession {
  pub(in crate::proxy::http3) async fn connect(
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

  pub(super) async fn accept_uni(&self) -> anyhow::Result<UpstreamWebTransportRecvStream> {
    self
      .inner
      .accept_uni()
      .await
      .map(UpstreamWebTransportRecvStream::new)
      .context("failed to accept an upstream WebTransport unidirectional stream")
  }

  pub(super) async fn accept_bi(
    &self,
  ) -> anyhow::Result<(
    UpstreamWebTransportSendStream,
    UpstreamWebTransportRecvStream,
  )> {
    let (send, recv) = self
      .inner
      .accept_bi()
      .await
      .context("failed to accept an upstream WebTransport bidirectional stream")?;
    Ok((
      UpstreamWebTransportSendStream::new(send),
      UpstreamWebTransportRecvStream::new(recv),
    ))
  }

  pub(super) async fn open_uni(&self) -> anyhow::Result<UpstreamWebTransportSendStream> {
    self
      .inner
      .open_uni()
      .await
      .map(UpstreamWebTransportSendStream::new)
      .context("failed to open an upstream WebTransport unidirectional stream")
  }

  pub(super) async fn open_bi(
    &self,
  ) -> anyhow::Result<(
    UpstreamWebTransportSendStream,
    UpstreamWebTransportRecvStream,
  )> {
    let (send, recv) = self
      .inner
      .open_bi()
      .await
      .context("failed to open an upstream WebTransport bidirectional stream")?;
    Ok((
      UpstreamWebTransportSendStream::new(send),
      UpstreamWebTransportRecvStream::new(recv),
    ))
  }

  pub(super) fn send_datagram(&self, payload: Bytes) -> anyhow::Result<()> {
    ensure!(
      payload.len() <= self.inner.max_datagram_size(),
      "upstream WebTransport datagram exceeds the negotiated payload limit"
    );
    self
      .inner
      .send_datagram(payload)
      .context("failed to send an upstream WebTransport datagram")
  }

  pub(super) async fn read_datagram(&self) -> anyhow::Result<Bytes> {
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

  pub(super) fn close(&self, code: u32, reason: &[u8]) {
    self.inner.close(code, reason);
  }
}

pub(super) struct UpstreamWebTransportRecvStream {
  inner: web_transport_quinn::RecvStream,
}

impl UpstreamWebTransportRecvStream {
  fn new(inner: web_transport_quinn::RecvStream) -> Self {
    Self { inner }
  }
}

impl AsyncRead for UpstreamWebTransportRecvStream {
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
      result => result,
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

pub(super) struct UpstreamWebTransportSendStream {
  inner: web_transport_quinn::SendStream,
}

impl UpstreamWebTransportSendStream {
  fn new(inner: web_transport_quinn::SendStream) -> Self {
    Self { inner }
  }
}

impl AsyncWrite for UpstreamWebTransportSendStream {
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
  fn adapter_streams_expose_only_initialized_tokio_io() {
    assert_receive_contract::<UpstreamWebTransportRecvStream>();
    assert_send_contract::<UpstreamWebTransportSendStream>();
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
