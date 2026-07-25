//! Selected-path adapter for the upstream WebTransport implementation.
//! OxiBelt intentionally exposes only Tokio initialized-buffer I/O and never
//! the generic `web-transport-trait` buffer APIs.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, ensure};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_CLOSE_REASON_BYTES: usize = 1_024;
const MAX_WEBTRANSPORT_DATAGRAM_BYTES: usize = 65_535;

#[derive(Clone)]
pub(in crate::proxy::http3) struct UpstreamWebTransportSession {
  inner: web_transport_quinn::Session,
}

impl UpstreamWebTransportSession {
  pub(in crate::proxy::http3) async fn connect(
    connection: web_transport_quinn::quinn::Connection,
    request: web_transport_quinn::proto::ConnectRequest,
  ) -> anyhow::Result<Self> {
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
    self.inner.close(code, bounded_close_reason(reason));
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
        let filled = buffer.filled().len().saturating_sub(filled_before);
        if filled > remaining_before {
          return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream WebTransport read exceeded initialized buffer capacity",
          )));
        }
        Poll::Ready(Ok(()))
      }
      result => result,
    }
  }
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

fn bounded_close_reason(reason: &[u8]) -> &[u8] {
  &reason[..reason.len().min(MAX_CLOSE_REASON_BYTES)]
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
  fn close_reasons_are_bounded_before_reaching_the_dependency() {
    let oversized = vec![b'x'; MAX_CLOSE_REASON_BYTES + 1];
    assert_eq!(
      bounded_close_reason(&oversized).len(),
      MAX_CLOSE_REASON_BYTES
    );
    assert_eq!(bounded_close_reason(b"closed"), b"closed");
  }
}
