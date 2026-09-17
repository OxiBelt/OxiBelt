//! I/O cancellation and reset forwarding for HTTP/2 WebTransport streams.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use super::{PROTOCOL_ERROR, UpstreamWebTransportRecvStream, UpstreamWebTransportSendStream};

pub(super) trait StoppableRecv {
  fn stop(&mut self, code: u32) -> io::Result<()>;
  fn reset_code(&self) -> Option<u32> {
    None
  }
}
pub(super) trait ResettableSend {
  fn reset(&mut self, code: u32) -> io::Result<()>;
}
pub(super) trait StopAwareSend {
  fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<io::Result<u32>>;
}

pub(super) enum SendControl {
  Complete,
  Stopped(u32),
}

pub(super) enum ReadControl {
  Read(io::Result<usize>),
  Stopped,
}

pub(super) async fn read_or_stop<R, W>(
  recv: &mut R,
  send: &mut W,
  buffer: &mut [u8],
) -> io::Result<ReadControl>
where
  R: AsyncRead + StoppableRecv + Unpin,
  W: StopAwareSend + Unpin,
{
  tokio::select! {
    biased;
    stopped = std::future::poll_fn(|context| send.poll_stopped(context)) => {
      recv.stop(stopped?)?;
      Ok(ReadControl::Stopped)
    }
    read = recv.read(buffer) => Ok(ReadControl::Read(read)),
  }
}

pub(super) async fn forward_reset<R, W>(
  recv: &mut R,
  send: &mut W,
  code: u32,
) -> io::Result<SendControl>
where
  R: StoppableRecv,
  W: AsyncWrite + ResettableSend + StopAwareSend + Unpin,
{
  let _ = recv.stop(PROTOCOL_ERROR);
  match flush_or_stop(send).await? {
    SendControl::Complete => {
      send.reset(code)?;
      Ok(SendControl::Complete)
    }
    SendControl::Stopped(code) => {
      recv.stop(code)?;
      Ok(SendControl::Stopped(code))
    }
  }
}

/// Preserve bytes that `AsyncWrite` already accepted before a peer RESET. A
/// peer can withhold window credit indefinitely, so a pending flush must still
/// yield to STOP_SENDING and cancel the opposite receive half.
pub(super) async fn flush_or_stop<W>(send: &mut W) -> io::Result<SendControl>
where
  W: AsyncWrite + StopAwareSend + Unpin,
{
  std::future::poll_fn(|context| match send.poll_stopped(context) {
    Poll::Ready(Ok(code)) => Poll::Ready(Ok(SendControl::Stopped(code))),
    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    Poll::Pending => match Pin::new(&mut *send).poll_flush(context) {
      Poll::Ready(Ok(())) => Poll::Ready(Ok(SendControl::Complete)),
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Pending => Poll::Pending,
    },
  })
  .await
}

pub(super) async fn shutdown_or_stop<W>(send: &mut W) -> io::Result<SendControl>
where
  W: AsyncWrite + StopAwareSend + Unpin,
{
  std::future::poll_fn(|context| match send.poll_stopped(context) {
    Poll::Ready(Ok(code)) => Poll::Ready(Ok(SendControl::Stopped(code))),
    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    Poll::Pending => match Pin::new(&mut *send).poll_shutdown(context) {
      Poll::Ready(Ok(())) => Poll::Ready(Ok(SendControl::Complete)),
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Pending => Poll::Pending,
    },
  })
  .await
}

pub(super) async fn write_all_or_stop<W>(send: &mut W, bytes: &[u8]) -> io::Result<SendControl>
where
  W: AsyncWrite + StopAwareSend + Unpin,
{
  let mut offset = 0;
  while offset < bytes.len() {
    let result = std::future::poll_fn(|context| match send.poll_stopped(context) {
      Poll::Ready(Ok(code)) => Poll::Ready(Ok(WriteResult::Stopped(code))),
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Pending => match Pin::new(&mut *send).poll_write(context, &bytes[offset..]) {
        Poll::Ready(Ok(count)) => Poll::Ready(Ok(WriteResult::Written(count))),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Pending => Poll::Pending,
      },
    })
    .await?;
    match result {
      WriteResult::Stopped(code) => return Ok(SendControl::Stopped(code)),
      WriteResult::Written(0) => {
        return Err(io::Error::new(
          io::ErrorKind::WriteZero,
          "WebTransport bridge write returned zero bytes",
        ));
      }
      WriteResult::Written(count) => {
        let remaining = bytes.len() - offset;
        if count > remaining {
          return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WebTransport bridge write exceeded its buffer",
          ));
        }
        offset += count;
      }
    }
  }
  Ok(SendControl::Complete)
}

enum WriteResult {
  Stopped(u32),
  Written(usize),
}

impl StoppableRecv for crate::webtransport::RecvStream {
  fn stop(&mut self, code: u32) -> io::Result<()> {
    self.stop(code)
  }
  fn reset_code(&self) -> Option<u32> {
    crate::webtransport::RecvStream::reset_code(self)
  }
}
impl StoppableRecv for UpstreamWebTransportRecvStream {
  fn stop(&mut self, code: u32) -> io::Result<()> {
    self.stop(code)
  }
  fn reset_code(&self) -> Option<u32> {
    UpstreamWebTransportRecvStream::reset_code(self)
  }
}
impl ResettableSend for crate::webtransport::SendStream {
  fn reset(&mut self, code: u32) -> io::Result<()> {
    self.reset(code)
  }
}
impl StopAwareSend for crate::webtransport::SendStream {
  fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<io::Result<u32>> {
    crate::webtransport::SendStream::poll_stopped(self, context)
  }
}
impl ResettableSend for UpstreamWebTransportSendStream {
  fn reset(&mut self, code: u32) -> io::Result<()> {
    self.reset(code)
  }
}
impl StopAwareSend for UpstreamWebTransportSendStream {
  fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<io::Result<u32>> {
    UpstreamWebTransportSendStream::poll_stopped(self, context)
  }
}
