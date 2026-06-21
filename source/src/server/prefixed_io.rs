//! Async IO wrapper that replays bytes already read by a lightweight preflight parser.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct PrefixedIo<I> {
  inner: I,
  prefix: Vec<u8>,
  prefix_offset: usize,
}

impl<I> PrefixedIo<I> {
  pub(super) fn new(inner: I, prefix: Vec<u8>) -> Self {
    Self {
      inner,
      prefix,
      prefix_offset: 0,
    }
  }
}

impl<I> AsyncRead for PrefixedIo<I>
where
  I: AsyncRead + Unpin,
{
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    if self.prefix_offset < self.prefix.len() {
      let remaining = &self.prefix[self.prefix_offset..];
      let to_copy = remaining.len().min(buf.remaining());
      buf.put_slice(&remaining[..to_copy]);
      self.prefix_offset += to_copy;
      if self.prefix_offset == self.prefix.len() {
        self.prefix.clear();
        self.prefix_offset = 0;
      }
      return Poll::Ready(Ok(()));
    }
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl<I> AsyncWrite for PrefixedIo<I>
where
  I: AsyncWrite + Unpin,
{
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}
