//! Plain TCP IO helpers for the lightweight HTTP path.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub(super) struct PlainHttpIo {
  stream: TcpStream,
  prefix: Vec<u8>,
  prefix_offset: usize,
}

impl PlainHttpIo {
  pub(super) fn new(stream: TcpStream, prefix: Vec<u8>) -> Self {
    Self {
      stream,
      prefix,
      prefix_offset: 0,
    }
  }

  #[cfg(test)]
  pub(super) fn prefix_for_tests(&self) -> &[u8] {
    &self.prefix[self.prefix_offset..]
  }
}

impl AsyncRead for PlainHttpIo {
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
    Pin::new(&mut self.stream).poll_read(cx, buf)
  }
}

impl AsyncWrite for PlainHttpIo {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.stream).poll_write(cx, buf)
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.stream).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.stream).poll_shutdown(cx)
  }
}
