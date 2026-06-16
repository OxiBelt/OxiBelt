use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(in crate::server) struct InstrumentedDownstreamIo<I> {
  inner: I,
  metrics: Arc<crate::metrics::Metrics>,
  protocol: &'static str,
  transport: &'static str,
}

impl<I> InstrumentedDownstreamIo<I> {
  pub(in crate::server) fn new(
    inner: I,
    metrics: Arc<crate::metrics::Metrics>,
    protocol: &'static str,
    transport: &'static str,
  ) -> Self {
    Self {
      inner,
      metrics,
      protocol,
      transport,
    }
  }
}

impl<I> AsyncRead for InstrumentedDownstreamIo<I>
where
  I: AsyncRead + Unpin,
{
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_read(cx, buf)
  }
}

impl<I> AsyncWrite for InstrumentedDownstreamIo<I>
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

  fn poll_write_vectored(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
  }

  fn is_write_vectored(&self) -> bool {
    self.inner.is_write_vectored()
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let result = Pin::new(&mut self.inner).poll_flush(cx);
    if matches!(result, Poll::Ready(Ok(()))) {
      self
        .metrics
        .record_http_downstream_write_flush(self.protocol, self.transport);
    }
    result
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  struct FlushReadyIo;

  impl AsyncRead for FlushReadyIo {
    fn poll_read(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
      Poll::Pending
    }
  }

  impl AsyncWrite for FlushReadyIo {
    fn poll_write(
      self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
      _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
      Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
      Poll::Ready(Ok(()))
    }
  }

  #[test]
  fn records_successful_flush() {
    let metrics = crate::metrics::Metrics::new();
    let mut io = InstrumentedDownstreamIo::new(FlushReadyIo, metrics.clone(), "h1", "tcp");
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());

    let result = AsyncWrite::poll_flush(Pin::new(&mut io), &mut cx);
    assert!(matches!(result, Poll::Ready(Ok(()))));

    let body = metrics.prometheus(
      &crate::config::MetricsConfig::default(),
      crate::cache::CacheStats::default(),
      crate::tls::TlsServerSessionStorageStats::default(),
    );
    assert!(body.contains(
      "oxibelt_http_downstream_write_flushes_total{protocol=\"h1\",transport=\"tcp\"} 1"
    ));
  }
}
