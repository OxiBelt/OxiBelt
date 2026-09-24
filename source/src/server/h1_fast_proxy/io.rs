use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::trace;

use super::H1FastProxyPreflight;

pub(super) async fn write_all_timeout<I>(
  stream: &mut I,
  bytes: &[u8],
  timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()>
where
  I: AsyncWrite + Unpin,
{
  tokio::time::timeout(timeout, stream.write_all(bytes))
    .await
    .context(context)??;
  Ok(())
}

pub(super) async fn shutdown_timeout<I>(stream: &mut I, timeout: Duration) -> anyhow::Result<()>
where
  I: AsyncWrite + Unpin,
{
  tokio::time::timeout(timeout, stream.shutdown())
    .await
    .context("TLS H1 pre-Hyper response shutdown failed")??;
  Ok(())
}

pub(super) async fn close_tls_stream(
  mut stream: TlsStream<TcpStream>,
  timeout: Duration,
) -> H1FastProxyPreflight {
  if let Err(error) = shutdown_timeout(&mut stream, timeout).await {
    trace!(%error, "TLS H1 pre-Hyper proxy close_notify could not be sent");
  }
  H1FastProxyPreflight::Done
}
