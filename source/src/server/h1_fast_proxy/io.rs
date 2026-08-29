use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncWrite, AsyncWriteExt};

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
