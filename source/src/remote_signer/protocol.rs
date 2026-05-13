use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{anyhow, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream as TokioUnixStream;

const MAX_FRAME_LEN: usize = 1024 * 1024;

pub(super) fn write_sync_frame<T: Serialize>(
  stream: &mut std::os::unix::net::UnixStream,
  value: &T,
) -> anyhow::Result<()> {
  let bytes = serde_json::to_vec(value)?;
  if bytes.len() > MAX_FRAME_LEN {
    bail!("remote signer frame is too large");
  }
  stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
  stream.write_all(&bytes)?;
  Ok(())
}

pub(super) fn read_sync_frame<T: DeserializeOwned>(
  stream: &mut std::os::unix::net::UnixStream,
) -> anyhow::Result<T> {
  let mut len = [0u8; 4];
  stream.read_exact(&mut len)?;
  let len = u32::from_be_bytes(len) as usize;
  if len > MAX_FRAME_LEN {
    bail!("remote signer frame is too large");
  }
  let mut bytes = vec![0u8; len];
  stream.read_exact(&mut bytes)?;
  Ok(serde_json::from_slice(&bytes)?)
}

async fn write_async_frame<T: Serialize>(
  stream: &mut TokioUnixStream,
  value: &T,
) -> anyhow::Result<()> {
  let bytes = serde_json::to_vec(value)?;
  if bytes.len() > MAX_FRAME_LEN {
    bail!("remote signer frame is too large");
  }
  stream
    .write_all(&(bytes.len() as u32).to_be_bytes())
    .await?;
  stream.write_all(&bytes).await?;
  Ok(())
}

pub(super) async fn write_async_frame_with_timeout<T: Serialize>(
  stream: &mut TokioUnixStream,
  value: &T,
  timeout_duration: Duration,
) -> anyhow::Result<()> {
  tokio::time::timeout(timeout_duration, write_async_frame(stream, value))
    .await
    .map_err(|_| anyhow!("remote signer write timed out"))?
}

async fn read_async_frame<T: DeserializeOwned>(stream: &mut TokioUnixStream) -> anyhow::Result<T> {
  let mut len = [0u8; 4];
  stream.read_exact(&mut len).await?;
  let len = u32::from_be_bytes(len) as usize;
  if len > MAX_FRAME_LEN {
    bail!("remote signer frame is too large");
  }
  let mut bytes = vec![0u8; len];
  stream.read_exact(&mut bytes).await?;
  Ok(serde_json::from_slice(&bytes)?)
}

pub(super) async fn read_async_frame_with_timeout<T: DeserializeOwned>(
  stream: &mut TokioUnixStream,
  timeout_duration: Duration,
) -> anyhow::Result<T> {
  tokio::time::timeout(timeout_duration, read_async_frame(stream))
    .await
    .map_err(|_| anyhow!("remote signer read timed out"))?
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum RemoteSignerRequest {
  DescribeKey {
    token: String,
    key_id: String,
  },
  Sign {
    token: String,
    key_id: String,
    scheme: u16,
    context: SignContext,
    message: String,
  },
}

impl RemoteSignerRequest {
  pub(super) fn token(&self) -> &str {
    match self {
      Self::DescribeKey { token, .. } | Self::Sign { token, .. } => token,
    }
  }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum RemoteSignerResponse {
  DescribeKey {
    public_key: String,
    algorithm: String,
    schemes: Vec<u16>,
  },
  Sign {
    signature: String,
  },
  Error {
    code: String,
    message: String,
  },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SignContext {
  Tls13ServerCertificateVerify,
  Tls12Unstructured,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn async_frame_reader_times_out_idle_peer() {
    let (mut server, _client) = TokioUnixStream::pair().expect("Unix stream pair should create");

    let error =
      read_async_frame_with_timeout::<RemoteSignerRequest>(&mut server, Duration::from_millis(25))
        .await
        .expect_err("idle peer must time out before authentication");

    assert!(
      error.to_string().contains("read timed out"),
      "unexpected error: {error:#}"
    );
  }
}
