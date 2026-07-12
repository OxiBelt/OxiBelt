//! Tokio RESP encoding and decoding used by the Redis shared-state backend.

use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, bail};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug)]
pub(super) enum Resp {
  Simple(String),
  Error(String),
  Int(i64),
  Bulk(Option<Vec<u8>>),
  Array(Vec<Resp>),
  Nil,
}

impl Resp {
  pub(super) fn into_i64(self) -> anyhow::Result<i64> {
    match self {
      Self::Int(value) => Ok(value),
      Self::Bulk(Some(bytes)) => String::from_utf8(bytes)?.parse().map_err(Into::into),
      other => bail!("expected Redis integer response, got {other:?}"),
    }
  }
}

pub(super) async fn write_resp_command<W>(stream: &mut W, args: &[Vec<u8>]) -> anyhow::Result<()>
where
  W: AsyncWrite + Unpin,
{
  write_resp_commands(stream, &[args]).await
}

pub(super) async fn write_resp_commands<W>(
  stream: &mut W,
  commands: &[&[Vec<u8>]],
) -> anyhow::Result<()>
where
  W: AsyncWrite + Unpin,
{
  for args in commands {
    write_resp_command_unflushed(stream, args).await?;
  }
  stream.flush().await?;
  Ok(())
}

async fn write_resp_command_unflushed<W>(stream: &mut W, args: &[Vec<u8>]) -> anyhow::Result<()>
where
  W: AsyncWrite + Unpin,
{
  stream
    .write_all(format!("*{}\r\n", args.len()).as_bytes())
    .await?;
  for arg in args {
    stream
      .write_all(format!("${}\r\n", arg.len()).as_bytes())
      .await?;
    stream.write_all(arg).await?;
    stream.write_all(b"\r\n").await?;
  }
  Ok(())
}

pub(super) fn read_resp<'a, R>(
  reader: &'a mut R,
) -> Pin<Box<dyn Future<Output = anyhow::Result<Resp>> + Send + 'a>>
where
  R: AsyncBufRead + Unpin + Send + 'a,
{
  Box::pin(async move {
    let mut prefix = [0u8; 1];
    reader.read_exact(&mut prefix).await?;
    match prefix[0] {
      b'+' => Ok(Resp::Simple(read_line(reader).await?)),
      b'-' => Ok(Resp::Error(read_line(reader).await?)),
      b':' => Ok(Resp::Int(read_line(reader).await?.parse()?)),
      b'$' => {
        let len = read_line(reader).await?.parse::<isize>()?;
        if len < 0 {
          return Ok(Resp::Nil);
        }
        let len = usize::try_from(len).context("invalid Redis bulk response length")?;
        let mut bytes = vec![0u8; len];
        reader.read_exact(&mut bytes).await?;
        read_crlf(reader).await?;
        Ok(Resp::Bulk(Some(bytes)))
      }
      b'*' => {
        let len = read_line(reader).await?.parse::<isize>()?;
        if len < 0 {
          return Ok(Resp::Nil);
        }
        let len = usize::try_from(len).context("invalid Redis array response length")?;
        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
          items.push(read_resp(reader).await?);
        }
        Ok(Resp::Array(items))
      }
      other => bail!("unsupported Redis response prefix {}", other as char),
    }
  })
}

async fn read_line<R>(reader: &mut R) -> anyhow::Result<String>
where
  R: AsyncBufRead + Unpin,
{
  let mut line = String::new();
  let read = reader.read_line(&mut line).await?;
  if read == 0 {
    bail!("unexpected EOF while reading Redis response");
  }
  if !line.ends_with("\r\n") {
    bail!("invalid Redis response line terminator");
  }
  line.truncate(line.len() - 2);
  Ok(line)
}

async fn read_crlf<R>(reader: &mut R) -> anyhow::Result<()>
where
  R: AsyncBufRead + Unpin,
{
  let mut crlf = [0u8; 2];
  reader.read_exact(&mut crlf).await?;
  if crlf != *b"\r\n" {
    bail!("invalid Redis bulk terminator");
  }
  Ok(())
}

pub(super) fn expect_ok(resp: Resp) -> anyhow::Result<()> {
  match resp {
    Resp::Simple(value) if value == "OK" => Ok(()),
    Resp::Int(_) => Ok(()),
    Resp::Error(error) => bail!("Redis error: {error}"),
    other => bail!("unexpected Redis response: {other:?}"),
  }
}

pub(super) fn expect_pong(resp: Resp) -> anyhow::Result<()> {
  match resp {
    Resp::Simple(value) if value == "PONG" => Ok(()),
    Resp::Error(error) => bail!("Redis error: {error}"),
    other => bail!("unexpected Redis PING response: {other:?}"),
  }
}

#[cfg(test)]
mod tests {
  use super::{Resp, expect_ok, expect_pong};

  #[test]
  fn redis_reply_validators_are_command_specific() {
    assert!(expect_pong(Resp::Simple("PONG".to_string())).is_ok());
    assert!(expect_pong(Resp::Simple("OK".to_string())).is_err());
    assert!(expect_pong(Resp::Int(1)).is_err());

    assert!(expect_ok(Resp::Simple("OK".to_string())).is_ok());
    assert!(expect_ok(Resp::Simple("PONG".to_string())).is_err());
    assert!(expect_ok(Resp::Int(1)).is_ok());
  }
}
