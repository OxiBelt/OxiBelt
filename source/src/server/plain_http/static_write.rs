//! Static response writes for the plain HTTP fast path.

use std::future::Future;
use std::io::{self, IoSlice};
use std::time::Duration;

use ::http::{HeaderMap, StatusCode};
use anyhow::{Context as AnyhowContext, bail};
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::TcpStream;
use tracing::debug;

use super::{TimedStaticResponsePlan, response_head::response_head_bytes, sendfile};
use crate::config::StaticFilesSendfileWriteStrategy;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::body::{BodyTimeoutError, BodyTimeoutKind};
use crate::proxy::http::fast_path::stage_timing;
use crate::proxy::http::static_files::{
  StaticBodyPlan, StaticResponseHeadBytes, StaticResponsePlan,
};
use crate::state::AppSnapshot;

pub(super) async fn write_static_plan(
  stream: &mut TcpStream,
  plan: &TimedStaticResponsePlan,
  keep_alive: bool,
  head_buffer: &mut Vec<u8>,
  snapshot: &AppSnapshot,
) -> anyhow::Result<()> {
  let TimedStaticResponsePlan {
    response,
    response_send_timeout,
    ..
  } = plan;
  let StaticResponsePlan {
    status,
    headers,
    body,
    response_heads,
  } = response;
  let response_send_timeout = *response_send_timeout;
  let stage_timing_metrics = snapshot.request_path_features.stage_timing_metrics;
  match body {
    StaticBodyPlan::Empty => {
      let head_started_at = stage_timing::start(stage_timing_metrics);
      let head = cached_or_rendered_response_head(
        response_heads.as_ref(),
        *status,
        headers,
        keep_alive,
        head_buffer,
      );
      stage_timing::record_metrics(
        &snapshot.metrics,
        stage_timing::PATH_STATIC_FILES,
        FastPathMetricProtocol::H1,
        stage_timing::STAGE_STATIC_HEAD_PREPARE,
        stage_timing::OUTCOME_OK,
        head_started_at,
      );
      let write_started_at = stage_timing::start(stage_timing_metrics);
      let result = write_all_tcp(
        stream,
        head,
        response_send_timeout,
        "static sendfile response head write failed",
      )
      .await;
      stage_timing::record_metrics(
        &snapshot.metrics,
        stage_timing::PATH_STATIC_FILES,
        FastPathMetricProtocol::H1,
        stage_timing::STAGE_STATIC_WRITE_HEAD,
        if result.is_ok() {
          stage_timing::OUTCOME_OK
        } else {
          stage_timing::OUTCOME_ERROR
        },
        write_started_at,
      );
      result?;
    }
    StaticBodyPlan::Text(message) => {
      let head_started_at = stage_timing::start(stage_timing_metrics);
      let head = cached_or_rendered_response_head(
        response_heads.as_ref(),
        *status,
        headers,
        keep_alive,
        head_buffer,
      );
      stage_timing::record_metrics(
        &snapshot.metrics,
        stage_timing::PATH_STATIC_FILES,
        FastPathMetricProtocol::H1,
        stage_timing::STAGE_STATIC_HEAD_PREPARE,
        stage_timing::OUTCOME_OK,
        head_started_at,
      );
      let write_started_at = stage_timing::start(stage_timing_metrics);
      let result = write_all_tcp_vectored(
        stream,
        head,
        message.as_bytes(),
        response_send_timeout,
        "static fast-path text response write failed",
      )
      .await;
      stage_timing::record_metrics(
        &snapshot.metrics,
        stage_timing::PATH_STATIC_FILES,
        FastPathMetricProtocol::H1,
        stage_timing::STAGE_STATIC_WRITE_BODY,
        if result.is_ok() {
          stage_timing::OUTCOME_OK
        } else {
          stage_timing::OUTCOME_ERROR
        },
        write_started_at,
      );
      result?;
    }
    StaticBodyPlan::Bytes {
      bytes,
      response_heads: body_response_heads,
      ..
    } => {
      let head_started_at = stage_timing::start(stage_timing_metrics);
      let head = match response_heads.as_ref().or(body_response_heads.as_ref()) {
        Some(response_heads) => response_heads.get(keep_alive).as_ref(),
        None => {
          response_head_bytes(*status, headers, keep_alive, head_buffer);
          head_buffer.as_slice()
        }
      };
      stage_timing::record_metrics(
        &snapshot.metrics,
        stage_timing::PATH_STATIC_FILES,
        FastPathMetricProtocol::H1,
        stage_timing::STAGE_STATIC_HEAD_PREPARE,
        stage_timing::OUTCOME_OK,
        head_started_at,
      );
      let write_started_at = stage_timing::start(stage_timing_metrics);
      let result = write_all_tcp_vectored(
        stream,
        head,
        bytes.as_ref(),
        response_send_timeout,
        "static fast-path bytes response write failed",
      )
      .await;
      stage_timing::record_metrics(
        &snapshot.metrics,
        stage_timing::PATH_STATIC_FILES,
        FastPathMetricProtocol::H1,
        stage_timing::STAGE_STATIC_WRITE_BODY,
        if result.is_ok() {
          stage_timing::OUTCOME_OK
        } else {
          stage_timing::OUTCOME_ERROR
        },
        write_started_at,
      );
      result?;
    }
    StaticBodyPlan::File(file) => {
      let head_started_at = stage_timing::start(stage_timing_metrics);
      let head = cached_or_rendered_response_head(
        response_heads.as_ref(),
        *status,
        headers,
        keep_alive,
        head_buffer,
      );
      stage_timing::record_metrics(
        &snapshot.metrics,
        stage_timing::PATH_STATIC_FILES,
        FastPathMetricProtocol::H1,
        stage_timing::STAGE_STATIC_HEAD_PREPARE,
        stage_timing::OUTCOME_OK,
        head_started_at,
      );
      let head_write_started_at = stage_timing::start(stage_timing_metrics);
      let write_strategy = snapshot.config.proxy.static_files.sendfile_write_strategy;
      let chunk_bytes = snapshot.config.proxy.static_files.sendfile_chunk_bytes;
      let corked = write_strategy == StaticFilesSendfileWriteStrategy::TcpCork
        && set_tcp_cork(stream, true).is_ok();
      let head_result = write_static_file_head(
        stream,
        head,
        write_strategy,
        response_send_timeout,
        "static sendfile response head write failed",
      )
      .await;
      stage_timing::record_metrics(
        &snapshot.metrics,
        stage_timing::PATH_STATIC_FILES,
        FastPathMetricProtocol::H1,
        stage_timing::STAGE_STATIC_WRITE_HEAD,
        if head_result.is_ok() {
          stage_timing::OUTCOME_OK
        } else {
          stage_timing::OUTCOME_ERROR
        },
        head_write_started_at,
      );
      if let Err(error) = head_result {
        if corked {
          let _ = set_tcp_cork(stream, false);
        }
        return Err(error);
      }
      let sendfile_started_at = stage_timing::start(stage_timing_metrics);
      let sendfile_result = sendfile_all(
        stream,
        &file.file,
        file.offset,
        file.len,
        chunk_bytes,
        response_send_timeout,
      )
      .await;
      if corked {
        let _ = set_tcp_cork(stream, false);
      }
      stage_timing::record_metrics(
        &snapshot.metrics,
        stage_timing::PATH_STATIC_FILES,
        FastPathMetricProtocol::H1,
        stage_timing::STAGE_STATIC_SENDFILE_BODY,
        if sendfile_result.is_ok() {
          stage_timing::OUTCOME_OK
        } else {
          stage_timing::OUTCOME_ERROR
        },
        sendfile_started_at,
      );
      sendfile_result?;
      debug!(
        path = %file.path.display(),
        bytes = file.len,
        "plain HTTP static fast-path response sent"
      );
    }
  }
  if !keep_alive {
    downstream_send_timeout(
      response_send_timeout,
      stream.shutdown(),
      "static sendfile response shutdown failed",
    )
    .await?;
  }
  Ok(())
}

#[cfg(target_os = "linux")]
async fn sendfile_all(
  stream: &mut TcpStream,
  file: &tokio::fs::File,
  offset: u64,
  len: u64,
  chunk_bytes: usize,
  response_send_timeout: Duration,
) -> anyhow::Result<()> {
  let mut remaining = len;
  let mut offset = libc::off64_t::try_from(offset).context("static file offset is too large")?;
  let chunk_bytes = chunk_bytes.max(1);
  while remaining > 0 {
    let count = remaining.min(chunk_bytes as u64) as usize;
    let stream_ref: &TcpStream = &*stream;
    match sendfile::sendfile_once(stream_ref, file, &mut offset, count) {
      Ok(0) => bail!("static sendfile wrote zero bytes"),
      Ok(sent) => remaining = remaining.saturating_sub(sent as u64),
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
        downstream_send_timeout(
          response_send_timeout,
          stream.writable(),
          "static sendfile socket wait failed",
        )
        .await?;
        let stream_ref: &TcpStream = &*stream;
        match stream_ref.try_io(Interest::WRITABLE, || {
          sendfile::sendfile_once(stream_ref, file, &mut offset, count)
        }) {
          Ok(0) => bail!("static sendfile wrote zero bytes"),
          Ok(sent) => remaining = remaining.saturating_sub(sent as u64),
          Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
          Err(error) => return Err(error).context("static sendfile syscall failed"),
        }
      }
      Err(error) => return Err(error).context("static sendfile syscall failed"),
    }
  }
  Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn sendfile_all(
  _stream: &mut TcpStream,
  _file: &tokio::fs::File,
  _offset: u64,
  _len: u64,
  _chunk_bytes: usize,
  _response_send_timeout: Duration,
) -> anyhow::Result<()> {
  bail!("kernel sendfile is not available on this platform")
}

async fn write_static_file_head(
  stream: &mut TcpStream,
  bytes: &[u8],
  strategy: StaticFilesSendfileWriteStrategy,
  response_send_timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()> {
  match strategy {
    StaticFilesSendfileWriteStrategy::MsgMore => {
      write_all_tcp_msg_more(stream, bytes, response_send_timeout, context).await
    }
    StaticFilesSendfileWriteStrategy::Auto
    | StaticFilesSendfileWriteStrategy::Split
    | StaticFilesSendfileWriteStrategy::TcpCork => {
      write_all_tcp(stream, bytes, response_send_timeout, context).await
    }
  }
}

#[cfg(target_os = "linux")]
async fn write_all_tcp_msg_more(
  stream: &mut TcpStream,
  mut bytes: &[u8],
  response_send_timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()> {
  while !bytes.is_empty() {
    match send_with_more(stream, bytes) {
      Ok(0) => bail!("{context}"),
      Ok(written) => bytes = &bytes[written..],
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
        downstream_send_timeout(response_send_timeout, stream.writable(), context).await?;
      }
      Err(error) => return Err(error).context(context),
    }
  }
  Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn write_all_tcp_msg_more(
  stream: &mut TcpStream,
  bytes: &[u8],
  response_send_timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()> {
  write_all_tcp(stream, bytes, response_send_timeout, context).await
}

#[cfg(target_os = "linux")]
fn send_with_more(stream: &TcpStream, bytes: &[u8]) -> io::Result<usize> {
  rustix::net::send(stream, bytes, rustix::net::SendFlags::MORE).map_err(io::Error::from)
}

#[cfg(target_os = "linux")]
fn set_tcp_cork(stream: &TcpStream, enabled: bool) -> io::Result<()> {
  rustix::net::sockopt::set_tcp_cork(stream, enabled).map_err(io::Error::from)
}

#[cfg(not(target_os = "linux"))]
fn set_tcp_cork(_stream: &TcpStream, _enabled: bool) -> io::Result<()> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "TCP_CORK is Linux-only",
  ))
}

async fn write_all_tcp(
  stream: &mut TcpStream,
  mut bytes: &[u8],
  response_send_timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()> {
  while !bytes.is_empty() {
    match stream.try_write(bytes) {
      Ok(0) => bail!("{context}"),
      Ok(written) => bytes = &bytes[written..],
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
        downstream_send_timeout(response_send_timeout, stream.writable(), context).await?;
      }
      Err(error) => return Err(error).context(context),
    }
  }
  Ok(())
}

async fn write_all_tcp_vectored(
  stream: &mut TcpStream,
  mut head: &[u8],
  mut body: &[u8],
  response_send_timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()> {
  while !head.is_empty() || !body.is_empty() {
    let written = match stream.try_write_vectored(&[IoSlice::new(head), IoSlice::new(body)]) {
      Ok(0) => bail!("{context}"),
      Ok(written) => written,
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
        downstream_send_timeout(response_send_timeout, stream.writable(), context).await?;
        continue;
      }
      Err(error) => return Err(error).context(context),
    };
    advance_vectored_write(&mut head, &mut body, written);
  }
  Ok(())
}

pub(in crate::server::plain_http) fn advance_vectored_write<'a>(
  head: &mut &'a [u8],
  body: &mut &'a [u8],
  written: usize,
) {
  if written < head.len() {
    *head = &head[written..];
    return;
  }
  let body_written = written.saturating_sub(head.len());
  *head = &[];
  *body = &body[body_written.min(body.len())..];
}

async fn downstream_send_timeout<T>(
  timeout: Duration,
  operation: impl Future<Output = io::Result<T>>,
  context: &'static str,
) -> anyhow::Result<T> {
  match tokio::time::timeout(timeout, operation).await {
    Ok(result) => result.context(context),
    Err(_) => Err(BodyTimeoutError::new(BodyTimeoutKind::DownstreamResponseSend).into()),
  }
}

fn cached_or_rendered_response_head<'a>(
  response_heads: Option<&'a StaticResponseHeadBytes>,
  status: StatusCode,
  headers: &HeaderMap,
  keep_alive: bool,
  head_buffer: &'a mut Vec<u8>,
) -> &'a [u8] {
  match response_heads {
    Some(response_heads) => response_heads.get(keep_alive).as_ref(),
    None => {
      response_head_bytes(status, headers, keep_alive, head_buffer);
      head_buffer.as_slice()
    }
  }
}
