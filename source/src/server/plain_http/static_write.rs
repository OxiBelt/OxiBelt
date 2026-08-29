//! Static response writes for the plain HTTP fast path.

use std::future::Future;
use std::io::{self, IoSlice};
use std::sync::Arc;
use std::time::Duration;

use ::http::{HeaderMap, StatusCode};
use anyhow::{Context as AnyhowContext, bail};
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::TcpStream;
use tracing::debug;

use super::{TimedStaticResponsePlan, response_head::response_head_bytes, sendfile};
use crate::bandwidth::{BandwidthDirection, BandwidthFlow, RouteBandwidthLimiter};
use crate::config::StaticFilesSendfileWriteStrategy;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::metrics::{BandwidthTrafficClass, Metrics};
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
    bandwidth,
    ..
  } = plan;
  let StaticResponsePlan {
    status,
    headers,
    body,
    response_heads,
  } = response;
  let response_send_timeout = *response_send_timeout;
  let mut bandwidth = StaticResponseBandwidth::new(bandwidth.as_ref(), snapshot.metrics.clone());
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
      let result = if bandwidth.is_retained() {
        async {
          write_all_tcp(
            stream,
            head,
            response_send_timeout,
            "static fast-path text response head write failed",
          )
          .await?;
          write_static_payload(
            stream,
            message.as_bytes(),
            &mut bandwidth,
            response_send_timeout,
            "static fast-path text response body write failed",
          )
          .await
        }
        .await
      } else {
        write_all_tcp_vectored(
          stream,
          head,
          message.as_bytes(),
          response_send_timeout,
          "static fast-path text response write failed",
        )
        .await
      };
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
      let result = if bandwidth.is_retained() {
        async {
          write_all_tcp(
            stream,
            head,
            response_send_timeout,
            "static fast-path bytes response head write failed",
          )
          .await?;
          write_static_payload(
            stream,
            bytes.as_ref(),
            &mut bandwidth,
            response_send_timeout,
            "static fast-path bytes response body write failed",
          )
          .await
        }
        .await
      } else {
        write_all_tcp_vectored(
          stream,
          head,
          bytes.as_ref(),
          response_send_timeout,
          "static fast-path bytes response write failed",
        )
        .await
      };
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
        &mut bandwidth,
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
  bandwidth: &mut StaticResponseBandwidth,
) -> anyhow::Result<()> {
  let mut remaining = len;
  let mut offset = libc::off64_t::try_from(offset).context("static file offset is too large")?;
  let chunk_bytes = chunk_bytes.max(1);
  while remaining > 0 {
    let requested = remaining.min(chunk_bytes as u64) as usize;
    let mut granted = bandwidth.acquire(requested).await?;
    while granted > 0 {
      let stream_ref: &TcpStream = &*stream;
      match sendfile::sendfile_once(stream_ref, file, &mut offset, granted) {
        Ok(0) => bail!("static sendfile wrote zero bytes"),
        Ok(sent) => {
          granted = granted.saturating_sub(sent);
          remaining = remaining.saturating_sub(sent as u64);
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
          downstream_send_timeout(
            response_send_timeout,
            stream.writable(),
            "static sendfile socket wait failed",
          )
          .await?;
          let stream_ref: &TcpStream = &*stream;
          match stream_ref.try_io(Interest::WRITABLE, || {
            sendfile::sendfile_once(stream_ref, file, &mut offset, granted)
          }) {
            Ok(0) => bail!("static sendfile wrote zero bytes"),
            Ok(sent) => {
              granted = granted.saturating_sub(sent);
              remaining = remaining.saturating_sub(sent as u64);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error).context("static sendfile syscall failed"),
          }
        }
        Err(error) => return Err(error).context("static sendfile syscall failed"),
      }
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
  _bandwidth: &mut StaticResponseBandwidth,
) -> anyhow::Result<()> {
  bail!("kernel sendfile is not available on this platform")
}

struct StaticResponseBandwidth {
  flow: Option<BandwidthFlow>,
  metrics: Arc<Metrics>,
}

impl StaticResponseBandwidth {
  fn new(limiter: Option<&Arc<RouteBandwidthLimiter>>, metrics: Arc<Metrics>) -> Self {
    Self {
      flow: limiter.map(|limiter| limiter.flow(BandwidthDirection::Download)),
      metrics,
    }
  }

  fn is_retained(&self) -> bool {
    self.flow.is_some()
  }

  async fn acquire(&mut self, requested: usize) -> anyhow::Result<usize> {
    let Some(flow) = self.flow.as_mut() else {
      return Ok(requested);
    };
    if !flow.is_limited()? {
      return Ok(requested);
    }
    let grant = flow.acquire(requested).await?;
    self.metrics.record_bandwidth_shaped_bytes(
      BandwidthDirection::Download,
      BandwidthTrafficClass::Http,
      u64::try_from(grant.bytes()).unwrap_or(u64::MAX),
    );
    if !grant.waited().is_zero() {
      self.metrics.record_bandwidth_wait(
        BandwidthDirection::Download,
        BandwidthTrafficClass::Http,
        grant.waited(),
      );
    }
    Ok(grant.bytes())
  }
}

async fn write_static_payload(
  stream: &mut TcpStream,
  mut bytes: &[u8],
  bandwidth: &mut StaticResponseBandwidth,
  response_send_timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()> {
  while !bytes.is_empty() {
    let granted = bandwidth.acquire(bytes.len()).await?;
    write_all_tcp(stream, &bytes[..granted], response_send_timeout, context).await?;
    bytes = &bytes[granted..];
  }
  Ok(())
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
  use std::num::NonZeroU64;

  use tokio::io::AsyncReadExt;

  use super::*;
  use crate::bandwidth::{BANDWIDTH_QUANTUM_BYTES, BandwidthPolicy, BandwidthRate};

  #[tokio::test(start_paused = true)]
  async fn sendfile_observes_mid_response_unlimited_to_limited_reload() {
    let temp_dir = tempfile::tempdir().unwrap();
    let path = temp_dir.path().join("payload.bin");
    let payload = vec![b'x'; 4 + BANDWIDTH_QUANTUM_BYTES + 1];
    std::fs::write(&path, &payload).unwrap();
    let file = tokio::fs::File::open(&path).await.unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let mut client = client.unwrap();
    let (mut server, _) = accepted.unwrap();

    let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED);
    let mut bandwidth = StaticResponseBandwidth::new(Some(&limiter), Metrics::new());
    sendfile_all(
      &mut server,
      &file,
      0,
      4,
      BANDWIDTH_QUANTUM_BYTES * 2,
      Duration::from_secs(5),
      &mut bandwidth,
    )
    .await
    .unwrap();
    let mut open = [0u8; 4];
    client.read_exact(&mut open).await.unwrap();
    assert_eq!(&open, b"xxxx");

    let rate =
      BandwidthRate::BytesPerSecond(NonZeroU64::new((BANDWIDTH_QUANTUM_BYTES * 4) as u64).unwrap());
    limiter
      .update(BandwidthPolicy::new(BandwidthRate::Unlimited, rate))
      .unwrap();
    let writer = tokio::spawn(async move {
      sendfile_all(
        &mut server,
        &file,
        4,
        (BANDWIDTH_QUANTUM_BYTES + 1) as u64,
        BANDWIDTH_QUANTUM_BYTES * 2,
        Duration::from_secs(5),
        &mut bandwidth,
      )
      .await
    });

    let mut first_grant = vec![0u8; BANDWIDTH_QUANTUM_BYTES];
    let first_read = client.read_exact(&mut first_grant);
    tokio::pin!(first_read);
    assert!(futures_util::poll!(first_read.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(249)).await;
    assert!(futures_util::poll!(first_read.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    first_read.await.unwrap();
    assert!(first_grant.iter().all(|byte| *byte == b'x'));

    let next = client.read_u8();
    tokio::pin!(next);
    assert!(futures_util::poll!(next.as_mut()).is_pending());
    writer.abort();
  }
}
