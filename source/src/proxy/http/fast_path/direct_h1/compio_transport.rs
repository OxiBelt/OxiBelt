//! Tokio request-path adapter for the persistent Compio direct-H1 service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
#[cfg(test)]
use bytes::{Bytes, BytesMut};
#[cfg(test)]
use http::Request;
#[cfg(test)]
use hyper::body::Body;

use crate::config::EarlyHintsMode;
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body;
#[cfg(test)]
use crate::proxy::http::body::ProxyBody;

use super::compio_service::{
  CompioDirectH1Operation, CompioDirectH1OperationResult, CompioDirectH1PredispatchReason,
  CompioDirectH1Service, CompioDirectH1Visibility,
};
use super::{
  COMPIO_RESOLUTION_CACHE_TTL, CompioDirectH1Resolution, DirectH1Pool, DirectH1Response,
  DirectH1SendMetricOptions, DirectH1TransportError, PreparedDirectH1Request,
};

pub(super) mod cancellation;
pub(super) mod failure;
#[cfg(test)]
mod tests;

use self::cancellation::CancellationToken;
#[cfg(test)]
use self::failure::{cancellation_failure, metric_reason};
#[cfg(test)]
use super::response_protocol::{
  ResponseEvent, ResponseProtocolEngine, ResponseProtocolFailureReason, ResponseState, ResponseStep,
};

const MAX_RESOLVED_ADDRESSES: usize = 16;

pub(super) enum CompioDirectH1SendResult {
  NotSubmitted {
    prepared: Box<PreparedDirectH1Request>,
    reason: CompioDirectH1PredispatchReason,
    source: Option<anyhow::Error>,
  },
  Sent {
    result: anyhow::Result<DirectH1Response>,
    visibility: CompioDirectH1Visibility,
    bytes_written: usize,
  },
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_prepared_request(
  service: &Arc<CompioDirectH1Service>,
  pool: Arc<DirectH1Pool>,
  metrics: Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  prepared: PreparedDirectH1Request,
  timeouts: EffectiveTimeouts,
  early_hints_mode: EarlyHintsMode,
  metric_options: DirectH1SendMetricOptions,
) -> CompioDirectH1SendResult {
  let resolved = match resolve_origin(&pool, timeouts.upstream_connect).await {
    Ok(resolved) => resolved,
    Err(source) => {
      return CompioDirectH1SendResult::NotSubmitted {
        prepared: Box::new(prepared),
        reason: CompioDirectH1PredispatchReason::Resolve,
        source: Some(DirectH1TransportError::connect(source)),
      };
    }
  };
  let (cancellation, cancellation_guard) = CancellationToken::pair();
  let operation = CompioDirectH1Operation::new(
    pool,
    metrics,
    protocol,
    prepared,
    resolved,
    timeouts,
    early_hints_mode,
    metric_options,
    cancellation,
  );
  match service.execute(operation).await {
    CompioDirectH1OperationResult::NotSubmitted {
      prepared: returned,
      reason,
      source,
      visibility,
      bytes_written,
    } => {
      debug_assert_eq!(visibility, CompioDirectH1Visibility::NotSubmitted);
      debug_assert_eq!(bytes_written, 0);
      CompioDirectH1SendResult::NotSubmitted {
        prepared: returned,
        reason,
        source,
      }
    }
    CompioDirectH1OperationResult::ResponseHead {
      head,
      body,
      downstream_cancellation_required,
      visibility,
      bytes_written,
    } => {
      let body = if downstream_cancellation_required {
        body::with_drop_guard(body, cancellation_guard)
      } else {
        drop(cancellation_guard);
        body
      };
      let result = head.into_response(body).map(|response| DirectH1Response {
        response,
        lease: None,
      });
      CompioDirectH1SendResult::Sent {
        result,
        visibility,
        bytes_written,
      }
    }
    CompioDirectH1OperationResult::Failed {
      visibility,
      bytes_written,
      source,
    } => CompioDirectH1SendResult::Sent {
      result: Err(source),
      visibility,
      bytes_written,
    },
  }
}

async fn resolve_origin(
  pool: &DirectH1Pool,
  timeout: std::time::Duration,
) -> anyhow::Result<Arc<[SocketAddr]>> {
  let deadline = Instant::now()
    .checked_add(timeout)
    .context("Compio direct-H1 DNS resolution deadline overflowed")?;
  if let Some(addresses) = cached_resolution(pool) {
    return Ok(addresses);
  }
  // Serialize only the refresh operation. The cache mutex itself is never held
  // across DNS I/O, and every follower spends from the same per-request
  // connect deadline while it waits for the in-flight refresh.
  let refresh = tokio::time::timeout(
    remaining_resolution_time(deadline)?,
    pool.compio_resolution_gate.acquire(),
  )
  .await
  .context("Compio direct-H1 DNS resolution waiter timed out")?
  .context("Compio direct-H1 DNS resolution gate closed")?;
  if let Some(addresses) = cached_resolution(pool) {
    return Ok(addresses);
  }
  let resolved = tokio::time::timeout(
    remaining_resolution_time(deadline)?,
    crate::upstream_resolution::resolve_socket_addrs(
      pool.origin.host.as_ref(),
      pool.origin.port,
      deadline.into(),
    ),
  )
  .await
  .context("Compio direct-H1 DNS resolution timed out")?
  .with_context(|| {
    format!(
      "failed to resolve Compio direct-H1 upstream {}:{}",
      pool.origin.host, pool.origin.port
    )
  })?;
  let addresses: Arc<[SocketAddr]> = resolved
    .into_iter()
    .take(MAX_RESOLVED_ADDRESSES)
    .collect::<Vec<_>>()
    .into();
  if addresses.is_empty() {
    anyhow::bail!("Compio direct-H1 upstream resolved no socket addresses");
  }
  pool
    .compio_resolution
    .store(Some(Arc::new(CompioDirectH1Resolution {
      expires_at: Instant::now() + COMPIO_RESOLUTION_CACHE_TTL,
      addresses: Arc::clone(&addresses),
    })));
  drop(refresh);
  Ok(addresses)
}

fn cached_resolution(pool: &DirectH1Pool) -> Option<Arc<[SocketAddr]>> {
  let cached = pool.compio_resolution.load();
  cached
    .as_ref()
    .filter(|resolution| resolution.expires_at > Instant::now())
    .map(|resolution| Arc::clone(&resolution.addresses))
}

fn remaining_resolution_time(deadline: Instant) -> anyhow::Result<std::time::Duration> {
  deadline
    .checked_duration_since(Instant::now())
    .filter(|remaining| !remaining.is_zero())
    .context("Compio direct-H1 DNS resolution timed out")
}

#[cfg(test)]
fn serialize_empty_h1_request(request: &Request<ProxyBody>) -> anyhow::Result<Vec<u8>> {
  use http::header::TRANSFER_ENCODING;

  if !request.body().is_end_stream() {
    anyhow::bail!("Compio direct-H1 only supports prevalidated empty request bodies");
  }
  if request.headers().contains_key(TRANSFER_ENCODING) {
    anyhow::bail!("Compio direct-H1 does not serialize transfer-encoded request bodies");
  }
  let mut bytes = Vec::with_capacity(512 + request.headers().len() * 48);
  bytes.extend_from_slice(request.method().as_str().as_bytes());
  bytes.push(b' ');
  let target = request
    .uri()
    .path_and_query()
    .map(|target| target.as_str())
    .unwrap_or("/");
  bytes.extend_from_slice(target.as_bytes());
  bytes.extend_from_slice(b" HTTP/1.1\r\n");
  for (name, value) in request.headers() {
    bytes.extend_from_slice(name.as_str().as_bytes());
    bytes.extend_from_slice(b": ");
    bytes.extend_from_slice(value.as_bytes());
    bytes.extend_from_slice(b"\r\n");
  }
  bytes.extend_from_slice(b"\r\n");
  Ok(bytes)
}

#[cfg(test)]
fn next_read_capacity(engine: &ResponseProtocolEngine, pending_len: usize) -> usize {
  let limits = engine.limits();
  match engine.state() {
    ResponseState::ReadingHead
    | ResponseState::ProcessingInterim
    | ResponseState::WaitingForFinalHead => limits
      .max_response_head_bytes
      .saturating_sub(pending_len)
      .max(1),
    ResponseState::ChunkSizeLine => limits
      .max_chunk_size_line_bytes
      .saturating_add(2)
      .saturating_sub(pending_len)
      .max(1),
    ResponseState::ChunkTerminator => 2usize.saturating_sub(pending_len).max(1),
    ResponseState::Trailers => limits
      .max_trailer_block_bytes
      .saturating_sub(pending_len)
      .max(1),
    ResponseState::FixedLength { remaining } | ResponseState::ChunkData { remaining } => {
      usize::try_from(remaining)
        .unwrap_or(usize::MAX)
        .clamp(1, 16 * 1024)
    }
    ResponseState::CloseDelimited => 16 * 1024,
    ResponseState::Completed | ResponseState::FailedNonReusable => 1,
  }
}
