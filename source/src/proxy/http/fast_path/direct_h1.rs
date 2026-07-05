//! Direct upstream HTTP/1.1 transport for the plain-proxy fast path.
//! It bypasses the legacy pooled client only for tightly guarded H1 requests.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use http::header::CONNECTION;
use http::{HeaderMap, Method, Request, Response};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::{HttpVersion, ProxyProtocolEgressMode, RuntimeDirectH1IoMode, UpstreamConfig};
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{
  DirectH1PoolEvent, FastPathMetricProtocol, FastPathTransportMissReason,
};
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{BoxError, ProxyBody};

use super::stage_timing as timing;

#[cfg(target_os = "linux")]
mod compio_transport;
mod origin;
mod request;
mod runtime_backend;
mod send_attempt;
use self::origin::DirectH1Origin;
use self::request::PreparedDirectH1Request;
pub(super) use self::request::mark_prevalidated_direct_h1_request;
#[cfg(test)]
use self::request::{PrevalidatedDirectH1Request, empty_body};
use self::runtime_backend::DirectH1RuntimeBackend;
use self::send_attempt::{DirectH1SendAttemptError, send_request_with_timing};

const DIRECT_H1_MAX_SHARDS: usize = 16;
#[derive(Clone, Default)]
pub(crate) struct DirectH1Pools {
  pools: Vec<Option<Arc<DirectH1Pool>>>,
}

impl DirectH1Pools {
  pub(crate) fn new(upstreams: &[UpstreamConfig]) -> Self {
    Self {
      pools: upstreams
        .iter()
        .map(|upstream| DirectH1Pool::new(upstream).map(Arc::new))
        .collect(),
    }
  }

  fn for_upstream_index(&self, upstream_index: usize) -> Option<Arc<DirectH1Pool>> {
    self
      .pools
      .get(upstream_index)
      .and_then(|pool| pool.as_ref())
      .cloned()
  }
}

struct DirectH1Pool {
  origin: DirectH1Origin,
  connect_timeout: Duration,
  idle_timeout: Duration,
  max_idle: usize,
  idle_count: AtomicUsize,
  next_shard: AtomicUsize,
  idle_shards: Vec<Mutex<Vec<DirectH1IdleConnection>>>,
}

struct DirectH1TakeSender {
  sender: Option<SendRequest<ProxyBody>>,
  stale_pruned: usize,
  miss_reason: DirectH1TakeMissReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectH1TakeMissReason {
  None,
  Empty,
  Locked,
}

enum DirectH1PutError {
  Full,
  Locked,
}

impl DirectH1Pool {
  fn new(upstream: &UpstreamConfig) -> Option<Self> {
    let origin = DirectH1Origin::from_url(&upstream.origin)?;
    let max_idle = upstream.pool_max_idle_per_host;
    let shard_count = max_idle.clamp(1, DIRECT_H1_MAX_SHARDS);
    Some(Self {
      origin,
      connect_timeout: Duration::from_millis(upstream.connect_timeout_ms),
      idle_timeout: Duration::from_millis(upstream.idle_timeout_ms),
      max_idle,
      idle_count: AtomicUsize::new(0),
      next_shard: AtomicUsize::new(0),
      idle_shards: (0..shard_count).map(|_| Mutex::new(Vec::new())).collect(),
    })
  }

  fn take_sender(&self) -> DirectH1TakeSender {
    let idle_count = self.idle_count.load(Ordering::Acquire);
    if self.max_idle == 0 || idle_count == 0 {
      return DirectH1TakeSender {
        sender: None,
        stale_pruned: 0,
        miss_reason: DirectH1TakeMissReason::Empty,
      };
    }

    let now = Instant::now();
    let mut stale_pruned = 0;
    let mut locked_shards = 0;
    let start = self.next_shard.fetch_add(1, Ordering::Relaxed);
    let shard_count = self.idle_shards.len();
    for offset in 0..shard_count {
      let shard_index = (start + offset) % self.idle_shards.len();
      let Ok(mut idle) = self.idle_shards[shard_index].try_lock() else {
        locked_shards += 1;
        continue;
      };
      while let Some(connection) = idle.pop() {
        self.idle_count.fetch_sub(1, Ordering::AcqRel);
        if now.duration_since(connection.idle_since) <= self.idle_timeout {
          return DirectH1TakeSender {
            sender: Some(connection.sender),
            stale_pruned,
            miss_reason: DirectH1TakeMissReason::None,
          };
        }
        stale_pruned += 1;
      }
    }
    let miss_reason = if locked_shards > 0 && self.idle_count.load(Ordering::Acquire) > 0 {
      DirectH1TakeMissReason::Locked
    } else {
      DirectH1TakeMissReason::Empty
    };
    DirectH1TakeSender {
      sender: None,
      stale_pruned,
      miss_reason,
    }
  }

  fn put_sender(&self, sender: SendRequest<ProxyBody>) -> Result<(), DirectH1PutError> {
    if self.max_idle == 0 {
      return Err(DirectH1PutError::Full);
    }
    let idle_count = self.idle_count.load(Ordering::Acquire);
    if idle_count >= self.max_idle {
      return Err(DirectH1PutError::Full);
    }

    let start = self.next_shard.fetch_add(1, Ordering::Relaxed);
    let shard_count = self.idle_shards.len();
    let Some(mut idle) = (0..shard_count).find_map(|offset| {
      let shard_index = (start + offset) % self.idle_shards.len();
      self.idle_shards[shard_index].try_lock().ok()
    }) else {
      return Err(DirectH1PutError::Locked);
    };

    let mut observed = self.idle_count.load(Ordering::Acquire);
    loop {
      if observed >= self.max_idle {
        return Err(DirectH1PutError::Full);
      }
      match self.idle_count.compare_exchange_weak(
        observed,
        observed + 1,
        Ordering::AcqRel,
        Ordering::Acquire,
      ) {
        Ok(_) => break,
        Err(current) => observed = current,
      }
    }

    idle.push(DirectH1IdleConnection {
      sender,
      idle_since: Instant::now(),
    });
    Ok(())
  }
}

struct DirectH1IdleConnection {
  sender: SendRequest<ProxyBody>,
  idle_since: Instant,
}

pub(super) enum DirectH1SendResult {
  Fallback(Request<ProxyBody>),
  Sent(Result<DirectH1Response, anyhow::Error>),
}

#[derive(Clone, Copy)]
struct DirectH1SendMetricOptions {
  hot_path_metrics: bool,
  diagnostic_metrics: bool,
  timing_enabled: bool,
}

pub(super) struct DirectH1Response {
  pub(super) response: Response<ProxyBody>,
  lease: Option<DirectH1Lease>,
}

impl DirectH1Response {
  pub(super) fn take_lease(&mut self) -> Option<DirectH1Lease> {
    self.lease.take()
  }
}

pub(super) struct DirectH1Lease {
  pool: Arc<DirectH1Pool>,
  metrics: Arc<Metrics>,
  sender: SendRequest<ProxyBody>,
  diagnostic_metrics: bool,
  reusable_by_headers: bool,
}

impl DirectH1Lease {
  pub(super) fn recycle_if_reusable(self, body_consumed: bool) {
    if body_consumed && self.reusable_by_headers {
      if let Err(error) = self.pool.put_sender(self.sender)
        && self.diagnostic_metrics
      {
        self
          .metrics
          .record_direct_h1_pool_event_id(DirectH1PoolEvent::Drop);
        match error {
          DirectH1PutError::Full => self
            .metrics
            .record_direct_h1_pool_event_id(DirectH1PoolEvent::DropFull),
          DirectH1PutError::Locked => self
            .metrics
            .record_direct_h1_pool_event_id(DirectH1PoolEvent::DropLocked),
        }
      }
    } else if self.diagnostic_metrics {
      self
        .metrics
        .record_direct_h1_pool_event_id(DirectH1PoolEvent::Drop);
    }
  }
}

pub(super) fn recycle_response_body(
  body: ProxyBody,
  lease: DirectH1Lease,
  body_consumed: bool,
) -> ProxyBody {
  if body_consumed {
    lease.recycle_if_reusable(true);
    return body;
  }
  recycle_body_on_eof(body, lease)
}

fn recycle_body_on_eof(body: ProxyBody, lease: DirectH1Lease) -> ProxyBody {
  DirectH1RecycleBody {
    body,
    lease: Some(lease),
  }
  .boxed()
}

struct DirectH1RecycleBody {
  body: ProxyBody,
  lease: Option<DirectH1Lease>,
}

impl DirectH1RecycleBody {
  fn recycle(&mut self, body_consumed: bool) {
    if let Some(lease) = self.lease.take() {
      lease.recycle_if_reusable(body_consumed);
    }
  }
}

impl Body for DirectH1RecycleBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match Pin::new(&mut self.body).poll_frame(cx) {
      Poll::Ready(None) => {
        self.recycle(true);
        Poll::Ready(None)
      }
      Poll::Ready(Some(Err(error))) => {
        self.recycle(false);
        Poll::Ready(Some(Err(error)))
      }
      poll => poll,
    }
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> hyper::body::SizeHint {
    self.body.size_hint()
  }
}

impl Drop for DirectH1RecycleBody {
  fn drop(&mut self) {
    self.recycle(false);
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn try_send_direct_h1(
  pools: &DirectH1Pools,
  metrics: &Arc<Metrics>,
  upstream_index: usize,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_proven_empty: bool,
  retry_policy_enabled: bool,
  direct_h1_io_mode: RuntimeDirectH1IoMode,
  outbound: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
  hot_path_metrics: bool,
  diagnostic_metrics: bool,
  timing_enabled: bool,
) -> DirectH1SendResult {
  let protocol = fast_path_metric_protocol(request_version);
  if let Some(reason) = direct_h1_guard_miss(
    upstream,
    upstream_version,
    request_version,
    direct_selection_used,
    request_body_proven_empty,
    retry_policy_enabled,
    &outbound,
  ) {
    if hot_path_metrics {
      metrics.record_direct_h1_transport_miss_id(protocol, reason);
    }
    return DirectH1SendResult::Fallback(outbound);
  }

  let Some(pool) = pools.for_upstream_index(upstream_index) else {
    if hot_path_metrics {
      metrics.record_direct_h1_transport_miss_id(
        protocol,
        FastPathTransportMissReason::UnsupportedUpstream,
      );
    }
    return DirectH1SendResult::Fallback(outbound);
  };

  let prepared = match PreparedDirectH1Request::from_request(outbound, &pool.origin) {
    Ok(prepared) => prepared,
    Err(error) => {
      if hot_path_metrics {
        metrics.record_direct_h1_transport_miss_id(
          protocol,
          FastPathTransportMissReason::UnsupportedRequest,
        );
      }
      return DirectH1SendResult::Sent(Err(error));
    }
  };

  let result = send_prepared_request(
    pool,
    metrics,
    protocol,
    prepared,
    timeouts,
    DirectH1RuntimeBackend::from_config(direct_h1_io_mode),
    DirectH1SendMetricOptions {
      hot_path_metrics,
      diagnostic_metrics,
      timing_enabled,
    },
  )
  .await;
  if hot_path_metrics {
    match &result {
      Ok(_) => {
        metrics.record_direct_h1_transport_hit_id(protocol);
        metrics.record_fast_path_selection("direct_h1", protocol.as_str(), "selected", "used");
      }
      Err(error) if error.to_string().contains("timed out") => {
        metrics
          .record_direct_h1_transport_miss_id(protocol, FastPathTransportMissReason::ConnectError);
      }
      Err(_) => {
        metrics
          .record_direct_h1_transport_miss_id(protocol, FastPathTransportMissReason::SendError);
      }
    }
  }
  DirectH1SendResult::Sent(result)
}

fn direct_h1_guard_miss(
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_proven_empty: bool,
  retry_policy_enabled: bool,
  outbound: &Request<ProxyBody>,
) -> Option<FastPathTransportMissReason> {
  if !matches!(
    request_version,
    http::Version::HTTP_11 | http::Version::HTTP_2 | http::Version::HTTP_3
  ) || !direct_selection_used
  {
    return Some(FastPathTransportMissReason::UnsupportedRequest);
  }
  let request_body_streaming = !outbound.body().is_end_stream();
  if !matches!(outbound.method(), &Method::GET | &Method::HEAD) && !request_body_streaming {
    return Some(FastPathTransportMissReason::UnsupportedRequest);
  }
  if upstream_version != HttpVersion::H1
    || upstream.origin.scheme() != "http"
    || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return Some(FastPathTransportMissReason::UnsupportedUpstream);
  }
  if request_body_streaming {
    if request_body_proven_empty || retry_policy_enabled {
      return Some(FastPathTransportMissReason::RequestBody);
    }
    return None;
  }
  if !request_body_proven_empty {
    return Some(FastPathTransportMissReason::RequestBody);
  }
  None
}

async fn send_prepared_request(
  pool: Arc<DirectH1Pool>,
  metrics: &Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  prepared: PreparedDirectH1Request,
  timeouts: EffectiveTimeouts,
  runtime_backend: DirectH1RuntimeBackend,
  metric_options: DirectH1SendMetricOptions,
) -> anyhow::Result<DirectH1Response> {
  if metric_options.hot_path_metrics {
    metrics.record_http_upstream_h1_http_primary_request();
  }
  let use_compio_transport = runtime_backend == DirectH1RuntimeBackend::Compio
    && compio_transport_eligible(protocol, &prepared);
  if metric_options.diagnostic_metrics {
    record_runtime_backend_selection(metrics, protocol, runtime_backend, use_compio_transport);
  }

  #[cfg(target_os = "linux")]
  if use_compio_transport {
    let result = compio_transport::send_prepared_request(
      pool,
      metrics.clone(),
      protocol,
      prepared,
      timeouts,
      metric_options,
    )
    .await;
    if result.is_err() && metric_options.diagnostic_metrics {
      runtime_backend.record_error(metrics, protocol);
    }
    return result;
  }

  #[cfg(not(target_os = "linux"))]
  if use_compio_transport {
    if metric_options.diagnostic_metrics {
      runtime_backend.record_error(metrics, protocol);
    }
    anyhow::bail!("runtime.direct_h1_io = \"compio\" is Linux-only");
  }

  let pool_take_started = timing::start(metric_options.timing_enabled);
  let reused_sender = pool.take_sender();
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_POOL_TAKE,
    true,
    pool_take_started,
  );
  if metric_options.diagnostic_metrics {
    record_stale_direct_h1_senders(metrics, reused_sender.stale_pruned);
  }
  let reused = reused_sender.sender.is_some();
  if metric_options.diagnostic_metrics {
    if reused {
      metrics.record_direct_h1_pool_event_id(DirectH1PoolEvent::Hit);
    } else {
      metrics.record_direct_h1_pool_event_id(DirectH1PoolEvent::Miss);
      match reused_sender.miss_reason {
        DirectH1TakeMissReason::None => {}
        DirectH1TakeMissReason::Empty => {
          metrics.record_direct_h1_pool_event_id(DirectH1PoolEvent::MissEmpty);
        }
        DirectH1TakeMissReason::Locked => {
          metrics.record_direct_h1_pool_event_id(DirectH1PoolEvent::MissLocked);
        }
      }
    }
  }
  let mut sender = match reused_sender.sender {
    Some(sender) => sender,
    None => {
      connect_sender(
        &pool,
        metrics,
        protocol,
        metric_options.hot_path_metrics,
        metric_options.timing_enabled,
      )
      .await?
    }
  };

  let mut retry = reused.then(|| prepared.retry_request()).flatten();
  let send_result = send_request_with_timing(
    &mut sender,
    prepared.into_request(),
    metrics,
    protocol,
    timeouts.upstream_first_byte,
    metric_options.timing_enabled,
  )
  .await;
  let response = match send_result {
    Ok(response) => response,
    Err(DirectH1SendAttemptError::Hyper(error)) if reused => {
      let Some(retry) = retry.take() else {
        return Err(error.into());
      };
      debug!(error = %error, "direct H1 upstream sender failed; reconnecting once");
      if metric_options.diagnostic_metrics {
        metrics.record_direct_h1_pool_event_id(DirectH1PoolEvent::Reconnect);
      }
      sender = connect_sender(
        &pool,
        metrics,
        protocol,
        metric_options.hot_path_metrics,
        metric_options.timing_enabled,
      )
      .await?;
      let retry_result = send_request_with_timing(
        &mut sender,
        retry.into_request(),
        metrics,
        protocol,
        timeouts.upstream_first_byte,
        metric_options.timing_enabled,
      )
      .await;
      match retry_result {
        Ok(response) => response,
        Err(DirectH1SendAttemptError::Hyper(error)) => return Err(error.into()),
        Err(DirectH1SendAttemptError::Timeout) => {
          anyhow::bail!("direct H1 upstream first-byte timed out");
        }
      }
    }
    Err(DirectH1SendAttemptError::Hyper(error)) => return Err(error.into()),
    Err(DirectH1SendAttemptError::Timeout) => {
      anyhow::bail!("direct H1 upstream first-byte timed out");
    }
  };

  let reusable_by_headers = h1_response_allows_reuse(response.headers());
  Ok(DirectH1Response {
    response: response.map(|body| {
      body
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed()
    }),
    lease: Some(DirectH1Lease {
      pool,
      metrics: metrics.clone(),
      sender,
      diagnostic_metrics: metric_options.diagnostic_metrics,
      reusable_by_headers,
    }),
  })
}

fn record_stale_direct_h1_senders(metrics: &Metrics, stale_pruned: usize) {
  for _ in 0..stale_pruned {
    metrics.record_direct_h1_pool_event_id(DirectH1PoolEvent::Stale);
  }
}

async fn connect_sender(
  pool: &Arc<DirectH1Pool>,
  metrics: &Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  hot_path_metrics: bool,
  timing_enabled: bool,
) -> anyhow::Result<SendRequest<ProxyBody>> {
  let connect_started = timing::start(timing_enabled);
  let result = connect_sender_inner(pool, metrics, hot_path_metrics).await;
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H1_CONNECT,
    result.is_ok(),
    connect_started,
  );
  result
}

async fn connect_sender_inner(
  pool: &Arc<DirectH1Pool>,
  metrics: &Arc<Metrics>,
  hot_path_metrics: bool,
) -> anyhow::Result<SendRequest<ProxyBody>> {
  if hot_path_metrics {
    metrics.record_http_upstream_h1_http_primary_pool_miss();
  }
  let stream = tokio::time::timeout(
    pool.connect_timeout,
    TcpStream::connect((pool.origin.host.as_str(), pool.origin.port)),
  )
  .await
  .context("direct H1 upstream connect timed out")?
  .with_context(|| {
    format!(
      "failed to connect direct H1 upstream {}:{}",
      pool.origin.host, pool.origin.port
    )
  })?;
  stream
    .set_nodelay(true)
    .context("failed to enable TCP_NODELAY for direct H1 upstream")?;
  let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
    .await
    .context("failed to establish direct H1 upstream connection")?;
  if hot_path_metrics {
    metrics.record_http_upstream_h1_http_primary_connection_created();
  }
  tokio::spawn(async move {
    if let Err(error) = connection.await {
      warn!(error = %error, "direct H1 upstream connection closed with error");
    }
  });
  Ok(sender)
}

fn compio_transport_eligible(
  protocol: FastPathMetricProtocol,
  prepared: &PreparedDirectH1Request,
) -> bool {
  protocol == FastPathMetricProtocol::H1 && prepared.compio_empty_body_wire_eligible()
}

fn record_runtime_backend_selection(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  runtime_backend: DirectH1RuntimeBackend,
  use_compio_transport: bool,
) {
  match runtime_backend {
    DirectH1RuntimeBackend::TokioHyper => runtime_backend.record_selected(metrics, protocol),
    DirectH1RuntimeBackend::Compio if use_compio_transport => {
      runtime_backend.record_selected(metrics, protocol);
    }
    DirectH1RuntimeBackend::Compio => {
      runtime_backend.record_fallback(metrics, protocol);
      DirectH1RuntimeBackend::TokioHyper.record_selected(metrics, protocol);
    }
  }
}

fn h1_response_allows_reuse(headers: &HeaderMap) -> bool {
  !connection_header_contains(headers, "close")
}

fn connection_header_contains(headers: &HeaderMap, token: &str) -> bool {
  headers.get_all(CONNECTION).iter().any(|value| {
    value
      .as_bytes()
      .split(|byte| *byte == b',')
      .filter_map(|part| std::str::from_utf8(part).ok())
      .any(|part| part.trim().eq_ignore_ascii_case(token))
  })
}

fn fast_path_metric_protocol(version: http::Version) -> FastPathMetricProtocol {
  match version {
    http::Version::HTTP_10 | http::Version::HTTP_11 => FastPathMetricProtocol::H1,
    http::Version::HTTP_2 => FastPathMetricProtocol::H2,
    http::Version::HTTP_3 => FastPathMetricProtocol::H3,
    _ => FastPathMetricProtocol::Other,
  }
}

#[cfg(test)]
mod tests;
