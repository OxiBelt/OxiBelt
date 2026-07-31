//! Direct upstream HTTP/1.1 transport for the plain-proxy fast path.
//! It bypasses the legacy pooled client only for tightly guarded H1 requests.

#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
#[cfg(target_os = "linux")]
use arc_swap::ArcSwapOption;
use http::header::CONNECTION;
use http::{HeaderMap, Method, Request};
use http_body_util::BodyExt;
use hyper::body::Body;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::circuit_breakers::CircuitBreakerRuntime;
#[cfg(target_os = "linux")]
use crate::circuit_breakers::{AdmissionRejection, AdmissionRejectionReason};
use crate::config::{
  EarlyHintsMode, HttpVersion, ProxyProtocolEgressMode, RuntimeDirectH1IoMode, UpstreamConfig,
};
use crate::metrics::Metrics;
#[cfg(target_os = "linux")]
use crate::metrics::compio_direct_h1::CompioDirectH1DispatchOutcome;
use crate::metrics::fast_path::labels::{
  DirectH1PoolEvent, FastPathMetricProtocol, FastPathTransportMissReason,
};
use crate::overload::{OverloadRuntime, WorkKind};
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{BoxError, ProxyBody};
use crate::proxy::http::headers::is_upgrade_request;

use super::request_body::FastPathRequestBodyMode;
use super::stage_timing as timing;

#[cfg(target_os = "linux")]
mod compio_service;
#[cfg(not(target_os = "linux"))]
#[path = "direct_h1/compio_service_portable.rs"]
mod compio_service;
#[cfg(target_os = "linux")]
mod compio_transport;
#[cfg(test)]
pub(crate) mod delimiters;
mod origin;
mod request;
mod response;
pub(crate) mod response_protocol;
mod runtime_backend;
mod send_attempt;
mod transport_error;
#[cfg(target_os = "linux")]
use self::compio_service::CompioDirectH1PredispatchReason;
pub(crate) use self::compio_service::{
  CompioDirectH1Service, CompioDirectH1ServicePlan, CompioDirectH1ShutdownSummary,
  CompioDirectH1Staged,
};
use self::origin::DirectH1Origin;
use self::request::PreparedDirectH1Request;
pub(super) use self::request::mark_prevalidated_direct_h1_request;
#[cfg(test)]
use self::request::{PrevalidatedDirectH1Request, empty_body};
use self::response::DirectH1Response;
pub(super) use self::response::{DirectH1Lease, recycle_response_body};
use self::runtime_backend::DirectH1RuntimeBackend;
use self::send_attempt::{DirectH1SendAttemptError, send_request_with_timing};
pub(super) use self::transport_error::direct_h1_upstream_error_response;
use self::transport_error::{DirectH1TransportError, direct_h1_transport_miss_reason};
#[cfg(test)]
pub(super) use self::transport_error::{DirectH1UpstreamErrorKind, direct_h1_upstream_error_kind};

const DIRECT_H1_MAX_SHARDS: usize = 16;
#[cfg(target_os = "linux")]
const COMPIO_CONNECT_ERROR_BACKOFF: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const COMPIO_RESOLUTION_CACHE_TTL: Duration = Duration::from_secs(30);
#[derive(Clone, Default)]
pub(crate) struct DirectH1Pools {
  pools: Vec<Option<Arc<DirectH1Pool>>>,
}

impl DirectH1Pools {
  pub(crate) fn new(
    upstreams: &[UpstreamConfig],
    circuit_breakers: Arc<CircuitBreakerRuntime>,
  ) -> Self {
    Self {
      pools: upstreams
        .iter()
        .map(|upstream| {
          DirectH1Pool::new_with_circuit_breakers(upstream, Some(circuit_breakers.clone()))
            .map(Arc::new)
        })
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
  max_lifetime: Duration,
  max_idle: usize,
  idle_count: AtomicUsize,
  next_shard: AtomicUsize,
  idle_shards: Vec<Mutex<Vec<DirectH1IdleConnection>>>,
  compio_connect_backoff_until: Mutex<Option<Instant>>,
  #[cfg(target_os = "linux")]
  compio_resolution: ArcSwapOption<CompioDirectH1Resolution>,
  #[cfg(target_os = "linux")]
  compio_resolution_gate: tokio::sync::Semaphore,
  circuit_breakers: Option<Arc<CircuitBreakerRuntime>>,
}

#[cfg(target_os = "linux")]
struct CompioDirectH1Resolution {
  expires_at: Instant,
  addresses: Arc<[SocketAddr]>,
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
  #[cfg(test)]
  fn new(upstream: &UpstreamConfig) -> Option<Self> {
    Self::new_with_circuit_breakers(upstream, None)
  }

  fn new_with_circuit_breakers(
    upstream: &UpstreamConfig,
    circuit_breakers: Option<Arc<CircuitBreakerRuntime>>,
  ) -> Option<Self> {
    let origin = DirectH1Origin::from_url(&upstream.origin)?;
    let max_idle = upstream.pool_max_idle_per_host;
    let shard_count = max_idle.clamp(1, DIRECT_H1_MAX_SHARDS);
    Some(Self {
      origin,
      connect_timeout: Duration::from_millis(upstream.connect_timeout_ms),
      idle_timeout: Duration::from_millis(upstream.idle_timeout_ms),
      max_lifetime: Duration::from_millis(upstream.max_lifetime_ms),
      max_idle,
      idle_count: AtomicUsize::new(0),
      next_shard: AtomicUsize::new(0),
      idle_shards: (0..shard_count).map(|_| Mutex::new(Vec::new())).collect(),
      compio_connect_backoff_until: Mutex::new(None),
      #[cfg(target_os = "linux")]
      compio_resolution: ArcSwapOption::empty(),
      #[cfg(target_os = "linux")]
      compio_resolution_gate: tokio::sync::Semaphore::new(1),
      circuit_breakers,
    })
  }

  fn compio_connect_backoff_active(&self) -> bool {
    let now = Instant::now();
    let Ok(mut backoff_until) = self.compio_connect_backoff_until.lock() else {
      return true;
    };
    if let Some(until) = *backoff_until {
      if now < until {
        return true;
      }
      *backoff_until = None;
    }
    false
  }

  #[cfg(target_os = "linux")]
  fn compio_worker_shard(&self, worker_count: usize) -> usize {
    debug_assert!(worker_count > 0);
    let origin_shard = self.origin.worker_shard(worker_count);
    let sequence = self.next_shard.fetch_add(1, Ordering::Relaxed);
    origin_shard.wrapping_add(sequence) % worker_count
  }

  #[cfg(target_os = "linux")]
  fn note_compio_connect_error(&self) {
    if let Ok(mut backoff_until) = self.compio_connect_backoff_until.lock() {
      *backoff_until = Some(Instant::now() + COMPIO_CONNECT_ERROR_BACKOFF);
    }
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn try_send_direct_h1(
  pools: &DirectH1Pools,
  compio_service: Option<&Arc<CompioDirectH1Service>>,
  metrics: &Arc<Metrics>,
  upstream_index: usize,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_mode: FastPathRequestBodyMode,
  retry_policy_enabled: bool,
  allow_reconnect_retry: bool,
  overload: Option<Arc<OverloadRuntime>>,
  direct_h1_io_mode: RuntimeDirectH1IoMode,
  early_hints_mode: EarlyHintsMode,
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
    request_body_mode,
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
    compio_service,
    metrics,
    protocol,
    prepared,
    timeouts,
    DirectH1RuntimeBackend::from_config(direct_h1_io_mode),
    allow_reconnect_retry,
    overload,
    early_hints_mode,
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
      Err(error) => {
        metrics
          .record_direct_h1_transport_miss_id(protocol, direct_h1_transport_miss_reason(error));
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
  request_body_mode: FastPathRequestBodyMode,
  retry_policy_enabled: bool,
  outbound: &Request<ProxyBody>,
) -> Option<FastPathTransportMissReason> {
  if !matches!(
    request_version,
    http::Version::HTTP_11 | http::Version::HTTP_2 | http::Version::HTTP_3
  ) || !direct_selection_used
    || is_upgrade_request(outbound)
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
    if request_body_mode == FastPathRequestBodyMode::Empty || retry_policy_enabled {
      return Some(FastPathTransportMissReason::RequestBody);
    }
    return None;
  }
  if request_body_mode != FastPathRequestBodyMode::Empty {
    return Some(FastPathTransportMissReason::RequestBody);
  }
  None
}

#[allow(clippy::too_many_arguments)]
async fn send_prepared_request(
  pool: Arc<DirectH1Pool>,
  compio_service: Option<&Arc<CompioDirectH1Service>>,
  metrics: &Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  prepared: PreparedDirectH1Request,
  timeouts: EffectiveTimeouts,
  runtime_backend: DirectH1RuntimeBackend,
  allow_reconnect_retry: bool,
  overload: Option<Arc<OverloadRuntime>>,
  early_hints_mode: EarlyHintsMode,
  metric_options: DirectH1SendMetricOptions,
) -> anyhow::Result<DirectH1Response> {
  if metric_options.hot_path_metrics {
    metrics.record_http_upstream_h1_http_primary_request();
  }
  let use_compio_transport = runtime_backend == DirectH1RuntimeBackend::Compio
    && compio_transport_eligible(protocol, &prepared)
    && !pool.compio_connect_backoff_active()
    && compio_service.is_some();
  if metric_options.diagnostic_metrics {
    record_runtime_backend_selection(metrics, protocol, runtime_backend, use_compio_transport);
  }
  #[cfg(target_os = "linux")]
  if runtime_backend == DirectH1RuntimeBackend::Compio && !use_compio_transport {
    metrics.record_compio_direct_h1_dispatch(CompioDirectH1DispatchOutcome::PredispatchFallback);
  }

  #[cfg(target_os = "linux")]
  if use_compio_transport {
    let Some(compio_service) = compio_service else {
      unreachable!("Compio service presence is part of transport eligibility");
    };
    let result = compio_transport::send_prepared_request(
      compio_service,
      pool.clone(),
      metrics.clone(),
      protocol,
      prepared,
      timeouts,
      early_hints_mode,
      metric_options,
    )
    .await;
    match result {
      compio_transport::CompioDirectH1SendResult::NotSubmitted {
        prepared,
        reason,
        source,
      } => {
        if !compio_predispatch_allows_hyper_fallback(reason) {
          metrics
            .record_compio_direct_h1_dispatch(CompioDirectH1DispatchOutcome::PredispatchRejection);
          if metric_options.diagnostic_metrics {
            runtime_backend.record_error(metrics, protocol);
          }
          let source = compio_predispatch_rejection_source(pool.as_ref(), reason, source);
          debug!(
            error = %source,
            ?reason,
            "Compio direct H1 was rejected before dispatch; suppressing upstream fallback"
          );
          return Err(source);
        }
        metrics
          .record_compio_direct_h1_dispatch(CompioDirectH1DispatchOutcome::PredispatchFallback);
        if matches!(
          reason,
          CompioDirectH1PredispatchReason::Resolve | CompioDirectH1PredispatchReason::Connect
        ) {
          pool.note_compio_connect_error();
        }
        if metric_options.diagnostic_metrics {
          runtime_backend.record_fallback(metrics, protocol);
          DirectH1RuntimeBackend::TokioHyper.record_selected(metrics, protocol);
        }
        if let Some(source) = source.as_ref() {
          debug!(
            error = %source,
            ?reason,
            "Compio direct H1 did not submit upstream bytes; falling back to Hyper direct H1"
          );
        }
        return send_prepared_request_hyper(
          pool,
          metrics,
          protocol,
          *prepared,
          timeouts,
          allow_reconnect_retry,
          overload,
          metric_options,
        )
        .await;
      }
      compio_transport::CompioDirectH1SendResult::Sent {
        result,
        visibility,
        bytes_written,
      } => {
        if result.is_err() {
          metrics
            .record_compio_direct_h1_dispatch(CompioDirectH1DispatchOutcome::PostdispatchFailure);
          if metric_options.diagnostic_metrics {
            runtime_backend.record_error(metrics, protocol);
          }
          debug!(
            ?visibility,
            bytes_written, "Compio direct H1 failed after the no-fallback boundary"
          );
        }
        return result;
      }
    }
  }

  #[cfg(not(target_os = "linux"))]
  if use_compio_transport {
    if metric_options.diagnostic_metrics {
      runtime_backend.record_error(metrics, protocol);
    }
    anyhow::bail!("runtime.direct_h1_io = \"compio\" is Linux-only");
  }

  send_prepared_request_hyper(
    pool,
    metrics,
    protocol,
    prepared,
    timeouts,
    allow_reconnect_retry,
    overload,
    metric_options,
  )
  .await
}

#[cfg(target_os = "linux")]
fn compio_predispatch_allows_hyper_fallback(reason: CompioDirectH1PredispatchReason) -> bool {
  match reason {
    CompioDirectH1PredispatchReason::Unhealthy
    | CompioDirectH1PredispatchReason::Draining
    | CompioDirectH1PredispatchReason::Resolve
    | CompioDirectH1PredispatchReason::Connect => true,
    CompioDirectH1PredispatchReason::QueueFull
    | CompioDirectH1PredispatchReason::ConnectionLimit
    | CompioDirectH1PredispatchReason::Cancelled => false,
  }
}

#[cfg(target_os = "linux")]
fn compio_predispatch_rejection_source(
  pool: &DirectH1Pool,
  reason: CompioDirectH1PredispatchReason,
  source: Option<anyhow::Error>,
) -> anyhow::Error {
  if let Some(source) = source {
    return source;
  }

  let retry_after = pool
    .circuit_breakers
    .as_ref()
    .map_or(Duration::ZERO, |runtime| runtime.capacity_retry_after());
  match reason {
    CompioDirectH1PredispatchReason::QueueFull => anyhow::Error::new(AdmissionRejection {
      reason: AdmissionRejectionReason::QueueFull,
      retry_after,
    }),
    CompioDirectH1PredispatchReason::ConnectionLimit => anyhow::Error::new(AdmissionRejection {
      reason: AdmissionRejectionReason::ActiveLimit,
      retry_after,
    }),
    CompioDirectH1PredispatchReason::Cancelled => {
      anyhow::anyhow!("Compio direct-H1 operation was cancelled before dispatch")
    }
    CompioDirectH1PredispatchReason::Unhealthy
    | CompioDirectH1PredispatchReason::Draining
    | CompioDirectH1PredispatchReason::Resolve
    | CompioDirectH1PredispatchReason::Connect => {
      anyhow::anyhow!("Compio direct-H1 fallback reason {reason:?} reached the rejection path")
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn send_prepared_request_hyper(
  pool: Arc<DirectH1Pool>,
  metrics: &Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  prepared: PreparedDirectH1Request,
  timeouts: EffectiveTimeouts,
  allow_reconnect_retry: bool,
  overload: Option<Arc<OverloadRuntime>>,
  metric_options: DirectH1SendMetricOptions,
) -> anyhow::Result<DirectH1Response> {
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

  let mut retry = (allow_reconnect_retry && reused)
    .then(|| prepared.retry_request())
    .flatten();
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
      if overload.as_ref().is_some_and(|runtime| {
        runtime.retries_disabled() || runtime.retry_budget_multiplier() < 1.0
      }) {
        return Err(error.into());
      }
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
      let _retry = overload
        .as_ref()
        .map(|runtime| runtime.lease(WorkKind::RetryConcurrency, 1));
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
    TcpStream::connect((pool.origin.host.as_ref(), pool.origin.port)),
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
  matches!(
    protocol,
    FastPathMetricProtocol::H1 | FastPathMetricProtocol::H2 | FastPathMetricProtocol::H3
  ) && prepared.compio_empty_body_wire_eligible()
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
