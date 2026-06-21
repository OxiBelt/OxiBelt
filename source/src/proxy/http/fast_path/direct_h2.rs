//! Direct upstream HTTP/2 transport for the plain-proxy fast path.
//! It is limited to direct empty-body safe requests and falls back for all broader semantics.

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use http::{Method, Request, Response};
use hyper::body::{Body, Incoming};
use hyper::client::conn::http2::SendRequest;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tracing::debug;

use crate::config::{HttpVersion, ProxyHttp2Config, ProxyProtocolEgressMode, UpstreamConfig};
use crate::metrics::Metrics;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{self, ProxyBody};
use crate::tls::{OutboundRevocationRuntime, TlsResumptionState};

mod connection;
mod request;

use self::connection::{
  DirectH2Origin, build_h2_tls_config, connect_tls_h2, h2_handshake_with_timeout,
};
use self::request::PreparedDirectH2Request;
#[cfg(test)]
use self::request::empty_body;
use super::helpers::fast_path_metric_protocol;

const DIRECT_H2_MAX_SLOTS: usize = 16;
const DIRECT_H2_STREAMS_PER_SLOT_SOFT_LIMIT: usize = 32;

#[derive(Clone, Default)]
pub(crate) struct DirectH2Pools {
  pools: Vec<Option<Arc<DirectH2Pool>>>,
}

impl DirectH2Pools {
  pub(crate) fn new(
    upstreams: &[UpstreamConfig],
    extra_root_certs: &[PathBuf],
    tls_resumption: &TlsResumptionState,
    http2_config: &ProxyHttp2Config,
    outbound_revocation: &OutboundRevocationRuntime,
  ) -> anyhow::Result<Self> {
    let mut pools = Vec::with_capacity(upstreams.len());
    for upstream in upstreams {
      pools.push(
        DirectH2Pool::new(
          upstream,
          extra_root_certs,
          tls_resumption,
          http2_config,
          outbound_revocation,
        )
        .transpose()
        .with_context(|| format!("failed to build direct H2 pool for {}", upstream.name))?
        .map(Arc::new),
      );
    }
    Ok(Self { pools })
  }

  fn for_upstream_index(&self, upstream_index: usize) -> Option<Arc<DirectH2Pool>> {
    self
      .pools
      .get(upstream_index)
      .and_then(|pool| pool.as_ref())
      .cloned()
  }
}

struct DirectH2Pool {
  origin: DirectH2Origin,
  connect_timeout: Duration,
  idle_timeout: Duration,
  max_lifetime: Duration,
  target_streams_per_slot: usize,
  max_streams_per_slot: usize,
  http2_config: ProxyHttp2Config,
  tls_config: Option<Arc<rustls::ClientConfig>>,
  next_slot: AtomicUsize,
  slots: Vec<DirectH2Slot>,
}

struct DirectH2Slot {
  connection: AsyncMutex<Option<Arc<DirectH2Connection>>>,
}

struct DirectH2Connection {
  sender: SendRequest<ProxyBody>,
  created_at: Instant,
  last_used: Mutex<Instant>,
  active_streams: AtomicUsize,
}

struct DirectH2Sender {
  sender: SendRequest<ProxyBody>,
  lease: DirectH2Lease,
  reused: bool,
}

pub(super) struct DirectH2Response {
  pub(super) response: Response<Incoming>,
  lease: Option<DirectH2Lease>,
}

pub(super) struct DirectH2Lease {
  connection: Arc<DirectH2Connection>,
}

struct DirectH2TakeSender {
  sender: Option<DirectH2Sender>,
  empty_slot: Option<usize>,
  miss_reason: DirectH2TakeMissReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectH2TakeMissReason {
  None,
  Empty,
  Locked,
  Saturated,
}

impl DirectH2Slot {
  fn new() -> Self {
    Self {
      connection: AsyncMutex::new(None),
    }
  }
}

impl DirectH2Connection {
  fn stale(&self, idle_timeout: Duration, max_lifetime: Duration) -> bool {
    if self.active_streams.load(Ordering::Acquire) > 0 {
      return false;
    }
    if self.created_at.elapsed() > max_lifetime {
      return true;
    }
    let last_used = self
      .last_used
      .lock()
      .expect("direct H2 last-used lock poisoned");
    last_used.elapsed() > idle_timeout
  }

  fn reserve(
    connection: &Arc<Self>,
    max_streams_per_slot: usize,
  ) -> Option<(SendRequest<ProxyBody>, DirectH2Lease)> {
    let mut active = connection.active_streams.load(Ordering::Acquire);
    loop {
      if active >= max_streams_per_slot {
        return None;
      }
      match connection.active_streams.compare_exchange_weak(
        active,
        active + 1,
        Ordering::AcqRel,
        Ordering::Acquire,
      ) {
        Ok(_) => break,
        Err(current) => active = current,
      }
    }
    let mut last_used = connection
      .last_used
      .lock()
      .expect("direct H2 last-used lock poisoned");
    *last_used = Instant::now();
    Some((
      connection.sender.clone(),
      DirectH2Lease {
        connection: Arc::clone(connection),
      },
    ))
  }
}

impl DirectH2Response {
  pub(super) fn take_lease(&mut self) -> Option<DirectH2Lease> {
    self.lease.take()
  }
}

impl Drop for DirectH2Lease {
  fn drop(&mut self) {
    self
      .connection
      .active_streams
      .fetch_sub(1, Ordering::AcqRel);
  }
}

pub(super) enum DirectH2SendResult {
  Fallback(Request<ProxyBody>),
  Sent(Result<DirectH2Response, anyhow::Error>),
}

impl DirectH2Pool {
  fn new(
    upstream: &UpstreamConfig,
    extra_root_certs: &[PathBuf],
    tls_resumption: &TlsResumptionState,
    http2_config: &ProxyHttp2Config,
    outbound_revocation: &OutboundRevocationRuntime,
  ) -> Option<anyhow::Result<Self>> {
    let origin = DirectH2Origin::from_url(&upstream.origin)?;
    let tls_config = if origin.scheme == "https" {
      Some(build_h2_tls_config(
        upstream,
        extra_root_certs,
        tls_resumption,
        outbound_revocation,
      ))
    } else {
      None
    };
    if upstream.pool_max_idle_per_host == 0 {
      return None;
    }
    let slot_count = upstream.pool_max_idle_per_host.min(DIRECT_H2_MAX_SLOTS);
    let max_streams_per_slot = (http2_config.max_concurrent_streams as usize).max(1);
    let target_streams_per_slot =
      max_streams_per_slot.clamp(1, DIRECT_H2_STREAMS_PER_SLOT_SOFT_LIMIT);
    Some(tls_config.transpose().map(|tls_config| Self {
      origin,
      connect_timeout: Duration::from_millis(upstream.connect_timeout_ms),
      idle_timeout: Duration::from_millis(upstream.idle_timeout_ms),
      max_lifetime: Duration::from_millis(upstream.max_lifetime_ms),
      target_streams_per_slot,
      max_streams_per_slot,
      http2_config: *http2_config,
      tls_config,
      next_slot: AtomicUsize::new(0),
      slots: (0..slot_count).map(|_| DirectH2Slot::new()).collect(),
    }))
  }

  async fn sender(&self, metrics: &Arc<Metrics>) -> anyhow::Result<Option<DirectH2Sender>> {
    self
      .sender_with(metrics, || self.connect_sender(metrics))
      .await
  }

  async fn sender_with<F, Fut>(
    &self,
    metrics: &Arc<Metrics>,
    connect_sender: F,
  ) -> anyhow::Result<Option<DirectH2Sender>>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<SendRequest<ProxyBody>>>,
  {
    let reusable = self.take_reusable_sender(metrics);
    if let Some(sender) = reusable.sender {
      metrics.record_direct_h2_pool_event("hit");
      return Ok(Some(sender));
    }

    metrics.record_direct_h2_pool_event("miss");
    match reusable.miss_reason {
      DirectH2TakeMissReason::None => {}
      DirectH2TakeMissReason::Empty => metrics.record_direct_h2_pool_event("miss_empty"),
      DirectH2TakeMissReason::Locked => metrics.record_direct_h2_pool_event("miss_locked"),
      DirectH2TakeMissReason::Saturated => metrics.record_direct_h2_pool_event("miss_saturated"),
    }
    if reusable.miss_reason == DirectH2TakeMissReason::Saturated && reusable.empty_slot.is_none() {
      return Ok(None);
    }

    let slot_index = reusable
      .empty_slot
      .unwrap_or_else(|| self.next_slot.fetch_add(1, Ordering::Relaxed) % self.slots.len());
    self.connect_slot(metrics, slot_index, connect_sender).await
  }

  fn take_reusable_sender(&self, metrics: &Arc<Metrics>) -> DirectH2TakeSender {
    let start = self.next_slot.fetch_add(1, Ordering::Relaxed);
    let mut empty_slot = None;
    let mut locked_slots = 0;
    let mut saturated_slots = 0;
    let mut best_under_target: Option<(usize, Arc<DirectH2Connection>)> = None;
    let mut best_over_target: Option<(usize, Arc<DirectH2Connection>)> = None;
    for offset in 0..self.slots.len() {
      let slot_index = (start + offset) % self.slots.len();
      let Ok(mut connection) = self.slots[slot_index].connection.try_lock() else {
        locked_slots += 1;
        continue;
      };
      let Some(candidate) = connection.as_ref() else {
        empty_slot.get_or_insert(slot_index);
        continue;
      };
      if candidate.stale(self.idle_timeout, self.max_lifetime) {
        metrics.record_direct_h2_pool_event("stale");
        metrics.record_direct_h2_pool_event("drop");
        *connection = None;
        empty_slot.get_or_insert(slot_index);
        continue;
      }
      let active = candidate.active_streams.load(Ordering::Acquire);
      if active >= self.max_streams_per_slot {
        saturated_slots += 1;
        continue;
      }
      if active < self.target_streams_per_slot {
        if best_under_target
          .as_ref()
          .is_none_or(|(best_active, _)| active < *best_active)
        {
          best_under_target = Some((active, Arc::clone(candidate)));
        }
      } else if best_over_target
        .as_ref()
        .is_none_or(|(best_active, _)| active < *best_active)
      {
        best_over_target = Some((active, Arc::clone(candidate)));
      }
    }
    let best = best_under_target.or_else(|| empty_slot.is_none().then_some(best_over_target)?);
    if let Some((_, connection)) = best
      && let Some((sender, lease)) =
        DirectH2Connection::reserve(&connection, self.max_streams_per_slot)
    {
      return DirectH2TakeSender {
        sender: Some(DirectH2Sender {
          sender,
          lease,
          reused: true,
        }),
        empty_slot,
        miss_reason: DirectH2TakeMissReason::None,
      };
    }
    let miss_reason = if empty_slot.is_some() {
      DirectH2TakeMissReason::Empty
    } else if saturated_slots > 0 {
      DirectH2TakeMissReason::Saturated
    } else if locked_slots > 0 {
      DirectH2TakeMissReason::Locked
    } else {
      DirectH2TakeMissReason::Empty
    };
    DirectH2TakeSender {
      sender: None,
      empty_slot,
      miss_reason,
    }
  }

  async fn connect_slot<F, Fut>(
    &self,
    metrics: &Arc<Metrics>,
    slot_index: usize,
    connect_sender: F,
  ) -> anyhow::Result<Option<DirectH2Sender>>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<SendRequest<ProxyBody>>>,
  {
    let slot = &self.slots[slot_index % self.slots.len()];
    let mut slot_connection = slot.connection.lock().await;
    if let Some(candidate) = slot_connection.as_ref() {
      if candidate.stale(self.idle_timeout, self.max_lifetime) {
        metrics.record_direct_h2_pool_event("stale");
        metrics.record_direct_h2_pool_event("drop");
        *slot_connection = None;
      } else if let Some((sender, lease)) =
        DirectH2Connection::reserve(candidate, self.max_streams_per_slot)
      {
        metrics.record_direct_h2_pool_event("hit");
        return Ok(Some(DirectH2Sender {
          sender,
          lease,
          reused: true,
        }));
      } else {
        metrics.record_direct_h2_pool_event("miss_saturated");
        return Ok(None);
      }
    }

    metrics.record_http_upstream_client_pool_miss(
      self.metric_version(),
      self.origin.scheme,
      "primary",
    );
    metrics.record_direct_h2_pool_event("connect");
    let sender = match connect_sender().await {
      Ok(sender) => sender,
      Err(error) => {
        metrics.record_direct_h2_pool_event("connect_error");
        return Err(error);
      }
    };
    let connection = Arc::new(DirectH2Connection {
      sender: sender.clone(),
      created_at: Instant::now(),
      last_used: Mutex::new(Instant::now()),
      active_streams: AtomicUsize::new(1),
    });
    *slot_connection = Some(Arc::clone(&connection));
    Ok(Some(DirectH2Sender {
      sender,
      lease: DirectH2Lease { connection },
      reused: false,
    }))
  }

  async fn clear_connection(&self, target: &Arc<DirectH2Connection>) {
    for slot in &self.slots {
      let mut connection = slot.connection.lock().await;
      if connection
        .as_ref()
        .is_some_and(|candidate| Arc::ptr_eq(candidate, target))
      {
        *connection = None;
        return;
      }
    }
  }

  async fn connect_sender(&self, metrics: &Arc<Metrics>) -> anyhow::Result<SendRequest<ProxyBody>> {
    let stream = tokio::time::timeout(
      self.connect_timeout,
      TcpStream::connect((self.origin.host.as_str(), self.origin.port)),
    )
    .await
    .context("direct H2 upstream connect timed out")?
    .with_context(|| {
      format!(
        "failed to connect direct H2 upstream {}:{}",
        self.origin.host, self.origin.port
      )
    })?;
    stream
      .set_nodelay(true)
      .context("failed to enable TCP_NODELAY for direct H2 upstream")?;

    let sender = if let Some(tls_config) = &self.tls_config {
      connect_tls_h2(
        tls_config.clone(),
        self.origin.host.clone(),
        stream,
        &self.http2_config,
        self.connect_timeout,
      )
      .await?
    } else {
      h2_handshake_with_timeout(stream, &self.http2_config, self.connect_timeout).await?
    };

    metrics.record_http_upstream_client_connection_created(
      self.metric_version(),
      self.origin.scheme,
      "primary",
    );
    Ok(sender)
  }

  fn metric_version(&self) -> &'static str {
    if self.origin.scheme == "http" {
      "h2c"
    } else {
      "h2"
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn try_send_direct_h2(
  pools: &DirectH2Pools,
  metrics: &Arc<Metrics>,
  upstream_index: usize,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_proven_empty: bool,
  outbound: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
) -> DirectH2SendResult {
  let protocol = fast_path_metric_protocol(request_version);
  if let Some(reason) = direct_h2_guard_miss(
    upstream,
    upstream_version,
    request_version,
    direct_selection_used,
    request_body_proven_empty,
    &outbound,
  ) {
    metrics.record_direct_h2_transport_miss(protocol, reason);
    return DirectH2SendResult::Fallback(outbound);
  }

  let Some(pool) = pools.for_upstream_index(upstream_index) else {
    metrics.record_direct_h2_transport_miss(protocol, "unsupported_upstream");
    return DirectH2SendResult::Fallback(outbound);
  };

  let prepared = match PreparedDirectH2Request::from_request(outbound) {
    Ok(prepared) => prepared,
    Err(error) => {
      metrics.record_direct_h2_transport_miss(protocol, "unsupported_request");
      return DirectH2SendResult::Sent(Err(error));
    }
  };

  send_prepared_request(pool, metrics, protocol, prepared, timeouts).await
}

fn direct_h2_guard_miss(
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_proven_empty: bool,
  outbound: &Request<ProxyBody>,
) -> Option<&'static str> {
  if !matches!(
    request_version,
    http::Version::HTTP_11 | http::Version::HTTP_2 | http::Version::HTTP_3
  ) || !direct_selection_used
    || !matches!(outbound.method(), &Method::GET | &Method::HEAD)
  {
    return Some("unsupported_request");
  }
  if upstream_version != HttpVersion::H2
    || !matches!(upstream.origin.scheme(), "http" | "https")
    || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return Some("unsupported_upstream");
  }
  if !request_body_proven_empty || !outbound.body().is_end_stream() {
    return Some("request_body");
  }
  None
}

async fn send_prepared_request(
  pool: Arc<DirectH2Pool>,
  metrics: &Arc<Metrics>,
  protocol: &'static str,
  prepared: PreparedDirectH2Request,
  timeouts: EffectiveTimeouts,
) -> DirectH2SendResult {
  metrics.record_http_upstream_client_request(pool.metric_version(), pool.origin.scheme, "primary");

  let direct_sender = match sender_with_first_byte_timeout(
    pool.sender(metrics),
    timeouts.upstream_first_byte,
  )
  .await
  {
    Ok(Some(direct_sender)) => direct_sender,
    Ok(None) => return saturated_fallback(metrics, protocol, prepared.into_fallback_request()),
    Err(error) => return direct_h2_send_error(metrics, protocol, error),
  };
  let reused = direct_sender.reused;
  let mut sender = direct_sender.sender;
  let lease = direct_sender.lease;
  let mut retry = reused.then(|| prepared.retry_request());
  let send_result = tokio::time::timeout(
    timeouts.upstream_first_byte,
    sender.send_request(prepared.into_request()),
  )
  .await;
  match send_result {
    Ok(Ok(response)) => {
      metrics.record_direct_h2_transport_hit(protocol);
      DirectH2SendResult::Sent(Ok(DirectH2Response {
        response,
        lease: Some(lease),
      }))
    }
    Ok(Err(error)) if reused => {
      debug!(error = %error, "direct H2 upstream sender failed; reconnecting once");
      metrics.record_direct_h2_pool_event("reconnect");
      pool.clear_connection(&lease.connection).await;
      drop(lease);
      let direct_sender =
        match sender_with_first_byte_timeout(pool.sender(metrics), timeouts.upstream_first_byte)
          .await
        {
          Ok(Some(direct_sender)) => direct_sender,
          Ok(None) => {
            return saturated_fallback(
              metrics,
              protocol,
              retry
                .take()
                .expect("reused direct H2 sends should retain one retry request")
                .into_fallback_request(),
            );
          }
          Err(error) => return direct_h2_send_error(metrics, protocol, error),
        };
      let mut sender = direct_sender.sender;
      let lease = direct_sender.lease;
      let retry = retry
        .take()
        .expect("reused direct H2 sends should retain one retry request");
      match tokio::time::timeout(
        timeouts.upstream_first_byte,
        sender.send_request(retry.into_request()),
      )
      .await
      {
        Ok(Ok(response)) => {
          metrics.record_direct_h2_transport_hit(protocol);
          DirectH2SendResult::Sent(Ok(DirectH2Response {
            response,
            lease: Some(lease),
          }))
        }
        Ok(Err(error)) => {
          pool.clear_connection(&lease.connection).await;
          drop(lease);
          direct_h2_send_error(
            metrics,
            protocol,
            anyhow::Error::new(error).context("direct H2 upstream retry request failed"),
          )
        }
        Err(_) => {
          pool.clear_connection(&lease.connection).await;
          drop(lease);
          direct_h2_send_error(
            metrics,
            protocol,
            anyhow::anyhow!("direct H2 upstream first-byte timed out"),
          )
        }
      }
    }
    Ok(Err(error)) => {
      pool.clear_connection(&lease.connection).await;
      drop(lease);
      direct_h2_send_error(metrics, protocol, error.into())
    }
    Err(_) => {
      pool.clear_connection(&lease.connection).await;
      drop(lease);
      direct_h2_send_error(
        metrics,
        protocol,
        anyhow::anyhow!("direct H2 upstream first-byte timed out"),
      )
    }
  }
}

fn saturated_fallback(
  metrics: &Metrics,
  protocol: &str,
  outbound: Request<ProxyBody>,
) -> DirectH2SendResult {
  metrics.record_direct_h2_transport_miss(protocol, "pool_full");
  DirectH2SendResult::Fallback(outbound)
}

fn direct_h2_send_error(
  metrics: &Metrics,
  protocol: &str,
  error: anyhow::Error,
) -> DirectH2SendResult {
  let reason = if error.to_string().contains("timed out") {
    "connect_error"
  } else {
    "send_error"
  };
  metrics.record_direct_h2_transport_miss(protocol, reason);
  DirectH2SendResult::Sent(Err(error))
}

async fn sender_with_first_byte_timeout<F>(
  sender: F,
  timeout: Duration,
) -> anyhow::Result<Option<DirectH2Sender>>
where
  F: Future<Output = anyhow::Result<Option<DirectH2Sender>>>,
{
  match tokio::time::timeout(timeout, sender).await {
    Ok(result) => result,
    Err(_) => anyhow::bail!("direct H2 upstream first-byte timed out"),
  }
}

pub(super) fn release_response_body(
  body: ProxyBody,
  lease: DirectH2Lease,
  body_consumed: bool,
) -> ProxyBody {
  if body_consumed {
    drop(lease);
    return body;
  }
  body::with_drop_guard(body, lease)
}

#[cfg(test)]
mod tests;
