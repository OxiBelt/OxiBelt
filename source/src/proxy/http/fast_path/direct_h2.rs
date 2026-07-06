//! Direct upstream HTTP/2 transport for the plain-proxy fast path.
//! It is limited to direct empty-body safe requests and falls back for all broader semantics.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
#[cfg(test)]
use http::Method;
use http::Response;
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::{CryptoConfig, ProxyHttp2Config, UpstreamConfig};
#[cfg(test)]
use crate::config::{HttpVersion, ProxyProtocolEgressMode};
use crate::metrics::Metrics;
#[cfg(test)]
use crate::metrics::fast_path::labels::FastPathTransportMissReason;
#[cfg(test)]
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::ProxyBody;
use crate::tls::{OutboundRevocationRuntime, TlsResumptionState};

mod connection;
mod metrics;
mod request;
mod send;

use self::connection::{
  DirectH2Origin, build_h2_tls_config, connect_tls_h2, h2_handshake_with_timeout,
};
use self::metrics as metric_record;
#[cfg(test)]
use self::request::PreparedDirectH2Request;
#[cfg(test)]
use self::request::empty_body;
pub(in crate::proxy::http::fast_path) use self::send::{
  DirectH2SendResult, release_response_body, try_send_direct_h2,
};
#[cfg(test)]
use self::send::{direct_h2_guard_miss, sender_with_first_byte_timeout};

const DIRECT_H2_MAX_SLOTS: usize = 16;
const DIRECT_H2_STREAMS_PER_SLOT_SOFT_LIMIT: usize = 32;

fn duration_nanos_u64(duration: Duration) -> u64 {
  duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Default)]
pub(crate) struct DirectH2Pools {
  pools: Vec<Option<Arc<DirectH2Pool>>>,
}

impl DirectH2Pools {
  pub(crate) fn new(
    upstreams: &[UpstreamConfig],
    extra_root_certs: &[PathBuf],
    crypto: &CryptoConfig,
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
          crypto,
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
  last_used_elapsed_ns: AtomicU64,
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
  fn stale(&self, idle_timeout: Duration, max_lifetime: Duration, now: Instant) -> bool {
    if self.active_streams.load(Ordering::Acquire) > 0 {
      return false;
    }
    let age = now.saturating_duration_since(self.created_at);
    if age > max_lifetime {
      return true;
    }
    let age_ns = duration_nanos_u64(age);
    let last_used_ns = self.last_used_elapsed_ns.load(Ordering::Acquire);
    age_ns.saturating_sub(last_used_ns) > duration_nanos_u64(idle_timeout)
  }

  fn reserve(
    connection: &Arc<Self>,
    max_streams_per_slot: usize,
    now: Instant,
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
    connection.last_used_elapsed_ns.store(
      duration_nanos_u64(now.saturating_duration_since(connection.created_at)),
      Ordering::Release,
    );
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

impl DirectH2Pool {
  fn new(
    upstream: &UpstreamConfig,
    extra_root_certs: &[PathBuf],
    crypto: &CryptoConfig,
    tls_resumption: &TlsResumptionState,
    http2_config: &ProxyHttp2Config,
    outbound_revocation: &OutboundRevocationRuntime,
  ) -> Option<anyhow::Result<Self>> {
    let origin = DirectH2Origin::from_url(&upstream.origin)?;
    let tls_config = if origin.scheme == "https" {
      Some(build_h2_tls_config(
        upstream,
        extra_root_certs,
        crypto,
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

  async fn sender(
    &self,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
  ) -> anyhow::Result<Option<DirectH2Sender>> {
    self
      .sender_with(metrics, hot_path_metrics, || {
        self.connect_sender(metrics, hot_path_metrics)
      })
      .await
  }

  async fn sender_with<F, Fut>(
    &self,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
    connect_sender: F,
  ) -> anyhow::Result<Option<DirectH2Sender>>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<SendRequest<ProxyBody>>>,
  {
    let reusable = self.take_reusable_sender(metrics, hot_path_metrics);
    if let Some(sender) = reusable.sender {
      metric_record::pool_event(metrics, hot_path_metrics, "hit");
      return Ok(Some(sender));
    }

    metric_record::pool_event(metrics, hot_path_metrics, "miss");
    match reusable.miss_reason {
      DirectH2TakeMissReason::None => {}
      DirectH2TakeMissReason::Empty => {
        metric_record::pool_event(metrics, hot_path_metrics, "miss_empty");
      }
      DirectH2TakeMissReason::Locked => {
        metric_record::pool_event(metrics, hot_path_metrics, "miss_locked");
      }
      DirectH2TakeMissReason::Saturated => {
        metric_record::pool_event(metrics, hot_path_metrics, "miss_saturated");
      }
    }
    if reusable.miss_reason == DirectH2TakeMissReason::Saturated && reusable.empty_slot.is_none() {
      return Ok(None);
    }

    let slot_index = reusable
      .empty_slot
      .unwrap_or_else(|| self.next_slot.fetch_add(1, Ordering::Relaxed) % self.slots.len());
    self
      .connect_slot(metrics, hot_path_metrics, slot_index, connect_sender)
      .await
  }

  fn take_reusable_sender(
    &self,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
  ) -> DirectH2TakeSender {
    let now = Instant::now();
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
      if candidate.stale(self.idle_timeout, self.max_lifetime, now) {
        metric_record::pool_stale_drop(metrics, hot_path_metrics);
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
    let best = match (best_under_target, empty_slot) {
      (Some((0, connection)), _) => Some((0, connection)),
      (Some(best), None) => Some(best),
      _ => best_over_target.filter(|_| empty_slot.is_none()),
    };
    if let Some((_, connection)) = best
      && let Some((sender, lease)) =
        DirectH2Connection::reserve(&connection, self.max_streams_per_slot, now)
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
    hot_path_metrics: bool,
    slot_index: usize,
    connect_sender: F,
  ) -> anyhow::Result<Option<DirectH2Sender>>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<SendRequest<ProxyBody>>>,
  {
    let slot = &self.slots[slot_index % self.slots.len()];
    let mut slot_connection = slot.connection.lock().await;
    let now = Instant::now();
    if let Some(candidate) = slot_connection.as_ref() {
      if candidate.stale(self.idle_timeout, self.max_lifetime, now) {
        metric_record::pool_stale_drop(metrics, hot_path_metrics);
        *slot_connection = None;
      } else if let Some((sender, lease)) =
        DirectH2Connection::reserve(candidate, self.max_streams_per_slot, now)
      {
        metric_record::pool_event(metrics, hot_path_metrics, "hit");
        return Ok(Some(DirectH2Sender {
          sender,
          lease,
          reused: true,
        }));
      } else {
        metric_record::pool_event(metrics, hot_path_metrics, "miss_saturated");
        return Ok(None);
      }
    }

    metric_record::upstream_pool_miss(self, metrics, hot_path_metrics);
    metric_record::pool_event(metrics, hot_path_metrics, "connect");
    let sender = match connect_sender().await {
      Ok(sender) => sender,
      Err(error) => {
        metric_record::pool_event(metrics, hot_path_metrics, "connect_error");
        return Err(error);
      }
    };
    let created_at = Instant::now();
    let connection = Arc::new(DirectH2Connection {
      sender: sender.clone(),
      created_at,
      last_used_elapsed_ns: AtomicU64::new(0),
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

  async fn connect_sender(
    &self,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
  ) -> anyhow::Result<SendRequest<ProxyBody>> {
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

    metric_record::upstream_connection_created(self, metrics, hot_path_metrics);
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

#[cfg(test)]
mod tests;
