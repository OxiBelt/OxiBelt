use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use anyhow::Context;
use http::Response;
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use tokio::sync::{Notify, Semaphore};

use crate::circuit_breakers::{AdmissionLease, AdmissionRejection, CircuitBreakerRuntime};
use crate::config::{
  CryptoConfig, ProxyHttp2Config, UpstreamConfig, UpstreamPoolConfig, upstream_pool_server_id,
};
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{DirectH2PoolEvent, FastPathMetricProtocol};
use crate::overload::OverloadState;
use crate::pools::synthetic_upstream_name_for_id;
use crate::proxy::http::body::ProxyBody;
use crate::tls::{OutboundRevocationRuntime, TlsResumptionState};

use super::super::stage_timing as timing;
use super::connection::{
  DirectH2ConnectErrorClass, DirectH2Connected, DirectH2Origin, build_h2_tls_config,
  connect_direct_h2,
};
use super::metrics as metric_record;
use super::{DIRECT_H2_MAX_SLOTS, DIRECT_H2_STREAMS_PER_SLOT_SOFT_LIMIT};

const DIRECT_H2_MAX_WAITERS: usize = 64;
const DIRECT_H2_CAPACITY_WAIT: Duration = Duration::from_millis(25);
const DIRECT_H2_CONNECT_COOLDOWN: Duration = Duration::from_secs(1);

#[derive(Clone, Default)]
pub(crate) struct DirectH2Pools {
  identity: Arc<()>,
  pools: Vec<Option<Arc<DirectH2Pool>>>,
}

impl DirectH2Pools {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    upstreams: &[UpstreamConfig],
    extra_root_certs: &[PathBuf],
    crypto: &CryptoConfig,
    tls_resumption: &TlsResumptionState,
    http2_config: &ProxyHttp2Config,
    outbound_revocation: &OutboundRevocationRuntime,
    circuit_breakers: Arc<CircuitBreakerRuntime>,
    circuit_pools: &[UpstreamPoolConfig],
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
          circuit_breakers.clone(),
          circuit_pool_for_upstream(&upstream.name, circuit_pools),
        )
        .transpose()
        .with_context(|| format!("failed to build direct H2 pool for {}", upstream.name))?
        .map(Arc::new),
      );
    }
    Ok(Self {
      identity: Arc::new(()),
      pools,
    })
  }

  pub(super) fn for_upstream_index(&self, upstream_index: usize) -> Option<Arc<DirectH2Pool>> {
    self
      .pools
      .get(upstream_index)
      .and_then(|pool| pool.as_ref())
      .cloned()
  }

  pub(crate) fn retire_if_replaced(&self, replacement: &Self) {
    if Arc::ptr_eq(&self.identity, &replacement.identity) {
      return;
    }
    for pool in self.pools.iter().flatten() {
      pool.retire();
    }
  }

  pub(crate) fn needs_restage(&self) -> bool {
    self
      .pools
      .iter()
      .flatten()
      .any(|pool| pool.retired.load(Ordering::Acquire))
  }

  #[cfg(test)]
  pub(crate) fn same_identity(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.identity, &other.identity)
  }
}

#[derive(Clone, Debug)]
struct DirectH2PoolGeneration(Arc<()>);

impl DirectH2PoolGeneration {
  fn new() -> Self {
    Self(Arc::new(()))
  }

  fn same_as(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.0, &other.0)
  }
}

pub(super) struct DirectH2Pool {
  generation: DirectH2PoolGeneration,
  retired: AtomicBool,
  pub(super) origin: DirectH2Origin,
  tls_server_name: Option<String>,
  connect_timeout: Duration,
  idle_timeout: Duration,
  max_lifetime: Duration,
  target_streams_per_slot: usize,
  max_streams_per_slot: usize,
  http2_config: ProxyHttp2Config,
  tls_config: Option<Arc<rustls::ClientConfig>>,
  circuit_breakers: Arc<CircuitBreakerRuntime>,
  circuit_pool: Option<Arc<str>>,
  changed: Arc<Notify>,
  waiters: Arc<Semaphore>,
  slots: Box<[DirectH2Slot]>,
  #[cfg(test)]
  release_slot_visits: AtomicUsize,
  #[cfg(test)]
  test_connector: Option<TestConnector>,
}

struct DirectH2Slot {
  state: Mutex<DirectH2SlotRecord>,
}

struct DirectH2SlotRecord {
  epoch: u64,
  state: DirectH2SlotState,
}

enum DirectH2SlotState {
  Empty,
  Connecting(Arc<DirectH2ConnectAttempt>),
  Ready(Arc<DirectH2Connection>),
  Draining {
    connection: Arc<DirectH2Connection>,
    reason: DirectH2DrainReason,
  },
  CoolingDown {
    until: Instant,
    error_class: DirectH2ErrorClass,
  },
  Backpressured {
    until: Instant,
  },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectH2DrainReason {
  Idle,
  Lifetime,
  GracefulClose,
  ConnectionError,
  SendError,
  Configuration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectH2ErrorClass {
  TcpConnect,
  TlsHandshake,
  H2Handshake,
  Connection,
}

struct DirectH2ConnectAttempt {
  generation: DirectH2PoolGeneration,
  slot_index: usize,
  slot_epoch: u64,
  operation: Arc<()>,
  deadline: Instant,
}

impl DirectH2ConnectAttempt {
  fn same_as(&self, other: &Self) -> bool {
    self.generation.same_as(&other.generation)
      && self.slot_index == other.slot_index
      && self.slot_epoch == other.slot_epoch
      && Arc::ptr_eq(&self.operation, &other.operation)
  }
}

pub(super) struct DirectH2Connection {
  sender: SendRequest<ProxyBody>,
  created_at: Instant,
  last_used_elapsed_ns: AtomicU64,
  pub(super) active_streams: AtomicUsize,
  peer_max_streams: Arc<AtomicUsize>,
  ever_reserved: AtomicBool,
  _connection_admission: Option<AdmissionLease>,
}

pub(super) struct DirectH2Sender {
  pub(super) sender: SendRequest<ProxyBody>,
  pub(super) lease: DirectH2Lease,
  pub(super) reused: bool,
}

pub(in crate::proxy::http::fast_path) struct DirectH2Response {
  pub(in crate::proxy::http::fast_path) response: Response<Incoming>,
  lease: Option<DirectH2Lease>,
}

pub(in crate::proxy::http::fast_path) struct DirectH2Lease {
  pool: Weak<DirectH2Pool>,
  generation: DirectH2PoolGeneration,
  slot_index: usize,
  slot_epoch: u64,
  pub(super) connection: Arc<DirectH2Connection>,
  stream_admission: Option<AdmissionLease>,
  metrics: Option<Arc<Metrics>>,
}

enum DirectH2AcquireAction {
  Ready(DirectH2Sender),
  Start {
    attempt: Arc<DirectH2ConnectAttempt>,
    cold: bool,
  },
  Wait {
    attempt_deadline: Option<Instant>,
    cold: bool,
  },
  Fallback,
}

#[cfg(test)]
pub(super) type TestConnector = Arc<
  dyn Fn(
      Instant,
    ) -> std::pin::Pin<
      Box<dyn std::future::Future<Output = anyhow::Result<DirectH2Connected>> + Send>,
    > + Send
    + Sync,
>;

fn duration_nanos_u64(duration: Duration) -> u64 {
  duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

impl DirectH2Slot {
  fn new() -> Self {
    Self {
      state: Mutex::new(DirectH2SlotRecord {
        epoch: 0,
        state: DirectH2SlotState::Empty,
      }),
    }
  }

  fn record(&self) -> MutexGuard<'_, DirectH2SlotRecord> {
    match self.state.lock() {
      Ok(record) => record,
      Err(poisoned) => {
        tracing::warn!("recovered poisoned direct H2 slot state");
        let record = poisoned.into_inner();
        self.state.clear_poison();
        record
      }
    }
  }
}

impl DirectH2Response {
  pub(super) fn new(response: Response<Incoming>, lease: DirectH2Lease) -> Self {
    Self {
      response,
      lease: Some(lease),
    }
  }

  pub(in crate::proxy::http::fast_path) fn take_lease(&mut self) -> Option<DirectH2Lease> {
    self.lease.take()
  }
}

impl DirectH2Lease {
  pub(super) fn set_stream_admission(&mut self, admission: AdmissionLease) {
    self.stream_admission = Some(admission);
  }
}

impl Drop for DirectH2Lease {
  fn drop(&mut self) {
    let elapsed = self.connection.created_at.elapsed();
    self
      .connection
      .last_used_elapsed_ns
      .fetch_max(duration_nanos_u64(elapsed), Ordering::AcqRel);
    let previous = self
      .connection
      .active_streams
      .fetch_sub(1, Ordering::AcqRel);
    debug_assert!(previous > 0, "direct H2 lease released without reservation");
    let Some(pool) = self.pool.upgrade() else {
      return;
    };
    pool.release_indexed(self, previous == 1);
  }
}

impl DirectH2Connection {
  fn active(&self) -> usize {
    self.active_streams.load(Ordering::Acquire)
  }

  fn reservation_limit(&self, configured_max: usize) -> usize {
    configured_max.min(self.peer_max_streams.load(Ordering::Acquire))
  }

  fn reserve(
    connection: &Arc<Self>,
    pool: &Arc<DirectH2Pool>,
    slot_index: usize,
    slot_epoch: u64,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
  ) -> Option<DirectH2Sender> {
    if connection.sender.is_closed() {
      return None;
    }
    let limit = connection
      .reservation_limit(pool.max_streams_per_slot)
      .min(pool.target_streams_per_slot);
    let mut active = connection.active_streams.load(Ordering::Acquire);
    loop {
      if active >= limit {
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
    let reused = connection.ever_reserved.swap(true, Ordering::AcqRel);
    Some(DirectH2Sender {
      sender: connection.sender.clone(),
      lease: DirectH2Lease {
        pool: Arc::downgrade(pool),
        generation: pool.generation.clone(),
        slot_index,
        slot_epoch,
        connection: connection.clone(),
        stream_admission: None,
        metrics: hot_path_metrics.then(|| metrics.clone()),
      },
      reused,
    })
  }
}

impl DirectH2Pool {
  #[allow(clippy::too_many_arguments)]
  fn new(
    upstream: &UpstreamConfig,
    extra_root_certs: &[PathBuf],
    crypto: &CryptoConfig,
    tls_resumption: &TlsResumptionState,
    http2_config: &ProxyHttp2Config,
    outbound_revocation: &OutboundRevocationRuntime,
    circuit_breakers: Arc<CircuitBreakerRuntime>,
    circuit_pool: Option<Arc<str>>,
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
    Some(tls_config.transpose().map(|tls_config| {
      Self {
        generation: DirectH2PoolGeneration::new(),
        retired: AtomicBool::new(false),
        origin,
        tls_server_name: upstream.tls.server_name.clone(),
        connect_timeout: Duration::from_millis(upstream.connect_timeout_ms),
        idle_timeout: Duration::from_millis(upstream.idle_timeout_ms),
        max_lifetime: Duration::from_millis(upstream.max_lifetime_ms),
        target_streams_per_slot,
        max_streams_per_slot,
        http2_config: *http2_config,
        tls_config,
        circuit_breakers,
        circuit_pool,
        changed: Arc::new(Notify::new()),
        waiters: Arc::new(Semaphore::new(DIRECT_H2_MAX_WAITERS)),
        slots: (0..slot_count)
          .map(|_| DirectH2Slot::new())
          .collect::<Vec<_>>()
          .into_boxed_slice(),
        #[cfg(test)]
        release_slot_visits: AtomicUsize::new(0),
        #[cfg(test)]
        test_connector: None,
      }
    }))
  }

  #[allow(clippy::too_many_arguments)]
  pub(super) async fn sender<F>(
    self: &Arc<Self>,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
    request_deadline: Instant,
    effective_connect_timeout: Duration,
    overload_state: F,
    protocol: FastPathMetricProtocol,
    timing_enabled: bool,
  ) -> anyhow::Result<Option<DirectH2Sender>>
  where
    F: Fn() -> OverloadState,
  {
    let mut waiter = None;
    let mut recorded_miss = false;
    loop {
      if Instant::now() >= request_deadline {
        anyhow::bail!("direct H2 upstream first-byte timed out");
      }
      let notified = self.changed.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      let action = self.acquire_action(
        metrics,
        hot_path_metrics,
        request_deadline,
        effective_connect_timeout,
        overload_state(),
      );
      match action {
        DirectH2AcquireAction::Ready(sender) => {
          metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::Hit);
          return Ok(Some(sender));
        }
        DirectH2AcquireAction::Fallback => return Ok(None),
        DirectH2AcquireAction::Start { attempt, cold } => {
          if !recorded_miss {
            metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::Miss);
            metric_record::pool_event(
              metrics,
              hot_path_metrics,
              if cold {
                DirectH2PoolEvent::MissEmpty
              } else {
                DirectH2PoolEvent::MissSaturated
              },
            );
            recorded_miss = true;
          }
          metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::ConnectLeader);
          self.spawn_connect(
            attempt.clone(),
            metrics.clone(),
            hot_path_metrics,
            protocol,
            timing_enabled,
          );
          if waiter.is_none() {
            waiter = Arc::clone(&self.waiters).try_acquire_owned().ok();
            if waiter.is_none() {
              metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::CapacityFull);
              return Ok(None);
            }
          }
          let changed = self
            .wait_for_change(
              notified,
              request_deadline,
              Some(attempt.deadline),
              cold,
              metrics,
              hot_path_metrics,
              protocol,
              timing_enabled,
            )
            .await?;
          if !changed {
            return Ok(None);
          }
        }
        DirectH2AcquireAction::Wait {
          attempt_deadline,
          cold,
        } => {
          if !recorded_miss {
            metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::Miss);
            metric_record::pool_event(
              metrics,
              hot_path_metrics,
              if cold {
                DirectH2PoolEvent::MissEmpty
              } else {
                DirectH2PoolEvent::MissSaturated
              },
            );
            recorded_miss = true;
          }
          if waiter.is_none() {
            waiter = Arc::clone(&self.waiters).try_acquire_owned().ok();
            if waiter.is_none() {
              metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::CapacityFull);
              return Ok(None);
            }
          }
          if cold {
            metric_record::pool_event(
              metrics,
              hot_path_metrics,
              DirectH2PoolEvent::ConnectCoalesced,
            );
          } else {
            metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::CapacityWait);
          }
          let changed = self
            .wait_for_change(
              notified,
              request_deadline,
              attempt_deadline,
              cold,
              metrics,
              hot_path_metrics,
              protocol,
              timing_enabled,
            )
            .await?;
          if !changed {
            return Ok(None);
          }
        }
      }
    }
  }

  fn acquire_action(
    self: &Arc<Self>,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
    request_deadline: Instant,
    effective_connect_timeout: Duration,
    overload_state: OverloadState,
  ) -> DirectH2AcquireAction {
    if self.retired.load(Ordering::Acquire) {
      return DirectH2AcquireAction::Fallback;
    }
    let now = Instant::now();
    let mut best: Option<(usize, usize, u64, Arc<DirectH2Connection>)> = None;
    let mut empty_slot = None;
    let mut connecting = None;
    let mut ready_count = 0;
    let mut draining_count = 0;
    let mut cooling = false;
    let mut backpressured = false;
    for (slot_index, slot) in self.slots.iter().enumerate() {
      let mut record = slot.record();
      let epoch = record.epoch;
      match &record.state {
        DirectH2SlotState::CoolingDown { until, .. } if *until <= now => {
          record.epoch = record.epoch.wrapping_add(1);
          record.state = DirectH2SlotState::Empty;
          metric_record::pool_event(
            metrics,
            hot_path_metrics,
            DirectH2PoolEvent::CooldownExpired,
          );
          empty_slot.get_or_insert(slot_index);
        }
        DirectH2SlotState::CoolingDown { error_class, .. } => {
          tracing::trace!(?error_class, "direct H2 slot is cooling down");
          cooling = true;
        }
        DirectH2SlotState::Backpressured { until } if *until <= now => {
          record.epoch = record.epoch.wrapping_add(1);
          record.state = DirectH2SlotState::Empty;
          empty_slot.get_or_insert(slot_index);
        }
        DirectH2SlotState::Backpressured { .. } => backpressured = true,
        DirectH2SlotState::Empty => {
          empty_slot.get_or_insert(slot_index);
        }
        DirectH2SlotState::Connecting(attempt) if attempt.deadline <= now => {
          record.epoch = record.epoch.wrapping_add(1);
          record.state = DirectH2SlotState::Empty;
          metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::ConnectError);
          empty_slot.get_or_insert(slot_index);
        }
        DirectH2SlotState::Connecting(attempt) => {
          connecting.get_or_insert_with(|| attempt.clone());
        }
        DirectH2SlotState::Draining { connection, reason } => {
          if connection.active() == 0 {
            let cooldown = matches!(
              reason,
              DirectH2DrainReason::ConnectionError | DirectH2DrainReason::SendError
            );
            record.epoch = record.epoch.wrapping_add(1);
            record.state = if cooldown {
              DirectH2SlotState::CoolingDown {
                until: now + DIRECT_H2_CONNECT_COOLDOWN,
                error_class: DirectH2ErrorClass::Connection,
              }
            } else {
              DirectH2SlotState::Empty
            };
            metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::DrainCompleted);
            if cooldown {
              cooling = true;
            } else {
              empty_slot.get_or_insert(slot_index);
            }
          } else {
            draining_count += 1;
          }
        }
        DirectH2SlotState::Ready(connection) => {
          let active = connection.active();
          if connection.sender.is_closed() {
            draining_count += 1;
            continue;
          }
          let age = now.saturating_duration_since(connection.created_at);
          let idle_ns = duration_nanos_u64(age)
            .saturating_sub(connection.last_used_elapsed_ns.load(Ordering::Acquire));
          let drain_reason = if age >= self.max_lifetime {
            Some(DirectH2DrainReason::Lifetime)
          } else if active == 0 && idle_ns >= duration_nanos_u64(self.idle_timeout) {
            Some(DirectH2DrainReason::Idle)
          } else {
            None
          };
          if let Some(reason) = drain_reason {
            metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::DrainStarted);
            if reason == DirectH2DrainReason::GracefulClose {
              metric_record::pool_event(
                metrics,
                hot_path_metrics,
                DirectH2PoolEvent::GracefulClose,
              );
            }
            if active == 0 {
              record.epoch = record.epoch.wrapping_add(1);
              record.state = DirectH2SlotState::Empty;
              metric_record::pool_event(
                metrics,
                hot_path_metrics,
                DirectH2PoolEvent::DrainCompleted,
              );
              empty_slot.get_or_insert(slot_index);
            } else {
              record.state = DirectH2SlotState::Draining {
                connection: connection.clone(),
                reason,
              };
              draining_count += 1;
            }
            continue;
          }
          ready_count += 1;
          let limit = connection
            .reservation_limit(self.max_streams_per_slot)
            .min(self.target_streams_per_slot);
          if active < limit
            && best
              .as_ref()
              .is_none_or(|(best_active, ..)| active < *best_active)
          {
            best = Some((active, slot_index, epoch, connection.clone()));
          }
        }
      }
    }

    if let Some((_, slot_index, slot_epoch, connection)) = best {
      let record = self.slots[slot_index].record();
      if record.epoch == slot_epoch
        && matches!(
          &record.state,
          DirectH2SlotState::Ready(current) if Arc::ptr_eq(current, &connection)
        )
        && let Some(sender) = DirectH2Connection::reserve(
          &connection,
          self,
          slot_index,
          slot_epoch,
          metrics,
          hot_path_metrics,
        )
      {
        return DirectH2AcquireAction::Ready(sender);
      }
      return DirectH2AcquireAction::Wait {
        attempt_deadline: None,
        cold: false,
      };
    }

    if overload_state != OverloadState::Normal {
      return DirectH2AcquireAction::Fallback;
    }
    if let Some(attempt) = connecting {
      return DirectH2AcquireAction::Wait {
        attempt_deadline: Some(attempt.deadline),
        cold: ready_count == 0,
      };
    }
    if backpressured {
      return DirectH2AcquireAction::Fallback;
    }
    if cooling && ready_count == 0 {
      return DirectH2AcquireAction::Fallback;
    }
    if let Some(slot_index) = empty_slot {
      let mut record = self.slots[slot_index].record();
      if !matches!(record.state, DirectH2SlotState::Empty) {
        return DirectH2AcquireAction::Wait {
          attempt_deadline: None,
          cold: ready_count == 0,
        };
      }
      record.epoch = record.epoch.wrapping_add(1);
      let deadline = request_deadline.min(
        now
          .checked_add(effective_connect_timeout.min(self.connect_timeout))
          .unwrap_or(request_deadline),
      );
      let attempt = Arc::new(DirectH2ConnectAttempt {
        generation: self.generation.clone(),
        slot_index,
        slot_epoch: record.epoch,
        operation: Arc::new(()),
        deadline,
      });
      record.state = DirectH2SlotState::Connecting(attempt.clone());
      return DirectH2AcquireAction::Start {
        attempt,
        cold: ready_count == 0,
      };
    }
    if ready_count > 0 || draining_count > 0 {
      DirectH2AcquireAction::Wait {
        attempt_deadline: None,
        cold: false,
      }
    } else {
      DirectH2AcquireAction::Fallback
    }
  }

  #[allow(clippy::too_many_arguments)]
  async fn wait_for_change(
    &self,
    notified: std::pin::Pin<&mut tokio::sync::futures::Notified<'_>>,
    request_deadline: Instant,
    attempt_deadline: Option<Instant>,
    cold: bool,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
    protocol: FastPathMetricProtocol,
    timing_enabled: bool,
  ) -> anyhow::Result<bool> {
    let now = Instant::now();
    let local_deadline = if cold {
      attempt_deadline.unwrap_or(request_deadline)
    } else {
      now
        .checked_add(DIRECT_H2_CAPACITY_WAIT)
        .unwrap_or(request_deadline)
    };
    let deadline = request_deadline.min(local_deadline);
    let capacity_started = timing::start(timing_enabled && !cold);
    let result = tokio::time::timeout_at(deadline.into(), notified).await;
    timing::record_metrics_plain_result(
      metrics,
      protocol,
      timing::STAGE_DIRECT_H2_CAPACITY_WAIT,
      result.is_ok(),
      capacity_started,
    );
    match result {
      Ok(()) => {
        if !cold {
          metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::CapacityReady);
        }
        Ok(true)
      }
      Err(_) if Instant::now() >= request_deadline => {
        anyhow::bail!("direct H2 upstream first-byte timed out")
      }
      Err(_) => {
        if !cold {
          metric_record::pool_event(
            metrics,
            hot_path_metrics,
            DirectH2PoolEvent::CapacityTimeout,
          );
        }
        Ok(false)
      }
    }
  }

  fn spawn_connect(
    self: &Arc<Self>,
    attempt: Arc<DirectH2ConnectAttempt>,
    metrics: Arc<Metrics>,
    hot_path_metrics: bool,
    protocol: FastPathMetricProtocol,
    timing_enabled: bool,
  ) {
    let pool = self.clone();
    tokio::spawn(async move {
      metric_record::upstream_pool_miss(&pool, &metrics, hot_path_metrics);
      let admission = pool
        .circuit_breakers
        .admit_upstream_connection(pool.circuit_pool.as_deref(), Some(attempt.deadline))
        .await;
      let admission = match admission {
        Ok(admission) => admission,
        Err(error) => {
          pool.publish_admission_rejection(&attempt, error, &metrics, hot_path_metrics);
          return;
        }
      };
      let connect_started = timing::start(timing_enabled);
      let connected = pool.connect(attempt.deadline).await;
      timing::record_metrics_plain_result(
        &metrics,
        protocol,
        timing::STAGE_DIRECT_H2_CONNECT,
        connected.is_ok(),
        connect_started,
      );
      match connected {
        Ok(connected) => {
          pool.publish_connected(attempt, connected, admission, metrics, hot_path_metrics);
        }
        Err(failure) => pool.publish_connect_failure(
          &attempt,
          match failure.class {
            DirectH2ConnectErrorClass::TcpConnect => DirectH2ErrorClass::TcpConnect,
            DirectH2ConnectErrorClass::TlsHandshake => DirectH2ErrorClass::TlsHandshake,
            DirectH2ConnectErrorClass::H2Handshake => DirectH2ErrorClass::H2Handshake,
          },
          failure.error,
          &metrics,
          hot_path_metrics,
        ),
      }
    });
  }

  async fn connect(
    &self,
    deadline: Instant,
  ) -> Result<DirectH2Connected, super::connection::DirectH2ConnectFailure> {
    #[cfg(test)]
    if let Some(connector) = &self.test_connector {
      return connector(deadline).await.map_err(|error| {
        super::connection::DirectH2ConnectFailure {
          class: DirectH2ConnectErrorClass::H2Handshake,
          error,
        }
      });
    }
    connect_direct_h2(
      &self.origin,
      self.tls_server_name.as_deref(),
      self.tls_config.clone(),
      &self.http2_config,
      deadline,
      self.changed.clone(),
    )
    .await
  }

  fn publish_connected(
    self: &Arc<Self>,
    attempt: Arc<DirectH2ConnectAttempt>,
    connected: DirectH2Connected,
    connection_admission: AdmissionLease,
    metrics: Arc<Metrics>,
    hot_path_metrics: bool,
  ) {
    let DirectH2Connected {
      sender,
      peer_max_streams,
      driver,
    } = connected;
    let connection = Arc::new(DirectH2Connection {
      sender,
      created_at: Instant::now(),
      last_used_elapsed_ns: AtomicU64::new(0),
      active_streams: AtomicUsize::new(0),
      peer_max_streams,
      ever_reserved: AtomicBool::new(false),
      _connection_admission: Some(connection_admission),
    });
    let published = if self.retired.load(Ordering::Acquire) {
      false
    } else {
      let mut record = self.slots[attempt.slot_index].record();
      if record.epoch == attempt.slot_epoch
        && matches!(
          &record.state,
          DirectH2SlotState::Connecting(current) if current.same_as(&attempt)
        )
      {
        record.state = DirectH2SlotState::Ready(connection.clone());
        true
      } else {
        false
      }
    };
    if !published {
      metric_record::pool_event(
        &metrics,
        hot_path_metrics,
        DirectH2PoolEvent::StaleGeneration,
      );
      self.changed.notify_waiters();
      return;
    }
    metric_record::pool_event(&metrics, hot_path_metrics, DirectH2PoolEvent::Connect);
    metric_record::upstream_connection_created(self, &metrics, hot_path_metrics);
    self.changed.notify_waiters();
    self.spawn_lifecycle_monitor(
      attempt.slot_index,
      attempt.slot_epoch,
      Arc::downgrade(&connection),
      metrics.clone(),
      hot_path_metrics,
    );
    let pool = Arc::downgrade(self);
    let generation = self.generation.clone();
    let slot_index = attempt.slot_index;
    let slot_epoch = attempt.slot_epoch;
    let driver_connection = Arc::downgrade(&connection);
    tokio::spawn(async move {
      let graceful = driver.await.is_ok();
      if let (Some(pool), Some(connection)) = (pool.upgrade(), driver_connection.upgrade()) {
        pool.driver_completed(
          generation,
          slot_index,
          slot_epoch,
          &connection,
          graceful,
          &metrics,
          hot_path_metrics,
        );
      }
    });
  }

  fn spawn_lifecycle_monitor(
    self: &Arc<Self>,
    slot_index: usize,
    slot_epoch: u64,
    connection: Weak<DirectH2Connection>,
    metrics: Arc<Metrics>,
    hot_path_metrics: bool,
  ) {
    let pool = Arc::downgrade(self);
    let generation = self.generation.clone();
    tokio::spawn(async move {
      loop {
        let (Some(pool), Some(connection)) = (pool.upgrade(), connection.upgrade()) else {
          return;
        };
        let notified = pool.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let Some(delay) = pool.lifecycle_delay(&generation, slot_index, slot_epoch, &connection)
        else {
          return;
        };
        tokio::select! {
          () = tokio::time::sleep(delay) => {}
          () = &mut notified => {}
        }
        if pool.lifecycle_tick(
          &generation,
          slot_index,
          slot_epoch,
          &connection,
          &metrics,
          hot_path_metrics,
        ) {
          return;
        }
      }
    });
  }

  fn lifecycle_delay(
    &self,
    generation: &DirectH2PoolGeneration,
    slot_index: usize,
    slot_epoch: u64,
    connection: &Arc<DirectH2Connection>,
  ) -> Option<Duration> {
    if self.retired.load(Ordering::Acquire)
      || !self.generation.same_as(generation)
      || slot_index >= self.slots.len()
    {
      return None;
    }
    let record = self.slots[slot_index].record();
    if record.epoch != slot_epoch
      || !matches!(
        &record.state,
        DirectH2SlotState::Ready(current) if Arc::ptr_eq(current, connection)
      )
    {
      return None;
    }
    let age = connection.created_at.elapsed();
    let lifetime_remaining = self.max_lifetime.saturating_sub(age);
    if connection.active() != 0 {
      return Some(lifetime_remaining);
    }
    let idle_elapsed = age.saturating_sub(Duration::from_nanos(
      connection.last_used_elapsed_ns.load(Ordering::Acquire),
    ));
    Some(lifetime_remaining.min(self.idle_timeout.saturating_sub(idle_elapsed)))
  }

  fn lifecycle_tick(
    &self,
    generation: &DirectH2PoolGeneration,
    slot_index: usize,
    slot_epoch: u64,
    connection: &Arc<DirectH2Connection>,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
  ) -> bool {
    if self.retired.load(Ordering::Acquire)
      || !self.generation.same_as(generation)
      || slot_index >= self.slots.len()
    {
      return true;
    }
    let mut record = self.slots[slot_index].record();
    if record.epoch != slot_epoch
      || !matches!(
        &record.state,
        DirectH2SlotState::Ready(current) if Arc::ptr_eq(current, connection)
      )
    {
      return true;
    }
    let age = connection.created_at.elapsed();
    let idle_elapsed = age.saturating_sub(Duration::from_nanos(
      connection.last_used_elapsed_ns.load(Ordering::Acquire),
    ));
    let reason = if age >= self.max_lifetime {
      Some(DirectH2DrainReason::Lifetime)
    } else if connection.active() == 0 && idle_elapsed >= self.idle_timeout {
      Some(DirectH2DrainReason::Idle)
    } else {
      None
    };
    let Some(reason) = reason else {
      return false;
    };
    metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::DrainStarted);
    if connection.active() == 0 {
      record.epoch = record.epoch.wrapping_add(1);
      record.state = DirectH2SlotState::Empty;
      metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::DrainCompleted);
    } else {
      record.state = DirectH2SlotState::Draining {
        connection: connection.clone(),
        reason,
      };
    }
    drop(record);
    self.changed.notify_waiters();
    true
  }

  fn publish_connect_failure(
    &self,
    attempt: &Arc<DirectH2ConnectAttempt>,
    error_class: DirectH2ErrorClass,
    error: anyhow::Error,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
  ) {
    tracing::debug!(error = %error, ?error_class, "direct H2 connection attempt failed");
    let mut record = self.slots[attempt.slot_index].record();
    if record.epoch == attempt.slot_epoch
      && matches!(
        &record.state,
        DirectH2SlotState::Connecting(current) if current.same_as(attempt)
      )
    {
      record.state = DirectH2SlotState::CoolingDown {
        until: Instant::now() + DIRECT_H2_CONNECT_COOLDOWN,
        error_class,
      };
      metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::ConnectError);
      metric_record::pool_event(
        metrics,
        hot_path_metrics,
        DirectH2PoolEvent::CooldownEntered,
      );
    } else {
      metric_record::pool_event(
        metrics,
        hot_path_metrics,
        DirectH2PoolEvent::StaleGeneration,
      );
    }
    drop(record);
    self.changed.notify_waiters();
  }

  fn publish_admission_rejection(
    &self,
    attempt: &Arc<DirectH2ConnectAttempt>,
    error: AdmissionRejection,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
  ) {
    tracing::debug!(error = %error, "direct H2 connection admission was rejected");
    let mut record = self.slots[attempt.slot_index].record();
    if record.epoch == attempt.slot_epoch
      && matches!(
        &record.state,
        DirectH2SlotState::Connecting(current) if current.same_as(attempt)
      )
    {
      let retry_after = error.retry_after.max(DIRECT_H2_CAPACITY_WAIT);
      let now = Instant::now();
      record.state = DirectH2SlotState::Backpressured {
        until: now
          .checked_add(retry_after)
          .unwrap_or_else(|| now.checked_add(DIRECT_H2_CONNECT_COOLDOWN).unwrap_or(now)),
      };
      metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::CapacityFull);
    } else {
      metric_record::pool_event(
        metrics,
        hot_path_metrics,
        DirectH2PoolEvent::StaleGeneration,
      );
    }
    drop(record);
    self.changed.notify_waiters();
  }

  #[allow(clippy::too_many_arguments)]
  fn driver_completed(
    &self,
    generation: DirectH2PoolGeneration,
    slot_index: usize,
    slot_epoch: u64,
    connection: &Arc<DirectH2Connection>,
    graceful: bool,
    metrics: &Arc<Metrics>,
    hot_path_metrics: bool,
  ) {
    if !self.generation.same_as(&generation) || slot_index >= self.slots.len() {
      metric_record::pool_event(
        metrics,
        hot_path_metrics,
        DirectH2PoolEvent::StaleGeneration,
      );
      return;
    }
    let mut record = self.slots[slot_index].record();
    if record.epoch != slot_epoch {
      metric_record::pool_event(
        metrics,
        hot_path_metrics,
        DirectH2PoolEvent::StaleGeneration,
      );
      return;
    }
    let existing_reason = match &record.state {
      DirectH2SlotState::Ready(current) if Arc::ptr_eq(current, connection) => None,
      DirectH2SlotState::Draining {
        connection: current,
        reason,
      } if Arc::ptr_eq(current, connection) => Some(*reason),
      _ => {
        metric_record::pool_event(
          metrics,
          hot_path_metrics,
          DirectH2PoolEvent::StaleGeneration,
        );
        return;
      }
    };
    let reason = existing_reason.unwrap_or_else(|| {
      if graceful {
        metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::GracefulClose);
        DirectH2DrainReason::GracefulClose
      } else {
        DirectH2DrainReason::ConnectionError
      }
    });
    if existing_reason.is_none() {
      metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::DrainStarted);
    }
    if connection.active() == 0 {
      let cooldown = matches!(
        reason,
        DirectH2DrainReason::ConnectionError | DirectH2DrainReason::SendError
      );
      record.epoch = record.epoch.wrapping_add(1);
      record.state = if cooldown {
        metric_record::pool_event(
          metrics,
          hot_path_metrics,
          DirectH2PoolEvent::CooldownEntered,
        );
        DirectH2SlotState::CoolingDown {
          until: Instant::now() + DIRECT_H2_CONNECT_COOLDOWN,
          error_class: DirectH2ErrorClass::Connection,
        }
      } else {
        DirectH2SlotState::Empty
      };
      metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::DrainCompleted);
    } else if existing_reason.is_none() {
      record.state = DirectH2SlotState::Draining {
        connection: connection.clone(),
        reason,
      };
    }
    drop(record);
    self.changed.notify_waiters();
  }

  pub(super) fn mark_unhealthy(&self, lease: &DirectH2Lease, reason: DirectH2DrainReason) {
    if !self.generation.same_as(&lease.generation) || lease.slot_index >= self.slots.len() {
      if let Some(metrics) = &lease.metrics {
        metric_record::pool_event(metrics, true, DirectH2PoolEvent::StaleGeneration);
      }
      return;
    }
    let mut record = self.slots[lease.slot_index].record();
    if record.epoch == lease.slot_epoch
      && matches!(
        &record.state,
        DirectH2SlotState::Ready(current) if Arc::ptr_eq(current, &lease.connection)
      )
    {
      record.state = DirectH2SlotState::Draining {
        connection: lease.connection.clone(),
        reason,
      };
      if let Some(metrics) = &lease.metrics {
        metric_record::pool_event(metrics, true, DirectH2PoolEvent::DrainStarted);
      }
    } else if let Some(metrics) = &lease.metrics {
      metric_record::pool_event(metrics, true, DirectH2PoolEvent::StaleGeneration);
    }
    drop(record);
    self.changed.notify_waiters();
  }

  fn release_indexed(&self, lease: &DirectH2Lease, last: bool) {
    if !self.generation.same_as(&lease.generation) || lease.slot_index >= self.slots.len() {
      if let Some(metrics) = &lease.metrics {
        metric_record::pool_event(metrics, true, DirectH2PoolEvent::StaleGeneration);
      }
      return;
    }
    #[cfg(test)]
    self.release_slot_visits.fetch_add(1, Ordering::Relaxed);
    if last {
      let mut record = self.slots[lease.slot_index].record();
      if record.epoch != lease.slot_epoch {
        if let Some(metrics) = &lease.metrics {
          metric_record::pool_event(metrics, true, DirectH2PoolEvent::StaleGeneration);
        }
      } else if let DirectH2SlotState::Draining { connection, reason } = &record.state
        && Arc::ptr_eq(connection, &lease.connection)
      {
        let cooldown = matches!(
          reason,
          DirectH2DrainReason::ConnectionError | DirectH2DrainReason::SendError
        );
        record.epoch = record.epoch.wrapping_add(1);
        record.state = if cooldown {
          if let Some(metrics) = &lease.metrics {
            metric_record::pool_event(metrics, true, DirectH2PoolEvent::CooldownEntered);
          }
          DirectH2SlotState::CoolingDown {
            until: Instant::now() + DIRECT_H2_CONNECT_COOLDOWN,
            error_class: DirectH2ErrorClass::Connection,
          }
        } else {
          DirectH2SlotState::Empty
        };
        if let Some(metrics) = &lease.metrics {
          metric_record::pool_event(metrics, true, DirectH2PoolEvent::DrainCompleted);
        }
      }
    }
    self.changed.notify_waiters();
  }

  fn retire(&self) {
    if self.retired.swap(true, Ordering::AcqRel) {
      return;
    }
    for slot in &self.slots {
      let mut record = slot.record();
      match &record.state {
        DirectH2SlotState::Ready(connection) if connection.active() > 0 => {
          record.state = DirectH2SlotState::Draining {
            connection: connection.clone(),
            reason: DirectH2DrainReason::Configuration,
          };
        }
        DirectH2SlotState::Draining { .. } => {}
        _ => {
          record.epoch = record.epoch.wrapping_add(1);
          record.state = DirectH2SlotState::Empty;
        }
      }
    }
    self.changed.notify_waiters();
  }

  pub(super) fn metric_version(&self) -> &'static str {
    if self.origin.scheme == "http" {
      "h2c"
    } else {
      "h2"
    }
  }

  #[cfg(test)]
  pub(super) fn for_test(
    slot_count: usize,
    target_streams_per_slot: usize,
    max_streams_per_slot: usize,
    connect_timeout: Duration,
    idle_timeout: Duration,
    max_lifetime: Duration,
    circuit_breakers: Arc<CircuitBreakerRuntime>,
    test_connector: TestConnector,
  ) -> Arc<Self> {
    Arc::new(Self {
      generation: DirectH2PoolGeneration::new(),
      retired: AtomicBool::new(false),
      origin: DirectH2Origin {
        scheme: "http",
        host: "127.0.0.1".to_owned(),
        port: 80,
      },
      tls_server_name: None,
      connect_timeout,
      idle_timeout,
      max_lifetime,
      target_streams_per_slot,
      max_streams_per_slot,
      http2_config: ProxyHttp2Config::default(),
      tls_config: None,
      circuit_breakers,
      circuit_pool: None,
      changed: Arc::new(Notify::new()),
      waiters: Arc::new(Semaphore::new(DIRECT_H2_MAX_WAITERS)),
      slots: (0..slot_count)
        .map(|_| DirectH2Slot::new())
        .collect::<Vec<_>>()
        .into_boxed_slice(),
      release_slot_visits: AtomicUsize::new(0),
      test_connector: Some(test_connector),
    })
  }

  #[cfg(test)]
  pub(super) fn test_slot_snapshot(&self, slot_index: usize) -> (&'static str, u64, usize) {
    let record = self.slots[slot_index].record();
    let (state, active) = match &record.state {
      DirectH2SlotState::Empty => ("empty", 0),
      DirectH2SlotState::Connecting(_) => ("connecting", 0),
      DirectH2SlotState::Ready(connection) => ("ready", connection.active()),
      DirectH2SlotState::Draining { connection, .. } => ("draining", connection.active()),
      DirectH2SlotState::CoolingDown { .. } => ("cooling_down", 0),
      DirectH2SlotState::Backpressured { .. } => ("backpressured", 0),
    };
    (state, record.epoch, active)
  }

  #[cfg(test)]
  pub(super) fn test_release_slot_visits(&self) -> usize {
    self.release_slot_visits.load(Ordering::Relaxed)
  }

  #[cfg(test)]
  pub(super) fn test_retire(&self) {
    self.retire();
  }

  #[cfg(test)]
  pub(super) fn test_abandon_slot(&self, slot_index: usize) {
    let mut record = self.slots[slot_index].record();
    record.epoch = record.epoch.wrapping_add(1);
    record.state = DirectH2SlotState::Empty;
    drop(record);
    self.changed.notify_waiters();
  }
}

fn circuit_pool_for_upstream(
  upstream_name: &str,
  pools: &[UpstreamPoolConfig],
) -> Option<Arc<str>> {
  pools
    .iter()
    .find(|pool| {
      pool.servers.iter().enumerate().any(|(index, server)| {
        synthetic_upstream_name_for_id(&pool.name, &upstream_pool_server_id(index, server))
          == upstream_name
      })
    })
    .map(|pool| Arc::<str>::from(pool.name.as_str()))
}

#[cfg(test)]
impl DirectH2Pools {
  pub(super) fn for_test(pool: Arc<DirectH2Pool>) -> Self {
    Self {
      identity: Arc::new(()),
      pools: vec![Some(pool)],
    }
  }
}
