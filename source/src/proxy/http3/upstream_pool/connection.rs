//! HTTP/3 pooled-stream leases and connection retirement checks.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::H3PoolSlot;
use crate::circuit_breakers::AdmissionLease;
use crate::config::{QuicConfig, UpstreamConfig};
use crate::proxy::http3::upstream_connection::ConnectedH3Upstream;

pub(super) struct PooledH3Connection {
  pub(super) connected: ConnectedH3Upstream,
  _connection_admission: AdmissionLease,
  created_at: Instant,
  last_used: std::sync::Mutex<Instant>,
  pub(super) streams: H3PoolStreamTracker,
}

impl PooledH3Connection {
  pub(super) fn new(connected: ConnectedH3Upstream, admission: AdmissionLease) -> Self {
    Self {
      connected,
      _connection_admission: admission,
      created_at: Instant::now(),
      last_used: std::sync::Mutex::new(Instant::now()),
      streams: H3PoolStreamTracker::default(),
    }
  }

  fn last_used_guard(&self) -> std::sync::MutexGuard<'_, Instant> {
    match self.last_used.lock() {
      Ok(last_used) => last_used,
      Err(poisoned) => {
        let mut last_used = poisoned.into_inner();
        *last_used = Instant::now();
        self.last_used.clear_poison();
        tracing::warn!("recovered poisoned HTTP/3 pool timestamp");
        last_used
      }
    }
  }

  pub(super) fn status(
    &self,
    upstream: &UpstreamConfig,
    quic_config: &QuicConfig,
  ) -> PooledConnectionStatus {
    if self.connected.connection.close_reason().is_some() {
      return PooledConnectionStatus::Closed;
    }
    if self.created_at.elapsed() >= Duration::from_millis(quic_config.upstream_pool.max_lifetime_ms)
    {
      return PooledConnectionStatus::Expired;
    }
    if !self.streams.is_active()
      && self.last_used_guard().elapsed() >= Duration::from_millis(upstream.idle_timeout_ms)
    {
      return PooledConnectionStatus::Idle;
    }
    PooledConnectionStatus::Ready
  }

  fn mark_used(&self) {
    *self.last_used_guard() = Instant::now();
  }

  pub(super) fn reserve(
    connection: &Arc<Self>,
    slot: Arc<H3PoolSlot>,
    changed: Arc<Notify>,
  ) -> PooledH3Lease {
    connection.streams.acquire();
    connection.mark_used();
    PooledH3Lease {
      connection: Arc::clone(connection),
      slot,
      changed,
    }
  }
}

#[derive(Default)]
pub(super) struct H3PoolStreamTracker {
  active_streams: AtomicUsize,
}

impl H3PoolStreamTracker {
  pub(super) fn acquire(&self) {
    self.active_streams.fetch_add(1, Ordering::AcqRel);
  }

  pub(super) fn release(&self) -> bool {
    let previous = self.active_streams.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(
      previous > 0,
      "H3 pool stream lease released without a reservation"
    );
    previous == 1
  }

  pub(super) fn is_active(&self) -> bool {
    self.active_streams.load(Ordering::Acquire) > 0
  }
}

pub(super) struct PooledH3Lease {
  pub(super) connection: Arc<PooledH3Connection>,
  pub(super) slot: Arc<H3PoolSlot>,
  changed: Arc<Notify>,
}

impl Drop for PooledH3Lease {
  fn drop(&mut self) {
    self.connection.mark_used();
    if self.connection.streams.release() {
      self.changed.notify_waiters();
    }
  }
}

pub(super) enum PooledConnectionStatus {
  Ready,
  Closed,
  Expired,
  Idle,
}

pub(super) struct OneShotH3Connection {
  pub(super) _connected: ConnectedH3Upstream,
  pub(super) _connection_admission: AdmissionLease,
}
