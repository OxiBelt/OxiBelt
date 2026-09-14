//! HTTP/3 pooled-stream leases and connection retirement checks.

use std::future::Future;
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
  connected: Option<ConnectedH3Upstream>,
  connection_admission: Option<AdmissionLease>,
  incremental_drain: Option<IncrementalOneShotDrain>,
}

struct IncrementalOneShotDrain {
  exchange: crate::proxy::http::incremental_exchange::IncrementalExchange,
  timeout: Duration,
  deadline_cap: Option<Instant>,
}

impl OneShotH3Connection {
  pub(super) fn new(connected: ConnectedH3Upstream, admission: AdmissionLease) -> Self {
    Self {
      connected: Some(connected),
      connection_admission: Some(admission),
      incremental_drain: None,
    }
  }

  pub(super) fn incremental(
    connected: ConnectedH3Upstream,
    admission: AdmissionLease,
    exchange: crate::proxy::http::incremental_exchange::IncrementalExchange,
    timeout: Duration,
    deadline_cap: Option<Instant>,
  ) -> Self {
    Self {
      connected: Some(connected),
      connection_admission: Some(admission),
      incremental_drain: Some(IncrementalOneShotDrain {
        exchange,
        timeout,
        deadline_cap,
      }),
    }
  }
}

impl Drop for OneShotH3Connection {
  fn drop(&mut self) {
    let Some(drain) = self.incremental_drain.take() else {
      return;
    };
    // Failures and downstream cancellation do not need a final clean-FIN
    // grace period. Drop normally closes the transport in those cases.
    if drain.exchange.is_cancelled() || drain.exchange.failure().is_some() {
      return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
      // Shutdown/no-runtime fallback: retaining an unsendable guard would be
      // unbounded, so normal Drop closes it immediately.
      return;
    };
    let (Some(connected), Some(admission)) =
      (self.connected.take(), self.connection_admission.take())
    else {
      return;
    };
    let deadline = one_shot_drain_deadline(drain.timeout, drain.deadline_cap);
    handle.spawn(async move {
      let close_wait_connection = connected.connection.clone();
      drain_retained_one_shot(
        (connected, admission),
        drain.exchange,
        close_wait_connection.closed(),
        deadline,
      )
      .await;
    });
  }
}

fn one_shot_drain_deadline(
  timeout: Duration,
  deadline_cap: Option<Instant>,
) -> tokio::time::Instant {
  let now = tokio::time::Instant::now();
  let deadline = now.checked_add(timeout).unwrap_or(now);
  deadline_cap
    .map(tokio::time::Instant::from_std)
    .map_or(deadline, |cap| cap.min(deadline))
}

async fn drain_retained_one_shot<T, F>(
  retained: T,
  exchange: crate::proxy::http::incremental_exchange::IncrementalExchange,
  connection_closed: F,
  deadline: tokio::time::Instant,
) where
  F: Future,
{
  if !exchange.is_cancelled() && exchange.failure().is_none() {
    tokio::select! {
      // Quinn resolves this for a peer close or its negotiated idle timeout.
      _ = connection_closed => {}
      () = exchange.cancelled() => {}
      _ = tokio::time::sleep_until(deadline) => {}
    }
  }
  drop(retained);
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::AtomicBool;

  use super::*;

  struct Guard(Arc<AtomicBool>);

  impl Drop for Guard {
    fn drop(&mut self) {
      self.0.store(true, Ordering::Release);
    }
  }

  fn clean_exchange() -> crate::proxy::http::incremental_exchange::IncrementalExchange {
    let exchange = crate::proxy::http::incremental_exchange::IncrementalExchange::new();
    exchange.mark_upload_complete();
    exchange.mark_response_complete();
    exchange
  }

  #[tokio::test]
  async fn drain_retains_guard_until_connection_closes() {
    let exchange = clean_exchange();
    let released = Arc::new(AtomicBool::new(false));
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(drain_retained_one_shot(
      Guard(Arc::clone(&released)),
      exchange,
      async move {
        let _ = started_tx.send(());
        let _ = closed_rx.await;
      },
      tokio::time::Instant::now() + Duration::from_secs(1),
    ));

    started_rx
      .await
      .expect("drain should await connection close");
    assert!(!released.load(Ordering::Acquire));
    let _ = closed_tx.send(());
    task.await.expect("drain task should not panic");
    assert!(released.load(Ordering::Acquire));
  }

  #[tokio::test]
  async fn drain_releases_guard_at_timeout_cap() {
    let released = Arc::new(AtomicBool::new(false));
    drain_retained_one_shot(
      Guard(Arc::clone(&released)),
      clean_exchange(),
      std::future::pending::<()>(),
      tokio::time::Instant::now(),
    )
    .await;
    assert!(released.load(Ordering::Acquire));
  }

  #[tokio::test]
  async fn drain_releases_guard_when_exchange_is_cancelled() {
    let exchange = clean_exchange();
    let released = Arc::new(AtomicBool::new(false));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(drain_retained_one_shot(
      Guard(Arc::clone(&released)),
      exchange.clone(),
      async move {
        let _ = started_tx.send(());
        std::future::pending::<()>().await;
      },
      tokio::time::Instant::now() + Duration::from_secs(1),
    ));

    started_rx.await.expect("drain should await cancellation");
    assert!(!released.load(Ordering::Acquire));
    exchange.cancel();
    task.await.expect("drain task should not panic");
    assert!(released.load(Ordering::Acquire));
  }
}
