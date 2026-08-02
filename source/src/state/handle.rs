//! Atomic application snapshot handle.
//! Reloads publish a new snapshot without mutating the one used by in-flight requests.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::proxy::http::fast_path::direct_h1::{
  CompioDirectH1Service, CompioDirectH1ShutdownSummary,
};
use crate::runtime_health::{
  RuntimeSubsystem, RuntimeSubsystemState, RuntimeTaskKind, RuntimeTaskPolicy,
};

use super::AppSnapshot;
use super::compio_direct_h1::CompioDirectH1FleetReservation;

const COMPIO_DIRECT_H1_TERMINAL_CLEANUP_MIN: Duration = Duration::from_millis(100);
const COMPIO_DIRECT_H1_TERMINAL_CLEANUP_MAX: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct AppHandle {
  current: Arc<ArcSwap<AppGeneration>>,
  updates: Arc<Mutex<()>>,
  retired_compio_direct_h1: Arc<Mutex<Vec<RetiredCompioDirectH1Service>>>,
}

struct AppGeneration {
  snapshot: Arc<AppSnapshot>,
  data_plane_drain: watch::Sender<bool>,
}

struct RetiredCompioDirectH1Service {
  service: Arc<CompioDirectH1Service>,
  reservation: Option<Arc<CompioDirectH1FleetReservation>>,
  shutdown: Option<JoinHandle<()>>,
}

pub(crate) struct AppConnectionSnapshot {
  pub(crate) snapshot: Arc<AppSnapshot>,
  pub(crate) data_plane_drain: watch::Receiver<bool>,
}

impl AppHandle {
  pub fn new(snapshot: AppSnapshot) -> Self {
    snapshot
      .overload
      .configure(&snapshot.config.overload, snapshot.lifecycle.as_ref());
    let (data_plane_drain, _) = watch::channel(false);
    let snapshot = Arc::new(snapshot);
    let handle = Self {
      current: Arc::new(ArcSwap::from_pointee(AppGeneration {
        snapshot: snapshot.clone(),
        data_plane_drain,
      })),
      updates: Arc::new(Mutex::new(())),
      retired_compio_direct_h1: Arc::new(Mutex::new(Vec::new())),
    };
    activate_published_snapshot(snapshot.as_ref(), None);
    handle
  }

  pub fn snapshot(&self) -> Arc<AppSnapshot> {
    self.current.load().snapshot.clone()
  }

  pub(crate) fn connection_snapshot(&self) -> AppConnectionSnapshot {
    let current = self.current.load();
    AppConnectionSnapshot {
      snapshot: current.snapshot.clone(),
      data_plane_drain: current.data_plane_drain.subscribe(),
    }
  }

  pub fn replace(&self, mut snapshot: AppSnapshot) {
    let _update = self.update_guard();
    snapshot.runtime_generation = snapshot.runtime_health.allocate_generation();
    snapshot.circuit_breakers.configure(&snapshot.config);
    snapshot
      .overload
      .configure(&snapshot.config.overload, snapshot.lifecycle.as_ref());
    let (data_plane_drain, _) = watch::channel(false);
    let snapshot = Arc::new(snapshot);
    let previous = self.current.swap(Arc::new(AppGeneration {
      snapshot: snapshot.clone(),
      data_plane_drain,
    }));
    activate_published_snapshot(snapshot.as_ref(), Some(previous.snapshot.as_ref()));
    let _ = previous.data_plane_drain.send(true);
    previous
      .snapshot
      .direct_h2_pools
      .retire_if_replaced(&snapshot.direct_h2_pools);
    self.retire_replaced_compio_direct_h1(previous.snapshot.as_ref(), snapshot.as_ref());
  }

  pub(crate) fn replace_if_current(
    &self,
    expected: &Arc<AppSnapshot>,
    mut snapshot: AppSnapshot,
  ) -> bool {
    let _update = self.update_guard();
    let current = self.current.load_full();
    if !Arc::ptr_eq(&current.snapshot, expected) {
      return false;
    }
    if let Err(error) = snapshot.restage_direct_h2_pools_for_publication() {
      tracing::warn!(
        error = %error,
        "snapshot publication rejected while staging fresh direct-H2 pools"
      );
      return false;
    }
    if let Err(error) = snapshot.restage_compio_direct_h1_service_for_publication() {
      tracing::warn!(
        error = %error,
        "snapshot publication rejected while staging a fresh Compio direct-H1 fleet"
      );
      return false;
    }
    snapshot.runtime_generation = snapshot.runtime_health.allocate_generation();
    snapshot.circuit_breakers.configure(&snapshot.config);
    snapshot
      .overload
      .configure(&snapshot.config.overload, snapshot.lifecycle.as_ref());
    let snapshot = Arc::new(snapshot);
    let (data_plane_drain, _) = watch::channel(false);
    let previous = self.current.swap(Arc::new(AppGeneration {
      snapshot: snapshot.clone(),
      data_plane_drain,
    }));
    activate_published_snapshot(snapshot.as_ref(), Some(previous.snapshot.as_ref()));
    let _ = previous.data_plane_drain.send(true);
    previous
      .snapshot
      .direct_h2_pools
      .retire_if_replaced(&snapshot.direct_h2_pools);
    self.retire_replaced_compio_direct_h1(previous.snapshot.as_ref(), snapshot.as_ref());
    true
  }

  pub(crate) fn begin_compio_direct_h1_drain(&self) {
    if let Some(service) = self.snapshot().compio_direct_h1_service.as_ref() {
      service.begin_drain();
    }
    for retired in self.retired_compio_guard().iter() {
      retired.service.begin_drain();
    }
  }

  pub(crate) async fn shutdown_compio_direct_h1(
    &self,
    deadline: tokio::time::Instant,
  ) -> CompioDirectH1ShutdownSummary {
    let (service_deadline, terminal_deadline) =
      compio_direct_h1_shutdown_deadlines(deadline, tokio::time::Instant::now());
    match tokio::time::timeout_at(
      terminal_deadline,
      self.shutdown_compio_direct_h1_inner(service_deadline),
    )
    .await
    {
      Ok(summary) => summary,
      Err(_) => abort_compio_direct_h1_terminal_overrun("process shutdown"),
    }
  }

  async fn shutdown_compio_direct_h1_inner(
    &self,
    deadline: tokio::time::Instant,
  ) -> CompioDirectH1ShutdownSummary {
    self.begin_compio_direct_h1_drain();
    let current_snapshot = self.snapshot();
    let current = current_snapshot.compio_direct_h1_service.clone();
    let current_reservation = current_snapshot.compio_direct_h1_fleet_reservation.clone();
    let retired = std::mem::take(&mut *self.retired_compio_guard());
    let mut services = retired
      .iter()
      .map(|entry| entry.service.clone())
      .collect::<Vec<_>>();
    if let Some(current) = current
      && !services
        .iter()
        .any(|service| Arc::ptr_eq(service, &current))
    {
      services.push(current);
    }
    let summaries =
      futures_util::future::join_all(services.iter().map(|service| service.shutdown(deadline)))
        .await;
    for retired in retired {
      if let Some(shutdown) = retired.shutdown {
        let _ = shutdown.await;
      }
      if let Some(reservation) = retired.reservation {
        reservation.release();
      }
    }
    if let Some(reservation) = current_reservation {
      reservation.release();
    }
    aggregate_compio_direct_h1_shutdown(summaries)
  }

  fn update_guard(&self) -> MutexGuard<'_, ()> {
    match self.updates.lock() {
      Ok(guard) => guard,
      Err(poisoned) => {
        let health = self.snapshot().runtime_health.clone();
        health.record_lock_recovery(RuntimeSubsystem::AppState);
        self.updates.clear_poison();
        poisoned.into_inner()
      }
    }
  }

  fn retire_replaced_compio_direct_h1(&self, previous: &AppSnapshot, active: &AppSnapshot) {
    let Some(previous_service) = previous.compio_direct_h1_service.as_ref() else {
      return;
    };
    if active
      .compio_direct_h1_service
      .as_ref()
      .is_some_and(|service| Arc::ptr_eq(service, previous_service))
    {
      return;
    }
    previous_service.begin_drain();
    let service = previous_service.clone();
    let reservation = previous.compio_direct_h1_fleet_reservation.clone();
    let shutdown_reservation = reservation.clone();
    let shutdown_service = service.clone();
    let current = self.current.clone();
    let timeout =
      std::time::Duration::from_millis(previous.config.runtime.drain.graceful_timeout_ms);
    let shutdown = match tokio::runtime::Handle::try_current() {
      Ok(runtime) => Some(runtime.spawn(async move {
        let started_at = tokio::time::Instant::now();
        let deadline = started_at + timeout;
        let (service_deadline, terminal_deadline) =
          compio_direct_h1_shutdown_deadlines(deadline, started_at);
        let summary = match tokio::time::timeout_at(
          terminal_deadline,
          shutdown_service.shutdown(service_deadline),
        )
        .await
        {
          Ok(summary) => summary,
          Err(_) => abort_compio_direct_h1_terminal_overrun("retired fleet shutdown"),
        };
        tracing::info!(
          workers_started = summary.workers_started,
          workers_joined = summary.workers_joined,
          worker_failures = summary.worker_failures,
          operations_cancelled = summary.operations_cancelled,
          queued_operations_rejected = summary.queued_operations_rejected,
          "retired Compio direct-H1 service completed bounded shutdown"
        );
        if let Some(reservation) = shutdown_reservation {
          reservation.release();
        }
        let active = current.load().snapshot.clone();
        publish_compio_direct_h1_health(active.as_ref());
      })),
      Err(_) => {
        tracing::warn!(
          "Compio direct-H1 replacement service deferred its bounded shutdown until a Tokio runtime is available"
        );
        None
      }
    };
    let mut retired = self.retired_compio_guard();
    retired.retain(|entry| {
      entry
        .shutdown
        .as_ref()
        .is_none_or(|shutdown| !shutdown.is_finished())
    });
    retired.push(RetiredCompioDirectH1Service {
      service,
      reservation,
      shutdown,
    });
  }

  fn retired_compio_guard(&self) -> MutexGuard<'_, Vec<RetiredCompioDirectH1Service>> {
    match self.retired_compio_direct_h1.lock() {
      Ok(retired) => retired,
      Err(poisoned) => {
        let retired = poisoned.into_inner();
        self.retired_compio_direct_h1.clear_poison();
        self
          .snapshot()
          .runtime_health
          .record_lock_recovery(RuntimeSubsystem::CompioDirectH1);
        retired
      }
    }
  }
}

fn compio_direct_h1_shutdown_deadlines(
  configured_deadline: tokio::time::Instant,
  now: tokio::time::Instant,
) -> (tokio::time::Instant, tokio::time::Instant) {
  let drain_window = configured_deadline.saturating_duration_since(now);
  if drain_window.is_zero() {
    return (now, configured_deadline);
  }
  let cleanup_reserve = drain_window
    .clamp(
      COMPIO_DIRECT_H1_TERMINAL_CLEANUP_MIN,
      COMPIO_DIRECT_H1_TERMINAL_CLEANUP_MAX,
    )
    .min(drain_window);
  let service_deadline = configured_deadline
    .checked_sub(cleanup_reserve)
    .unwrap_or(now)
    .max(now);
  (service_deadline, configured_deadline)
}

fn abort_compio_direct_h1_terminal_overrun(context: &'static str) -> ! {
  tracing::error!(
    context,
    "Compio direct-H1 workers did not return terminal FD and buffer ownership before the hard cleanup deadline; aborting the process rather than detaching native workers"
  );
  std::process::abort()
}

fn aggregate_compio_direct_h1_shutdown(
  summaries: Vec<CompioDirectH1ShutdownSummary>,
) -> CompioDirectH1ShutdownSummary {
  summaries.into_iter().fold(
    CompioDirectH1ShutdownSummary::default(),
    |mut aggregate, summary| {
      aggregate.workers_started = aggregate
        .workers_started
        .saturating_add(summary.workers_started);
      aggregate.workers_joined = aggregate
        .workers_joined
        .saturating_add(summary.workers_joined);
      aggregate.worker_failures = aggregate
        .worker_failures
        .saturating_add(summary.worker_failures);
      aggregate.operations_cancelled = aggregate
        .operations_cancelled
        .saturating_add(summary.operations_cancelled);
      aggregate.queued_operations_rejected = aggregate
        .queued_operations_rejected
        .saturating_add(summary.queued_operations_rejected);
      aggregate
    },
  )
}

fn activate_published_snapshot(snapshot: &AppSnapshot, previous: Option<&AppSnapshot>) {
  #[cfg(not(feature = "admin-runtime"))]
  let _ = previous;
  #[cfg(feature = "admin-runtime")]
  if let Some(previous) = previous {
    previous.admin_audit.retire_runtime_generation();
  }
  snapshot.activate_compio_direct_h1_service();
  snapshot
    .runtime_health
    .activate_generation(snapshot.runtime_generation);
  publish_compio_direct_h1_health(snapshot);
  #[cfg(feature = "admin-runtime")]
  snapshot
    .admin_audit
    .activate_runtime_generation(snapshot.runtime_generation);
}

fn publish_compio_direct_h1_health(snapshot: &AppSnapshot) {
  let required = snapshot
    .compio_direct_h1_service
    .as_ref()
    .is_some_and(|service| service.is_required());
  let task_policy = if required {
    RuntimeTaskPolicy::RestartableCritical
  } else {
    RuntimeTaskPolicy::RestartableOptional
  };
  // Publish the optimistic state before checking the live endpoints. An
  // endpoint failure racing activation then either wins this write or is
  // observed below, so activation cannot overwrite a real failure.
  snapshot.runtime_health.set_subsystem_state(
    snapshot.runtime_generation,
    RuntimeSubsystem::CompioDirectH1,
    RuntimeSubsystemState::Healthy,
    required,
  );
  snapshot.runtime_health.set_task_state(
    snapshot.runtime_generation,
    RuntimeTaskKind::CompioDirectH1Worker,
    task_policy,
    RuntimeSubsystemState::Healthy,
  );
  if snapshot
    .compio_direct_h1_service
    .as_ref()
    .is_some_and(|service| !service.is_healthy())
  {
    snapshot.runtime_health.set_subsystem_state(
      snapshot.runtime_generation,
      RuntimeSubsystem::CompioDirectH1,
      RuntimeSubsystemState::Failed,
      required,
    );
    snapshot.runtime_health.set_task_state(
      snapshot.runtime_generation,
      RuntimeTaskKind::CompioDirectH1Worker,
      task_policy,
      RuntimeSubsystemState::Failed,
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn terminal_cleanup_reserve_stays_inside_configured_drain_policy() {
    let now = tokio::time::Instant::now();
    let long_drain = now + Duration::from_secs(30);
    assert_eq!(
      compio_direct_h1_shutdown_deadlines(long_drain, now),
      (
        long_drain - COMPIO_DIRECT_H1_TERMINAL_CLEANUP_MAX,
        long_drain
      )
    );

    let short_drain = now + Duration::from_millis(40);
    assert_eq!(
      compio_direct_h1_shutdown_deadlines(short_drain, now),
      (now, short_drain)
    );
  }
}
