//! Atomic application snapshot handle.
//! Reloads publish a new snapshot without mutating the one used by in-flight requests.

use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwap;
use tokio::sync::watch;

use crate::runtime_health::RuntimeSubsystem;

use super::AppSnapshot;
#[derive(Clone)]
pub struct AppHandle {
  current: Arc<ArcSwap<AppGeneration>>,
  updates: Arc<Mutex<()>>,
}

struct AppGeneration {
  snapshot: Arc<AppSnapshot>,
  data_plane_drain: watch::Sender<bool>,
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
    snapshot.route_table.activate_bandwidth();
    let (data_plane_drain, _) = watch::channel(false);
    let snapshot = Arc::new(snapshot);
    let handle = Self {
      current: Arc::new(ArcSwap::from_pointee(AppGeneration {
        snapshot: snapshot.clone(),
        data_plane_drain,
      })),
      updates: Arc::new(Mutex::new(())),
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
    // This is the final infallible publication phase. Activate shared limiters
    // before the ArcSwap so no request can observe a new route snapshot with
    // the previous route policy.
    snapshot.route_table.activate_bandwidth();
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
    snapshot.runtime_generation = snapshot.runtime_health.allocate_generation();
    snapshot.circuit_breakers.configure(&snapshot.config);
    snapshot
      .overload
      .configure(&snapshot.config.overload, snapshot.lifecycle.as_ref());
    snapshot.route_table.activate_bandwidth();
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
    true
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
}

fn activate_published_snapshot(snapshot: &AppSnapshot, previous: Option<&AppSnapshot>) {
  #[cfg(not(feature = "admin-runtime"))]
  let _ = previous;
  #[cfg(feature = "admin-runtime")]
  if let Some(previous) = previous {
    previous.admin_audit.retire_runtime_generation();
  }
  snapshot.uploads.activate();
  snapshot
    .runtime_health
    .activate_generation(snapshot.runtime_generation);
  #[cfg(feature = "admin-runtime")]
  snapshot
    .admin_audit
    .activate_runtime_generation(snapshot.runtime_generation);
}
