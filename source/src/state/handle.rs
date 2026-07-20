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
    let (data_plane_drain, _) = watch::channel(false);
    activate_published_snapshot(&snapshot, None);
    Self {
      current: Arc::new(ArcSwap::from_pointee(AppGeneration {
        snapshot: Arc::new(snapshot),
        data_plane_drain,
      })),
      updates: Arc::new(Mutex::new(())),
    }
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
    snapshot.runtime_generation = snapshot.runtime_health.allocate_generation();
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
  snapshot
    .runtime_health
    .activate_generation(snapshot.runtime_generation);
  #[cfg(feature = "admin-runtime")]
  snapshot
    .admin_audit
    .activate_runtime_generation(snapshot.runtime_generation);
}
