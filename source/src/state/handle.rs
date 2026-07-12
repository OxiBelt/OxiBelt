//! Atomic application snapshot handle.
//! Reloads publish a new snapshot without mutating the one used by in-flight requests.

use std::sync::{Arc, RwLock};

use tokio::sync::watch;

use super::AppSnapshot;

#[derive(Clone)]
pub struct AppHandle {
  current: Arc<RwLock<AppGeneration>>,
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
    Self {
      current: Arc::new(RwLock::new(AppGeneration {
        snapshot: Arc::new(snapshot),
        data_plane_drain,
      })),
    }
  }

  pub fn snapshot(&self) -> Arc<AppSnapshot> {
    self
      .current
      .read()
      .expect("app snapshot lock poisoned")
      .snapshot
      .clone()
  }

  pub(crate) fn connection_snapshot(&self) -> AppConnectionSnapshot {
    let current = self.current.read().expect("app snapshot lock poisoned");
    AppConnectionSnapshot {
      snapshot: current.snapshot.clone(),
      data_plane_drain: current.data_plane_drain.subscribe(),
    }
  }

  pub fn replace(&self, snapshot: AppSnapshot) {
    snapshot
      .overload
      .configure(&snapshot.config.overload, snapshot.lifecycle.as_ref());
    let (data_plane_drain, _) = watch::channel(false);
    let previous = {
      let mut current = self.current.write().expect("app snapshot lock poisoned");
      std::mem::replace(
        &mut *current,
        AppGeneration {
          snapshot: Arc::new(snapshot),
          data_plane_drain,
        },
      )
    };
    let _ = previous.data_plane_drain.send(true);
  }

  pub(crate) fn replace_if_current(
    &self,
    expected: &Arc<AppSnapshot>,
    snapshot: AppSnapshot,
  ) -> bool {
    let snapshot = Arc::new(snapshot);
    let (data_plane_drain, _) = watch::channel(false);
    let previous = {
      let mut current = self.current.write().expect("app snapshot lock poisoned");
      if !Arc::ptr_eq(&current.snapshot, expected) {
        return false;
      }
      snapshot
        .overload
        .configure(&snapshot.config.overload, snapshot.lifecycle.as_ref());
      std::mem::replace(
        &mut *current,
        AppGeneration {
          snapshot,
          data_plane_drain,
        },
      )
    };
    let _ = previous.data_plane_drain.send(true);
    true
  }
}
