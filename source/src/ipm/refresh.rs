//! IPM store refresh coordination.
//! Refreshes replace snapshots atomically so authorization reads a consistent policy set.

use std::sync::{Arc, Weak};
use std::time::Duration;

use tracing::{info, warn};

use super::{IpmRefreshState, IpmRuntimeInner};

const STORE_REFRESH_INTERVAL: Duration = Duration::from_secs(3);

pub(super) fn spawn_store_refresh_task(inner: &Arc<IpmRuntimeInner>) {
  if inner.store.is_none() {
    return;
  }
  let weak = Arc::downgrade(inner);
  tokio::spawn(async move {
    refresh_loop(weak).await;
  });
}

async fn refresh_loop(inner: Weak<IpmRuntimeInner>) {
  loop {
    tokio::time::sleep(STORE_REFRESH_INTERVAL).await;
    let Some(inner) = inner.upgrade() else {
      break;
    };
    match refresh_store_inner(&inner).await {
      Ok(true) => info!("IPM store snapshot refreshed"),
      Ok(false) => {}
      Err(error) => {
        let current_generation = inner
          .snapshot
          .read()
          .expect("IPM snapshot lock poisoned")
          .generation;
        *inner
          .last_refresh
          .write()
          .expect("IPM refresh state lock poisoned") =
          IpmRefreshState::failed(current_generation, error.to_string());
        warn!(error = %error, "failed to refresh IPM store snapshot; keeping last-good snapshot");
      }
    }
  }
}

pub(super) async fn refresh_store_inner(inner: &Arc<IpmRuntimeInner>) -> anyhow::Result<bool> {
  let Some(store) = &inner.store else {
    return Ok(false);
  };
  let next = store.load_snapshot(&inner.static_snapshot).await?;
  let mut current = inner.snapshot.write().expect("IPM snapshot lock poisoned");
  let changed = current.generation != next.generation || current.fingerprint != next.fingerprint;
  if changed {
    *current = Arc::new(next);
  }
  let generation = current.generation;
  *inner
    .last_refresh
    .write()
    .expect("IPM refresh state lock poisoned") = IpmRefreshState::ok(generation);
  Ok(changed)
}
