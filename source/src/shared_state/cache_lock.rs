//! Lease cleanup for shared cache fill locks.

use std::sync::Arc;

use super::{Backend, CleanupDispatcher};

#[derive(Debug)]
pub struct SharedCacheLock {
  backend: Arc<Backend>,
  key: String,
  token: String,
  cleanup: Arc<CleanupDispatcher>,
  released: bool,
}

impl SharedCacheLock {
  pub(super) fn new(
    backend: Arc<Backend>,
    key: String,
    token: String,
    cleanup: Arc<CleanupDispatcher>,
  ) -> Self {
    Self {
      backend,
      key,
      token,
      cleanup,
      released: false,
    }
  }

  pub async fn unlock(&mut self) -> anyhow::Result<()> {
    if self.released {
      return Ok(());
    }
    self.backend.unlock(&self.key, &self.token).await?;
    self.released = true;
    Ok(())
  }
}

impl Drop for SharedCacheLock {
  fn drop(&mut self) {
    if !self.released {
      self
        .cleanup
        .defer_unlock(self.backend.clone(), self.key.clone(), self.token.clone());
    }
  }
}
