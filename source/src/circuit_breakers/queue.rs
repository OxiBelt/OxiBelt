//! Cancellation-safe ownership of a queued admission entry.

use std::sync::Arc;

use super::runtime::CircuitBreakerRuntime;

/// Removes a queued admission if its caller is cancelled while waiting.
pub(super) struct QueuedWaiter {
  runtime: Arc<CircuitBreakerRuntime>,
  id: Option<u64>,
}

impl QueuedWaiter {
  pub(super) fn new(runtime: Arc<CircuitBreakerRuntime>) -> Self {
    Self { runtime, id: None }
  }

  pub(super) fn id(&self) -> Option<u64> {
    self.id
  }

  pub(super) fn set(&mut self, id: u64) {
    debug_assert!(self.id.is_none(), "queued waiter must have one queue entry");
    self.id = Some(id);
  }

  pub(super) fn take(&mut self) -> Option<u64> {
    self.id.take()
  }

  pub(super) fn remove(&mut self) {
    self.runtime.remove_waiter(self.id.take());
  }
}

impl Drop for QueuedWaiter {
  fn drop(&mut self) {
    self.remove();
  }
}
