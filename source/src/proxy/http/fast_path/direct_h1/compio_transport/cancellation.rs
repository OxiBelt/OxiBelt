//! Drop-driven cancellation shared by the async response body and Compio worker.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Waker;

#[derive(Default)]
struct CancellationInner {
  cancelled: AtomicBool,
  driver_waker: Mutex<Option<Waker>>,
}

#[derive(Clone)]
pub(super) struct CancellationToken {
  inner: Arc<CancellationInner>,
}

pub(super) struct CancellationGuard {
  inner: Arc<CancellationInner>,
}

impl CancellationToken {
  pub(super) fn pair() -> (Self, CancellationGuard) {
    let inner = Arc::new(CancellationInner::default());
    (
      Self {
        inner: Arc::clone(&inner),
      },
      CancellationGuard { inner },
    )
  }

  pub(super) fn is_cancelled(&self) -> bool {
    self.inner.cancelled.load(Ordering::Acquire)
  }

  pub(super) fn install_driver_waker(&self, waker: Waker) {
    let mut slot = self
      .inner
      .driver_waker
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = Some(waker);
    if self.is_cancelled()
      && let Some(waker) = slot.as_ref()
    {
      waker.wake_by_ref();
    }
  }
}

impl CancellationGuard {
  fn cancel(&self) {
    if self.inner.cancelled.swap(true, Ordering::AcqRel) {
      return;
    }
    let slot = self
      .inner
      .driver_waker
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(waker) = slot.as_ref() {
      waker.wake_by_ref();
    }
  }
}

impl Drop for CancellationGuard {
  fn drop(&mut self) {
    self.cancel();
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn dropping_guard_marks_token_cancelled() {
    let (token, guard) = CancellationToken::pair();
    assert!(!token.is_cancelled());
    drop(guard);
    assert!(token.is_cancelled());
  }
}
