//! Atomic lifecycle drain state shared by production and Loom models.

use std::fmt::Debug;
use std::sync::atomic::{AtomicU8, Ordering};

const ADMIN_DRAINING: u8 = 1 << 0;
const OVERLOAD_DRAINING: u8 = 1 << 1;
const SHUTDOWN_DRAINING: u8 = 1 << 2;

pub(super) trait AtomicDrainBits: Debug + Send + Sync + 'static {
  fn new(value: u8) -> Self;
  fn load(&self, order: Ordering) -> u8;
  fn fetch_or(&self, value: u8, order: Ordering) -> u8;
  fn fetch_and(&self, value: u8, order: Ordering) -> u8;
}

impl AtomicDrainBits for AtomicU8 {
  fn new(value: u8) -> Self {
    Self::new(value)
  }

  fn load(&self, order: Ordering) -> u8 {
    self.load(order)
  }

  fn fetch_or(&self, value: u8, order: Ordering) -> u8 {
    self.fetch_or(value, order)
  }

  fn fetch_and(&self, value: u8, order: Ordering) -> u8 {
    self.fetch_and(value, order)
  }
}

#[derive(Debug)]
pub(super) struct DrainState<A: AtomicDrainBits = AtomicU8> {
  bits: A,
}

impl<A: AtomicDrainBits> DrainState<A> {
  pub(super) fn new() -> Self {
    Self { bits: A::new(0) }
  }

  pub(super) fn is_draining(&self) -> bool {
    self.snapshot() != 0
  }

  pub(super) fn is_shutdown_draining(&self) -> bool {
    self.snapshot() & SHUTDOWN_DRAINING != 0
  }

  pub(super) fn reason(&self) -> &'static str {
    let bits = self.snapshot();
    if bits & SHUTDOWN_DRAINING != 0 {
      "shutdown"
    } else if bits & ADMIN_DRAINING != 0 {
      "admin"
    } else if bits & OVERLOAD_DRAINING != 0 {
      "overload"
    } else {
      "ready"
    }
  }

  pub(super) fn set_admin_draining(&self) {
    self.bits.fetch_or(ADMIN_DRAINING, Ordering::AcqRel);
  }

  pub(super) fn clear_admin_draining(&self) {
    self.bits.fetch_and(!ADMIN_DRAINING, Ordering::AcqRel);
  }

  pub(super) fn set_overload_draining(&self) {
    self.bits.fetch_or(OVERLOAD_DRAINING, Ordering::AcqRel);
  }

  pub(super) fn clear_overload_draining(&self) {
    self.bits.fetch_and(!OVERLOAD_DRAINING, Ordering::AcqRel);
  }

  pub(super) fn start_shutdown(&self) -> bool {
    self.bits.fetch_or(SHUTDOWN_DRAINING, Ordering::AcqRel) & SHUTDOWN_DRAINING == 0
  }

  fn snapshot(&self) -> u8 {
    self.bits.load(Ordering::Acquire)
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::Ordering;

  use loom::sync::Arc;
  use loom::sync::atomic::{AtomicU8, AtomicUsize};
  use loom::thread;

  use super::{AtomicDrainBits, DrainState};

  impl AtomicDrainBits for AtomicU8 {
    fn new(value: u8) -> Self {
      Self::new(value)
    }

    fn load(&self, order: Ordering) -> u8 {
      self.load(order)
    }

    fn fetch_or(&self, value: u8, order: Ordering) -> u8 {
      self.fetch_or(value, order)
    }

    fn fetch_and(&self, value: u8, order: Ordering) -> u8 {
      self.fetch_and(value, order)
    }
  }

  #[test]
  #[ignore = "run explicitly in the bounded Loom CI step"]
  fn loom_lifecycle_shutdown_is_monotonic_and_has_one_winner() {
    loom::model(|| {
      let state = Arc::new(DrainState::<AtomicU8>::new());
      let winners = Arc::new(AtomicUsize::new(0));

      let shutdowns = (0..2)
        .map(|_| {
          let state = state.clone();
          let winners = winners.clone();
          thread::spawn(move || {
            if state.start_shutdown() {
              winners.fetch_add(1, Ordering::Relaxed);
            }
          })
        })
        .collect::<Vec<_>>();
      let competing_drain = {
        let state = state.clone();
        thread::spawn(move || {
          state.set_admin_draining();
          state.set_overload_draining();
          state.clear_admin_draining();
          state.clear_overload_draining();
        })
      };

      for shutdown in shutdowns {
        shutdown.join().expect("shutdown thread should not panic");
      }
      competing_drain
        .join()
        .expect("competing drain thread should not panic");

      assert_eq!(winners.load(Ordering::Relaxed), 1);
      assert!(state.is_draining());
      assert!(state.is_shutdown_draining());
      assert_eq!(state.reason(), "shutdown");
    });
  }

  #[test]
  #[ignore = "run explicitly in the bounded Loom CI step"]
  fn loom_lifecycle_drain_sources_cannot_clear_each_other() {
    loom::model(|| {
      let state = Arc::new(DrainState::<AtomicU8>::new());
      let admin = {
        let state = state.clone();
        thread::spawn(move || {
          state.set_admin_draining();
          state.clear_admin_draining();
        })
      };
      let overload = {
        let state = state.clone();
        thread::spawn(move || state.set_overload_draining())
      };

      admin.join().expect("admin drain thread should not panic");
      overload
        .join()
        .expect("overload drain thread should not panic");

      assert!(state.is_draining());
      assert!(!state.is_shutdown_draining());
      assert_eq!(state.reason(), "overload");
    });
  }
}
