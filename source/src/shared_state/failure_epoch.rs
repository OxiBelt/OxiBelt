//! Coherent shared-state degradation epochs shared by production and Loom models.

use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) trait AtomicFailureEpoch: Debug + Send + Sync + 'static {
  fn new(value: u64) -> Self;
  fn load(&self, order: Ordering) -> u64;
  fn compare_exchange(
    &self,
    current: u64,
    new: u64,
    success: Ordering,
    failure: Ordering,
  ) -> Result<u64, u64>;
  fn swap(&self, value: u64, order: Ordering) -> u64;
}

impl AtomicFailureEpoch for AtomicU64 {
  fn new(value: u64) -> Self {
    Self::new(value)
  }

  fn load(&self, order: Ordering) -> u64 {
    self.load(order)
  }

  fn compare_exchange(
    &self,
    current: u64,
    new: u64,
    success: Ordering,
    failure: Ordering,
  ) -> Result<u64, u64> {
    self.compare_exchange(current, new, success, failure)
  }

  fn swap(&self, value: u64, order: Ordering) -> u64 {
    self.swap(value, order)
  }
}

#[derive(Debug)]
pub(super) struct FailureEpoch<A: AtomicFailureEpoch = AtomicU64> {
  degraded_since_ms: A,
}

impl<A: AtomicFailureEpoch> FailureEpoch<A> {
  pub(super) fn new() -> Self {
    Self {
      degraded_since_ms: A::new(0),
    }
  }

  /// Records the first failure in an epoch. Returns true only to the caller
  /// that transitioned the state from healthy to degraded.
  pub(super) fn record_failure(&self, now_ms: u64) -> bool {
    self
      .degraded_since_ms
      .compare_exchange(0, now_ms.max(1), Ordering::AcqRel, Ordering::Acquire)
      .is_ok()
  }

  /// Ends the active failure epoch. Returns true only once per epoch.
  pub(super) fn record_success(&self) -> bool {
    self.degraded_since_ms.swap(0, Ordering::AcqRel) != 0
  }

  pub(super) fn is_degraded(&self) -> bool {
    self.degraded_since_ms() != 0
  }

  pub(super) fn degraded_since_ms(&self) -> u64 {
    self.degraded_since_ms.load(Ordering::Acquire)
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::Ordering;

  use loom::sync::Arc;
  use loom::sync::atomic::{AtomicU64, AtomicUsize};
  use loom::thread;

  use super::{AtomicFailureEpoch, FailureEpoch};

  impl AtomicFailureEpoch for AtomicU64 {
    fn new(value: u64) -> Self {
      Self::new(value)
    }

    fn load(&self, order: Ordering) -> u64 {
      self.load(order)
    }

    fn compare_exchange(
      &self,
      current: u64,
      new: u64,
      success: Ordering,
      failure: Ordering,
    ) -> Result<u64, u64> {
      self.compare_exchange(current, new, success, failure)
    }

    fn swap(&self, value: u64, order: Ordering) -> u64 {
      self.swap(value, order)
    }
  }

  #[test]
  #[ignore = "run explicitly in the bounded Loom CI step"]
  fn loom_shared_state_failure_epoch_has_single_failure_and_recovery_edges() {
    loom::model(|| {
      let epoch = Arc::new(FailureEpoch::<AtomicU64>::new());
      let failure_edges = Arc::new(AtomicUsize::new(0));
      let failures = [11_u64, 22_u64].map(|timestamp| {
        let epoch = epoch.clone();
        let failure_edges = failure_edges.clone();
        thread::spawn(move || {
          if epoch.record_failure(timestamp) {
            failure_edges.fetch_add(1, Ordering::Relaxed);
          }
        })
      });
      for failure in failures {
        failure.join().expect("failure thread should not panic");
      }

      assert_eq!(failure_edges.load(Ordering::Relaxed), 1);
      assert!(matches!(epoch.degraded_since_ms(), 11 | 22));
      assert!(epoch.is_degraded());

      let recovery_edges = Arc::new(AtomicUsize::new(0));
      let recoveries = (0..2)
        .map(|_| {
          let epoch = epoch.clone();
          let recovery_edges = recovery_edges.clone();
          thread::spawn(move || {
            if epoch.record_success() {
              recovery_edges.fetch_add(1, Ordering::Relaxed);
            }
          })
        })
        .collect::<Vec<_>>();
      for recovery in recoveries {
        recovery.join().expect("recovery thread should not panic");
      }

      assert_eq!(recovery_edges.load(Ordering::Relaxed), 1);
      assert!(!epoch.is_degraded());
      assert_eq!(epoch.degraded_since_ms(), 0);
    });
  }

  #[test]
  #[ignore = "run explicitly in the bounded Loom CI step"]
  fn loom_shared_state_failure_success_and_snapshot_are_linearizable() {
    loom::model(|| {
      let epoch = Arc::new(FailureEpoch::<AtomicU64>::new());
      let failure_edges = Arc::new(AtomicUsize::new(0));
      let recovery_edges = Arc::new(AtomicUsize::new(0));
      let observed = Arc::new(AtomicU64::new(u64::MAX));

      let failure = {
        let epoch = epoch.clone();
        let failure_edges = failure_edges.clone();
        thread::spawn(move || {
          if epoch.record_failure(17) {
            failure_edges.fetch_add(1, Ordering::Relaxed);
          }
        })
      };
      let success = {
        let epoch = epoch.clone();
        let recovery_edges = recovery_edges.clone();
        thread::spawn(move || {
          if epoch.record_success() {
            recovery_edges.fetch_add(1, Ordering::Relaxed);
          }
        })
      };
      let snapshot = {
        let epoch = epoch.clone();
        let observed = observed.clone();
        thread::spawn(move || {
          observed.store(epoch.degraded_since_ms(), Ordering::Relaxed);
        })
      };

      failure.join().expect("failure thread should not panic");
      success.join().expect("success thread should not panic");
      snapshot.join().expect("snapshot thread should not panic");

      assert_eq!(failure_edges.load(Ordering::Relaxed), 1);
      assert!(matches!(observed.load(Ordering::Relaxed), 0 | 17));
      match recovery_edges.load(Ordering::Relaxed) {
        0 => assert_eq!(epoch.degraded_since_ms(), 17),
        1 => assert_eq!(epoch.degraded_since_ms(), 0),
        other => panic!("unexpected recovery edge count {other}"),
      }
    });
  }
}
