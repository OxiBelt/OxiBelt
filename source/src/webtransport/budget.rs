//! Process-local byte reservations retained across snapshot replacement.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub(crate) struct Budget {
  used: AtomicUsize,
}

impl Budget {
  pub(crate) fn new() -> Arc<Self> {
    Arc::new(Self {
      used: AtomicUsize::new(0),
    })
  }

  /// The active snapshot supplies its ceiling; old sessions retain their reservations.
  pub(crate) fn reserve(self: &Arc<Self>, bytes: usize, ceiling: usize) -> io::Result<Reservation> {
    self
      .used
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
        used.checked_add(bytes).filter(|next| *next <= ceiling)
      })
      .map_err(|_| io::Error::other("WebTransport buffer capacity exhausted"))?;
    Ok(Reservation {
      budget: self.clone(),
      bytes,
    })
  }

  #[cfg(test)]
  pub(crate) fn used(&self) -> usize {
    self.used.load(Ordering::Acquire)
  }
}

#[derive(Debug)]
pub(crate) struct Reservation {
  budget: Arc<Budget>,
  bytes: usize,
}

impl Drop for Reservation {
  fn drop(&mut self) {
    self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reservations_survive_lowered_reload_ceiling_and_release_exactly_once() {
    let budget = Budget::new();
    let old_session = budget.reserve(80, 100).unwrap();
    assert!(budget.reserve(1, 50).is_err());
    assert_eq!(budget.used(), 80);
    drop(old_session);
    let new_session = budget.reserve(50, 50).unwrap();
    assert!(budget.reserve(1, 50).is_err());
    drop(new_session);
    assert_eq!(budget.used(), 0);
    let full = budget.reserve(usize::MAX, usize::MAX).unwrap();
    assert!(budget.reserve(1, usize::MAX).is_err());
    drop(full);
    assert_eq!(budget.used(), 0);
  }
}
