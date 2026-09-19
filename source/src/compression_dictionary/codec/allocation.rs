//! Hard allocation ceiling for the infallible Shared Brotli allocator interface.
//! A private unwind payload crosses only Rust frames and is converted to I/O
//! failure at the codec boundary. No panic hook runs on a budget refusal.
#[cfg(panic = "abort")]
compile_error!(
  "the bounded Brotli dictionary codec requires panic=unwind to recover allocation refusals"
);

use brotli::{Allocator, SliceWrapper, SliceWrapperMut};
use std::{
  io,
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
};

const HEAP_LIMIT: usize = 384 * 1024 * 1024;
struct Budget {
  live: AtomicUsize,
  maximum: usize,
}
#[derive(Clone)]
pub(super) struct BoundedAlloc(Arc<Budget>);
impl Default for BoundedAlloc {
  fn default() -> Self {
    Self(Arc::new(Budget {
      live: AtomicUsize::new(0),
      maximum: HEAP_LIMIT,
    }))
  }
}
#[derive(Debug)]
struct AllocationDenied;
fn denied() -> ! {
  std::panic::resume_unwind(Box::new(AllocationDenied))
}

pub(super) struct Cell<T> {
  data: Vec<T>,
  charge: Option<(Arc<Budget>, usize)>,
}
impl<T> Default for Cell<T> {
  fn default() -> Self {
    Self {
      data: Vec::new(),
      charge: None,
    }
  }
}
impl<T> SliceWrapper<T> for Cell<T> {
  fn slice(&self) -> &[T] {
    &self.data
  }
}
impl<T> SliceWrapperMut<T> for Cell<T> {
  fn slice_mut(&mut self) -> &mut [T] {
    &mut self.data
  }
}
impl<T> Drop for Cell<T> {
  fn drop(&mut self) {
    // Field destructors run after this method. Free the backing allocation
    // first so another allocator clone cannot reuse its charge prematurely.
    drop(std::mem::take(&mut self.data));
    if let Some((budget, bytes)) = &self.charge {
      budget.live.fetch_sub(*bytes, Ordering::AcqRel);
    }
  }
}
impl<T: Clone + Default> Allocator<T> for BoundedAlloc {
  type AllocatedMemory = Cell<T>;
  fn alloc_cell(&mut self, count: usize) -> Cell<T> {
    let Some(bytes) = count.checked_mul(std::mem::size_of::<T>()) else {
      denied()
    };
    if self
      .0
      .live
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
        live
          .checked_add(bytes)
          .filter(|next| *next <= self.0.maximum)
      })
      .is_err()
    {
      denied();
    }
    let mut cell = Cell {
      data: Vec::new(),
      charge: Some((self.0.clone(), bytes)),
    };
    if cell.data.try_reserve_exact(count).is_err() {
      denied();
    }
    cell.data.resize(count, T::default());
    cell
  }
  fn free_cell(&mut self, cell: Cell<T>) {
    drop(cell);
  }
}
impl brotli::enc::BrotliAlloc for BoundedAlloc {}

pub(super) fn catch<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
  match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
    Ok(result) => result,
    Err(payload) if payload.is::<AllocationDenied>() => Err(io::Error::other(
      "dictionary Brotli allocation budget exceeded",
    )),
    Err(payload) => std::panic::resume_unwind(payload),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn denial_releases_all_prior_cells() {
    let mut allocator = BoundedAlloc(Arc::new(Budget {
      live: AtomicUsize::new(0),
      maximum: 8,
    }));
    let result = catch(|| {
      let _first: Cell<u32> = allocator.alloc_cell(2);
      let _second: Cell<u8> = allocator.alloc_cell(1);
      Ok(())
    });
    assert!(result.is_err());
    assert_eq!(allocator.0.live.load(Ordering::Acquire), 0);
  }

  #[test]
  fn typed_allocator_clones_share_one_budget() {
    let mut first = BoundedAlloc(Arc::new(Budget {
      live: AtomicUsize::new(0),
      maximum: 8,
    }));
    let mut second = first.clone();
    let words: Cell<u32> = first.alloc_cell(2);
    assert!(
      catch(|| {
        let _: Cell<u8> = second.alloc_cell(1);
        Ok(())
      })
      .is_err()
    );
    assert_eq!(first.0.live.load(Ordering::Acquire), 8);
    drop(words);
    let bytes: Cell<u8> = second.alloc_cell(8);
    assert_eq!(first.0.live.load(Ordering::Acquire), 8);
    drop(bytes);
    assert_eq!(first.0.live.load(Ordering::Acquire), 0);
  }

  #[test]
  fn arithmetic_and_capacity_failures_release_the_charge() {
    let mut allocator = BoundedAlloc(Arc::new(Budget {
      live: AtomicUsize::new(0),
      maximum: usize::MAX,
    }));
    assert!(
      catch(|| {
        let _: Cell<u64> = allocator.alloc_cell(usize::MAX);
        Ok(())
      })
      .is_err()
    );
    assert_eq!(allocator.0.live.load(Ordering::Acquire), 0);
    // This fits usize but exceeds Vec's isize::MAX allocation bound. It
    // deterministically exercises try_reserve_exact failure without OOM.
    assert!(
      catch(|| {
        let _: Cell<u8> = allocator.alloc_cell(usize::MAX);
        Ok(())
      })
      .is_err()
    );
    assert_eq!(allocator.0.live.load(Ordering::Acquire), 0);
  }

  #[test]
  fn charge_is_held_through_element_destruction() {
    struct Probe {
      budget: Arc<Budget>,
      observed: Arc<AtomicUsize>,
    }
    impl Drop for Probe {
      fn drop(&mut self) {
        self
          .observed
          .store(self.budget.live.load(Ordering::Acquire), Ordering::Release);
      }
    }
    let bytes = std::mem::size_of::<Probe>();
    let budget = Arc::new(Budget {
      live: AtomicUsize::new(bytes),
      maximum: bytes,
    });
    let observed = Arc::new(AtomicUsize::new(0));
    let cell = Cell {
      data: vec![Probe {
        budget: budget.clone(),
        observed: observed.clone(),
      }],
      charge: Some((budget.clone(), bytes)),
    };
    drop(cell);
    assert_eq!(observed.load(Ordering::Acquire), bytes);
    assert_eq!(budget.live.load(Ordering::Acquire), 0);
  }

  #[test]
  fn unrelated_panics_propagate_and_release_allocations() {
    let mut allocator = BoundedAlloc(Arc::new(Budget {
      live: AtomicUsize::new(0),
      maximum: 8,
    }));
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _ = catch(|| -> io::Result<()> {
        let _cell: Cell<u64> = allocator.alloc_cell(1);
        std::panic::resume_unwind(Box::new(42_u32));
      });
    }))
    .unwrap_err();
    assert_eq!(*panic.downcast::<u32>().unwrap(), 42);
    assert_eq!(allocator.0.live.load(Ordering::Acquire), 0);
  }

  #[test]
  fn concurrent_clones_cannot_overbook_budget() {
    let allocator = BoundedAlloc(Arc::new(Budget {
      live: AtomicUsize::new(0),
      maximum: 8,
    }));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
      let mut allocator = allocator.clone();
      let barrier = barrier.clone();
      threads.push(std::thread::spawn(move || {
        barrier.wait();
        let cell: io::Result<Cell<u64>> = catch(|| Ok(allocator.alloc_cell(1)));
        // Retain the winning allocation until both contenders have attempted.
        barrier.wait();
        cell.is_ok()
      }));
    }
    assert_eq!(
      threads
        .into_iter()
        .map(|thread| usize::from(thread.join().unwrap()))
        .sum::<usize>(),
      1
    );
    assert_eq!(allocator.0.live.load(Ordering::Acquire), 0);
  }

  #[test]
  fn decoder_constructor_denial_is_recoverable() {
    let allocator = BoundedAlloc(Arc::new(Budget {
      live: AtomicUsize::new(0),
      maximum: 8,
    }));
    let result = catch(|| {
      let _state =
        brotli::BrotliState::new_strict(allocator.clone(), allocator.clone(), allocator.clone());
      Ok(())
    });
    assert!(result.is_err());
    assert_eq!(allocator.0.live.load(Ordering::Acquire), 0);
  }

  #[test]
  fn encoder_constructor_denial_is_recoverable() {
    let allocator = BoundedAlloc(Arc::new(Budget {
      live: AtomicUsize::new(0),
      maximum: 8,
    }));
    let result = catch(|| {
      let mut input = io::Cursor::new(b"dictionary dictionary");
      let mut output = Vec::new();
      let params = brotli::enc::backward_references::BrotliEncoderParams {
        quality: 3,
        lgwin: 24,
        ..Default::default()
      };
      brotli::BrotliCompressCustomIoCustomDict(
        &mut brotli::IoReaderWrapper(&mut input),
        &mut brotli::IoWriterWrapper(&mut output),
        &mut [0_u8; 256],
        &mut [0_u8; 256],
        &params,
        allocator.clone(),
        &mut |_, _, _, _| {},
        b"dictionary",
        io::Error::other("input"),
      )
      .map(|_| ())
    });
    assert!(result.is_err());
    assert_eq!(allocator.0.live.load(Ordering::Acquire), 0);
  }
}
