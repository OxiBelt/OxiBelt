//! Drop-driven cancellation shared by the async response body and Compio worker.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::task::AtomicWaker;

const ACTIVE: u8 = 0;
const CANCELLED: u8 = 1;
const DISARMED: u8 = 2;

#[derive(Default)]
struct CancellationInner {
  state: AtomicU8,
  cancelled_at: Mutex<Option<Instant>>,
  listener_waker: AtomicWaker,
}

#[derive(Clone)]
pub(in crate::proxy::http::fast_path::direct_h1) struct CancellationToken {
  inner: Arc<CancellationInner>,
}

pub(in crate::proxy::http::fast_path::direct_h1) struct CancellationGuard {
  inner: Arc<CancellationInner>,
}

struct CancellationListener<'a> {
  token: &'a CancellationToken,
}

impl Future for CancellationListener<'_> {
  type Output = ();

  fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    if self.token.is_cancelled() {
      return Poll::Ready(());
    }
    self.token.inner.listener_waker.register(context.waker());
    if self.token.is_cancelled() {
      Poll::Ready(())
    } else {
      Poll::Pending
    }
  }
}

impl Drop for CancellationListener<'_> {
  fn drop(&mut self) {
    // A normal I/O or handoff completion drops its losing cancellation branch.
    // Remove that branch's waker so the later response-body guard teardown
    // cannot issue a stale cross-thread wake into the Compio runtime.
    self.token.inner.listener_waker.take();
  }
}

impl CancellationToken {
  pub(in crate::proxy::http::fast_path::direct_h1) fn pair() -> (Self, CancellationGuard) {
    let inner = Arc::new(CancellationInner::default());
    (
      Self {
        inner: Arc::clone(&inner),
      },
      CancellationGuard { inner },
    )
  }

  pub(in crate::proxy::http::fast_path::direct_h1) fn is_cancelled(&self) -> bool {
    self.inner.state.load(Ordering::Acquire) == CANCELLED
  }

  pub(in crate::proxy::http::fast_path::direct_h1) fn identity(&self) -> usize {
    Arc::as_ptr(&self.inner) as usize
  }

  pub(in crate::proxy::http::fast_path::direct_h1) fn cancel(&self) {
    if self.inner.state.load(Ordering::Acquire) != ACTIVE {
      return;
    }
    {
      let mut cancelled_at = self
        .inner
        .cancelled_at
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
      *cancelled_at = Some(Instant::now());
      if self
        .inner
        .state
        .compare_exchange(ACTIVE, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
      {
        // `DISARMED` is terminal. Clear the speculative timestamp when a
        // completed operation wins the race instead of overwriting it with a
        // late body-drop cancellation.
        *cancelled_at = None;
        return;
      }
    }
    self.inner.listener_waker.wake();
  }

  pub(in crate::proxy::http::fast_path::direct_h1) fn disarm(&self) {
    let _ =
      self
        .inner
        .state
        .compare_exchange(ACTIVE, DISARMED, Ordering::AcqRel, Ordering::Acquire);
  }

  pub(in crate::proxy::http::fast_path::direct_h1) fn cancellation_elapsed(
    &self,
  ) -> Option<Duration> {
    if !self.is_cancelled() {
      return None;
    }
    self
      .inner
      .cancelled_at
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .map(|cancelled_at| cancelled_at.elapsed())
  }

  pub(in crate::proxy::http::fast_path::direct_h1) async fn cancelled(&self) {
    // Each physical direct-H1 operation owns one cancellation listener. The
    // pre-check/register/post-check sequence is the single-listener
    // `AtomicWaker` contract and prevents a lost wake racing registration.
    CancellationListener { token: self }.await
  }
}

impl CancellationGuard {
  fn cancel(&self) {
    CancellationToken {
      inner: Arc::clone(&self.inner),
    }
    .cancel();
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
  use std::sync::atomic::AtomicUsize;
  use std::task::Waker;

  use futures_util::task::{ArcWake, waker};

  struct WakeCounter(AtomicUsize);

  impl ArcWake for WakeCounter {
    fn wake_by_ref(arc_self: &Arc<Self>) {
      arc_self.0.fetch_add(1, Ordering::Relaxed);
    }
  }

  #[test]
  fn dropping_guard_marks_token_cancelled() {
    let (token, guard) = CancellationToken::pair();
    assert!(!token.is_cancelled());
    drop(guard);
    assert!(token.is_cancelled());
  }

  #[tokio::test]
  async fn registered_listener_wakes_when_guard_drops() {
    let (token, guard) = CancellationToken::pair();
    let waiter = tokio::spawn(async move { token.cancelled().await });
    tokio::task::yield_now().await;
    drop(guard);
    tokio::time::timeout(Duration::from_millis(100), waiter)
      .await
      .expect("registered cancellation listener must wake")
      .expect("cancellation listener task must complete");
  }

  #[test]
  fn dropped_listener_clears_its_registered_waker() {
    let (token, guard) = CancellationToken::pair();
    let wake_counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker: Waker = waker(Arc::clone(&wake_counter));
    let mut context = Context::from_waker(&waker);
    let mut listener = Box::pin(CancellationListener { token: &token });

    assert!(listener.as_mut().poll(&mut context).is_pending());
    drop(listener);
    drop(guard);

    assert_eq!(wake_counter.0.load(Ordering::Relaxed), 0);
    assert!(token.is_cancelled());
  }

  #[test]
  fn disarmed_token_ignores_late_body_guard_drop() {
    let (token, guard) = CancellationToken::pair();
    token.disarm();
    drop(guard);

    assert!(!token.is_cancelled());
    assert_eq!(token.inner.state.load(Ordering::Acquire), DISARMED);
  }
}
