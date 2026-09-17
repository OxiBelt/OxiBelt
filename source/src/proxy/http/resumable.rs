//! Typed request classification shared by resumable transport paths.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A resumable request may not be replayed after it enters an upstream path.
///
/// This marker intentionally says nothing about `Incremental`: upload
/// deadlines, admission lifetime, and final-response handling retain their
/// existing independent semantics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NoReplayRequest;

/// Request-scoped evidence that the fixed upstream returned final response
/// headers. This latch survives response-WAF replacement of the response.
#[derive(Clone, Debug, Default)]
pub(super) struct UpstreamResponseObserved(Arc<AtomicBool>);

impl UpstreamResponseObserved {
  pub(super) fn mark(&self) {
    self.0.store(true, Ordering::Release);
  }

  pub(super) fn get(&self) -> bool {
    self.0.load(Ordering::Acquire)
  }
}
