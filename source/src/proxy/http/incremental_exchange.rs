//! Shared lifetime tracking for RFC 10036 incremental exchanges.
//!
//! Request and response bodies are deliberately tracked independently: a
//! successful early response is not permission to stop forwarding the request.

use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::task::AtomicWaker;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::body::{BoxError, ProxyBody, boxed_error};

/// Owns resources for an incremental request until both transfer directions
/// have reached a terminal state.
#[derive(Clone)]
pub(crate) struct IncrementalExchange {
  inner: Arc<IncrementalExchangeInner>,
}

struct IncrementalExchangeInner {
  terminal_halves: AtomicU8,
  unstarted_upload: AtomicBool,
  upload_outcome: AtomicU8,
  upload_deadline: OnceLock<Instant>,
  upload_deadline_armed: AtomicBool,
  upload_completion: Notify,
  cancelled: AtomicBool,
  cancellation: Notify,
  request_waker: AtomicWaker,
  response_waker: AtomicWaker,
  failure: Mutex<Option<IncrementalExchangeFailure>>,
  retained: Mutex<Vec<Box<dyn Send + 'static>>>,
}

impl IncrementalExchange {
  pub(crate) fn new() -> Self {
    Self::with_optional_upload_deadline(None)
  }

  pub(crate) fn with_upload_deadline(deadline: Instant) -> Self {
    Self::with_optional_upload_deadline(Some(deadline))
  }

  fn with_optional_upload_deadline(upload_deadline: Option<Instant>) -> Self {
    let deadline = OnceLock::new();
    if let Some(upload_deadline) = upload_deadline {
      let _ = deadline.set(upload_deadline);
    }
    Self {
      inner: Arc::new(IncrementalExchangeInner {
        terminal_halves: AtomicU8::new(0),
        unstarted_upload: AtomicBool::new(false),
        upload_outcome: AtomicU8::new(UPLOAD_ACTIVE),
        upload_deadline: deadline,
        upload_deadline_armed: AtomicBool::new(false),
        upload_completion: Notify::new(),
        cancelled: AtomicBool::new(false),
        cancellation: Notify::new(),
        request_waker: AtomicWaker::new(),
        response_waker: AtomicWaker::new(),
        failure: Mutex::new(None),
        retained: Mutex::new(Vec::new()),
      }),
    }
  }

  /// Retain a connection or admission resource until both halves terminate.
  pub(crate) fn retain<T>(&self, value: T)
  where
    T: Send + 'static,
  {
    let mut retained = self
      .inner
      .retained
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    retained.push(Box::new(value));
    drop(retained);
    self.release_if_complete();
  }

  pub(crate) fn is_cancelled(&self) -> bool {
    self.inner.cancelled.load(Ordering::Acquire)
  }

  pub(crate) fn failure(&self) -> Option<String> {
    self
      .inner
      .failure
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .as_ref()
      .map(ToString::to_string)
  }

  pub(crate) fn cancellation_error(&self) -> BoxError {
    match self
      .inner
      .failure
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .clone()
    {
      Some(IncrementalExchangeFailure::UploadDeadline) => {
        boxed_error(IncrementalUploadDeadlineError)
      }
      Some(IncrementalExchangeFailure::Message(message)) => {
        boxed_error(IncrementalExchangeError::new(message))
      }
      None => boxed_error(IncrementalExchangeError::new(
        "incremental exchange cancelled",
      )),
    }
  }

  pub(crate) fn cancel(&self) {
    let _ = self.inner.upload_outcome.compare_exchange(
      UPLOAD_ACTIVE,
      UPLOAD_CANCELLED,
      Ordering::AcqRel,
      Ordering::Acquire,
    );
    if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
      self.inner.cancellation.notify_waiters();
      self.inner.request_waker.wake();
      self.inner.response_waker.wake();
    }
  }

  /// Arm cancellation for the interval before an upstream response is safely
  /// handed to the final downstream response owner.
  pub(crate) fn begin_response(&self) -> IncrementalResponseGuard {
    IncrementalResponseGuard {
      exchange: Some(self.clone()),
    }
  }

  /// Arm both halves until a managed transport uploader takes ownership.
  pub(crate) fn begin_dispatch(&self) -> IncrementalDispatchGuard {
    IncrementalDispatchGuard {
      exchange: Some(self.clone()),
    }
  }

  /// Cover an H3 body that has not yet been handed to its managed uploader.
  /// A response guard that unwinds before `claim_unstarted_upload` will mark
  /// this half complete after cancellation.
  pub(crate) fn arm_unstarted_upload(&self) {
    self.inner.unstarted_upload.store(true, Ordering::Release);
  }

  /// Transfer an armed raw H3 upload to the transport-local dispatch guard.
  pub(crate) fn claim_unstarted_upload(&self) -> bool {
    self.inner.unstarted_upload.swap(false, Ordering::AcqRel)
  }

  pub(crate) fn upload_deadline(&self) -> Option<Instant> {
    self.inner.upload_deadline.get().copied()
  }

  pub(crate) fn set_upload_deadline(&self, deadline: Instant) -> Instant {
    *self.inner.upload_deadline.get_or_init(|| deadline)
  }

  /// Start the post-header H1/H2 deadline without depending on Hyper polling
  /// the request body. H3 enforces the same stored deadline in its uploader.
  pub(crate) fn arm_upload_deadline(&self) {
    let Some(deadline) = self.upload_deadline() else {
      return;
    };
    if self.upload_is_complete() || self.is_cancelled() {
      return;
    }
    if self
      .inner
      .upload_deadline_armed
      .swap(true, Ordering::AcqRel)
    {
      return;
    }
    if Instant::now() >= deadline {
      self.expire_upload_deadline();
      return;
    }
    let exchange = self.clone();
    tokio::spawn(async move {
      tokio::select! {
        biased;
        () = exchange.upload_completed() => {}
        () = exchange.cancelled() => {}
        () = tokio::time::sleep_until(deadline) => exchange.expire_upload_deadline(),
      }
    });
  }

  pub(crate) fn fail_upload(&self, message: impl Into<String>) {
    self.store_failure(message.into());
    self.cancel();
    self.mark_upload_complete();
  }

  /// Signal an upload failure to the peer half without claiming that an
  /// owning transport has finished its reset/FIN operation yet.
  pub(crate) fn signal_upload_failure(&self, message: impl Into<String>) {
    self.store_failure(message.into());
    self.cancel();
  }

  /// Signal a receive-side failure without claiming the final downstream
  /// response has finished sending.
  pub(crate) fn signal_response_failure(&self, message: impl Into<String>) {
    self.store_failure(message.into());
    self.cancel();
  }

  pub(crate) fn fail_response(&self, message: impl Into<String>) {
    self.store_failure(message.into());
    self.cancel();
    self.mark_response_complete();
  }

  pub(crate) fn mark_upload_complete(&self) {
    let _ = self.inner.upload_outcome.compare_exchange(
      UPLOAD_ACTIVE,
      UPLOAD_COMPLETED,
      Ordering::AcqRel,
      Ordering::Acquire,
    );
    self.inner.unstarted_upload.store(false, Ordering::Release);
    self.mark_terminal_half(UPLOAD_COMPLETE);
    self.inner.upload_completion.notify_waiters();
  }

  pub(crate) fn mark_response_complete(&self) {
    self.mark_terminal_half(RESPONSE_COMPLETE);
  }

  pub(crate) fn is_complete(&self) -> bool {
    self.inner.terminal_halves.load(Ordering::Acquire) == BOTH_COMPLETE
  }

  pub(crate) fn response_is_complete(&self) -> bool {
    self.inner.terminal_halves.load(Ordering::Acquire) & RESPONSE_COMPLETE != 0
  }

  fn upload_is_complete(&self) -> bool {
    self.inner.terminal_halves.load(Ordering::Acquire) & UPLOAD_COMPLETE != 0
  }

  async fn upload_completed(&self) {
    loop {
      let notified = self.inner.upload_completion.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      if self.upload_is_complete() {
        return;
      }
      notified.await;
    }
  }

  pub(crate) async fn cancelled(&self) {
    loop {
      let notified = self.inner.cancellation.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      if self.is_cancelled() {
        return;
      }
      notified.await;
    }
  }

  fn expire_upload_deadline(&self) {
    if self
      .inner
      .upload_outcome
      .compare_exchange(
        UPLOAD_ACTIVE,
        UPLOAD_DEADLINE_EXPIRED,
        Ordering::AcqRel,
        Ordering::Acquire,
      )
      .is_err()
    {
      return;
    }
    self.store_failure_kind(IncrementalExchangeFailure::UploadDeadline);
    self.cancel();
  }

  fn store_failure(&self, message: String) {
    self.store_failure_kind(IncrementalExchangeFailure::Message(message));
  }

  fn store_failure_kind(&self, value: IncrementalExchangeFailure) {
    let mut failure = self
      .inner
      .failure
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if failure.is_none() {
      *failure = Some(value);
    }
  }

  fn release_if_complete(&self) {
    if !self.is_complete() {
      return;
    }
    let retained = std::mem::take(
      &mut *self
        .inner
        .retained
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    // Retained resources can contain response/request body guards whose Drop
    // paths notify this exchange. Never run those Drops while holding the
    // mutex they may re-enter.
    drop(retained);
  }

  fn mark_terminal_half(&self, half: u8) {
    // A pair of independent stores and loads can each observe only their own
    // completion on separate CPUs. `fetch_or` establishes one coherent state:
    // the call that observes both bits releases retained resources.
    let terminal_halves = self.inner.terminal_halves.fetch_or(half, Ordering::AcqRel) | half;
    if terminal_halves == BOTH_COMPLETE {
      self.release_if_complete();
    }
  }
}

const UPLOAD_COMPLETE: u8 = 0b01;
const RESPONSE_COMPLETE: u8 = 0b10;
const BOTH_COMPLETE: u8 = UPLOAD_COMPLETE | RESPONSE_COMPLETE;
const UPLOAD_ACTIVE: u8 = 0;
const UPLOAD_COMPLETED: u8 = 1;
const UPLOAD_CANCELLED: u8 = 2;
const UPLOAD_DEADLINE_EXPIRED: u8 = 3;

/// Wrap a downstream request body so response cancellation interrupts a
/// pending body read and so request EOF participates in exchange lifetime.
pub(crate) fn wrap_request_body(body: ProxyBody, exchange: IncrementalExchange) -> ProxyBody {
  wrap_request_body_inner(body, exchange, true)
}

/// Wrap a request source owned by a transport that must acknowledge its final
/// frame separately (HTTP/3 `finish`/`stop_stream`, for example).
pub(crate) fn wrap_request_body_for_transport(
  body: ProxyBody,
  exchange: IncrementalExchange,
) -> ProxyBody {
  wrap_request_body_inner(body, exchange, false)
}

fn wrap_request_body_inner(
  body: ProxyBody,
  exchange: IncrementalExchange,
  mark_upload_on_terminal_source: bool,
) -> ProxyBody {
  let terminal = body.is_end_stream();
  if terminal && mark_upload_on_terminal_source {
    exchange.mark_upload_complete();
  }
  IncrementalRequestBody {
    body,
    exchange,
    terminal,
    mark_upload_on_terminal_source,
    upload_completion_on_drop: false,
  }
  .boxed()
}

/// Wrap an upstream response body so a clean EOF leaves an in-flight upload
/// alone, while an abandoned response cancels it.
pub(crate) fn wrap_response_body(body: ProxyBody, exchange: IncrementalExchange) -> ProxyBody {
  wrap_response_body_with_length(body, exchange, None)
}

/// Wrap the final downstream response body, optionally recognizing a
/// validated, trailer-free Content-Length boundary that the downstream H1
/// encoder can complete without polling source EOF.
pub(crate) fn wrap_response_body_with_length(
  body: ProxyBody,
  exchange: IncrementalExchange,
  remaining_response_bytes: Option<u64>,
) -> ProxyBody {
  let terminal = remaining_response_bytes == Some(0)
    || (body.is_end_stream() && remaining_response_bytes.is_none());
  if terminal {
    exchange.mark_response_complete();
  }
  IncrementalResponseBody {
    body,
    exchange,
    terminal,
    remaining_response_bytes,
  }
  .boxed()
}

/// Observe the upstream response stream while it is transformed into the
/// final downstream body. Source EOF is not downstream completion: queued
/// bandwidth/output bytes can still be pending after it is observed.
pub(crate) fn observe_upstream_response_body(
  body: ProxyBody,
  exchange: IncrementalExchange,
) -> ProxyBody {
  let terminal = body.is_end_stream();
  IncrementalUpstreamResponseObserver {
    body,
    exchange,
    terminal,
  }
  .boxed()
}

struct IncrementalRequestBody {
  body: ProxyBody,
  exchange: IncrementalExchange,
  terminal: bool,
  mark_upload_on_terminal_source: bool,
  upload_completion_on_drop: bool,
}

impl Body for IncrementalRequestBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.exchange.is_cancelled() {
      self.terminal = true;
      self.upload_completion_on_drop = self.mark_upload_on_terminal_source;
      return Poll::Ready(Some(Err(self.exchange.cancellation_error())));
    }
    self.exchange.inner.request_waker.register(cx.waker());
    if self.exchange.is_cancelled() {
      self.terminal = true;
      self.upload_completion_on_drop = self.mark_upload_on_terminal_source;
      return Poll::Ready(Some(Err(self.exchange.cancellation_error())));
    }
    match Pin::new(&mut self.body).poll_frame(cx) {
      Poll::Ready(None) => {
        self.terminal = true;
        if self.mark_upload_on_terminal_source {
          self.exchange.mark_upload_complete();
        }
        Poll::Ready(None)
      }
      Poll::Ready(Some(Err(error))) => {
        self.terminal = true;
        self.exchange.signal_upload_failure(error.to_string());
        self.upload_completion_on_drop = self.mark_upload_on_terminal_source;
        Poll::Ready(Some(Err(error)))
      }
      poll => poll,
    }
  }

  fn is_end_stream(&self) -> bool {
    // Force a terminal poll. A transport can otherwise drop an underlying
    // empty body without giving this wrapper a chance to record its half.
    self.terminal
  }

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

impl Drop for IncrementalRequestBody {
  fn drop(&mut self) {
    if !self.terminal {
      self.exchange.cancel();
      if self.mark_upload_on_terminal_source {
        self.exchange.mark_upload_complete();
      }
    } else if self.upload_completion_on_drop {
      self.exchange.mark_upload_complete();
    }
  }
}

struct IncrementalUpstreamResponseObserver {
  body: ProxyBody,
  exchange: IncrementalExchange,
  terminal: bool,
}

impl Body for IncrementalUpstreamResponseObserver {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match Pin::new(&mut self.body).poll_frame(cx) {
      Poll::Ready(None) => {
        self.terminal = true;
        Poll::Ready(None)
      }
      Poll::Ready(Some(Err(error))) => {
        self.terminal = true;
        self.exchange.signal_response_failure(error.to_string());
        Poll::Ready(Some(Err(error)))
      }
      poll => poll,
    }
  }

  fn is_end_stream(&self) -> bool {
    // Force a terminal poll so clean source EOF cannot be mistaken for the
    // completion of the final bandwidth/output producer.
    self.terminal
  }

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

impl Drop for IncrementalUpstreamResponseObserver {
  fn drop(&mut self) {
    if !self.terminal && !self.exchange.response_is_complete() {
      self.exchange.cancel();
    }
  }
}

struct IncrementalResponseBody {
  body: ProxyBody,
  exchange: IncrementalExchange,
  terminal: bool,
  remaining_response_bytes: Option<u64>,
}

impl Body for IncrementalResponseBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.exchange.inner.response_waker.register(cx.waker());
    if let Some(message) = self.exchange.failure() {
      self.terminal = true;
      self.exchange.mark_response_complete();
      return Poll::Ready(Some(Err(boxed_error(IncrementalExchangeError::new(
        message,
      )))));
    }
    match Pin::new(&mut self.body).poll_frame(cx) {
      Poll::Ready(None) => {
        self.terminal = true;
        if self
          .remaining_response_bytes
          .is_some_and(|remaining| remaining > 0)
        {
          let message = "downstream response body ended before Content-Length boundary";
          self.exchange.fail_response(message);
          return Poll::Ready(Some(Err(boxed_error(IncrementalExchangeError::new(
            message,
          )))));
        }
        self.exchange.mark_response_complete();
        Poll::Ready(None)
      }
      Poll::Ready(Some(Err(error))) => {
        self.terminal = true;
        self.exchange.fail_response(error.to_string());
        Poll::Ready(Some(Err(error)))
      }
      Poll::Ready(Some(Ok(frame))) => {
        if let (Some(remaining), Some(data)) = (self.remaining_response_bytes, frame.data_ref()) {
          let data_len = data.len() as u64;
          if data_len == remaining {
            self.remaining_response_bytes = Some(0);
            self.terminal = true;
            self.exchange.mark_response_complete();
          } else if data_len < remaining {
            self.remaining_response_bytes = Some(remaining - data_len);
          } else {
            let message = "downstream response body exceeded Content-Length boundary";
            self.terminal = true;
            self.exchange.fail_response(message);
            return Poll::Ready(Some(Err(boxed_error(IncrementalExchangeError::new(
              message,
            )))));
          }
        }
        Poll::Ready(Some(Ok(frame)))
      }
      poll => poll,
    }
  }

  fn is_end_stream(&self) -> bool {
    // Do not report a delegated empty body as complete until `poll_frame`
    // records the response half. Callers are otherwise allowed to drop an
    // `is_end_stream` body without polling it, which would incorrectly abort
    // an upload that is still in progress.
    self.terminal
  }

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

impl Drop for IncrementalResponseBody {
  fn drop(&mut self) {
    if !self.terminal {
      self.exchange.cancel();
      self.exchange.mark_response_complete();
    }
  }
}

#[derive(Clone, Debug)]
enum IncrementalExchangeFailure {
  Message(String),
  UploadDeadline,
}

impl fmt::Display for IncrementalExchangeFailure {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Message(message) => formatter.write_str(message),
      Self::UploadDeadline => IncrementalUploadDeadlineError.fmt(formatter),
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IncrementalUploadDeadlineError;

impl fmt::Display for IncrementalUploadDeadlineError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("incremental upload deadline timed out")
  }
}

impl std::error::Error for IncrementalUploadDeadlineError {}

#[derive(Debug)]
struct IncrementalExchangeError {
  message: String,
}

impl IncrementalExchangeError {
  fn new(message: impl Into<String>) -> Self {
    Self {
      message: message.into(),
    }
  }
}

impl fmt::Display for IncrementalExchangeError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::error::Error for IncrementalExchangeError {}

/// Cancels a pre-header/pre-handoff exchange unless explicitly disarmed.
pub(crate) struct IncrementalResponseGuard {
  exchange: Option<IncrementalExchange>,
}

impl IncrementalResponseGuard {
  pub(crate) fn disarm(mut self) {
    self.exchange.take();
  }
}

impl Drop for IncrementalResponseGuard {
  fn drop(&mut self) {
    if let Some(exchange) = self.exchange.take() {
      exchange.cancel();
      if exchange.claim_unstarted_upload() {
        exchange.mark_upload_complete();
      }
      exchange.mark_response_complete();
    }
  }
}

/// Covers the fallible interval before a transport has spawned its uploader.
pub(crate) struct IncrementalDispatchGuard {
  exchange: Option<IncrementalExchange>,
}

impl IncrementalDispatchGuard {
  /// Transfer upload ownership to the managed sender. The returned guard still
  /// protects the response handoff, but its Drop leaves upload completion to
  /// the sender's FIN/reset path.
  pub(crate) fn uploader_started(mut self) -> IncrementalResponseGuard {
    IncrementalResponseGuard {
      exchange: self.exchange.take(),
    }
  }
}

impl Drop for IncrementalDispatchGuard {
  fn drop(&mut self) {
    if let Some(exchange) = self.exchange.take() {
      exchange.cancel();
      exchange.mark_upload_complete();
      exchange.mark_response_complete();
    }
  }
}

#[cfg(test)]
mod tests;
