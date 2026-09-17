//! Request-scoped server support for informational responses.
//!
//! A service receives an [`InformationalSender`] through request extensions.
//! The connection task owns the matching receiver, which keeps response ordering
//! and protocol-specific writers inside Hyper.

use std::fmt;
use std::sync::{
  atomic::{AtomicUsize, Ordering},
  Arc,
};
use std::task::{Context, Poll};

use http::{header, Response, StatusCode};
use tokio::sync::mpsc;

/// Maximum number of informational response heads buffered for one request.
pub const MAX_INFORMATIONAL_RESPONSES: usize = 16;
/// Maximum total header bytes buffered for one request.
pub const MAX_INFORMATIONAL_HEADER_BYTES: usize = 8 * 1024;

/// Sends bounded informational responses for the request carrying this extension.
#[derive(Clone)]
pub struct InformationalSender {
  tx: mpsc::Sender<QueuedResponse>,
  state: Arc<QueueState>,
}

impl fmt::Debug for InformationalSender {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("InformationalSender")
      .finish_non_exhaustive()
  }
}

/// An error returned when an informational response cannot be queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InformationalSendError {
  /// The response status is not a supported non-switching 1xx response.
  InvalidStatus,
  /// Informational responses cannot carry framing or upgrade headers.
  ForbiddenHeader,
  /// The response would exceed the bounded header queue.
  HeaderTooLarge,
  /// The bounded per-request FIFO is full.
  Full,
  /// The final response was sent or the downstream stream was closed.
  Closed,
}

#[derive(Clone, Copy)]
pub(crate) struct ServerInformational;

struct QueueState {
  queued_header_bytes: AtomicUsize,
}

struct QueuedResponse {
  response: Response<()>,
  header_bytes: usize,
}

pub(crate) struct InformationalReceiver {
  rx: mpsc::Receiver<QueuedResponse>,
  state: Arc<QueueState>,
}

pub(crate) fn informational_channel() -> (InformationalSender, InformationalReceiver) {
  let state = Arc::new(QueueState {
    queued_header_bytes: AtomicUsize::new(0),
  });
  let (tx, rx) = mpsc::channel(MAX_INFORMATIONAL_RESPONSES);
  (
    InformationalSender {
      tx,
      state: state.clone(),
    },
    InformationalReceiver { rx, state },
  )
}

impl InformationalSender {
  /// Queue an informational response without waiting for downstream I/O.
  ///
  /// Responses are written in FIFO order before the final response. A caller
  /// must treat `Full` and `Closed` as exchange failure; Hyper intentionally
  /// never drops or reorders an accepted response.
  pub fn try_send(&self, mut response: Response<()>) -> Result<(), InformationalSendError> {
    if !response.status().is_informational() || response.status() == StatusCode::SWITCHING_PROTOCOLS
    {
      return Err(InformationalSendError::InvalidStatus);
    }
    if response.headers().contains_key(header::CONNECTION)
      || response.headers().contains_key(header::CONTENT_LENGTH)
      || response.headers().contains_key(header::TRANSFER_ENCODING)
      || response.headers().contains_key(header::UPGRADE)
    {
      return Err(InformationalSendError::ForbiddenHeader);
    }
    let header_bytes = response
      .headers()
      .iter()
      .try_fold(0usize, |total, (name, value)| {
        total
          .checked_add(name.as_str().len())
          .and_then(|total| total.checked_add(value.as_bytes().len()))
          .and_then(|total| total.checked_add(4))
      });
    let Some(header_bytes) = header_bytes else {
      return Err(InformationalSendError::HeaderTooLarge);
    };
    if !self.reserve_header_bytes(header_bytes) {
      return Err(InformationalSendError::HeaderTooLarge);
    }

    response.extensions_mut().insert(ServerInformational);
    match self.tx.try_send(QueuedResponse {
      response,
      header_bytes,
    }) {
      Ok(()) => Ok(()),
      Err(error) => {
        self.release_header_bytes(header_bytes);
        match error {
          mpsc::error::TrySendError::Full(_) => Err(InformationalSendError::Full),
          mpsc::error::TrySendError::Closed(_) => Err(InformationalSendError::Closed),
        }
      }
    }
  }

  fn reserve_header_bytes(&self, bytes: usize) -> bool {
    let mut current = self.state.queued_header_bytes.load(Ordering::Relaxed);
    loop {
      let Some(next) = current.checked_add(bytes) else {
        return false;
      };
      if next > MAX_INFORMATIONAL_HEADER_BYTES {
        return false;
      }
      match self.state.queued_header_bytes.compare_exchange_weak(
        current,
        next,
        Ordering::AcqRel,
        Ordering::Relaxed,
      ) {
        Ok(_) => return true,
        Err(observed) => current = observed,
      }
    }
  }

  fn release_header_bytes(&self, bytes: usize) {
    self
      .state
      .queued_header_bytes
      .fetch_sub(bytes, Ordering::AcqRel);
  }
}

impl InformationalReceiver {
  pub(crate) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Response<()>>> {
    match std::pin::Pin::new(&mut self.rx).poll_recv(cx) {
      Poll::Ready(Some(queued)) => {
        self
          .state
          .queued_header_bytes
          .fetch_sub(queued.header_bytes, Ordering::AcqRel);
        Poll::Ready(Some(queued.response))
      }
      Poll::Ready(None) => Poll::Ready(None),
      Poll::Pending => Poll::Pending,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rejects_switching_and_framing_headers() {
    let (sender, _receiver) = informational_channel();
    let switching = Response::builder()
      .status(StatusCode::SWITCHING_PROTOCOLS)
      .body(())
      .expect("switching response");
    assert_eq!(
      sender.try_send(switching),
      Err(InformationalSendError::InvalidStatus)
    );
    let framed = Response::builder()
      .status(StatusCode::EARLY_HINTS)
      .header(header::CONTENT_LENGTH, "0")
      .body(())
      .expect("framed response");
    assert_eq!(
      sender.try_send(framed),
      Err(InformationalSendError::ForbiddenHeader)
    );
  }

  #[test]
  fn rejects_fifo_overflow_without_dropping_an_accepted_head() {
    let (sender, _receiver) = informational_channel();
    for _ in 0..MAX_INFORMATIONAL_RESPONSES {
      let response = Response::builder()
        .status(StatusCode::EARLY_HINTS)
        .body(())
        .expect("informational response");
      assert_eq!(sender.try_send(response), Ok(()));
    }
    let response = Response::builder()
      .status(StatusCode::EARLY_HINTS)
      .body(())
      .expect("overflow response");
    assert_eq!(sender.try_send(response), Err(InformationalSendError::Full));
  }

  #[tokio::test]
  async fn receiver_pumps_fifo_and_releases_capacity() {
    let (sender, mut receiver) = informational_channel();
    for status in [100, 103, 104] {
      sender
        .try_send(
          Response::builder()
            .status(status)
            .body(())
            .expect("response"),
        )
        .expect("queue informational response");
    }

    for status in [100, 103, 104] {
      let response = futures_util::future::poll_fn(|cx| receiver.poll_recv(cx))
        .await
        .expect("queued response");
      assert_eq!(response.status().as_u16(), status);
    }

    // The receiver's write-side pump releases both count and byte budget, so
    // a later head cannot be rejected merely because an earlier one was sent.
    sender
      .try_send(Response::builder().status(104).body(()).expect("response"))
      .expect("queue after drain");
  }

  #[tokio::test]
  async fn receiver_drain_releases_header_budget_and_close_is_observable() {
    let (sender, mut receiver) = informational_channel();
    let value = "x".repeat(MAX_INFORMATIONAL_HEADER_BYTES - 16);
    let response = Response::builder()
      .status(104)
      .header("x", value)
      .body(())
      .expect("large response");
    sender.try_send(response).expect("queue large response");
    assert_eq!(
      sender.try_send(
        Response::builder()
          .status(104)
          .header("x", "overflow")
          .body(())
          .expect("overflow response")
      ),
      Err(InformationalSendError::HeaderTooLarge)
    );
    let _ = futures_util::future::poll_fn(|cx| receiver.poll_recv(cx))
      .await
      .expect("drain large response");
    sender
      .try_send(
        Response::builder()
          .status(104)
          .header("x", "reused")
          .body(())
          .expect("reused response"),
      )
      .expect("header budget released");
    drop(receiver);
    assert_eq!(
      sender.try_send(Response::builder().status(104).body(()).expect("response")),
      Err(InformationalSendError::Closed)
    );
  }
}
