//! Typed HTTP/2 WebTransport CONNECT stream handles.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_channel::{mpsc, oneshot};
use h2::{Reason, RecvStream};

use crate::proto::h2::upgrade::ResetState;
use crate::proto::h2::upgrade::SendCommand;

#[derive(Clone, Copy, Debug)]
pub(crate) struct WebTransportRequest;

/// A future for a WebTransport session accepted on an HTTP/2 CONNECT stream.
#[derive(Clone)]
pub struct OnWebTransport {
  rx: Option<Arc<Mutex<oneshot::Receiver<crate::Result<WebTransportSession>>>>>,
}

/// Obtains the typed WebTransport session future from a CONNECT request or response.
pub fn on_webtransport<T: sealed::CanWebTransport>(message: T) -> OnWebTransport {
  message.on_webtransport()
}

pub(crate) struct PendingWebTransport {
  tx: oneshot::Sender<crate::Result<WebTransportSession>>,
}

pub(crate) fn pending() -> (PendingWebTransport, OnWebTransport) {
  let (tx, rx) = oneshot::channel();
  (
    PendingWebTransport { tx },
    OnWebTransport {
      rx: Some(Arc::new(Mutex::new(rx))),
    },
  )
}

impl PendingWebTransport {
  pub(crate) fn fulfill(self, session: WebTransportSession) {
    let _ = self.tx.send(Ok(session));
  }
}

impl Future for OnWebTransport {
  type Output = crate::Result<WebTransportSession>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    match &self.rx {
      Some(rx) => Pin::new(&mut *rx.lock().expect("webtransport future poisoned"))
        .poll(cx)
        .map(|result| match result {
          Ok(result) => result,
          Err(_) => Err(crate::Error::new_closed()),
        }),
      None => Poll::Ready(Err(crate::Error::new_user_no_upgrade())),
    }
  }
}

impl fmt::Debug for OnWebTransport {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("OnWebTransport").finish()
  }
}

mod sealed {
  use super::OnWebTransport;

  pub trait CanWebTransport {
    fn on_webtransport(self) -> OnWebTransport;
  }

  impl<B> CanWebTransport for &mut http::Request<B> {
    fn on_webtransport(self) -> OnWebTransport {
      self
        .extensions_mut()
        .remove::<OnWebTransport>()
        .unwrap_or(OnWebTransport { rx: None })
    }
  }

  impl<B> CanWebTransport for &mut http::Response<B> {
    fn on_webtransport(self) -> OnWebTransport {
      self
        .extensions_mut()
        .remove::<OnWebTransport>()
        .unwrap_or(OnWebTransport { rx: None })
    }
  }
}

/// WebTransport settings captured at an HTTP/2 CONNECT boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebTransportSettings {
  /// Whether WebTransport is enabled.
  pub enabled: bool,
  /// Initial session-level data credit.
  pub initial_max_data: Option<u32>,
  /// Initial data credit for unidirectional streams.
  pub initial_max_stream_data_uni: Option<u32>,
  /// Initial data credit for locally initiated bidirectional streams.
  pub initial_max_stream_data_bidi_local: Option<u32>,
  /// Initial data credit for remotely initiated bidirectional streams.
  pub initial_max_stream_data_bidi_remote: Option<u32>,
  /// Initial cumulative credit for unidirectional streams.
  pub initial_max_streams_uni: Option<u32>,
  /// Initial cumulative credit for bidirectional streams.
  pub initial_max_streams_bidi: Option<u32>,
}

impl From<h2::webtransport::Settings> for WebTransportSettings {
  fn from(settings: h2::webtransport::Settings) -> Self {
    Self {
      enabled: settings.enabled,
      initial_max_data: settings.initial_max_data,
      initial_max_stream_data_uni: settings.initial_max_stream_data_uni,
      initial_max_stream_data_bidi_local: settings.initial_max_stream_data_bidi_local,
      initial_max_stream_data_bidi_remote: settings.initial_max_stream_data_bidi_remote,
      initial_max_streams_uni: settings.initial_max_streams_uni,
      initial_max_streams_bidi: settings.initial_max_streams_bidi,
    }
  }
}

impl From<WebTransportSettings> for h2::webtransport::Settings {
  fn from(settings: WebTransportSettings) -> Self {
    Self {
      enabled: settings.enabled,
      initial_max_data: settings.initial_max_data,
      initial_max_stream_data_uni: settings.initial_max_stream_data_uni,
      initial_max_stream_data_bidi_local: settings.initial_max_stream_data_bidi_local,
      initial_max_stream_data_bidi_remote: settings.initial_max_stream_data_bidi_remote,
      initial_max_streams_uni: settings.initial_max_streams_uni,
      initial_max_streams_bidi: settings.initial_max_streams_bidi,
    }
  }
}

/// An HTTP/2 reset reason available to a WebTransport CONNECT stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebTransportReset {
  /// The session completed without an error.
  NoError,
  /// The peer violated HTTP/2 or WebTransport framing requirements.
  ProtocolError,
  /// An internal endpoint failure occurred.
  InternalError,
  /// A flow-control limit was violated.
  FlowControlError,
  /// The peer referenced a closed stream.
  StreamClosed,
  /// The session was cancelled.
  Cancel,
  /// The session was refused before processing.
  RefusedStream,
  /// The peer exceeded a local resource limit.
  EnhanceYourCalm,
  /// The required transport security was unavailable.
  InadequateSecurity,
}

impl WebTransportReset {
  pub(crate) fn into_reason(self) -> Reason {
    match self {
      Self::NoError => Reason::NO_ERROR,
      Self::ProtocolError => Reason::PROTOCOL_ERROR,
      Self::InternalError => Reason::INTERNAL_ERROR,
      Self::FlowControlError => Reason::FLOW_CONTROL_ERROR,
      Self::StreamClosed => Reason::STREAM_CLOSED,
      Self::Cancel => Reason::CANCEL,
      Self::RefusedStream => Reason::REFUSED_STREAM,
      Self::EnhanceYourCalm => Reason::ENHANCE_YOUR_CALM,
      Self::InadequateSecurity => Reason::INADEQUATE_SECURITY,
    }
  }
}

/// A successful WebTransport CONNECT stream.
pub struct WebTransportSession {
  receive: WebTransportReceive,
  send: WebTransportSend,
  local_settings: Option<WebTransportSettings>,
  peer_settings: Option<WebTransportSettings>,
}

impl WebTransportSession {
  pub(crate) fn new(
    recv_stream: RecvStream,
    tx: mpsc::Sender<SendCommand>,
    error_rx: oneshot::Receiver<crate::Error>,
    reset: std::sync::Arc<ResetState>,
    local_settings: Option<WebTransportSettings>,
    peer_settings: Option<WebTransportSettings>,
  ) -> Self {
    Self {
      receive: WebTransportReceive { recv_stream },
      send: WebTransportSend {
        tx,
        error_rx,
        reset,
      },
      local_settings,
      peer_settings,
    }
  }

  /// Returns the locally sent settings acknowledged for this session.
  pub fn local_settings(&self) -> Option<WebTransportSettings> {
    self.local_settings
  }

  /// Returns the peer settings acknowledged for this session.
  pub fn peer_settings(&self) -> Option<WebTransportSettings> {
    self.peer_settings
  }

  /// Splits the session into independent receive and send handles.
  pub fn split(self) -> (WebTransportReceive, WebTransportSend) {
    (self.receive, self.send)
  }
}

impl fmt::Debug for WebTransportSession {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("WebTransportSession").finish()
  }
}

/// The receive half of a WebTransport CONNECT stream.
pub struct WebTransportReceive {
  recv_stream: RecvStream,
}

impl WebTransportReceive {
  /// Polls for the next HTTP/2 DATA payload without releasing receive credit.
  pub fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Option<crate::Result<Bytes>>> {
    match self.recv_stream.poll_data(cx) {
      Poll::Ready(Some(Ok(data))) => Poll::Ready(Some(Ok(data))),
      Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(crate::Error::new_body_write(error)))),
      Poll::Ready(None) => Poll::Ready(None),
      Poll::Pending => Poll::Pending,
    }
  }

  /// Releases exactly the HTTP/2 receive credit consumed by the caller.
  pub fn release_capacity(&mut self, capacity: usize) -> crate::Result<()> {
    self
      .recv_stream
      .flow_control()
      .release_capacity(capacity)
      .map_err(crate::Error::new_body_write)
  }

  /// Returns whether the peer ended the CONNECT stream.
  pub fn is_end_stream(&self) -> bool {
    self.recv_stream.is_end_stream()
  }
}

impl fmt::Debug for WebTransportReceive {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("WebTransportReceive").finish()
  }
}

/// The send half of a WebTransport CONNECT stream.
pub struct WebTransportSend {
  tx: mpsc::Sender<SendCommand>,
  error_rx: oneshot::Receiver<crate::Error>,
  reset: std::sync::Arc<ResetState>,
}

impl WebTransportSend {
  /// Polls until a DATA payload can be queued.
  pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
    match self.tx.poll_ready(cx) {
      Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
      Poll::Ready(Err(_)) => match Pin::new(&mut self.error_rx).poll(cx) {
        Poll::Ready(Ok(error)) => Poll::Ready(Err(error)),
        Poll::Ready(Err(_)) => Poll::Ready(Err(crate::Error::new_closed())),
        Poll::Pending => Poll::Pending,
      },
      Poll::Pending => Poll::Pending,
    }
  }

  /// Queues one HTTP/2 DATA payload after [`poll_ready`](Self::poll_ready) succeeds.
  pub fn send_data(&mut self, data: Bytes) -> crate::Result<()> {
    self
      .tx
      .start_send(SendCommand::Data(data))
      .map_err(|_| crate::Error::new_closed())
  }

  /// Ends the CONNECT stream after queued DATA payloads are sent.
  pub fn finish(&mut self) -> crate::Result<()> {
    self
      .tx
      .start_send(SendCommand::Finish)
      .map_err(|_| crate::Error::new_closed())
  }

  /// Resets the CONNECT stream with the selected standard HTTP/2 reason.
  pub fn reset(&mut self, reason: WebTransportReset) -> crate::Result<()> {
    self.reset.request(reason.into_reason());
    Ok(())
  }
}

impl fmt::Debug for WebTransportSend {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("WebTransportSend").finish()
  }
}
