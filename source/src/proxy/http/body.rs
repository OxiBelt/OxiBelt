//! Body capture, timeout, and streaming helpers for HTTP proxying.
//! Captured prefixes are bounded because request and response bodies are attacker controlled.

use std::convert::Infallible;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Response};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::mpsc;
use tokio::time::Sleep;

use crate::limits::ConnectionPermit;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub(crate) type ProxyBody = BoxBody<Bytes, BoxError>;
pub(crate) type ProxyBodyFrame = Result<Frame<Bytes>, BoxError>;
const TIMEOUT_BODY_CHANNEL_CAPACITY: usize = 16;
pub(crate) const KNOWN_SMALL_BODY_MAX_BYTES: usize = 16 * 1024;
type TerminalBodyError = Arc<Mutex<Option<BoxError>>>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct KnownSmallResponseBody;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CompiledKnownSmallNoopResponse;

#[derive(Debug, Clone)]
pub(crate) struct InlinedKnownSmallResponseBody {
  pub(crate) data: Bytes,
  pub(crate) trailers: Option<HeaderMap>,
}

impl InlinedKnownSmallResponseBody {
  pub(crate) fn new(data: Bytes, trailers: Option<HeaderMap>) -> Self {
    Self { data, trailers }
  }

  pub(crate) fn into_parts(self) -> (Bytes, Option<HeaderMap>) {
    (self.data, self.trailers)
  }
}

pub(crate) fn is_known_small_response_body_len(len: usize) -> bool {
  len <= KNOWN_SMALL_BODY_MAX_BYTES
}

pub(crate) fn known_small_no_trailers_body(bytes: Bytes) -> ProxyBody {
  KnownSmallNoTrailersBody::new(bytes).boxed()
}

pub(crate) fn materialized_known_small_body(
  bytes: Bytes,
  trailers: Option<HeaderMap>,
) -> ProxyBody {
  let Some(trailers) = trailers else {
    return known_small_no_trailers_body(bytes);
  };

  Full::new(bytes)
    .with_trailers(std::future::ready(Some(Ok::<_, Infallible>(trailers))))
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

#[derive(Debug, Clone)]
pub(crate) struct CapturedBody {
  pub(crate) bytes: Bytes,
  pub(crate) is_truncated: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum BodyTimeoutKind {
  DownstreamRequestRead,
  UpstreamRequestSend,
  UpstreamResponseRead,
  DownstreamResponseSend,
}

impl BodyTimeoutKind {
  fn message(self) -> &'static str {
    match self {
      Self::DownstreamRequestRead => "downstream request body timed out",
      Self::UpstreamRequestSend => "upstream request body send timed out",
      Self::UpstreamResponseRead => "upstream response body read timed out",
      Self::DownstreamResponseSend => "downstream response body send timed out",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct BodyTimeoutError {
  kind: BodyTimeoutKind,
}

impl BodyTimeoutError {
  pub(crate) fn new(kind: BodyTimeoutKind) -> Self {
    Self { kind }
  }

  pub(crate) fn kind(self) -> BodyTimeoutKind {
    self.kind
  }
}

impl fmt::Display for BodyTimeoutError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.kind.message())
  }
}

impl std::error::Error for BodyTimeoutError {}

pub(crate) fn boxed_error<E>(error: E) -> BoxError
where
  E: std::error::Error + Send + Sync + 'static,
{
  Box::new(error)
}

pub(crate) fn error_is_timeout(error: &BoxError, kind: BodyTimeoutKind) -> bool {
  error
    .downcast_ref::<BodyTimeoutError>()
    .is_some_and(|error| error.kind() == kind)
}

pub(crate) fn timeout_message(kind: BodyTimeoutKind) -> &'static str {
  kind.message()
}

#[cfg(test)]
pub(crate) use super::body_capture::capture_prefix;
pub(crate) use super::body_capture::{capture_proxy_body_prefix, capture_proxy_request_prefix};

pub(crate) fn channel_body(capacity: usize) -> (mpsc::Sender<ProxyBodyFrame>, ProxyBody) {
  channel_body_with_size_hint(capacity, SizeHint::new())
}

fn channel_body_with_size_hint(
  capacity: usize,
  size_hint: SizeHint,
) -> (mpsc::Sender<ProxyBodyFrame>, ProxyBody) {
  channel_body_with_size_hint_and_terminal_error(capacity, size_hint, None)
}

fn channel_body_with_size_hint_and_terminal_error(
  capacity: usize,
  size_hint: SizeHint,
  terminal_error: Option<TerminalBodyError>,
) -> (mpsc::Sender<ProxyBodyFrame>, ProxyBody) {
  let (sender, receiver) = mpsc::channel(capacity);
  (
    sender,
    ChannelBody {
      receiver,
      size_hint,
      terminal_error,
    }
    .boxed(),
  )
}

pub(crate) fn with_read_timeout<B>(body: B, timeout: Duration, kind: BodyTimeoutKind) -> ProxyBody
where
  B: Body<Data = Bytes> + Send + Sync + 'static,
  B::Error: Into<BoxError> + Send + Sync + 'static,
{
  let size_hint = body.size_hint();

  ReadTimeoutBody {
    body: Box::pin(body),
    timeout,
    kind,
    sleep: None,
    size_hint,
  }
  .boxed()
}

pub(crate) fn error_is_body_length_limit(error: &BoxError) -> bool {
  let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error.as_ref());
  while let Some(error) = current {
    let message = error.to_string();
    if message.contains("length limit")
      || message.contains("body length")
      || message.contains("body is too large")
    {
      return true;
    }
    current = error.source();
  }
  false
}

pub(crate) fn error_indicates_body_timeout(error: &anyhow::Error, kind: BodyTimeoutKind) -> bool {
  error.chain().any(|cause| {
    cause
      .downcast_ref::<BodyTimeoutError>()
      .is_some_and(|timeout| timeout.kind() == kind)
      || cause.to_string().contains(timeout_message(kind))
  })
}

pub(crate) fn with_poll_send_timeout(
  body: ProxyBody,
  timeout: Duration,
  kind: BodyTimeoutKind,
) -> ProxyBody {
  if body.is_end_stream() {
    return body;
  }

  let size_hint = body.size_hint();
  PollSendTimeoutBody {
    body,
    timeout,
    kind,
    sleep: None,
    size_hint,
  }
  .boxed()
}

pub(crate) fn with_backpressure_send_timeout(
  mut body: ProxyBody,
  timeout: Duration,
  kind: BodyTimeoutKind,
) -> ProxyBody {
  if body.is_end_stream() {
    return body;
  }

  let size_hint = body.size_hint();
  let terminal_error = Arc::new(Mutex::new(None));
  let (sender, wrapped) = channel_body_with_size_hint_and_terminal_error(
    TIMEOUT_BODY_CHANNEL_CAPACITY,
    size_hint,
    Some(Arc::clone(&terminal_error)),
  );
  tokio::spawn(async move {
    while let Some(frame) = body.frame().await {
      let stop_after_send = frame.is_err();
      match tokio::time::timeout(timeout, sender.send(frame)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => break,
        Err(_) => {
          store_terminal_error(&terminal_error, boxed_error(BodyTimeoutError::new(kind)));
          break;
        }
      }
      if stop_after_send {
        break;
      }
    }
  });
  wrapped
}

pub(crate) fn with_drop_guard<T>(body: ProxyBody, guard: T) -> ProxyBody
where
  T: Send + Sync + Unpin + 'static,
{
  DropGuardBody {
    body,
    _guard: guard,
  }
  .boxed()
}

pub(crate) fn with_connection_permit(
  response: Response<ProxyBody>,
  permit: ConnectionPermit,
) -> Response<ProxyBody> {
  let (parts, body) = response.into_parts();
  Response::from_parts(parts, with_drop_guard(body, permit))
}

struct ChannelBody {
  receiver: mpsc::Receiver<ProxyBodyFrame>,
  size_hint: SizeHint,
  terminal_error: Option<TerminalBodyError>,
}

struct ReadTimeoutBody<B> {
  body: Pin<Box<B>>,
  timeout: Duration,
  kind: BodyTimeoutKind,
  sleep: Option<Pin<Box<Sleep>>>,
  size_hint: SizeHint,
}

struct PollSendTimeoutBody {
  body: ProxyBody,
  timeout: Duration,
  kind: BodyTimeoutKind,
  sleep: Option<Pin<Box<Sleep>>>,
  size_hint: SizeHint,
}

struct DropGuardBody<T> {
  body: ProxyBody,
  _guard: T,
}

struct KnownSmallNoTrailersBody {
  data: Option<Bytes>,
}

impl KnownSmallNoTrailersBody {
  fn new(bytes: Bytes) -> Self {
    Self {
      data: (!bytes.is_empty()).then_some(bytes),
    }
  }
}

fn store_terminal_error(terminal_error: &TerminalBodyError, error: BoxError) {
  let mut terminal_error = terminal_error
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner());
  if terminal_error.is_none() {
    *terminal_error = Some(error);
  }
}

impl ChannelBody {
  fn take_terminal_error(&self) -> Option<BoxError> {
    let terminal_error = self.terminal_error.as_ref()?;
    terminal_error
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .take()
  }
}

impl Body for ChannelBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match self.receiver.poll_recv(cx) {
      Poll::Ready(None) => Poll::Ready(self.take_terminal_error().map(Err)),
      poll => poll,
    }
  }

  fn size_hint(&self) -> SizeHint {
    self.size_hint.clone()
  }
}

impl<B> Body for ReadTimeoutBody<B>
where
  B: Body<Data = Bytes>,
  B::Error: Into<BoxError>,
{
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match self.body.as_mut().poll_frame(cx) {
      Poll::Ready(frame) => {
        self.sleep = None;
        return Poll::Ready(frame.map(|result| result.map_err(Into::into)));
      }
      Poll::Pending => {}
    }

    if self.sleep.is_none() {
      let timeout = self.timeout;
      self.sleep = Some(Box::pin(tokio::time::sleep(timeout)));
    }

    if let Some(sleep) = self.sleep.as_mut()
      && sleep.as_mut().poll(cx).is_ready()
    {
      self.sleep = None;
      return Poll::Ready(Some(Err(boxed_error(BodyTimeoutError::new(self.kind)))));
    }

    Poll::Pending
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.size_hint.clone()
  }
}

impl Body for PollSendTimeoutBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match Pin::new(&mut self.body).poll_frame(cx) {
      Poll::Ready(frame) => {
        self.sleep = None;
        return Poll::Ready(frame);
      }
      Poll::Pending => {}
    }

    if self.sleep.is_none() {
      let timeout = self.timeout;
      self.sleep = Some(Box::pin(tokio::time::sleep(timeout)));
    }

    if let Some(sleep) = self.sleep.as_mut()
      && sleep.as_mut().poll(cx).is_ready()
    {
      self.sleep = None;
      return Poll::Ready(Some(Err(boxed_error(BodyTimeoutError::new(self.kind)))));
    }

    Poll::Pending
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.size_hint.clone()
  }
}

impl<T> Body for DropGuardBody<T>
where
  T: Send + Sync + Unpin + 'static,
{
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    Pin::new(&mut self.body).poll_frame(cx)
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

impl Body for KnownSmallNoTrailersBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
  }

  fn is_end_stream(&self) -> bool {
    self.data.is_none()
  }

  fn size_hint(&self) -> SizeHint {
    match self.data.as_ref() {
      Some(data) => SizeHint::with_exact(data.len() as u64),
      None => SizeHint::with_exact(0),
    }
  }
}

#[cfg(test)]
#[path = "body_tests.rs"]
mod tests;
