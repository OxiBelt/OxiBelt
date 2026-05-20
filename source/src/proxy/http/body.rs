use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::Request;
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::mpsc;
use tokio::time::Sleep;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type ProxyBody = BoxBody<Bytes, BoxError>;
pub(crate) type ProxyBodyFrame = Result<Frame<Bytes>, BoxError>;
const TIMEOUT_BODY_CHANNEL_CAPACITY: usize = 16;
pub(crate) const KNOWN_SMALL_BODY_MAX_BYTES: usize = 16 * 1024;
type TerminalBodyError = Arc<Mutex<Option<BoxError>>>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct KnownSmallResponseBody;

pub(crate) fn is_known_small_response_body_len(len: usize) -> bool {
  len <= KNOWN_SMALL_BODY_MAX_BYTES
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

pub(crate) fn with_send_timeout(
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

fn store_terminal_error(terminal_error: &TerminalBodyError, error: BoxError) {
  let mut terminal_error = terminal_error
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner());
  if terminal_error.is_none() {
    *terminal_error = Some(error);
  }
}

pub(crate) async fn capture_prefix<B>(
  request: Request<B>,
  limit: usize,
) -> Result<(Request<ProxyBody>, CapturedBody), BoxError>
where
  B: Body<Data = Bytes> + Send + Sync + 'static,
  B::Error: Into<BoxError> + Send + Sync + 'static,
{
  let (parts, body) = request.into_parts();
  let content_length = parts
    .headers
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok());
  let (body, captured) = capture_body_prefix_with_length(body, limit, content_length).await?;
  Ok((Request::from_parts(parts, body), captured))
}

pub(crate) async fn capture_body_prefix<B>(
  body: B,
  limit: usize,
  content_length: Option<u64>,
) -> Result<(ProxyBody, CapturedBody), BoxError>
where
  B: Body<Data = Bytes> + Send + Sync + 'static,
  B::Error: Into<BoxError> + Send + Sync + 'static,
{
  capture_body_prefix_with_length(body, limit, content_length).await
}

async fn capture_body_prefix_with_length<B>(
  body: B,
  limit: usize,
  content_length: Option<u64>,
) -> Result<(ProxyBody, CapturedBody), BoxError>
where
  B: Body<Data = Bytes> + Send + Sync + 'static,
  B::Error: Into<BoxError> + Send + Sync + 'static,
{
  let hinted_upper = body.size_hint().upper();
  let known_body_len = content_length.or(hinted_upper);
  let mut body = Box::pin(body);
  let mut captured = BytesMut::new();
  let mut queued = VecDeque::new();
  let mut reached_end = false;
  let mut split_at_limit = false;

  while captured.len() < limit {
    let Some(frame) = body.as_mut().frame().await else {
      reached_end = true;
      break;
    };
    let frame = frame.map_err(Into::into)?;
    match frame.into_data() {
      Ok(data) => {
        let remaining = limit.saturating_sub(captured.len());
        if data.len() <= remaining {
          captured.extend_from_slice(&data);
          queued.push_back(Frame::data(data));
        } else {
          captured.extend_from_slice(&data[..remaining]);
          queued.push_back(Frame::data(data.slice(..remaining)));
          queued.push_back(Frame::data(data.slice(remaining..)));
          split_at_limit = true;
          break;
        }
      }
      Err(frame) => {
        if let Ok(trailers) = frame.into_trailers() {
          queued.push_back(Frame::trailers(trailers));
          reached_end = true;
          break;
        }
      }
    }
  }

  let is_truncated = split_at_limit
    || (!reached_end
      && known_body_len
        .map(|length| length > captured.len() as u64)
        .unwrap_or(captured.len() >= limit));
  let body = ReplayBody {
    queued,
    inner: body,
  }
  .boxed();
  Ok((
    body,
    CapturedBody {
      bytes: captured.freeze(),
      is_truncated,
    },
  ))
}

struct ReplayBody<B> {
  queued: VecDeque<Frame<Bytes>>,
  inner: Pin<Box<B>>,
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

struct DropGuardBody<T> {
  body: ProxyBody,
  _guard: T,
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
    if self.sleep.is_none() {
      let timeout = self.timeout;
      self.sleep = Some(Box::pin(tokio::time::sleep(timeout)));
    }

    match self.body.as_mut().poll_frame(cx) {
      Poll::Ready(frame) => {
        self.sleep = None;
        return Poll::Ready(frame.map(|result| result.map_err(Into::into)));
      }
      Poll::Pending => {}
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

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

impl<B> Body for ReplayBody<B>
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
    if let Some(frame) = self.queued.pop_front() {
      return Poll::Ready(Some(Ok(frame)));
    }

    self
      .inner
      .as_mut()
      .poll_frame(cx)
      .map(|frame| frame.map(|result| result.map_err(Into::into)))
  }

  fn is_end_stream(&self) -> bool {
    self.queued.is_empty() && self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}

#[cfg(test)]
mod tests {
  use bytes::Bytes;
  use http::Request;
  use http_body_util::{BodyExt, Empty, Full};
  use hyper::body::{Body as _, Frame, SizeHint};
  use std::time::Duration;

  use super::{
    BodyTimeoutKind, BoxError, TIMEOUT_BODY_CHANNEL_CAPACITY, capture_prefix, channel_body,
    error_is_timeout, with_read_timeout, with_send_timeout,
  };

  #[tokio::test]
  async fn capture_prefix_replays_full_body_after_truncation() {
    let request = Request::builder()
      .body(
        Full::new(Bytes::from_static(b"abcdef"))
          .map_err(|never| -> BoxError { match never {} })
          .boxed(),
      )
      .expect("request should build");

    let (request, captured) = capture_prefix(request, 3)
      .await
      .expect("body capture should succeed");
    assert_eq!(captured.bytes.as_ref(), b"abc");
    assert!(captured.is_truncated);

    let replayed = request
      .into_body()
      .collect()
      .await
      .expect("replayed body should collect")
      .to_bytes();
    assert_eq!(replayed.as_ref(), b"abcdef");
  }

  #[tokio::test]
  async fn capture_prefix_marks_complete_body_as_not_truncated() {
    let request = Request::builder()
      .body(
        Full::new(Bytes::from_static(b"abc"))
          .map_err(|never| -> BoxError { match never {} })
          .boxed(),
      )
      .expect("request should build");

    let (request, captured) = capture_prefix(request, 8)
      .await
      .expect("body capture should succeed");
    assert_eq!(captured.bytes.as_ref(), b"abc");
    assert!(!captured.is_truncated);

    let replayed = request
      .into_body()
      .collect()
      .await
      .expect("replayed body should collect")
      .to_bytes();
    assert_eq!(replayed.as_ref(), b"abc");
  }

  #[tokio::test]
  async fn read_timeout_body_returns_typed_timeout_error() {
    let (_sender, pending_body) = channel_body(1);
    let timed_body = with_read_timeout(
      pending_body,
      Duration::from_millis(5),
      BodyTimeoutKind::DownstreamRequestRead,
    );

    let error = timed_body
      .collect()
      .await
      .expect_err("pending body should time out");
    assert!(error_is_timeout(
      &error,
      BodyTimeoutKind::DownstreamRequestRead
    ));
  }

  #[tokio::test]
  async fn read_timeout_body_times_out_zero_size_hint_pending_body() {
    let (_sender, pending_body) = super::channel_body_with_size_hint(1, exact_zero_size_hint());
    let timed_body = with_read_timeout(
      pending_body,
      Duration::from_millis(5),
      BodyTimeoutKind::DownstreamRequestRead,
    );

    let error = timed_body
      .collect()
      .await
      .expect_err("zero-size-hint pending body should time out");
    assert!(error_is_timeout(
      &error,
      BodyTimeoutKind::DownstreamRequestRead
    ));
  }

  #[tokio::test]
  async fn capture_prefix_times_out_zero_size_hint_pending_body() {
    let (_sender, pending_body) = super::channel_body_with_size_hint(1, exact_zero_size_hint());
    let timed_body = with_read_timeout(
      pending_body,
      Duration::from_millis(5),
      BodyTimeoutKind::DownstreamRequestRead,
    );
    let request = Request::builder()
      .body(timed_body)
      .expect("request should build");

    let error = capture_prefix(request, 8)
      .await
      .expect_err("WAF-style capture should inherit body read timeout");
    assert!(error_is_timeout(
      &error,
      BodyTimeoutKind::DownstreamRequestRead
    ));
  }

  #[tokio::test]
  async fn send_timeout_body_returns_typed_timeout_after_buffered_frames() {
    let (sender, pending_body) = channel_body(TIMEOUT_BODY_CHANNEL_CAPACITY + 1);
    for _ in 0..=TIMEOUT_BODY_CHANNEL_CAPACITY {
      sender
        .send(Ok(Frame::data(Bytes::from_static(b"x"))))
        .await
        .expect("source body should accept queued frame");
    }
    drop(sender);

    let timed_body = with_send_timeout(
      pending_body,
      Duration::from_millis(5),
      BodyTimeoutKind::UpstreamRequestSend,
    );
    tokio::time::sleep(Duration::from_millis(25)).await;

    let error = timed_body
      .collect()
      .await
      .expect_err("send timeout should propagate after buffered frames");
    assert!(error_is_timeout(
      &error,
      BodyTimeoutKind::UpstreamRequestSend
    ));
  }

  #[tokio::test]
  async fn send_timeout_body_applies_to_zero_size_hint_source_body() {
    let (sender, pending_body) =
      super::channel_body_with_size_hint(TIMEOUT_BODY_CHANNEL_CAPACITY + 1, exact_zero_size_hint());
    for _ in 0..=TIMEOUT_BODY_CHANNEL_CAPACITY {
      sender
        .send(Ok(Frame::data(Bytes::from_static(b"x"))))
        .await
        .expect("source body should accept queued frame");
    }
    drop(sender);

    let timed_body = with_send_timeout(
      pending_body,
      Duration::from_millis(5),
      BodyTimeoutKind::UpstreamRequestSend,
    );
    tokio::time::sleep(Duration::from_millis(25)).await;

    let error = timed_body
      .collect()
      .await
      .expect_err("send timeout should apply even when size hint is exact zero");
    assert!(error_is_timeout(
      &error,
      BodyTimeoutKind::UpstreamRequestSend
    ));
  }

  #[tokio::test]
  async fn send_timeout_body_collects_ready_body() {
    let body = Full::new(Bytes::from_static(b"abc"))
      .map_err(|never| -> BoxError { match never {} })
      .boxed();
    let timed_body = with_send_timeout(
      body,
      Duration::from_secs(1),
      BodyTimeoutKind::DownstreamResponseSend,
    );

    let collected = timed_body
      .collect()
      .await
      .expect("ready body should collect")
      .to_bytes();
    assert_eq!(collected.as_ref(), b"abc");
  }

  #[tokio::test]
  async fn timeout_wrappers_allow_completed_empty_bodies() {
    let read_body = Empty::<Bytes>::new()
      .map_err(|never| -> BoxError { match never {} })
      .boxed();
    let read_body = with_read_timeout(
      read_body,
      Duration::from_millis(5),
      BodyTimeoutKind::DownstreamRequestRead,
    );
    let read_bytes = read_body
      .collect()
      .await
      .expect("empty read body should collect")
      .to_bytes();
    assert!(read_bytes.is_empty());

    let send_body = Empty::<Bytes>::new()
      .map_err(|never| -> BoxError { match never {} })
      .boxed();
    let send_body = with_send_timeout(
      send_body,
      Duration::from_millis(5),
      BodyTimeoutKind::DownstreamResponseSend,
    );
    assert!(send_body.is_end_stream());
    let send_bytes = send_body
      .collect()
      .await
      .expect("empty send body should collect")
      .to_bytes();
    assert!(send_bytes.is_empty());
  }

  #[tokio::test]
  async fn timeout_body_preserves_size_hint() {
    let body = Full::new(Bytes::from_static(b"abc"))
      .map_err(|never| -> BoxError { match never {} })
      .boxed();
    let timed_body = with_read_timeout(
      body,
      Duration::from_secs(1),
      BodyTimeoutKind::UpstreamResponseRead,
    );

    let size_hint = timed_body.size_hint();
    assert_eq!(size_hint.lower(), 3);
    assert_eq!(size_hint.upper(), Some(3));
  }

  #[test]
  fn known_small_response_body_threshold_is_bounded() {
    assert!(super::is_known_small_response_body_len(
      super::KNOWN_SMALL_BODY_MAX_BYTES
    ));
    assert!(!super::is_known_small_response_body_len(
      super::KNOWN_SMALL_BODY_MAX_BYTES + 1
    ));
  }

  fn exact_zero_size_hint() -> SizeHint {
    let mut size_hint = SizeHint::new();
    size_hint.set_exact(0);
    size_hint
  }
}
