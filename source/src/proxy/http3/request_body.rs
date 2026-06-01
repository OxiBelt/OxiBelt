use std::fmt;
use std::future::{Future, poll_fn};
use std::task::{Context, Poll};

use ::http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use ::http::{Method, Request};
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty};
use hyper::body::Frame;

use crate::proxy::http::body::{BoxError, ProxyBody, boxed_error, channel_body};

use super::{H3_BODY_CHANNEL_CAPACITY, H3RequestRecvStream};

pub(super) async fn prepare_h3_request_body(
  request: Request<()>,
  stream: H3RequestRecvStream,
) -> Request<ProxyBody> {
  prepare_h3_request_body_with_spawner(request, stream, &TokioBodyTaskSpawner).await
}

trait H3RequestBodyStream: Send + 'static {
  type Error: fmt::Display + Send + Sync + 'static;

  fn is_end_stream(&self) -> bool {
    false
  }

  fn poll_recv_data_bytes(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Bytes>, Self::Error>>;

  fn recv_data_bytes(
    &mut self,
  ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_;
}

impl H3RequestBodyStream for H3RequestRecvStream {
  type Error = h3::error::StreamError;

  fn poll_recv_data_bytes(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Bytes>, Self::Error>> {
    self.poll_recv_data(cx).map(|result| {
      result.map(|chunk| {
        chunk.map(|mut chunk| {
          let len = chunk.remaining();
          chunk.copy_to_bytes(len)
        })
      })
    })
  }

  async fn recv_data_bytes(&mut self) -> Result<Option<Bytes>, Self::Error> {
    self.recv_data().await.map(|chunk| {
      chunk.map(|mut chunk| {
        let len = chunk.remaining();
        chunk.copy_to_bytes(len)
      })
    })
  }
}

trait BodyTaskSpawner {
  fn spawn_request_body_task<F>(&self, future: F)
  where
    F: Future<Output = ()> + Send + 'static;
}

struct TokioBodyTaskSpawner;

impl BodyTaskSpawner for TokioBodyTaskSpawner {
  fn spawn_request_body_task<F>(&self, future: F)
  where
    F: Future<Output = ()> + Send + 'static,
  {
    tokio::spawn(future);
  }
}

async fn prepare_h3_request_body_with_spawner<S, Spawner>(
  request: Request<()>,
  mut stream: S,
  spawner: &Spawner,
) -> Request<ProxyBody>
where
  S: H3RequestBodyStream,
  Spawner: BodyTaskSpawner,
{
  let first = match poll_h3_request_body_once(&mut stream).await {
    None if h3_request_body_empty_probe_allowed(request.method(), request.headers()) => {
      if stream.is_end_stream() {
        Some(Ok(None))
      } else {
        tokio::task::yield_now().await;
        if stream.is_end_stream() {
          Some(Ok(None))
        } else {
          poll_h3_request_body_once(&mut stream).await
        }
      }
    }
    first => first,
  };

  match first {
    Some(Ok(None)) => {
      let (parts, _) = request.into_parts();
      drop(stream);
      Request::from_parts(parts, empty_body())
    }
    Some(Ok(Some(chunk))) => {
      stream_h3_request_body_with_initial(request, stream, Some(Ok(Frame::data(chunk))), spawner)
    }
    Some(Err(error)) => stream_h3_request_body_with_initial(
      request,
      stream,
      Some(Err(downstream_h3_request_body_error(error))),
      spawner,
    ),
    None => stream_h3_request_body(request, stream, spawner),
  }
}

async fn poll_h3_request_body_once<S>(stream: &mut S) -> Option<Result<Option<Bytes>, S::Error>>
where
  S: H3RequestBodyStream,
{
  poll_fn(|cx| match stream.poll_recv_data_bytes(cx) {
    Poll::Ready(result) => Poll::Ready(Some(result)),
    Poll::Pending => Poll::Ready(None),
  })
  .await
}

fn h3_request_body_empty_probe_allowed(method: &Method, headers: &::http::HeaderMap) -> bool {
  matches!(method, &Method::GET | &Method::HEAD)
    && !headers.contains_key(CONTENT_LENGTH)
    && !headers.contains_key(TRANSFER_ENCODING)
}

fn stream_h3_request_body<S, Spawner>(
  request: Request<()>,
  stream: S,
  spawner: &Spawner,
) -> Request<ProxyBody>
where
  S: H3RequestBodyStream,
  Spawner: BodyTaskSpawner,
{
  stream_h3_request_body_with_initial(request, stream, None, spawner)
}

fn stream_h3_request_body_with_initial<S, Spawner>(
  request: Request<()>,
  stream: S,
  initial_frame: Option<Result<Frame<Bytes>, BoxError>>,
  spawner: &Spawner,
) -> Request<ProxyBody>
where
  S: H3RequestBodyStream,
  Spawner: BodyTaskSpawner,
{
  let (parts, _) = request.into_parts();
  let (body_sender, body) = channel_body(H3_BODY_CHANNEL_CAPACITY);
  let mut stream = stream;
  let initial_is_error = initial_frame.as_ref().is_some_and(Result::is_err);
  spawner.spawn_request_body_task(async move {
    if let Some(frame) = initial_frame
      && body_sender.send(frame).await.is_err()
    {
      return;
    }
    if initial_is_error {
      return;
    }
    loop {
      tokio::select! {
        () = body_sender.closed() => break,
        result = stream.recv_data_bytes() => {
          match result {
            Ok(Some(chunk)) => {
              if body_sender.send(Ok(Frame::data(chunk))).await.is_err() {
                break;
              }
            }
            Ok(None) => break,
            Err(error) => {
              let _ = body_sender
                .send(Err(downstream_h3_request_body_error(error)))
                .await;
              break;
            }
          }
        }
      }
    }
  });
  Request::from_parts(parts, body)
}

fn downstream_h3_request_body_error(error: impl fmt::Display) -> BoxError {
  boxed_error(std::io::Error::other(format!(
    "failed to receive downstream HTTP/3 request data: {error}"
  )))
}

fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

#[cfg(test)]
mod tests {
  use std::collections::VecDeque;
  use std::fmt;
  use std::future::{Future, poll_fn};
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::task::{Context, Poll};
  use std::time::Duration;

  use ::http::header::CONTENT_LENGTH;
  use ::http::{HeaderValue, Method, Request};
  use bytes::Bytes;
  use http_body_util::BodyExt;

  use super::*;

  #[tokio::test]
  async fn get_content_length_zero_data_is_streamed_into_proxy_body() {
    assert_content_length_zero_data_is_streamed(Method::GET).await;
  }

  #[tokio::test]
  async fn head_content_length_zero_data_is_streamed_into_proxy_body() {
    assert_content_length_zero_data_is_streamed(Method::HEAD).await;
  }

  #[tokio::test]
  async fn post_body_uses_streaming_path() {
    let request = request(Method::POST);
    let stream = FakeRequestStream::new([
      FakeStreamEvent::Data(Bytes::from_static(b"abc")),
      FakeStreamEvent::End,
    ]);
    let spawner = CountingSpawner::default();

    let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    let body = request
      .into_body()
      .collect()
      .await
      .expect("POST body should collect")
      .to_bytes();
    assert_eq!(body, Bytes::from_static(b"abc"));
  }

  #[tokio::test]
  async fn content_length_zero_end_stream_returns_empty_body_after_polling_stream() {
    let request = request_with_content_length(Method::GET, &["0"]);
    let stream = FakeRequestStream::new([FakeStreamEvent::End]);
    let poll_count = stream.poll_count();
    let spawner = CountingSpawner::default();

    let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 0);
    assert_eq!(poll_count.load(Ordering::SeqCst), 1);
    let body = request
      .into_body()
      .collect()
      .await
      .expect("ended H3 stream should collect")
      .to_bytes();
    assert!(body.is_empty());
  }

  #[tokio::test]
  async fn get_content_length_zero_uses_streaming_path_when_body_might_arrive() {
    let request = request_with_content_length(Method::GET, &["0"]);
    let stream = FakeRequestStream::pending();
    let poll_count = stream.poll_count();
    let spawner = CountingSpawner::default();

    let _request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    assert_eq!(poll_count.load(Ordering::SeqCst), 1);
  }

  #[tokio::test]
  async fn get_without_content_length_uses_streaming_path_when_body_might_arrive() {
    let request = request(Method::GET);
    let stream = FakeRequestStream::pending();
    let spawner = CountingSpawner::default();

    let _request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
  }

  #[tokio::test]
  async fn get_and_head_without_framing_headers_shortcut_pending_marked_end() {
    for method in [Method::GET, Method::HEAD] {
      let request = request(method);
      let stream = FakeRequestStream::new([FakeStreamEvent::Pending, FakeStreamEvent::End]);
      let poll_count = stream.poll_count();
      let spawner = CountingSpawner::default();

      let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

      assert_eq!(spawner.spawned(), 0);
      assert_eq!(poll_count.load(Ordering::SeqCst), 1);
      let body = request
        .into_body()
        .collect()
        .await
        .expect("pending then EOF request body should collect")
        .to_bytes();
      assert!(body.is_empty());
    }
  }

  #[tokio::test]
  async fn post_without_framing_headers_does_not_use_empty_probe() {
    let request = request(Method::POST);
    let stream = FakeRequestStream::new([FakeStreamEvent::Pending, FakeStreamEvent::End]);
    let spawner = CountingSpawner::default();

    let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    let body = request
      .into_body()
      .collect()
      .await
      .expect("POST body should still use the streaming path")
      .to_bytes();
    assert!(body.is_empty());
  }

  #[tokio::test]
  async fn get_content_length_positive_does_not_use_empty_probe() {
    let request = request_with_content_length(Method::GET, &["5"]);
    let stream = FakeRequestStream::new([FakeStreamEvent::Pending, FakeStreamEvent::End]);
    let poll_count = stream.poll_count();
    let spawner = CountingSpawner::default();

    let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    assert_eq!(poll_count.load(Ordering::SeqCst), 1);
    let body = request
      .into_body()
      .collect()
      .await
      .expect("framed GET body should still use the streaming path")
      .to_bytes();
    assert!(body.is_empty());
  }

  #[tokio::test]
  async fn get_without_framing_headers_preserves_late_data_and_errors() {
    let request = request(Method::GET);
    let stream = FakeRequestStream::new([
      FakeStreamEvent::Pending,
      FakeStreamEvent::Data(Bytes::from_static(b"body")),
      FakeStreamEvent::End,
    ]);
    let spawner = CountingSpawner::default();

    let prepared = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    let body = prepared
      .into_body()
      .collect()
      .await
      .expect("late DATA should collect through the streaming path")
      .to_bytes();
    assert_eq!(body, Bytes::from_static(b"body"));

    let request = self::request(Method::GET);
    let stream = FakeRequestStream::new([
      FakeStreamEvent::Pending,
      FakeStreamEvent::Error("stream reset"),
    ]);
    let spawner = CountingSpawner::default();

    let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    let error = request
      .into_body()
      .collect()
      .await
      .expect_err("late stream error should be exposed as a body error");
    assert!(
      error
        .to_string()
        .contains("failed to receive downstream HTTP/3 request data: stream reset")
    );
  }

  #[tokio::test]
  async fn h3_stream_error_propagates_through_streaming_body() {
    let request = request(Method::POST);
    let stream = FakeRequestStream::new([FakeStreamEvent::Error("stream reset")]);
    let spawner = CountingSpawner::default();

    let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    let error = request
      .into_body()
      .collect()
      .await
      .expect_err("stream error should be exposed as a body error");
    assert!(
      error
        .to_string()
        .contains("failed to receive downstream HTTP/3 request data: stream reset")
    );
  }

  #[tokio::test]
  async fn dropping_proxy_body_stops_background_recv_task() {
    let request = request(Method::POST);
    let stream = FakeRequestStream::new([
      FakeStreamEvent::Data(Bytes::from_static(b"first")),
      FakeStreamEvent::Data(Bytes::from_static(b"second")),
      FakeStreamEvent::End,
    ]);
    let drop_count = stream.drop_count();
    let spawner = CountingSpawner::default();

    let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;
    assert_eq!(spawner.spawned(), 1);

    drop(request);
    tokio::time::timeout(Duration::from_secs(1), async {
      loop {
        if drop_count.load(Ordering::SeqCst) > 0 {
          break;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("recv task should stop after downstream body is dropped");
  }

  #[tokio::test]
  async fn dropping_pending_proxy_body_stops_background_recv_task() {
    let request = request(Method::POST);
    let stream = FakeRequestStream::pending();
    let drop_count = stream.drop_count();
    let spawner = CountingSpawner::default();

    let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;
    assert_eq!(spawner.spawned(), 1);

    drop(request);
    tokio::time::timeout(Duration::from_secs(1), async {
      loop {
        if drop_count.load(Ordering::SeqCst) > 0 {
          break;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("pending recv task should stop after downstream body is dropped");
  }

  async fn assert_content_length_zero_data_is_streamed(method: Method) {
    let request = request_with_content_length(method, &["0"]);
    let stream = FakeRequestStream::new([
      FakeStreamEvent::Data(Bytes::from_static(b"malicious-body")),
      FakeStreamEvent::End,
    ]);
    let poll_count = stream.poll_count();
    let spawner = CountingSpawner::default();

    let request = prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    assert_eq!(poll_count.load(Ordering::SeqCst), 1);
    let body = request
      .into_body()
      .collect()
      .await
      .expect("Content-Length: 0 DATA should collect through ProxyBody")
      .to_bytes();
    assert_eq!(body, Bytes::from_static(b"malicious-body"));
  }

  fn request(method: Method) -> Request<()> {
    Request::builder()
      .method(method)
      .uri("https://example.com/resource")
      .body(())
      .expect("request should build")
  }

  fn request_with_content_length(method: Method, values: &[&'static str]) -> Request<()> {
    let mut request = request(method);
    for value in values {
      request
        .headers_mut()
        .append(CONTENT_LENGTH, HeaderValue::from_static(value));
    }
    request
  }

  #[derive(Default)]
  struct CountingSpawner {
    spawned: Arc<AtomicUsize>,
  }

  impl CountingSpawner {
    fn spawned(&self) -> usize {
      self.spawned.load(Ordering::SeqCst)
    }
  }

  impl BodyTaskSpawner for CountingSpawner {
    fn spawn_request_body_task<F>(&self, future: F)
    where
      F: Future<Output = ()> + Send + 'static,
    {
      self.spawned.fetch_add(1, Ordering::SeqCst);
      tokio::spawn(future);
    }
  }

  enum FakeStreamEvent {
    Pending,
    Data(Bytes),
    End,
    Error(&'static str),
  }

  struct FakeRequestStream {
    events: VecDeque<FakeStreamEvent>,
    pending: bool,
    poll_count: Arc<AtomicUsize>,
    drop_count: Arc<AtomicUsize>,
  }

  impl FakeRequestStream {
    fn new(events: impl IntoIterator<Item = FakeStreamEvent>) -> Self {
      Self {
        events: events.into_iter().collect(),
        pending: false,
        poll_count: Arc::new(AtomicUsize::new(0)),
        drop_count: Arc::new(AtomicUsize::new(0)),
      }
    }

    fn pending() -> Self {
      Self {
        events: VecDeque::new(),
        pending: true,
        poll_count: Arc::new(AtomicUsize::new(0)),
        drop_count: Arc::new(AtomicUsize::new(0)),
      }
    }

    fn poll_count(&self) -> Arc<AtomicUsize> {
      Arc::clone(&self.poll_count)
    }

    fn drop_count(&self) -> Arc<AtomicUsize> {
      Arc::clone(&self.drop_count)
    }
  }

  impl Drop for FakeRequestStream {
    fn drop(&mut self) {
      self.drop_count.fetch_add(1, Ordering::SeqCst);
    }
  }

  impl H3RequestBodyStream for FakeRequestStream {
    type Error = FakeStreamError;

    fn is_end_stream(&self) -> bool {
      !self.pending
        && (self.events.is_empty() || matches!(self.events.front(), Some(FakeStreamEvent::End)))
    }

    fn poll_recv_data_bytes(
      &mut self,
      cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, Self::Error>> {
      self.poll_count.fetch_add(1, Ordering::SeqCst);
      if self.pending {
        return Poll::Pending;
      }

      match self.events.pop_front().unwrap_or(FakeStreamEvent::End) {
        FakeStreamEvent::Pending => {
          cx.waker().wake_by_ref();
          Poll::Pending
        }
        FakeStreamEvent::Data(bytes) => Poll::Ready(Ok(Some(bytes))),
        FakeStreamEvent::End => Poll::Ready(Ok(None)),
        FakeStreamEvent::Error(message) => Poll::Ready(Err(FakeStreamError(message))),
      }
    }

    fn recv_data_bytes(
      &mut self,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_ {
      poll_fn(|cx| self.poll_recv_data_bytes(cx))
    }
  }

  #[derive(Debug)]
  struct FakeStreamError(&'static str);

  impl fmt::Display for FakeStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      formatter.write_str(self.0)
    }
  }
}
