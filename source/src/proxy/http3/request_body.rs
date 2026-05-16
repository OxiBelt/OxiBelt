use std::fmt;
use std::future::{Future, poll_fn};
use std::task::{Context, Poll};

use ::http::header::CONTENT_LENGTH;
use ::http::{HeaderMap, HeaderValue, Method, Request};
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty};
use hyper::body::Frame;
use tokio::sync::oneshot;

use crate::proxy::http::body::{BoxError, ProxyBody, boxed_error, channel_body};

use super::{H3_BODY_CHANNEL_CAPACITY, H3RequestStream};

pub(super) struct H3RequestStreamCompletion(RequestStreamCompletion<H3RequestStream>);

impl H3RequestStreamCompletion {
  pub(super) async fn into_stream(self) -> anyhow::Result<H3RequestStream> {
    self.0.into_stream().await
  }
}

pub(super) async fn prepare_h3_request_body(
  request: Request<()>,
  stream: H3RequestStream,
) -> (Request<ProxyBody>, H3RequestStreamCompletion) {
  let (request, completion) =
    prepare_h3_request_body_with_spawner(request, stream, &TokioBodyTaskSpawner).await;
  (request, H3RequestStreamCompletion(completion))
}

trait H3RequestBodyStream: Send + 'static {
  type Error: fmt::Display + Send + Sync + 'static;

  fn poll_recv_data_bytes(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Bytes>, Self::Error>>;

  fn recv_data_bytes(
    &mut self,
  ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_;
}

impl H3RequestBodyStream for H3RequestStream {
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

struct RequestStreamCompletion<S> {
  ready: Option<S>,
  receiver: Option<oneshot::Receiver<S>>,
}

impl<S> RequestStreamCompletion<S> {
  fn ready(stream: S) -> Self {
    Self {
      ready: Some(stream),
      receiver: None,
    }
  }

  fn receiver(receiver: oneshot::Receiver<S>) -> Self {
    Self {
      ready: None,
      receiver: Some(receiver),
    }
  }

  async fn into_stream(self) -> anyhow::Result<S> {
    if let Some(stream) = self.ready {
      return Ok(stream);
    }
    let Some(receiver) = self.receiver else {
      return Err(anyhow::anyhow!(
        "downstream HTTP/3 request body stream completion is missing"
      ));
    };
    receiver
      .await
      .map_err(|_| anyhow::anyhow!("downstream HTTP/3 request body task did not return stream"))
  }

  #[cfg(test)]
  fn is_ready(&self) -> bool {
    self.ready.is_some()
  }
}

async fn prepare_h3_request_body_with_spawner<S, Spawner>(
  request: Request<()>,
  mut stream: S,
  spawner: &Spawner,
) -> (Request<ProxyBody>, RequestStreamCompletion<S>)
where
  S: H3RequestBodyStream,
  Spawner: BodyTaskSpawner,
{
  if has_explicit_empty_h3_body(&request) {
    let (parts, _) = request.into_parts();
    return (
      Request::from_parts(parts, empty_body()),
      RequestStreamCompletion::ready(stream),
    );
  }

  let first = poll_fn(|cx| match stream.poll_recv_data_bytes(cx) {
    Poll::Ready(result) => Poll::Ready(Some(result)),
    Poll::Pending => Poll::Ready(None),
  })
  .await;

  match first {
    Some(Ok(None)) => {
      let (parts, _) = request.into_parts();
      (
        Request::from_parts(parts, empty_body()),
        RequestStreamCompletion::ready(stream),
      )
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

fn stream_h3_request_body<S, Spawner>(
  request: Request<()>,
  stream: S,
  spawner: &Spawner,
) -> (Request<ProxyBody>, RequestStreamCompletion<S>)
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
) -> (Request<ProxyBody>, RequestStreamCompletion<S>)
where
  S: H3RequestBodyStream,
  Spawner: BodyTaskSpawner,
{
  let (parts, _) = request.into_parts();
  let (body_sender, body) = channel_body(H3_BODY_CHANNEL_CAPACITY);
  let (stream_sender, stream_receiver) = oneshot::channel();
  let mut stream = stream;
  let initial_is_error = initial_frame.as_ref().is_some_and(Result::is_err);
  spawner.spawn_request_body_task(async move {
    if let Some(frame) = initial_frame
      && body_sender.send(frame).await.is_err()
    {
      let _ = stream_sender.send(stream);
      return;
    }
    if initial_is_error {
      let _ = stream_sender.send(stream);
      return;
    }
    loop {
      match stream.recv_data_bytes().await {
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
    let _ = stream_sender.send(stream);
  });
  (
    Request::from_parts(parts, body),
    RequestStreamCompletion::receiver(stream_receiver),
  )
}

fn has_explicit_empty_h3_body(request: &Request<()>) -> bool {
  matches!(request.method(), &Method::GET | &Method::HEAD)
    && content_length_headers_are_all_zero(request.headers())
}

fn content_length_headers_are_all_zero(headers: &HeaderMap) -> bool {
  let mut values = headers.get_all(CONTENT_LENGTH).iter();
  let Some(first) = values.next() else {
    return false;
  };

  content_length_value_is_zero(first) && values.all(content_length_value_is_zero)
}

fn content_length_value_is_zero(value: &HeaderValue) -> bool {
  let Ok(value) = value.to_str() else {
    return false;
  };
  let value = value.trim_matches(|character| matches!(character, ' ' | '\t'));
  !value.is_empty() && value.bytes().all(|byte| byte == b'0')
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

  use ::http::header::CONTENT_LENGTH;
  use ::http::{HeaderValue, Method, Request};
  use bytes::Bytes;
  use http_body_util::BodyExt;

  use super::*;

  #[tokio::test]
  async fn get_content_length_zero_uses_spawn_free_empty_body() {
    assert_explicit_empty_fast_path(Method::GET).await;
  }

  #[tokio::test]
  async fn head_content_length_zero_uses_spawn_free_empty_body() {
    assert_explicit_empty_fast_path(Method::HEAD).await;
  }

  #[tokio::test]
  async fn post_body_uses_streaming_path() {
    let request = request(Method::POST);
    let stream = FakeRequestStream::new([
      FakeStreamEvent::Data(Bytes::from_static(b"abc")),
      FakeStreamEvent::End,
    ]);
    let spawner = CountingSpawner::default();

    let (request, completion) =
      prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    assert!(!completion.is_ready());
    let body = request
      .into_body()
      .collect()
      .await
      .expect("POST body should collect")
      .to_bytes();
    assert_eq!(body, Bytes::from_static(b"abc"));
    let _stream = completion
      .into_stream()
      .await
      .expect("streaming task should return the stream");
  }

  #[tokio::test]
  async fn get_without_content_length_uses_streaming_path_when_body_might_arrive() {
    let request = request(Method::GET);
    let stream = FakeRequestStream::pending();
    let spawner = CountingSpawner::default();

    let (_request, completion) =
      prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 1);
    assert!(!completion.is_ready());
  }

  #[tokio::test]
  async fn h3_stream_error_propagates_through_streaming_body() {
    let request = request(Method::POST);
    let stream = FakeRequestStream::new([FakeStreamEvent::Error("stream reset")]);
    let spawner = CountingSpawner::default();

    let (request, completion) =
      prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

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
    let _stream = completion
      .into_stream()
      .await
      .expect("streaming task should return the stream after an error");
  }

  #[test]
  fn explicit_empty_body_requires_safe_method_and_valid_zero_content_length() {
    assert!(has_explicit_empty_h3_body(&request_with_content_length(
      Method::GET,
      &["0"]
    )));
    assert!(has_explicit_empty_h3_body(&request_with_content_length(
      Method::HEAD,
      &["00"]
    )));
    assert!(has_explicit_empty_h3_body(&request_with_content_length(
      Method::GET,
      &["0", "00"]
    )));

    assert!(!has_explicit_empty_h3_body(&request(Method::GET)));
    assert!(!has_explicit_empty_h3_body(&request_with_content_length(
      Method::POST,
      &["0"]
    )));
    assert!(!has_explicit_empty_h3_body(&request_with_content_length(
      Method::GET,
      &["1"]
    )));
    assert!(!has_explicit_empty_h3_body(&request_with_content_length(
      Method::GET,
      &["not-a-number"]
    )));
    assert!(!has_explicit_empty_h3_body(&request_with_content_length(
      Method::GET,
      &["0, 0"]
    )));
    assert!(!has_explicit_empty_h3_body(&request_with_content_length(
      Method::GET,
      &["0", "1"]
    )));
  }

  async fn assert_explicit_empty_fast_path(method: Method) {
    let request = request_with_content_length(method, &["0"]);
    let stream = FakeRequestStream::pending();
    let poll_count = stream.poll_count();
    let spawner = CountingSpawner::default();

    let (request, completion) =
      prepare_h3_request_body_with_spawner(request, stream, &spawner).await;

    assert_eq!(spawner.spawned(), 0);
    assert_eq!(poll_count.load(Ordering::SeqCst), 0);
    assert!(completion.is_ready());
    let body = request
      .into_body()
      .collect()
      .await
      .expect("explicit empty body should collect")
      .to_bytes();
    assert!(body.is_empty());
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
    Data(Bytes),
    End,
    Error(&'static str),
  }

  struct FakeRequestStream {
    events: VecDeque<FakeStreamEvent>,
    pending: bool,
    poll_count: Arc<AtomicUsize>,
  }

  impl FakeRequestStream {
    fn new(events: impl IntoIterator<Item = FakeStreamEvent>) -> Self {
      Self {
        events: events.into_iter().collect(),
        pending: false,
        poll_count: Arc::new(AtomicUsize::new(0)),
      }
    }

    fn pending() -> Self {
      Self {
        events: VecDeque::new(),
        pending: true,
        poll_count: Arc::new(AtomicUsize::new(0)),
      }
    }

    fn poll_count(&self) -> Arc<AtomicUsize> {
      Arc::clone(&self.poll_count)
    }
  }

  impl H3RequestBodyStream for FakeRequestStream {
    type Error = FakeStreamError;

    fn poll_recv_data_bytes(
      &mut self,
      _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, Self::Error>> {
      self.poll_count.fetch_add(1, Ordering::SeqCst);
      if self.pending {
        return Poll::Pending;
      }

      match self.events.pop_front().unwrap_or(FakeStreamEvent::End) {
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
