use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ::http::header::CONTENT_LENGTH;
use ::http::{HeaderValue, Method, Request};
use bytes::Bytes;
use http_body_util::BodyExt;

use super::*;

fn assert_inline_ready(prepared: &PreparedH3RequestBody) {
  assert_eq!(
    prepared.inline_readiness,
    PreparedH3RequestBodyReadiness::InlineReady
  );
}

fn assert_spawn(prepared: &PreparedH3RequestBody) {
  assert_eq!(
    prepared.inline_readiness,
    PreparedH3RequestBodyReadiness::Spawn
  );
}

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

  let prepared = prepare_h3_request_body_inner(request, stream).await;
  assert_spawn(&prepared);
  let request = prepared.request;

  let body = request
    .into_body()
    .collect()
    .await
    .expect("POST body should collect")
    .to_bytes();
  assert_eq!(body, Bytes::from_static(b"abc"));
}

#[tokio::test]
async fn large_initial_body_uses_spawn_path() {
  let request = request(Method::POST);
  let large = Bytes::from(vec![b'x'; 16 * 1024 + 1]);
  let stream = FakeRequestStream::new([FakeStreamEvent::Data(large.clone()), FakeStreamEvent::End]);

  let prepared = prepare_h3_request_body_inner(request, stream).await;

  assert_spawn(&prepared);
  let body = prepared
    .request
    .into_body()
    .collect()
    .await
    .expect("large body should collect")
    .to_bytes();
  assert_eq!(body, large);
}

#[tokio::test]
async fn content_length_zero_end_stream_returns_empty_body_after_polling_stream() {
  let request = request_with_content_length(Method::GET, &["0"]);
  let stream = FakeRequestStream::new([FakeStreamEvent::End]);
  let poll_count = stream.poll_count();

  let prepared = prepare_h3_request_body_inner(request, stream).await;

  assert_eq!(poll_count.load(Ordering::SeqCst), 1);
  assert_spawn(&prepared);
  assert!(!prepared.verified_empty);
  let request = prepared.request;
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

  let prepared = prepare_h3_request_body_inner(request, stream).await;

  assert_eq!(poll_count.load(Ordering::SeqCst), 1);
  assert_spawn(&prepared);
}

#[tokio::test]
async fn get_without_content_length_uses_streaming_path_when_body_might_arrive() {
  let request = request(Method::GET);
  let stream = FakeRequestStream::pending();

  let prepared = prepare_h3_request_body_inner(request, stream).await;
  assert_spawn(&prepared);
}

#[tokio::test]
async fn get_and_head_without_framing_headers_mark_verified_empty_after_data_and_trailer_eof() {
  for method in [Method::GET, Method::HEAD] {
    let request = request(method);
    let stream = FakeRequestStream::new([FakeStreamEvent::End]);
    let poll_count = stream.poll_count();
    let trailer_poll_count = stream.trailer_poll_count();

    let prepared = prepare_h3_request_body_inner(request, stream).await;

    assert_eq!(poll_count.load(Ordering::SeqCst), 1);
    assert_eq!(trailer_poll_count.load(Ordering::SeqCst), 1);
    assert!(prepared.verified_empty);
    assert_inline_ready(&prepared);
    let request = prepared.request;
    assert!(
      request
        .extensions()
        .get::<VerifiedEmptyRequestBody>()
        .is_some()
    );
    let body = request
      .into_body()
      .collect()
      .await
      .expect("ended H3 stream should collect")
      .to_bytes();
    assert!(body.is_empty());
  }
}

#[tokio::test]
async fn get_and_head_without_framing_headers_pending_data_uses_spawn_path() {
  for method in [Method::GET, Method::HEAD] {
    let request = request(method);
    let stream = FakeRequestStream::new([FakeStreamEvent::Pending, FakeStreamEvent::End]);
    let poll_count = stream.poll_count();

    let prepared = prepare_h3_request_body_inner(request, stream).await;

    assert_eq!(poll_count.load(Ordering::SeqCst), 1);
    assert!(!prepared.verified_empty);
    assert_spawn(&prepared);
    let request = prepared.request;
    assert!(
      request
        .extensions()
        .get::<VerifiedEmptyRequestBody>()
        .is_none()
    );
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

  let prepared = prepare_h3_request_body_inner(request, stream).await;
  assert_spawn(&prepared);
  let request = prepared.request;

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

  let prepared = prepare_h3_request_body_inner(request, stream).await;

  assert_eq!(poll_count.load(Ordering::SeqCst), 1);
  assert_spawn(&prepared);
  let request = prepared.request;
  assert!(
    request
      .extensions()
      .get::<VerifiedEmptyRequestBody>()
      .is_none()
  );
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

  let prepared = prepare_h3_request_body_inner(request, stream).await;

  assert!(!prepared.verified_empty);
  assert_spawn(&prepared);
  let body = prepared
    .request
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

  let prepared = prepare_h3_request_body_inner(request, stream).await;
  assert_spawn(&prepared);
  let request = prepared.request;

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
async fn get_without_framing_headers_immediate_data_uses_spawn_path() {
  let request = request(Method::GET);
  let stream = FakeRequestStream::new([
    FakeStreamEvent::Data(Bytes::from_static(b"body")),
    FakeStreamEvent::End,
  ]);

  let prepared = prepare_h3_request_body_inner(request, stream).await;

  assert!(!prepared.verified_empty);
  assert_spawn(&prepared);
  let body = prepared
    .request
    .into_body()
    .collect()
    .await
    .expect("immediate DATA should remain on the spawned path")
    .to_bytes();
  assert_eq!(body, Bytes::from_static(b"body"));
}

#[tokio::test]
async fn request_body_streams_data_then_trailers_then_eof() {
  let request = request(Method::POST);
  let stream = FakeRequestStream::with_trailers(
    [
      FakeStreamEvent::Data(Bytes::from_static(b"body")),
      FakeStreamEvent::End,
    ],
    [FakeTrailerEvent::Trailers(trailer_map())],
  );

  let prepared = prepare_h3_request_body_inner(request, stream).await;
  assert_spawn(&prepared);
  let mut body = prepared.request.into_body();

  let data = body
    .frame()
    .await
    .expect("data frame should exist")
    .expect("data frame should be valid")
    .into_data()
    .expect("first frame should be DATA");
  assert_eq!(data, Bytes::from_static(b"body"));
  let trailers = body
    .frame()
    .await
    .expect("trailers frame should exist")
    .expect("trailers frame should be valid")
    .into_trailers()
    .expect("second frame should be trailers");
  assert_sanitized_request_trailers(&trailers);
  assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn immediate_or_delayed_trailers_never_mark_safe_request_verified_empty() {
  for trailer_events in [
    vec![FakeTrailerEvent::Trailers(trailer_map())],
    vec![
      FakeTrailerEvent::Pending,
      FakeTrailerEvent::Trailers(trailer_map()),
    ],
  ] {
    let request = request(Method::GET);
    let stream = FakeRequestStream::with_trailers([FakeStreamEvent::End], trailer_events);

    let prepared = prepare_h3_request_body_inner(request, stream).await;

    assert!(!prepared.verified_empty);
    assert_spawn(&prepared);
    assert!(
      prepared
        .request
        .extensions()
        .get::<VerifiedEmptyRequestBody>()
        .is_none()
    );
    let mut body = prepared.request.into_body();
    let trailers = body
      .frame()
      .await
      .expect("trailer-bearing request should preserve trailers")
      .expect("trailers frame should be valid")
      .into_trailers()
      .expect("first frame should be trailers");
    assert_sanitized_request_trailers(&trailers);
    assert!(body.frame().await.is_none());
  }
}

#[tokio::test]
async fn trailer_errors_propagate_through_streaming_body() {
  let request = request(Method::POST);
  let stream = FakeRequestStream::with_trailers(
    [FakeStreamEvent::End],
    [FakeTrailerEvent::Error("trailer reset")],
  );

  let error = prepare_h3_request_body_inner(request, stream)
    .await
    .request
    .into_body()
    .collect()
    .await
    .expect_err("trailer error should be returned");
  assert!(
    error
      .to_string()
      .contains("failed to receive downstream HTTP/3 request trailers: trailer reset")
  );
}

#[tokio::test]
async fn h3_stream_error_propagates_through_streaming_body() {
  let request = request(Method::POST);
  let stream = FakeRequestStream::new([FakeStreamEvent::Error("stream reset")]);

  let prepared = prepare_h3_request_body_inner(request, stream).await;
  assert_spawn(&prepared);
  let request = prepared.request;

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
async fn dropping_proxy_body_drops_direct_recv_stream() {
  let request = request(Method::POST);
  let stream = FakeRequestStream::new([
    FakeStreamEvent::Data(Bytes::from_static(b"first")),
    FakeStreamEvent::Data(Bytes::from_static(b"second")),
    FakeStreamEvent::End,
  ]);
  let drop_count = stream.drop_count();

  let prepared = prepare_h3_request_body_inner(request, stream).await;
  assert_spawn(&prepared);
  let request = prepared.request;

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
  .expect("direct recv stream should drop with downstream body");
}

#[tokio::test]
async fn dropping_pending_proxy_body_drops_direct_recv_stream() {
  let request = request(Method::POST);
  let stream = FakeRequestStream::pending();
  let drop_count = stream.drop_count();

  let request = prepare_h3_request_body_inner(request, stream).await.request;

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
  .expect("pending direct recv stream should drop with downstream body");
}

async fn assert_content_length_zero_data_is_streamed(method: Method) {
  let request = request_with_content_length(method, &["0"]);
  let stream = FakeRequestStream::new([
    FakeStreamEvent::Data(Bytes::from_static(b"malicious-body")),
    FakeStreamEvent::End,
  ]);
  let poll_count = stream.poll_count();

  let request = prepare_h3_request_body_inner(request, stream).await.request;

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

fn trailer_map() -> http::HeaderMap {
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-request-checksum", "ok".parse().unwrap());
  trailers.insert("x-forwarded-for", "203.0.113.66".parse().unwrap());
  trailers.insert("x-forwarded-proto", "http".parse().unwrap());
  trailers.insert("x-forwarded-host", "admin.internal".parse().unwrap());
  trailers.insert("x-forwarded-port", "80".parse().unwrap());
  trailers.insert("x-real-ip", "203.0.113.66".parse().unwrap());
  trailers.insert("forwarded", "for=203.0.113.66;proto=http".parse().unwrap());
  trailers.insert("authorization", "Bearer attacker".parse().unwrap());
  trailers.insert("cookie", "session=attacker".parse().unwrap());
  trailers.insert("host", "admin.internal".parse().unwrap());
  trailers.insert("connection", "x-trailer-control".parse().unwrap());
  trailers.insert("x-trailer-control", "remove-me".parse().unwrap());
  trailers.insert("te", "gzip".parse().unwrap());
  trailers
}

fn assert_sanitized_request_trailers(trailers: &http::HeaderMap) {
  assert_eq!(trailers["x-request-checksum"], "ok");
  for stripped in [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-real-ip",
    "forwarded",
    "authorization",
    "cookie",
    "host",
    "connection",
    "x-trailer-control",
    "te",
  ] {
    assert!(
      !trailers.contains_key(stripped),
      "request trailers should strip {stripped}"
    );
  }
}

enum FakeStreamEvent {
  Pending,
  Data(Bytes),
  End,
  Error(&'static str),
}

enum FakeTrailerEvent {
  Pending,
  Trailers(http::HeaderMap),
  End,
  Error(&'static str),
}

struct FakeRequestStream {
  events: VecDeque<FakeStreamEvent>,
  trailer_events: VecDeque<FakeTrailerEvent>,
  pending: bool,
  poll_count: Arc<AtomicUsize>,
  trailer_poll_count: Arc<AtomicUsize>,
  drop_count: Arc<AtomicUsize>,
}

impl FakeRequestStream {
  fn new(events: impl IntoIterator<Item = FakeStreamEvent>) -> Self {
    Self {
      events: events.into_iter().collect(),
      trailer_events: VecDeque::from([FakeTrailerEvent::End]),
      pending: false,
      poll_count: Arc::new(AtomicUsize::new(0)),
      trailer_poll_count: Arc::new(AtomicUsize::new(0)),
      drop_count: Arc::new(AtomicUsize::new(0)),
    }
  }

  fn with_trailers(
    events: impl IntoIterator<Item = FakeStreamEvent>,
    trailer_events: impl IntoIterator<Item = FakeTrailerEvent>,
  ) -> Self {
    Self {
      events: events.into_iter().collect(),
      trailer_events: trailer_events.into_iter().collect(),
      pending: false,
      poll_count: Arc::new(AtomicUsize::new(0)),
      trailer_poll_count: Arc::new(AtomicUsize::new(0)),
      drop_count: Arc::new(AtomicUsize::new(0)),
    }
  }

  fn pending() -> Self {
    Self {
      events: VecDeque::new(),
      trailer_events: VecDeque::from([FakeTrailerEvent::End]),
      pending: true,
      poll_count: Arc::new(AtomicUsize::new(0)),
      trailer_poll_count: Arc::new(AtomicUsize::new(0)),
      drop_count: Arc::new(AtomicUsize::new(0)),
    }
  }

  fn poll_count(&self) -> Arc<AtomicUsize> {
    Arc::clone(&self.poll_count)
  }

  fn trailer_poll_count(&self) -> Arc<AtomicUsize> {
    Arc::clone(&self.trailer_poll_count)
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

  fn poll_recv_trailers(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
    self.trailer_poll_count.fetch_add(1, Ordering::SeqCst);
    match self
      .trailer_events
      .pop_front()
      .unwrap_or(FakeTrailerEvent::End)
    {
      FakeTrailerEvent::Pending => {
        cx.waker().wake_by_ref();
        Poll::Pending
      }
      FakeTrailerEvent::Trailers(trailers) => Poll::Ready(Ok(Some(trailers))),
      FakeTrailerEvent::End => Poll::Ready(Ok(None)),
      FakeTrailerEvent::Error(message) => Poll::Ready(Err(FakeStreamError(message))),
    }
  }
}

#[derive(Debug)]
struct FakeStreamError(&'static str);

impl fmt::Display for FakeStreamError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.0)
  }
}
