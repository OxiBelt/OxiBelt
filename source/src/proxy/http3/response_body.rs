use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokio::time::Sleep;

use crate::proxy::http::body::{
  BodyTimeoutError, BodyTimeoutKind, BoxError, ProxyBody, boxed_error,
};

type H3ClientRequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

pub(super) fn upstream_h3_response_body(
  stream: H3ClientRequestStream,
  timeout: Duration,
) -> ProxyBody {
  upstream_h3_response_body_inner(stream, timeout)
}

trait H3ResponseBodyStream: Send + Sync + Unpin + 'static {
  type Error: fmt::Display + Send + Sync + 'static;

  fn poll_recv_data_bytes(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Bytes>, Self::Error>>;

  fn poll_recv_trailers(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>>;

  fn stop_sending(&mut self);
}

impl H3ResponseBodyStream for H3ClientRequestStream {
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

  fn poll_recv_trailers(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
    self.poll_recv_trailers(cx)
  }

  fn stop_sending(&mut self) {
    self.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
  }
}

fn upstream_h3_response_body_inner<S>(stream: S, timeout: Duration) -> ProxyBody
where
  S: H3ResponseBodyStream,
{
  UpstreamH3ResponseBody {
    stream,
    timeout,
    sleep: None,
    state: H3ResponseBodyState::Data,
  }
  .boxed()
}

struct UpstreamH3ResponseBody<S>
where
  S: H3ResponseBodyStream,
{
  stream: S,
  timeout: Duration,
  sleep: Option<Pin<Box<Sleep>>>,
  state: H3ResponseBodyState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3ResponseBodyState {
  Data,
  Trailers,
  End,
}

impl<S> UpstreamH3ResponseBody<S>
where
  S: H3ResponseBodyStream,
{
  fn stop_sending(&mut self) {
    self.stream.stop_sending();
  }

  fn pending_or_timeout(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
    if self.sleep.is_none() {
      self.sleep = Some(Box::pin(tokio::time::sleep(self.timeout)));
    }
    if let Some(sleep) = self.sleep.as_mut()
      && sleep.as_mut().poll(cx).is_ready()
    {
      self.sleep = None;
      self.state = H3ResponseBodyState::End;
      self.stream.stop_sending();
      return Poll::Ready(Some(Err(boxed_error(BodyTimeoutError::new(
        BodyTimeoutKind::UpstreamResponseRead,
      )))));
    }
    Poll::Pending
  }
}

impl<S> Body for UpstreamH3ResponseBody<S>
where
  S: H3ResponseBodyStream,
{
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let this = self.get_mut();
    loop {
      match this.state {
        H3ResponseBodyState::Data => match this.stream.poll_recv_data_bytes(cx) {
          Poll::Ready(Ok(Some(chunk))) => {
            this.sleep = None;
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
          }
          Poll::Ready(Ok(None)) => {
            this.sleep = None;
            this.state = H3ResponseBodyState::Trailers;
          }
          Poll::Ready(Err(error)) => {
            this.sleep = None;
            this.state = H3ResponseBodyState::End;
            return Poll::Ready(Some(Err(upstream_h3_response_body_error(error))));
          }
          Poll::Pending => return this.pending_or_timeout(cx),
        },
        H3ResponseBodyState::Trailers => match this.stream.poll_recv_trailers(cx) {
          Poll::Ready(Ok(Some(trailers))) => {
            this.sleep = None;
            this.state = H3ResponseBodyState::End;
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
          }
          Poll::Ready(Ok(None)) => {
            this.sleep = None;
            this.state = H3ResponseBodyState::End;
            return Poll::Ready(None);
          }
          Poll::Ready(Err(error)) => {
            this.sleep = None;
            this.state = H3ResponseBodyState::End;
            return Poll::Ready(Some(Err(upstream_h3_response_body_trailers_error(error))));
          }
          Poll::Pending => return this.pending_or_timeout(cx),
        },
        H3ResponseBodyState::End => return Poll::Ready(None),
      }
    }
  }

  fn is_end_stream(&self) -> bool {
    self.state == H3ResponseBodyState::End
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

impl<S> Drop for UpstreamH3ResponseBody<S>
where
  S: H3ResponseBodyStream,
{
  fn drop(&mut self) {
    if self.state != H3ResponseBodyState::End {
      self.stop_sending();
    }
  }
}

fn upstream_h3_response_body_error(error: impl fmt::Display) -> BoxError {
  boxed_error(std::io::Error::other(format!(
    "failed to receive upstream HTTP/3 response data: {error}"
  )))
}

fn upstream_h3_response_body_trailers_error(error: impl fmt::Display) -> BoxError {
  boxed_error(std::io::Error::other(format!(
    "failed to receive upstream HTTP/3 response trailers: {error}"
  )))
}

#[cfg(test)]
mod tests {
  use std::collections::VecDeque;
  use std::fmt;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool, Ordering};

  use http_body_util::BodyExt;

  use super::*;

  #[tokio::test]
  async fn direct_h3_response_body_streams_data_until_eof() {
    let stream = FakeResponseStream::new([
      FakeStreamEvent::Data(Bytes::from_static(b"ab")),
      FakeStreamEvent::Data(Bytes::from_static(b"cd")),
      FakeStreamEvent::End,
    ]);

    let body = upstream_h3_response_body_inner(stream, Duration::from_secs(30));
    let collected = body
      .collect()
      .await
      .expect("body should collect")
      .to_bytes();

    assert_eq!(collected, Bytes::from_static(b"abcd"));
  }

  #[tokio::test]
  async fn direct_h3_response_body_streams_data_then_trailers_then_eof() {
    let mut expected_trailers = http::HeaderMap::new();
    expected_trailers.insert("x-upstream-checksum", "ok".parse().unwrap());
    let stream = FakeResponseStream::with_trailers(
      [
        FakeStreamEvent::Data(Bytes::from_static(b"ab")),
        FakeStreamEvent::End,
      ],
      [FakeTrailerEvent::Trailers(expected_trailers)],
    );
    let mut body = upstream_h3_response_body_inner(stream, Duration::from_secs(30));

    let data = body
      .frame()
      .await
      .expect("data frame should exist")
      .expect("data frame should be valid")
      .into_data()
      .expect("first frame should be DATA");
    assert_eq!(data, Bytes::from_static(b"ab"));
    let trailers = body
      .frame()
      .await
      .expect("trailers frame should exist")
      .expect("trailers frame should be valid")
      .into_trailers()
      .expect("second frame should be trailers");
    assert_eq!(trailers["x-upstream-checksum"], "ok");
    assert!(body.frame().await.is_none());
  }

  #[tokio::test]
  async fn direct_h3_response_body_preserves_delayed_trailers() {
    let stream = FakeResponseStream::with_trailers(
      [FakeStreamEvent::End],
      [
        FakeTrailerEvent::YieldPending,
        FakeTrailerEvent::Trailers(trailer_map()),
      ],
    );
    let mut body = upstream_h3_response_body_inner(stream, Duration::from_secs(30));

    let trailers = body
      .frame()
      .await
      .expect("delayed trailers frame should exist")
      .expect("delayed trailers frame should be valid")
      .into_trailers()
      .expect("first frame should be trailers");
    assert_eq!(trailers["x-upstream-checksum"], "ok");
    assert!(body.frame().await.is_none());
  }

  #[tokio::test]
  async fn direct_h3_response_body_reports_stream_errors() {
    let stream = FakeResponseStream::new([FakeStreamEvent::Error("reset")]);
    let error = upstream_h3_response_body_inner(stream, Duration::from_secs(30))
      .collect()
      .await
      .expect_err("stream error should be returned");

    assert!(error.to_string().contains("reset"));
  }

  #[tokio::test]
  async fn direct_h3_response_body_reports_trailer_errors() {
    let stream = FakeResponseStream::with_trailers(
      [FakeStreamEvent::End],
      [FakeTrailerEvent::Error("trailer reset")],
    );
    let error = upstream_h3_response_body_inner(stream, Duration::from_secs(30))
      .collect()
      .await
      .expect_err("trailer error should be returned");

    assert!(
      error
        .to_string()
        .contains("failed to receive upstream HTTP/3 response trailers: trailer reset")
    );
  }

  #[tokio::test]
  async fn direct_h3_response_body_times_out_pending_streams() {
    let stopped = Arc::new(AtomicBool::new(false));
    let stream = FakeResponseStream::pending(stopped.clone());
    let error = upstream_h3_response_body_inner(stream, Duration::from_millis(1))
      .collect()
      .await
      .expect_err("timeout should be returned");

    assert!(
      error
        .to_string()
        .contains("upstream response body read timed out")
    );
    assert!(stopped.load(Ordering::SeqCst));
  }

  #[tokio::test]
  async fn direct_h3_response_body_times_out_pending_trailers() {
    let stopped = Arc::new(AtomicBool::new(false));
    let stream = FakeResponseStream::with_stopped_and_trailers(
      [FakeStreamEvent::End],
      [FakeTrailerEvent::Pending],
      stopped.clone(),
    );
    let error = upstream_h3_response_body_inner(stream, Duration::from_millis(1))
      .collect()
      .await
      .expect_err("trailer timeout should be returned");

    assert!(
      error
        .to_string()
        .contains("upstream response body read timed out")
    );
    assert!(stopped.load(Ordering::SeqCst));
  }

  #[test]
  fn direct_h3_response_body_stops_stream_on_drop_before_eof() {
    let stopped = Arc::new(AtomicBool::new(false));
    let stream = FakeResponseStream::pending(stopped.clone());

    drop(upstream_h3_response_body_inner(
      stream,
      Duration::from_secs(30),
    ));

    assert!(stopped.load(Ordering::SeqCst));
  }

  enum FakeStreamEvent {
    Data(Bytes),
    End,
    Error(&'static str),
    Pending,
  }

  enum FakeTrailerEvent {
    Pending,
    YieldPending,
    Trailers(http::HeaderMap),
    End,
    Error(&'static str),
  }

  struct FakeResponseStream {
    events: VecDeque<FakeStreamEvent>,
    trailer_events: VecDeque<FakeTrailerEvent>,
    stopped: Arc<AtomicBool>,
  }

  impl FakeResponseStream {
    fn new(events: impl IntoIterator<Item = FakeStreamEvent>) -> Self {
      Self {
        events: events.into_iter().collect(),
        trailer_events: VecDeque::from([FakeTrailerEvent::End]),
        stopped: Arc::new(AtomicBool::new(false)),
      }
    }

    fn with_trailers(
      events: impl IntoIterator<Item = FakeStreamEvent>,
      trailer_events: impl IntoIterator<Item = FakeTrailerEvent>,
    ) -> Self {
      Self {
        events: events.into_iter().collect(),
        trailer_events: trailer_events.into_iter().collect(),
        stopped: Arc::new(AtomicBool::new(false)),
      }
    }

    fn with_stopped_and_trailers(
      events: impl IntoIterator<Item = FakeStreamEvent>,
      trailer_events: impl IntoIterator<Item = FakeTrailerEvent>,
      stopped: Arc<AtomicBool>,
    ) -> Self {
      Self {
        events: events.into_iter().collect(),
        trailer_events: trailer_events.into_iter().collect(),
        stopped,
      }
    }

    fn pending(stopped: Arc<AtomicBool>) -> Self {
      Self {
        events: VecDeque::from([FakeStreamEvent::Pending]),
        trailer_events: VecDeque::from([FakeTrailerEvent::End]),
        stopped,
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

  impl std::error::Error for FakeStreamError {}

  impl H3ResponseBodyStream for FakeResponseStream {
    type Error = FakeStreamError;

    fn poll_recv_data_bytes(
      &mut self,
      _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, Self::Error>> {
      if self
        .events
        .front()
        .is_some_and(|event| matches!(event, FakeStreamEvent::Pending))
      {
        return Poll::Pending;
      }
      match self.events.pop_front() {
        Some(FakeStreamEvent::Data(data)) => Poll::Ready(Ok(Some(data))),
        Some(FakeStreamEvent::End) | None => Poll::Ready(Ok(None)),
        Some(FakeStreamEvent::Error(error)) => Poll::Ready(Err(FakeStreamError(error))),
        Some(FakeStreamEvent::Pending) => unreachable!("pending events are handled by peek"),
      }
    }

    fn poll_recv_trailers(
      &mut self,
      cx: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
      if self
        .trailer_events
        .front()
        .is_some_and(|event| matches!(event, FakeTrailerEvent::Pending))
      {
        return Poll::Pending;
      }
      if self
        .trailer_events
        .front()
        .is_some_and(|event| matches!(event, FakeTrailerEvent::YieldPending))
      {
        self.trailer_events.pop_front();
        cx.waker().wake_by_ref();
        return Poll::Pending;
      }
      match self.trailer_events.pop_front() {
        Some(FakeTrailerEvent::Trailers(trailers)) => Poll::Ready(Ok(Some(trailers))),
        Some(FakeTrailerEvent::End) | None => Poll::Ready(Ok(None)),
        Some(FakeTrailerEvent::Error(error)) => Poll::Ready(Err(FakeStreamError(error))),
        Some(FakeTrailerEvent::Pending | FakeTrailerEvent::YieldPending) => {
          unreachable!("pending trailers are handled by peek")
        }
      }
    }

    fn stop_sending(&mut self) {
      self.stopped.store(true, Ordering::SeqCst);
    }
  }

  fn trailer_map() -> http::HeaderMap {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-upstream-checksum", "ok".parse().unwrap());
    trailers
  }
}
