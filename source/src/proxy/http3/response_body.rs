use std::fmt;
use std::pin::Pin;
use std::sync::Mutex;
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

trait H3ResponseBodyStream: Send + Unpin + 'static {
  type Error: fmt::Display + Send + Sync + 'static;

  fn poll_recv_data_bytes(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Bytes>, Self::Error>>;

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

  fn stop_sending(&mut self) {
    self.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
  }
}

fn upstream_h3_response_body_inner<S>(stream: S, timeout: Duration) -> ProxyBody
where
  S: H3ResponseBodyStream,
{
  UpstreamH3ResponseBody {
    stream: Mutex::new(stream),
    timeout,
    sleep: None,
    ended: false,
  }
  .boxed()
}

struct UpstreamH3ResponseBody<S>
where
  S: H3ResponseBodyStream,
{
  stream: Mutex<S>,
  timeout: Duration,
  sleep: Option<Pin<Box<Sleep>>>,
  ended: bool,
}

impl<S> UpstreamH3ResponseBody<S>
where
  S: H3ResponseBodyStream,
{
  fn stop_sending(&mut self) {
    let stream = match self.stream.get_mut() {
      Ok(stream) => stream,
      Err(poisoned) => poisoned.into_inner(),
    };
    stream.stop_sending();
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
    if this.ended {
      return Poll::Ready(None);
    }
    if this.sleep.is_none() {
      this.sleep = Some(Box::pin(tokio::time::sleep(this.timeout)));
    }

    let stream = match this.stream.get_mut() {
      Ok(stream) => stream,
      Err(poisoned) => poisoned.into_inner(),
    };
    match stream.poll_recv_data_bytes(cx) {
      Poll::Ready(Ok(Some(chunk))) => {
        this.sleep = None;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
      }
      Poll::Ready(Ok(None)) => {
        this.sleep = None;
        this.ended = true;
        Poll::Ready(None)
      }
      Poll::Ready(Err(error)) => {
        this.sleep = None;
        this.ended = true;
        Poll::Ready(Some(Err(upstream_h3_response_body_error(error))))
      }
      Poll::Pending => {
        if let Some(sleep) = this.sleep.as_mut()
          && sleep.as_mut().poll(cx).is_ready()
        {
          this.sleep = None;
          this.ended = true;
          stream.stop_sending();
          return Poll::Ready(Some(Err(boxed_error(BodyTimeoutError::new(
            BodyTimeoutKind::UpstreamResponseRead,
          )))));
        }
        Poll::Pending
      }
    }
  }

  fn is_end_stream(&self) -> bool {
    self.ended
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
    if !self.ended {
      self.stop_sending();
    }
  }
}

fn upstream_h3_response_body_error(error: impl fmt::Display) -> BoxError {
  boxed_error(std::io::Error::other(format!(
    "failed to receive upstream HTTP/3 response data: {error}"
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
  async fn direct_h3_response_body_reports_stream_errors() {
    let stream = FakeResponseStream::new([FakeStreamEvent::Error("reset")]);
    let error = upstream_h3_response_body_inner(stream, Duration::from_secs(30))
      .collect()
      .await
      .expect_err("stream error should be returned");

    assert!(error.to_string().contains("reset"));
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

  struct FakeResponseStream {
    events: VecDeque<FakeStreamEvent>,
    stopped: Arc<AtomicBool>,
  }

  impl FakeResponseStream {
    fn new(events: impl IntoIterator<Item = FakeStreamEvent>) -> Self {
      Self {
        events: events.into_iter().collect(),
        stopped: Arc::new(AtomicBool::new(false)),
      }
    }

    fn pending(stopped: Arc<AtomicBool>) -> Self {
      Self {
        events: VecDeque::from([FakeStreamEvent::Pending]),
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

    fn stop_sending(&mut self) {
      self.stopped.store(true, Ordering::SeqCst);
    }
  }
}
