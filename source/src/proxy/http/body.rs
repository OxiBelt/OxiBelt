use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::Request;
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Frame, SizeHint};
use tokio::sync::mpsc;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type ProxyBody = BoxBody<Bytes, BoxError>;
pub(crate) type ProxyBodyFrame = Result<Frame<Bytes>, BoxError>;

#[derive(Debug, Clone)]
pub(crate) struct CapturedBody {
  pub(crate) bytes: Bytes,
  pub(crate) is_truncated: bool,
}

pub(crate) fn boxed_error<E>(error: E) -> BoxError
where
  E: std::error::Error + Send + Sync + 'static,
{
  Box::new(error)
}

pub(crate) fn channel_body(capacity: usize) -> (mpsc::Sender<ProxyBodyFrame>, ProxyBody) {
  let (sender, receiver) = mpsc::channel(capacity);
  (sender, ChannelBody { receiver }.boxed())
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
    Request::from_parts(parts, body),
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
}

impl Body for ChannelBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.receiver.poll_recv(cx)
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
  use http_body_util::{BodyExt, Full};

  use super::{BoxError, capture_prefix};

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
}
