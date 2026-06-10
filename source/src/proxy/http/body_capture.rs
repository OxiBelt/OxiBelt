//! Bounded HTTP body prefix capture and replay helpers.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::Request;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};

use super::body::{BoxError, CapturedBody, ProxyBody};

#[cfg(test)]
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

pub(crate) async fn capture_proxy_request_prefix(
  request: Request<ProxyBody>,
  limit: usize,
) -> Result<(Request<ProxyBody>, CapturedBody), BoxError> {
  let (parts, body) = request.into_parts();
  let content_length = parts
    .headers
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok());
  let (body, captured) = capture_proxy_body_prefix(body, limit, content_length).await?;
  Ok((Request::from_parts(parts, body), captured))
}

pub(crate) async fn capture_proxy_body_prefix(
  body: ProxyBody,
  limit: usize,
  content_length: Option<u64>,
) -> Result<(ProxyBody, CapturedBody), BoxError> {
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
    let frame = frame?;
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
  let body = ProxyReplayBody {
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

#[cfg(test)]
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

#[cfg(test)]
struct ReplayBody<B> {
  queued: VecDeque<Frame<Bytes>>,
  inner: Pin<Box<B>>,
}

struct ProxyReplayBody {
  queued: VecDeque<Frame<Bytes>>,
  inner: Pin<Box<ProxyBody>>,
}

#[cfg(test)]
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

  fn size_hint(&self) -> hyper::body::SizeHint {
    self.inner.size_hint()
  }
}

impl Body for ProxyReplayBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if let Some(frame) = self.queued.pop_front() {
      return Poll::Ready(Some(Ok(frame)));
    }

    self.inner.as_mut().poll_frame(cx)
  }

  fn is_end_stream(&self) -> bool {
    self.queued.is_empty() && self.inner.is_end_stream()
  }

  fn size_hint(&self) -> hyper::body::SizeHint {
    self.inner.size_hint()
  }
}
