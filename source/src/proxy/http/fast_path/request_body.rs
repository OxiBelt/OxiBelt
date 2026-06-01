use std::pin::Pin;
use std::task::{Context, Poll};

use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{HeaderMap, Method};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Body, Frame, SizeHint};

use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody};

#[allow(clippy::manual_async_fn)]
pub(super) fn fast_path_request_body<B>(
  body: B,
  max_body_bytes: usize,
  timeout: std::time::Duration,
  definitely_empty: bool,
  empty_probe_allowed: bool,
) -> impl std::future::Future<Output = ProxyBody> + Send
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  async move {
    if body.is_end_stream() || definitely_empty {
      return empty_body();
    }

    if empty_probe_allowed {
      return fast_path_request_body_with_empty_probe(body, max_body_bytes, timeout).await;
    }

    body::with_read_timeout(
      Limited::new(body, max_body_bytes),
      timeout,
      BodyTimeoutKind::DownstreamRequestRead,
    )
  }
}

#[allow(clippy::manual_async_fn)]
fn fast_path_request_body_with_empty_probe<B>(
  body: B,
  max_body_bytes: usize,
  timeout: std::time::Duration,
) -> impl std::future::Future<Output = ProxyBody> + Send
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  async move {
    let size_hint = body.size_hint();
    let mut body = Box::pin(body);
    let first = match fast_path_poll_request_body_once(body.as_mut()) {
      Poll::Ready(None) => return empty_body(),
      Poll::Ready(Some(frame)) => Some(frame),
      Poll::Pending => {
        if body.is_end_stream() {
          return empty_body();
        }
        tokio::task::yield_now().await;
        if body.is_end_stream() {
          return empty_body();
        }
        match fast_path_poll_request_body_once(body.as_mut()) {
          Poll::Ready(None) => return empty_body(),
          Poll::Ready(Some(frame)) => Some(frame),
          Poll::Pending => None,
        }
      }
    };

    body::with_read_timeout(
      Limited::new(
        PeekedRequestBody {
          first,
          body,
          size_hint,
        },
        max_body_bytes,
      ),
      timeout,
      BodyTimeoutKind::DownstreamRequestRead,
    )
  }
}

fn fast_path_poll_request_body_once<B>(
  body: Pin<&mut B>,
) -> Poll<Option<Result<Frame<bytes::Bytes>, B::Error>>>
where
  B: Body<Data = bytes::Bytes>,
{
  let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
  body.poll_frame(&mut context)
}

struct PeekedRequestBody<B>
where
  B: Body<Data = bytes::Bytes>,
{
  first: Option<Result<Frame<bytes::Bytes>, B::Error>>,
  body: Pin<Box<B>>,
  size_hint: SizeHint,
}

impl<B> Unpin for PeekedRequestBody<B> where B: Body<Data = bytes::Bytes> {}

impl<B> Body for PeekedRequestBody<B>
where
  B: Body<Data = bytes::Bytes>,
{
  type Data = bytes::Bytes;
  type Error = B::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if let Some(frame) = self.first.take() {
      return Poll::Ready(Some(frame));
    }

    self.body.as_mut().poll_frame(cx)
  }

  fn is_end_stream(&self) -> bool {
    self.first.is_none() && self.body.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.size_hint.clone()
  }
}

pub(super) fn fast_path_request_body_is_definitely_empty(
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  if !matches!(version, http::Version::HTTP_10 | http::Version::HTTP_11)
    || headers.contains_key(TRANSFER_ENCODING)
  {
    return false;
  }

  let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
  let Some(content_length) = content_lengths.next() else {
    return true;
  };
  content_lengths.next().is_none()
    && content_length
      .to_str()
      .ok()
      .is_some_and(|value| value.trim() == "0")
}

pub(super) fn fast_path_request_body_empty_probe_allowed(
  method: &Method,
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  matches!(version, http::Version::HTTP_2 | http::Version::HTTP_3)
    && matches!(method, &Method::GET | &Method::HEAD)
    && !headers.contains_key(CONTENT_LENGTH)
    && !headers.contains_key(TRANSFER_ENCODING)
}

fn empty_body() -> ProxyBody {
  Empty::<bytes::Bytes>::new()
    .map_err(|never| -> body::BoxError { match never {} })
    .boxed()
}
