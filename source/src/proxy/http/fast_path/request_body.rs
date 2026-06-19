use std::pin::Pin;
use std::task::{Context, Poll};

use http::{HeaderMap, Method};
use http_body_util::Limited;
use hyper::body::{Body, Frame, SizeHint};

use crate::metrics::Metrics;
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody};
use crate::proxy::http::request_framing::{
  h2_or_h3_safe_method_empty_probe_allowed, http1_request_body_is_definitely_empty,
};

#[cfg(test)]
pub(super) fn fast_path_empty_request_body() -> ProxyBody {
  body::empty()
}

pub(super) struct FastPathRequestBody {
  body: ProxyBody,
  proven_empty: bool,
}

#[derive(Clone, Copy)]
pub(super) struct FastPathRequestBodyMetrics<'a> {
  pub(super) metrics: &'a Metrics,
  pub(super) protocol: &'static str,
}

impl FastPathRequestBodyMetrics<'_> {
  fn record(self, outcome: &str) {
    self
      .metrics
      .record_fast_path_request_body(self.protocol, outcome);
  }
}

impl FastPathRequestBody {
  pub(super) fn empty() -> Self {
    Self {
      body: body::empty(),
      proven_empty: true,
    }
  }

  pub(super) fn streaming(body: ProxyBody) -> Self {
    Self {
      body,
      proven_empty: false,
    }
  }

  pub(super) fn proven_empty(&self) -> bool {
    self.proven_empty
  }

  pub(super) fn into_body(self) -> ProxyBody {
    self.body
  }
}

impl Body for FastPathRequestBody {
  type Data = bytes::Bytes;
  type Error = body::BoxError;

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

#[allow(clippy::manual_async_fn)]
#[cfg(test)]
pub(super) fn fast_path_request_body<B>(
  body: B,
  max_body_bytes: usize,
  timeout: std::time::Duration,
  definitely_empty: bool,
  empty_probe_allowed: bool,
) -> impl std::future::Future<Output = FastPathRequestBody> + Send
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  fast_path_request_body_inner(
    body,
    max_body_bytes,
    timeout,
    definitely_empty,
    empty_probe_allowed,
    None,
  )
}

#[allow(clippy::manual_async_fn)]
pub(super) fn fast_path_request_body_with_metrics<'a, B>(
  body: B,
  max_body_bytes: usize,
  timeout: std::time::Duration,
  definitely_empty: bool,
  empty_probe_allowed: bool,
  metrics: Option<FastPathRequestBodyMetrics<'a>>,
) -> impl std::future::Future<Output = FastPathRequestBody> + Send + 'a
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  fast_path_request_body_inner(
    body,
    max_body_bytes,
    timeout,
    definitely_empty,
    empty_probe_allowed,
    metrics,
  )
}

#[allow(clippy::manual_async_fn)]
fn fast_path_request_body_inner<'a, B>(
  body: B,
  max_body_bytes: usize,
  timeout: std::time::Duration,
  definitely_empty: bool,
  empty_probe_allowed: bool,
  metrics: Option<FastPathRequestBodyMetrics<'a>>,
) -> impl std::future::Future<Output = FastPathRequestBody> + Send + 'a
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  async move {
    if body.is_end_stream() || definitely_empty {
      if let Some(metrics) = metrics {
        metrics.record(if definitely_empty {
          "verified_empty"
        } else {
          "already_empty"
        });
      }
      return FastPathRequestBody::empty();
    }

    if empty_probe_allowed {
      return fast_path_request_body_with_empty_probe(body, max_body_bytes, timeout, metrics).await;
    }

    if let Some(metrics) = metrics {
      metrics.record("streaming");
    }
    FastPathRequestBody::streaming(body::with_read_timeout(
      Limited::new(body, max_body_bytes),
      timeout,
      BodyTimeoutKind::DownstreamRequestRead,
    ))
  }
}

#[allow(clippy::manual_async_fn)]
fn fast_path_request_body_with_empty_probe<B>(
  body: B,
  max_body_bytes: usize,
  timeout: std::time::Duration,
  metrics: Option<FastPathRequestBodyMetrics<'_>>,
) -> impl std::future::Future<Output = FastPathRequestBody> + Send
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  async move {
    let mut body = body;
    let first = match fast_path_poll_request_body_once(Pin::new(&mut body)) {
      Poll::Ready(None) => {
        if let Some(metrics) = metrics {
          metrics.record("probe_eof");
        }
        return FastPathRequestBody::empty();
      }
      Poll::Ready(Some(frame)) => Some(frame),
      Poll::Pending => {
        if body.is_end_stream() {
          if let Some(metrics) = metrics {
            metrics.record("probe_eof");
          }
          return FastPathRequestBody::empty();
        }
        tokio::task::yield_now().await;
        if body.is_end_stream() {
          if let Some(metrics) = metrics {
            metrics.record("probe_eof");
          }
          return FastPathRequestBody::empty();
        }
        match fast_path_poll_request_body_once(Pin::new(&mut body)) {
          Poll::Ready(None) => {
            if let Some(metrics) = metrics {
              metrics.record("probe_eof");
            }
            return FastPathRequestBody::empty();
          }
          Poll::Ready(Some(frame)) => Some(frame),
          Poll::Pending => None,
        }
      }
    };

    if let Some(metrics) = metrics {
      metrics.record("streaming");
    }
    FastPathRequestBody::streaming(body::with_read_timeout(
      Limited::new(
        PeekedRequestBody {
          first,
          body,
          size_hint: SizeHint::new(),
        },
        max_body_bytes,
      ),
      timeout,
      BodyTimeoutKind::DownstreamRequestRead,
    ))
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
  body: B,
  size_hint: SizeHint,
}

impl<B> Body for PeekedRequestBody<B>
where
  B: Body<Data = bytes::Bytes> + Unpin,
  B::Error: Unpin,
{
  type Data = bytes::Bytes;
  type Error = B::Error;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let this = self.get_mut();
    if let Some(frame) = this.first.take() {
      return Poll::Ready(Some(frame));
    }

    Pin::new(&mut this.body).poll_frame(cx)
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
  http1_request_body_is_definitely_empty(version, headers)
}

pub(super) fn fast_path_request_body_empty_probe_allowed(
  method: &Method,
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  h2_or_h3_safe_method_empty_probe_allowed(method, version, headers)
}
