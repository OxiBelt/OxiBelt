use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use http::{HeaderMap, Response};
use hyper::body::{Body, Frame, SizeHint};

use crate::config::TrailerMode;
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody};
use crate::proxy::http::semantics::filter_trailers;

use super::small_response::{SmallResponseDisposition, try_inline_response_body};
use super::stage_timing as timing;

pub(super) struct FastPathResponseBody {
  pub(super) body: ProxyBody,
  pub(super) known_small_response_body: bool,
  pub(super) inlined_known_small_body: Option<body::InlinedKnownSmallResponseBody>,
  pub(super) trailers_handled: bool,
  pub(super) disposition: &'static str,
  pub(super) reason: &'static str,
}

pub(super) struct FastPathResponseBodyError {
  pub(super) response: Response<ProxyBody>,
  pub(super) reason: &'static str,
}

pub(super) async fn fast_path_response_body<B>(
  headers: &HeaderMap,
  response_body: B,
  upstream_read_timeout: std::time::Duration,
  trailer_mode: TrailerMode,
  request_version: http::Version,
  direct_h1_first_frame_timing: Option<(Arc<Metrics>, FastPathMetricProtocol)>,
) -> Result<FastPathResponseBody, FastPathResponseBodyError>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  if let Some((metrics, protocol)) = direct_h1_first_frame_timing {
    return fast_path_response_body_inner(
      headers,
      DirectH1ResponseFirstFrameBody::new(response_body, metrics, protocol),
      upstream_read_timeout,
      trailer_mode,
      request_version,
    )
    .await;
  }
  fast_path_response_body_inner(
    headers,
    response_body,
    upstream_read_timeout,
    trailer_mode,
    request_version,
  )
  .await
}

async fn fast_path_response_body_inner<B>(
  headers: &HeaderMap,
  response_body: B,
  upstream_read_timeout: std::time::Duration,
  trailer_mode: TrailerMode,
  request_version: http::Version,
) -> Result<FastPathResponseBody, FastPathResponseBodyError>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  match try_inline_response_body(
    headers,
    response_body,
    upstream_read_timeout,
    trailer_mode,
    request_version != http::Version::HTTP_3,
  )
  .await
  {
    SmallResponseDisposition::Inlined { body, inlined } => Ok(FastPathResponseBody {
      body,
      known_small_response_body: true,
      inlined_known_small_body: inlined,
      trailers_handled: true,
      disposition: "inlined",
      reason: "known_small",
    }),
    SmallResponseDisposition::Streaming { body, .. } if body.is_end_stream() => {
      Ok(FastPathResponseBody {
        body,
        known_small_response_body: true,
        inlined_known_small_body: None,
        trailers_handled: true,
        disposition: "inlined",
        reason: "empty",
      })
    }
    SmallResponseDisposition::Streaming { body, reason } => Ok(FastPathResponseBody {
      body: body::with_read_timeout(
        body,
        upstream_read_timeout,
        BodyTimeoutKind::UpstreamResponseRead,
      ),
      known_small_response_body: false,
      inlined_known_small_body: None,
      trailers_handled: false,
      disposition: "streamed",
      reason: reason.as_str(),
    }),
    SmallResponseDisposition::Error { response, reason } => Err(FastPathResponseBodyError {
      response,
      reason: reason.as_str(),
    }),
  }
}

pub(super) fn fast_path_filter_trailers(body: ProxyBody, mode: TrailerMode) -> ProxyBody {
  if body.is_end_stream() {
    return body;
  }
  if mode == TrailerMode::Pass {
    return body;
  }
  filter_trailers(body, mode, false)
}

struct DirectH1ResponseFirstFrameBody<B> {
  body: B,
  metrics: Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  started_at: Option<std::time::Instant>,
  recorded: bool,
}

impl<B> DirectH1ResponseFirstFrameBody<B>
where
  B: Body,
{
  fn new(body: B, metrics: Arc<Metrics>, protocol: FastPathMetricProtocol) -> Self {
    let mut wrapper = Self {
      body,
      metrics,
      protocol,
      started_at: timing::start(true),
      recorded: false,
    };
    if wrapper.body.is_end_stream() {
      wrapper.record(true);
    }
    wrapper
  }

  fn record(&mut self, success: bool) {
    if self.recorded {
      return;
    }
    self.recorded = true;
    timing::record_metrics_plain_result(
      &self.metrics,
      self.protocol,
      timing::STAGE_DIRECT_H1_RESPONSE_BODY_FIRST_FRAME,
      success,
      self.started_at,
    );
  }
}

impl<B> Body for DirectH1ResponseFirstFrameBody<B>
where
  B: Body<Data = bytes::Bytes> + Unpin,
{
  type Data = bytes::Bytes;
  type Error = B::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut TaskContext<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let poll = Pin::new(&mut self.body).poll_frame(cx);
    let success = match &poll {
      Poll::Ready(Some(Ok(_))) | Poll::Ready(None) => Some(true),
      Poll::Ready(Some(Err(_))) => Some(false),
      Poll::Pending => None,
    };
    if let Some(success) = success {
      self.record(success);
    }
    poll
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}
