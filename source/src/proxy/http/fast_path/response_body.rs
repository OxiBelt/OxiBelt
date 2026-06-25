use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use http::{HeaderMap, Method, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};

use crate::config::TrailerMode;
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody};
use crate::proxy::http::semantics::filter_trailers;

use super::small_response::{
  SmallResponseDisposition, SmallResponseFirstFrameRecorder, SmallResponseMaterialization,
  try_inline_response_body_with_first_frame_recorder,
};
use super::stage_timing as timing;

pub(super) struct FastPathResponseBody {
  pub(super) body: ProxyBody,
  pub(super) known_small_response_body: bool,
  pub(super) inlined_known_small_body: Option<body::InlinedKnownSmallResponseBody>,
  pub(super) known_no_trailers: bool,
  pub(super) trailers_handled: bool,
  pub(super) disposition: &'static str,
  pub(super) reason: &'static str,
}

pub(super) struct FastPathResponseBodyError {
  pub(super) response: Response<ProxyBody>,
  pub(super) reason: &'static str,
}

pub(super) struct FastPathResponseBodyOptions {
  pub(super) upstream_read_timeout: Duration,
  pub(super) trailer_mode: TrailerMode,
  pub(super) request_version: http::Version,
  pub(super) compiled_known_small_noop_candidate: bool,
  pub(super) direct_h1_first_frame_timing: Option<(Arc<Metrics>, FastPathMetricProtocol)>,
}

pub(super) struct FastPathResponseSemantics {
  request_method: Method,
  response_status: StatusCode,
}

impl FastPathResponseSemantics {
  pub(super) fn new(request_method: Method, response_status: StatusCode) -> Self {
    Self {
      request_method,
      response_status,
    }
  }

  fn response_body_must_be_empty(&self) -> bool {
    self.request_method == Method::HEAD
      || self.response_status.is_informational()
      || self.response_status == StatusCode::NO_CONTENT
      || self.response_status == StatusCode::NOT_MODIFIED
  }
}

pub(super) async fn fast_path_response_body<B>(
  semantics: FastPathResponseSemantics,
  headers: &HeaderMap,
  response_body: B,
  options: FastPathResponseBodyOptions,
) -> Result<FastPathResponseBody, FastPathResponseBodyError>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  let mut first_frame_timing = options
    .direct_h1_first_frame_timing
    .map(|(metrics, protocol)| DirectH1ResponseFirstFrameTiming::new(metrics, protocol));
  fast_path_response_body_inner(
    semantics,
    headers,
    response_body,
    FastPathResponseBodyInnerOptions {
      upstream_read_timeout: options.upstream_read_timeout,
      trailer_mode: options.trailer_mode,
      request_version: options.request_version,
      compiled_known_small_noop_candidate: options.compiled_known_small_noop_candidate,
      first_frame_timing: first_frame_timing.as_mut(),
    },
  )
  .await
}

struct FastPathResponseBodyInnerOptions<'a> {
  upstream_read_timeout: Duration,
  trailer_mode: TrailerMode,
  request_version: http::Version,
  compiled_known_small_noop_candidate: bool,
  first_frame_timing: Option<&'a mut DirectH1ResponseFirstFrameTiming>,
}

async fn fast_path_response_body_inner<B>(
  semantics: FastPathResponseSemantics,
  headers: &HeaderMap,
  response_body: B,
  mut options: FastPathResponseBodyInnerOptions<'_>,
) -> Result<FastPathResponseBody, FastPathResponseBodyError>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  if semantics.response_body_must_be_empty() {
    let body = response_body
      .map_err(|error| -> body::BoxError { error.into() })
      .boxed();
    if body.is_end_stream() {
      record_first_frame_success(options.first_frame_timing.as_deref_mut());
      return Ok(FastPathResponseBody {
        body,
        known_small_response_body: true,
        inlined_known_small_body: None,
        known_no_trailers: true,
        trailers_handled: true,
        disposition: "inlined",
        reason: "no_body_semantics",
      });
    }
    return Ok(FastPathResponseBody {
      body: streaming_body_with_timing(
        body,
        options.upstream_read_timeout,
        options.first_frame_timing,
      ),
      known_small_response_body: false,
      inlined_known_small_body: None,
      known_no_trailers: false,
      trailers_handled: false,
      disposition: "streamed",
      reason: "no_body_semantics",
    });
  }

  match try_inline_response_body_with_first_frame_recorder(
    headers,
    response_body,
    options.upstream_read_timeout,
    options.trailer_mode,
    response_materialization(
      options.request_version,
      options.compiled_known_small_noop_candidate,
    ),
    options
      .first_frame_timing
      .as_deref_mut()
      .map(|recorder| recorder as &mut dyn SmallResponseFirstFrameRecorder),
  )
  .await
  {
    SmallResponseDisposition::Inlined {
      body,
      inlined,
      trailers_present,
    } => Ok(FastPathResponseBody {
      body,
      known_small_response_body: true,
      inlined_known_small_body: inlined,
      known_no_trailers: !trailers_present,
      trailers_handled: true,
      disposition: "inlined",
      reason: "known_small",
    }),
    SmallResponseDisposition::Streaming { body, .. } if body.is_end_stream() => {
      record_first_frame_success(options.first_frame_timing.as_deref_mut());
      Ok(FastPathResponseBody {
        body,
        known_small_response_body: true,
        inlined_known_small_body: None,
        known_no_trailers: true,
        trailers_handled: true,
        disposition: "inlined",
        reason: "empty",
      })
    }
    SmallResponseDisposition::Streaming { body, reason } => Ok(FastPathResponseBody {
      body: streaming_body_with_timing(
        body,
        options.upstream_read_timeout,
        options.first_frame_timing,
      ),
      known_small_response_body: false,
      inlined_known_small_body: None,
      known_no_trailers: false,
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

fn streaming_body_with_timing(
  body: ProxyBody,
  upstream_read_timeout: std::time::Duration,
  first_frame_timing: Option<&mut DirectH1ResponseFirstFrameTiming>,
) -> ProxyBody {
  let body = match first_frame_timing {
    Some(timing) => DirectH1ResponseFirstFrameBody::new(body, timing.take()).boxed(),
    None => body,
  };
  body::with_read_timeout(
    body,
    upstream_read_timeout,
    BodyTimeoutKind::UpstreamResponseRead,
  )
}

fn record_first_frame_success(timing: Option<&mut DirectH1ResponseFirstFrameTiming>) {
  if let Some(timing) = timing {
    timing.record(true);
  }
}

fn response_materialization(
  request_version: http::Version,
  compiled_known_small_noop_candidate: bool,
) -> SmallResponseMaterialization {
  if compiled_known_small_noop_candidate {
    match request_version {
      http::Version::HTTP_2 => return SmallResponseMaterialization::H2KnownSmallNoTrailers,
      http::Version::HTTP_3 => return SmallResponseMaterialization::MetadataOnly,
      _ => {}
    }
  }
  match request_version {
    http::Version::HTTP_2 => SmallResponseMaterialization::H2KnownSmallNoTrailers,
    http::Version::HTTP_3 => SmallResponseMaterialization::MetadataOnly,
    _ => SmallResponseMaterialization::Boxed,
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

struct DirectH1ResponseFirstFrameTiming {
  metrics: Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  started_at: Option<std::time::Instant>,
  recorded: bool,
}

impl DirectH1ResponseFirstFrameTiming {
  fn new(metrics: Arc<Metrics>, protocol: FastPathMetricProtocol) -> Self {
    Self {
      metrics,
      protocol,
      started_at: timing::start(true),
      recorded: false,
    }
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

  fn take(&mut self) -> Self {
    Self {
      metrics: self.metrics.clone(),
      protocol: self.protocol,
      started_at: self.started_at.take(),
      recorded: self.recorded,
    }
  }
}

impl SmallResponseFirstFrameRecorder for DirectH1ResponseFirstFrameTiming {
  fn record_first_frame(&mut self, success: bool) {
    self.record(success);
  }
}

struct DirectH1ResponseFirstFrameBody<B> {
  body: B,
  timing: DirectH1ResponseFirstFrameTiming,
}

impl<B> DirectH1ResponseFirstFrameBody<B>
where
  B: Body,
{
  fn new(body: B, mut timing: DirectH1ResponseFirstFrameTiming) -> Self {
    if body.is_end_stream() {
      timing.record(true);
    }
    Self { body, timing }
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
      self.timing.record(success);
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
