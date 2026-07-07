use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, TRAILER, TRANSFER_ENCODING};
use http::{HeaderMap, Method, StatusCode};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Body, Frame, SizeHint};

use crate::config::HttpVersion;
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{FastPathMetricProtocol, FastPathRequestBodyOutcome};
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody};
use crate::proxy::http::request_framing::{
  h2_or_h3_safe_method_empty_probe_allowed, http1_request_body_is_definitely_empty,
};
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::waf::BodyNeed;

#[cfg(test)]
pub(super) fn fast_path_empty_request_body() -> ProxyBody {
  empty_body()
}

pub(super) struct FastPathRequestBody {
  body: ProxyBody,
  mode: FastPathRequestBodyMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FastPathRequestBodyMode {
  Empty,
  SmallExact,
  Streaming,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FastPathSmallRequestBodyOptions {
  content_length: usize,
}

#[derive(Clone, Copy)]
pub(super) struct FastPathRequestBodyMetrics<'a> {
  pub(super) metrics: &'a Metrics,
  pub(super) protocol: FastPathMetricProtocol,
}

impl FastPathRequestBodyMetrics<'_> {
  fn record(self, outcome: FastPathRequestBodyOutcome) {
    self
      .metrics
      .record_fast_path_request_body_id(self.protocol, outcome);
  }
}

impl FastPathRequestBody {
  pub(super) fn empty() -> Self {
    Self {
      body: empty_body(),
      mode: FastPathRequestBodyMode::Empty,
    }
  }

  pub(super) fn streaming(body: ProxyBody) -> Self {
    Self {
      body,
      mode: FastPathRequestBodyMode::Streaming,
    }
  }

  fn small_exact(bytes: Bytes) -> Self {
    Self {
      body: body::known_small_no_trailers_body(bytes),
      mode: FastPathRequestBodyMode::SmallExact,
    }
  }

  pub(super) fn proven_empty(&self) -> bool {
    self.mode == FastPathRequestBodyMode::Empty
  }

  pub(super) fn is_small_exact(&self) -> bool {
    self.mode == FastPathRequestBodyMode::SmallExact
  }

  pub(super) fn mode(&self) -> FastPathRequestBodyMode {
    self.mode
  }

  pub(super) fn into_body(self) -> ProxyBody {
    self.body
  }
}

impl FastPathSmallRequestBodyOptions {
  fn new(content_length: usize) -> Self {
    Self { content_length }
  }

  fn content_length(self) -> usize {
    self.content_length
  }
}

pub(super) fn fast_path_small_request_body_options(
  method: &Method,
  small_body_candidate: bool,
  retry_policy_enabled: bool,
  headers: &HeaderMap,
  max_body_bytes: usize,
  small_body_max_bytes: usize,
) -> Option<FastPathSmallRequestBodyOptions> {
  if !small_body_candidate
    || retry_policy_enabled
    || method != Method::POST
    || headers.contains_key(TRANSFER_ENCODING)
    || headers.contains_key(TRAILER)
  {
    return None;
  }

  let content_length = headers
    .get(CONTENT_LENGTH)?
    .to_str()
    .ok()?
    .parse::<u64>()
    .ok()
    .and_then(|length| usize::try_from(length).ok())?;
  if content_length == 0 || content_length > small_body_max_bytes || content_length > max_body_bytes
  {
    return None;
  }
  Some(FastPathSmallRequestBodyOptions::new(content_length))
}

pub(super) fn fast_path_small_request_body_candidate(
  upstream_version: HttpVersion,
  request_waf_body_need: BodyNeed,
) -> bool {
  upstream_version == HttpVersion::H1 && request_waf_body_need == BodyNeed::None
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
#[cfg(test)]
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

#[allow(clippy::too_many_arguments)]
#[allow(clippy::manual_async_fn)]
pub(super) fn fast_path_prepare_nonempty_request_body<'a, B>(
  body: B,
  method: &Method,
  version: http::Version,
  headers: &HeaderMap,
  state: &'a AppSnapshot,
  resolved: &ResolvedRoute<'_>,
  upstream_version: HttpVersion,
  retry_policy_enabled: bool,
  metric_protocol: FastPathMetricProtocol,
) -> impl std::future::Future<Output = Result<FastPathRequestBody, body::BoxError>> + Send + 'a
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  let client_body_timeout = EffectiveTimeouts::route_body_only(&state.config, resolved.route);
  let empty_probe_allowed = fast_path_request_body_empty_probe_allowed(method, version, headers);
  let metrics =
    state
      .request_path_features
      .hot_path_metrics
      .then_some(FastPathRequestBodyMetrics {
        metrics: state.metrics.as_ref(),
        protocol: metric_protocol,
      });
  let max_body_bytes = resolved
    .route
    .effective_max_request_body_bytes(&state.config.limits) as usize;
  let small_options = fast_path_small_request_body_options(
    method,
    fast_path_small_request_body_candidate(
      upstream_version,
      resolved.execution_plan.waf.request.body_need(),
    ),
    retry_policy_enabled,
    headers,
    max_body_bytes,
    state
      .config
      .proxy
      .http
      .direct_h1_small_request_body_max_bytes,
  );

  fast_path_request_body_with_small_exact(
    body,
    max_body_bytes,
    client_body_timeout,
    empty_probe_allowed,
    small_options,
    metrics,
  )
}

#[allow(clippy::manual_async_fn)]
pub(super) fn fast_path_request_body_with_small_exact<'a, B>(
  body: B,
  max_body_bytes: usize,
  timeout: std::time::Duration,
  empty_probe_allowed: bool,
  small_request_body_options: Option<FastPathSmallRequestBodyOptions>,
  metrics: Option<FastPathRequestBodyMetrics<'a>>,
) -> impl std::future::Future<Output = Result<FastPathRequestBody, body::BoxError>> + Send + 'a
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  async move {
    if let Some(options) = small_request_body_options {
      return fast_path_small_exact_request_body(body, max_body_bytes, timeout, options, metrics)
        .await;
    }
    Ok(
      fast_path_request_body_inner(
        body,
        max_body_bytes,
        timeout,
        false,
        empty_probe_allowed,
        metrics,
      )
      .await,
    )
  }
}

pub(super) fn fast_path_request_body_error_status(
  error: &body::BoxError,
) -> (StatusCode, &'static str) {
  if body::error_is_timeout(error, BodyTimeoutKind::DownstreamRequestRead) {
    (StatusCode::REQUEST_TIMEOUT, "request body timed out")
  } else if body::error_is_body_length_limit(error) {
    (StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
  } else {
    (StatusCode::BAD_REQUEST, "invalid request body")
  }
}

#[allow(clippy::manual_async_fn)]
pub(super) fn fast_path_small_exact_request_body<'a, B>(
  body: B,
  max_body_bytes: usize,
  timeout: std::time::Duration,
  options: FastPathSmallRequestBodyOptions,
  metrics: Option<FastPathRequestBodyMetrics<'a>>,
) -> impl std::future::Future<Output = Result<FastPathRequestBody, body::BoxError>> + Send + 'a
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  async move {
    let mut body = body::with_read_timeout(
      Limited::new(body, max_body_bytes),
      timeout,
      BodyTimeoutKind::DownstreamRequestRead,
    );
    let expected = options.content_length();
    let mut bytes = BytesMut::with_capacity(expected);
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
      let frame = frame?;
      match frame.into_data() {
        Ok(data) => {
          let actual = bytes.len().saturating_add(data.len());
          if actual > expected {
            return Err(body::boxed_error(RequestBodyLengthMismatch {
              expected,
              actual,
            }));
          }
          bytes.extend_from_slice(&data);
        }
        Err(frame) => {
          if let Ok(frame_trailers) = frame.into_trailers() {
            trailers = Some(frame_trailers);
          }
        }
      }
    }

    let bytes = bytes.freeze();
    if bytes.len() != expected {
      return Err(body::boxed_error(RequestBodyLengthMismatch {
        expected,
        actual: bytes.len(),
      }));
    }

    if let Some(metrics) = metrics {
      metrics.record(FastPathRequestBodyOutcome::Streaming);
    }
    if let Some(trailers) = trailers {
      return Ok(FastPathRequestBody::streaming(
        body::materialized_known_small_body(bytes, Some(trailers)),
      ));
    }
    Ok(FastPathRequestBody::small_exact(bytes))
  }
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
          FastPathRequestBodyOutcome::VerifiedEmpty
        } else {
          FastPathRequestBodyOutcome::AlreadyEmpty
        });
      }
      return FastPathRequestBody::empty();
    }

    if empty_probe_allowed {
      return fast_path_request_body_with_empty_probe(body, max_body_bytes, timeout, metrics).await;
    }

    if let Some(metrics) = metrics {
      metrics.record(FastPathRequestBodyOutcome::Streaming);
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
          metrics.record(FastPathRequestBodyOutcome::ProbeEof);
        }
        return FastPathRequestBody::empty();
      }
      Poll::Ready(Some(frame)) => Some(frame),
      Poll::Pending => {
        if body.is_end_stream() {
          if let Some(metrics) = metrics {
            metrics.record(FastPathRequestBodyOutcome::ProbeEof);
          }
          return FastPathRequestBody::empty();
        }
        tokio::task::yield_now().await;
        if body.is_end_stream() {
          if let Some(metrics) = metrics {
            metrics.record(FastPathRequestBodyOutcome::ProbeEof);
          }
          return FastPathRequestBody::empty();
        }
        match fast_path_poll_request_body_once(Pin::new(&mut body)) {
          Poll::Ready(None) => {
            if let Some(metrics) = metrics {
              metrics.record(FastPathRequestBodyOutcome::ProbeEof);
            }
            return FastPathRequestBody::empty();
          }
          Poll::Ready(Some(frame)) => Some(frame),
          Poll::Pending => None,
        }
      }
    };

    if let Some(metrics) = metrics {
      metrics.record(FastPathRequestBodyOutcome::Streaming);
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

fn empty_body() -> ProxyBody {
  Empty::<bytes::Bytes>::new()
    .map_err(|never| -> body::BoxError { match never {} })
    .boxed()
}

#[derive(Debug)]
struct RequestBodyLengthMismatch {
  expected: usize,
  actual: usize,
}

impl std::fmt::Display for RequestBodyLengthMismatch {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "request body length mismatch: expected {} bytes, received {} bytes",
      self.expected, self.actual
    )
  }
}

impl std::error::Error for RequestBodyLengthMismatch {}
