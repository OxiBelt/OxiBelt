//! HTTP semantic helpers centralize trailer, expectation, and error-response handling.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, EXPECT, HeaderMap, HeaderName, HeaderValue, LINK};
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use oxibelt_control_protocol::HyphenUnderscoreHeaderNameSet;
use tokio::sync::Notify;

use crate::config::{
  Config, EarlyHintsMode, ErrorResponseMode, ExpectContinueMode, GrpcRetryMode, PriorityMode,
  TrailerMode,
};

use super::EffectiveTimeouts;
use super::body::{BoxError, ProxyBody};
use super::headers::sanitize_request_trailers_for_upstream;

const PRIORITY: HeaderName = HeaderName::from_static("priority");
const GRPC_STATUS: HeaderName = HeaderName::from_static("grpc-status");
const GRPC_MESSAGE: HeaderName = HeaderName::from_static("grpc-message");
const GRPC_TIMEOUT: HeaderName = HeaderName::from_static("grpc-timeout");

#[derive(Clone, Debug, Default)]
pub(crate) struct InterimResponses {
  pub(crate) responses: Vec<InterimResponse>,
}

#[derive(Clone, Debug)]
pub(crate) struct InterimResponse {
  pub(crate) status: StatusCode,
  pub(crate) headers: HeaderMap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EarlyHintCaptureOutcome {
  Ignored,
  Captured,
  AtCapacity,
}

#[derive(Clone, Default)]
pub(crate) struct EarlyHintsCapture {
  inner: Arc<Mutex<InterimResponses>>,
}

impl EarlyHintsCapture {
  pub(crate) fn take(&self) -> InterimResponses {
    let mut inner = self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::mem::take(&mut *inner)
  }
}

/// Captures configured 103 responses and relays negotiated informational
/// responses live. This retains arrival order for a 100, 103, 104 sequence.
///
/// The relay failure is deliberately retained for the request pipeline to turn
/// into an exchange failure. Hyper's informational callback has no error return
/// path, so silently ignoring a bounded-emitter failure would violate ordering.
#[derive(Clone)]
pub(crate) struct UpstreamInformationalCapture {
  early_hints: EarlyHintsCapture,
  relay_failure: Arc<Mutex<Option<super::informational::SendError>>>,
  relay_failure_notify: Arc<Notify>,
}

impl UpstreamInformationalCapture {
  pub(crate) fn take_early_hints(&self) -> InterimResponses {
    self.early_hints.take()
  }

  pub(crate) fn take_relay_failure(&self) -> Option<super::informational::SendError> {
    self
      .relay_failure
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .take()
  }

  pub(crate) async fn relay_failed(&self) -> super::informational::SendError {
    loop {
      let notified = self.relay_failure_notify.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      if let Some(error) = *self
        .relay_failure
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
      {
        return error;
      }
      notified.await;
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum ExpectRejection {
  Disabled,
  Unsupported,
}

impl ExpectRejection {
  pub(super) fn message(self) -> &'static str {
    match self {
      Self::Disabled => "Expect: 100-continue is disabled",
      Self::Unsupported => "unsupported Expect header",
    }
  }
}

pub(super) fn validate_expect(
  headers: &HeaderMap,
  mode: ExpectContinueMode,
) -> Result<(), ExpectRejection> {
  if !headers.contains_key(EXPECT) {
    return Ok(());
  }
  if mode == ExpectContinueMode::Reject {
    return Err(ExpectRejection::Disabled);
  }
  let accepted = headers
    .get_all(EXPECT)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .all(|value| value.trim().eq_ignore_ascii_case("100-continue"));
  if accepted {
    Ok(())
  } else {
    Err(ExpectRejection::Unsupported)
  }
}

pub(super) fn strip_accepted_expect(headers: &mut HeaderMap) {
  if !headers.contains_key(EXPECT) {
    return;
  }
  if headers
    .get_all(EXPECT)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .all(|value| value.trim().eq_ignore_ascii_case("100-continue"))
  {
    headers.remove(EXPECT);
  }
}

pub(super) fn apply_priority_policy(headers: &mut HeaderMap, mode: PriorityMode) {
  if mode == PriorityMode::Ignore {
    headers.remove(PRIORITY);
  }
}

#[cfg(test)]
pub(crate) fn attach_early_hints_capture<B>(
  request: &mut Request<B>,
  mode: EarlyHintsMode,
) -> Option<EarlyHintsCapture> {
  if mode == EarlyHintsMode::Drop {
    return None;
  }
  let capture = EarlyHintsCapture::default();
  let callback_capture = capture.clone();
  hyper::ext::on_informational(request, move |response| {
    let mut interim = callback_capture
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Hyper owns the informational-response parser, so retain its established
    // capture behavior. Bounded protocol engines pass their validated limit.
    let _ = capture_early_hint(
      &mut interim,
      mode,
      response.status(),
      response.headers(),
      usize::MAX,
    );
  });
  Some(capture)
}

/// Attach the one upstream informational callback used for both existing 103
/// capture and interop-9 live 104 relay.
///
/// An incompatible draft response is ignored as required by draft-12; it is
/// not exposed as a final-response extension. The callback never changes
/// `Incremental` state or request deadlines.
pub(crate) fn attach_upstream_informational_capture<B>(
  request: &mut Request<B>,
  mode: EarlyHintsMode,
) -> Option<UpstreamInformationalCapture> {
  let relay_candidate = super::informational::relay_armed(request);
  let emitter = request
    .extensions()
    .get::<super::informational::Emitter>()
    .cloned();
  let incremental_exchange = request
    .extensions()
    .get::<super::incremental_exchange::IncrementalExchange>()
    .cloned();
  if mode == EarlyHintsMode::Drop && !relay_candidate {
    return None;
  }
  let relay_failure = relay_candidate
    .then_some(super::informational::SendError::MissingEmitter)
    .filter(|_| emitter.is_none());
  let capture = UpstreamInformationalCapture {
    early_hints: EarlyHintsCapture::default(),
    relay_failure: Arc::new(Mutex::new(relay_failure)),
    relay_failure_notify: Arc::new(Notify::new()),
  };
  let callback_capture = capture.clone();
  hyper::ext::on_informational(request, move |response| {
    if callback_capture
      .relay_failure
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .is_some()
    {
      return;
    }
    if let Some(emitter) = emitter.as_ref()
      && live_relay_eligible(mode, relay_candidate, response.status(), response.headers())
    {
      let mut interim = Response::new(());
      *interim.status_mut() = response.status();
      *interim.headers_mut() = live_relay_headers(response.status(), response.headers());
      if let Err(error) = super::informational::send_via(emitter, interim) {
        if let Some(exchange) = &incremental_exchange {
          // The sender cannot return an error through Hyper's callback. Stop
          // an in-flight upload immediately; the pipeline later converts the
          // retained failure into the terminal exchange error.
          exchange.cancel();
        }
        let mut relay_failure = callback_capture
          .relay_failure
          .lock()
          .unwrap_or_else(|poisoned| poisoned.into_inner());
        let first_failure = relay_failure.is_none();
        relay_failure.get_or_insert(error);
        drop(relay_failure);
        if first_failure {
          callback_capture.relay_failure_notify.notify_waiters();
        }
      }
      return;
    }
    // 104 is never a final response. An incompatible draft response is
    // intentionally ignored, but must not fall through to legacy handling.
    if response.status().as_u16() == 104 {
      return;
    }
    let mut interim = callback_capture
      .early_hints
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = capture_early_hint(
      &mut interim,
      mode,
      response.status(),
      response.headers(),
      usize::MAX,
    );
  });
  Some(capture)
}

/// Identifies upstream informational heads that a negotiated request must
/// deliver on the live downstream response path.  103 retains its configured
/// pass/drop policy; 100 and 102 are protocol progress signals, while 104 is
/// draft-gated by the matching interop version.
pub(crate) fn live_relay_eligible(
  mode: EarlyHintsMode,
  relay_candidate: bool,
  status: StatusCode,
  headers: &HeaderMap,
) -> bool {
  relay_candidate
    && match status.as_u16() {
      100 | 102 => true,
      103 => mode == EarlyHintsMode::Pass,
      104 => super::informational::compatible_104(headers),
      _ => false,
    }
}

/// Preserves the existing 103 sanitization rule on the new live path. Progress
/// statuses need no upstream metadata, while draft 104 headers carry the
/// negotiated resumption metadata and remain subject to sender framing checks.
pub(crate) fn live_relay_headers(status: StatusCode, headers: &HeaderMap) -> HeaderMap {
  match status.as_u16() {
    103 => match sanitize_interim_response(status, headers) {
      Some(response) => response.headers,
      None => HeaderMap::new(),
    },
    100 | 102 => HeaderMap::new(),
    _ => headers.clone(),
  }
}

pub(crate) fn sanitize_live_relay_response(mut response: Response<()>) -> Response<()> {
  let headers = live_relay_headers(response.status(), response.headers());
  *response.headers_mut() = headers;
  response
}

pub(crate) fn capture_early_hint(
  interim: &mut InterimResponses,
  mode: EarlyHintsMode,
  status: StatusCode,
  headers: &HeaderMap,
  max_responses: usize,
) -> EarlyHintCaptureOutcome {
  if mode == EarlyHintsMode::Drop || status != StatusCode::EARLY_HINTS {
    return EarlyHintCaptureOutcome::Ignored;
  }
  if interim.responses.len() >= max_responses {
    return EarlyHintCaptureOutcome::AtCapacity;
  }
  let Some(response) = sanitize_interim_response(status, headers) else {
    return EarlyHintCaptureOutcome::Ignored;
  };
  interim.responses.push(response);
  EarlyHintCaptureOutcome::Captured
}

pub(crate) fn sanitize_interim_response(
  status: StatusCode,
  headers: &HeaderMap,
) -> Option<InterimResponse> {
  if status != StatusCode::EARLY_HINTS {
    return None;
  }
  let mut sanitized = HeaderMap::new();
  for value in headers.get_all(LINK) {
    sanitized.append(LINK, value.clone());
  }
  Some(InterimResponse {
    status,
    headers: sanitized,
  })
}

pub(crate) fn attach_interim_responses<B>(response: &mut Response<B>, interim: InterimResponses) {
  if !interim.responses.is_empty() {
    response.extensions_mut().insert(interim);
  }
}

pub(super) fn is_sse(headers: &HeaderMap) -> bool {
  normalized_content_type(headers).is_some_and(|content_type| content_type == "text/event-stream")
}

pub(super) fn is_native_grpc_request(headers: &HeaderMap, config: &Config) -> bool {
  config.proxy.http.grpc.enabled && content_type_is_native_grpc(headers)
}

pub(super) fn should_retry_grpc(config: &Config) -> bool {
  config.proxy.http.grpc.retry == GrpcRetryMode::SafeUnary
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct GrpcTimeoutCaps {
  pub(super) upstream_first_byte: bool,
}

pub(super) fn cap_timeouts_for_grpc(
  mut timeouts: EffectiveTimeouts,
  headers: &HeaderMap,
  respect_grpc_timeout: bool,
) -> (EffectiveTimeouts, GrpcTimeoutCaps) {
  if !respect_grpc_timeout {
    return (timeouts, GrpcTimeoutCaps::default());
  }
  let Some(deadline) = parse_grpc_timeout(headers) else {
    return (timeouts, GrpcTimeoutCaps::default());
  };
  let caps = GrpcTimeoutCaps {
    upstream_first_byte: deadline < timeouts.upstream_first_byte,
  };
  timeouts.upstream_first_byte = timeouts.upstream_first_byte.min(deadline);
  timeouts.upstream_request = timeouts.upstream_request.min(deadline);
  timeouts.upstream_read = timeouts.upstream_read.min(deadline);
  (timeouts, caps)
}

pub(super) fn parse_grpc_timeout(headers: &HeaderMap) -> Option<Duration> {
  let value = headers.get(GRPC_TIMEOUT)?.to_str().ok()?.trim();
  let unit = value.chars().last()?;
  let number = value.strip_suffix(unit)?;
  if number.is_empty() || number.len() > 8 || !number.bytes().all(|byte| byte.is_ascii_digit()) {
    return None;
  }
  let amount = number.parse::<u64>().ok()?;
  match unit {
    'H' => amount.checked_mul(60 * 60).map(Duration::from_secs),
    'M' => amount.checked_mul(60).map(Duration::from_secs),
    'S' => Some(Duration::from_secs(amount)),
    'm' => Some(Duration::from_millis(amount)),
    'u' => Some(Duration::from_micros(amount)),
    'n' => Some(Duration::from_nanos(amount)),
    _ => None,
  }
}

pub(super) fn filter_trailers(
  body: ProxyBody,
  mode: TrailerMode,
  preserve_grpc: bool,
) -> ProxyBody {
  if mode == TrailerMode::Pass || preserve_grpc {
    return body;
  }
  DropTrailersBody { body }.boxed()
}

pub(super) fn sanitize_upstream_request_trailers(
  body: ProxyBody,
  identity_headers: Vec<HeaderName>,
  client_certificate_headers: HyphenUnderscoreHeaderNameSet,
) -> ProxyBody {
  if body.is_end_stream() {
    return body;
  }
  SanitizeRequestTrailersBody {
    body,
    identity_headers,
    client_certificate_headers,
  }
  .boxed()
}

pub(super) fn configured_error_response(
  config: &Config,
  request_id: &str,
  status: StatusCode,
  message: &str,
  code: &str,
) -> Response<ProxyBody> {
  match config.proxy.http.errors.mode {
    ErrorResponseMode::LegacyPlain => plain_response(status, message, None),
    ErrorResponseMode::Plain => plain_response(status, message, Some("text/plain; charset=utf-8")),
    ErrorResponseMode::Json => {
      let body = serde_json::json!({
        "error": message,
        "status": status.as_u16(),
        "code": code,
        "request_id": request_id,
      });
      let mut response = plain_response(status, &body.to_string(), Some("application/json"));
      response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
      response
    }
  }
}

pub(super) fn grpc_upstream_error_response(
  config: &Config,
  request_headers: &HeaderMap,
  upstream_error_code: &str,
  message: &str,
) -> Option<Response<ProxyBody>> {
  if !is_native_grpc_request(request_headers, config) {
    return None;
  }
  let grpc_status = if upstream_error_code.contains("timeout") {
    "4"
  } else {
    "14"
  };
  let mut response = plain_response(StatusCode::OK, "", Some("application/grpc"));
  response
    .headers_mut()
    .insert(GRPC_STATUS, HeaderValue::from_static(grpc_status));
  if let Ok(value) = HeaderValue::from_str(&sanitize_grpc_message(message)) {
    response.headers_mut().insert(GRPC_MESSAGE, value);
  }
  Some(response)
}

fn plain_response(
  status: StatusCode,
  message: &str,
  content_type: Option<&'static str>,
) -> Response<ProxyBody> {
  let mut response = super::response::text_response(status, message);
  if let Some(content_type) = content_type {
    response
      .headers_mut()
      .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
  }
  response
}

fn normalized_content_type(headers: &HeaderMap) -> Option<String> {
  headers
    .get(CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.split(';').next())
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .map(str::to_ascii_lowercase)
}

fn content_type_is_native_grpc(headers: &HeaderMap) -> bool {
  normalized_content_type(headers).is_some_and(|content_type| {
    content_type == "application/grpc" || content_type.starts_with("application/grpc+")
  })
}

fn sanitize_grpc_message(message: &str) -> String {
  message
    .chars()
    .filter(|ch| !matches!(ch, '\r' | '\n' | '\0'))
    .collect()
}

struct DropTrailersBody {
  body: ProxyBody,
}

struct SanitizeRequestTrailersBody {
  body: ProxyBody,
  identity_headers: Vec<HeaderName>,
  client_certificate_headers: HyphenUnderscoreHeaderNameSet,
}

impl Body for SanitizeRequestTrailersBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    match Pin::new(&mut self.body).poll_frame(cx) {
      Poll::Ready(Some(Ok(frame))) => match frame.into_trailers() {
        Ok(mut trailers) => {
          sanitize_request_trailers_for_upstream(
            &mut trailers,
            &self.identity_headers,
            &self.client_certificate_headers,
          );
          Poll::Ready(Some(Ok(Frame::trailers(trailers))))
        }
        Err(frame) => Poll::Ready(Some(Ok(frame))),
      },
      other => other,
    }
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

impl Body for DropTrailersBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let frame = match Pin::new(&mut self.body).poll_frame(cx) {
      Poll::Ready(frame) => frame,
      Poll::Pending => return Poll::Pending,
    };
    let Some(frame) = frame else {
      return Poll::Ready(None);
    };
    match frame {
      Ok(frame) if frame.is_trailers() => Poll::Ready(None),
      other => Poll::Ready(Some(other)),
    }
  }

  fn is_end_stream(&self) -> bool {
    self.body.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.body.size_hint()
  }
}

#[cfg(test)]
mod tests {
  use bytes::Bytes;
  use http::HeaderMap;
  use http_body_util::BodyExt;
  use hyper::body::Frame;

  use crate::config::{Config, EarlyHintsMode, ExpectContinueMode, TrailerMode};

  use super::*;
  use crate::proxy::http::body::channel_body;

  #[test]
  fn expect_auto_accepts_only_100_continue() {
    let mut headers = HeaderMap::new();
    headers.insert(EXPECT, HeaderValue::from_static("100-continue"));
    assert_eq!(validate_expect(&headers, ExpectContinueMode::Auto), Ok(()));

    headers.insert(EXPECT, HeaderValue::from_static("custom"));
    assert_eq!(
      validate_expect(&headers, ExpectContinueMode::Auto),
      Err(ExpectRejection::Unsupported)
    );
  }

  #[test]
  fn expect_reject_blocks_continue() {
    let mut headers = HeaderMap::new();
    headers.insert(EXPECT, HeaderValue::from_static("100-continue"));
    assert_eq!(
      validate_expect(&headers, ExpectContinueMode::Reject),
      Err(ExpectRejection::Disabled)
    );
  }

  #[test]
  fn early_hint_capture_applies_mode_sanitization_and_capacity() {
    let mut headers = HeaderMap::new();
    headers.append(
      LINK,
      HeaderValue::from_static("</app.css>; rel=preload; as=style"),
    );
    headers.append(
      LINK,
      HeaderValue::from_static("</app.js>; rel=preload; as=script"),
    );
    headers.insert(
      HeaderName::from_static("x-origin-secret"),
      HeaderValue::from_static("do-not-forward"),
    );
    let mut interim = InterimResponses::default();

    assert_eq!(
      capture_early_hint(
        &mut interim,
        EarlyHintsMode::Drop,
        StatusCode::EARLY_HINTS,
        &headers,
        1,
      ),
      EarlyHintCaptureOutcome::Ignored
    );
    for status in [
      StatusCode::CONTINUE,
      StatusCode::SWITCHING_PROTOCOLS,
      StatusCode::PROCESSING,
      StatusCode::OK,
    ] {
      assert_eq!(
        capture_early_hint(&mut interim, EarlyHintsMode::Pass, status, &headers, 1,),
        EarlyHintCaptureOutcome::Ignored
      );
    }
    assert_eq!(
      capture_early_hint(
        &mut interim,
        EarlyHintsMode::Pass,
        StatusCode::EARLY_HINTS,
        &headers,
        1,
      ),
      EarlyHintCaptureOutcome::Captured
    );
    assert_eq!(interim.responses.len(), 1);
    assert_eq!(interim.responses[0].headers.get_all(LINK).iter().count(), 2);
    assert!(!interim.responses[0].headers.contains_key("x-origin-secret"));
    assert_eq!(
      capture_early_hint(
        &mut interim,
        EarlyHintsMode::Pass,
        StatusCode::EARLY_HINTS,
        &headers,
        1,
      ),
      EarlyHintCaptureOutcome::AtCapacity
    );
    assert_eq!(interim.responses.len(), 1);
  }

  #[test]
  fn negotiated_live_relay_preserves_progress_ordering_contract() {
    let mut compatible_104 = HeaderMap::new();
    compatible_104.insert(
      "upload-draft-interop-version",
      HeaderValue::from_static("9"),
    );
    let empty = HeaderMap::new();

    assert!(live_relay_eligible(
      EarlyHintsMode::Pass,
      true,
      StatusCode::CONTINUE,
      &empty
    ));
    assert!(live_relay_eligible(
      EarlyHintsMode::Pass,
      true,
      StatusCode::EARLY_HINTS,
      &empty
    ));
    assert!(live_relay_eligible(
      EarlyHintsMode::Pass,
      true,
      StatusCode::from_u16(104).expect("104 status"),
      &compatible_104
    ));
    assert!(!live_relay_eligible(
      EarlyHintsMode::Drop,
      true,
      StatusCode::EARLY_HINTS,
      &empty
    ));
    assert!(!live_relay_eligible(
      EarlyHintsMode::Pass,
      true,
      StatusCode::from_u16(104).expect("104 status"),
      &empty
    ));
    assert!(!live_relay_eligible(
      EarlyHintsMode::Pass,
      false,
      StatusCode::CONTINUE,
      &empty
    ));
  }

  #[test]
  fn live_relay_keeps_103_sanitized_and_104_metadata() {
    let mut hints = HeaderMap::new();
    hints.insert(LINK, HeaderValue::from_static("</upload.css>; rel=preload"));
    hints.insert("x-origin-secret", HeaderValue::from_static("drop"));
    let sanitized = live_relay_headers(StatusCode::EARLY_HINTS, &hints);
    assert_eq!(sanitized.get(LINK), hints.get(LINK));
    assert!(!sanitized.contains_key("x-origin-secret"));

    let mut resume = HeaderMap::new();
    resume.insert(
      "upload-draft-interop-version",
      HeaderValue::from_static("9"),
    );
    resume.insert("upload-offset", HeaderValue::from_static("4096"));
    assert_eq!(
      live_relay_headers(StatusCode::from_u16(104).expect("104 status"), &resume),
      resume
    );
  }

  #[test]
  fn grpc_timeout_parses_units() {
    let mut headers = HeaderMap::new();
    headers.insert(GRPC_TIMEOUT, HeaderValue::from_static("250m"));
    assert_eq!(
      parse_grpc_timeout(&headers),
      Some(Duration::from_millis(250))
    );
    headers.insert(GRPC_TIMEOUT, HeaderValue::from_static("2S"));
    assert_eq!(parse_grpc_timeout(&headers), Some(Duration::from_secs(2)));
    headers.insert(GRPC_TIMEOUT, HeaderValue::from_static("3u"));
    assert_eq!(parse_grpc_timeout(&headers), Some(Duration::from_micros(3)));
  }

  #[test]
  fn grpc_timeout_cap_records_client_limited_first_byte() {
    let mut headers = HeaderMap::new();
    headers.insert(GRPC_TIMEOUT, HeaderValue::from_static("0n"));
    let timeouts = EffectiveTimeouts {
      response_send: Duration::from_secs(30),
      websocket_idle: Duration::from_secs(30),
      webtransport_idle: Duration::from_secs(30),
      upstream_connect: Duration::from_secs(3),
      upstream_request: Duration::from_secs(30),
      upstream_first_byte: Duration::from_secs(30),
      upstream_read: Duration::from_secs(30),
      upstream_send: Duration::from_secs(30),
      upstream_deadline: None,
    };

    let (timeouts, caps) = cap_timeouts_for_grpc(timeouts, &headers, true);

    assert_eq!(timeouts.upstream_first_byte, Duration::ZERO);
    assert_eq!(timeouts.upstream_request, Duration::ZERO);
    assert_eq!(timeouts.upstream_read, Duration::ZERO);
    assert_eq!(
      caps,
      GrpcTimeoutCaps {
        upstream_first_byte: true
      }
    );
  }

  #[test]
  fn detects_sse_and_native_grpc_content_types() {
    let mut headers = HeaderMap::new();
    headers.insert(
      CONTENT_TYPE,
      HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    assert!(is_sse(&headers));

    headers.insert(
      CONTENT_TYPE,
      HeaderValue::from_static("application/grpc+proto"),
    );
    assert!(content_type_is_native_grpc(&headers));

    headers.insert(
      CONTENT_TYPE,
      HeaderValue::from_static("application/grpc-web+proto"),
    );
    assert!(!content_type_is_native_grpc(&headers));
  }

  #[tokio::test]
  async fn drop_trailers_body_discards_trailer_frames() {
    let (sender, body) = channel_body(4);
    sender
      .send(Ok(Frame::data(Bytes::from_static(b"abc"))))
      .await
      .expect("data frame should send");
    let mut trailers = HeaderMap::new();
    trailers.insert("x-trailer", HeaderValue::from_static("secret"));
    sender
      .send(Ok(Frame::trailers(trailers)))
      .await
      .expect("trailer frame should send");
    drop(sender);

    let body = filter_trailers(body, TrailerMode::Drop, false);
    let collected = body.collect().await.expect("body should collect");
    assert!(collected.trailers().is_none());
    assert_eq!(collected.to_bytes().as_ref(), b"abc");
  }

  #[tokio::test]
  async fn passed_request_trailers_strip_security_fields_and_preserve_benign_fields() {
    let (sender, body) = channel_body(4);
    sender
      .send(Ok(Frame::data(Bytes::from_static(b"abc"))))
      .await
      .expect("data frame should send");
    let mut trailers = HeaderMap::new();
    trailers.insert("x-request-checksum", HeaderValue::from_static("ok"));
    trailers.insert(
      http::header::AUTHORIZATION,
      HeaderValue::from_static("Bearer attacker"),
    );
    trailers.insert(
      http::header::COOKIE,
      HeaderValue::from_static("sid=attacker"),
    );
    let custom_identity = HeaderName::from_static("x-custom-identity");
    trailers.insert(
      custom_identity.clone(),
      HeaderValue::from_static("attacker"),
    );
    sender
      .send(Ok(Frame::trailers(trailers)))
      .await
      .expect("trailer frame should send");
    drop(sender);

    let body = filter_trailers(body, TrailerMode::Pass, false);
    let body = sanitize_upstream_request_trailers(
      body,
      vec![custom_identity.clone()],
      HyphenUnderscoreHeaderNameSet::default(),
    );
    let collected = body.collect().await.expect("body should collect");
    let trailers = collected.trailers().expect("benign trailers should remain");
    assert_eq!(trailers["x-request-checksum"], "ok");
    assert!(!trailers.contains_key(http::header::AUTHORIZATION));
    assert!(!trailers.contains_key(http::header::COOKIE));
    assert!(!trailers.contains_key(custom_identity));
    assert_eq!(collected.to_bytes().as_ref(), b"abc");
  }

  #[tokio::test]
  async fn json_error_response_has_stable_fields() {
    let config: Config = toml::from_str(
      r#"
[listeners]
https_bind = "0.0.0.0:8443"

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

[proxy.http.errors]
mode = "json"

[[upstreams]]
name = "app"
origin = "http://app:8080"

[[routes]]
name = "main"
hosts = ["example.test"]
path_prefix = "/"
upstream = "app"
"#,
    )
    .expect("config should parse");

    let response = configured_error_response(
      &config,
      "req-1",
      StatusCode::BAD_GATEWAY,
      "upstream request failed",
      "connect_error",
    );
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
    let body = response
      .into_body()
      .collect()
      .await
      .expect("body should collect")
      .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json body should parse");
    assert_eq!(body["error"], "upstream request failed");
    assert_eq!(body["status"], 502);
    assert_eq!(body["code"], "connect_error");
    assert_eq!(body["request_id"], "req-1");
  }

  #[tokio::test]
  async fn grpc_upstream_error_response_maps_timeout_and_connect_error() {
    let config: Config = toml::from_str(
      r#"
[listeners]
https_bind = "0.0.0.0:8443"

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"

[[upstreams]]
name = "app"
origin = "http://app:8080"

[[routes]]
name = "main"
hosts = ["example.test"]
path_prefix = "/"
upstream = "app"
"#,
    )
    .expect("config should parse");
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));

    let response = grpc_upstream_error_response(&config, &headers, "read_timeout", "timed out")
      .expect("grpc response should be generated");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[GRPC_STATUS], "4");

    let response =
      grpc_upstream_error_response(&config, &headers, "connect_error", "connect failed")
        .expect("grpc response should be generated");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[GRPC_STATUS], "14");
  }
}
