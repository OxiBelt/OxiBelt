use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, EXPECT, HeaderMap, HeaderName, HeaderValue, LINK};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};

use crate::config::{
  Config, EarlyHintsMode, ErrorResponseMode, ExpectContinueMode, GrpcRetryMode, PriorityMode,
  TrailerMode,
};

use super::EffectiveTimeouts;
use super::body::{BoxError, ProxyBody};

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

#[derive(Clone, Default)]
pub(crate) struct EarlyHintsCapture {
  inner: Arc<Mutex<Vec<InterimResponse>>>,
}

impl EarlyHintsCapture {
  pub(crate) fn take(&self) -> InterimResponses {
    let mut inner = self
      .inner
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    InterimResponses {
      responses: std::mem::take(&mut *inner),
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
    if response.status() != StatusCode::EARLY_HINTS {
      return;
    }
    if let Some(interim) = sanitize_interim_response(response.status(), response.headers()) {
      callback_capture
        .inner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(interim);
    }
  });
  Some(capture)
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
  let body = Full::new(Bytes::copy_from_slice(message.as_bytes()))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = status;
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

  use crate::config::{Config, ExpectContinueMode, TrailerMode};

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
      upstream_first_byte: Duration::from_secs(30),
      upstream_read: Duration::from_secs(30),
      upstream_send: Duration::from_secs(30),
    };

    let (timeouts, caps) = cap_timeouts_for_grpc(timeouts, &headers, true);

    assert_eq!(timeouts.upstream_first_byte, Duration::ZERO);
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
