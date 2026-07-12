//! WAF body capture orchestration, including optional HTTP body coding transforms.

use std::fmt;
use std::sync::Arc;

use http::{HeaderMap, Request, StatusCode};

use crate::waf::{BodyNeed, WafBodyInput};

use super::body::{
  BodyTimeoutKind, BoxError, CapturedBody, ProxyBody, capture_proxy_body_prefix,
  capture_proxy_request_prefix, error_is_timeout,
};
use super::request_framing::{
  http1_content_length_zero_body_is_definitely_empty, http1_response_body_is_definitely_empty,
  positive_content_length,
};
use super::waf_body_coding::{
  WafBodyCodingError, WafBodyCodingErrorKind, WafBodyCodingState,
  has_non_identity_content_encoding, transform_request_body_for_waf,
  transform_response_body_for_waf,
};

pub(crate) fn waf_body_input(body: &CapturedBody) -> WafBodyInput<'_> {
  WafBodyInput {
    bytes: body.bytes.as_ref(),
    is_truncated: body.is_truncated,
  }
}

pub(crate) async fn capture_request_body_for_waf(
  request: Request<ProxyBody>,
  body_need: BodyNeed,
  limit: usize,
  transform_enabled: bool,
  transform_config: &crate::waf::WafHttpBodyCompressionConfig,
  transform_state: &Arc<WafBodyCodingState>,
) -> Result<(Request<ProxyBody>, Option<CapturedBody>), WafBodyCaptureError> {
  let force_transform = transform_enabled
    && body_need != BodyNeed::None
    && has_non_identity_content_encoding(request.headers());
  let decision = if force_transform {
    WafBodyCaptureDecision::Prefix
  } else {
    request_body_capture_decision(request.version(), request.headers(), body_need)
  };
  match decision {
    WafBodyCaptureDecision::Skip => Ok((request, None)),
    WafBodyCaptureDecision::Empty => Ok((request, Some(empty_captured_body()))),
    WafBodyCaptureDecision::Prefix => {
      if force_transform {
        let Some((request, captured)) = transform_request_body_for_waf(
          request,
          transform_config.clone(),
          Arc::clone(transform_state),
          limit,
        )
        .await?
        else {
          return Err(WafBodyCaptureError::Coding(WafBodyCodingError::new(
            WafBodyCodingErrorKind::Unsupported,
            "missing Content-Encoding for WAF body transform",
          )));
        };
        return Ok((request, Some(captured)));
      }
      let _inspection = transform_state.inspection_lease()?;
      capture_proxy_request_prefix(request, limit)
        .await
        .map(|(request, captured)| (request, Some(captured)))
        .map_err(WafBodyCaptureError::Body)
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn capture_response_body_for_waf(
  version: http::Version,
  headers: &mut HeaderMap,
  body: ProxyBody,
  body_need: BodyNeed,
  limit: usize,
  transform_enabled: bool,
  transform_config: &crate::waf::WafHttpBodyCompressionConfig,
  transform_state: &Arc<WafBodyCodingState>,
) -> Result<(ProxyBody, Option<CapturedBody>), WafBodyCaptureError> {
  let force_transform =
    transform_enabled && body_need != BodyNeed::None && has_non_identity_content_encoding(headers);
  let decision = if force_transform {
    WafBodyCaptureDecision::Prefix
  } else {
    response_body_capture_decision(version, headers, body_need)
  };
  match decision {
    WafBodyCaptureDecision::Skip => Ok((body, None)),
    WafBodyCaptureDecision::Empty => Ok((body, Some(empty_captured_body()))),
    WafBodyCaptureDecision::Prefix => {
      if force_transform {
        let Some((body, captured)) = transform_response_body_for_waf(
          headers,
          body,
          transform_config.clone(),
          Arc::clone(transform_state),
          limit,
        )
        .await?
        else {
          return Err(WafBodyCaptureError::Coding(WafBodyCodingError::new(
            WafBodyCodingErrorKind::Unsupported,
            "missing Content-Encoding for WAF body transform",
          )));
        };
        return Ok((body, Some(captured)));
      }
      let _inspection = transform_state.inspection_lease()?;
      capture_proxy_body_prefix(body, limit, positive_content_length(headers))
        .await
        .map(|(body, captured)| (body, Some(captured)))
        .map_err(WafBodyCaptureError::Body)
    }
  }
}

#[derive(Debug)]
pub(crate) enum WafBodyCaptureError {
  Body(BoxError),
  Coding(WafBodyCodingError),
}

impl fmt::Display for WafBodyCaptureError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Body(error) => write!(formatter, "{error}"),
      Self::Coding(error) => write!(formatter, "{error}"),
    }
  }
}

impl From<WafBodyCodingError> for WafBodyCaptureError {
  fn from(error: WafBodyCodingError) -> Self {
    Self::Coding(error)
  }
}

pub(crate) fn request_body_capture_error_response(
  error: &WafBodyCaptureError,
) -> (StatusCode, &'static str) {
  match error {
    WafBodyCaptureError::Body(error) => {
      if error_is_timeout(error, BodyTimeoutKind::DownstreamRequestRead) {
        (StatusCode::REQUEST_TIMEOUT, "request body timed out")
      } else {
        (StatusCode::BAD_REQUEST, "failed to read request body")
      }
    }
    WafBodyCaptureError::Coding(error) => match error.kind() {
      WafBodyCodingErrorKind::Overloaded => (StatusCode::SERVICE_UNAVAILABLE, "overloaded"),
      WafBodyCodingErrorKind::Unsupported => (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported content encoding",
      ),
      WafBodyCodingErrorKind::Malformed => {
        (StatusCode::BAD_REQUEST, "failed to decode request body")
      }
      WafBodyCodingErrorKind::TooLarge => {
        (StatusCode::PAYLOAD_TOO_LARGE, "request body is too large")
      }
      WafBodyCodingErrorKind::DecodeTimeout | WafBodyCodingErrorKind::BodyReadTimeout => {
        (StatusCode::REQUEST_TIMEOUT, "request body timed out")
      }
      WafBodyCodingErrorKind::UnsafeTransform | WafBodyCodingErrorKind::BodyRead => {
        (StatusCode::BAD_REQUEST, "failed to read request body")
      }
    },
  }
}

pub(crate) fn response_body_capture_error_response(
  error: &WafBodyCaptureError,
) -> (StatusCode, &'static str) {
  match error {
    WafBodyCaptureError::Body(error) => {
      if error_is_timeout(error, BodyTimeoutKind::UpstreamResponseRead) {
        (
          StatusCode::GATEWAY_TIMEOUT,
          "upstream response body timed out",
        )
      } else {
        (
          StatusCode::BAD_GATEWAY,
          "failed to read upstream response body",
        )
      }
    }
    WafBodyCaptureError::Coding(error) => match error.kind() {
      WafBodyCodingErrorKind::Overloaded => (StatusCode::SERVICE_UNAVAILABLE, "overloaded"),
      WafBodyCodingErrorKind::DecodeTimeout | WafBodyCodingErrorKind::BodyReadTimeout => (
        StatusCode::GATEWAY_TIMEOUT,
        "upstream response body timed out",
      ),
      WafBodyCodingErrorKind::Unsupported
      | WafBodyCodingErrorKind::UnsafeTransform
      | WafBodyCodingErrorKind::Malformed
      | WafBodyCodingErrorKind::TooLarge
      | WafBodyCodingErrorKind::BodyRead => (
        StatusCode::BAD_GATEWAY,
        "failed to transform upstream response body",
      ),
    },
  }
}

fn empty_captured_body() -> CapturedBody {
  CapturedBody {
    bytes: bytes::Bytes::new(),
    is_truncated: false,
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WafBodyCaptureDecision {
  Skip,
  Empty,
  Prefix,
}

fn request_body_capture_decision(
  version: http::Version,
  headers: &HeaderMap,
  body_need: BodyNeed,
) -> WafBodyCaptureDecision {
  body_capture_decision(
    version,
    headers,
    body_need,
    request_body_is_definitely_empty,
  )
}

fn response_body_capture_decision(
  version: http::Version,
  headers: &HeaderMap,
  body_need: BodyNeed,
) -> WafBodyCaptureDecision {
  body_capture_decision(
    version,
    headers,
    body_need,
    response_body_is_definitely_empty,
  )
}

fn body_capture_decision(
  version: http::Version,
  headers: &HeaderMap,
  body_need: BodyNeed,
  body_is_definitely_empty: fn(http::Version, &HeaderMap) -> bool,
) -> WafBodyCaptureDecision {
  match body_need {
    BodyNeed::None => WafBodyCaptureDecision::Skip,
    BodyNeed::SizeOnly => {
      if body_is_definitely_empty(version, headers) {
        WafBodyCaptureDecision::Empty
      } else if positive_content_length(headers).is_some() {
        WafBodyCaptureDecision::Skip
      } else {
        WafBodyCaptureDecision::Prefix
      }
    }
    BodyNeed::PrefixBytes => {
      if body_is_definitely_empty(version, headers) {
        WafBodyCaptureDecision::Empty
      } else {
        WafBodyCaptureDecision::Prefix
      }
    }
  }
}

pub(crate) fn request_body_is_definitely_empty(
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  http1_content_length_zero_body_is_definitely_empty(version, headers)
}

pub(crate) fn response_body_is_definitely_empty(
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  http1_response_body_is_definitely_empty(version, headers)
}
