//! Request framing classification for security-sensitive body handling.
//! Ambiguous `Content-Length` and `Transfer-Encoding` combinations must be rejected consistently.

use http::header::{CONTENT_LENGTH, HeaderMap, TRANSFER_ENCODING};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum RequestBodyFraming {
  NoBodyHeaders,
  ContentLength(u64),
  InvalidContentLength,
  TransferEncoding,
  Ambiguous,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VerifiedContentLengthZeroBody;

pub(crate) fn request_body_framing(headers: &HeaderMap) -> RequestBodyFraming {
  let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
  let first_content_length = content_lengths.next();
  let has_transfer_encoding = headers.contains_key(TRANSFER_ENCODING);

  if has_transfer_encoding {
    return if first_content_length.is_some() {
      RequestBodyFraming::Ambiguous
    } else {
      RequestBodyFraming::TransferEncoding
    };
  }

  let Some(content_length) = first_content_length else {
    return RequestBodyFraming::NoBodyHeaders;
  };
  if content_lengths.next().is_some() {
    return RequestBodyFraming::Ambiguous;
  }

  content_length
    .to_str()
    .ok()
    .and_then(|value| value.trim().parse::<u64>().ok())
    .map(RequestBodyFraming::ContentLength)
    .unwrap_or(RequestBodyFraming::InvalidContentLength)
}

pub(crate) fn positive_content_length(headers: &HeaderMap) -> Option<u64> {
  match request_body_framing(headers) {
    RequestBodyFraming::ContentLength(length) if length > 0 => Some(length),
    _ => None,
  }
}

pub(crate) fn content_length_is_exact_zero(headers: &HeaderMap) -> bool {
  request_body_framing(headers) == RequestBodyFraming::ContentLength(0)
}

pub(crate) fn http1_request_body_is_definitely_empty(
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  matches!(version, http::Version::HTTP_10 | http::Version::HTTP_11)
    && matches!(
      request_body_framing(headers),
      RequestBodyFraming::NoBodyHeaders | RequestBodyFraming::ContentLength(0)
    )
}

pub(crate) fn http1_content_length_zero_body_is_definitely_empty(
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  matches!(version, http::Version::HTTP_10 | http::Version::HTTP_11)
    && content_length_is_exact_zero(headers)
}

pub(crate) fn http1_response_body_is_definitely_empty(
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  http1_content_length_zero_body_is_definitely_empty(version, headers)
}

pub(crate) fn h2_or_h3_content_length_zero_guard_required(
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  matches!(version, http::Version::HTTP_2 | http::Version::HTTP_3)
    && content_length_is_exact_zero(headers)
}

pub(crate) fn h2_or_h3_safe_method_empty_probe_allowed(
  method: &http::Method,
  version: http::Version,
  headers: &HeaderMap,
) -> bool {
  matches!(version, http::Version::HTTP_2 | http::Version::HTTP_3)
    && matches!(method, &http::Method::GET | &http::Method::HEAD)
    && request_body_framing(headers) == RequestBodyFraming::NoBodyHeaders
}

#[cfg(test)]
mod tests {
  use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
  use http::{HeaderMap, HeaderValue};

  use super::*;

  #[test]
  fn request_body_framing_detects_ambiguous_headers() {
    let mut duplicate_content_length = HeaderMap::new();
    duplicate_content_length.append(CONTENT_LENGTH, HeaderValue::from_static("0"));
    duplicate_content_length.append(CONTENT_LENGTH, HeaderValue::from_static("0"));
    assert_eq!(
      request_body_framing(&duplicate_content_length),
      RequestBodyFraming::Ambiguous
    );

    let mut transfer_encoding_and_content_length = HeaderMap::new();
    transfer_encoding_and_content_length
      .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    transfer_encoding_and_content_length.insert(CONTENT_LENGTH, HeaderValue::from_static("7"));
    assert_eq!(
      request_body_framing(&transfer_encoding_and_content_length),
      RequestBodyFraming::Ambiguous
    );
  }

  #[test]
  fn request_body_framing_classifies_unambiguous_lengths() {
    let no_body_headers = HeaderMap::new();
    assert_eq!(
      request_body_framing(&no_body_headers),
      RequestBodyFraming::NoBodyHeaders
    );
    assert!(http1_request_body_is_definitely_empty(
      http::Version::HTTP_11,
      &no_body_headers
    ));

    let mut zero = HeaderMap::new();
    zero.insert(CONTENT_LENGTH, HeaderValue::from_static(" 0 "));
    assert_eq!(
      request_body_framing(&zero),
      RequestBodyFraming::ContentLength(0)
    );
    assert!(content_length_is_exact_zero(&zero));
    assert!(http1_request_body_is_definitely_empty(
      http::Version::HTTP_11,
      &zero
    ));
    assert!(!http1_request_body_is_definitely_empty(
      http::Version::HTTP_2,
      &zero
    ));

    let mut positive = HeaderMap::new();
    positive.insert(CONTENT_LENGTH, HeaderValue::from_static("4096"));
    assert_eq!(positive_content_length(&positive), Some(4096));
    assert!(!http1_request_body_is_definitely_empty(
      http::Version::HTTP_11,
      &positive
    ));

    let mut invalid = HeaderMap::new();
    invalid.insert(CONTENT_LENGTH, HeaderValue::from_static("abc"));
    assert_eq!(
      request_body_framing(&invalid),
      RequestBodyFraming::InvalidContentLength
    );
    assert_eq!(positive_content_length(&invalid), None);
  }

  #[test]
  fn h2_h3_empty_probe_requires_safe_method_and_no_framing_headers() {
    let empty = HeaderMap::new();
    assert!(h2_or_h3_safe_method_empty_probe_allowed(
      &http::Method::GET,
      http::Version::HTTP_2,
      &empty
    ));
    assert!(h2_or_h3_safe_method_empty_probe_allowed(
      &http::Method::HEAD,
      http::Version::HTTP_3,
      &empty
    ));
    assert!(!h2_or_h3_safe_method_empty_probe_allowed(
      &http::Method::POST,
      http::Version::HTTP_3,
      &empty
    ));
    assert!(!h2_or_h3_safe_method_empty_probe_allowed(
      &http::Method::GET,
      http::Version::HTTP_11,
      &empty
    ));

    let mut content_length_zero = HeaderMap::new();
    content_length_zero.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    assert!(h2_or_h3_content_length_zero_guard_required(
      http::Version::HTTP_3,
      &content_length_zero
    ));
    assert!(!h2_or_h3_safe_method_empty_probe_allowed(
      &http::Method::GET,
      http::Version::HTTP_3,
      &content_length_zero
    ));

    let mut transfer_encoding = HeaderMap::new();
    transfer_encoding.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    assert!(!h2_or_h3_safe_method_empty_probe_allowed(
      &http::Method::GET,
      http::Version::HTTP_2,
      &transfer_encoding
    ));
  }
}
