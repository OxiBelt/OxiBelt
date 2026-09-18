//! Draft-12 wire parsing. Protocol values never become paths or authorities.

use std::convert::Infallible;

use http::{HeaderMap, HeaderValue, Method, StatusCode};
use sfv::visitor::{Ignored, ItemVisitor, ParameterVisitor, parameter_visitor_with};
use sfv::{BareItemFromInput, Parser};

pub(super) const INTEROP_VERSION: u64 = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scalar {
  Boolean(bool),
  Integer(u64),
  Other,
}

struct ScalarVisitor;

impl<'de> ItemVisitor<'de> for ScalarVisitor {
  type Out = Scalar;
  type Error = Infallible;

  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = Scalar>, Infallible> {
    let value = match item {
      BareItemFromInput::Boolean(value) => Scalar::Boolean(value),
      BareItemFromInput::Integer(value) => u64::try_from(i64::from(value))
        .map(Scalar::Integer)
        .unwrap_or(Scalar::Other),
      _ => Scalar::Other,
    };
    Ok(parameter_visitor_with(Ignored, move |_| Ok(value)))
  }
}

fn scalar(headers: &HeaderMap, name: &'static str) -> Result<Option<Scalar>, StatusCode> {
  let mut values = headers.get_all(name).iter();
  let Some(value) = values.next() else {
    return Ok(None);
  };
  if values.next().is_some() {
    return Err(StatusCode::BAD_REQUEST);
  }
  Parser::new(value.as_bytes())
    .parse_item_with_visitor(ScalarVisitor)
    .map(Some)
    .map_err(|_| StatusCode::BAD_REQUEST)
}

pub(super) fn integer(headers: &HeaderMap, name: &'static str) -> Result<Option<u64>, StatusCode> {
  match scalar(headers, name)? {
    Some(Scalar::Integer(value)) => Ok(Some(value)),
    None => Ok(None),
    _ => Err(StatusCode::BAD_REQUEST),
  }
}

pub(super) fn completion(headers: &HeaderMap) -> Result<bool, StatusCode> {
  match scalar(headers, "upload-complete")? {
    Some(Scalar::Boolean(value)) => Ok(value),
    _ => Err(StatusCode::BAD_REQUEST),
  }
}

pub(super) fn negotiate(headers: &HeaderMap) -> Result<(), StatusCode> {
  if integer(headers, "upload-draft-interop-version")? != Some(INTEROP_VERSION) {
    return Err(StatusCode::BAD_REQUEST);
  }
  Ok(())
}

/// Whether the request has exactly one syntactically valid interop-9 item.
///
/// This is intentionally a parser-only predicate for the transport relay.
/// Authorization and all managed-upload operation validation remain in the
/// managed handler.
pub(super) fn compatible_interop(headers: &HeaderMap) -> bool {
  integer(headers, "upload-draft-interop-version") == Ok(Some(INTEROP_VERSION))
}

/// Whether an ordinary proxied request is a complete draft-12 creation or
/// append tuple whose live informational responses must be preserved.
///
/// Keep this stricter than `compatible_interop`: that predicate also validates
/// upstream 104 responses, which carry only the interop version.
pub(super) fn relay_request(method: &Method, headers: &HeaderMap) -> bool {
  if !creation_method(method)
    || !compatible_interop(headers)
    || completion(headers).is_err()
    || integer(headers, "upload-length").is_err()
  {
    return false;
  }

  let append_shape = headers.contains_key("upload-offset")
    || headers
      .get_all(http::header::CONTENT_TYPE)
      .iter()
      .any(|value| partial_upload_media_type(value.as_bytes()));
  if append_shape {
    method == Method::PATCH && validate_append(headers).is_ok()
  } else {
    true
  }
}

fn partial_upload_media_type(value: &[u8]) -> bool {
  const TYPE: &[u8] = b"application/partial-upload";
  value
    .get(..TYPE.len())
    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(TYPE))
    && value
      .get(TYPE.len())
      .is_none_or(|next| next.is_ascii_whitespace() || *next == b';')
}

pub(super) fn identity_encoding(headers: &HeaderMap) -> Result<(), StatusCode> {
  let mut values = headers.get_all(http::header::CONTENT_ENCODING).iter();
  if let Some(value) = values.next()
    && (values.next().is_some() || !value.as_bytes().eq_ignore_ascii_case(b"identity"))
  {
    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
  }
  Ok(())
}

pub(super) fn validate_append(headers: &HeaderMap) -> Result<u64, StatusCode> {
  let mut types = headers.get_all(http::header::CONTENT_TYPE).iter();
  if types.next().is_none_or(|value| {
    !value
      .as_bytes()
      .eq_ignore_ascii_case(b"application/partial-upload")
  }) || types.next().is_some()
  {
    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
  }
  integer(headers, "upload-offset")?.ok_or(StatusCode::BAD_REQUEST)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Resource<'a> {
  Creation,
  Upload(&'a str),
  Status(&'a str),
  Object(&'a str),
}

pub(super) fn resource<'a>(
  path: &'a str,
  upload_prefix: &str,
  object_prefix: &str,
) -> Result<Resource<'a>, StatusCode> {
  for (prefix, object) in [(upload_prefix, false), (object_prefix, true)] {
    if let Some(suffix) = path.strip_prefix(prefix)
      && let Some(suffix) = suffix.strip_prefix('/')
    {
      let (id, status) = match suffix.strip_suffix("/status") {
        Some(id) if !object => (id, true),
        _ => (suffix, false),
      };
      if id.len() != 64
        || !id
          .bytes()
          .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
      {
        return Err(StatusCode::NOT_FOUND);
      }
      return Ok(if object {
        Resource::Object(id)
      } else if status {
        Resource::Status(id)
      } else {
        Resource::Upload(id)
      });
    }
  }
  Ok(Resource::Creation)
}

pub(super) fn creation_method(method: &Method) -> bool {
  matches!(*method, Method::POST | Method::PUT | Method::PATCH)
}

pub(super) fn set_integer(headers: &mut HeaderMap, name: &'static str, value: u64) {
  // A decimal u64 is always a legal HTTP field value.
  if let Ok(value) = HeaderValue::from_str(&value.to_string()) {
    headers.insert(name, value);
  }
}

pub(super) fn state_headers(
  headers: &mut HeaderMap,
  offset: u64,
  complete: bool,
  length: Option<u64>,
) {
  headers.insert(
    http::header::CACHE_CONTROL,
    HeaderValue::from_static("no-store"),
  );
  headers.insert(
    "upload-draft-interop-version",
    HeaderValue::from_static("9"),
  );
  headers.insert(
    "upload-complete",
    HeaderValue::from_static(if complete { "?1" } else { "?0" }),
  );
  set_integer(headers, "upload-offset", offset);
  if let Some(length) = length {
    set_integer(headers, "upload-length", length);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn strictly_parse_items_without_losing_false_or_zero() {
    let mut headers = HeaderMap::new();
    headers.insert("upload-complete", HeaderValue::from_static("?0;p=1"));
    headers.insert("upload-offset", HeaderValue::from_static("0"));
    assert_eq!(completion(&headers), Ok(false));
    assert_eq!(integer(&headers, "upload-offset"), Ok(Some(0)));
    for value in ["-1", "1.0", "\"1\"", "?1", "1, 2", "1000000000000000"] {
      headers.insert("upload-offset", HeaderValue::from_str(value).unwrap());
      assert_eq!(
        integer(&headers, "upload-offset"),
        Err(StatusCode::BAD_REQUEST)
      );
    }
    headers.append("upload-complete", HeaderValue::from_static("?0"));
    assert_eq!(completion(&headers), Err(StatusCode::BAD_REQUEST));
  }

  #[test]
  fn control_paths_accept_only_opaque_ids() {
    let id = "a".repeat(64);
    let path = format!("/uploads/{id}/status");
    assert_eq!(
      resource(&path, "/uploads", "/objects"),
      Ok(Resource::Status(id.as_str()))
    );
    for path in [
      "/uploads/../x",
      "/uploads/%2f",
      "/uploads/a/b",
      "/objects/",
      "/uploads/ABC",
    ] {
      assert_eq!(
        resource(path, "/uploads", "/objects"),
        Err(StatusCode::NOT_FOUND)
      );
    }
    assert_eq!(
      resource("/uploading/file", "/uploads", "/objects"),
      Ok(Resource::Creation)
    );
  }

  #[test]
  fn negotiation_and_encoding_fail_closed() {
    let mut headers = HeaderMap::new();
    assert_eq!(negotiate(&headers), Err(StatusCode::BAD_REQUEST));
    headers.insert(
      "upload-draft-interop-version",
      HeaderValue::from_static("9"),
    );
    assert_eq!(negotiate(&headers), Ok(()));
    headers.insert(
      http::header::CONTENT_ENCODING,
      HeaderValue::from_static("gzip"),
    );
    assert_eq!(
      identity_encoding(&headers),
      Err(StatusCode::UNSUPPORTED_MEDIA_TYPE)
    );
  }

  fn relay_headers(complete: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
      "upload-draft-interop-version",
      HeaderValue::from_static("9"),
    );
    headers.insert("upload-complete", HeaderValue::from_static(complete));
    headers
  }

  #[test]
  fn relay_request_requires_a_complete_creation_tuple() {
    for method in [Method::POST, Method::PUT, Method::PATCH] {
      for complete in ["?0", "?1"] {
        let headers = relay_headers(complete);
        assert!(relay_request(&method, &headers), "{method} {complete}");
      }
    }

    let mut with_length = relay_headers("?0");
    with_length.insert("upload-length", HeaderValue::from_static("0"));
    assert!(relay_request(&Method::POST, &with_length));

    for method in [
      Method::GET,
      Method::HEAD,
      Method::OPTIONS,
      Method::DELETE,
      Method::CONNECT,
    ] {
      assert!(!relay_request(&method, &relay_headers("?0")), "{method}");
    }

    let mut missing_complete = relay_headers("?0");
    missing_complete.remove("upload-complete");
    assert!(!relay_request(&Method::POST, &missing_complete));

    for (name, value) in [
      ("upload-draft-interop-version", "8"),
      ("upload-draft-interop-version", "\"9\""),
      ("upload-complete", "1"),
      ("upload-complete", "maybe"),
      ("upload-length", "-1"),
    ] {
      let mut headers = relay_headers("?0");
      headers.insert(name, HeaderValue::from_static(value));
      assert!(!relay_request(&Method::POST, &headers), "{name}: {value}");
    }

    for name in [
      "upload-draft-interop-version",
      "upload-complete",
      "upload-length",
    ] {
      let mut headers = relay_headers("?0");
      if name == "upload-length" {
        headers.insert(name, HeaderValue::from_static("1"));
      }
      headers.append(name, HeaderValue::from_static("1"));
      assert!(!relay_request(&Method::POST, &headers), "duplicate {name}");
    }
  }

  #[test]
  fn relay_request_requires_a_complete_append_tuple() {
    let mut headers = relay_headers("?0");
    headers.insert(
      http::header::CONTENT_TYPE,
      HeaderValue::from_static("application/partial-upload"),
    );
    headers.insert("upload-offset", HeaderValue::from_static("0"));
    assert!(relay_request(&Method::PATCH, &headers));

    for method in [Method::POST, Method::PUT] {
      assert!(!relay_request(&method, &headers), "{method}");
    }

    for missing in ["upload-offset", "content-type"] {
      let mut incomplete = headers.clone();
      incomplete.remove(missing);
      assert!(!relay_request(&Method::PATCH, &incomplete), "{missing}");
    }

    for value in ["-1", "?0", "1, 2"] {
      let mut malformed = headers.clone();
      malformed.insert("upload-offset", HeaderValue::from_static(value));
      assert!(!relay_request(&Method::PATCH, &malformed), "{value}");
    }

    let mut parameterized = headers.clone();
    parameterized.insert(
      http::header::CONTENT_TYPE,
      HeaderValue::from_static("application/partial-upload; charset=utf-8"),
    );
    assert!(!relay_request(&Method::PATCH, &parameterized));

    let mut duplicate_type = headers;
    duplicate_type.append(
      http::header::CONTENT_TYPE,
      HeaderValue::from_static("application/partial-upload"),
    );
    assert!(!relay_request(&Method::PATCH, &duplicate_type));
  }
}
