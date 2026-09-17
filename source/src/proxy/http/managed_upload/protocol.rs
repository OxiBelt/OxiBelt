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
}
