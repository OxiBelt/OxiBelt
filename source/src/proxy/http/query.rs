//! QUERY admission and request-content identity preparation.
//!
//! Method safety never proves that a QUERY has an empty request body.

use http::{HeaderMap, Method};

pub(crate) mod capture;
pub(super) mod conditional;

/// Capture after all representation transformations and trailer sanitization.
/// A missing or incomplete original observation can only produce a cache bypass.
pub(crate) async fn prepare_cache_request(
  mut request: http::Request<super::body::ProxyBody>,
  buffering: &super::buffering::EffectiveBuffering,
  state: &crate::state::AppSnapshot,
) -> Result<http::Request<super::body::ProxyBody>, super::buffering::BufferingError> {
  use crate::cache::{CacheQueryIdentity, CacheQueryRepresentation};
  let Some(original) = request
    .extensions()
    .get::<capture::OriginalQuery>()
    .cloned()
  else {
    return Ok(request);
  };
  if super::incremental::request_marked(&request) {
    return Ok(request);
  }
  let body = std::mem::replace(request.body_mut(), super::full_body(bytes::Bytes::new()));
  let captured = capture::capture(
    body,
    buffering.request,
    buffering.temp_dir.as_deref(),
    &state.overload,
  )
  .await?;
  *request.body_mut() = captured.body;
  let Some(snapshot) = captured.snapshot else {
    return Ok(request);
  };
  super::body::prepare_replay_trailer_headers(request.headers_mut(), snapshot.trailers())
    .map_err(|error| super::buffering::BufferingError::Body(super::body::boxed_error(error)))?;
  let Some((len, digest, trailers)) = original.content() else {
    return Ok(request);
  };
  let Some(scheme) = request.uri().scheme_str() else {
    return Ok(request);
  };
  let Some(authority) = request.uri().authority() else {
    return Ok(request);
  };
  let identity = (|| {
    let received = CacheQueryRepresentation::new(
      &original.scheme,
      &original.authority,
      &original.uri,
      len,
      digest,
      &original.headers,
      &trailers,
    )?;
    let forwarded = CacheQueryRepresentation::new(
      scheme,
      authority.as_str(),
      request.uri(),
      snapshot.len(),
      snapshot.digest(),
      request.headers(),
      snapshot.trailers(),
    )?;
    CacheQueryIdentity::new(received, forwarded, request.headers().clone())
  })();
  if let Ok(identity) = identity {
    request.extensions_mut().insert(identity);
    request.extensions_mut().insert(snapshot);
  }
  Ok(request)
}

pub(crate) fn is_query(method: &Method) -> bool {
  method.as_str() == "QUERY"
}

pub(crate) fn invalidates_target(method: &Method) -> bool {
  !matches!(
    *method,
    Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
  ) && !is_query(method)
}

pub(crate) async fn invalidate_after_origin_response(
  state: &crate::state::AppSnapshot,
  method: &Method,
  status: http::StatusCode,
  scheme: &str,
  host: &str,
  uri: &http::Uri,
) {
  if !invalidates_target(method) || !(status.is_success() || status.is_redirection()) {
    return;
  }
  if state
    .cache
    .invalidate_query_target_async_all_policies(
      scheme,
      host,
      uri.path_and_query().map_or("/", |value| value.as_str()),
    )
    .await
    .is_err()
  {
    tracing::warn!("QUERY target cache invalidation failed; QUERY reuse is fenced");
  }
  if state
    .cache
    .invalidate_nvs_all_policies(scheme, host, uri)
    .await
    .is_err()
  {
    tracing::warn!("No-Vary-Search cache invalidation failed; alias reuse is fenced");
  }
}

/// Validate the field envelope and media-type syntax, without interpreting
/// application query content or rewriting the received field.
pub(crate) fn validate_content_type(
  method: &Method,
  headers: &HeaderMap,
) -> Result<(), &'static str> {
  if !is_query(method) {
    return Ok(());
  }
  let invalid = "invalid QUERY Content-Type";
  let mut values = headers.get_all(http::header::CONTENT_TYPE).iter();
  let value = values.next().ok_or(invalid)?;
  if values.next().is_some() {
    return Err(invalid);
  }
  if !valid_media_type(value.as_bytes()) {
    return Err(invalid);
  }
  Ok(())
}

/// RFC 9110 media-type envelope; application parameters remain opaque.
fn valid_media_type(mut bytes: &[u8]) -> bool {
  fn ows(bytes: &mut &[u8]) {
    while bytes
      .first()
      .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
      *bytes = &bytes[1..];
    }
  }
  fn token(bytes: &mut &[u8]) -> bool {
    let length = bytes
      .iter()
      .take_while(|byte| {
        byte.is_ascii_alphanumeric()
          || matches!(
            byte,
            b'!'
              | b'#'
              | b'$'
              | b'%'
              | b'&'
              | b'\''
              | b'*'
              | b'+'
              | b'-'
              | b'.'
              | b'^'
              | b'_'
              | b'`'
              | b'|'
              | b'~'
          )
      })
      .count();
    *bytes = &bytes[length..];
    length > 0
  }
  ows(&mut bytes);
  if !token(&mut bytes) || bytes.first() != Some(&b'/') {
    return false;
  }
  bytes = &bytes[1..];
  if !token(&mut bytes) {
    return false;
  }
  loop {
    ows(&mut bytes);
    if bytes.is_empty() {
      return true;
    }
    if bytes.first() != Some(&b';') {
      return false;
    }
    bytes = &bytes[1..];
    ows(&mut bytes);
    // Empty parameters are allowed by the RFC 9110 parameters grammar.
    if bytes.is_empty() || bytes.first() == Some(&b';') {
      continue;
    }
    if !token(&mut bytes) || bytes.first() != Some(&b'=') {
      return false;
    }
    bytes = &bytes[1..];
    if bytes.first() != Some(&b'"') {
      if !token(&mut bytes) {
        return false;
      }
      continue;
    }
    bytes = &bytes[1..];
    loop {
      let Some((&byte, rest)) = bytes.split_first() else {
        return false;
      };
      bytes = rest;
      match byte {
        b'"' => break,
        b'\\' => {
          let Some((&escaped, rest)) = bytes.split_first() else {
            return false;
          };
          if !matches!(escaped, b'\t' | b' '..=b'~' | 0x80..=0xff) {
            return false;
          }
          bytes = rest;
        }
        b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff => {}
        _ => return false,
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::HeaderValue;

  #[test]
  fn query_requires_one_complete_media_type() {
    let query = Method::from_bytes(b"QUERY").unwrap();
    let mut headers = HeaderMap::new();
    assert!(validate_content_type(&query, &headers).is_err());
    for value in [
      "application/json",
      "application/example+json; charset=utf-8",
      " application/sql; profile=\"a,b\" ",
    ] {
      headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_str(value).unwrap(),
      );
      assert!(validate_content_type(&query, &headers).is_ok(), "{value}");
      assert_eq!(headers[http::header::CONTENT_TYPE], value);
    }
    for value in [
      "",
      " ",
      "application",
      "application/json, text/plain",
      "application/json; p=\"broken",
    ] {
      headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_str(value).unwrap(),
      );
      assert!(validate_content_type(&query, &headers).is_err(), "{value}");
    }
    headers.insert(
      http::header::CONTENT_TYPE,
      HeaderValue::from_static("application/json"),
    );
    headers.append(
      http::header::CONTENT_TYPE,
      HeaderValue::from_static("application/json"),
    );
    assert!(validate_content_type(&query, &headers).is_err());
  }

  #[test]
  fn extension_method_case_and_empty_body_shortcuts_are_distinct() {
    let query = Method::from_bytes(b"QUERY").unwrap();
    let lower = Method::from_bytes(b"query").unwrap();
    assert!(!is_query(&lower));
    assert!(validate_content_type(&lower, &HeaderMap::new()).is_ok());
    assert!(validate_content_type(&Method::POST, &HeaderMap::new()).is_ok());
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
      assert!(
        !super::super::request_framing::h2_or_h3_safe_method_empty_probe_allowed(
          &query,
          version,
          &HeaderMap::new(),
        )
      );
    }
  }
}
