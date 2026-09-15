//! Conditional QUERY requests select the exact body-bound equivalent resource.
//! Malformed validators are forwarded to the origin instead of guessed at.

use http::header::{DATE, ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use http::{HeaderMap, StatusCode};

const MAX_VALIDATOR_BYTES: usize = 8192;
const MAX_ENTITY_TAGS: usize = 64;

pub(crate) fn not_modified(
  entry: &crate::cache::CacheEntry,
  request: &HeaderMap,
) -> Result<bool, ()> {
  if entry.status != StatusCode::OK && entry.status != StatusCode::PARTIAL_CONTENT {
    return Ok(false);
  }
  if request.contains_key(IF_NONE_MATCH) {
    let mut combined = Vec::new();
    for value in request.get_all(IF_NONE_MATCH) {
      if combined
        .len()
        .saturating_add(value.as_bytes().len())
        .saturating_add(1)
        > MAX_VALIDATOR_BYTES
      {
        return Err(());
      }
      if !combined.is_empty() {
        combined.push(b',');
      }
      combined.extend_from_slice(value.as_bytes());
    }
    let combined = trim_ows(&combined);
    if combined == b"*" {
      return Ok(true);
    }
    let candidates = parse_tags(combined)?;
    let mut values = entry.headers.get_all(ETAG).iter();
    let Some(value) = values.next() else {
      return Ok(false);
    };
    if values.next().is_some() {
      return Err(());
    }
    let tags = parse_tags(trim_ows(value.as_bytes()))?;
    if tags.len() != 1 {
      return Err(());
    }
    return Ok(candidates.iter().any(|candidate| *candidate == tags[0]));
  }
  let Some(since) = request
    .get(IF_MODIFIED_SINCE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| httpdate::parse_http_date(value).ok())
  else {
    return Ok(false);
  };
  let changed = entry
    .headers
    .get(LAST_MODIFIED)
    .or_else(|| entry.headers.get(DATE))
    .and_then(|value| value.to_str().ok())
    .and_then(|value| httpdate::parse_http_date(value).ok())
    .unwrap_or(entry.stored_at);
  Ok(changed <= since)
}

fn trim_ows(mut bytes: &[u8]) -> &[u8] {
  while bytes
    .first()
    .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
  {
    bytes = &bytes[1..];
  }
  while bytes
    .last()
    .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
  {
    bytes = &bytes[..bytes.len() - 1];
  }
  bytes
}

/// The weak marker is deliberately omitted: If-None-Match uses weak comparison.
fn parse_tags(mut bytes: &[u8]) -> Result<Vec<&[u8]>, ()> {
  if bytes.len() > MAX_VALIDATOR_BYTES {
    return Err(());
  }
  let mut tags = Vec::new();
  loop {
    bytes = trim_ows(bytes);
    if bytes.starts_with(b"W/") {
      bytes = &bytes[2..];
    }
    if bytes.first() != Some(&b'"') {
      return Err(());
    }
    bytes = &bytes[1..];
    let end = bytes.iter().position(|byte| *byte == b'"').ok_or(())?;
    let tag = &bytes[..end];
    if tag
      .iter()
      .any(|byte| !matches!(byte, 0x21 | 0x23..=0x7e | 0x80..=0xff))
    {
      return Err(());
    }
    tags.push(tag);
    if tags.len() > MAX_ENTITY_TAGS {
      return Err(());
    }
    bytes = trim_ows(&bytes[end + 1..]);
    if bytes.is_empty() {
      return Ok(tags);
    }
    if bytes.first() != Some(&b',') {
      return Err(());
    }
    bytes = &bytes[1..];
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn quoted_commas_and_weak_tags_keep_opaque_bytes() {
    assert_eq!(
      parse_tags(b"W/\"a,b\", \"c\"").unwrap(),
      [b"a,b".as_slice(), b"c"]
    );
    assert_eq!(parse_tags(b"\"a\\b\"").unwrap(), [b"a\\b".as_slice()]);
    for invalid in [
      b"\"a\",*".as_slice(),
      b"\"a\",",
      b"w/\"a\"",
      b"\"unterminated",
      b"\"a\"garbage",
    ] {
      assert!(parse_tags(invalid).is_err(), "{invalid:?}");
    }
  }
}
