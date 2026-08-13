//! HTTP metadata normalization for WAF matching.
//! Normalized views are derived data and must not rewrite the original request.

use http::{HeaderMap, Uri};
#[cfg(feature = "fuzzing")]
use http::{HeaderName, HeaderValue};
use unicode_normalization::UnicodeNormalization;
use url::form_urlencoded;

#[cfg(feature = "fuzzing")]
const MAX_FUZZ_INPUT_BYTES: usize = 8 * 1024;
#[cfg(feature = "fuzzing")]
const MAX_FUZZ_URI_BYTES: usize = 1024;
#[cfg(feature = "fuzzing")]
const MAX_FUZZ_TEXT_BYTES: usize = 1024;
#[cfg(feature = "fuzzing")]
const MAX_FUZZ_CRS_BYTES: usize = 4 * 1024;
#[cfg(feature = "fuzzing")]
const MAX_FUZZ_HEADERS: usize = 16;
#[cfg(feature = "fuzzing")]
const MAX_FUZZ_HEADER_NAME_BYTES: usize = 64;
#[cfg(feature = "fuzzing")]
const MAX_FUZZ_HEADER_VALUE_BYTES: usize = 512;
#[cfg(feature = "fuzzing")]
const MAX_FUZZ_NORMALIZED_BYTES: usize = MAX_FUZZ_INPUT_BYTES * 4;

pub(crate) fn normalize_text(input: &str) -> String {
  let decoded = decode_percent_and_unicode(input);
  let without_nulls = decoded.replace('\0', "");
  let nfc = without_nulls.nfc().collect::<String>();
  let mut out = String::with_capacity(nfc.len());
  let mut previous_was_space = false;
  for ch in nfc.chars() {
    if ch.is_whitespace() {
      if !previous_was_space {
        out.push(' ');
        previous_was_space = true;
      }
    } else {
      for lower in ch.to_lowercase() {
        out.push(lower);
      }
      previous_was_space = false;
    }
  }
  out.trim().to_string()
}

pub(crate) fn normalized_http_path(uri: &Uri) -> String {
  normalize_path(uri.path())
}

pub(crate) fn normalized_http_query(uri: &Uri) -> String {
  uri.query().map(normalize_text).unwrap_or_default()
}

pub(crate) fn normalized_http_uri(uri: &Uri) -> String {
  let path = normalized_http_path(uri);
  let query = normalized_http_query(uri);
  if query.is_empty() {
    path
  } else {
    format!("{path}?{query}")
  }
}

pub(crate) fn normalize_header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
  headers
    .iter()
    .filter_map(|(name, value)| {
      value
        .to_str()
        .ok()
        .map(|value| (normalize_text(name.as_str()), normalize_text(value)))
    })
    .collect()
}

pub(crate) fn normalize_query_pairs(uri: &Uri) -> Vec<(String, String)> {
  let query = uri.query().unwrap_or_default();
  form_urlencoded::parse(query.as_bytes())
    .map(|(name, value)| (normalize_text(&name), normalize_text(&value)))
    .collect()
}

pub(crate) fn normalize_cookie_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
  headers
    .get_all(http::header::COOKIE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(';'))
    .filter_map(|part| part.trim().split_once('='))
    .map(|(name, value)| (normalize_text(name.trim()), normalize_text(value.trim())))
    .collect()
}

pub(crate) fn normalize_path(path: &str) -> String {
  let decoded = normalize_text(path).replace('\\', "/");
  let absolute = decoded.starts_with('/');
  let mut segments = Vec::new();
  for segment in decoded.split('/') {
    match segment {
      "" | "." => {}
      ".." => {
        segments.pop();
      }
      value => segments.push(value),
    }
  }
  let mut normalized = segments.join("/");
  if absolute {
    normalized.insert(0, '/');
  }
  if normalized.is_empty() {
    "/".to_string()
  } else {
    normalized
  }
}

fn decode_percent_and_unicode(input: &str) -> String {
  let mut out = String::with_capacity(input.len());
  let bytes = input.as_bytes();
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'%' {
      if index + 5 < bytes.len()
        && matches!(bytes[index + 1], b'u' | b'U')
        && let Some(codepoint) = hex_u32(&bytes[index + 2..index + 6])
        && let Some(ch) = char::from_u32(codepoint)
      {
        out.push(ch);
        index += 6;
        continue;
      }
      if index + 2 < bytes.len()
        && let Some(byte) = hex_byte(bytes[index + 1], bytes[index + 2])
      {
        out.push(byte as char);
        index += 3;
        continue;
      }
    }
    let ch = input[index..].chars().next().unwrap_or('\u{fffd}');
    out.push(ch);
    index += ch.len_utf8();
  }
  out
}

fn hex_u32(bytes: &[u8]) -> Option<u32> {
  let mut value = 0u32;
  for byte in bytes {
    value = value.checked_mul(16)?;
    value = value.checked_add(u32::from(hex_nibble(*byte)?))?;
  }
  Some(value)
}

fn hex_byte(high: u8, low: u8) -> Option<u8> {
  Some((hex_nibble(high)? << 4) | hex_nibble(low)?)
}

fn hex_nibble(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

/// Exercise bounded, derived WAF request metadata without mutating request data.
///
/// A second normalization pass is observed for deterministic behavior, but is
/// deliberately not compared with the first pass: nested percent encodings can
/// change under the established single-pass normalization semantics.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_request_normalization(data: &[u8]) {
  let data = &data[..data.len().min(MAX_FUZZ_INPUT_BYTES)];
  let (uri, headers, text, crs_source) = fuzz_components(data);
  let uri_before = uri.clone();
  let headers_before = headers.clone();

  let first = normalized_projection(&text, &uri, &headers);
  let second = normalized_projection(&text, &uri, &headers);
  assert_eq!(
    first, second,
    "WAF normalization changed for identical request metadata"
  );
  assert_eq!(uri, uri_before, "WAF normalization mutated the request URI");
  assert_eq!(
    headers, headers_before,
    "WAF normalization mutated the request headers"
  );
  assert_normalized_projection(&first);

  let first_reprocessed = reprocess_projection(&first);
  let second_reprocessed = reprocess_projection(&first);
  assert_eq!(
    first_reprocessed, second_reprocessed,
    "WAF re-normalization changed for identical normalized metadata"
  );
  assert_normalized_projection(&first_reprocessed);

  crate::waf::crs::fuzz_parse_and_process(&crs_source, &first.text);
}

#[cfg(feature = "fuzzing")]
#[derive(Debug, Eq, PartialEq)]
struct NormalizedProjection {
  text: String,
  path: String,
  query: String,
  uri: String,
  headers: Vec<(String, String)>,
  query_pairs: Vec<(String, String)>,
  cookie_pairs: Vec<(String, String)>,
}

#[cfg(feature = "fuzzing")]
fn normalized_projection(text: &str, uri: &Uri, headers: &HeaderMap) -> NormalizedProjection {
  NormalizedProjection {
    text: normalize_text(text),
    path: normalized_http_path(uri),
    query: normalized_http_query(uri),
    uri: normalized_http_uri(uri),
    headers: normalize_header_pairs(headers),
    query_pairs: normalize_query_pairs(uri),
    cookie_pairs: normalize_cookie_pairs(headers),
  }
}

#[cfg(feature = "fuzzing")]
fn reprocess_projection(value: &NormalizedProjection) -> NormalizedProjection {
  NormalizedProjection {
    text: normalize_text(&value.text),
    path: normalize_path(&value.path),
    query: normalize_text(&value.query),
    uri: normalize_text(&value.uri),
    headers: value
      .headers
      .iter()
      .map(|(name, value)| (normalize_text(name), normalize_text(value)))
      .collect(),
    query_pairs: value
      .query_pairs
      .iter()
      .map(|(name, value)| (normalize_text(name), normalize_text(value)))
      .collect(),
    cookie_pairs: value
      .cookie_pairs
      .iter()
      .map(|(name, value)| (normalize_text(name), normalize_text(value)))
      .collect(),
  }
}

#[cfg(feature = "fuzzing")]
fn assert_normalized_projection(value: &NormalizedProjection) {
  for text in std::iter::once(&value.text)
    .chain(std::iter::once(&value.path))
    .chain(std::iter::once(&value.query))
    .chain(std::iter::once(&value.uri))
    .chain(value.headers.iter().flat_map(|(name, value)| [name, value]))
    .chain(
      value
        .query_pairs
        .iter()
        .flat_map(|(name, value)| [name, value]),
    )
    .chain(
      value
        .cookie_pairs
        .iter()
        .flat_map(|(name, value)| [name, value]),
    )
  {
    assert!(
      text.len() <= MAX_FUZZ_NORMALIZED_BYTES,
      "bounded WAF normalization exceeded the fuzz output limit"
    );
    assert!(
      !text.contains('\0'),
      "normalized WAF metadata retained a NUL"
    );
    assert_eq!(
      text.trim(),
      text,
      "normalized WAF metadata retained edge whitespace"
    );
  }
}

#[cfg(feature = "fuzzing")]
fn fuzz_components(data: &[u8]) -> (Uri, HeaderMap, String, String) {
  let mut input = FuzzInput::new(data);
  let uri_text = input.text(MAX_FUZZ_URI_BYTES);
  let uri = uri_text.parse().unwrap_or_else(|_| Uri::from_static("/"));
  let text = input.text(MAX_FUZZ_TEXT_BYTES);
  let mut headers = HeaderMap::new();
  for _ in 0..input.usize(MAX_FUZZ_HEADERS + 1) {
    let name = input.header_name();
    let value_length = input.usize(MAX_FUZZ_HEADER_VALUE_BYTES + 1);
    let value = input.bytes(value_length);
    if let Ok(value) = HeaderValue::from_bytes(&value) {
      headers.append(name, value);
    }
  }
  let crs_source = input.text(MAX_FUZZ_CRS_BYTES);
  (uri, headers, text, crs_source)
}

#[cfg(feature = "fuzzing")]
struct FuzzInput<'a> {
  data: &'a [u8],
  offset: usize,
}

#[cfg(feature = "fuzzing")]
impl<'a> FuzzInput<'a> {
  fn new(data: &'a [u8]) -> Self {
    Self { data, offset: 0 }
  }

  fn byte(&mut self) -> u8 {
    if self.data.is_empty() {
      return 0;
    }
    let byte = self.data[self.offset % self.data.len()];
    self.offset = self.offset.wrapping_add(1);
    byte
  }

  fn usize(&mut self, modulo: usize) -> usize {
    if modulo == 0 {
      return 0;
    }
    ((usize::from(self.byte()) << 8) | usize::from(self.byte())) % modulo
  }

  fn bytes(&mut self, length: usize) -> Vec<u8> {
    (0..length).map(|_| self.byte()).collect()
  }

  fn text(&mut self, maximum: usize) -> String {
    let length = self.usize(maximum + 1);
    String::from_utf8_lossy(&self.bytes(length)).into_owned()
  }

  fn header_name(&mut self) -> HeaderName {
    const FALLBACK_NAMES: &[&str] = &["cookie", "host", "user-agent", "x-waf-fuzz"];
    let length = self.usize(MAX_FUZZ_HEADER_NAME_BYTES + 1);
    let raw = self.bytes(length);
    HeaderName::from_bytes(&raw)
      .unwrap_or_else(|_| HeaderName::from_static(FALLBACK_NAMES[self.usize(FALLBACK_NAMES.len())]))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn path_normalization_decodes_unicode_percent_and_segments() {
    let uri: Uri = "/A/%75%6e%69%6f%6e/%2e%2e/%u0053ELECT//x".parse().unwrap();

    assert_eq!(normalized_http_path(&uri), "/a/select/x");
  }

  #[test]
  fn invalid_percent_sequences_are_preserved() {
    assert_eq!(normalize_text("%zz UNION\t SELECT"), "%zz union select");
  }
}
