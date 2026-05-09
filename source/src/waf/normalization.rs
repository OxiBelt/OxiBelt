use http::{HeaderMap, Uri};
use unicode_normalization::UnicodeNormalization;
use url::form_urlencoded;

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
