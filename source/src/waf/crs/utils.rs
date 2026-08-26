//! CRS variable extraction helpers.
//! Extracted values are request snapshots used only for rule matching.

use http::{HeaderMap, Uri, Version};

use super::super::WafBodyInput;
use super::variables::CrsSelector;

pub(super) fn crs_phase_name(phase: u8) -> &'static str {
  match phase {
    1 | 2 => "request",
    3 | 4 => "response",
    _ => "unknown",
  }
}

pub(super) fn version_string(version: Version) -> String {
  match version {
    Version::HTTP_09 => "HTTP/0.9",
    Version::HTTP_10 => "HTTP/1.0",
    Version::HTTP_11 => "HTTP/1.1",
    Version::HTTP_2 => "HTTP/2.0",
    Version::HTTP_3 => "HTTP/3.0",
    _ => "HTTP/1.1",
  }
  .to_string()
}

pub(super) fn header_values(
  headers: &HeaderMap,
  selector: &CrsSelector,
) -> anyhow::Result<Vec<String>> {
  Ok(match selector {
    CrsSelector::Regex(regex) => {
      let mut values = Vec::new();
      for (name, value) in headers {
        if regex.is_match(name.as_str())?
          && let Ok(value) = value.to_str()
        {
          values.push(value.to_string());
        }
      }
      values
    }
    CrsSelector::Exact(selector) => headers
      .get_all(selector)
      .iter()
      .filter_map(|value| value.to_str().ok().map(ToString::to_string))
      .collect(),
    CrsSelector::Any => headers
      .values()
      .filter_map(|value| value.to_str().ok().map(ToString::to_string))
      .collect(),
  })
}

pub(super) fn query_pairs(uri: &Uri) -> Vec<(String, String)> {
  url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect()
}

pub(super) fn cookie_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
  headers
    .get_all(http::header::COOKIE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(';'))
    .filter_map(|part| part.trim().split_once('='))
    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
    .collect()
}

pub(super) fn body_pairs(
  headers: &HeaderMap,
  body: Option<WafBodyInput<'_>>,
) -> Vec<(String, String)> {
  let content_type = headers
    .get(http::header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default()
    .to_ascii_lowercase();
  if !content_type.contains("application/x-www-form-urlencoded") {
    return Vec::new();
  }
  let Some(body) = body else {
    return Vec::new();
  };
  url::form_urlencoded::parse(body.bytes)
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect()
}

pub(super) fn select_pairs(pairs: Vec<(String, String)>, selector: Option<&str>) -> Vec<String> {
  match selector {
    Some(selector) => pairs
      .into_iter()
      .filter(|(name, _)| name.eq_ignore_ascii_case(selector))
      .map(|(_, value)| value)
      .collect(),
    None => pairs.into_iter().map(|(_, value)| value).collect(),
  }
}

pub(super) fn invalid_url_encoding(value: &str) -> bool {
  let bytes = value.as_bytes();
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'%' {
      if index + 2 >= bytes.len()
        || hex_nibble(bytes[index + 1]).is_none()
        || hex_nibble(bytes[index + 2]).is_none()
      {
        return true;
      }
      index += 3;
    } else {
      index += 1;
    }
  }
  false
}

pub(super) fn invalid_utf8_encoding(value: &str) -> bool {
  if value.contains('\u{FFFD}') {
    return true;
  }

  let bytes = value.as_bytes();
  let mut decoded = Vec::with_capacity(bytes.len());
  let mut saw_percent_encoding = false;
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'%'
      && index + 2 < bytes.len()
      && let (Some(high), Some(low)) = (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
    {
      decoded.push((high << 4) | low);
      saw_percent_encoding = true;
      index += 3;
      continue;
    }
    decoded.push(bytes[index]);
    index += 1;
  }

  saw_percent_encoding && std::str::from_utf8(&decoded).is_err()
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
  use super::{invalid_url_encoding, invalid_utf8_encoding};

  #[test]
  fn invalid_url_encoding_detects_malformed_percent_sequences() {
    assert!(!invalid_url_encoding("/app/search?q=safe%20value"));
    assert!(!invalid_url_encoding("/app/search?q=%2f"));
    assert!(invalid_url_encoding("/app/search?q=%ZZ"));
    assert!(invalid_url_encoding("/app/search?q=trailing%"));
  }

  #[test]
  fn invalid_utf8_encoding_detects_bad_percent_encoded_bytes() {
    assert!(!invalid_utf8_encoding("/app/search?q=plain"));
    assert!(!invalid_utf8_encoding("/app/search?q=%E2%9C%93"));
    assert!(!invalid_utf8_encoding("/app/search?q=%ZZ"));
    assert!(invalid_utf8_encoding("/app/search?q=%C0%AF"));
    assert!(invalid_utf8_encoding("\u{FFFD}\u{FFFD}"));
  }
}
