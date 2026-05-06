use std::str::FromStr;

use http::Request;
use http::header::{
  CONNECTION, FORWARDED, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE,
  PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};

use crate::config::ForwardedHeaderMode;
use crate::routes::normalize_host;

pub(crate) fn extract_host<B>(request: &Request<B>) -> Option<String> {
  if let Some(authority) = request.uri().authority() {
    return Some(normalize_host(authority.as_str()));
  }

  request
    .headers()
    .get(HOST)
    .and_then(|value| value.to_str().ok())
    .map(normalize_host)
}

pub(crate) fn add_forwarded_headers(
  headers: &mut HeaderMap,
  peer_addr: std::net::SocketAddr,
  host: &str,
  mode: ForwardedHeaderMode,
) {
  remove_inbound_forwarded_headers(headers, mode);
  match mode {
    ForwardedHeaderMode::Overwrite => {
      set_header(headers, "x-forwarded-for", &peer_addr.ip().to_string());
    }
    ForwardedHeaderMode::Append => {
      append_csv_header(headers, "x-forwarded-for", &peer_addr.ip().to_string());
    }
  }

  headers.insert(
    HeaderName::from_static("x-forwarded-proto"),
    HeaderValue::from_static("https"),
  );

  if let Ok(value) = HeaderValue::from_str(host) {
    headers.insert(HeaderName::from_static("x-forwarded-host"), value);
  }

  if let Ok(value) = HeaderValue::from_str(&peer_addr.port().to_string()) {
    headers.insert(HeaderName::from_static("x-forwarded-port"), value);
  }
}

fn remove_inbound_forwarded_headers(headers: &mut HeaderMap, mode: ForwardedHeaderMode) {
  headers.remove(FORWARDED);
  if mode == ForwardedHeaderMode::Overwrite {
    headers.remove(HeaderName::from_static("x-forwarded-for"));
  }
  headers.remove(HeaderName::from_static("x-forwarded-host"));
  headers.remove(HeaderName::from_static("x-forwarded-proto"));
  headers.remove(HeaderName::from_static("x-forwarded-port"));
}

fn set_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
  let header_name = HeaderName::from_static(name);
  if let Ok(header_value) = HeaderValue::from_str(value) {
    headers.insert(header_name, header_value);
  }
}

fn append_csv_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
  let header_name = HeaderName::from_static(name);
  let next_value = match headers
    .get(&header_name)
    .and_then(|item| item.to_str().ok())
  {
    Some(existing) if !existing.is_empty() => format!("{existing}, {value}"),
    _ => value.to_string(),
  };

  if let Ok(header_value) = HeaderValue::from_str(&next_value) {
    headers.insert(header_name, header_value);
  }
}

pub(crate) fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
  let connection_tokens = headers
    .get_all(CONNECTION)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .filter_map(|value| HeaderName::from_str(value).ok())
    .collect::<Vec<_>>();

  for token in connection_tokens {
    headers.remove(token);
  }

  headers.remove(CONNECTION);
  headers.remove(HeaderName::from_static("keep-alive"));
  headers.remove(PROXY_AUTHENTICATE);
  headers.remove(PROXY_AUTHORIZATION);
  headers.remove(TRAILER);
  headers.remove(TRANSFER_ENCODING);
  headers.remove(UPGRADE);

  let remove_te = headers
    .get(TE)
    .and_then(|value| value.to_str().ok())
    .map(|value| !value.eq_ignore_ascii_case("trailers"))
    .unwrap_or(false);
  if remove_te {
    headers.remove(TE);
  }
}

pub(crate) fn is_upgrade_request<B>(request: &Request<B>) -> bool {
  request.headers().contains_key(UPGRADE)
    || request
      .headers()
      .get(CONNECTION)
      .and_then(|value| value.to_str().ok())
      .map(|value| {
        value
          .split(',')
          .any(|item| item.trim().eq_ignore_ascii_case("upgrade"))
      })
      .unwrap_or(false)
}

#[cfg(test)]
mod tests {
  use http::HeaderMap;

  use super::*;

  #[test]
  fn forwarded_headers_overwrite_spoofed_inbound_values() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "forwarded",
      HeaderValue::from_static("for=198.51.100.1;proto=http"),
    );
    headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
    headers.insert("x-forwarded-host", HeaderValue::from_static("evil.test"));
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    headers.insert("x-forwarded-port", HeaderValue::from_static("80"));

    add_forwarded_headers(
      &mut headers,
      "203.0.113.10:5443".parse().unwrap(),
      "example.test",
      ForwardedHeaderMode::Overwrite,
    );

    assert!(!headers.contains_key(FORWARDED));
    assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
    assert_eq!(headers["x-forwarded-host"], "example.test");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-port"], "5443");
  }

  #[test]
  fn forwarded_headers_append_preserves_only_x_forwarded_for_chain() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "forwarded",
      HeaderValue::from_static("for=198.51.100.1;proto=http"),
    );
    headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
    headers.insert("x-forwarded-host", HeaderValue::from_static("evil.test"));
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    headers.insert("x-forwarded-port", HeaderValue::from_static("80"));

    add_forwarded_headers(
      &mut headers,
      "203.0.113.10:5443".parse().unwrap(),
      "example.test",
      ForwardedHeaderMode::Append,
    );

    assert!(!headers.contains_key(FORWARDED));
    assert_eq!(headers["x-forwarded-for"], "198.51.100.1, 203.0.113.10");
    assert_eq!(headers["x-forwarded-host"], "example.test");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-port"], "5443");
  }
}
