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

pub(crate) fn validate_authority_host_consistency<B>(
  request: &Request<B>,
) -> Result<(), HostConsistencyError> {
  let Some(authority) = request.uri().authority() else {
    return Ok(());
  };
  let Some(host) = request.headers().get(HOST) else {
    return Ok(());
  };
  let host = host.to_str().map_err(|_| HostConsistencyError)?;
  if normalize_host(authority.as_str()) == normalize_host(host) {
    Ok(())
  } else {
    Err(HostConsistencyError)
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct HostConsistencyError;

pub(crate) fn set_effective_host_header(headers: &mut HeaderMap, host: &str) {
  if host.is_empty() {
    headers.remove(HOST);
    return;
  }
  match HeaderValue::from_str(host) {
    Ok(value) => {
      headers.insert(HOST, value);
    }
    Err(_) => {
      headers.remove(HOST);
    }
  }
}

pub(crate) fn add_forwarded_headers(
  headers: &mut HeaderMap,
  peer_addr: std::net::SocketAddr,
  host: &str,
  scheme: &str,
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
    HeaderValue::from_str(scheme).unwrap_or_else(|_| HeaderValue::from_static("https")),
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
  if headers.contains_key(CONNECTION) {
    let mut dynamic_tokens: Option<Vec<HeaderName>> = None;
    let mut remove_close_header = false;
    let mut remove_te_header = false;
    for token in headers
      .get_all(CONNECTION)
      .iter()
      .filter_map(|value| value.to_str().ok())
      .flat_map(|value| value.split(','))
      .map(str::trim)
      .filter(|value| !value.is_empty())
    {
      if fixed_connection_token(token, &mut remove_close_header, &mut remove_te_header) {
        continue;
      }
      if let Ok(name) = HeaderName::from_str(token) {
        dynamic_tokens.get_or_insert_with(Vec::new).push(name);
      }
    }

    if let Some(dynamic_tokens) = dynamic_tokens {
      for token in dynamic_tokens {
        headers.remove(token);
      }
    }
    if remove_close_header {
      headers.remove(HeaderName::from_static("close"));
    }
    if remove_te_header {
      headers.remove(TE);
    }
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

fn fixed_connection_token(
  token: &str,
  remove_close_header: &mut bool,
  remove_te_header: &mut bool,
) -> bool {
  if token.eq_ignore_ascii_case("close") {
    *remove_close_header = true;
    return true;
  }
  if token.eq_ignore_ascii_case("te") {
    *remove_te_header = true;
    return true;
  }
  if token.eq_ignore_ascii_case("connection")
    || token.eq_ignore_ascii_case("keep-alive")
    || token.eq_ignore_ascii_case("proxy-authenticate")
    || token.eq_ignore_ascii_case("proxy-authorization")
    || token.eq_ignore_ascii_case("trailer")
    || token.eq_ignore_ascii_case("transfer-encoding")
    || token.eq_ignore_ascii_case("upgrade")
  {
    return true;
  }
  false
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
  use http::{HeaderMap, Request};

  use super::*;

  #[test]
  fn extract_host_prefers_absolute_form_authority_over_host_header() {
    let request = Request::builder()
      .uri("http://absolute.example:8080/path?query=1")
      .header(HOST, "header.example")
      .body(())
      .expect("request should build");

    assert_eq!(extract_host(&request).as_deref(), Some("absolute.example"));
  }

  #[test]
  fn authority_host_consistency_rejects_absolute_form_mismatch() {
    let request = Request::builder()
      .uri("http://absolute.example/path")
      .header(HOST, "header.example")
      .body(())
      .expect("request should build");

    assert_eq!(
      validate_authority_host_consistency(&request),
      Err(HostConsistencyError)
    );
  }

  #[test]
  fn authority_host_consistency_accepts_matching_normalized_hosts() {
    let request = Request::builder()
      .uri("http://example.test:8443/path")
      .header(HOST, "Example.Test")
      .body(())
      .expect("request should build");

    assert!(validate_authority_host_consistency(&request).is_ok());
  }

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
      "https",
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
      "https",
      ForwardedHeaderMode::Append,
    );

    assert!(!headers.contains_key(FORWARDED));
    assert_eq!(headers["x-forwarded-for"], "198.51.100.1, 203.0.113.10");
    assert_eq!(headers["x-forwarded-host"], "example.test");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-port"], "5443");
  }

  #[test]
  fn hop_by_hop_stripping_removes_connection_tokens_and_fixed_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, x-hop"));
    headers.insert("x-hop", HeaderValue::from_static("remove"));
    headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));

    strip_hop_by_hop_headers(&mut headers);

    assert!(!headers.contains_key(CONNECTION));
    assert!(!headers.contains_key("x-hop"));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key(TRANSFER_ENCODING));
    assert!(!headers.contains_key(UPGRADE));
  }

  #[test]
  fn hop_by_hop_stripping_handles_common_fixed_connection_tokens() {
    let mut headers = HeaderMap::new();
    headers.insert(
      CONNECTION,
      HeaderValue::from_static("keep-alive, close, upgrade"),
    );
    headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
    headers.insert("close", HeaderValue::from_static("remove"));
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert("x-hop", HeaderValue::from_static("preserve"));

    strip_hop_by_hop_headers(&mut headers);

    assert!(!headers.contains_key(CONNECTION));
    assert!(!headers.contains_key("keep-alive"));
    assert!(!headers.contains_key("close"));
    assert!(!headers.contains_key(UPGRADE));
    assert_eq!(headers["x-hop"], "preserve");
  }

  #[test]
  fn hop_by_hop_stripping_preserves_only_te_trailers() {
    let mut trailers = HeaderMap::new();
    trailers.insert(TE, HeaderValue::from_static("trailers"));
    strip_hop_by_hop_headers(&mut trailers);
    assert_eq!(trailers.get(TE).unwrap(), "trailers");

    let mut gzip = HeaderMap::new();
    gzip.insert(TE, HeaderValue::from_static("gzip"));
    strip_hop_by_hop_headers(&mut gzip);
    assert!(!gzip.contains_key(TE));
  }

  #[test]
  fn hop_by_hop_stripping_removes_te_when_connection_lists_te() {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("te"));
    headers.insert(TE, HeaderValue::from_static("trailers"));

    strip_hop_by_hop_headers(&mut headers);

    assert!(!headers.contains_key(CONNECTION));
    assert!(!headers.contains_key(TE));
  }
}
