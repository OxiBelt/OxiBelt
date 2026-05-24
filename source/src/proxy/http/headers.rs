use std::net::IpAddr;
use std::str::FromStr;

use http::Request;
use http::header::{
  CONNECTION, FORWARDED, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE,
  PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::uri::Authority;

use crate::config::ForwardedHeaderMode;
use crate::routes::normalize_host;

pub(crate) fn extract_host<B>(request: &Request<B>) -> Option<String> {
  if let Some(authority) = request.uri().authority() {
    return Some(normalize_host(authority.host()));
  }

  request
    .headers()
    .get(HOST)
    .and_then(|value| value.to_str().ok())
    .map(normalize_host)
}

pub(crate) fn extract_downstream_port<B>(request: &Request<B>, scheme: &str) -> u16 {
  request
    .uri()
    .authority()
    .and_then(|authority| authority.port_u16())
    .or_else(|| {
      request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(explicit_authority_port)
    })
    .unwrap_or_else(|| default_port_for_scheme(scheme))
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
  let scheme = request.uri().scheme_str();
  if effective_authority(authority.as_str(), scheme)? == effective_authority(host, scheme)? {
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
  forwarded_client_addr: std::net::SocketAddr,
  host: &str,
  scheme: &str,
  port: u16,
  mode: ForwardedHeaderMode,
) {
  remove_inbound_forwarded_headers(headers, mode);
  let forwarded_ip = forwarded_client_addr.ip();
  match mode {
    ForwardedHeaderMode::Overwrite => {
      headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        ip_header_value(forwarded_ip),
      );
    }
    ForwardedHeaderMode::Append => {
      let forwarded_for = forwarded_ip.to_string();
      append_csv_header(headers, "x-forwarded-for", &forwarded_for);
    }
  }

  headers.insert(
    HeaderName::from_static("x-forwarded-proto"),
    forwarded_proto_header_value(scheme),
  );

  if let Ok(value) = HeaderValue::from_str(host) {
    headers.insert(HeaderName::from_static("x-forwarded-host"), value);
  }

  headers.insert(
    HeaderName::from_static("x-forwarded-port"),
    port_header_value(port),
  );
}

#[derive(Debug, Eq, PartialEq)]
struct EffectiveAuthority {
  host: String,
  port: Option<u16>,
}

fn effective_authority(
  raw: &str,
  scheme: Option<&str>,
) -> Result<EffectiveAuthority, HostConsistencyError> {
  let authority = Authority::from_str(raw.trim()).map_err(|_| HostConsistencyError)?;
  Ok(EffectiveAuthority {
    host: normalize_host(authority.host()),
    port: authority
      .port_u16()
      .or_else(|| scheme.and_then(default_port_for_optional_scheme)),
  })
}

fn explicit_authority_port(raw: &str) -> Option<u16> {
  Authority::from_str(raw.trim())
    .ok()
    .and_then(|authority| authority.port_u16())
}

fn default_port_for_scheme(scheme: &str) -> u16 {
  default_port_for_optional_scheme(scheme).unwrap_or(443)
}

fn default_port_for_optional_scheme(scheme: &str) -> Option<u16> {
  match scheme {
    "http" => Some(80),
    "https" => Some(443),
    _ => None,
  }
}

fn remove_inbound_forwarded_headers(headers: &mut HeaderMap, mode: ForwardedHeaderMode) {
  if !has_inbound_forwarded_headers(headers, mode) {
    return;
  }

  headers.remove(FORWARDED);
  if mode == ForwardedHeaderMode::Overwrite {
    headers.remove(HeaderName::from_static("x-forwarded-for"));
  }
  headers.remove(HeaderName::from_static("x-forwarded-host"));
  headers.remove(HeaderName::from_static("x-forwarded-proto"));
  headers.remove(HeaderName::from_static("x-forwarded-port"));
}

fn has_inbound_forwarded_headers(headers: &HeaderMap, mode: ForwardedHeaderMode) -> bool {
  headers.contains_key(FORWARDED)
    || (mode == ForwardedHeaderMode::Overwrite && headers.contains_key("x-forwarded-for"))
    || headers.contains_key("x-forwarded-host")
    || headers.contains_key("x-forwarded-proto")
    || headers.contains_key("x-forwarded-port")
}

fn forwarded_proto_header_value(scheme: &str) -> HeaderValue {
  match scheme {
    "http" => HeaderValue::from_static("http"),
    "https" => HeaderValue::from_static("https"),
    _ => HeaderValue::from_str(scheme).unwrap_or_else(|_| HeaderValue::from_static("https")),
  }
}

fn ip_header_value(ip: IpAddr) -> HeaderValue {
  match ip {
    IpAddr::V4(addr) => {
      let octets = addr.octets();
      let mut buf = [0u8; 15];
      let mut len = 0;
      for (index, octet) in octets.into_iter().enumerate() {
        if index > 0 {
          buf[len] = b'.';
          len += 1;
        }
        len += write_u8_decimal(octet, &mut buf[len..]);
      }
      HeaderValue::from_bytes(&buf[..len]).expect("IPv4 text is a valid header value")
    }
    IpAddr::V6(addr) => {
      HeaderValue::from_str(&addr.to_string()).expect("IPv6 text is a valid header value")
    }
  }
}

fn write_u8_decimal(value: u8, output: &mut [u8]) -> usize {
  if value >= 100 {
    output[0] = b'0' + value / 100;
    output[1] = b'0' + (value / 10) % 10;
    output[2] = b'0' + value % 10;
    3
  } else if value >= 10 {
    output[0] = b'0' + value / 10;
    output[1] = b'0' + value % 10;
    2
  } else {
    output[0] = b'0' + value;
    1
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

fn port_header_value(port: u16) -> HeaderValue {
  let mut buf = [0u8; 5];
  let mut value = port;
  let mut index = buf.len();
  loop {
    index -= 1;
    buf[index] = b'0' + (value % 10) as u8;
    value /= 10;
    if value == 0 {
      break;
    }
  }
  HeaderValue::from_bytes(&buf[index..]).expect("u16 decimal port is a valid header value")
}

pub(crate) fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
  if !has_hop_by_hop_headers(headers) {
    return;
  }

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

fn has_hop_by_hop_headers(headers: &HeaderMap) -> bool {
  headers.contains_key(CONNECTION)
    || headers.contains_key("keep-alive")
    || headers.contains_key(PROXY_AUTHENTICATE)
    || headers.contains_key(PROXY_AUTHORIZATION)
    || headers.contains_key(TRAILER)
    || headers.contains_key(TRANSFER_ENCODING)
    || headers.contains_key(UPGRADE)
    || headers.contains_key(TE)
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
      .header(HOST, "Example.Test:8443")
      .body(())
      .expect("request should build");

    assert!(validate_authority_host_consistency(&request).is_ok());
  }

  #[test]
  fn authority_host_consistency_rejects_absolute_form_port_mismatch() {
    let request = Request::builder()
      .uri("http://example.test:8443/path")
      .header(HOST, "example.test:9443")
      .body(())
      .expect("request should build");

    assert_eq!(
      validate_authority_host_consistency(&request),
      Err(HostConsistencyError)
    );
  }

  #[test]
  fn authority_host_consistency_accepts_default_port_equivalence() {
    let request = Request::builder()
      .uri("http://example.test/path")
      .header(HOST, "example.test:80")
      .body(())
      .expect("request should build");

    assert!(validate_authority_host_consistency(&request).is_ok());
  }

  #[test]
  fn downstream_port_prefers_authority_then_host_then_scheme_default() {
    let authority = Request::builder()
      .uri("http://absolute.example:8080/path")
      .header(HOST, "header.example:9443")
      .body(())
      .expect("request should build");
    let host = Request::builder()
      .uri("/path")
      .header(HOST, "header.example:9443")
      .body(())
      .expect("request should build");
    let default = Request::builder()
      .uri("/path")
      .header(HOST, "header.example")
      .body(())
      .expect("request should build");

    assert_eq!(extract_downstream_port(&authority, "http"), 8080);
    assert_eq!(extract_downstream_port(&host, "https"), 9443);
    assert_eq!(extract_downstream_port(&default, "https"), 443);
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
      443,
      ForwardedHeaderMode::Overwrite,
    );

    assert!(!headers.contains_key(FORWARDED));
    assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
    assert_eq!(headers["x-forwarded-host"], "example.test");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-port"], "443");
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
      8443,
      ForwardedHeaderMode::Append,
    );

    assert!(!headers.contains_key(FORWARDED));
    assert_eq!(headers["x-forwarded-for"], "198.51.100.1, 203.0.113.10");
    assert_eq!(headers["x-forwarded-host"], "example.test");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-port"], "8443");
  }

  #[test]
  fn forwarded_headers_format_ipv6_client_ip() {
    let mut headers = HeaderMap::new();

    add_forwarded_headers(
      &mut headers,
      "[2001:db8::10]:5443".parse().unwrap(),
      "example.test",
      "https",
      443,
      ForwardedHeaderMode::Overwrite,
    );

    assert_eq!(headers["x-forwarded-for"], "2001:db8::10");
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
  fn hop_by_hop_stripping_keeps_ordinary_headers_on_empty_fast_path() {
    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("2"));
    headers.insert("content-type", HeaderValue::from_static("text/plain"));

    strip_hop_by_hop_headers(&mut headers);

    assert_eq!(headers["content-length"], "2");
    assert_eq!(headers["content-type"], "text/plain");
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
