//! Header normalization and forwarding helpers for HTTP proxying.
//! Hop-by-hop and authority-sensitive headers are handled here before upstream dispatch.

use std::net::IpAddr;
use std::str::FromStr;

use http::Request;
use http::header::{
  CONNECTION, FORWARDED, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE,
  PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::uri::Authority;

use crate::config::{
  ForwardedClientIpSource, ForwardedHeaderMode, ForwardedHeadersConfig, RealIpConfig,
};
use crate::routes::normalize_host;

mod host;
pub(crate) use self::host::{extract_downstream_port, extract_host, extract_host_snapshot};

const CLOSE_HEADER: HeaderName = HeaderName::from_static("close");
const KEEP_ALIVE_HEADER: HeaderName = HeaderName::from_static("keep-alive");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PORT: HeaderName = HeaderName::from_static("x-forwarded-port");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

#[derive(Clone, Debug)]
pub(crate) struct ForwardedHeaderCache {
  x_forwarded_for: HeaderValue,
  x_forwarded_proto: HeaderValue,
}

#[derive(Clone, Debug)]
pub(crate) struct ForwardedRequestHeaderValues {
  host: Option<HeaderValue>,
  port: HeaderValue,
}

impl ForwardedRequestHeaderValues {
  pub(crate) fn new(host: &str, port: u16) -> Self {
    Self {
      host: effective_host_header_value(host),
      port: port_header_value(port),
    }
  }

  pub(crate) fn host(&self) -> Option<&HeaderValue> {
    self.host.as_ref()
  }

  fn port(&self) -> &HeaderValue {
    &self.port
  }
}

pub(crate) fn build_forwarded_header_cache(
  peer_addr: std::net::SocketAddr,
  scheme: &str,
  forwarded_headers: &ForwardedHeadersConfig,
  real_ip: &RealIpConfig,
) -> Option<ForwardedHeaderCache> {
  if forwarded_headers.mode != ForwardedHeaderMode::Overwrite {
    return None;
  }
  if real_ip.enabled && forwarded_headers.client_ip_source != ForwardedClientIpSource::DirectPeer {
    return None;
  }
  Some(ForwardedHeaderCache {
    x_forwarded_for: ip_header_value(peer_addr.ip()),
    x_forwarded_proto: forwarded_proto_header_value(scheme),
  })
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
  let value = effective_host_header_value(host);
  set_effective_host_header_value(headers, value.as_ref());
}

pub(crate) fn set_effective_host_header_value(headers: &mut HeaderMap, host: Option<&HeaderValue>) {
  if let Some(value) = host
    && !value.as_bytes().is_empty()
  {
    headers.insert(HOST, value.clone());
  } else {
    headers.remove(HOST);
  }
}

pub(crate) fn add_forwarded_headers(
  headers: &mut HeaderMap,
  forwarded_client_addr: std::net::SocketAddr,
  host: &str,
  scheme: &str,
  port: u16,
  mode: ForwardedHeaderMode,
  cache: Option<&ForwardedHeaderCache>,
) {
  add_forwarded_headers_with_values(
    headers,
    forwarded_client_addr,
    host,
    scheme,
    port,
    mode,
    cache,
    None,
  );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_forwarded_headers_with_values(
  headers: &mut HeaderMap,
  forwarded_client_addr: std::net::SocketAddr,
  host: &str,
  scheme: &str,
  port: u16,
  mode: ForwardedHeaderMode,
  cache: Option<&ForwardedHeaderCache>,
  values: Option<&ForwardedRequestHeaderValues>,
) {
  remove_inbound_forwarded_headers(headers);
  let forwarded_ip = forwarded_client_addr.ip();
  match mode {
    ForwardedHeaderMode::Overwrite => {
      let value = cache
        .map(|cache| cache.x_forwarded_for.clone())
        .unwrap_or_else(|| ip_header_value(forwarded_ip));
      headers.insert(X_FORWARDED_FOR, value);
    }
    ForwardedHeaderMode::Append => {
      let forwarded_for = forwarded_ip.to_string();
      append_csv_header(headers, X_FORWARDED_FOR, &forwarded_for);
    }
  }

  let proto = cache
    .map(|cache| cache.x_forwarded_proto.clone())
    .unwrap_or_else(|| forwarded_proto_header_value(scheme));
  headers.insert(X_FORWARDED_PROTO, proto);

  if let Some(value) = values
    .and_then(ForwardedRequestHeaderValues::host)
    .cloned()
    .or_else(|| effective_host_header_value(host))
  {
    headers.insert(X_FORWARDED_HOST, value);
  } else {
    headers.remove(X_FORWARDED_HOST);
  }

  let port = values
    .map(|values| values.port().clone())
    .unwrap_or_else(|| port_header_value(port));
  headers.insert(X_FORWARDED_PORT, port);
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
  let raw = raw.trim();
  if !authority_may_have_explicit_port(raw) {
    return None;
  }
  Authority::from_str(raw)
    .ok()
    .and_then(|authority| authority.port_u16())
}

fn authority_may_have_explicit_port(raw: &str) -> bool {
  if raw.starts_with('[') {
    return raw
      .find(']')
      .and_then(|end| raw.as_bytes().get(end + 1))
      .is_some_and(|byte| *byte == b':');
  }

  raw.rsplit_once(':').is_some_and(|(host, port)| {
    !host.contains(':') && !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
  })
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

fn remove_inbound_forwarded_headers(headers: &mut HeaderMap) {
  headers.remove(FORWARDED);
}

fn effective_host_header_value(host: &str) -> Option<HeaderValue> {
  if host.is_empty() {
    return None;
  }
  HeaderValue::from_str(host).ok()
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

fn append_csv_header(headers: &mut HeaderMap, header_name: HeaderName, value: &str) {
  let header_value = match headers
    .get(&header_name)
    .and_then(|item| item.to_str().ok())
  {
    Some(existing) if !existing.is_empty() => {
      HeaderValue::from_str(&format!("{existing}, {value}"))
    }
    _ => HeaderValue::from_str(value),
  };

  if let Ok(header_value) = header_value {
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
      headers.remove(CLOSE_HEADER);
    }
    if remove_te_header {
      headers.remove(TE);
    }
  }

  headers.remove(CONNECTION);
  headers.remove(KEEP_ALIVE_HEADER);
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
  headers.keys().any(is_hop_by_hop_header_name)
}

fn is_hop_by_hop_header_name(name: &HeaderName) -> bool {
  name == CONNECTION
    || name == KEEP_ALIVE_HEADER
    || name == PROXY_AUTHENTICATE
    || name == PROXY_AUTHORIZATION
    || name == TRAILER
    || name == TRANSFER_ENCODING
    || name == UPGRADE
    || name == TE
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
      None,
    );

    assert!(!headers.contains_key(FORWARDED));
    assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
    assert_eq!(headers["x-forwarded-host"], "example.test");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-port"], "443");
  }

  #[test]
  fn forwarded_header_cache_reuses_xff_and_proto_only() {
    let peer_addr = "203.0.113.10:5443".parse().unwrap();
    let cache = build_forwarded_header_cache(
      peer_addr,
      "https",
      &ForwardedHeadersConfig::default(),
      &RealIpConfig::default(),
    )
    .expect("default overwrite headers without real IP can be cached");

    let mut headers = HeaderMap::new();
    add_forwarded_headers(
      &mut headers,
      peer_addr,
      "example.test",
      "https",
      443,
      ForwardedHeaderMode::Overwrite,
      Some(&cache),
    );
    assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-host"], "example.test");
    assert_eq!(headers["x-forwarded-port"], "443");

    add_forwarded_headers(
      &mut headers,
      peer_addr,
      "other.test",
      "https",
      8443,
      ForwardedHeaderMode::Overwrite,
      Some(&cache),
    );
    assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-host"], "other.test");
    assert_eq!(headers["x-forwarded-port"], "8443");
  }

  #[test]
  fn forwarded_header_cache_is_disabled_when_forwarded_client_can_vary() {
    let peer_addr = "203.0.113.10:5443".parse().unwrap();
    let append = ForwardedHeadersConfig {
      mode: ForwardedHeaderMode::Append,
      ..ForwardedHeadersConfig::default()
    };
    assert!(
      build_forwarded_header_cache(peer_addr, "https", &append, &RealIpConfig::default()).is_none()
    );

    let real_ip = RealIpConfig {
      enabled: true,
      ..RealIpConfig::default()
    };
    assert!(
      build_forwarded_header_cache(
        peer_addr,
        "https",
        &ForwardedHeadersConfig::default(),
        &real_ip
      )
      .is_none()
    );

    let direct_peer = ForwardedHeadersConfig {
      client_ip_source: ForwardedClientIpSource::DirectPeer,
      ..ForwardedHeadersConfig::default()
    };
    assert!(build_forwarded_header_cache(peer_addr, "https", &direct_peer, &real_ip).is_some());
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
      None,
    );

    assert!(!headers.contains_key(FORWARDED));
    assert_eq!(headers["x-forwarded-for"], "198.51.100.1, 203.0.113.10");
    assert_eq!(headers["x-forwarded-host"], "example.test");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-port"], "8443");
  }

  #[test]
  fn forwarded_headers_drop_inbound_host_when_effective_host_is_invalid() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-host", HeaderValue::from_static("evil.test"));

    add_forwarded_headers(
      &mut headers,
      "203.0.113.10:5443".parse().unwrap(),
      "bad\nhost",
      "https",
      443,
      ForwardedHeaderMode::Overwrite,
      None,
    );

    assert!(!headers.contains_key("x-forwarded-host"));
    assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-port"], "443");
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
      None,
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
