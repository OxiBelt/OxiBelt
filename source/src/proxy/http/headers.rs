use std::str::FromStr;

use http::Request;
use http::header::{
  CONNECTION, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION,
  TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use hyper::body::Incoming;

use crate::routes::normalize_host;

pub(super) fn extract_host(request: &Request<Incoming>) -> Option<String> {
  if let Some(authority) = request.uri().authority() {
    return Some(normalize_host(authority.as_str()));
  }

  request
    .headers()
    .get(HOST)
    .and_then(|value| value.to_str().ok())
    .map(normalize_host)
}

pub(super) fn add_forwarded_headers(
  headers: &mut HeaderMap,
  peer_addr: std::net::SocketAddr,
  host: &str,
) {
  append_csv_header(headers, "x-forwarded-for", &peer_addr.ip().to_string());
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

pub(super) fn strip_hop_by_hop_headers(headers: &mut HeaderMap) {
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

pub(super) fn is_upgrade_request(request: &Request<Incoming>) -> bool {
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
