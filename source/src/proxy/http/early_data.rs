//! Verified TLS early-data policy and upstream header handling.

use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};

use crate::config::{Config, RouteConfig, TlsEarlyDataMode};

use super::body::ProxyBody;
use super::response::text_response;

const EARLY_DATA_HEADER: &str = "early-data";

#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifiedEarlyData;

pub(crate) fn mark_verified<B>(request: &mut Request<B>) {
  request.extensions_mut().insert(VerifiedEarlyData);
}

pub(crate) fn is_verified<B>(request: &Request<B>) -> bool {
  request.extensions().get::<VerifiedEarlyData>().is_some()
}

pub(crate) fn strip_untrusted_header(headers: &mut HeaderMap) {
  headers.remove(EARLY_DATA_HEADER);
}

pub(crate) fn apply_verified_upstream_header(headers: &mut HeaderMap, verified: bool) {
  headers.remove(EARLY_DATA_HEADER);
  if verified {
    headers.insert(EARLY_DATA_HEADER, HeaderValue::from_static("1"));
  }
}

pub(crate) fn reject_if_disallowed<B>(
  request: &Request<B>,
  config: &Config,
  route: &RouteConfig,
) -> Option<Response<ProxyBody>> {
  if !is_verified(request) {
    return None;
  }
  let mode = effective_mode(config, route, request.version());
  if mode.permits_method(request.method()) {
    return None;
  }
  Some(text_response(StatusCode::TOO_EARLY, "too early"))
}

fn effective_mode(config: &Config, route: &RouteConfig, version: Version) -> TlsEarlyDataMode {
  if version == Version::HTTP_3 {
    config
      .tls
      .effective_http3_early_data_mode(&route.tls, config.quic.zero_rtt)
  } else {
    config.tls.effective_tcp_early_data_mode(&route.tls)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::Method;

  #[test]
  fn safe_methods_permit_only_get_and_head() {
    assert!(TlsEarlyDataMode::SafeMethods.permits_method(&Method::GET));
    assert!(TlsEarlyDataMode::SafeMethods.permits_method(&Method::HEAD));
    assert!(!TlsEarlyDataMode::SafeMethods.permits_method(&Method::POST));
    assert!(!TlsEarlyDataMode::Off.permits_method(&Method::GET));
    assert!(TlsEarlyDataMode::On.permits_method(&Method::POST));
  }

  #[test]
  fn verified_upstream_header_replaces_untrusted_values() {
    let mut headers = HeaderMap::new();
    headers.insert(EARLY_DATA_HEADER, HeaderValue::from_static("spoofed"));

    apply_verified_upstream_header(&mut headers, false);
    assert!(!headers.contains_key(EARLY_DATA_HEADER));

    headers.insert(EARLY_DATA_HEADER, HeaderValue::from_static("spoofed"));
    apply_verified_upstream_header(&mut headers, true);
    assert_eq!(
      headers
        .get(EARLY_DATA_HEADER)
        .and_then(|value| value.to_str().ok()),
      Some("1")
    );
  }
}
