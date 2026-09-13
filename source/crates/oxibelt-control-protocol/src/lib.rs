//! Small, listener-independent policies shared by control-plane executables.

#![forbid(unsafe_code)]

use http::HeaderName;
use std::cmp::Ordering;
use std::sync::Arc;

/// Precomputed header names compared using CGI/WSGI-style hyphen/underscore
/// equivalence. Construction is configuration-time; lookups do not allocate.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[doc(hidden)]
pub struct HyphenUnderscoreHeaderNameSet {
  canonical_names: Arc<[Box<str>]>,
}

impl HyphenUnderscoreHeaderNameSet {
  #[doc(hidden)]
  pub fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
    let mut canonical_names = names
      .into_iter()
      .map(canonicalize_hyphen_underscore_header_name)
      .map(String::into_boxed_str)
      .collect::<Vec<_>>();
    canonical_names.sort_unstable();
    canonical_names.dedup();
    Self {
      canonical_names: canonical_names.into(),
    }
  }

  #[doc(hidden)]
  pub fn contains(&self, name: &str) -> bool {
    self
      .canonical_names
      .binary_search_by(|canonical| compare_canonical_header_name(canonical.as_bytes(), name))
      .is_ok()
  }

  #[doc(hidden)]
  pub fn is_empty(&self) -> bool {
    self.canonical_names.is_empty()
  }
}

/// Compare two header names using ASCII case-insensitive hyphen/underscore
/// equivalence without allocating.
#[doc(hidden)]
pub fn hyphen_underscore_header_names_equivalent(left: &str, right: &str) -> bool {
  left.len() == right.len()
    && left
      .bytes()
      .zip(right.bytes())
      .all(|(left, right)| canonical_header_name_byte(left) == canonical_header_name_byte(right))
}

fn canonicalize_hyphen_underscore_header_name(name: &str) -> String {
  name
    .bytes()
    .map(canonical_header_name_byte)
    .map(char::from)
    .collect()
}

fn canonical_header_name_byte(byte: u8) -> u8 {
  match byte {
    b'_' => b'-',
    _ => byte.to_ascii_lowercase(),
  }
}

fn compare_canonical_header_name(canonical: &[u8], candidate: &str) -> Ordering {
  canonical
    .iter()
    .copied()
    .cmp(candidate.bytes().map(canonical_header_name_byte))
}

fn has_hyphen_underscore_header_prefix(name: &str, prefix: &str) -> bool {
  name.len() >= prefix.len()
    && name
      .bytes()
      .zip(prefix.bytes())
      .take(prefix.len())
      .all(|(name, prefix)| canonical_header_name_byte(name) == prefix)
}

/// Parse and normalize a route-action header name.
#[doc(hidden)]
pub fn normalize_route_action_header_name(name: &str) -> anyhow::Result<String> {
  Ok(
    HeaderName::from_bytes(name.as_bytes())?
      .as_str()
      .to_ascii_lowercase(),
  )
}

/// Return whether request-side route actions must not replace this header.
#[doc(hidden)]
pub fn is_reserved_route_request_header(name: &str) -> bool {
  is_forbidden_route_action_header(name)
    || matches!(
      name,
      "host"
        | "forwarded"
        | "x-forwarded-for"
        | "x-forwarded-host"
        | "x-forwarded-proto"
        | "x-forwarded-port"
        | "x-real-ip"
        | "cf-connecting-ip"
    )
}

/// Reject certificate targets that would replace credentials or proxy-owned
/// transport, replay, compression, or tracing semantics. Input is normalized.
#[doc(hidden)]
pub fn is_reserved_client_certificate_forwarding_header(name: &str) -> bool {
  const RESERVED: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "cf-connecting-ip",
    "authorization",
    "cookie",
    "set-cookie",
    "www-authenticate",
    "accept-encoding",
    "early-data",
    "traceparent",
    "tracestate",
    "priority",
    "cache-control",
    "pragma",
    "accept",
    "accept-language",
    "content-type",
    "content-encoding",
    "content-range",
    "expect",
    "range",
    "if-range",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
    "origin",
    "referer",
    "x-grpc-web",
  ];
  RESERVED
    .iter()
    .any(|reserved| hyphen_underscore_header_names_equivalent(name, reserved))
    || has_hyphen_underscore_header_prefix(name, "grpc-")
    || has_hyphen_underscore_header_prefix(name, "sec-websocket-")
}

/// Return whether a hop-by-hop or framing header must not be mutated.
#[doc(hidden)]
pub fn is_forbidden_route_action_header(name: &str) -> bool {
  matches!(
    name,
    "connection"
      | "content-length"
      | "keep-alive"
      | "proxy-authenticate"
      | "proxy-authorization"
      | "te"
      | "trailer"
      | "transfer-encoding"
      | "upgrade"
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn certificate_targets_cannot_replace_existing_http_controls() {
    for name in [
      "accept-encoding",
      "early-data",
      "traceparent",
      "tracestate",
      "priority",
      "cache-control",
      "pragma",
      "content-type",
      "content-encoding",
      "expect",
      "range",
      "if-none-match",
      "origin",
      "grpc-timeout",
      "sec-websocket-key",
      "x_forwarded_for",
      "content_length",
      "grpc_timeout",
      "sec_websocket_key",
      "x_grpc_web",
    ] {
      assert!(
        is_reserved_client_certificate_forwarding_header(name),
        "{name}"
      );
    }
    assert!(!is_reserved_client_certificate_forwarding_header(
      "x-client-cert"
    ));
    assert!(!is_reserved_client_certificate_forwarding_header(
      "client-cert"
    ));
  }

  #[test]
  fn certificate_header_alias_set_folds_only_case_hyphens_and_underscores() {
    let names = HyphenUnderscoreHeaderNameSet::new([
      "X-Verified_Client-Cert",
      "client-cert",
      "x_verified-client_cert",
    ]);

    for alias in [
      "x-verified-client-cert",
      "X_VERIFIED_CLIENT_CERT",
      "x_verified-client-cert",
    ] {
      assert!(names.contains(alias), "{alias}");
    }
    assert!(names.contains("CLIENT_CERT"));
    assert!(!names.contains("x.verified.client.cert"));
    assert!(!names.contains("x-verified-client-certificate"));
    assert!(!names.is_empty());
    assert_eq!(names.canonical_names.len(), 2);
  }

  #[test]
  fn certificate_header_alias_comparison_handles_long_mixed_names() {
    let name = format!("x{}cert", "-_".repeat(256));
    let alias = format!("X{}CERT", "_-".repeat(256));
    let names = HyphenUnderscoreHeaderNameSet::new([name.as_str()]);

    assert!(names.contains(&alias));
    assert!(hyphen_underscore_header_names_equivalent(&name, &alias));
  }

  #[test]
  fn normalizes_header_names_before_policy_checks() {
    assert_eq!(
      normalize_route_action_header_name("X-Forwarded-For").expect("valid header"),
      "x-forwarded-for"
    );
    assert!(is_reserved_route_request_header("x-forwarded-for"));
    assert!(is_forbidden_route_action_header("content-length"));
  }
}
