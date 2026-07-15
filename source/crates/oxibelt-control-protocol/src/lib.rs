//! Small, listener-independent policies shared by control-plane executables.

#![forbid(unsafe_code)]

use http::HeaderName;

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
  fn normalizes_header_names_before_policy_checks() {
    assert_eq!(
      normalize_route_action_header_name("X-Forwarded-For").expect("valid header"),
      "x-forwarded-for"
    );
    assert!(is_reserved_route_request_header("x-forwarded-for"));
    assert!(is_forbidden_route_action_header("content-length"));
  }
}
