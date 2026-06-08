//! Shared header mutation policy for route-level actions.
//! Request-side route actions cannot override proxy-owned identity metadata.

use http::HeaderName;

#[doc(hidden)]
pub fn normalize_route_action_header_name(name: &str) -> anyhow::Result<String> {
  Ok(
    HeaderName::from_bytes(name.as_bytes())?
      .as_str()
      .to_ascii_lowercase(),
  )
}

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

pub(crate) fn is_forbidden_route_action_header(name: &str) -> bool {
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
