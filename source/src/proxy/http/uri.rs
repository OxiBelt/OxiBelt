//! URI validation and upstream rewrite helpers.
//! Downstream targets are untrusted and must be normalized before route or upstream use.

use std::str::FromStr;

use http::Uri;
use http::uri::{Authority, PathAndQuery, Scheme};
use url::{Position, Url};

const MAX_PERCENT_DECODE_DEPTH: usize = 8;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct UpstreamUriParts {
  scheme: Scheme,
  authority: Authority,
  base_path: String,
  base_path_is_root: bool,
}

impl UpstreamUriParts {
  pub(crate) fn from_url(origin: &Url) -> anyhow::Result<Self> {
    let authority = &origin[Position::BeforeUsername..Position::AfterPort];
    if authority.is_empty() {
      anyhow::bail!("upstream origin is missing an authority: {origin}");
    }
    let base_path = origin.path().to_string();

    Ok(Self {
      scheme: Scheme::from_str(origin.scheme())
        .map_err(|error| anyhow::anyhow!("upstream origin has invalid scheme: {error}"))?,
      authority: Authority::from_str(authority)
        .map_err(|error| anyhow::anyhow!("upstream origin has invalid authority: {error}"))?,
      base_path_is_root: base_path.is_empty() || base_path == "/",
      base_path,
    })
  }

  pub(crate) fn base_path(&self) -> &str {
    &self.base_path
  }
}

pub(crate) fn validate_downstream_path(path: &str) -> anyhow::Result<()> {
  if path
    .bytes()
    .any(|byte| byte.is_ascii_control() || byte == b'\\')
  {
    anyhow::bail!("request path contains unsafe characters");
  }

  for segment in path.split('/') {
    if matches!(segment, "." | "..") {
      anyhow::bail!("request path contains dot segments");
    }
  }

  if contains_unsafe_or_over_nested_encoding(path.as_bytes()) {
    anyhow::bail!("request path contains unsafe or overly nested encoding");
  }

  Ok(())
}

fn contains_unsafe_or_over_nested_encoding(path: &[u8]) -> bool {
  // Inspect every layer through the fixed decoding bound. OxiBelt and an
  // upstream must not disagree merely because an unsafe separator was hidden
  // behind an encoded percent sign (for example `%252e` or `%25252f`). Reject
  // inputs that still decode after the bound instead of forwarding a layer we
  // did not inspect. The bound keeps validation work linear while covering
  // deeper nesting than any OxiBelt normalization stage performs.
  let mut decoded = path.to_vec();
  for depth in 0..=MAX_PERCENT_DECODE_DEPTH {
    for index in memchr::memchr_iter(b'%', &decoded) {
      let Some(encoded) = decoded.get(index + 1..index + 3) else {
        continue;
      };
      if (encoded[0] == b'2'
        && (encoded[1].eq_ignore_ascii_case(&b'e') || encoded[1].eq_ignore_ascii_case(&b'f')))
        || (encoded[0] == b'5' && encoded[1].eq_ignore_ascii_case(&b'c'))
      {
        return true;
      }
    }
    let Some(next) = percent_decode_path_once(&decoded) else {
      break;
    };
    if depth == MAX_PERCENT_DECODE_DEPTH {
      return true;
    }
    if next
      .iter()
      .any(|byte| *byte == b'\\' || *byte < 0x20 || *byte == 0x7f)
      || next
        .split(|byte| *byte == b'/')
        .any(|segment| matches!(segment, b"." | b".."))
    {
      return true;
    }
    decoded = next;
  }
  false
}

fn percent_decode_path_once(path: &[u8]) -> Option<Vec<u8>> {
  let first_percent = memchr::memchr(b'%', path)?;
  let mut decoded = Vec::with_capacity(path.len());
  let mut changed = false;
  decoded.extend_from_slice(&path[..first_percent]);
  let mut copy_start = first_percent;
  let mut search_start = first_percent;
  while let Some(relative) = memchr::memchr(b'%', &path[search_start..]) {
    let index = search_start + relative;
    decoded.extend_from_slice(&path[copy_start..index]);
    if index + 5 < path.len()
      && matches!(path[index + 1], b'u' | b'U')
      && let Some(codepoint) = hex_u16(&path[index + 2..index + 6])
      && codepoint <= 0x7f
    {
      decoded.push(codepoint as u8);
      changed = true;
      search_start = index + 6;
      copy_start = search_start;
    } else if index + 2 < path.len()
      && let (Some(high), Some(low)) = (hex_nibble(path[index + 1]), hex_nibble(path[index + 2]))
    {
      decoded.push((high << 4) | low);
      changed = true;
      search_start = index + 3;
      copy_start = search_start;
    } else {
      decoded.push(b'%');
      search_start = index + 1;
      copy_start = search_start;
    }
  }
  decoded.extend_from_slice(&path[copy_start..]);
  changed.then_some(decoded)
}

fn hex_u16(bytes: &[u8]) -> Option<u16> {
  let mut value = 0u16;
  for byte in bytes {
    value = value.checked_mul(16)?;
    value = value.checked_add(u16::from(hex_nibble(*byte)?))?;
  }
  Some(value)
}

fn hex_nibble(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

pub(crate) fn rewrite_uri(
  origin: &UpstreamUriParts,
  route_prefix: &str,
  replace_prefix_with: Option<&str>,
  downstream_uri: &Uri,
) -> anyhow::Result<Uri> {
  build_uri(
    origin,
    rewrite_path_and_query(origin, route_prefix, replace_prefix_with, downstream_uri)?,
  )
}

pub(crate) fn rewrite_path_and_query(
  origin: &UpstreamUriParts,
  route_prefix: &str,
  replace_prefix_with: Option<&str>,
  downstream_uri: &Uri,
) -> anyhow::Result<PathAndQuery> {
  if replace_prefix_with.is_none() && origin.base_path_is_root {
    return Ok(
      downstream_uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/")),
    );
  }

  let incoming_path = downstream_uri.path();
  let rewritten_path = if let Some(replacement) = replace_prefix_with {
    let suffix = if route_prefix == "/" {
      incoming_path
    } else {
      incoming_path
        .strip_prefix(route_prefix)
        .unwrap_or(incoming_path)
    };
    join_paths(replacement, suffix)
  } else {
    incoming_path.to_string()
  };

  let upstream_path = join_paths(&origin.base_path, &rewritten_path);
  let path_and_query = match downstream_uri.query() {
    Some(query) => {
      let mut value = String::with_capacity(upstream_path.len() + 1 + query.len());
      value.push_str(&upstream_path);
      value.push('?');
      value.push_str(query);
      value
    }
    None => upstream_path,
  };

  PathAndQuery::from_str(path_and_query.as_str())
    .map_err(|error| anyhow::anyhow!("failed to build rewritten URI: {error}"))
}

pub(crate) fn build_uri(
  origin: &UpstreamUriParts,
  path_and_query: PathAndQuery,
) -> anyhow::Result<Uri> {
  let mut parts = http::uri::Parts::default();
  parts.scheme = Some(origin.scheme.clone());
  parts.authority = Some(origin.authority.clone());
  parts.path_and_query = Some(path_and_query);
  Uri::from_parts(parts).map_err(|error| anyhow::anyhow!("failed to build rewritten URI: {error}"))
}

pub(crate) fn join_paths(base: &str, suffix: &str) -> String {
  let normalized_base = if base.is_empty() { "/" } else { base };
  let left = normalized_base.trim_end_matches('/');
  let right = suffix.trim_start_matches('/');

  match (left.is_empty(), right.is_empty()) {
    (true, true) => "/".to_string(),
    (true, false) => {
      let mut path = String::with_capacity(right.len() + 1);
      path.push('/');
      path.push_str(right);
      path
    }
    (false, true) => left.to_string(),
    (false, false) => {
      let mut path = String::with_capacity(left.len() + 1 + right.len());
      path.push_str(left);
      path.push('/');
      path.push_str(right);
      path
    }
  }
}

#[cfg(test)]
mod tests {
  use pretty_assertions::assert_eq;
  use url::Url;

  use super::*;

  fn nest_percent_encoding(value: &str, depth: usize) -> String {
    (0..depth).fold(value.to_string(), |encoded, _| encoded.replace('%', "%25"))
  }

  #[test]
  fn join_paths_handles_slashes() {
    assert_eq!(join_paths("/", "/api"), "/api");
    assert_eq!(join_paths("/base", "/api"), "/base/api");
    assert_eq!(join_paths("/base/", "api"), "/base/api");
  }

  #[test]
  fn rewrite_uri_replaces_prefix() {
    let origin =
      UpstreamUriParts::from_url(&Url::parse("https://backend.internal/root").unwrap()).unwrap();
    let uri = "https://example.com/v1/users?id=1".parse().unwrap();

    let rewritten = rewrite_uri(&origin, "/v1", Some("/"), &uri).unwrap();
    assert_eq!(
      rewritten.to_string(),
      "https://backend.internal/root/users?id=1"
    );
  }

  #[test]
  fn rewrite_uri_preserves_query_without_url_clone() {
    let origin =
      UpstreamUriParts::from_url(&Url::parse("http://backend.internal/base").unwrap()).unwrap();
    let uri = "/api/search?q=rust&sort=desc".parse().unwrap();

    let rewritten = rewrite_uri(&origin, "/api", Some("/v2"), &uri).unwrap();
    assert_eq!(
      rewritten.to_string(),
      "http://backend.internal/base/v2/search?q=rust&sort=desc"
    );
  }

  #[test]
  fn rewrite_uri_uses_root_origin_fast_path_without_rewrite() {
    let origin =
      UpstreamUriParts::from_url(&Url::parse("http://backend.internal/").unwrap()).unwrap();
    let uri = "/perf/h1?body=ok".parse().unwrap();

    let rewritten = rewrite_uri(&origin, "/", None, &uri).unwrap();
    assert_eq!(
      rewritten.to_string(),
      "http://backend.internal/perf/h1?body=ok"
    );
  }

  #[test]
  fn rewrite_uri_root_fast_path_handles_absolute_form_request_targets() {
    let origin =
      UpstreamUriParts::from_url(&Url::parse("https://backend.internal/").unwrap()).unwrap();
    let uri = "http://public.example.com/perf/h1?body=ok".parse().unwrap();

    let rewritten = rewrite_uri(&origin, "/", None, &uri).unwrap();
    assert_eq!(
      rewritten.to_string(),
      "https://backend.internal/perf/h1?body=ok"
    );
  }

  #[test]
  fn rewrite_uri_handles_absolute_form_request_targets() {
    let origin =
      UpstreamUriParts::from_url(&Url::parse("https://backend.internal/root").unwrap()).unwrap();
    let uri = "http://public.example.com/api/users?active=true"
      .parse()
      .unwrap();

    let rewritten = rewrite_uri(&origin, "/api", Some("/internal"), &uri).unwrap();
    assert_eq!(
      rewritten.to_string(),
      "https://backend.internal/root/internal/users?active=true"
    );
  }

  #[test]
  fn validate_downstream_path_rejects_route_bypass_segments() {
    for path in [
      "/safe/../admin",
      "/safe/./admin",
      "/safe/%2e%2e/admin",
      "/safe/%2E/admin",
      "/safe/%2f/admin",
      "/safe/%5c/admin",
      "/safe/%252e%252e/admin",
      "/safe/%25252e%25252e/admin",
      "/safe/%25%32%65%25%32%65/admin",
      "/safe/%252fadmin",
      "/safe/%255cadmin",
      "/safe/%u002e%u002e/admin",
      "/safe/%U002E%U002E/admin",
      "/safe/%25u002e%25u002e/admin",
      "/safe/%u0025u002e%u0025u002e/admin",
      "/safe/%u002e%u002e%u002fadmin",
      "/safe/%u002e%u002e%u005cadmin",
      "/safe/%00/admin",
      "/safe/%2500/admin",
      "/safe/%u0000/admin",
      "/safe\\admin",
    ] {
      assert!(
        validate_downstream_path(path).is_err(),
        "expected {path} to be rejected"
      );
    }

    validate_downstream_path("/safe/admin").unwrap();
    validate_downstream_path("/safe/%20space").unwrap();
  }

  #[test]
  fn nested_percent_route_bypass_regressions_fail_closed() {
    let cases = include_str!(
      "../../../../tests/fixtures/fuzz-regressions/path_security_semantics/nested-percent-route-bypass.txt"
    );
    for path in cases
      .lines()
      .map(str::trim)
      .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
      assert!(
        validate_downstream_path(path).is_err(),
        "nested path case must be rejected: {path}"
      );
    }
  }

  #[test]
  fn percent_decode_depth_scans_every_allowed_layer() {
    for token in ["%2e%2e", "%2f", "%5c", "%00", "%u002e%u002e"] {
      for depth in 0..=MAX_PERCENT_DECODE_DEPTH {
        let path = format!("/safe/{}/admin", nest_percent_encoding(token, depth));
        assert!(
          validate_downstream_path(&path).is_err(),
          "unsafe token at decode depth {depth} must be rejected: {path}"
        );
      }
    }

    for token in ["%20", "%41", "%7e"] {
      for depth in 0..MAX_PERCENT_DECODE_DEPTH {
        let path = format!("/safe/{}/value", nest_percent_encoding(token, depth));
        assert!(
          validate_downstream_path(&path).is_ok(),
          "benign token at decode depth {depth} must remain accepted: {path}"
        );
      }
    }

    for depth in 0..=MAX_PERCENT_DECODE_DEPTH {
      let path = format!("/safe/{}/value", nest_percent_encoding("%zz", depth));
      assert!(
        validate_downstream_path(&path).is_ok(),
        "terminal malformed encoding at depth {depth} must remain accepted: {path}"
      );
    }

    for token in ["%20", "%41", "%7e"] {
      let path = format!(
        "/safe/{}/value",
        nest_percent_encoding(token, MAX_PERCENT_DECODE_DEPTH)
      );
      assert!(
        validate_downstream_path(&path).is_err(),
        "encoding beyond the decode bound must fail closed: {path}"
      );
    }

    let malformed_over_depth = format!(
      "/safe/{}/value",
      nest_percent_encoding("%zz", MAX_PERCENT_DECODE_DEPTH + 1)
    );
    assert!(
      validate_downstream_path(&malformed_over_depth).is_err(),
      "over-depth malformed encoding must fail closed: {malformed_over_depth}"
    );
  }
}
