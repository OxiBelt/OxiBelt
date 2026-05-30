use std::str::FromStr;

use http::Uri;
use http::uri::{Authority, PathAndQuery, Scheme};
use url::{Position, Url};

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

  if contains_encoded_dot_or_separator(path.as_bytes()) {
    anyhow::bail!("request path contains encoded dot or slash separators");
  }

  Ok(())
}

fn contains_encoded_dot_or_separator(path: &[u8]) -> bool {
  path.windows(3).any(|window| {
    window[0] == b'%'
      && ((window[1] == b'2'
        && (window[2].eq_ignore_ascii_case(&b'e') || window[2].eq_ignore_ascii_case(&b'f')))
        || (window[1] == b'5' && window[2].eq_ignore_ascii_case(&b'c')))
  })
}

pub(crate) fn rewrite_uri(
  origin: &UpstreamUriParts,
  route_prefix: &str,
  replace_prefix_with: Option<&str>,
  downstream_uri: &Uri,
) -> anyhow::Result<Uri> {
  if replace_prefix_with.is_none() && origin.base_path_is_root {
    let path_and_query = downstream_uri
      .path_and_query()
      .cloned()
      .unwrap_or_else(|| PathAndQuery::from_static("/"));
    return build_uri(origin, path_and_query);
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

  let path_and_query = PathAndQuery::from_str(path_and_query.as_str())
    .map_err(|error| anyhow::anyhow!("failed to build rewritten URI: {error}"))?;
  build_uri(origin, path_and_query)
}

fn build_uri(origin: &UpstreamUriParts, path_and_query: PathAndQuery) -> anyhow::Result<Uri> {
  let mut parts = http::uri::Parts::default();
  parts.scheme = Some(origin.scheme.clone());
  parts.authority = Some(origin.authority.clone());
  parts.path_and_query = Some(path_and_query);
  Uri::from_parts(parts).map_err(|error| anyhow::anyhow!("failed to build rewritten URI: {error}"))
}

fn join_paths(base: &str, suffix: &str) -> String {
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
}
