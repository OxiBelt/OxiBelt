//! Narrow, side-effect-free adapters for security-property fuzz targets.

use std::path::Path;

use http::Uri;
use url::Url;

use crate::proxy::http::static_files::resolve_request_path;
use crate::proxy::http::uri::{
  UpstreamUriParts, rewrite_path_and_query, rewrite_uri, validate_downstream_path,
};

const MAX_PATH_BYTES: usize = 1024;
const MAX_WAF_BODY_BYTES: usize = 8 * 1024;
const STATIC_ROOT: &str = "/oxibelt-fuzz-static-root";

/// Exercises path validation, route matching, static lexical resolution, WAF
/// normalization, and upstream rewriting without accessing the filesystem.
pub fn exercise_path_security_semantics(
  raw_path: &str,
  query: &str,
  route_prefix: &str,
  replacement_prefix: Option<&str>,
  absolute_form: bool,
) {
  let raw_path = bounded_text(raw_path, MAX_PATH_BYTES);
  let query = bounded_text(query, MAX_PATH_BYTES);
  let target = request_target(raw_path, query, absolute_form);
  let Ok(uri) = target.parse::<Uri>() else {
    return;
  };
  let path = uri.path();
  let validated = validate_downstream_path(path);
  let static_resolution = resolve_request_path(Path::new(STATIC_ROOT), route_prefix, path);
  let normalized = crate::waf::fuzz_normalize_path(path);
  let nested_normalized = crate::waf::fuzz_normalize_path(&normalized);
  let route_matches_raw = crate::routes::path_prefix_matches(route_prefix, path);
  let route_matches_normalized = crate::routes::path_prefix_matches(route_prefix, &normalized);
  let route_matches_nested = crate::routes::path_prefix_matches(route_prefix, &nested_normalized);

  // The resolver is deliberately lexical. Its accepted path must remain
  // beneath its supplied root regardless of later normalization decisions.
  if let Ok(candidate) = &static_resolution {
    assert!(
      candidate.starts_with(Path::new(STATIC_ROOT)),
      "static lexical resolution escaped its configured root"
    );
    assert!(
      !has_parent_segment(&candidate.to_string_lossy()),
      "static lexical resolution retained a parent traversal segment"
    );
  }

  // This intentionally does not assert normalization idempotence: nested
  // percent encodings may change on a second established single-pass pass.
  if validated.is_ok() {
    assert!(
      !has_parent_segment(&normalized),
      "accepted downstream path normalized into a parent traversal"
    );
  }
  if has_parent_segment(&nested_normalized)
    && let Ok(candidate) = &static_resolution
  {
    assert!(
      candidate.starts_with(Path::new(STATIC_ROOT)),
      "nested decoding changed the already-resolved static confinement decision"
    );
  }
  // Raw routing and the WAF-normalized request view intentionally have
  // different semantics. Only a second normalization pass may not move the
  // already-normalized request across a protected prefix.
  if route_matches_normalized != route_matches_nested
    && path.bytes().any(|byte| matches!(byte, b'.' | b'%' | b'\\'))
  {
    assert!(
      validated.is_err(),
      "nested path interpretation crossed a protected route prefix"
    );
  }

  let Ok(origin) = Url::parse("https://upstream.example.test/base") else {
    panic!("fixed fuzz upstream URL should parse");
  };
  let Ok(origin) = UpstreamUriParts::from_url(&origin) else {
    panic!("fixed fuzz upstream should be valid");
  };
  let rewritten = rewrite_uri(&origin, route_prefix, replacement_prefix, &uri);
  if validated.is_ok()
    && let Ok(rewritten) = rewritten
  {
    let rewritten_path = rewritten.path();
    assert!(
      !has_parent_segment(rewritten_path),
      "trusted rewrite configuration introduced a parent traversal"
    );
    let Ok(path_and_query) =
      rewrite_path_and_query(&origin, route_prefix, replacement_prefix, &uri)
    else {
      panic!("rewrite_uri and rewrite_path_and_query must agree");
    };
    assert_eq!(
      rewritten.path_and_query(),
      Some(&path_and_query),
      "URI rewrite was not deterministic"
    );
  }

  // Equivalent origin- and absolute-form targets share the path decisions
  // that are defined for both forms.
  if absolute_form {
    let origin_target = request_target(path, uri.query().unwrap_or_default(), false);
    if let Ok(origin_uri) = origin_target.parse::<Uri>() {
      assert_eq!(
        validate_downstream_path(origin_uri.path()).is_ok(),
        validated.is_ok(),
        "equivalent origin and absolute forms disagreed on path validation"
      );
      assert_eq!(
        crate::routes::path_prefix_matches(route_prefix, origin_uri.path()),
        route_matches_raw,
        "equivalent origin and absolute forms disagreed on route prefix matching"
      );
    }
  }

  assert_eq!(
    route_matches_normalized,
    crate::routes::path_prefix_matches(route_prefix, &normalized),
    "normalized route decision was nondeterministic"
  );
}

/// Exercises a fixed in-memory WAF ruleset through the production evaluator.
pub fn exercise_waf_request_evaluation(
  path: &str,
  body: &[u8],
  header_value: &str,
  transform: u8,
  protocol: u8,
  body_coding: u8,
) {
  crate::waf::fuzz_evaluate_security_request(
    bounded_text(path, MAX_PATH_BYTES),
    &body[..body.len().min(MAX_WAF_BODY_BYTES)],
    bounded_text(header_value, MAX_PATH_BYTES),
    transform,
    protocol,
    body_coding,
  );
}

/// Exercises bearer parsing, identity stripping/reinsertion, terminal auth
/// decisions, and sensitive trailer filtering without an auth network client.
pub fn exercise_auth_request_semantics(
  authorization: &str,
  duplicate_authorization: &str,
  identity: &str,
  trailer_authorization: &str,
  outcome: u8,
  fail_open: bool,
  route_path: &str,
) {
  crate::external_auth::fuzz_auth_request_semantics(
    bounded_text(authorization, 512),
    bounded_text(duplicate_authorization, 512),
    bounded_text(identity, 512),
    bounded_text(trailer_authorization, 512),
    outcome,
    fail_open,
    bounded_text(route_path, MAX_PATH_BYTES),
  );
}

fn bounded_text(value: &str, max: usize) -> &str {
  if value.len() <= max {
    return value;
  }
  let mut end = max;
  while !value.is_char_boundary(end) {
    end -= 1;
  }
  &value[..end]
}

fn request_target(path: &str, query: &str, absolute_form: bool) -> String {
  let path = if path.starts_with('/') { path } else { "/" };
  let target = if query.is_empty() {
    path.to_string()
  } else {
    format!("{path}?{query}")
  };
  if absolute_form {
    format!("https://public.example.test{target}")
  } else {
    target
  }
}

fn has_parent_segment(path: &str) -> bool {
  path.split('/').any(|segment| segment == "..")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn path_oracle_keeps_raw_and_waf_normalized_views_distinct() {
    let path = "//safe/252e%969g7_jcret";
    let normalized = crate::waf::fuzz_normalize_path(path);

    assert!(!crate::routes::path_prefix_matches("/safe", path));
    assert!(crate::routes::path_prefix_matches("/safe", &normalized));

    exercise_path_security_semantics(path, "q=xxxxxxxxxxxxxxxxxxxxxd", "/safe", None, false);
  }
}
