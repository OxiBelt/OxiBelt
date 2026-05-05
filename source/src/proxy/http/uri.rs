use http::Uri;
use url::Url;

pub(crate) fn rewrite_uri(
  origin: &Url,
  route_prefix: &str,
  replace_prefix_with: Option<&str>,
  downstream_uri: &Uri,
) -> anyhow::Result<Uri> {
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

  let upstream_path = join_paths(origin.path(), &rewritten_path);

  let mut rewritten = origin.clone();
  rewritten.set_path(&upstream_path);
  rewritten.set_query(downstream_uri.query());
  rewritten
    .as_str()
    .parse()
    .map_err(|error| anyhow::anyhow!("failed to parse rewritten URI {}: {error}", rewritten))
}

fn join_paths(base: &str, suffix: &str) -> String {
  let normalized_base = if base.is_empty() { "/" } else { base };
  let left = normalized_base.trim_end_matches('/');
  let right = suffix.trim_start_matches('/');

  match (left.is_empty(), right.is_empty()) {
    (true, true) => "/".to_string(),
    (true, false) => format!("/{right}"),
    (false, true) => left.to_string(),
    (false, false) => format!("{left}/{right}"),
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
    let origin = Url::parse("https://backend.internal/root").unwrap();
    let uri = "https://example.com/v1/users?id=1".parse().unwrap();

    let rewritten = rewrite_uri(&origin, "/v1", Some("/"), &uri).unwrap();
    assert_eq!(
      rewritten.to_string(),
      "https://backend.internal/root/users?id=1"
    );
  }
}
