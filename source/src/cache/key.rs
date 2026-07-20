//! Pure cache-key expansion, partitioning, and variant identity.

use super::*;

pub(super) fn expanded_cache_key(
  template: &str,
  scheme: &str,
  host: &str,
  uri: &Uri,
  headers: &HeaderMap,
) -> String {
  let mut key = template
    .replace("{scheme}", scheme)
    .replace("{host}", host)
    .replace("{uri}", &uri.to_string())
    .replace("{path}", uri.path())
    .replace("{query}", uri.query().unwrap_or_default());
  key = replace_dynamic_tokens(&key, "query", |name| query_value(uri, name));
  key = replace_dynamic_tokens(&key, "header", |name| {
    header_values(headers, &name.to_ascii_lowercase())
  });
  replace_dynamic_tokens(&key, "cookie", |name| cookie_value(headers, name))
}

pub(super) fn replace_dynamic_tokens<F>(input: &str, kind: &str, mut value: F) -> String
where
  F: FnMut(&str) -> String,
{
  let prefix = format!("{{{kind}:");
  let mut output = String::with_capacity(input.len());
  let mut rest = input;
  while let Some(start) = rest.find(&prefix) {
    output.push_str(&rest[..start]);
    let token_rest = &rest[start + prefix.len()..];
    let Some(end) = token_rest.find('}') else {
      output.push_str(&rest[start..]);
      return output;
    };
    let name = &token_rest[..end];
    output.push_str(&value(name));
    rest = &token_rest[end + 1..];
  }
  output.push_str(rest);
  output
}

pub(super) fn query_value(uri: &Uri, name: &str) -> String {
  uri
    .query()
    .and_then(|query| {
      url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
    })
    .unwrap_or_default()
}

pub(super) fn cookie_value(headers: &HeaderMap, name: &str) -> String {
  headers
    .get(http::header::COOKIE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| {
      value
        .split(';')
        .map(str::trim)
        .filter_map(|item| item.split_once('='))
        .find(|(cookie_name, _)| *cookie_name == name)
        .map(|(_, value)| value.to_string())
    })
    .unwrap_or_default()
}

pub(super) fn variant_key(partition: &str, base_key: &str, vary: &[VaryMatcher]) -> String {
  let mut key = String::new();
  key.push_str("partition=");
  key.push_str(partition);
  key.push('\n');
  key.push_str(base_key);
  for item in vary {
    key.push('\n');
    key.push_str(&item.name);
    key.push('=');
    key.push_str(&item.value);
  }
  key
}
