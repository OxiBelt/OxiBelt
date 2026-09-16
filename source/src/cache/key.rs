//! Pure cache-key expansion, partitioning, and variant identity.

use super::*;

const CACHE_CERTIFICATE_DOMAIN: &str = "\0oxibelt-cache-certificate-v1\0";
const CACHE_PLAIN_KEY_ESCAPE_DOMAIN: &str = "\0oxibelt-cache-plain-key-v1\0";
pub(super) const CACHE_QUERY_DOMAIN: &str = "\0oxibelt-cache-query-v1\0";
pub(crate) const GROUP_EXTERNAL_CACHE_KEY_VERSION: &str = "oxibelt-cache-groups-key-v1";
pub(crate) const GROUP_QUERY_EXTERNAL_CACHE_KEY_VERSION: &str = "oxibelt-cache-groups-query-key-v1";
const GROUP_QUERY_DOMAIN: &str = "\0oxibelt-cache-groups-query-v1\0";
pub(crate) const QUERY_EXTERNAL_CACHE_KEY_VERSION: &str = "oxibelt-cache-query-key-v1";

/// Produces the physical base-key namespace while preserving user-visible
/// logical cache-key semantics.
///
/// Ordinary keys remain byte-for-byte unchanged. Keys containing NUL are
/// length-prefixed in the plain-key domain first; certificate-aware keys are a
/// separate length-prefixed tuple. Therefore no user-configured expanded key
/// can collide with either internal certificate namespace.
pub(super) fn certificate_partitioned_base_key(
  base_key: String,
  certificate_identity: Option<&CacheCertificateIdentity>,
) -> String {
  let base_key = escape_plain_base_key(base_key);
  let Some(identity) = certificate_identity else {
    return base_key;
  };
  let fingerprint = identity.fingerprint_sha256().unwrap_or("absent");
  format!(
    "{CACHE_CERTIFICATE_DOMAIN}base:{}:{}header:{}:{}format:{}:{}identity:{}:{}",
    base_key.len(),
    base_key,
    identity.header_name().as_str().len(),
    identity.header_name().as_str(),
    identity.format().len(),
    identity.format(),
    fingerprint.len(),
    fingerprint,
  )
}

/// Applies the QUERY namespace after every existing identity partition.
/// Keeping this outermost makes Query entries distinguishable for targeted
/// invalidation even when certificate or PROXY-TLS partitioning is enabled.
pub(super) fn query_partitioned_base_key(
  base_key: String,
  identity: &CacheQueryIdentity,
) -> String {
  let domain = if base_key.starts_with("\0oxibelt-cache-groups-v1\0") {
    GROUP_QUERY_DOMAIN
  } else {
    CACHE_QUERY_DOMAIN
  };
  let mut material = Vec::with_capacity(base_key.len() + 512);
  material.extend_from_slice(domain.as_bytes());
  append_query_field(&mut material, base_key.as_bytes());
  identity.append_key_material(&mut material);
  let digest = crate::crypto::sha256(&material);
  let mut encoded = String::with_capacity(CACHE_QUERY_DOMAIN.len() + 64);
  encoded.push_str(domain);
  for byte in digest {
    use std::fmt::Write as _;
    let _ = write!(encoded, "{byte:02x}");
  }
  encoded
}

pub(crate) fn is_query_v1_base_key(base_key: &str) -> bool {
  base_key.starts_with(CACHE_QUERY_DOMAIN) || base_key.starts_with(GROUP_QUERY_DOMAIN)
}

pub(crate) fn external_cache_key_version(base_key: &str) -> &'static str {
  if base_key.starts_with(GROUP_QUERY_DOMAIN) {
    GROUP_QUERY_EXTERNAL_CACHE_KEY_VERSION
  } else if base_key.starts_with("\0oxibelt-cache-groups-v1\0") {
    GROUP_EXTERNAL_CACHE_KEY_VERSION
  } else if is_query_v1_base_key(base_key) {
    QUERY_EXTERNAL_CACHE_KEY_VERSION
  } else {
    super::external_handler::CACHE_KEY_VERSION
  }
}

fn escape_plain_base_key(base_key: String) -> String {
  if !base_key.contains('\0') {
    return base_key;
  }
  let bytes = base_key.as_bytes();
  let mut encoded =
    String::with_capacity(CACHE_PLAIN_KEY_ESCAPE_DOMAIN.len() + bytes.len() * 2 + 24);
  encoded.push_str(CACHE_PLAIN_KEY_ESCAPE_DOMAIN);
  encoded.push_str(&bytes.len().to_string());
  encoded.push(':');
  for byte in bytes {
    encoded.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
    encoded.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
  }
  encoded
}

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
