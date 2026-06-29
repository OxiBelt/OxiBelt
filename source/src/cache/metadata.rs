//! Disk cache metadata encoding and recovery parsing.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, StatusCode};

use super::{
  CacheFileKind, StoredBody, StoredEntry, VaryMatcher, cache_file_name, cache_file_path,
  cache_file_path_from_stem,
};

pub(super) fn encode_metadata(entry: &StoredEntry) -> anyhow::Result<String> {
  let StoredBody::Disk(body_path) = &entry.body else {
    return Ok(String::new());
  };
  let body_file = body_path
    .file_name()
    .and_then(|value| value.to_str())
    .ok_or_else(|| anyhow!("invalid cache body path"))?;
  let mut lines = Vec::new();
  lines.push("version=1".to_string());
  for (key, value) in [
    ("policy", entry.policy.as_str()),
    ("partition", entry.partition.as_str()),
    ("base_key", entry.base_key.as_str()),
    ("variant_key", entry.variant_key.as_str()),
    ("scheme", entry.scheme.as_str()),
    ("host", entry.host.as_str()),
    ("uri", entry.uri.as_str()),
    ("body_file", body_file),
  ] {
    lines.push(format!("{key}={}", b64(value.as_bytes())));
  }
  lines.push(format!("status={}", entry.status.as_u16()));
  lines.push(format!("expires_at={}", unix_seconds(entry.expires_at)));
  lines.push(format!(
    "stale_if_error_until={}",
    entry.stale_if_error_until.map(unix_seconds).unwrap_or(0)
  ));
  lines.push(format!(
    "stale_while_revalidate_until={}",
    entry
      .stale_while_revalidate_until
      .map(unix_seconds)
      .unwrap_or(0)
  ));
  lines.push(format!("must_revalidate={}", entry.must_revalidate));
  lines.push(format!("stored_at={}", unix_seconds(entry.stored_at)));
  lines.push(format!("size={}", entry.size));
  lines.push(format!(
    "security_headers_neutral={}",
    entry.security_headers_neutral
  ));
  for matcher in &entry.vary {
    lines.push(format!(
      "vary={}:{}",
      b64(matcher.name.as_bytes()),
      b64(matcher.value.as_bytes())
    ));
  }
  for tag in &entry.tags {
    lines.push(format!("tag={}", b64(tag.as_bytes())));
  }
  for (name, value) in &entry.headers {
    lines.push(format!(
      "header={}:{}",
      b64(name.as_str().as_bytes()),
      b64(value.as_bytes())
    ));
  }
  Ok(lines.join("\n"))
}

pub(super) fn decode_metadata(path: &Path, disk_dir: &Path) -> anyhow::Result<StoredEntry> {
  let metadata_file_name = path
    .file_name()
    .and_then(|value| value.to_str())
    .ok_or_else(|| anyhow!("invalid cache metadata file name"))?;
  let Some(metadata_stem) = metadata_file_name.strip_suffix(".meta") else {
    bail!("invalid cache metadata file extension");
  };
  let expected_metadata_path =
    cache_file_path_from_stem(disk_dir, metadata_stem, CacheFileKind::Meta)
      .ok_or_else(|| anyhow!("invalid cache metadata file name"))?;
  if path != expected_metadata_path {
    bail!("cache metadata path must stay under cache disk_dir");
  }
  let raw = std::fs::read_to_string(path)
    .with_context(|| format!("failed to read cache metadata {}", path.display()))?;
  let mut values: HashMap<&str, Vec<String>> = HashMap::new();
  for line in raw.lines() {
    let Some((key, value)) = line.split_once('=') else {
      continue;
    };
    values.entry(key).or_default().push(value.to_string());
  }
  let get = |key: &str| -> anyhow::Result<String> {
    values
      .get(key)
      .and_then(|items| items.first())
      .ok_or_else(|| anyhow!("missing cache metadata key {key}"))
      .and_then(|value| unb64(value))
  };
  let policy = get("policy")?;
  let partition = values
    .get("partition")
    .and_then(|items| items.first())
    .map(|value| unb64(value))
    .transpose()?
    .unwrap_or_default();
  let base_key = get("base_key")?;
  let variant_key = get("variant_key")?;
  let scheme = get("scheme")?;
  let host = get("host")?;
  let uri = get("uri")?;
  let expected_metadata_stem = cache_file_name(&variant_key);
  if metadata_stem != expected_metadata_stem {
    bail!("cache metadata file name does not match variant key");
  }
  let body_path = cache_file_path(disk_dir, &variant_key, CacheFileKind::Body)
    .ok_or_else(|| anyhow!("invalid cache body file name"))?;
  let status = values
    .get("status")
    .and_then(|items| items.first())
    .and_then(|value| value.parse::<u16>().ok())
    .and_then(|value| StatusCode::from_u16(value).ok())
    .ok_or_else(|| anyhow!("invalid cache metadata status"))?;
  let expires_at = metadata_time(&values, "expires_at")?;
  let stale_if_error_until = metadata_optional_time(&values, "stale_if_error_until")?;
  let stale_while_revalidate_until =
    metadata_optional_time(&values, "stale_while_revalidate_until")?;
  let must_revalidate = values
    .get("must_revalidate")
    .and_then(|items| items.first())
    .is_some_and(|value| value == "true");
  let stored_at = metadata_optional_time(&values, "stored_at")?.unwrap_or_else(SystemTime::now);
  let size = values
    .get("size")
    .and_then(|items| items.first())
    .and_then(|value| value.parse::<usize>().ok())
    .ok_or_else(|| anyhow!("invalid cache metadata size"))?;
  let mut vary = Vec::new();
  for item in values.get("vary").into_iter().flatten() {
    if let Some((name, value)) = item.split_once(':') {
      vary.push(VaryMatcher {
        name: unb64(name)?,
        value: unb64(value)?,
      });
    }
  }
  let mut headers = HeaderMap::new();
  for item in values.get("header").into_iter().flatten() {
    if let Some((name, value)) = item.split_once(':') {
      let name = HeaderName::from_bytes(unb64(name)?.as_bytes())?;
      let value = HeaderValue::from_bytes(&base64_decode(value)?)?;
      headers.append(name, value);
    }
  }
  let tags = values
    .get("tag")
    .into_iter()
    .flatten()
    .filter_map(|tag| unb64(tag).ok())
    .collect();
  let security_headers_neutral = values
    .get("security_headers_neutral")
    .and_then(|items| items.first())
    .is_some_and(|value| value == "true");
  Ok(StoredEntry {
    policy,
    partition,
    base_key,
    variant_key,
    scheme,
    host,
    uri,
    status,
    headers,
    security_headers_neutral,
    body: StoredBody::Disk(body_path),
    expires_at,
    stale_if_error_until,
    stale_while_revalidate_until,
    must_revalidate,
    stored_at,
    vary,
    tags,
    size,
  })
}

pub(super) fn remove_metadata(entry: &StoredEntry) {
  if let StoredBody::Disk(path) = &entry.body
    && let Some(dir) = path.parent()
    && let Some(meta) = cache_file_path(dir, &entry.variant_key, CacheFileKind::Meta)
  {
    let _ = std::fs::remove_file(meta);
  }
}

fn metadata_time(values: &HashMap<&str, Vec<String>>, key: &str) -> anyhow::Result<SystemTime> {
  let seconds = values
    .get(key)
    .and_then(|items| items.first())
    .and_then(|value| value.parse::<u64>().ok())
    .ok_or_else(|| anyhow!("invalid cache metadata time {key}"))?;
  Ok(UNIX_EPOCH + Duration::from_secs(seconds))
}

fn metadata_optional_time(
  values: &HashMap<&str, Vec<String>>,
  key: &str,
) -> anyhow::Result<Option<SystemTime>> {
  let seconds = values
    .get(key)
    .and_then(|items| items.first())
    .and_then(|value| value.parse::<u64>().ok())
    .unwrap_or(0);
  Ok((seconds > 0).then_some(UNIX_EPOCH + Duration::from_secs(seconds)))
}

fn unix_seconds(time: SystemTime) -> u64 {
  time
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

fn b64(bytes: &[u8]) -> String {
  base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

fn unb64(value: &str) -> anyhow::Result<String> {
  String::from_utf8(base64_decode(value)?).context("cache metadata value is not UTF-8")
}

fn base64_decode(value: &str) -> anyhow::Result<Vec<u8>> {
  base64::engine::general_purpose::STANDARD_NO_PAD
    .decode(value)
    .context("invalid base64 cache metadata")
}
