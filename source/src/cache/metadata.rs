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
  if let Some(stamp) = &entry.group_stamp {
    lines.push(format!("group_stamp={}", b64(&serde_json::to_vec(stamp)?)));
  }
  if let Some(nvs) = &entry.no_vary_search {
    lines.push(format!("no_vary_search={}", b64(&serde_json::to_vec(nvs)?)));
  }
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
  if super::is_query_v1_base_key(&entry.base_key) {
    let epoch = entry
      .query_target_epoch
      .ok_or_else(|| anyhow!("Q1 disk entry is missing its target epoch"))?;
    lines.push(format!("query_target_epoch={epoch}"));
  }
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
  decode_metadata_text(&raw, metadata_stem, disk_dir)
}

/// Decodes cache metadata after the filesystem wrapper has established the
/// trusted metadata stem and cache root.
///
/// Keeping text parsing separate lets recovery tests and fuzzing exercise the
/// attacker-controlled representation without granting the parser filesystem
/// access.
pub(super) fn decode_metadata_text(
  raw: &str,
  metadata_stem: &str,
  disk_dir: &Path,
) -> anyhow::Result<StoredEntry> {
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
  let query_target_epoch = values
    .get("query_target_epoch")
    .and_then(|items| items.first())
    .map(|value| {
      value
        .parse::<u64>()
        .map_err(|_| anyhow!("invalid Q1 cache target epoch"))
    })
    .transpose()?;
  if super::is_query_v1_base_key(&base_key) && query_target_epoch.is_none() {
    bail!("legacy Q1 disk metadata is missing its target epoch");
  }
  let group_stamp = values
    .get("group_stamp")
    .map(|items| -> anyhow::Result<super::CacheGroupStamp> {
      if items.len() != 1 || items[0].len() > 131072 {
        bail!("invalid cache group metadata envelope");
      }
      let stamp: super::CacheGroupStamp = serde_json::from_str(&unb64(&items[0])?)?;
      let target = uri
        .parse::<http::Uri>()
        .map_err(|_| anyhow!("invalid cache group metadata URI"))
        .and_then(|uri| super::groups::model::canonical_target(&uri))?;
      if !stamp.valid()
        || stamp.policy != policy
        || stamp.partition != partition
        || stamp.target != target
      {
        bail!("cache group metadata scope mismatch");
      }
      Ok(stamp)
    })
    .transpose()?;
  if matches!(
    super::external_cache_key_version(&base_key),
    super::key::GROUP_EXTERNAL_CACHE_KEY_VERSION
      | super::key::GROUP_QUERY_EXTERNAL_CACHE_KEY_VERSION
  ) && group_stamp.is_none()
  {
    bail!("group-enabled cache metadata missing coherence stamp");
  }
  Ok(StoredEntry {
    group_stamp,
    no_vary_search: values
      .get("no_vary_search")
      .filter(|values| values.len() == 1)
      .and_then(|values| values.first())
      .filter(|value| value.len() <= 65_536)
      .and_then(|value| unb64(value).ok())
      .and_then(|value| serde_json::from_str::<super::CacheNvsMetadata>(&value).ok())
      .filter(|nvs| nvs.valid() && nvs.owner_uri == uri),
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
    query_target_epoch,
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

#[cfg(feature = "fuzzing")]
pub(super) fn fuzz_decode_metadata(raw: &str) {
  const FUZZ_CACHE_ROOT: &str = "/oxibelt-fuzz-cache";
  let variant_key = raw.lines().find_map(|line| {
    let encoded = line.strip_prefix("variant_key=")?;
    unb64(encoded).ok()
  });
  let stem = variant_key
    .as_deref()
    .map(cache_file_name)
    .unwrap_or_else(|| "0".repeat(64));
  let _ = decode_metadata_text(raw, &stem, Path::new(FUZZ_CACHE_ROOT));
  let _ = decode_metadata_text(raw, &"f".repeat(64), Path::new(FUZZ_CACHE_ROOT));
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn text_decoder_preserves_the_filesystem_binding() {
    let variant_key = "variant-key";
    let stem = cache_file_name(variant_key);
    let raw = [
      "version=1".to_string(),
      format!("policy={}", b64(b"default")),
      format!("partition={}", b64(b"tenant")),
      format!("base_key={}", b64(b"https://cache.example.test/item")),
      format!("variant_key={}", b64(variant_key.as_bytes())),
      format!("scheme={}", b64(b"https")),
      format!("host={}", b64(b"cache.example.test")),
      format!("uri={}", b64(b"/item")),
      "status=200".to_string(),
      "expires_at=1893456000".to_string(),
      "stored_at=1767225600".to_string(),
      "size=4".to_string(),
      "security_headers_neutral=true".to_string(),
    ]
    .join("\n");
    let decoded = decode_metadata_text(&raw, &stem, Path::new("/cache"))
      .expect("bounded metadata should decode");
    assert_eq!(decoded.variant_key, variant_key);
    assert!(decode_metadata_text(&raw, &"f".repeat(64), Path::new("/cache")).is_err());
  }

  #[test]
  fn group_stamp_matches_an_absolute_stored_uri_by_canonical_target() {
    let variant_key = "absolute-variant";
    let stem = cache_file_name(variant_key);
    let stamp = super::super::CacheGroupStamp {
      policy: "default".to_string(),
      origin: super::super::CacheGroupOrigin::new("https", "cache.example.test").unwrap(),
      partition: "tenant".to_string(),
      incarnation: "a".repeat(64),
      sequence: 0,
      target: "/item?version=one".to_string(),
      groups: Vec::new(),
      tags: Vec::new(),
      equivalent_path: None,
    };
    let raw = [
      "version=1".to_string(),
      format!("group_stamp={}", b64(&serde_json::to_vec(&stamp).unwrap())),
      format!("policy={}", b64(b"default")),
      format!("partition={}", b64(b"tenant")),
      format!("base_key={}", b64(b"https://cache.example.test/item")),
      format!("variant_key={}", b64(variant_key.as_bytes())),
      format!("scheme={}", b64(b"https")),
      format!("host={}", b64(b"cache.example.test")),
      format!(
        "uri={}",
        b64(b"https://cache.example.test/item?version=one")
      ),
      "status=200".to_string(),
      "expires_at=1893456000".to_string(),
      "stored_at=1767225600".to_string(),
      "size=4".to_string(),
      "security_headers_neutral=true".to_string(),
    ]
    .join("\n");

    let decoded = decode_metadata_text(&raw, &stem, Path::new("/cache")).unwrap();
    assert_eq!(decoded.group_stamp.unwrap().target, "/item?version=one");

    let encoded_stamp = b64(&serde_json::to_vec(&stamp).unwrap());
    let mut legacy_stamp = stamp;
    legacy_stamp.target = "https://cache.example.test/item?version=one".to_string();
    let legacy_raw = raw.replacen(
      &format!("group_stamp={encoded_stamp}"),
      &format!(
        "group_stamp={}",
        b64(&serde_json::to_vec(&legacy_stamp).unwrap())
      ),
      1,
    );
    assert!(decode_metadata_text(&legacy_raw, &stem, Path::new("/cache")).is_err());
  }
}
