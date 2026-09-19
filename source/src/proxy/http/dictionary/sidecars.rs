//! Explicit, verified dictionary-compressed static-file sidecars.
//!
//! A sidecar is never inferred from a filename suffix. Its manifest binds the
//! identity resource, encoded resource, dictionary digest, and coding. The
//! final response must still expose the exact identity representation through
//! `AvailableRepresentation`, which makes a changed file fail closed.

use std::path::{Component, Path};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Response;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncReadExt;
use url::Url;

use crate::compression_dictionary::{
  codec::{DecodeLimits, DictionaryCoding, decode_bounded, maximum_working_set_bytes},
  fields::DictionaryHash,
};
use crate::config::RouteConfig;
use crate::state::AppSnapshot;

use super::super::{body::ProxyBody, integrity_digest::AvailableRepresentation, static_files};

const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// A verified encoded representation ready to replace a final identity body.
pub(super) struct StaticDictionarySidecar {
  pub(super) bytes: Bytes,
  pub(super) coding: DictionaryCoding,
  pub(super) permit: Arc<tokio::sync::OwnedSemaphorePermit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
  entries: Vec<ManifestEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
  path: String,
  identity_sha256: String,
  encoded_path: String,
  encoded_sha256: String,
  dictionary: String,
  dictionary_sha256: String,
  coding: String,
}

/// Returns an encoded sidecar only after the final response WAF has accepted
/// the identity response and every manifest binding has been revalidated.
pub(super) async fn select(
  route: &RouteConfig,
  state: &AppSnapshot,
  request_url: &Url,
  available_hash: DictionaryHash,
  coding: DictionaryCoding,
  response: &Response<ProxyBody>,
) -> Option<StaticDictionarySidecar> {
  if response.status() != http::StatusCode::OK
    || response
      .headers()
      .contains_key(http::header::CONTENT_ENCODING)
    || response.headers().contains_key(http::header::CONTENT_RANGE)
  {
    return None;
  }
  let manifest_path = route.static_files.dictionary_manifest.as_deref()?;
  let static_root = route.static_root.as_deref()?;
  let profile_name = route.compression_dictionary_profile.as_deref()?;
  let profile = state.compression_dictionary.profile(profile_name)?;
  let sidecar_budget = profile
    .config
    .max_codec_memory_bytes
    .checked_sub(maximum_working_set_bytes())?
    // Reserve manifest input, parsed strings, and collection overhead.
    .checked_sub(128 * 1024 * 1024)?;
  let representation_limit = sidecar_budget
    .checked_div(2)?
    .min(profile.config.max_decoded_size_bytes);
  if representation_limit == 0 {
    return None;
  }
  // Materialization uses the remaining profile budget, so admit it exclusively
  // and retain that reservation until the response body is dropped.
  let permits = profile.config.max_codec_concurrency.min(
    usize::try_from(profile.config.max_codec_memory_bytes / maximum_working_set_bytes()).ok()?,
  );
  let permit = Arc::new(
    profile
      .codec_permits
      .clone()
      .try_acquire_many_owned(u32::try_from(permits).ok()?)
      .ok()?,
  );
  let manifest = read_manifest(manifest_path, representation_limit).await?;
  if manifest.entries.len() > profile.config.max_dictionaries {
    return None;
  }
  let entry = manifest.entries.iter().find(|entry| {
    entry.path == request_url.path() && entry.coding.eq_ignore_ascii_case(coding_name(coding))
  })?;
  let identity_hash = parse_hash(&entry.identity_sha256)?;
  if response_identity_hash(response, representation_limit)? != identity_hash {
    return None;
  }
  let dictionary = state.compression_dictionary.configured(&entry.dictionary)?;
  if !dictionary.public
    || dictionary.hash != available_hash
    || dictionary.hash != parse_hash(&entry.dictionary_sha256)?
    || !profile
      .config
      .dictionaries
      .iter()
      .any(|name| name == &entry.dictionary)
  {
    return None;
  }
  let root = state.static_files.root_handle(static_root);
  let encoded =
    Bytes::from(read_static_resource(&root, &entry.encoded_path, representation_limit).await?);
  if hash(&encoded)? != parse_hash(&entry.encoded_sha256)? {
    return None;
  }
  let timeout = Duration::from_millis(profile.config.codec_timeout_ms);
  let deadline = Instant::now().checked_add(timeout)?;
  let cancel = Arc::new(AtomicBool::new(false));
  let worker_cancel = Arc::clone(&cancel);
  let dictionary_bytes = dictionary.bytes.clone();
  let worker_encoded = encoded.clone();
  let worker_permit = permit.clone();
  let decoded = match tokio::time::timeout(
    timeout,
    tokio::task::spawn_blocking(move || {
      let _permit = worker_permit;
      decode_bounded(
        coding,
        dictionary_bytes,
        &worker_encoded,
        &DecodeLimits {
          max_decoded_bytes: usize::try_from(representation_limit).unwrap_or(usize::MAX),
          max_expansion_ratio: usize::try_from(profile.config.max_expansion_ratio)
            .unwrap_or(usize::MAX),
          deadline: Some(deadline),
          cancel: Some(worker_cancel),
        },
      )
    }),
  )
  .await
  {
    Ok(Ok(Ok(decoded))) => decoded,
    _ => {
      cancel.store(true, Ordering::Release);
      return None;
    }
  };
  if hash(&decoded)? != identity_hash {
    return None;
  }
  Some(StaticDictionarySidecar {
    bytes: encoded,
    coding,
    permit,
  })
}

async fn read_manifest(path: &Path, profile_limit: u64) -> Option<Manifest> {
  let bytes = read_bounded(path, profile_limit.min(MAX_MANIFEST_BYTES)).await?;
  serde_json::from_slice(&bytes).ok()
}

fn safe_relative_path(wire_path: &str) -> Option<&Path> {
  let relative = wire_path.strip_prefix('/')?;
  if relative.is_empty()
    || Path::new(relative)
      .components()
      .any(|component| !matches!(component, Component::Normal(_)))
  {
    return None;
  }
  Some(Path::new(relative))
}

async fn read_bounded(path: &Path, maximum: u64) -> Option<Vec<u8>> {
  if maximum == 0 {
    return None;
  }
  let metadata = tokio::fs::metadata(path).await.ok()?;
  if !metadata.is_file() || metadata.len() > maximum {
    return None;
  }
  let file = tokio::fs::File::open(path).await.ok()?;
  let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).ok()?);
  file
    .take(maximum.saturating_add(1))
    .read_to_end(&mut bytes)
    .await
    .ok()?;
  (u64::try_from(bytes.len()).ok()? <= maximum).then_some(bytes)
}

async fn read_static_resource(
  root: &static_files::StaticRootHandle,
  wire_path: &str,
  maximum: u64,
) -> Option<Vec<u8>> {
  let relative = safe_relative_path(wire_path)?;
  let opened = static_files::open_verified_file(root, relative)
    .await
    .ok()?;
  if opened.metadata.len() > maximum {
    return None;
  }
  let file = opened.file;
  let mut bytes = Vec::with_capacity(usize::try_from(opened.metadata.len()).ok()?);
  file
    .take(maximum.saturating_add(1))
    .read_to_end(&mut bytes)
    .await
    .ok()?;
  (u64::try_from(bytes.len()).ok()? <= maximum).then_some(bytes)
}

fn response_identity_hash(response: &Response<ProxyBody>, maximum: u64) -> Option<DictionaryHash> {
  let identity = response.extensions().get::<AvailableRepresentation>()?;
  (u64::try_from(identity.0.len()).ok()? <= maximum).then(|| hash(&identity.0))?
}

fn hash(bytes: &[u8]) -> Option<DictionaryHash> {
  DictionaryHash::from_slice(&Sha256::digest(bytes)).ok()
}

fn parse_hash(value: &str) -> Option<DictionaryHash> {
  if value.len() != 64
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return None;
  }
  let mut output = [0_u8; 32];
  for (index, byte) in output.iter_mut().enumerate() {
    let high = hex(value.as_bytes()[index * 2])?;
    let low = hex(value.as_bytes()[index * 2 + 1])?;
    *byte = high << 4 | low;
  }
  DictionaryHash::from_slice(&output).ok()
}

const fn hex(value: u8) -> Option<u8> {
  match value {
    b'0'..=b'9' => Some(value - b'0'),
    b'a'..=b'f' => Some(value - b'a' + 10),
    b'A'..=b'F' => Some(value - b'A' + 10),
    _ => None,
  }
}

const fn coding_name(coding: DictionaryCoding) -> &'static str {
  match coding {
    DictionaryCoding::Dcb => "dcb",
    DictionaryCoding::Dcz => "dcz",
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn manifest_hashes_require_complete_hex_digests() {
    assert!(parse_hash(&"00".repeat(32)).is_some());
    assert!(parse_hash(&"0".repeat(63)).is_none());
    assert!(parse_hash(&format!("{}g", "00".repeat(31))).is_none());
    assert!(parse_hash(&format!("{}AA", "00".repeat(31))).is_none());
  }

  #[test]
  fn sidecar_paths_are_root_relative_and_traversal_free() {
    assert!(safe_relative_path("/assets/app.js").is_some());
    for path in ["app.js", "/", "/../app.js", "/a/../app.js"] {
      assert!(safe_relative_path(path).is_none(), "{path}");
    }
  }
}
