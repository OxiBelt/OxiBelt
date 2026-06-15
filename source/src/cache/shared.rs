//! Shared-state cache entry conversion helpers.

use crate::shared_state::{SharedCacheEntry, SharedVaryMatcher};

use super::*;

pub(in crate::cache) fn shared_cache_entry(entry: &StoredEntry) -> Option<SharedCacheEntry> {
  let body = match &entry.body {
    StoredBody::Memory(body) => body.to_vec(),
    StoredBody::Tmpfs(path) | StoredBody::Disk(path) => std::fs::read(path).ok()?,
  };
  let mut shared_entry = shared_cache_entry_metadata(entry, body.len());
  shared_entry.body = body;
  Some(shared_entry)
}

pub(in crate::cache) fn shared_cache_entry_metadata(
  entry: &StoredEntry,
  body_len: usize,
) -> SharedCacheEntry {
  SharedCacheEntry {
    policy: entry.policy.clone(),
    partition: entry.partition.clone(),
    base_key: entry.base_key.clone(),
    variant_key: entry.variant_key.clone(),
    scheme: entry.scheme.clone(),
    host: entry.host.clone(),
    uri: entry.uri.clone(),
    status: entry.status.as_u16(),
    headers: entry
      .headers
      .iter()
      .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
      .collect(),
    body_len,
    body_chunks: Vec::new(),
    body: Vec::new(),
    stored_at_ms: system_time_ms(entry.stored_at),
    expires_at_ms: system_time_ms(entry.expires_at),
    stale_if_error_until_ms: entry.stale_if_error_until.map(system_time_ms),
    stale_while_revalidate_until_ms: entry.stale_while_revalidate_until.map(system_time_ms),
    must_revalidate: entry.must_revalidate,
    vary: entry
      .vary
      .iter()
      .map(|item| SharedVaryMatcher {
        name: item.name.clone(),
        value: item.value.clone(),
      })
      .collect(),
    tags: entry.tags.clone(),
  }
}
