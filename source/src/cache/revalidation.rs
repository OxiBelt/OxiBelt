use super::*;
use tracing::warn;

pub(super) fn update_from_not_modified(
  cache: &ResponseCache,
  ctx: CacheInsertContext<'_>,
  cached_entry: &CacheEntry,
  not_modified_headers: &HeaderMap,
) {
  let mut headers = cached_entry.headers.clone();
  for (name, value) in not_modified_headers {
    if matches!(
      name.as_str().to_ascii_lowercase().as_str(),
      "cache-control" | "expires" | "etag" | "last-modified" | "vary"
    ) {
      headers.insert(name.clone(), value.clone());
    }
  }
  let body_len = cached_entry.body_len();
  let old_prepared = match cache.prepare_insert(
    ctx.clone(),
    cached_entry.status,
    &cached_entry.headers,
    Some(body_len),
  ) {
    CachePreparedInsertDecision::Cacheable(prepared) => prepared,
    CachePreparedInsertDecision::NotCacheable(_) | CachePreparedInsertDecision::Rejected(_) => {
      return;
    }
  };
  let prepared = match cache.prepare_insert(ctx, cached_entry.status, &headers, Some(body_len)) {
    CachePreparedInsertDecision::Cacheable(prepared) => prepared,
    CachePreparedInsertDecision::NotCacheable(_) | CachePreparedInsertDecision::Rejected(_) => {
      return;
    }
  };
  if old_prepared.variant_key != prepared.variant_key {
    return;
  }

  update_prepared_not_modified(cache, *prepared, headers, body_len);
}

fn update_prepared_not_modified(
  cache: &ResponseCache,
  prepared: CachePreparedInsert,
  headers: HeaderMap,
  body_len: usize,
) {
  let size = match body_len.checked_add(prepared.header_bytes) {
    Some(size) if size <= cache.config.max_size_bytes => size,
    _ => return,
  };
  let (shared_entry, external_metadata) = {
    let mut inner = cache.inner.lock().expect("cache lock poisoned");
    let Some(mut stored) = detach_entry(&mut inner, &prepared.variant_key) else {
      return;
    };
    let original = stored.clone();
    stored.status = prepared.status;
    stored.headers = prepared.stored_headers;
    stored.expires_at = prepared.metadata.expires_at;
    stored.stale_if_error_until = prepared.metadata.stale_if_error_until;
    stored.stale_while_revalidate_until = prepared.metadata.stale_while_revalidate_until;
    stored.must_revalidate = prepared.metadata.must_revalidate;
    stored.stored_at = prepared.metadata.stored_at;
    stored.vary = prepared.metadata.vary;
    stored.tags = extract_tags(&headers, &prepared.policy);
    stored.size = size;
    if let Err(error) = cache.persist_metadata(&stored) {
      warn!(error = %error, "failed to persist cache metadata");
      add_size(&mut inner, &original);
      index_entry(&mut inner, &original);
      inner.entries.insert(prepared.variant_key, original);
      return;
    }
    add_size(&mut inner, &stored);
    index_entry(&mut inner, &stored);
    let shared_entry = cache
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
      .and_then(|_| shared_cache_entry(&stored));
    let external_metadata = cache.external_metadata_for_stored(&stored);
    inner.entries.insert(prepared.variant_key, stored);
    cache.evict_if_needed(&mut inner, &prepared.policy);
    (shared_entry, external_metadata)
  };
  if let Some(shared) = &cache.shared_state
    && shared.has_cache()
    && let Some(shared_entry) = shared_entry
  {
    shared.cache_put(&shared_entry);
  }
  if let Some((handler, metadata)) = external_metadata {
    cache.spawn_external_revalidate(handler, metadata);
  }
}
