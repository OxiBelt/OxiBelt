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
      name.as_str(),
      "cache-control" | "expires" | "etag" | "last-modified" | "vary"
    ) {
      headers.insert(name.clone(), value.clone());
    }
  }
  merge_nvs_not_modified_headers(&mut headers, not_modified_headers);
  merge_digest_not_modified_headers(&mut headers, not_modified_headers);
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
  let mut prepared = match cache.prepare_insert(ctx, cached_entry.status, &headers, Some(body_len))
  {
    CachePreparedInsertDecision::Cacheable(prepared) => prepared,
    CachePreparedInsertDecision::NotCacheable(_) | CachePreparedInsertDecision::Rejected(_) => {
      return;
    }
  };
  if !not_modified_headers.contains_key("no-vary-search") {
    prepared.no_vary_search = cached_entry.no_vary_search.clone();
    prepared.header_bytes = header_size(&prepared.stored_headers)
      .saturating_add(nvs::metadata_size(prepared.no_vary_search.as_ref()));
  }
  let replace = {
    let mut inner = cache.inner_guard();
    if !cache.prepared_generation_current_locked(&inner, &prepared) {
      return;
    }
    if old_prepared.variant_key != prepared.variant_key {
      remove_entry(&mut inner, &old_prepared.variant_key);
      true
    } else {
      !inner.entries.contains_key(&prepared.variant_key)
    }
  };
  // A validated owner may have come from L2/L3, or acquired a new Vary key.
  // Publish its body only after the 304 has renewed its response metadata.
  if replace {
    let mut entry = cached_entry.clone();
    entry.headers = headers;
    cache.insert_prepared(*prepared, entry);
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
    let mut inner = cache.inner_guard();
    // A 304 may arrive after an unsafe response invalidated this Q1 target.
    // Validate while holding the same lock that detaches and republishes the
    // entry, otherwise the revalidation path could resurrect old metadata.
    if !cache.prepared_generation_current_locked(&inner, &prepared) {
      return;
    }
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
    stored.no_vary_search = prepared.no_vary_search;
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
  // Synchronous revalidation updates are L1-only. Request paths use the
  // asynchronous cache insertion path before publishing to shared state.
  let _ = shared_entry;
  if let Some((handler, metadata)) = external_metadata {
    cache.spawn_external_revalidate(handler, metadata);
  }
}

pub(super) fn merge_nvs_not_modified_headers(headers: &mut HeaderMap, update: &HeaderMap) {
  if update.contains_key("no-vary-search") {
    headers.remove("no-vary-search");
    for value in update.get_all("no-vary-search") {
      headers.append("no-vary-search", value.clone());
    }
  }
}

pub(super) fn merge_digest_not_modified_headers(headers: &mut HeaderMap, update: &HeaderMap) {
  // A 304's content digest describes empty message content, not the stored
  // response body. Only whole-representation metadata can update that body.
  for name in ["repr-digest", "unencoded-digest"] {
    if update.contains_key(name) {
      headers.remove(name);
      for value in update.get_all(name) {
        headers.append(name, value.clone());
      }
    }
  }
}

#[cfg(test)]
mod digest_tests {
  use super::*;

  #[test]
  fn not_modified_updates_representation_digests_without_replacing_content_digest() {
    let mut headers = HeaderMap::new();
    headers.insert("content-digest", HeaderValue::from_static("sha-256=:AQ==:"));
    headers.insert("repr-digest", HeaderValue::from_static("sha-256=:AA==:"));
    let mut update = HeaderMap::new();
    update.insert("content-digest", HeaderValue::from_static("sha-256=:Ag==:"));
    update.append("repr-digest", HeaderValue::from_static("sha-256=:Aw==:"));
    update.append("repr-digest", HeaderValue::from_static("sha-512=:BA==:"));
    update.insert(
      "unencoded-digest",
      HeaderValue::from_static("sha-256=:BQ==:"),
    );
    merge_digest_not_modified_headers(&mut headers, &update);
    assert_eq!(headers["content-digest"], "sha-256=:AQ==:");
    assert_eq!(headers.get_all("repr-digest").iter().count(), 2);
    assert_eq!(headers["unencoded-digest"], "sha-256=:BQ==:");
  }
}
