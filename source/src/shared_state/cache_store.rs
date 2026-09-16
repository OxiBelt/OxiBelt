//! Shared cache-store abstractions.
//! Serialized cache entries keep HTTP metadata separate from backend storage details.

use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::warn;

use crate::cache::{CacheEntry, CacheLookup, Revalidation, StaleEntry};

use super::{
  Backend, SharedCacheEntry, SharedCacheLock, SharedState, SharedStateFeature, SharedVaryMatcher,
  now_unix_ms, random_hex,
};

impl SharedState {
  /// Reads the durable generation for all Q1 variants of a target.  The
  /// counter deliberately excludes the cache partition: an unsafe response
  /// invalidates every private partition for the selected resource.
  pub async fn cache_query_epoch(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
  ) -> anyhow::Result<u64> {
    let Some(backend) = &self.cache else {
      return Ok(0);
    };
    let key = self.shared_query_epoch_key(policy, scheme, host, uri);
    let result = match tokio::time::timeout(self.operation_timeout, backend.counter_get(&key)).await
    {
      Ok(result) => result.map(|value| value as u64),
      Err(_) => Err(anyhow::anyhow!("shared QUERY epoch read timed out")),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }

  /// Atomically advances the durable Q1 target generation before deletion.
  /// A stale fill can still finish its bytes, but its old epoch can never be
  /// selected by a subsequent lookup.
  pub async fn cache_advance_query_epoch(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
  ) -> anyhow::Result<u64> {
    let Some(backend) = &self.cache else {
      return Ok(0);
    };
    let key = self.shared_query_epoch_key(policy, scheme, host, uri);
    let result = match tokio::time::timeout(
      self.operation_timeout,
      backend.counter_add(&key, 1, None),
    )
    .await
    {
      Ok(result) => result.map(|value| value as u64),
      Err(_) => Err(anyhow::anyhow!("shared QUERY epoch advance timed out")),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }

  #[allow(clippy::too_many_arguments)]
  pub async fn cache_lookup(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    partition: &str,
    base_key: &str,
    uri: &str,
    method: &Method,
    request_headers: &HeaderMap,
    request_no_cache: bool,
    background_refresh: bool,
    max_vary_variants: usize,
    query_target_epoch: Option<u64>,
  ) -> anyhow::Result<Option<CacheLookup>> {
    let result = match tokio::time::timeout(
      self.operation_timeout,
      self.cache_lookup_inner(
        policy,
        scheme,
        host,
        partition,
        base_key,
        uri,
        method,
        request_headers,
        request_no_cache,
        background_refresh,
        max_vary_variants,
        query_target_epoch,
      ),
    )
    .await
    {
      Ok(result) => result,
      Err(_) => Err(anyhow::anyhow!("shared cache lookup enumeration timed out")),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }
  #[allow(clippy::too_many_arguments)]
  async fn cache_lookup_inner(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    partition: &str,
    base_key: &str,
    uri: &str,
    method: &Method,
    request_headers: &HeaderMap,
    request_no_cache: bool,
    background_refresh: bool,
    max_vary_variants: usize,
    query_target_epoch: Option<u64>,
  ) -> anyhow::Result<Option<CacheLookup>> {
    let Some(backend) = &self.cache else {
      return Ok(None);
    };
    let now = now_unix_ms();
    let direct_variant_key = shared_no_vary_variant_key(partition, base_key);
    let direct_key = self.shared_cache_entry_key(&direct_variant_key, query_target_epoch);
    if let Some(bytes) = backend.get(&direct_key).await?
      && let Ok(entry) = serde_json::from_slice::<SharedCacheEntry>(&bytes)
      && entry.vary.is_empty()
      && shared_entry_matches(
        &entry,
        SharedCacheMatch {
          policy,
          scheme,
          host,
          partition,
          base_key,
          uri,
          query_target_epoch,
        },
      )
      && let Some(lookup) = self
        .cache_lookup_entry(
          backend,
          Some(&direct_key),
          None,
          entry,
          method,
          request_headers,
          request_no_cache,
          background_refresh,
          now,
        )
        .await?
    {
      return Ok(Some(lookup));
    }
    let index_prefix =
      self.shared_cache_index_prefix(policy, scheme, host, partition, base_key, uri);
    let mut cursor = None;
    let mut inspected = 0_usize;
    for _ in 0..self.enumeration.max_rounds() {
      let remaining = max_vary_variants
        .max(1)
        .min(self.enumeration.max_items.saturating_sub(inspected));
      if remaining == 0 {
        backend.record_enumeration("cache_index", "cap_exhausted", 1);
        break;
      }
      let page = backend
        .enumeration_keys(
          &index_prefix,
          cursor.as_ref(),
          self.enumeration.page_size.min(remaining).max(1),
          "cache_index",
        )
        .await?;
      inspected = inspected.saturating_add(page.keys.len());
      let values = backend
        .enumeration_values(&page.keys, "cache_index")
        .await?;
      let mut candidates = Vec::new();
      let mut cleanup = Vec::new();
      for (index_key, value) in page.keys.iter().zip(values) {
        let Some(value) = value else {
          cleanup.push(index_key.clone());
          continue;
        };
        let Ok(variant_key) = String::from_utf8(value) else {
          cleanup.push(index_key.clone());
          continue;
        };
        candidates.push((
          index_key.clone(),
          self.shared_cache_entry_key_from_storage(&variant_key),
        ));
      }
      let entry_keys = candidates
        .iter()
        .map(|(_, entry_key)| entry_key.clone())
        .collect::<Vec<_>>();
      let entries = backend
        .enumeration_values(&entry_keys, "cache_index")
        .await?;
      for ((index_key, entry_key), bytes) in candidates.into_iter().zip(entries) {
        let Some(bytes) = bytes else {
          cleanup.push(index_key);
          continue;
        };
        let Ok(entry) = serde_json::from_slice::<SharedCacheEntry>(&bytes) else {
          cleanup.push(index_key);
          continue;
        };
        if !shared_entry_matches(
          &entry,
          SharedCacheMatch {
            policy,
            scheme,
            host,
            partition,
            base_key,
            uri,
            query_target_epoch,
          },
        ) || !shared_vary_matches(&entry.vary, request_headers)
        {
          continue;
        }
        if let Some(lookup) = self
          .cache_lookup_entry(
            backend,
            Some(&entry_key),
            Some(&index_key),
            entry,
            method,
            request_headers,
            request_no_cache,
            background_refresh,
            now,
          )
          .await?
        {
          if !cleanup.is_empty() {
            backend.enumeration_delete(&cleanup, "cache_index").await?;
          }
          return Ok(Some(lookup));
        }
      }
      if !cleanup.is_empty() {
        backend.enumeration_delete(&cleanup, "cache_index").await?;
      }
      cursor = page.next_cursor;
      if cursor.is_none() {
        break;
      }
    }
    if cursor.is_some() {
      backend.record_enumeration("cache_index", "cap_exhausted", 1);
    }
    Ok(None)
  }
  #[allow(clippy::too_many_arguments)]
  async fn cache_lookup_entry(
    &self,
    backend: &Backend,
    entry_key: Option<&str>,
    index_key: Option<&str>,
    entry: SharedCacheEntry,
    method: &Method,
    _request_headers: &HeaderMap,
    request_no_cache: bool,
    background_refresh: bool,
    now: i64,
  ) -> anyhow::Result<Option<CacheLookup>> {
    if shared_cache_retention_until_ms(&entry) <= now {
      if let Some(entry_key) = entry_key {
        let _ = backend.delete(entry_key).await;
      }
      if let Some(index_key) = index_key {
        let _ = backend.delete(index_key).await;
      }
      for chunk_key in &entry.body_chunks {
        let _ = backend.delete(chunk_key).await;
      }
      return Ok(None);
    }
    let Some(cache_entry) = self.shared_cache_entry_to_cache_entry(&entry).await else {
      if let Some(entry_key) = entry_key {
        let _ = backend.delete(entry_key).await;
      }
      if let Some(index_key) = index_key {
        let _ = backend.delete(index_key).await;
      }
      return Ok(None);
    };
    if method == Method::HEAD {
      return Ok(Some(CacheLookup::Fresh(
        cache_entry.with_body(bytes::Bytes::new()),
      )));
    }
    if request_no_cache || entry.must_revalidate || entry.expires_at_ms <= now {
      let validators = validator_headers(&cache_entry.headers);
      let query_entry = crate::cache::is_query_v1_base_key(&entry.base_key);
      if !request_no_cache
        && !entry.must_revalidate
        && entry
          .stale_while_revalidate_until_ms
          .is_some_and(|until| until > now)
      {
        return Ok(Some(CacheLookup::Stale(StaleEntry {
          entry: cache_entry,
          request_headers: validators,
          serve_stale_on_error: entry
            .stale_if_error_until_ms
            .is_some_and(|until| until > now),
          background_refresh,
        })));
      }
      if validators.is_empty() {
        if query_entry && (request_no_cache || entry.must_revalidate) {
          return Ok(None);
        }
        if entry
          .stale_while_revalidate_until_ms
          .is_some_and(|until| until > now)
        {
          return Ok(Some(CacheLookup::Stale(StaleEntry {
            entry: cache_entry,
            request_headers: HeaderMap::new(),
            serve_stale_on_error: entry
              .stale_if_error_until_ms
              .is_some_and(|until| until > now),
            background_refresh,
          })));
        }
        if entry
          .stale_if_error_until_ms
          .is_some_and(|until| until > now)
        {
          return Ok(Some(CacheLookup::Revalidate(Revalidation {
            entry: cache_entry,
            request_headers: HeaderMap::new(),
            serve_stale_on_error: true,
          })));
        }
        return Ok(None);
      }
      return Ok(Some(CacheLookup::Revalidate(Revalidation {
        entry: cache_entry,
        request_headers: validators,
        serve_stale_on_error: (!query_entry || !entry.must_revalidate)
          && entry
            .stale_if_error_until_ms
            .is_some_and(|until| until > now),
      })));
    }
    Ok(Some(CacheLookup::Fresh(cache_entry)))
  }
  pub async fn cache_put(&self, entry: &SharedCacheEntry) {
    let Some(backend) = &self.cache else {
      return;
    };
    let result = match backend.operation_timeout() {
      Some(timeout) => {
        match tokio::time::timeout(timeout, self.cache_put_inner(backend, entry)).await {
          Ok(result) => result,
          Err(_) => Err(anyhow::anyhow!(
            "shared cache write exceeded its operation deadline"
          )),
        }
      }
      None => self.cache_put_inner(backend, entry).await,
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    if let Err(error) = result {
      warn!(error = %error, "failed to write shared cache entry");
    }
  }
  async fn cache_put_inner(
    &self,
    backend: &Backend,
    entry: &SharedCacheEntry,
  ) -> anyhow::Result<()> {
    let ttl = super::ttl_from_expires_ms(shared_cache_retention_until_ms(entry));
    let key = self.shared_cache_entry_key(&entry.variant_key, entry.query_target_epoch);
    let mut entry = entry.clone();
    entry.body_len = entry.body.len();
    if entry.body.len() > self.cache_chunk_bytes {
      let chunk_ttl = ttl;
      let storage_variant = self.shared_cache_storage_variant_key(&entry);
      let stem = shared_cache_chunk_stem(&storage_variant);
      let mut chunks = Vec::new();
      for (index, chunk) in entry.body.chunks(self.cache_chunk_bytes).enumerate() {
        let chunk_key = self.key(&format!("cache:chunk:{stem}:{index}"));
        backend.put(&chunk_key, chunk, chunk_ttl).await?;
        chunks.push(chunk_key);
      }
      entry.body.clear();
      entry.body_chunks = chunks;
    }
    let value = serde_json::to_vec(&entry)?;
    match self
      .cache_publish_query_indexed(backend, &entry, &value, ttl)
      .await
    {
      Ok(true) => return Ok(()),
      Ok(false) => {}
      Err(error) => {
        delete_shared_chunks(backend, &entry.body_chunks).await;
        return Err(error);
      }
    }
    backend.put(&key, &value, ttl).await?;
    self.cache_put_index(&entry).await;
    Ok(())
  }

  pub async fn cache_put_file(
    &self,
    entry: &SharedCacheEntry,
    body_path: &Path,
    body_len: usize,
  ) -> anyhow::Result<()> {
    let Some(backend) = &self.cache else {
      return Ok(());
    };
    let ttl = super::ttl_from_expires_ms(shared_cache_retention_until_ms(entry));
    let mut file = tokio::fs::File::open(body_path).await?;
    let storage_variant = self.shared_cache_storage_variant_key(entry);
    let stem = shared_cache_chunk_stem(&storage_variant);
    let mut chunks = Vec::new();
    let mut buffer = vec![0_u8; self.cache_chunk_bytes.max(1)];
    let mut copied = 0_usize;
    loop {
      let read = file.read(&mut buffer).await?;
      if read == 0 {
        break;
      }
      copied = copied
        .checked_add(read)
        .ok_or_else(|| anyhow::anyhow!("shared cache file body length overflow"))?;
      let chunk_key = self.key(&format!("cache:chunk:{stem}:{}", chunks.len()));
      if let Err(error) = backend.put(&chunk_key, &buffer[..read], ttl).await {
        delete_shared_chunks(backend, &chunks).await;
        return Err(error);
      }
      chunks.push(chunk_key);
    }
    if copied != body_len {
      delete_shared_chunks(backend, &chunks).await;
      anyhow::bail!("shared cache file body length mismatch: expected {body_len}, copied {copied}");
    }
    let key = self.shared_cache_entry_key(&entry.variant_key, entry.query_target_epoch);
    let mut entry = entry.clone();
    entry.body.clear();
    entry.body_len = body_len;
    entry.body_chunks = chunks;
    let value = serde_json::to_vec(&entry)?;
    match self
      .cache_publish_query_indexed(backend, &entry, &value, ttl)
      .await
    {
      Ok(true) => return Ok(()),
      Ok(false) => {}
      Err(error) => {
        delete_shared_chunks(backend, &entry.body_chunks).await;
        return Err(error);
      }
    }
    if let Err(error) = backend.put(&key, &value, ttl).await {
      delete_shared_chunks(backend, &entry.body_chunks).await;
      return Err(error);
    }
    self.cache_put_index(&entry).await;
    Ok(())
  }

  async fn cache_put_index(&self, entry: &SharedCacheEntry) {
    let Some(backend) = &self.cache else {
      return;
    };
    let ttl = super::ttl_from_expires_ms(shared_cache_retention_until_ms(entry));
    let key = self.shared_cache_index_key(entry);
    let storage_variant = self.shared_cache_storage_variant_key(entry);
    if let Err(error) = backend.put(&key, storage_variant.as_bytes(), ttl).await {
      warn!(error = %error, "failed to write shared cache index");
    }
  }

  fn shared_cache_entry_key(&self, variant_key: &str, query_target_epoch: Option<u64>) -> String {
    let storage_variant = match query_target_epoch {
      Some(epoch) => format!("q1-epoch:{epoch}:{}", digest_hex(variant_key.as_bytes())),
      None => variant_key.to_string(),
    };
    self.shared_cache_entry_key_from_storage(&storage_variant)
  }

  pub(super) fn shared_cache_storage_variant_key(&self, entry: &SharedCacheEntry) -> String {
    match entry.query_target_epoch {
      Some(epoch) => format!(
        "q1-epoch:{epoch}:{}",
        digest_hex(entry.variant_key.as_bytes())
      ),
      None => entry.variant_key.clone(),
    }
  }

  pub(super) fn shared_cache_entry_key_from_storage(&self, variant_key: &str) -> String {
    self.key(&format!("cache:entry:{variant_key}"))
  }

  fn shared_query_epoch_key(&self, policy: &str, scheme: &str, host: &str, uri: &str) -> String {
    let material = format!("{policy}\n{scheme}\n{host}\n{uri}");
    let digest = crate::crypto::sha256(material.as_bytes());
    let bucket = u16::from_be_bytes([digest[0], digest[1]]) % crate::cache::QUERY_EPOCH_BUCKETS;
    // Policy names are configuration-bounded; targets map into a fixed bucket
    // set. A collision only forces an extra Q1 miss after invalidation.
    self.key(&format!(
      "cache:query-epoch:{}:{bucket}",
      digest_hex(policy.as_bytes())
    ))
  }

  pub(super) fn shared_cache_index_key(&self, entry: &SharedCacheEntry) -> String {
    let prefix = self.shared_cache_index_prefix(
      &entry.policy,
      &entry.scheme,
      &entry.host,
      &entry.partition,
      &entry.base_key,
      &entry.uri,
    );
    format!("{prefix}:{}", digest_hex(entry.variant_key.as_bytes()))
  }

  fn shared_cache_index_prefix(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    partition: &str,
    base_key: &str,
    uri: &str,
  ) -> String {
    let digest =
      digest_hex(format!("{policy}\n{partition}\n{scheme}\n{host}\n{uri}\n{base_key}").as_bytes());
    self.key(&format!("cache:index:{digest}"))
  }

  pub async fn cache_try_lock(&self, fill_key: &str) -> Option<SharedCacheLock> {
    self.cache_try_lock_result(fill_key).await.ok().flatten()
  }

  pub async fn cache_try_lock_result(
    &self,
    fill_key: &str,
  ) -> anyhow::Result<Option<SharedCacheLock>> {
    let Some(backend) = &self.cache else {
      return Ok(None);
    };
    let backend = backend.clone();
    let key = self.key(&format!("cache:lock:{fill_key}"));
    let token = random_hex(16)?;
    let result = match backend
      .put_if_absent(&key, token.as_bytes(), Some(self.cache_lock))
      .await
    {
      Ok(true) => Ok(Some(SharedCacheLock::new(
        backend,
        key,
        token,
        self.cleanup.clone(),
      ))),
      Ok(false) => Ok(None),
      Err(error) => Err(error.context("failed to acquire shared cache fill lock")),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }

  pub async fn cache_purge_exact(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> anyhow::Result<usize> {
    self
      .cache_purge(|entry| {
        entry.policy == policy
          && entry.scheme == scheme
          && entry.host == host
          && entry.uri == uri
          && partition.is_none_or(|partition| entry.partition == partition)
      })
      .await
  }

  /// Removes only OxiBelt QUERY-v1 cache entries for one target.  This is an
  /// internal invalidation primitive; the public cache-purge API remains
  /// intentionally broad across all cache-key namespaces.
  pub async fn cache_purge_query_exact(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> anyhow::Result<usize> {
    self
      .cache_purge(|entry| {
        entry.policy == policy
          && entry.scheme == scheme
          && entry.host == host
          && entry.uri == uri
          && partition.is_none_or(|partition| entry.partition == partition)
          && crate::cache::is_query_v1_base_key(&entry.base_key)
      })
      .await
  }

  pub async fn cache_purge_prefix(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    path_prefix: &str,
    partition: Option<&str>,
  ) -> anyhow::Result<usize> {
    self
      .cache_purge(|entry| {
        entry.policy == policy
          && entry.scheme == scheme
          && entry.host == host
          && partition.is_none_or(|partition| entry.partition == partition)
          && entry
            .uri
            .parse::<Uri>()
            .ok()
            .is_some_and(|uri| uri.path().starts_with(path_prefix))
      })
      .await
  }

  pub async fn cache_purge_tag(
    &self,
    policy: &str,
    tag: &str,
    scheme: Option<&str>,
    host: Option<&str>,
    partition: Option<&str>,
  ) -> anyhow::Result<usize> {
    self
      .cache_purge(|entry| {
        entry.policy == policy
          && partition.is_none_or(|partition| entry.partition == partition)
          && scheme.is_none_or(|scheme| entry.scheme == scheme)
          && host.is_none_or(|host| entry.host == host)
          && entry.tags.iter().any(|candidate| candidate == tag)
      })
      .await
  }

  async fn cache_purge(
    &self,
    matches: impl Fn(&SharedCacheEntry) -> bool,
  ) -> anyhow::Result<usize> {
    let Some(backend) = &self.cache else {
      return Ok(0);
    };
    let prefix = self.key("cache:entry:");
    let operation = async {
      let mut cursor = None;
      let mut examined = 0_usize;
      let mut purged = 0_usize;
      for _ in 0..self.enumeration.max_rounds() {
        let remaining = self.enumeration.max_items.saturating_sub(examined);
        if remaining == 0 {
          backend.record_enumeration("cache_purge", "cap_exhausted", 1);
          anyhow::bail!("shared cache purge enumeration reached its configured item limit");
        }
        let page = backend
          .enumeration_keys(
            &prefix,
            cursor.as_ref(),
            self.enumeration.page_size.min(remaining).max(1),
            "cache_purge",
          )
          .await?;
        examined = examined.saturating_add(page.keys.len());
        let values = backend
          .enumeration_values(&page.keys, "cache_purge")
          .await?;
        let mut delete_keys = Vec::new();
        for (key, value) in page.keys.iter().zip(values) {
          let Some(value) = value else {
            continue;
          };
          let Ok(entry) = serde_json::from_slice::<SharedCacheEntry>(&value) else {
            continue;
          };
          if matches(&entry) {
            delete_keys.push(key.clone());
            delete_keys.push(self.shared_cache_index_key(&entry));
            delete_keys.extend(entry.body_chunks.iter().cloned());
            purged = purged.saturating_add(1);
          }
        }
        for delete_batch in delete_keys.chunks(self.enumeration.page_size.max(1)) {
          backend
            .enumeration_delete(delete_batch, "cache_purge")
            .await?;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
          return Ok(purged);
        }
      }
      backend.record_enumeration("cache_purge", "cap_exhausted", 1);
      anyhow::bail!("shared cache purge enumeration reached its configured scan-round limit")
    };
    let result = match tokio::time::timeout(self.operation_timeout, operation).await {
      Ok(result) => result,
      Err(_) => Err(anyhow::anyhow!("shared cache purge enumeration timed out")),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }

  async fn shared_cache_entry_to_cache_entry(
    &self,
    entry: &SharedCacheEntry,
  ) -> Option<CacheEntry> {
    if !entry.security_headers_neutral {
      return None;
    }
    if entry.body_chunks.is_empty() {
      return entry.to_cache_entry();
    }
    let backend = self.cache.as_ref()?;
    let headers = shared_entry_headers(entry)?;
    let stored_at = shared_entry_stored_at(entry);
    let file = tempfile::Builder::new()
      .prefix("oxibelt-shared-cache-")
      .tempfile()
      .ok()?;
    let mut writer = tokio::fs::File::from_std(file.reopen().ok()?);
    let mut copied = 0_usize;
    for chunk_key in &entry.body_chunks {
      let chunk = backend.get(chunk_key).await.ok().flatten()?;
      copied = copied.checked_add(chunk.len())?;
      if copied > entry.body_len {
        return None;
      }
      writer.write_all(&chunk).await.ok()?;
    }
    if copied != entry.body_len || writer.flush().await.is_err() {
      return None;
    }
    drop(writer);
    Some(CacheEntry::temporary_file(
      http::StatusCode::from_u16(entry.status).ok()?,
      headers,
      file,
      entry.body_len,
      stored_at,
    ))
  }
}

async fn delete_shared_chunks(backend: &Backend, chunks: &[String]) {
  for chunk_key in chunks {
    let _ = backend.delete(chunk_key).await;
  }
}

impl SharedCacheEntry {
  pub fn to_cache_entry(&self) -> Option<CacheEntry> {
    if !self.security_headers_neutral {
      return None;
    }
    Some(
      CacheEntry::memory(
        http::StatusCode::from_u16(self.status).ok()?,
        shared_entry_headers(self)?,
        bytes::Bytes::from(self.body.clone()),
      )
      .with_stored_at(shared_entry_stored_at(self))
      .with_expires_at(shared_entry_expires_at(self)),
    )
  }
}

fn shared_entry_headers(entry: &SharedCacheEntry) -> Option<HeaderMap> {
  let mut headers = HeaderMap::new();
  for (name, value) in &entry.headers {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    let value = HeaderValue::from_bytes(value).ok()?;
    headers.append(name, value);
  }
  Some(headers)
}

fn shared_entry_stored_at(entry: &SharedCacheEntry) -> std::time::SystemTime {
  std::time::UNIX_EPOCH + std::time::Duration::from_millis(entry.stored_at_ms.max(0) as u64)
}

fn shared_entry_expires_at(entry: &SharedCacheEntry) -> std::time::SystemTime {
  std::time::UNIX_EPOCH + std::time::Duration::from_millis(entry.expires_at_ms.max(0) as u64)
}

/// Q1 entries must survive their stale-while-revalidate window so a later
/// reader can initiate or join its revalidation. Legacy GET/HEAD keeps its
/// established stale-if-error retention bound.
pub(super) fn shared_cache_retention_until_ms(entry: &SharedCacheEntry) -> i64 {
  let mut retention = entry
    .stale_if_error_until_ms
    .unwrap_or(entry.expires_at_ms)
    .max(entry.expires_at_ms);
  if crate::cache::is_query_v1_base_key(&entry.base_key) {
    retention = retention.max(
      entry
        .stale_while_revalidate_until_ms
        .unwrap_or(entry.expires_at_ms),
    );
  }
  retention
}

fn validator_headers(headers: &HeaderMap) -> HeaderMap {
  let mut validators = HeaderMap::new();
  if let Some(etag) = headers.get(http::header::ETAG) {
    validators.insert(http::header::IF_NONE_MATCH, etag.clone());
  }
  if let Some(last_modified) = headers.get(http::header::LAST_MODIFIED) {
    validators.insert(http::header::IF_MODIFIED_SINCE, last_modified.clone());
  }
  validators
}

fn shared_vary_matches(vary: &[SharedVaryMatcher], request_headers: &HeaderMap) -> bool {
  vary
    .iter()
    .all(|item| header_values(request_headers, &item.name) == item.value)
}

struct SharedCacheMatch<'a> {
  policy: &'a str,
  scheme: &'a str,
  host: &'a str,
  partition: &'a str,
  base_key: &'a str,
  uri: &'a str,
  query_target_epoch: Option<u64>,
}

fn shared_entry_matches(entry: &SharedCacheEntry, target: SharedCacheMatch<'_>) -> bool {
  entry.policy == target.policy
    && entry.scheme == target.scheme
    && entry.host == target.host
    && entry.partition == target.partition
    && entry.base_key == target.base_key
    && entry.uri == target.uri
    && (!crate::cache::is_query_v1_base_key(target.base_key)
      || (target.query_target_epoch.is_some()
        && entry.query_target_epoch == target.query_target_epoch))
}

pub fn shared_header_values(headers: &HeaderMap, name: &str) -> String {
  header_values(headers, name)
}

fn header_values(headers: &HeaderMap, name: &str) -> String {
  HeaderName::from_bytes(name.as_bytes())
    .ok()
    .map(|name| {
      headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
    })
    .unwrap_or_default()
}

pub(super) fn shared_cache_chunk_stem(variant_key: &str) -> String {
  digest_hex(variant_key.as_bytes())
}

fn shared_no_vary_variant_key(partition: &str, base_key: &str) -> String {
  format!("partition={partition}\n{base_key}")
}

fn digest_hex(bytes: &[u8]) -> String {
  super::hex_encode(&crate::crypto::sha256(bytes))
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::{HeaderMap, Method};

  fn entry(query_target_epoch: Option<u64>) -> SharedCacheEntry {
    SharedCacheEntry {
      policy: "default".to_string(),
      partition: String::new(),
      base_key: match query_target_epoch {
        Some(_) => "\0oxibelt-cache-query-v1\0fixture".to_string(),
        None => "fixture".to_string(),
      },
      variant_key: "fixture".to_string(),
      scheme: "https".to_string(),
      host: "example.test".to_string(),
      uri: "/asset".to_string(),
      status: 200,
      headers: Vec::new(),
      security_headers_neutral: true,
      body: Vec::new(),
      body_len: 0,
      body_chunks: Vec::new(),
      stored_at_ms: 0,
      expires_at_ms: 100,
      stale_if_error_until_ms: Some(200),
      stale_while_revalidate_until_ms: Some(300),
      must_revalidate: false,
      vary: Vec::new(),
      tags: Vec::new(),
      query_target_epoch,
    }
  }

  #[test]
  fn q1_shared_entry_retains_its_stale_while_revalidate_window() {
    assert_eq!(shared_cache_retention_until_ms(&entry(Some(0))), 300);
    assert_eq!(shared_cache_retention_until_ms(&entry(None)), 200);
  }

  #[test]
  fn q1_shared_storage_keys_are_text_safe_and_match_direct_lookup() {
    let shared = SharedState::test_memory("q1-shared-storage-key");
    let mut query_entry = entry(Some(7));
    query_entry.variant_key = shared_no_vary_variant_key("", &query_entry.base_key);

    let storage_variant = shared.shared_cache_storage_variant_key(&query_entry);
    assert!(!storage_variant.contains('\0'));
    assert_eq!(storage_variant.len(), "q1-epoch:7:".len() + 64);
    assert_eq!(
      shared.shared_cache_entry_key(&query_entry.variant_key, Some(7)),
      shared.shared_cache_entry_key_from_storage(&storage_variant)
    );
  }

  #[tokio::test]
  async fn q1_shared_lookup_serves_stale_during_its_swr_window() {
    let shared = SharedState::test_memory("q1-shared-swr");
    let now = now_unix_ms();
    let mut stale_entry = entry(Some(0));
    stale_entry.variant_key = shared_no_vary_variant_key("", &stale_entry.base_key);
    stale_entry.expires_at_ms = now.saturating_sub(1);
    stale_entry.stale_if_error_until_ms = None;
    stale_entry.stale_while_revalidate_until_ms = Some(now.saturating_add(60_000));
    shared.cache_put(&stale_entry).await;

    let headers = HeaderMap::new();
    let lookup = shared
      .cache_lookup(
        "default",
        "https",
        "example.test",
        "",
        &stale_entry.base_key,
        "/asset",
        &Method::GET,
        &headers,
        false,
        true,
        1,
        Some(0),
      )
      .await
      .expect("shared Q1 lookup should not fail");
    assert!(matches!(lookup, Some(CacheLookup::Stale(_))));
  }

  #[tokio::test]
  async fn q1_no_cache_without_validators_never_uses_swr() {
    let shared = SharedState::test_memory("q1-shared-swr-no-cache");
    let now = now_unix_ms();
    let mut stale_entry = entry(Some(0));
    stale_entry.variant_key = shared_no_vary_variant_key("", &stale_entry.base_key);
    stale_entry.expires_at_ms = now.saturating_sub(1);
    stale_entry.stale_if_error_until_ms = None;
    stale_entry.stale_while_revalidate_until_ms = Some(now.saturating_add(60_000));
    shared.cache_put(&stale_entry).await;

    let headers = HeaderMap::new();
    let lookup = shared
      .cache_lookup(
        "default",
        "https",
        "example.test",
        "",
        &stale_entry.base_key,
        "/asset",
        &Method::GET,
        &headers,
        true,
        true,
        1,
        Some(0),
      )
      .await
      .expect("shared Q1 no-cache lookup should not fail");
    assert!(lookup.is_none());
  }
}
