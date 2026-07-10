//! Shared cache-store abstractions.
//! Serialized cache entries keep HTTP metadata separate from backend storage details.

use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::warn;

use crate::cache::{CacheEntry, CacheLookup, Revalidation, StaleEntry};

use super::{
  Backend, CleanupDispatcher, SharedCacheEntry, SharedState, SharedVaryMatcher, now_unix_ms,
  random_hex,
};

impl SharedState {
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
  ) -> anyhow::Result<Option<CacheLookup>> {
    let Some(backend) = &self.cache else {
      return Ok(None);
    };
    let now = now_unix_ms();
    let direct_variant_key = shared_no_vary_variant_key(partition, base_key);
    let direct_key = self.shared_cache_entry_key(&direct_variant_key);
    if let Some(bytes) = backend.get(&direct_key).await?
      && let Ok(entry) = serde_json::from_slice::<SharedCacheEntry>(&bytes)
      && entry.vary.is_empty()
      && shared_entry_matches(&entry, policy, scheme, host, partition, base_key, uri)
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
    for (index_key, value) in backend.raw_entries(&index_prefix).await? {
      let Ok(variant_key) = String::from_utf8(value) else {
        let _ = backend.delete(&index_key).await;
        continue;
      };
      let entry_key = self.shared_cache_entry_key(&variant_key);
      let Some(bytes) = backend.get(&entry_key).await? else {
        let _ = backend.delete(&index_key).await;
        continue;
      };
      let Ok(entry) = serde_json::from_slice::<SharedCacheEntry>(&bytes) else {
        let _ = backend.delete(&index_key).await;
        continue;
      };
      if !shared_entry_matches(&entry, policy, scheme, host, partition, base_key, uri)
        || !shared_vary_matches(&entry.vary, request_headers)
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
        return Ok(Some(lookup));
      }
    }

    let entries = backend.cache_entries(&self.key("cache:entry:")).await?;
    for entry in entries {
      if !shared_entry_matches(&entry, policy, scheme, host, partition, base_key, uri)
        || !shared_vary_matches(&entry.vary, request_headers)
      {
        continue;
      }
      self.cache_put_index(&entry).await;
      let entry_key = self.shared_cache_entry_key(&entry.variant_key);
      let index_key = self.shared_cache_index_key(&entry);
      return self
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
        .await;
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
    if entry.stale_if_error_until_ms.unwrap_or(entry.expires_at_ms) <= now {
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
        serve_stale_on_error: entry
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
    if let Err(error) = result {
      warn!(error = %error, "failed to write shared cache entry");
    }
  }

  async fn cache_put_inner(
    &self,
    backend: &Backend,
    entry: &SharedCacheEntry,
  ) -> anyhow::Result<()> {
    let ttl = super::ttl_from_expires_ms(
      entry
        .stale_if_error_until_ms
        .unwrap_or(entry.expires_at_ms)
        .max(entry.expires_at_ms),
    );
    let key = self.key(&format!("cache:entry:{}", entry.variant_key));
    let mut entry = entry.clone();
    entry.body_len = entry.body.len();
    if entry.body.len() > self.cache_chunk_bytes {
      let chunk_ttl = ttl;
      let stem = shared_cache_chunk_stem(&entry.variant_key);
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
    let ttl = super::ttl_from_expires_ms(
      entry
        .stale_if_error_until_ms
        .unwrap_or(entry.expires_at_ms)
        .max(entry.expires_at_ms),
    );
    let mut file = tokio::fs::File::open(body_path).await?;
    let stem = shared_cache_chunk_stem(&entry.variant_key);
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
    let key = self.shared_cache_entry_key(&entry.variant_key);
    let mut entry = entry.clone();
    entry.body.clear();
    entry.body_len = body_len;
    entry.body_chunks = chunks;
    let value = serde_json::to_vec(&entry)?;
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
    let ttl = super::ttl_from_expires_ms(
      entry
        .stale_if_error_until_ms
        .unwrap_or(entry.expires_at_ms)
        .max(entry.expires_at_ms),
    );
    let key = self.shared_cache_index_key(entry);
    if let Err(error) = backend.put(&key, entry.variant_key.as_bytes(), ttl).await {
      warn!(error = %error, "failed to write shared cache index");
    }
  }

  fn shared_cache_entry_key(&self, variant_key: &str) -> String {
    self.key(&format!("cache:entry:{variant_key}"))
  }

  fn shared_cache_index_key(&self, entry: &SharedCacheEntry) -> String {
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
    match backend
      .put_if_absent(&key, token.as_bytes(), Some(self.cache_lock))
      .await
    {
      Ok(true) => Ok(Some(SharedCacheLock {
        backend,
        key,
        token,
        cleanup: self.cleanup.clone(),
        released: false,
      })),
      Ok(false) => Ok(None),
      Err(error) => Err(error.context("failed to acquire shared cache fill lock")),
    }
  }

  pub async fn cache_purge_exact(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> usize {
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

  pub async fn cache_purge_prefix(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    path_prefix: &str,
    partition: Option<&str>,
  ) -> usize {
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
  ) -> usize {
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

  async fn cache_purge(&self, matches: impl Fn(&SharedCacheEntry) -> bool) -> usize {
    let Some(backend) = &self.cache else {
      return 0;
    };
    let Ok(entries) = backend
      .cache_entries_with_keys(&self.key("cache:entry:"))
      .await
    else {
      return 0;
    };
    let mut purged = 0;
    for (key, entry) in entries {
      if matches(&entry) && backend.delete(&key).await.is_ok() {
        let _ = backend.delete(&self.shared_cache_index_key(&entry)).await;
        for chunk_key in &entry.body_chunks {
          let _ = backend.delete(chunk_key).await;
        }
        purged += 1;
      }
    }
    purged
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

#[derive(Debug)]
pub struct SharedCacheLock {
  backend: Arc<Backend>,
  key: String,
  token: String,
  cleanup: Arc<CleanupDispatcher>,
  released: bool,
}

impl SharedCacheLock {
  pub async fn unlock(&mut self) -> anyhow::Result<()> {
    if self.released {
      return Ok(());
    }
    self.backend.unlock(&self.key, &self.token).await?;
    self.released = true;
    Ok(())
  }
}

impl Drop for SharedCacheLock {
  fn drop(&mut self) {
    if !self.released {
      self
        .cleanup
        .defer_unlock(self.backend.clone(), self.key.clone(), self.token.clone());
    }
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
      .with_stored_at(shared_entry_stored_at(self)),
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

fn shared_entry_matches(
  entry: &SharedCacheEntry,
  policy: &str,
  scheme: &str,
  host: &str,
  partition: &str,
  base_key: &str,
  uri: &str,
) -> bool {
  entry.policy == policy
    && entry.scheme == scheme
    && entry.host == host
    && entry.partition == partition
    && entry.base_key == base_key
    && entry.uri == uri
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

fn shared_cache_chunk_stem(variant_key: &str) -> String {
  digest_hex(variant_key.as_bytes())
}

fn shared_no_vary_variant_key(partition: &str, base_key: &str) -> String {
  format!("partition={partition}\n{base_key}")
}

fn digest_hex(bytes: &[u8]) -> String {
  super::hex_encode(&crate::crypto::sha256(bytes))
}
