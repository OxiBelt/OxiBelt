use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use ring::digest;
use std::sync::Arc;
use tracing::warn;

use crate::cache::{CacheEntry, CacheLookup, Revalidation, StaleEntry};

use super::{Backend, SharedCacheEntry, SharedState, SharedVaryMatcher, now_unix_ms, random_hex};

impl SharedState {
  #[allow(clippy::too_many_arguments)]
  pub fn cache_lookup(
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
    if let Some(bytes) = backend.get(&direct_key)?
      && let Ok(entry) = serde_json::from_slice::<SharedCacheEntry>(&bytes)
      && entry.vary.is_empty()
      && shared_entry_matches(&entry, policy, scheme, host, partition, base_key, uri)
      && let Some(lookup) = self.cache_lookup_entry(
        backend,
        Some(&direct_key),
        None,
        entry,
        method,
        request_headers,
        request_no_cache,
        background_refresh,
        now,
      )?
    {
      return Ok(Some(lookup));
    }

    let index_prefix =
      self.shared_cache_index_prefix(policy, scheme, host, partition, base_key, uri);
    for (index_key, value) in backend.raw_entries(&index_prefix)? {
      let Ok(variant_key) = String::from_utf8(value) else {
        let _ = backend.delete(&index_key);
        continue;
      };
      let entry_key = self.shared_cache_entry_key(&variant_key);
      let Some(bytes) = backend.get(&entry_key)? else {
        let _ = backend.delete(&index_key);
        continue;
      };
      let Ok(entry) = serde_json::from_slice::<SharedCacheEntry>(&bytes) else {
        let _ = backend.delete(&index_key);
        continue;
      };
      if !shared_entry_matches(&entry, policy, scheme, host, partition, base_key, uri)
        || !shared_vary_matches(&entry.vary, request_headers)
      {
        continue;
      }
      if let Some(lookup) = self.cache_lookup_entry(
        backend,
        Some(&entry_key),
        Some(&index_key),
        entry,
        method,
        request_headers,
        request_no_cache,
        background_refresh,
        now,
      )? {
        return Ok(Some(lookup));
      }
    }

    let entries = backend.cache_entries(&self.key("cache:entry:"))?;
    for entry in entries {
      if !shared_entry_matches(&entry, policy, scheme, host, partition, base_key, uri)
        || !shared_vary_matches(&entry.vary, request_headers)
      {
        continue;
      }
      self.cache_put_index(&entry);
      let entry_key = self.shared_cache_entry_key(&entry.variant_key);
      let index_key = self.shared_cache_index_key(&entry);
      return self.cache_lookup_entry(
        backend,
        Some(&entry_key),
        Some(&index_key),
        entry,
        method,
        request_headers,
        request_no_cache,
        background_refresh,
        now,
      );
    }
    Ok(None)
  }

  #[allow(clippy::too_many_arguments)]
  fn cache_lookup_entry(
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
        let _ = backend.delete(entry_key);
      }
      if let Some(index_key) = index_key {
        let _ = backend.delete(index_key);
      }
      for chunk_key in &entry.body_chunks {
        let _ = backend.delete(chunk_key);
      }
      return Ok(None);
    }
    let Some(cache_entry) = self.shared_cache_entry_to_cache_entry(&entry) else {
      if let Some(entry_key) = entry_key {
        let _ = backend.delete(entry_key);
      }
      if let Some(index_key) = index_key {
        let _ = backend.delete(index_key);
      }
      return Ok(None);
    };
    if method == Method::HEAD {
      return Ok(Some(CacheLookup::Fresh(CacheEntry {
        body: bytes::Bytes::new(),
        ..cache_entry
      })));
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

  pub fn cache_put(&self, entry: &SharedCacheEntry) {
    let Some(backend) = &self.cache else {
      return;
    };
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
        if let Err(error) = backend.put(&chunk_key, chunk, chunk_ttl) {
          warn!(error = %error, "failed to write shared cache body chunk");
          return;
        }
        chunks.push(chunk_key);
      }
      entry.body.clear();
      entry.body_chunks = chunks;
    }
    match serde_json::to_vec(&entry)
      .map_err(Into::into)
      .and_then(|value| backend.put(&key, &value, ttl))
    {
      Ok(()) => self.cache_put_index(&entry),
      Err(error) => warn!(error = %error, "failed to write shared cache entry"),
    }
  }

  fn cache_put_index(&self, entry: &SharedCacheEntry) {
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
    if let Err(error) = backend.put(&key, entry.variant_key.as_bytes(), ttl) {
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

  pub fn cache_try_lock(&self, fill_key: &str) -> Option<SharedCacheLock> {
    self.cache_try_lock_result(fill_key).ok().flatten()
  }

  pub fn cache_try_lock_result(&self, fill_key: &str) -> anyhow::Result<Option<SharedCacheLock>> {
    let Some(backend) = &self.cache else {
      return Ok(None);
    };
    let backend = backend.clone();
    let key = self.key(&format!("cache:lock:{fill_key}"));
    let token = random_hex(16)?;
    match backend.put_if_absent(&key, token.as_bytes(), Some(self.cache_lock)) {
      Ok(true) => Ok(Some(SharedCacheLock {
        backend,
        key,
        token,
      })),
      Ok(false) => Ok(None),
      Err(error) => Err(error.context("failed to acquire shared cache fill lock")),
    }
  }

  pub fn cache_purge_exact(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> usize {
    self.cache_purge(|entry| {
      entry.policy == policy
        && entry.scheme == scheme
        && entry.host == host
        && entry.uri == uri
        && partition.is_none_or(|partition| entry.partition == partition)
    })
  }

  pub fn cache_purge_prefix(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    path_prefix: &str,
    partition: Option<&str>,
  ) -> usize {
    self.cache_purge(|entry| {
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
  }

  pub fn cache_purge_tag(
    &self,
    policy: &str,
    tag: &str,
    scheme: Option<&str>,
    host: Option<&str>,
    partition: Option<&str>,
  ) -> usize {
    self.cache_purge(|entry| {
      entry.policy == policy
        && partition.is_none_or(|partition| entry.partition == partition)
        && scheme.is_none_or(|scheme| entry.scheme == scheme)
        && host.is_none_or(|host| entry.host == host)
        && entry.tags.iter().any(|candidate| candidate == tag)
    })
  }

  fn cache_purge(&self, matches: impl Fn(&SharedCacheEntry) -> bool) -> usize {
    let Some(backend) = &self.cache else {
      return 0;
    };
    let Ok(entries) = backend.cache_entries_with_keys(&self.key("cache:entry:")) else {
      return 0;
    };
    let mut purged = 0;
    for (key, entry) in entries {
      if matches(&entry) && backend.delete(&key).is_ok() {
        let _ = backend.delete(&self.shared_cache_index_key(&entry));
        for chunk_key in &entry.body_chunks {
          let _ = backend.delete(chunk_key);
        }
        purged += 1;
      }
    }
    purged
  }

  fn shared_cache_entry_to_cache_entry(&self, entry: &SharedCacheEntry) -> Option<CacheEntry> {
    if entry.body_chunks.is_empty() {
      return entry.to_cache_entry();
    }
    let backend = self.cache.as_ref()?;
    let mut body = Vec::with_capacity(entry.body_len);
    for chunk_key in &entry.body_chunks {
      let chunk = backend.get(chunk_key).ok().flatten()?;
      body.extend_from_slice(&chunk);
    }
    let mut entry = entry.clone();
    entry.body = body;
    entry.to_cache_entry()
  }
}

#[derive(Debug)]
pub struct SharedCacheLock {
  backend: Arc<Backend>,
  key: String,
  token: String,
}

impl Drop for SharedCacheLock {
  fn drop(&mut self) {
    if let Err(error) = self.backend.unlock(&self.key, &self.token) {
      warn!(error = %error, "failed to release shared cache fill lock");
    }
  }
}

impl SharedCacheEntry {
  pub fn to_cache_entry(&self) -> Option<CacheEntry> {
    let mut headers = HeaderMap::new();
    for (name, value) in &self.headers {
      let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
      let value = HeaderValue::from_bytes(value).ok()?;
      headers.append(name, value);
    }
    Some(CacheEntry {
      status: http::StatusCode::from_u16(self.status).ok()?,
      headers,
      body: bytes::Bytes::from(self.body.clone()),
    })
  }
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
  super::hex_encode(digest::digest(&digest::SHA256, bytes).as_ref())
}
