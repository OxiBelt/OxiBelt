use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use bytes::Bytes;
use http::header::{
  ACCEPT_RANGES, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
  EXPIRES, HeaderName, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, PRAGMA, RANGE,
  VARY,
};
use http::{HeaderMap, Method, StatusCode, Uri};
use ring::digest;
use tokio::sync::Notify;
use tracing::warn;

use crate::config::{CacheConfig, CachePolicyConfig, CacheStore, default_cache_tmpfs_dir};
use crate::shared_state::{SharedCacheEntry, SharedCacheLock, SharedState, SharedVaryMatcher};

#[derive(Debug, Clone)]
pub struct CacheEntry {
  pub status: StatusCode,
  pub headers: HeaderMap,
  pub body: Bytes,
}

#[derive(Debug, Clone)]
pub struct Revalidation {
  pub entry: CacheEntry,
  pub request_headers: HeaderMap,
  pub serve_stale_on_error: bool,
}

#[derive(Debug, Clone)]
pub enum CacheLookup {
  Fresh(CacheEntry),
  Stale(CacheEntry),
  Revalidate(Revalidation),
}

#[derive(Debug)]
pub enum CacheFillPermit {
  Leader(CacheFillGuard),
  Follower(CacheFillWaiter),
}

#[derive(Debug)]
pub struct CacheFillGuard {
  cache: Weak<ResponseCache>,
  key: String,
  notify: Arc<Notify>,
  _shared_lock: Option<SharedCacheLock>,
}

#[derive(Debug, Clone)]
pub struct CacheFillWaiter {
  notify: Arc<Notify>,
}

impl CacheFillWaiter {
  pub async fn wait(self) {
    self.notify.notified().await;
  }
}

impl Drop for CacheFillGuard {
  fn drop(&mut self) {
    let Some(cache) = self.cache.upgrade() else {
      self.notify.notify_waiters();
      return;
    };
    let notify = {
      let mut inner = cache.inner.lock().expect("cache lock poisoned");
      inner
        .inflight
        .remove(&self.key)
        .unwrap_or_else(|| self.notify.clone())
    };
    notify.notify_waiters();
  }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
  pub memory_entries: usize,
  pub disk_entries: usize,
  pub tmpfs_entries: usize,
  pub memory_bytes: usize,
  pub disk_bytes: usize,
  pub tmpfs_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct CacheInsertContext<'a> {
  pub policy_name: Option<&'a str>,
  pub scheme: &'a str,
  pub host: &'a str,
  pub method: &'a Method,
  pub uri: &'a Uri,
  pub request_headers: &'a HeaderMap,
}

#[derive(Debug, Clone)]
pub struct CacheLookupContext<'a> {
  pub policy_name: Option<&'a str>,
  pub scheme: &'a str,
  pub host: &'a str,
  pub method: &'a Method,
  pub uri: &'a Uri,
  pub request_headers: &'a HeaderMap,
}

#[derive(Debug)]
struct StoredEntry {
  policy: String,
  base_key: String,
  variant_key: String,
  scheme: String,
  host: String,
  uri: String,
  status: StatusCode,
  headers: HeaderMap,
  body: StoredBody,
  expires_at: SystemTime,
  stale_if_error_until: Option<SystemTime>,
  stale_while_revalidate_until: Option<SystemTime>,
  must_revalidate: bool,
  vary: Vec<VaryMatcher>,
  size: usize,
}

#[derive(Debug)]
enum StoredBody {
  Memory(Bytes),
  Tmpfs(PathBuf),
  Disk(PathBuf),
}

#[derive(Debug, Clone)]
struct VaryMatcher {
  name: String,
  value: String,
}

#[derive(Debug, Default)]
struct CacheInner {
  entries: HashMap<String, StoredEntry>,
  inflight: HashMap<String, Arc<Notify>>,
  order: VecDeque<String>,
  memory_size: usize,
  disk_size: usize,
  tmpfs_size: usize,
}

#[derive(Debug, Clone)]
struct CachePolicyRuntime {
  name: String,
  store: CacheStore,
  cache_key: String,
  default_ttl_seconds: u64,
  memory_max_size_bytes: usize,
  disk_max_size_bytes: Option<usize>,
  rules: Vec<CachePolicyRuleRuntime>,
}

#[derive(Debug, Clone)]
struct CachePolicyRuleRuntime {
  mime_types: Vec<String>,
  store: CacheStore,
}

#[derive(Debug)]
pub struct ResponseCache {
  config: CacheConfig,
  policies: HashMap<String, CachePolicyRuntime>,
  tmpfs_dir: Option<PathBuf>,
  disk_dir: Option<PathBuf>,
  inner: Mutex<CacheInner>,
  shared_state: Option<Arc<SharedState>>,
}

impl ResponseCache {
  pub fn new(
    config: &CacheConfig,
    shared_state: Option<Arc<SharedState>>,
  ) -> anyhow::Result<Arc<Self>> {
    let tmpfs_dir = if config.enabled && config.store == CacheStore::Tmpfs {
      let dir = config
        .tmpfs_dir
        .clone()
        .unwrap_or_else(default_cache_tmpfs_dir);
      validate_tmpfs_dir(&dir)?;
      Some(dir)
    } else {
      None
    };
    let disk_dir = if config.enabled && config.store.uses_disk() {
      let dir = config
        .disk_dir
        .clone()
        .ok_or_else(|| anyhow!("cache.disk_dir is required when cache.store uses disk"))?;
      validate_disk_dir(&dir)?;
      Some(dir)
    } else {
      config.disk_dir.clone()
    };

    let default_memory_limit = config
      .memory_max_size_bytes
      .unwrap_or_else(|| auto_memory_cache_limit(config));
    let default_policy = CachePolicyRuntime {
      name: "default".to_string(),
      store: config.store,
      cache_key: config.cache_key.clone(),
      default_ttl_seconds: config.default_ttl_seconds,
      memory_max_size_bytes: default_memory_limit,
      disk_max_size_bytes: config.disk_max_size_bytes,
      rules: Vec::new(),
    };
    let mut policies = HashMap::new();
    policies.insert(default_policy.name.clone(), default_policy);
    for policy in &config.policies {
      let runtime = policy_runtime(config, policy, default_memory_limit);
      policies.insert(runtime.name.clone(), runtime);
    }

    let cache = Arc::new(Self {
      config: config.clone(),
      policies,
      tmpfs_dir,
      disk_dir,
      inner: Mutex::new(CacheInner::default()),
      shared_state,
    });
    cache.load_disk_entries();
    Ok(cache)
  }

  pub fn enabled(&self) -> bool {
    self.config.enabled
  }

  pub fn policy_enabled(&self, policy_name: Option<&str>, method: &Method) -> bool {
    self.config.enabled && self.policy(policy_name).is_some() && self.is_cacheable_method(method)
  }

  pub fn is_cacheable_method(&self, method: &Method) -> bool {
    self
      .config
      .cache_methods
      .iter()
      .any(|item| item.eq_ignore_ascii_case(method.as_str()))
  }

  pub fn lookup(&self, ctx: CacheLookupContext<'_>) -> Option<CacheLookup> {
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return None;
    }
    if request_no_store(ctx.request_headers) {
      return None;
    }
    let policy = self.policy(ctx.policy_name)?;
    let base_key = expanded_cache_key(
      &policy.cache_key,
      ctx.scheme,
      ctx.host,
      ctx.uri,
      ctx.request_headers,
    );
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    let now = SystemTime::now();
    let key = inner
      .entries
      .iter()
      .find(|(_, entry)| {
        entry.policy == policy.name
          && entry.base_key == base_key
          && entry.scheme == ctx.scheme
          && entry.host == ctx.host
          && entry.uri == ctx.uri.to_string()
          && vary_matches(&entry.vary, ctx.request_headers)
      })
      .map(|(key, _)| key.clone());
    let Some(key) = key else {
      drop(inner);
      return self.lookup_shared(&policy.name, &base_key, ctx);
    };

    let expired = inner
      .entries
      .get(&key)
      .is_some_and(|entry| entry.stale_if_error_until.unwrap_or(entry.expires_at) <= now);
    if expired {
      remove_entry(&mut inner, &key);
      return None;
    }
    let entry = inner.entries.get(&key)?;
    let cache_entry = entry.to_cache_entry()?;
    if request_no_cache(ctx.request_headers) || entry.must_revalidate || entry.expires_at <= now {
      let validators = validator_headers(&entry.headers);
      if validators.is_empty() {
        if entry
          .stale_while_revalidate_until
          .is_some_and(|until| until > now)
          || entry.stale_if_error_until.is_some_and(|until| until > now)
        {
          return Some(CacheLookup::Stale(cache_entry));
        }
        return None;
      }
      return Some(CacheLookup::Revalidate(Revalidation {
        entry: cache_entry,
        request_headers: validators,
        serve_stale_on_error: entry.stale_if_error_until.is_some_and(|until| until > now),
      }));
    }
    Some(CacheLookup::Fresh(cache_entry))
  }

  fn lookup_shared(
    &self,
    policy: &str,
    base_key: &str,
    ctx: CacheLookupContext<'_>,
  ) -> Option<CacheLookup> {
    let shared = self.shared_state.as_ref()?;
    if !shared.has_cache() {
      return None;
    }
    let uri = ctx.uri.to_string();
    match shared.cache_lookup(
      policy,
      ctx.scheme,
      ctx.host,
      base_key,
      &uri,
      ctx.method,
      ctx.request_headers,
      request_no_cache(ctx.request_headers),
    ) {
      Ok(Some(lookup)) => {
        self.promote_shared_lookup(ctx, &lookup);
        Some(lookup)
      }
      Ok(None) => None,
      Err(error) => {
        warn!(error = %error, "shared cache lookup failed; falling back to local miss");
        None
      }
    }
  }

  fn promote_shared_lookup(&self, ctx: CacheLookupContext<'_>, lookup: &CacheLookup) {
    let entry = match lookup {
      CacheLookup::Fresh(entry) | CacheLookup::Stale(entry) => entry.clone(),
      CacheLookup::Revalidate(revalidation) => revalidation.entry.clone(),
    };
    self.insert(
      CacheInsertContext {
        policy_name: ctx.policy_name,
        scheme: ctx.scheme,
        host: ctx.host,
        method: ctx.method,
        uri: ctx.uri,
        request_headers: ctx.request_headers,
      },
      entry,
    );
  }

  pub fn begin_fill(self: &Arc<Self>, ctx: CacheLookupContext<'_>) -> Option<CacheFillPermit> {
    if !self.config.lock {
      return None;
    }
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return None;
    }
    if request_no_store(ctx.request_headers) {
      return None;
    }
    let key = self.fill_key(ctx)?;
    let shared_lock = self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
      .and_then(|shared| shared.cache_try_lock(&key));
    if self
      .shared_state
      .as_ref()
      .is_some_and(|shared| shared.has_cache())
      && shared_lock.is_none()
    {
      return None;
    }
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    if let Some(notify) = inner.inflight.get(&key) {
      return Some(CacheFillPermit::Follower(CacheFillWaiter {
        notify: notify.clone(),
      }));
    }
    let notify = Arc::new(Notify::new());
    inner.inflight.insert(key.clone(), notify.clone());
    Some(CacheFillPermit::Leader(CacheFillGuard {
      cache: Arc::downgrade(self),
      key,
      notify,
      _shared_lock: shared_lock,
    }))
  }

  pub fn insert(&self, ctx: CacheInsertContext<'_>, entry: CacheEntry) {
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return;
    }
    if request_no_store(ctx.request_headers) {
      return;
    }
    let Some(policy) = self.policy(ctx.policy_name).cloned() else {
      return;
    };
    let Some(metadata) = cache_metadata(&self.config, &policy, ctx.request_headers, &entry) else {
      return;
    };
    let base_key = expanded_cache_key(
      &policy.cache_key,
      ctx.scheme,
      ctx.host,
      ctx.uri,
      ctx.request_headers,
    );
    let variant_key = variant_key(&base_key, &metadata.vary);
    let size = entry.body.len() + header_size(&entry.headers);
    if size > self.config.max_size_bytes {
      return;
    }

    let mut inner = self.inner.lock().expect("cache lock poisoned");
    remove_entry(&mut inner, &variant_key);
    let selected_store = select_store(&policy, &entry.headers);
    let Some(body) = self.store_body(
      &mut inner,
      &policy,
      selected_store,
      &variant_key,
      &entry.body,
      size,
    ) else {
      return;
    };
    let stored = StoredEntry {
      policy: policy.name.clone(),
      base_key,
      variant_key: variant_key.clone(),
      scheme: ctx.scheme.to_string(),
      host: ctx.host.to_string(),
      uri: ctx.uri.to_string(),
      status: entry.status,
      headers: entry.headers,
      body,
      expires_at: metadata.expires_at,
      stale_if_error_until: metadata.stale_if_error_until,
      stale_while_revalidate_until: metadata.stale_while_revalidate_until,
      must_revalidate: metadata.must_revalidate,
      vary: metadata.vary,
      size,
    };
    if let Err(error) = self.persist_metadata(&stored) {
      warn!(error = %error, "failed to persist cache metadata");
      if matches!(stored.body, StoredBody::Disk(_)) {
        stored.remove_body();
        return;
      }
    }
    if let Some(shared) = &self.shared_state
      && shared.has_cache()
      && let Some(shared_entry) = shared_cache_entry(&stored)
    {
      shared.cache_put(&shared_entry);
    }
    add_size(&mut inner, &stored);
    inner.order.push_back(variant_key.clone());
    inner.entries.insert(variant_key, stored);
    self.evict_if_needed(&mut inner, &policy);
  }

  pub fn update_from_not_modified(
    &self,
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
    self.insert(
      ctx,
      CacheEntry {
        status: cached_entry.status,
        headers,
        body: cached_entry.body.clone(),
      },
    );
  }

  pub fn purge_exact(&self, policy: &str, scheme: &str, host: &str, uri: &str) -> usize {
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    let keys = inner
      .entries
      .iter()
      .filter(|(_, entry)| {
        entry.policy == policy && entry.scheme == scheme && entry.host == host && entry.uri == uri
      })
      .map(|(key, _)| key.clone())
      .collect::<Vec<_>>();
    let count = keys.len();
    for key in keys {
      remove_entry(&mut inner, &key);
    }
    count
      + self
        .shared_state
        .as_ref()
        .filter(|shared| shared.has_cache())
        .map(|shared| shared.cache_purge_exact(policy, scheme, host, uri))
        .unwrap_or(0)
  }

  pub fn purge_prefix(&self, policy: &str, scheme: &str, host: &str, path_prefix: &str) -> usize {
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    let keys = inner
      .entries
      .iter()
      .filter(|(_, entry)| {
        entry.policy == policy
          && entry.scheme == scheme
          && entry.host == host
          && entry
            .uri
            .parse::<Uri>()
            .ok()
            .is_some_and(|uri| uri.path().starts_with(path_prefix))
      })
      .map(|(key, _)| key.clone())
      .collect::<Vec<_>>();
    let count = keys.len();
    for key in keys {
      remove_entry(&mut inner, &key);
    }
    count
      + self
        .shared_state
        .as_ref()
        .filter(|shared| shared.has_cache())
        .map(|shared| shared.cache_purge_prefix(policy, scheme, host, path_prefix))
        .unwrap_or(0)
  }

  pub fn stats(&self) -> CacheStats {
    let inner = self.inner.lock().expect("cache lock poisoned");
    let mut stats = CacheStats {
      memory_bytes: inner.memory_size,
      disk_bytes: inner.disk_size,
      tmpfs_bytes: inner.tmpfs_size,
      ..CacheStats::default()
    };
    for entry in inner.entries.values() {
      match entry.body {
        StoredBody::Memory(_) => stats.memory_entries += 1,
        StoredBody::Tmpfs(_) => stats.tmpfs_entries += 1,
        StoredBody::Disk(_) => stats.disk_entries += 1,
      }
    }
    stats
  }

  fn policy(&self, policy_name: Option<&str>) -> Option<&CachePolicyRuntime> {
    let name = policy_name.unwrap_or("default");
    self.policies.get(name)
  }

  fn fill_key(&self, ctx: CacheLookupContext<'_>) -> Option<String> {
    let policy = self.policy(ctx.policy_name)?;
    let base_key = expanded_cache_key(
      &policy.cache_key,
      ctx.scheme,
      ctx.host,
      ctx.uri,
      ctx.request_headers,
    );
    Some(format!(
      "{}\n{}\n{}\n{}\n{}",
      policy.name,
      ctx.method.as_str(),
      ctx.scheme,
      ctx.host,
      base_key
    ))
  }

  fn store_body(
    &self,
    inner: &mut CacheInner,
    policy: &CachePolicyRuntime,
    store: CacheStore,
    key: &str,
    body: &Bytes,
    size: usize,
  ) -> Option<StoredBody> {
    match store {
      CacheStore::Memory => {
        if size > policy.memory_max_size_bytes {
          return None;
        }
        Some(StoredBody::Memory(body.clone()))
      }
      CacheStore::Tmpfs => {
        if size > policy.memory_max_size_bytes {
          return None;
        }
        let dir = self.tmpfs_dir.as_ref()?;
        write_body_file(dir, key, body).map(StoredBody::Tmpfs)
      }
      CacheStore::Disk => {
        if policy.disk_max_size_bytes.is_some_and(|limit| size > limit) {
          return None;
        }
        let dir = self.disk_dir.as_ref()?;
        write_body_file(dir, key, body).map(StoredBody::Disk)
      }
      CacheStore::MemoryThenDisk => {
        if inner.memory_size + size <= policy.memory_max_size_bytes {
          return Some(StoredBody::Memory(body.clone()));
        }
        if policy.disk_max_size_bytes.is_some_and(|limit| size > limit) {
          return None;
        }
        let dir = self.disk_dir.as_ref()?;
        write_body_file(dir, key, body).map(StoredBody::Disk)
      }
    }
  }

  fn evict_if_needed(&self, inner: &mut CacheInner, policy: &CachePolicyRuntime) {
    while inner.memory_size > policy.memory_max_size_bytes
      || self
        .config
        .disk_max_size_bytes
        .is_some_and(|limit| inner.disk_size > limit)
      || policy
        .disk_max_size_bytes
        .is_some_and(|limit| inner.disk_size > limit)
      || inner.tmpfs_size > policy.memory_max_size_bytes
      || total_size(inner) > self.config.max_size_bytes
    {
      let Some(oldest) = inner.order.pop_front() else {
        break;
      };
      if let Some(removed) = inner.entries.remove(&oldest) {
        subtract_size(inner, &removed);
        remove_metadata(&removed);
        removed.remove_body();
      }
    }
  }

  fn persist_metadata(&self, entry: &StoredEntry) -> anyhow::Result<()> {
    if !matches!(entry.body, StoredBody::Disk(_)) {
      return Ok(());
    }
    let Some(dir) = &self.disk_dir else {
      return Ok(());
    };
    let meta = encode_metadata(entry)?;
    let path = dir.join(format!("{}.meta", cache_file_name(&entry.variant_key)));
    let tmp = path.with_extension("meta.tmp");
    std::fs::write(&tmp, meta)
      .with_context(|| format!("failed to write cache metadata {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
      .with_context(|| format!("failed to commit cache metadata {}", path.display()))?;
    Ok(())
  }

  fn load_disk_entries(&self) {
    if !self.config.enabled {
      return;
    }
    let Some(dir) = &self.disk_dir else {
      return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
      return;
    };
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    for entry in entries.flatten() {
      let path = entry.path();
      if path.extension().and_then(|value| value.to_str()) != Some("meta") {
        continue;
      }
      match decode_metadata(&path) {
        Ok(stored) => {
          let now = SystemTime::now();
          if stored
            .stale_if_error_until
            .unwrap_or(stored.expires_at)
            .duration_since(now)
            .is_err()
          {
            remove_metadata(&stored);
            stored.remove_body();
            continue;
          }
          add_size(&mut inner, &stored);
          inner.order.push_back(stored.variant_key.clone());
          inner.entries.insert(stored.variant_key.clone(), stored);
        }
        Err(error) => {
          warn!(error = %error, path = %path.display(), "failed to load disk cache metadata");
          let _ = std::fs::remove_file(path);
        }
      }
    }
  }
}

impl Drop for ResponseCache {
  fn drop(&mut self) {
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    for (_, entry) in inner.entries.drain() {
      if !matches!(entry.body, StoredBody::Disk(_)) {
        entry.remove_body();
      }
    }
    inner.order.clear();
    inner.memory_size = 0;
    inner.disk_size = 0;
    inner.tmpfs_size = 0;
  }
}

pub fn validate_tmpfs_dir(path: &Path) -> anyhow::Result<()> {
  let metadata = path
    .metadata()
    .with_context(|| format!("failed to inspect cache tmpfs_dir {}", path.display()))?;
  if !metadata.is_dir() {
    bail!("cache tmpfs_dir {} must be a directory", path.display());
  }
  let canonical = path
    .canonicalize()
    .with_context(|| format!("failed to resolve cache tmpfs_dir {}", path.display()))?;
  if !canonical.starts_with("/dev/shm") {
    bail!("cache tmpfs_dir {} must be under /dev/shm", path.display());
  }
  validate_writable_dir("cache tmpfs_dir", path)
}

pub fn validate_disk_dir(path: &Path) -> anyhow::Result<()> {
  let metadata = path
    .metadata()
    .with_context(|| format!("failed to inspect cache disk_dir {}", path.display()))?;
  if !metadata.is_dir() {
    bail!("cache disk_dir {} must be a directory", path.display());
  }
  validate_writable_dir("cache disk_dir", path)
}

pub fn range_entry(entry: CacheEntry, method: &Method, request_headers: &HeaderMap) -> CacheEntry {
  if method == Method::HEAD {
    return CacheEntry {
      body: Bytes::new(),
      ..entry
    };
  }
  let Some(range) = request_headers
    .get(RANGE)
    .and_then(|value| value.to_str().ok())
  else {
    return entry;
  };
  let Some((start, end)) = parse_byte_range(range, entry.body.len()) else {
    let mut headers = entry.headers;
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(
      CONTENT_RANGE,
      HeaderValue::from_str(&format!("bytes */{}", entry.body.len()))
        .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
    );
    headers.remove(CONTENT_LENGTH);
    return CacheEntry {
      status: StatusCode::RANGE_NOT_SATISFIABLE,
      headers,
      body: Bytes::new(),
    };
  };
  let body = entry.body.slice(start..end + 1);
  let mut headers = entry.headers;
  headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  if let Ok(value) = HeaderValue::from_str(&format!("bytes {start}-{end}/{}", entry.body.len())) {
    headers.insert(CONTENT_RANGE, value);
  }
  if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
    headers.insert(CONTENT_LENGTH, value);
  }
  CacheEntry {
    status: StatusCode::PARTIAL_CONTENT,
    headers,
    body,
  }
}

struct ResponseMetadata {
  expires_at: SystemTime,
  stale_if_error_until: Option<SystemTime>,
  stale_while_revalidate_until: Option<SystemTime>,
  must_revalidate: bool,
  vary: Vec<VaryMatcher>,
}

fn cache_metadata(
  config: &CacheConfig,
  policy: &CachePolicyRuntime,
  request_headers: &HeaderMap,
  entry: &CacheEntry,
) -> Option<ResponseMetadata> {
  if entry.status == StatusCode::PARTIAL_CONTENT {
    return None;
  }
  if !cacheable_status(config, entry.status) {
    return None;
  }
  if response_has_set_cookie(&entry.headers) {
    return None;
  }
  let request_directives = cache_control_directives(request_headers);
  if request_directives.has("no-store") {
    return None;
  }
  let directives = cache_control_directives(&entry.headers);
  if config.respect_cache_control && (directives.has("no-store") || directives.has("private")) {
    return None;
  }
  let vary = vary_matchers(&entry.headers, request_headers)?;
  let now = SystemTime::now();
  let mut ttl = if config.respect_cache_control {
    directives
      .seconds("s-maxage")
      .or_else(|| directives.seconds("max-age"))
      .or_else(|| expires_ttl(&entry.headers, now))
      .unwrap_or(policy.default_ttl_seconds)
  } else {
    policy.default_ttl_seconds
  };
  if !config.negative_statuses.is_empty()
    && config
      .negative_statuses
      .iter()
      .any(|status| StatusCode::from_u16(*status).ok() == Some(entry.status))
  {
    ttl = config.negative_ttl_seconds;
  }
  if ttl == 0 {
    return None;
  }
  let must_revalidate = directives.has("no-cache")
    || directives.has("must-revalidate")
    || directives.has("proxy-revalidate");
  let expires_at = if must_revalidate {
    now
  } else {
    now + Duration::from_secs(ttl)
  };
  let stale_if_error_seconds = if config.respect_cache_control {
    directives
      .seconds("stale-if-error")
      .unwrap_or(config.stale_if_error_seconds)
  } else {
    config.stale_if_error_seconds
  };
  let stale_while_revalidate_seconds = if config.respect_cache_control {
    directives
      .seconds("stale-while-revalidate")
      .unwrap_or(config.stale_while_revalidate_seconds)
  } else {
    config.stale_while_revalidate_seconds
  };
  Some(ResponseMetadata {
    expires_at,
    stale_if_error_until: (stale_if_error_seconds > 0)
      .then_some(expires_at + Duration::from_secs(stale_if_error_seconds)),
    stale_while_revalidate_until: (stale_while_revalidate_seconds > 0)
      .then_some(expires_at + Duration::from_secs(stale_while_revalidate_seconds)),
    must_revalidate,
    vary,
  })
}

fn cacheable_status(config: &CacheConfig, status: StatusCode) -> bool {
  matches!(
    status,
    StatusCode::OK
      | StatusCode::NON_AUTHORITATIVE_INFORMATION
      | StatusCode::NO_CONTENT
      | StatusCode::MOVED_PERMANENTLY
      | StatusCode::PERMANENT_REDIRECT
  ) || config
    .negative_statuses
    .iter()
    .any(|candidate| StatusCode::from_u16(*candidate).ok() == Some(status))
}

fn response_has_set_cookie(headers: &HeaderMap) -> bool {
  headers.contains_key(http::header::SET_COOKIE)
}

fn request_no_store(headers: &HeaderMap) -> bool {
  headers.contains_key(AUTHORIZATION) || cache_control_directives(headers).has("no-store")
}

fn request_no_cache(headers: &HeaderMap) -> bool {
  headers
    .get(PRAGMA)
    .and_then(|value| value.to_str().ok())
    .is_some_and(|value| value.eq_ignore_ascii_case("no-cache"))
    || cache_control_directives(headers).has("no-cache")
}

fn validator_headers(headers: &HeaderMap) -> HeaderMap {
  let mut validators = HeaderMap::new();
  if let Some(etag) = headers.get(ETAG) {
    validators.insert(IF_NONE_MATCH, etag.clone());
  }
  if let Some(last_modified) = headers.get(LAST_MODIFIED) {
    validators.insert(IF_MODIFIED_SINCE, last_modified.clone());
  }
  validators
}

fn vary_matchers(
  response_headers: &HeaderMap,
  request_headers: &HeaderMap,
) -> Option<Vec<VaryMatcher>> {
  let mut result = Vec::new();
  for value in response_headers.get_all(VARY) {
    let value = value.to_str().ok()?;
    for name in value
      .split(',')
      .map(str::trim)
      .filter(|name| !name.is_empty())
    {
      if name == "*" {
        return None;
      }
      let lower = name.to_ascii_lowercase();
      result.push(VaryMatcher {
        name: lower.clone(),
        value: header_values(request_headers, &lower),
      });
    }
  }
  result.sort_by(|left, right| left.name.cmp(&right.name));
  result.dedup_by(|left, right| left.name == right.name);
  Some(result)
}

fn vary_matches(vary: &[VaryMatcher], request_headers: &HeaderMap) -> bool {
  vary
    .iter()
    .all(|item| header_values(request_headers, &item.name) == item.value)
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

#[derive(Debug, Default)]
struct CacheControl {
  values: HashMap<String, Option<String>>,
}

impl CacheControl {
  fn has(&self, name: &str) -> bool {
    self.values.contains_key(&name.to_ascii_lowercase())
  }

  fn seconds(&self, name: &str) -> Option<u64> {
    self
      .values
      .get(&name.to_ascii_lowercase())
      .and_then(|value| value.as_ref())
      .and_then(|value| value.parse::<u64>().ok())
  }
}

fn cache_control_directives(headers: &HeaderMap) -> CacheControl {
  let mut directives = CacheControl::default();
  for value in headers.get_all(CACHE_CONTROL) {
    let Ok(value) = value.to_str() else {
      continue;
    };
    for item in value.split(',') {
      let item = item.trim();
      if item.is_empty() {
        continue;
      }
      let (name, value) = item
        .split_once('=')
        .map(|(name, value)| {
          (
            name.trim(),
            Some(value.trim().trim_matches('"').to_string()),
          )
        })
        .unwrap_or((item, None));
      directives.values.insert(name.to_ascii_lowercase(), value);
    }
  }
  directives
}

fn expires_ttl(headers: &HeaderMap, now: SystemTime) -> Option<u64> {
  let expires = headers.get(EXPIRES)?.to_str().ok()?;
  let expires = httpdate::parse_http_date(expires).ok()?;
  expires
    .duration_since(now)
    .ok()
    .map(|duration| duration.as_secs())
}

fn expanded_cache_key(
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

fn replace_dynamic_tokens<F>(input: &str, kind: &str, mut value: F) -> String
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

fn query_value(uri: &Uri, name: &str) -> String {
  uri
    .query()
    .and_then(|query| {
      url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
    })
    .unwrap_or_default()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> String {
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

fn variant_key(base_key: &str, vary: &[VaryMatcher]) -> String {
  let mut key = base_key.to_string();
  for item in vary {
    key.push('\n');
    key.push_str(&item.name);
    key.push('=');
    key.push_str(&item.value);
  }
  key
}

fn select_store(policy: &CachePolicyRuntime, headers: &HeaderMap) -> CacheStore {
  let content_type = headers
    .get(CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .map(|value| {
      value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
    })
    .unwrap_or_default();
  for rule in &policy.rules {
    if rule
      .mime_types
      .iter()
      .any(|pattern| mime_matches(pattern, &content_type))
    {
      return rule.store;
    }
  }
  policy.store
}

fn mime_matches(pattern: &str, mime: &str) -> bool {
  if pattern == "*/*" {
    return true;
  }
  let pattern = pattern.to_ascii_lowercase();
  if let Some(prefix) = pattern.strip_suffix("/*") {
    return mime.starts_with(&format!("{prefix}/"));
  }
  if let Some(suffix) = pattern.strip_prefix("*/") {
    return mime.ends_with(&format!("/{suffix}"));
  }
  if let Some(suffix) = pattern.split_once("/*+").map(|(_, suffix)| suffix) {
    return mime.ends_with(&format!("+{suffix}"));
  }
  pattern == mime
}

fn parse_byte_range(range: &str, len: usize) -> Option<(usize, usize)> {
  let range = range.strip_prefix("bytes=")?;
  if range.contains(',') || len == 0 {
    return None;
  }
  let (start, end) = range.split_once('-')?;
  if start.is_empty() {
    let suffix = end.parse::<usize>().ok()?;
    if suffix == 0 {
      return None;
    }
    let start = len.saturating_sub(suffix);
    return Some((start, len - 1));
  }
  let start = start.parse::<usize>().ok()?;
  let end = if end.is_empty() {
    len - 1
  } else {
    end.parse::<usize>().ok()?
  };
  (start <= end && start < len).then_some((start, end.min(len - 1)))
}

fn policy_runtime(
  config: &CacheConfig,
  policy: &CachePolicyConfig,
  default_memory_limit: usize,
) -> CachePolicyRuntime {
  CachePolicyRuntime {
    name: policy.name.clone(),
    store: policy.store.unwrap_or(config.store),
    cache_key: policy
      .cache_key
      .clone()
      .unwrap_or_else(|| config.cache_key.clone()),
    default_ttl_seconds: policy
      .default_ttl_seconds
      .unwrap_or(config.default_ttl_seconds),
    memory_max_size_bytes: policy.memory_max_size_bytes.unwrap_or(default_memory_limit),
    disk_max_size_bytes: policy.disk_max_size_bytes.or(config.disk_max_size_bytes),
    rules: policy
      .rules
      .iter()
      .map(|rule| CachePolicyRuleRuntime {
        mime_types: rule.mime_types.clone(),
        store: rule.store,
      })
      .collect(),
  }
}

fn auto_memory_cache_limit(config: &CacheConfig) -> usize {
  let limit = detect_memory_limit_bytes().unwrap_or(config.max_size_bytes as u64);
  ((limit as f64) * config.memory_auto_fraction)
    .max(1.0)
    .min(usize::MAX as f64) as usize
}

pub fn detect_memory_limit_bytes() -> Option<u64> {
  for path in [
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
  ] {
    let Ok(raw) = std::fs::read_to_string(path) else {
      continue;
    };
    let raw = raw.trim();
    if raw == "max" {
      continue;
    }
    if let Ok(value) = raw.parse::<u64>()
      && value > 0
      && value < i64::MAX as u64
    {
      return Some(value);
    }
  }
  std::fs::read_to_string("/proc/meminfo")
    .ok()
    .and_then(|raw| {
      raw.lines().find_map(|line| {
        let rest = line.strip_prefix("MemTotal:")?;
        let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
        Some(kb * 1024)
      })
    })
}

fn validate_writable_dir(field_name: &str, path: &Path) -> anyhow::Result<()> {
  let probe = path.join(format!(".oxibelt-write-test-{}", std::process::id()));
  std::fs::write(&probe, b"ok")
    .with_context(|| format!("{field_name} {} must be writable", path.display()))?;
  let _ = std::fs::remove_file(probe);
  Ok(())
}

fn remove_entry(inner: &mut CacheInner, key: &str) {
  if let Some(existing) = inner.entries.remove(key) {
    subtract_size(inner, &existing);
    remove_metadata(&existing);
    existing.remove_body();
  }
}

fn shared_cache_entry(entry: &StoredEntry) -> Option<SharedCacheEntry> {
  let body = match &entry.body {
    StoredBody::Memory(body) => body.to_vec(),
    StoredBody::Tmpfs(path) | StoredBody::Disk(path) => std::fs::read(path).ok()?,
  };
  Some(SharedCacheEntry {
    policy: entry.policy.clone(),
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
    body,
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
  })
}

fn system_time_ms(time: SystemTime) -> i64 {
  time
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis()
    .min(i64::MAX as u128) as i64
}

impl StoredEntry {
  fn to_cache_entry(&self) -> Option<CacheEntry> {
    let body = match &self.body {
      StoredBody::Memory(body) => body.clone(),
      StoredBody::Tmpfs(path) | StoredBody::Disk(path) => Bytes::from(std::fs::read(path).ok()?),
    };
    Some(CacheEntry {
      status: self.status,
      headers: self.headers.clone(),
      body,
    })
  }

  fn remove_body(self) {
    match self.body {
      StoredBody::Tmpfs(path) | StoredBody::Disk(path) => {
        let _ = std::fs::remove_file(path);
      }
      StoredBody::Memory(_) => {}
    }
  }
}

fn write_body_file(dir: &Path, key: &str, body: &Bytes) -> Option<PathBuf> {
  let path = dir.join(format!("{}.body", cache_file_name(key)));
  let tmp = path.with_extension("body.tmp");
  if std::fs::write(&tmp, body).is_err() {
    return None;
  }
  if std::fs::rename(&tmp, &path).is_err() {
    let _ = std::fs::remove_file(tmp);
    return None;
  }
  Some(path)
}

fn add_size(inner: &mut CacheInner, entry: &StoredEntry) {
  match entry.body {
    StoredBody::Memory(_) => inner.memory_size += entry.size,
    StoredBody::Tmpfs(_) => inner.tmpfs_size += entry.size,
    StoredBody::Disk(_) => inner.disk_size += entry.size,
  }
}

fn subtract_size(inner: &mut CacheInner, entry: &StoredEntry) {
  match entry.body {
    StoredBody::Memory(_) => inner.memory_size = inner.memory_size.saturating_sub(entry.size),
    StoredBody::Tmpfs(_) => inner.tmpfs_size = inner.tmpfs_size.saturating_sub(entry.size),
    StoredBody::Disk(_) => inner.disk_size = inner.disk_size.saturating_sub(entry.size),
  }
}

fn total_size(inner: &CacheInner) -> usize {
  inner.memory_size + inner.tmpfs_size + inner.disk_size
}

fn cache_file_name(key: &str) -> String {
  let digest = digest::digest(&digest::SHA256, key.as_bytes());
  let mut name = String::with_capacity(digest.as_ref().len() * 2);
  for byte in digest.as_ref() {
    use std::fmt::Write;
    let _ = write!(&mut name, "{byte:02x}");
  }
  name
}

fn header_size(headers: &HeaderMap) -> usize {
  headers
    .iter()
    .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
    .sum()
}

fn encode_metadata(entry: &StoredEntry) -> anyhow::Result<String> {
  let StoredBody::Disk(body_path) = &entry.body else {
    return Ok(String::new());
  };
  let mut lines = Vec::new();
  lines.push("version=1".to_string());
  for (key, value) in [
    ("policy", entry.policy.as_str()),
    ("base_key", entry.base_key.as_str()),
    ("variant_key", entry.variant_key.as_str()),
    ("scheme", entry.scheme.as_str()),
    ("host", entry.host.as_str()),
    ("uri", entry.uri.as_str()),
    ("body_path", body_path.to_string_lossy().as_ref()),
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
  lines.push(format!("size={}", entry.size));
  for matcher in &entry.vary {
    lines.push(format!(
      "vary={}:{}",
      b64(matcher.name.as_bytes()),
      b64(matcher.value.as_bytes())
    ));
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

fn decode_metadata(path: &Path) -> anyhow::Result<StoredEntry> {
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
  let base_key = get("base_key")?;
  let variant_key = get("variant_key")?;
  let scheme = get("scheme")?;
  let host = get("host")?;
  let uri = get("uri")?;
  let body_path = PathBuf::from(get("body_path")?);
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
  Ok(StoredEntry {
    policy,
    base_key,
    variant_key,
    scheme,
    host,
    uri,
    status,
    headers,
    body: StoredBody::Disk(body_path),
    expires_at,
    stale_if_error_until,
    stale_while_revalidate_until,
    must_revalidate,
    vary,
    size,
  })
}

fn remove_metadata(entry: &StoredEntry) {
  if let StoredBody::Disk(path) = &entry.body {
    let _ = std::fs::remove_file(path.with_extension("meta"));
    let meta = path.with_file_name(format!("{}.meta", cache_file_name(&entry.variant_key)));
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cache_key_expands_dynamic_tokens() {
    let uri = "/asset/app.css?v=1&lang=en".parse::<Uri>().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("accept-language", HeaderValue::from_static("en-US"));
    headers.insert(
      "cookie",
      HeaderValue::from_static("session=abc; theme=dark"),
    );
    let key = expanded_cache_key(
      "{scheme}:{host}:{path}:{query:v}:{header:Accept-Language}:{cookie:theme}",
      "https",
      "example.test",
      &uri,
      &headers,
    );
    assert_eq!(key, "https:example.test:/asset/app.css:1:en-US:dark");
  }

  #[test]
  fn range_entry_returns_partial_body() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("10"));
    let entry = CacheEntry {
      status: StatusCode::OK,
      headers,
      body: Bytes::from_static(b"0123456789"),
    };
    let mut request_headers = HeaderMap::new();
    request_headers.insert(RANGE, HeaderValue::from_static("bytes=2-5"));
    let entry = range_entry(entry, &Method::GET, &request_headers);
    assert_eq!(entry.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(entry.body, Bytes::from_static(b"2345"));
    assert_eq!(entry.headers.get(CONTENT_RANGE).unwrap(), "bytes 2-5/10");
  }

  #[tokio::test]
  async fn fill_permit_coalesces_followers_until_leader_drops() {
    let config = CacheConfig {
      enabled: true,
      ..CacheConfig::default()
    };
    let cache = ResponseCache::new(&config, None).unwrap();
    let uri = "/asset/app.css?v=1".parse::<Uri>().unwrap();
    let headers = HeaderMap::new();
    let ctx = CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &headers,
    };
    let guard = match cache.begin_fill(ctx.clone()).unwrap() {
      CacheFillPermit::Leader(guard) => guard,
      CacheFillPermit::Follower(_) => panic!("first fill should lead"),
    };
    let waiter = match cache.begin_fill(ctx.clone()).unwrap() {
      CacheFillPermit::Leader(_) => panic!("second fill should wait"),
      CacheFillPermit::Follower(waiter) => waiter,
    };
    let wait_task = tokio::spawn(waiter.wait());
    tokio::task::yield_now().await;
    assert!(!wait_task.is_finished());
    drop(guard);
    tokio::time::timeout(Duration::from_secs(1), wait_task)
      .await
      .unwrap()
      .unwrap();
    assert!(matches!(
      cache.begin_fill(ctx).unwrap(),
      CacheFillPermit::Leader(_)
    ));
  }

  #[test]
  fn shared_cache_entries_are_visible_across_instances_and_purgeable() {
    let shared = crate::shared_state::SharedState::test_memory("cache-test");
    let config = CacheConfig {
      enabled: true,
      ..CacheConfig::default()
    };
    let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
    let second = ResponseCache::new(&config, Some(shared)).unwrap();
    let uri = "/asset/app.css?body=shared".parse::<Uri>().unwrap();
    let headers = HeaderMap::new();
    let ctx = CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &headers,
    };

    first.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &headers,
      },
      CacheEntry {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"shared-cache"),
      },
    );

    match second.lookup(ctx.clone()) {
      Some(CacheLookup::Fresh(entry)) => {
        assert_eq!(entry.body, Bytes::from_static(b"shared-cache"))
      }
      other => panic!("expected shared cache hit, got {other:?}"),
    }

    assert_eq!(
      second.purge_exact(
        "default",
        "https",
        "example.test",
        "/asset/app.css?body=shared"
      ),
      2
    );
    assert!(second.lookup(ctx).is_none());
  }

  #[test]
  fn shared_cache_requires_exact_uri_when_cache_key_collides() {
    let shared = crate::shared_state::SharedState::test_memory("cache-uri-isolation");
    let config = CacheConfig {
      enabled: true,
      cache_key: "{scheme}:{host}:{path}".to_string(),
      ..CacheConfig::default()
    };
    let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
    let second = ResponseCache::new(&config, Some(shared)).unwrap();
    let secret_uri = "/profile?token=secret".parse::<Uri>().unwrap();
    let other_uri = "/profile?token=other".parse::<Uri>().unwrap();
    let headers = HeaderMap::new();

    first.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &secret_uri,
        request_headers: &headers,
      },
      CacheEntry {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"secret-token-response"),
      },
    );

    let other_ctx = CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &other_uri,
      request_headers: &headers,
    };
    assert!(second.lookup(other_ctx).is_none());

    let secret_ctx = CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &secret_uri,
      request_headers: &headers,
    };
    match second.lookup(secret_ctx) {
      Some(CacheLookup::Fresh(entry)) => {
        assert_eq!(entry.body, Bytes::from_static(b"secret-token-response"))
      }
      other => panic!("expected exact URI shared cache hit, got {other:?}"),
    }
  }
}
