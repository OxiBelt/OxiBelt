//! Runtime state for static-file routes.
//! Precomputed route metadata keeps hot-path file serving deterministic.

use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use bytes::Bytes;
use http::HeaderMap;
use http::header::{
  ACCEPT_RANGES, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderValue,
  LAST_MODIFIED, VARY,
};

use crate::config::{Config, ProxyStaticFilesConfig};

use super::response_plan::StaticResponseMetadata;

#[derive(Clone)]
pub(crate) struct StaticFilesRuntime {
  roots: Arc<HashMap<PathBuf, StaticRootHandle>>,
  hot_objects: Arc<StaticHotObjectCache>,
}

impl StaticFilesRuntime {
  pub(crate) fn new(config: &Config) -> anyhow::Result<Self> {
    let mut roots = HashMap::new();
    for route in &config.routes {
      let Some(root) = route.static_root.as_ref() else {
        continue;
      };
      if !roots.contains_key(root) {
        roots.insert(root.clone(), StaticRootHandle::new(root)?);
      }
    }

    Ok(Self {
      roots: Arc::new(roots),
      hot_objects: Arc::new(StaticHotObjectCache::new(config.proxy.static_files)),
    })
  }

  #[cfg(test)]
  pub(crate) fn for_roots(
    roots: impl IntoIterator<Item = PathBuf>,
    config: ProxyStaticFilesConfig,
  ) -> anyhow::Result<Self> {
    let mut handles = HashMap::new();
    for root in roots {
      handles.insert(root.clone(), StaticRootHandle::new(&root)?);
    }
    Ok(Self {
      roots: Arc::new(handles),
      hot_objects: Arc::new(StaticHotObjectCache::new(config)),
    })
  }

  pub(crate) fn root_handle(&self, root: &Path) -> StaticRootHandle {
    self
      .roots
      .get(root)
      .cloned()
      .unwrap_or_else(|| StaticRootHandle::uncached(root))
  }

  pub(crate) fn cached_object(
    &self,
    root: &Path,
    path: &Path,
    response_metadata: &StaticResponseMetadata,
  ) -> Option<CachedStaticObject> {
    self.hot_objects.get(root, path, response_metadata)
  }

  pub(crate) fn object_cache_accepts(&self, len: u64) -> bool {
    self.hot_objects.accepts(len)
  }

  pub(crate) fn store_object(
    &self,
    root: &Path,
    path: PathBuf,
    etag: String,
    modified: Option<SystemTime>,
    response_metadata: StaticResponseMetadata,
    body: Bytes,
  ) {
    self
      .hot_objects
      .insert(root, path, etag, modified, response_metadata, body);
  }
}

#[derive(Clone)]
pub(crate) struct StaticRootHandle {
  root: PathBuf,
  #[cfg(target_os = "linux")]
  dir_fd: Option<Arc<OwnedFd>>,
  #[cfg(target_os = "linux")]
  root_id: Option<StaticRootId>,
}

impl StaticRootHandle {
  fn new(root: &Path) -> anyhow::Result<Self> {
    #[cfg(target_os = "linux")]
    let (dir_fd, root_id) = open_root_dir_fd(root)?;
    Ok(Self {
      root: root.to_path_buf(),
      #[cfg(target_os = "linux")]
      dir_fd: Some(Arc::new(dir_fd)),
      #[cfg(target_os = "linux")]
      root_id: Some(root_id),
    })
  }

  fn uncached(root: &Path) -> Self {
    Self {
      root: root.to_path_buf(),
      #[cfg(target_os = "linux")]
      dir_fd: None,
      #[cfg(target_os = "linux")]
      root_id: None,
    }
  }

  pub(crate) fn root(&self) -> &Path {
    &self.root
  }

  pub(crate) fn path_status(&self) -> StaticRootPathStatus {
    #[cfg(target_os = "linux")]
    {
      let Some(root_id) = self.root_id else {
        return StaticRootPathStatus::Uncached;
      };
      let Ok(current_metadata) = std::fs::metadata(&self.root) else {
        return StaticRootPathStatus::Unavailable;
      };
      if root_id.matches(&current_metadata) {
        StaticRootPathStatus::Matches
      } else {
        StaticRootPathStatus::Replaced
      }
    }
    #[cfg(not(target_os = "linux"))]
    {
      StaticRootPathStatus::Uncached
    }
  }

  #[cfg(target_os = "linux")]
  pub(crate) fn dir_fd(&self) -> Option<Arc<OwnedFd>> {
    self.dir_fd.clone()
  }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct StaticRootId {
  dev: u64,
  ino: u64,
}

#[cfg(target_os = "linux")]
impl StaticRootId {
  fn matches(self, metadata: &std::fs::Metadata) -> bool {
    self.dev == metadata.dev() && self.ino == metadata.ino()
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum StaticRootPathStatus {
  Matches,
  Replaced,
  Unavailable,
  Uncached,
}

#[cfg(target_os = "linux")]
fn open_root_dir_fd(root: &Path) -> anyhow::Result<(OwnedFd, StaticRootId)> {
  use nix::fcntl::{OFlag, open};
  use nix::sys::stat::{Mode, fstat};

  let dir_fd = open(
    root,
    OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY,
    Mode::empty(),
  )
  .with_context(|| format!("failed to open static_root directory {}", root.display()))?;
  let stat = fstat(&dir_fd)
    .with_context(|| format!("failed to inspect static_root directory {}", root.display()))?;
  Ok((
    dir_fd,
    StaticRootId {
      dev: stat.st_dev,
      ino: stat.st_ino,
    },
  ))
}

#[derive(Clone, Debug)]
pub(crate) struct CachedStaticObject {
  pub(crate) path: PathBuf,
  pub(crate) etag: String,
  pub(crate) modified: Option<SystemTime>,
  pub(crate) response_metadata: StaticResponseMetadata,
  pub(crate) full_headers: HeaderMap,
  pub(crate) body: Bytes,
}

#[derive(Debug)]
struct StaticHotObjectCache {
  ttl: Duration,
  max_entries: usize,
  max_bytes: usize,
  max_file_bytes: usize,
  inner: RwLock<StaticHotObjectCacheInner>,
}

#[derive(Debug, Default)]
struct StaticHotObjectCacheInner {
  total_bytes: usize,
  entries: HashMap<StaticObjectCacheKey, StaticHotObjectCacheEntry>,
  order: VecDeque<StaticObjectCacheKey>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct StaticObjectCacheKey {
  root: PathBuf,
  path: PathBuf,
  response_metadata: StaticResponseMetadata,
}

#[derive(Clone, Debug)]
struct StaticHotObjectCacheEntry {
  object: CachedStaticObject,
  expires_at: Instant,
}

impl StaticHotObjectCache {
  fn new(config: ProxyStaticFilesConfig) -> Self {
    Self {
      ttl: Duration::from_millis(config.open_file_cache_ttl_ms),
      max_entries: config.open_file_cache_max_entries,
      max_bytes: config.hot_object_cache_max_bytes,
      max_file_bytes: config.hot_object_cache_max_file_bytes,
      inner: RwLock::new(StaticHotObjectCacheInner::default()),
    }
  }

  fn enabled(&self) -> bool {
    self.max_entries > 0 && !self.ttl.is_zero() && self.max_bytes > 0 && self.max_file_bytes > 0
  }

  fn accepts(&self, len: u64) -> bool {
    self.enabled()
      && usize::try_from(len)
        .ok()
        .is_some_and(|len| len <= self.max_file_bytes && len <= self.max_bytes)
  }

  fn get(
    &self,
    root: &Path,
    path: &Path,
    response_metadata: &StaticResponseMetadata,
  ) -> Option<CachedStaticObject> {
    if !self.enabled() {
      return None;
    }
    let key = StaticObjectCacheKey {
      root: root.to_path_buf(),
      path: path.to_path_buf(),
      response_metadata: response_metadata.clone(),
    };
    let now = Instant::now();
    {
      let inner = self.inner.read().expect("static file cache lock poisoned");
      let entry = inner.entries.get(&key)?;
      if entry.expires_at > now {
        return Some(entry.object.clone());
      }
    }

    let mut inner = self.inner.write().expect("static file cache lock poisoned");
    if inner
      .entries
      .get(&key)
      .is_some_and(|entry| entry.expires_at <= now)
    {
      remove_entry(&mut inner, &key);
    }
    None
  }

  fn insert(
    &self,
    root: &Path,
    path: PathBuf,
    etag: String,
    modified: Option<SystemTime>,
    response_metadata: StaticResponseMetadata,
    body: Bytes,
  ) {
    if !self.accepts(body.len() as u64) {
      return;
    }
    let key = StaticObjectCacheKey {
      root: root.to_path_buf(),
      path: path.clone(),
      response_metadata: response_metadata.clone(),
    };
    let entry = StaticHotObjectCacheEntry {
      object: CachedStaticObject::new(path, etag, modified, response_metadata, body),
      expires_at: Instant::now() + self.ttl,
    };
    let mut inner = self.inner.write().expect("static file cache lock poisoned");
    remove_entry(&mut inner, &key);
    inner.total_bytes = inner.total_bytes.saturating_add(entry.object.body.len());
    inner.entries.insert(key.clone(), entry);
    inner.order.push_back(key);
    evict_over_limits(&mut inner, self.max_entries, self.max_bytes);
  }
}

impl CachedStaticObject {
  pub(crate) fn new(
    path: PathBuf,
    etag: String,
    modified: Option<SystemTime>,
    response_metadata: StaticResponseMetadata,
    body: Bytes,
  ) -> Self {
    Self {
      full_headers: cached_full_headers(&etag, modified, &response_metadata, body.len() as u64),
      path,
      etag,
      modified,
      response_metadata,
      body,
    }
  }
}

fn remove_entry(inner: &mut StaticHotObjectCacheInner, key: &StaticObjectCacheKey) {
  if let Some(entry) = inner.entries.remove(key) {
    inner.total_bytes = inner.total_bytes.saturating_sub(entry.object.body.len());
  }
  inner.order.retain(|queued| queued != key);
}

fn evict_over_limits(inner: &mut StaticHotObjectCacheInner, max_entries: usize, max_bytes: usize) {
  while inner.entries.len() > max_entries || inner.total_bytes > max_bytes {
    let Some(key) = inner.order.pop_front() else {
      break;
    };
    remove_entry(inner, &key);
  }
}

fn cached_full_headers(
  etag: &str,
  modified: Option<SystemTime>,
  response_metadata: &StaticResponseMetadata,
  body_len: u64,
) -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  if let Ok(value) = HeaderValue::from_str(&body_len.to_string()) {
    headers.insert(CONTENT_LENGTH, value);
  }
  if let Ok(value) = HeaderValue::from_str(etag) {
    headers.insert(ETAG, value);
  }
  if let Some(modified) = modified
    && let Ok(value) = HeaderValue::from_str(&httpdate::fmt_http_date(modified))
  {
    headers.insert(LAST_MODIFIED, value);
  }
  if let Ok(value) = HeaderValue::from_str(&response_metadata.content_type) {
    headers.insert(CONTENT_TYPE, value);
  }
  if let Some(encoding) = response_metadata.content_encoding {
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static(encoding));
  }
  if let Some(cache_control) = &response_metadata.cache_control
    && let Ok(value) = HeaderValue::from_str(cache_control)
  {
    headers.insert(CACHE_CONTROL, value);
  }
  if response_metadata.vary_accept_encoding {
    headers.insert(VARY, HeaderValue::from_static("Accept-Encoding"));
  }
  headers
}
