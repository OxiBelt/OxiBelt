use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Context;
use bytes::Bytes;

use crate::config::{Config, ProxyStaticFilesConfig};

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

  pub(crate) fn cached_object(&self, root: &Path, path: &Path) -> Option<CachedStaticObject> {
    self.hot_objects.get(root, path)
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
    body: Bytes,
  ) {
    self.hot_objects.insert(root, path, etag, modified, body);
  }
}

#[derive(Clone)]
pub(crate) struct StaticRootHandle {
  root: PathBuf,
  #[cfg(target_os = "linux")]
  dir_fd: Option<Arc<OwnedFd>>,
}

impl StaticRootHandle {
  fn new(root: &Path) -> anyhow::Result<Self> {
    Ok(Self {
      root: root.to_path_buf(),
      #[cfg(target_os = "linux")]
      dir_fd: Some(Arc::new(open_root_dir_fd(root)?)),
    })
  }

  fn uncached(root: &Path) -> Self {
    Self {
      root: root.to_path_buf(),
      #[cfg(target_os = "linux")]
      dir_fd: None,
    }
  }

  pub(crate) fn root(&self) -> &Path {
    &self.root
  }

  #[cfg(target_os = "linux")]
  pub(crate) fn dir_fd(&self) -> Option<Arc<OwnedFd>> {
    self.dir_fd.clone()
  }
}

#[cfg(target_os = "linux")]
fn open_root_dir_fd(root: &Path) -> anyhow::Result<OwnedFd> {
  use nix::fcntl::{OFlag, open};
  use nix::sys::stat::Mode;

  open(
    root,
    OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY,
    Mode::empty(),
  )
  .with_context(|| format!("failed to open static_root directory {}", root.display()))
}

#[derive(Clone, Debug)]
pub(crate) struct CachedStaticObject {
  pub(crate) path: PathBuf,
  pub(crate) etag: String,
  pub(crate) modified: Option<SystemTime>,
  pub(crate) body: Bytes,
}

#[derive(Debug)]
struct StaticHotObjectCache {
  ttl: Duration,
  max_entries: usize,
  max_bytes: usize,
  max_file_bytes: usize,
  inner: Mutex<StaticHotObjectCacheInner>,
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
      inner: Mutex::new(StaticHotObjectCacheInner::default()),
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

  fn get(&self, root: &Path, path: &Path) -> Option<CachedStaticObject> {
    if !self.enabled() {
      return None;
    }
    let key = StaticObjectCacheKey {
      root: root.to_path_buf(),
      path: path.to_path_buf(),
    };
    let now = Instant::now();
    let mut inner = self.inner.lock().expect("static file cache lock poisoned");
    let Some(entry) = inner.entries.get(&key) else {
      return None;
    };
    if entry.expires_at <= now {
      remove_entry(&mut inner, &key);
      return None;
    }
    Some(entry.object.clone())
  }

  fn insert(
    &self,
    root: &Path,
    path: PathBuf,
    etag: String,
    modified: Option<SystemTime>,
    body: Bytes,
  ) {
    if !self.accepts(body.len() as u64) {
      return;
    }
    let key = StaticObjectCacheKey {
      root: root.to_path_buf(),
      path: path.clone(),
    };
    let entry = StaticHotObjectCacheEntry {
      object: CachedStaticObject {
        path,
        etag,
        modified,
        body,
      },
      expires_at: Instant::now() + self.ttl,
    };
    let mut inner = self.inner.lock().expect("static file cache lock poisoned");
    remove_entry(&mut inner, &key);
    inner.total_bytes = inner.total_bytes.saturating_add(entry.object.body.len());
    inner.entries.insert(key.clone(), entry);
    inner.order.push_back(key);
    evict_over_limits(&mut inner, self.max_entries, self.max_bytes);
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
    if let Some(entry) = inner.entries.remove(&key) {
      inner.total_bytes = inner.total_bytes.saturating_sub(entry.object.body.len());
    }
  }
}
