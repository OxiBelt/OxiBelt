use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};
use ring::digest;

use crate::config::{CacheConfig, CacheStore, default_cache_tmpfs_dir};

#[derive(Debug, Clone)]
pub struct CacheEntry {
  pub status: StatusCode,
  pub headers: HeaderMap,
  pub body: Bytes,
}

#[derive(Debug)]
struct StoredEntry {
  status: StatusCode,
  headers: HeaderMap,
  body: StoredBody,
  expires_at: Instant,
  size: usize,
}

#[derive(Debug)]
enum StoredBody {
  Memory(Bytes),
  Tmpfs(PathBuf),
}

#[derive(Debug, Default)]
struct CacheInner {
  entries: HashMap<String, StoredEntry>,
  order: VecDeque<String>,
  size: usize,
}

#[derive(Debug)]
pub struct ResponseCache {
  config: CacheConfig,
  tmpfs_dir: Option<PathBuf>,
  inner: Mutex<CacheInner>,
}

impl ResponseCache {
  pub fn new(config: &CacheConfig) -> anyhow::Result<Arc<Self>> {
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
    Ok(Arc::new(Self {
      config: config.clone(),
      tmpfs_dir,
      inner: Mutex::new(CacheInner::default()),
    }))
  }

  pub fn enabled(&self) -> bool {
    self.config.enabled
  }

  pub fn key(&self, scheme: &str, host: &str, uri: &Uri) -> String {
    self
      .config
      .cache_key
      .replace("{scheme}", scheme)
      .replace("{host}", host)
      .replace("{uri}", &uri.to_string())
  }

  pub fn is_cacheable_method(&self, method: &Method) -> bool {
    self
      .config
      .cache_methods
      .iter()
      .any(|item| item.eq_ignore_ascii_case(method.as_str()))
  }

  pub fn get(&self, key: &str) -> Option<CacheEntry> {
    let now = Instant::now();
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    let expired = inner
      .entries
      .get(key)
      .map(|entry| entry.expires_at <= now)
      .unwrap_or(false);
    if expired {
      remove_entry(&mut inner, key);
      return None;
    }
    let entry = inner.entries.get(key).and_then(StoredEntry::to_cache_entry);
    if entry.is_none() {
      remove_entry(&mut inner, key);
    }
    entry
  }

  pub fn insert(&self, key: String, entry: CacheEntry) {
    if !self.config.enabled || self.config.default_ttl_seconds == 0 {
      return;
    }
    let size = entry.body.len() + header_size(&entry.headers);
    if size > self.config.max_size_bytes {
      return;
    }
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    remove_entry(&mut inner, &key);
    let Some(body) = self.store_body(&key, &entry.body) else {
      return;
    };
    inner.order.push_back(key.clone());
    inner.size += size;
    inner.entries.insert(
      key,
      StoredEntry {
        status: entry.status,
        headers: entry.headers,
        body,
        expires_at: Instant::now() + Duration::from_secs(self.config.default_ttl_seconds),
        size,
      },
    );
    while inner.size > self.config.max_size_bytes {
      let Some(oldest) = inner.order.pop_front() else {
        break;
      };
      if let Some(removed) = inner.entries.remove(&oldest) {
        inner.size = inner.size.saturating_sub(removed.size);
        removed.remove_body();
      }
    }
  }

  fn store_body(&self, key: &str, body: &Bytes) -> Option<StoredBody> {
    let Some(dir) = &self.tmpfs_dir else {
      return Some(StoredBody::Memory(body.clone()));
    };
    let path = dir.join(cache_file_name(key));
    if std::fs::write(&path, body).is_err() {
      return None;
    }
    Some(StoredBody::Tmpfs(path))
  }
}

impl Drop for ResponseCache {
  fn drop(&mut self) {
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    for (_, entry) in inner.entries.drain() {
      entry.remove_body();
    }
    inner.order.clear();
    inner.size = 0;
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

  let probe = path.join(format!(".oxibelt-write-test-{}", std::process::id()));
  std::fs::write(&probe, b"ok")
    .with_context(|| format!("cache tmpfs_dir {} must be writable", path.display()))?;
  let _ = std::fs::remove_file(probe);
  Ok(())
}

fn remove_entry(inner: &mut CacheInner, key: &str) {
  if let Some(existing) = inner.entries.remove(key) {
    inner.size = inner.size.saturating_sub(existing.size);
    existing.remove_body();
  }
}

impl StoredEntry {
  fn to_cache_entry(&self) -> Option<CacheEntry> {
    let body = match &self.body {
      StoredBody::Memory(body) => body.clone(),
      StoredBody::Tmpfs(path) => Bytes::from(std::fs::read(path).ok()?),
    };
    Some(CacheEntry {
      status: self.status,
      headers: self.headers.clone(),
      body,
    })
  }

  fn remove_body(self) {
    if let StoredBody::Tmpfs(path) = self.body {
      let _ = std::fs::remove_file(path);
    }
  }
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
