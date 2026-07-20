//! Concrete local storage selection, eviction, and metadata persistence.

use super::*;

impl ResponseCache {
  pub(super) fn policy(&self, policy_name: Option<&str>) -> Option<&CachePolicyRuntime> {
    let name = policy_name.unwrap_or("default");
    self.policies.get(name)
  }

  pub fn background_refresh_enabled(&self, policy_name: Option<&str>) -> bool {
    self
      .policy(policy_name)
      .is_some_and(|policy| policy.background_refresh)
  }

  pub fn try_background_refresh_permit(
    &self,
    policy_name: Option<&str>,
  ) -> Option<OwnedSemaphorePermit> {
    if !self.background_refresh_enabled(policy_name) {
      return None;
    }
    if self
      .overload
      .load()
      .as_ref()
      .is_some_and(|runtime| runtime.cache_fill_disabled() || runtime.prefer_cached_or_stale())
    {
      return None;
    }
    let name = policy_name.unwrap_or("default");
    self
      .refresh_limiters
      .get(name)?
      .clone()
      .try_acquire_owned()
      .ok()
  }

  pub fn lock_wait_timeout(&self, policy_name: Option<&str>) -> Duration {
    self
      .policy(policy_name)
      .map(|policy| policy.lock_wait_timeout)
      .unwrap_or_else(|| Duration::from_millis(self.config.lock_wait_timeout_ms))
  }

  pub fn stale_if_error_allows_connect(&self, policy_name: Option<&str>) -> bool {
    self
      .policy(policy_name)
      .is_some_and(|policy| policy.stale_if_error.connect_error)
  }

  pub fn stale_if_error_allows_read_timeout(&self, policy_name: Option<&str>) -> bool {
    self
      .policy(policy_name)
      .is_some_and(|policy| policy.stale_if_error.read_timeout)
  }

  pub fn stale_if_error_allows_status(
    &self,
    policy_name: Option<&str>,
    status: StatusCode,
  ) -> bool {
    self.policy(policy_name).is_some_and(|policy| {
      policy
        .stale_if_error
        .statuses
        .iter()
        .any(|candidate| StatusCode::from_u16(*candidate).ok() == Some(status))
    })
  }

  pub(super) fn store_body(
    &self,
    policy: &CachePolicyRuntime,
    store: CacheStore,
    key: &str,
    entry: &CacheEntry,
    size: usize,
  ) -> Option<StoredBody> {
    match store {
      CacheStore::Memory => {
        if size > policy.memory_max_size_bytes {
          return None;
        }
        entry_body_bytes(entry).map(StoredBody::Memory)
      }
      CacheStore::Tmpfs => {
        if size > policy.memory_max_size_bytes {
          return None;
        }
        let dir = self.tmpfs_dir.as_ref()?;
        write_body_file_from_entry(&self.config, dir, key, entry).map(StoredBody::Tmpfs)
      }
      CacheStore::Disk => {
        if policy.disk_max_size_bytes.is_some_and(|limit| size > limit) {
          return None;
        }
        let dir = self.disk_dir.as_ref()?;
        write_body_file_from_entry(&self.config, dir, key, entry).map(StoredBody::Disk)
      }
      CacheStore::MemoryThenDisk => {
        if policy.disk_max_size_bytes.is_some_and(|limit| size > limit) {
          return None;
        }
        let dir = self.disk_dir.as_ref()?;
        write_body_file_from_entry(&self.config, dir, key, entry).map(StoredBody::Disk)
      }
    }
  }

  pub(super) fn evict_if_needed(&self, inner: &mut CacheInner, policy: &CachePolicyRuntime) {
    while inner.memory_size > policy.memory_max_size_bytes
      || self
        .config
        .disk_max_size_bytes
        .is_some_and(|limit| inner.disk_size.saturating_add(inner.disk_inflight_size) > limit)
      || policy
        .disk_max_size_bytes
        .is_some_and(|limit| inner.disk_size.saturating_add(inner.disk_inflight_size) > limit)
      || inner.tmpfs_size > policy.memory_max_size_bytes
      || total_size(inner).saturating_add(inner.disk_inflight_size) > self.config.max_size_bytes
    {
      let Some(oldest) = inner.order.pop_front() else {
        break;
      };
      remove_entry(inner, &oldest);
    }
  }

  pub(super) fn persist_metadata(&self, entry: &StoredEntry) -> anyhow::Result<()> {
    if !matches!(entry.body, StoredBody::Disk(_)) {
      return Ok(());
    }
    let Some(dir) = &self.disk_dir else {
      return Ok(());
    };
    let meta = encode_metadata(entry)?;
    let path = cache_file_path(dir, &entry.variant_key, CacheFileKind::Meta)
      .ok_or_else(|| anyhow!("invalid cache metadata file name"))?;
    let tmp = cache_file_path(dir, &entry.variant_key, CacheFileKind::MetaTmp)
      .ok_or_else(|| anyhow!("invalid temporary cache metadata file name"))?;
    std::fs::write(&tmp, meta)
      .with_context(|| format!("failed to write cache metadata {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
      .with_context(|| format!("failed to commit cache metadata {}", path.display()))?;
    Ok(())
  }
}

pub fn validate_tmpfs_dir(path: &Path) -> anyhow::Result<()> {
  validated_tmpfs_dir(path).map(|_| ())
}

pub fn validate_disk_dir(path: &Path) -> anyhow::Result<()> {
  validated_disk_dir(path).map(|_| ())
}

pub(super) fn cache_needs_disk_dir(config: &CacheConfig) -> bool {
  config.store.uses_disk()
    || config.policies.iter().any(|policy| {
      policy.store.is_some_and(CacheStore::uses_disk)
        || policy.rules.iter().any(|rule| rule.store.uses_disk())
    })
}

pub(super) fn auto_memory_cache_limit(config: &CacheConfig) -> usize {
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

pub(super) fn validated_tmpfs_dir(path: &Path) -> anyhow::Result<PathBuf> {
  let canonical = canonical_cache_dir("cache tmpfs_dir", path)?;
  if !canonical.starts_with(Path::new(TMPFS_CACHE_ROOT)) {
    bail!("cache tmpfs_dir {} must be under /dev/shm", path.display());
  }
  validate_writable_dir("cache tmpfs_dir", &canonical)?;
  Ok(canonical)
}

pub(super) fn validated_disk_dir(path: &Path) -> anyhow::Result<PathBuf> {
  let canonical = canonical_cache_dir("cache disk_dir", path)?;
  validate_writable_dir("cache disk_dir", &canonical)?;
  Ok(canonical)
}

pub(super) fn canonical_cache_dir(field_name: &str, path: &Path) -> anyhow::Result<PathBuf> {
  let canonical = path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;
  let metadata = canonical
    .metadata()
    .with_context(|| format!("failed to inspect {field_name} {}", path.display()))?;
  if !metadata.is_dir() {
    bail!("{field_name} {} must be a directory", path.display());
  }
  Ok(canonical)
}

pub(super) fn validate_writable_dir(field_name: &str, path: &Path) -> anyhow::Result<()> {
  let probe_name = format!(".oxibelt-write-test-{}", std::process::id());
  let probe = safe_child_path(path, &probe_name)
    .ok_or_else(|| anyhow!("{field_name} write probe file name is invalid"))?;
  std::fs::write(&probe, b"ok")
    .with_context(|| format!("{field_name} {} must be writable", path.display()))?;
  let _ = std::fs::remove_file(probe);
  Ok(())
}

pub(super) fn remove_entry(inner: &mut CacheInner, key: &str) {
  if let Some(existing) = detach_entry(inner, key) {
    remove_metadata(&existing);
    existing.remove_body();
  }
}

pub(super) fn detach_entry(inner: &mut CacheInner, key: &str) -> Option<StoredEntry> {
  let existing = inner.entries.remove(key)?;
  unindex_entry(inner, &existing);
  subtract_size(inner, &existing);
  Some(existing)
}

pub(super) fn remove_replaced_entry_files(existing: StoredEntry, replacement: &StoredEntry) {
  let shared_body_path = stored_body_path(&existing.body) == stored_body_path(&replacement.body);
  let shared_metadata_path = shared_body_path
    && matches!(
      (&existing.body, &replacement.body),
      (StoredBody::Disk(_), StoredBody::Disk(_))
    );
  if !shared_metadata_path {
    remove_metadata(&existing);
  }
  if !shared_body_path {
    existing.remove_body();
  }
}

pub(super) fn index_entry(inner: &mut CacheInner, entry: &StoredEntry) {
  inner
    .index
    .insert(entry_lookup_key(entry), &entry.variant_key);
}

pub(super) fn unindex_entry(inner: &mut CacheInner, entry: &StoredEntry) {
  inner
    .index
    .remove(&entry_lookup_key(entry), &entry.variant_key);
}

pub(super) fn entry_lookup_key(entry: &StoredEntry) -> index::LookupKey {
  index::LookupKey::new(
    &entry.policy,
    &entry.partition,
    &entry.scheme,
    &entry.host,
    &entry.uri,
    &entry.base_key,
  )
}

pub(super) fn system_time_ms(time: SystemTime) -> i64 {
  time
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis()
    .min(i64::MAX as u128) as i64
}

impl StoredEntry {
  pub(super) fn to_cache_entry(&self) -> Option<CacheEntry> {
    if !self.security_headers_neutral {
      return None;
    }
    match &self.body {
      StoredBody::Memory(body) => Some(
        CacheEntry::memory(self.status, self.headers.clone(), body.clone())
          .with_stored_at(self.stored_at),
      ),
      StoredBody::Tmpfs(path) | StoredBody::Disk(path) => {
        let body_len = std::fs::metadata(path).ok()?.len().try_into().ok()?;
        Some(CacheEntry::file(
          self.status,
          self.headers.clone(),
          path.clone(),
          body_len,
          self.stored_at,
        ))
      }
    }
  }

  pub(super) fn remove_body(self) {
    match self.body {
      StoredBody::Tmpfs(path) | StoredBody::Disk(path) => {
        let _ = std::fs::remove_file(path);
      }
      StoredBody::Memory(_) => {}
    }
  }

  pub(super) fn remove_body_files(&self) {
    match &self.body {
      StoredBody::Tmpfs(path) | StoredBody::Disk(path) => {
        let _ = std::fs::remove_file(path);
      }
      StoredBody::Memory(_) => {}
    }
  }
}

pub(super) fn stored_body_path(body: &StoredBody) -> Option<&Path> {
  match body {
    StoredBody::Tmpfs(path) | StoredBody::Disk(path) => Some(path),
    StoredBody::Memory(_) => None,
  }
}

pub(super) fn write_body_file(dir: &Path, key: &str, body: &Bytes) -> Option<PathBuf> {
  let path = cache_file_path(dir, key, CacheFileKind::Body)?;
  let tmp = cache_file_path(dir, key, CacheFileKind::BodyTmp)?;
  if std::fs::write(&tmp, body).is_err() {
    return None;
  }
  if std::fs::rename(&tmp, &path).is_err() {
    let _ = std::fs::remove_file(tmp);
    return None;
  }
  Some(path)
}

pub(super) fn write_body_file_from_entry(
  config: &CacheConfig,
  dir: &Path,
  key: &str,
  entry: &CacheEntry,
) -> Option<PathBuf> {
  let path = cache_file_path(dir, key, CacheFileKind::Body)?;
  let tmp = cache_file_path(dir, key, CacheFileKind::BodyTmp)?;
  if let Some(file) = &entry.body_file {
    match file_clone::materialize_cache_file(
      &file.path,
      file.offset,
      file.len,
      &tmp,
      &path,
      config.copy_file_range,
    ) {
      Ok(_) => return Some(path),
      Err(error) => {
        warn!(error = %error, "failed to materialize file-backed cache body");
        let _ = std::fs::remove_file(tmp);
        return None;
      }
    }
  }
  write_body_file(dir, key, &entry.body)
}

pub(super) fn entry_body_bytes(entry: &CacheEntry) -> Option<Bytes> {
  let Some(file) = &entry.body_file else {
    return Some(entry.body.clone());
  };
  let mut source = std::fs::File::open(&file.path).ok()?;
  source.seek(SeekFrom::Start(file.offset)).ok()?;
  let mut body = vec![0_u8; file.len];
  source.read_exact(&mut body).ok()?;
  Some(Bytes::from(body))
}

pub(super) fn add_size(inner: &mut CacheInner, entry: &StoredEntry) {
  match entry.body {
    StoredBody::Memory(_) => inner.memory_size += entry.size,
    StoredBody::Tmpfs(_) => inner.tmpfs_size += entry.size,
    StoredBody::Disk(_) => inner.disk_size += entry.size,
  }
}

pub(super) fn subtract_size(inner: &mut CacheInner, entry: &StoredEntry) {
  match entry.body {
    StoredBody::Memory(_) => inner.memory_size = inner.memory_size.saturating_sub(entry.size),
    StoredBody::Tmpfs(_) => inner.tmpfs_size = inner.tmpfs_size.saturating_sub(entry.size),
    StoredBody::Disk(_) => inner.disk_size = inner.disk_size.saturating_sub(entry.size),
  }
}

pub(super) fn total_size(inner: &CacheInner) -> usize {
  inner.memory_size + inner.tmpfs_size + inner.disk_size
}

pub(super) fn cache_file_name(key: &str) -> String {
  let digest = crate::crypto::sha256(key.as_bytes());
  let mut name = String::with_capacity(digest.len() * 2);
  for byte in digest {
    use std::fmt::Write;
    let _ = write!(&mut name, "{byte:02x}");
  }
  name
}

pub(super) fn cache_file_path(dir: &Path, key: &str, kind: CacheFileKind) -> Option<PathBuf> {
  let stem = cache_file_name(key);
  cache_file_path_from_stem(dir, &stem, kind)
}

pub(super) fn cache_file_path_from_stem(
  dir: &Path,
  stem: &str,
  kind: CacheFileKind,
) -> Option<PathBuf> {
  if !is_cache_file_stem(stem) {
    return None;
  }
  safe_child_path(dir, &format!("{}.{}", stem, kind.suffix()))
}

pub(super) fn safe_child_path(dir: &Path, file_name: &str) -> Option<PathBuf> {
  if file_name.is_empty()
    || file_name.contains("..")
    || file_name.contains('/')
    || file_name.contains('\\')
  {
    return None;
  }
  let path = dir.join(file_name);
  (path.parent() == Some(dir)).then_some(path)
}

pub(super) fn is_cache_file_stem(stem: &str) -> bool {
  stem.len() == crate::crypto::SHA256_HEX_LEN && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn header_size(headers: &HeaderMap) -> usize {
  headers
    .iter()
    .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
    .sum()
}
