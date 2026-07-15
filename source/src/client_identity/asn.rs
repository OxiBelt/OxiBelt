//! Bounded IP-prefix to ASN lookup runtime.
//! The origin-ASN database is operator supplied; IANA registry URLs are metadata only.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use arc_swap::ArcSwap;
use http::header::ACCEPT;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::{
  ClientIdentityAsnConfig, ClientIdentityAsnFailurePolicy, ClientIdentityAsnManagedStorage,
  ClientIdentityAsnMode,
};
use crate::control_http::{ControlHttpClient, empty_body, uri_from_url};

mod iana;
use iana::{AsnRegistry, load_registry as load_iana_registry};
mod table;
#[cfg(test)]
use table::parse_prefix_asn_csv;
use table::{AsnDatabase, parse_asn, parse_database_bytes};

const DATABASE_CACHE_FILE: &str = "asn-prefixes.csv";
const METADATA_CACHE_FILE: &str = "asn.metadata.json";

#[cfg(test)]
#[path = "asn/tests.rs"]
mod tests;

#[derive(Clone)]
pub struct AsnRuntime {
  inner: Option<Arc<AsnRuntimeInner>>,
}

struct AsnRuntimeInner {
  config: ClientIdentityAsnConfig,
  database: Arc<ArcSwap<AsnDatabase>>,
  status: Arc<Mutex<AsnRuntimeStatus>>,
  control_http: ControlHttpClient,
  worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for AsnRuntimeInner {
  fn drop(&mut self) {
    if let Ok(mut worker) = self.worker.lock()
      && let Some(worker) = worker.take()
    {
      worker.abort();
    }
  }
}

#[derive(Clone, Debug, Serialize)]
pub struct AsnRuntimeStatus {
  pub status: String,
  pub enabled: bool,
  pub mode: &'static str,
  pub database_loaded: bool,
  pub database_stale: bool,
  pub entries: usize,
  pub cache_present: bool,
  pub cache_fresh: bool,
  pub managed: bool,
  pub storage: Option<String>,
  pub last_refresh_at: Option<u64>,
  pub next_refresh_at: Option<u64>,
  pub last_success_at: Option<u64>,
  pub last_error_kind: Option<String>,
}

#[derive(Debug)]
struct LoadedDatabase {
  database: AsnDatabase,
  cache_present: bool,
  cache_fresh: bool,
  database_stale: bool,
  last_success_at: Option<u64>,
}

#[derive(Debug)]
struct RemoteDatabase {
  bytes: Vec<u8>,
  sha256: String,
  size: usize,
}

#[derive(Debug)]
struct CachedDatabase {
  bytes: Vec<u8>,
  stale: bool,
  metadata: CacheMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
  sha256: String,
  size: usize,
  fetched_at: u64,
}

impl AsnRuntime {
  pub async fn new(
    config: &ClientIdentityAsnConfig,
    control_http: &ControlHttpClient,
  ) -> anyhow::Result<Self> {
    match config.mode {
      ClientIdentityAsnMode::Disabled => Ok(Self { inner: None }),
      ClientIdentityAsnMode::Local => Self::from_local(config, control_http.clone()).await,
      ClientIdentityAsnMode::Managed => Self::from_managed(config, control_http.clone()).await,
    }
  }

  pub fn lookup(&self, ip: IpAddr) -> Option<u32> {
    let inner = self.inner.as_ref()?;
    inner.database.load().lookup(ip)
  }

  pub fn status(&self) -> AsnRuntimeStatus {
    self
      .inner
      .as_ref()
      .map(|inner| {
        inner
          .status
          .lock()
          .map(|status| status.clone())
          .unwrap_or_else(|_| AsnRuntimeStatus {
            status: "degraded".to_string(),
            enabled: true,
            mode: config_mode_name(inner.config.mode),
            database_loaded: false,
            database_stale: false,
            entries: 0,
            cache_present: false,
            cache_fresh: false,
            managed: inner.config.mode == ClientIdentityAsnMode::Managed,
            storage: None,
            last_refresh_at: Some(unix_now()),
            next_refresh_at: None,
            last_success_at: None,
            last_error_kind: Some("asn_status_lock".to_string()),
          })
      })
      .unwrap_or_else(disabled_status)
  }

  async fn from_local(
    config: &ClientIdentityAsnConfig,
    control_http: ControlHttpClient,
  ) -> anyhow::Result<Self> {
    let loaded = async {
      let registry = load_iana_registry(config, &control_http).await?;
      load_local_database(config, registry.as_ref())
    }
    .await;
    match loaded {
      Ok(loaded) => Ok(Self::active(config.clone(), control_http, loaded, false)),
      Err(error) if config.failure_policy == ClientIdentityAsnFailurePolicy::DegradedNull => {
        tracing::warn!(error = %error, "ASN local database load degraded to null lookups");
        Ok(Self::active_with_status(
          config.clone(),
          control_http,
          AsnDatabase::default(),
          degraded_status(config, "asn_local_database_load"),
        ))
      }
      Err(error) => Err(error).context("failed to load ASN database"),
    }
  }

  async fn from_managed(
    config: &ClientIdentityAsnConfig,
    control_http: ControlHttpClient,
  ) -> anyhow::Result<Self> {
    let loaded = async {
      let registry = load_iana_registry(config, &control_http).await?;
      load_or_fetch_managed_database(config, &control_http, registry.as_ref()).await
    }
    .await;
    let runtime = match loaded {
      Ok(loaded) => Self::active(config.clone(), control_http, loaded, true),
      Err(error) if config.failure_policy == ClientIdentityAsnFailurePolicy::DegradedNull => {
        tracing::warn!(error = %error, "ASN managed database load degraded to null lookups");
        Self::active_with_status(
          config.clone(),
          control_http,
          AsnDatabase::default(),
          degraded_status(config, "asn_managed_database_load"),
        )
      }
      Err(error) => return Err(error).context("failed to load managed ASN database"),
    };
    runtime.spawn_refresh_task();
    Ok(runtime)
  }

  fn active(
    config: ClientIdentityAsnConfig,
    control_http: ControlHttpClient,
    loaded: LoadedDatabase,
    managed: bool,
  ) -> Self {
    let status = AsnRuntimeStatus {
      status: if loaded.database_stale {
        "degraded".to_string()
      } else {
        "ok".to_string()
      },
      enabled: true,
      mode: config_mode_name(config.mode),
      database_loaded: true,
      database_stale: loaded.database_stale,
      entries: loaded.database.entries,
      cache_present: loaded.cache_present,
      cache_fresh: loaded.cache_fresh,
      managed,
      storage: managed.then(|| config.managed.storage.as_str().to_string()),
      last_refresh_at: loaded.last_success_at,
      next_refresh_at: next_refresh_at(&config, loaded.last_success_at),
      last_success_at: loaded.last_success_at,
      last_error_kind: None,
    };
    Self::active_with_status(config, control_http, loaded.database, status)
  }

  fn active_with_status(
    config: ClientIdentityAsnConfig,
    control_http: ControlHttpClient,
    database: AsnDatabase,
    status: AsnRuntimeStatus,
  ) -> Self {
    Self {
      inner: Some(Arc::new(AsnRuntimeInner {
        config,
        database: Arc::new(ArcSwap::from_pointee(database)),
        status: Arc::new(Mutex::new(status)),
        control_http,
        worker: Mutex::new(None),
      })),
    }
  }

  fn spawn_refresh_task(&self) {
    let Some(inner) = &self.inner else {
      return;
    };
    if inner.config.mode != ClientIdentityAsnMode::Managed {
      return;
    }
    let weak = Arc::downgrade(inner);
    let interval = Duration::from_secs(inner.config.managed.refresh_interval_seconds);
    let worker = tokio::spawn(async move {
      refresh_loop(weak, interval).await;
    });
    if let Ok(mut slot) = inner.worker.lock() {
      *slot = Some(worker);
    }
  }
}

fn load_local_database(
  config: &ClientIdentityAsnConfig,
  registry: Option<&AsnRegistry>,
) -> anyhow::Result<LoadedDatabase> {
  let path = config
    .database_file
    .as_deref()
    .ok_or_else(|| anyhow!("asn_database_file_missing"))?;
  let metadata = fs::metadata(path).context("asn_database_metadata")?;
  if metadata.len() > config.max_database_bytes as u64 {
    bail!("asn_database_too_large");
  }
  let bytes = fs::read(path).context("asn_database_read")?;
  verify_config_sha256(config, &bytes)?;
  let database = parse_database_bytes(config, &bytes, registry)?;
  let modified = metadata.modified().ok();
  let database_stale = modified
    .and_then(|modified| modified.elapsed().ok())
    .is_some_and(|age| age.as_secs() > config.max_database_age_seconds);
  Ok(LoadedDatabase {
    database,
    cache_present: false,
    cache_fresh: false,
    database_stale,
    last_success_at: Some(unix_now()),
  })
}

async fn load_or_fetch_managed_database(
  config: &ClientIdentityAsnConfig,
  control_http: &ControlHttpClient,
  registry: Option<&AsnRegistry>,
) -> anyhow::Result<LoadedDatabase> {
  if config.managed.storage == ClientIdentityAsnManagedStorage::Memory {
    let remote = fetch_remote_database(config, control_http).await?;
    let database = parse_database_bytes(config, &remote.bytes, registry)?;
    return Ok(LoadedDatabase {
      database,
      cache_present: false,
      cache_fresh: false,
      database_stale: false,
      last_success_at: Some(unix_now()),
    });
  }

  let cached = load_cached_database(config).ok();
  if let Some(cached) = cached.as_ref()
    && !cached.stale
  {
    let database = parse_database_bytes(config, &cached.bytes, registry)?;
    return Ok(LoadedDatabase {
      database,
      cache_present: true,
      cache_fresh: true,
      database_stale: false,
      last_success_at: Some(cached.metadata.fetched_at),
    });
  }

  match fetch_and_store_database(config, control_http, registry).await {
    Ok(loaded) => Ok(loaded),
    Err(error) => {
      if let Some(cached) = cached {
        let database = parse_database_bytes(config, &cached.bytes, registry)?;
        return Ok(LoadedDatabase {
          database,
          cache_present: true,
          cache_fresh: false,
          database_stale: true,
          last_success_at: Some(cached.metadata.fetched_at),
        });
      }
      Err(error)
    }
  }
}

async fn fetch_and_store_database(
  config: &ClientIdentityAsnConfig,
  control_http: &ControlHttpClient,
  registry: Option<&AsnRegistry>,
) -> anyhow::Result<LoadedDatabase> {
  let remote = fetch_remote_database(config, control_http).await?;
  if config.managed.storage != ClientIdentityAsnManagedStorage::Memory {
    store_cached_database(config, &remote)?;
  }
  let database = parse_database_bytes(config, &remote.bytes, registry)?;
  Ok(LoadedDatabase {
    database,
    cache_present: config.managed.storage != ClientIdentityAsnManagedStorage::Memory,
    cache_fresh: config.managed.storage != ClientIdentityAsnManagedStorage::Memory,
    database_stale: false,
    last_success_at: Some(unix_now()),
  })
}

async fn fetch_remote_database(
  config: &ClientIdentityAsnConfig,
  control_http: &ControlHttpClient,
) -> anyhow::Result<RemoteDatabase> {
  let raw = config
    .managed
    .source_url
    .as_deref()
    .filter(|value| !value.trim().is_empty())
    .ok_or_else(|| anyhow!("asn_managed_source_url_missing"))?;
  let url = Url::parse(raw).context("asn_managed_source_url")?;
  if url.scheme() != "https" {
    bail!("asn_managed_source_url_scheme");
  }
  let request = http::Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&url)?)
    .header(ACCEPT, "text/csv,text/plain,*/*")
    .body(empty_body())
    .context("asn_managed_request_build")?;
  let max_bytes = config
    .max_database_bytes
    .min(config.managed.max_cache_bytes)
    .max(1);
  let response = control_http
    .request(
      request,
      Duration::from_millis(config.managed.request_timeout_ms),
      max_bytes,
    )
    .await
    .context("asn_managed_http")?;
  if response.status != http::StatusCode::OK {
    bail!("asn_managed_http_status");
  }
  verify_config_sha256(config, &response.body)?;
  Ok(RemoteDatabase {
    sha256: sha256_hex(&response.body),
    size: response.body.len(),
    bytes: response.body.to_vec(),
  })
}

fn load_cached_database(config: &ClientIdentityAsnConfig) -> anyhow::Result<CachedDatabase> {
  let dir = cache_dir(config);
  let metadata_path = dir.join(METADATA_CACHE_FILE);
  let database_path = dir.join(DATABASE_CACHE_FILE);
  let metadata: CacheMetadata =
    serde_json::from_slice(&fs::read(&metadata_path).context("asn_managed_cache_metadata_read")?)
      .context("asn_managed_cache_metadata_parse")?;
  if metadata.size > config.max_database_bytes || metadata.size > config.managed.max_cache_bytes {
    bail!("asn_managed_cache_too_large");
  }
  let bytes = fs::read(&database_path).context("asn_managed_cache_database_read")?;
  if bytes.len() != metadata.size {
    bail!("asn_managed_cache_size_mismatch");
  }
  verify_sha256(&metadata.sha256, &bytes).context("asn_managed_cache_hash_mismatch")?;
  verify_config_sha256(config, &bytes)?;
  Ok(CachedDatabase {
    stale: cache_is_stale(metadata.fetched_at, config.max_database_age_seconds),
    bytes,
    metadata,
  })
}

fn store_cached_database(
  config: &ClientIdentityAsnConfig,
  remote: &RemoteDatabase,
) -> anyhow::Result<()> {
  let dir = cache_dir(config);
  let metadata = CacheMetadata {
    sha256: remote.sha256.clone(),
    size: remote.size,
    fetched_at: unix_now(),
  };
  let metadata_bytes =
    serde_json::to_vec(&metadata).context("asn_managed_cache_metadata_encode")?;
  if remote.bytes.len() + metadata_bytes.len() > config.managed.max_cache_bytes {
    bail!("asn_managed_cache_too_large");
  }
  atomic_write(&dir.join(DATABASE_CACHE_FILE), &remote.bytes)
    .context("asn_managed_cache_database_write")?;
  atomic_write(&dir.join(METADATA_CACHE_FILE), &metadata_bytes)
    .context("asn_managed_cache_metadata_write")?;
  Ok(())
}

fn verify_config_sha256(config: &ClientIdentityAsnConfig, bytes: &[u8]) -> anyhow::Result<()> {
  let Some(expected) = config
    .database_sha256
    .as_deref()
    .map(str::trim)
    .filter(|value| !value.is_empty())
  else {
    return Ok(());
  };
  verify_sha256(&expected.to_ascii_lowercase(), bytes)
}

fn verify_sha256(expected: &str, bytes: &[u8]) -> anyhow::Result<()> {
  let actual = sha256_hex(bytes);
  if actual != expected.to_ascii_lowercase() {
    bail!("asn_database_sha256_mismatch");
  }
  Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
  let digest = crate::crypto::sha256(bytes);
  let mut output = String::with_capacity(digest.len() * 2);
  for byte in digest {
    use std::fmt::Write as _;
    let _ = write!(&mut output, "{byte:02x}");
  }
  output
}

fn cache_dir(config: &ClientIdentityAsnConfig) -> PathBuf {
  match config.managed.storage {
    ClientIdentityAsnManagedStorage::Memory => PathBuf::new(),
    ClientIdentityAsnManagedStorage::Tmpfs => config.managed.tmpfs_dir.clone(),
    ClientIdentityAsnManagedStorage::Disk => config.managed.cache_dir.clone(),
  }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent).context("asn_cache_create_dir")?;
  }
  let tmp = path.with_extension("tmp");
  fs::write(&tmp, bytes).context("asn_cache_tmp_write")?;
  fs::rename(&tmp, path).context("asn_cache_rename")?;
  Ok(())
}

async fn refresh_loop(inner: Weak<AsnRuntimeInner>, interval: Duration) {
  loop {
    tokio::time::sleep(interval).await;
    let Some(inner) = inner.upgrade() else {
      break;
    };
    let registry = match load_iana_registry(&inner.config, &inner.control_http).await {
      Ok(registry) => registry,
      Err(error) => {
        tracing::warn!(error = %error, "managed ASN IANA registry refresh failed");
        if let Ok(mut status) = inner.status.lock() {
          status.status = "degraded".to_string();
          status.last_refresh_at = Some(unix_now());
          status.next_refresh_at = next_refresh_at(&inner.config, Some(unix_now()));
          status.last_error_kind = Some("asn_iana_registry_refresh".to_string());
        }
        continue;
      }
    };
    match load_or_fetch_managed_database(&inner.config, &inner.control_http, registry.as_ref())
      .await
    {
      Ok(loaded) => {
        let entries = loaded.database.entries;
        inner.database.store(Arc::new(loaded.database));
        if let Ok(mut status) = inner.status.lock() {
          *status = AsnRuntimeStatus {
            status: if loaded.database_stale {
              "degraded".to_string()
            } else {
              "ok".to_string()
            },
            enabled: true,
            mode: config_mode_name(inner.config.mode),
            database_loaded: true,
            database_stale: loaded.database_stale,
            entries,
            cache_present: loaded.cache_present,
            cache_fresh: loaded.cache_fresh,
            managed: true,
            storage: Some(inner.config.managed.storage.as_str().to_string()),
            last_refresh_at: Some(unix_now()),
            next_refresh_at: next_refresh_at(&inner.config, Some(unix_now())),
            last_success_at: loaded.last_success_at,
            last_error_kind: None,
          };
        }
      }
      Err(error) => {
        tracing::warn!(error = %error, "managed ASN database refresh failed");
        if let Ok(mut status) = inner.status.lock() {
          status.status = "degraded".to_string();
          status.last_refresh_at = Some(unix_now());
          status.next_refresh_at = next_refresh_at(&inner.config, Some(unix_now()));
          status.last_error_kind = Some("asn_managed_refresh".to_string());
        }
      }
    }
  }
}

fn disabled_status() -> AsnRuntimeStatus {
  AsnRuntimeStatus {
    status: "disabled".to_string(),
    enabled: false,
    mode: "disabled",
    database_loaded: false,
    database_stale: false,
    entries: 0,
    cache_present: false,
    cache_fresh: false,
    managed: false,
    storage: None,
    last_refresh_at: None,
    next_refresh_at: None,
    last_success_at: None,
    last_error_kind: None,
  }
}

fn degraded_status(config: &ClientIdentityAsnConfig, error_kind: &str) -> AsnRuntimeStatus {
  AsnRuntimeStatus {
    status: "degraded".to_string(),
    enabled: true,
    mode: config_mode_name(config.mode),
    database_loaded: false,
    database_stale: false,
    entries: 0,
    cache_present: false,
    cache_fresh: false,
    managed: config.mode == ClientIdentityAsnMode::Managed,
    storage: (config.mode == ClientIdentityAsnMode::Managed)
      .then(|| config.managed.storage.as_str().to_string()),
    last_refresh_at: Some(unix_now()),
    next_refresh_at: next_refresh_at(config, Some(unix_now())),
    last_success_at: None,
    last_error_kind: Some(error_kind.to_string()),
  }
}

fn config_mode_name(mode: ClientIdentityAsnMode) -> &'static str {
  match mode {
    ClientIdentityAsnMode::Disabled => "disabled",
    ClientIdentityAsnMode::Local => "local",
    ClientIdentityAsnMode::Managed => "managed",
  }
}

fn next_refresh_at(config: &ClientIdentityAsnConfig, last: Option<u64>) -> Option<u64> {
  if config.mode != ClientIdentityAsnMode::Managed {
    return None;
  }
  last.map(|value| value.saturating_add(config.managed.refresh_interval_seconds))
}

fn cache_is_stale(fetched_at: u64, max_age_seconds: u64) -> bool {
  unix_now().saturating_sub(fetched_at) > max_age_seconds
}

fn unix_now() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}
