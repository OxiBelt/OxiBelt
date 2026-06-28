use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use http::header::ACCEPT;
use ring::digest;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::{CrliteConfig, CrliteManagedStorage, TlsConfig};
use crate::control_http::{ControlHttpClient, ControlHttpResponse, empty_body, uri_from_url};

const REMOTE_SETTINGS_ROOT: &str = "https://firefox.settings.services.mozilla.com/v1/";
const CERT_REVOCATIONS_RECORDS_PATH: &str =
  "buckets/security-state/collections/cert-revocations/records";
const JSON_MAX_BODY_BYTES: usize = 1_048_576;
const FILTER_CACHE_FILE: &str = "crlite.filter";
const METADATA_CACHE_FILE: &str = "crlite.metadata.json";

#[derive(Debug)]
pub(super) struct ManagedFilter {
  pub bytes: Vec<u8>,
  pub cache_present: bool,
  pub cache_fresh: bool,
  pub filter_stale: bool,
  pub last_success_at: Option<u64>,
}

#[derive(Clone)]
pub(super) struct ManagedCrliteRemoteClient {
  control_http: ControlHttpClient,
}

impl ManagedCrliteRemoteClient {
  pub(super) fn new_webpki_only() -> anyhow::Result<Self> {
    Ok(Self {
      control_http: ControlHttpClient::new_webpki_only()?,
    })
  }

  async fn request(
    &self,
    request: http::Request<crate::control_http::ControlBody>,
    timeout: Duration,
    max_body_bytes: usize,
  ) -> anyhow::Result<ControlHttpResponse> {
    self
      .control_http
      .request(request, timeout, max_body_bytes)
      .await
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMetadata {
  sha256: String,
  size: usize,
  fetched_at: u64,
  record_last_modified: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RootResponse {
  capabilities: Option<RootCapabilities>,
}

#[derive(Debug, Deserialize)]
struct RootCapabilities {
  attachments: Option<AttachmentCapability>,
}

#[derive(Debug, Deserialize)]
struct AttachmentCapability {
  base_url: String,
}

#[derive(Debug, Deserialize)]
struct RecordsResponse {
  data: Vec<RemoteRecord>,
}

#[derive(Debug, Clone, Deserialize)]
struct RemoteRecord {
  last_modified: Option<u64>,
  attachment: Option<RemoteAttachment>,
}

#[derive(Debug, Clone, Deserialize)]
struct RemoteAttachment {
  location: String,
  hash: String,
  size: u64,
  filename: Option<String>,
}

#[derive(Debug)]
struct RemoteFilter {
  bytes: Vec<u8>,
  sha256: String,
  size: usize,
  record_last_modified: Option<u64>,
}

#[derive(Debug)]
struct CachedFilter {
  bytes: Vec<u8>,
  stale: bool,
  metadata: CacheMetadata,
}

pub(super) async fn load_or_fetch_filter(
  tls: &TlsConfig,
  remote_client: &ManagedCrliteRemoteClient,
) -> anyhow::Result<ManagedFilter> {
  load_or_fetch_filter_for_config(&tls.crlite, remote_client).await
}

pub(super) async fn load_or_fetch_filter_for_config(
  config: &CrliteConfig,
  remote_client: &ManagedCrliteRemoteClient,
) -> anyhow::Result<ManagedFilter> {
  if config.managed.storage == CrliteManagedStorage::Memory {
    return fetch_filter(config, remote_client)
      .await
      .map(|filter| ManagedFilter {
        bytes: filter.bytes,
        cache_present: false,
        cache_fresh: false,
        filter_stale: false,
        last_success_at: Some(unix_now()),
      });
  }

  let cached = load_cached_filter(config).ok();
  if let Some(cached) = cached.as_ref()
    && !cached.stale
  {
    return Ok(ManagedFilter {
      bytes: cached.bytes.clone(),
      cache_present: true,
      cache_fresh: true,
      filter_stale: false,
      last_success_at: Some(cached.metadata.fetched_at),
    });
  }

  match fetch_and_store_filter_for_config(config, remote_client).await {
    Ok(filter) => Ok(filter),
    Err(error) => {
      if let Some(cached) = cached {
        return Ok(ManagedFilter {
          bytes: cached.bytes,
          cache_present: true,
          cache_fresh: false,
          filter_stale: true,
          last_success_at: Some(cached.metadata.fetched_at),
        });
      }
      Err(error)
    }
  }
}

pub(super) async fn fetch_and_store_filter(
  tls: &TlsConfig,
  remote_client: &ManagedCrliteRemoteClient,
) -> anyhow::Result<ManagedFilter> {
  fetch_and_store_filter_for_config(&tls.crlite, remote_client).await
}

pub(super) async fn fetch_and_store_filter_for_config(
  config: &CrliteConfig,
  remote_client: &ManagedCrliteRemoteClient,
) -> anyhow::Result<ManagedFilter> {
  let filter = fetch_filter(config, remote_client).await?;
  if config.managed.storage != CrliteManagedStorage::Memory {
    store_cached_filter(config, &filter)?;
  }
  Ok(ManagedFilter {
    bytes: filter.bytes,
    cache_present: config.managed.storage != CrliteManagedStorage::Memory,
    cache_fresh: config.managed.storage != CrliteManagedStorage::Memory,
    filter_stale: false,
    last_success_at: Some(unix_now()),
  })
}

pub(super) fn storage_name(storage: CrliteManagedStorage) -> &'static str {
  storage.as_str()
}

fn load_cached_filter(config: &CrliteConfig) -> anyhow::Result<CachedFilter> {
  let dir = cache_dir(config);
  let metadata_path = dir.join(METADATA_CACHE_FILE);
  let filter_path = dir.join(FILTER_CACHE_FILE);
  let metadata: CacheMetadata = serde_json::from_slice(
    &fs::read(&metadata_path).with_context(|| "crlite_managed_cache_metadata_read")?,
  )
  .with_context(|| "crlite_managed_cache_metadata_parse")?;
  if metadata.size > config.max_filter_bytes || metadata.size > config.managed.max_cache_bytes {
    bail!("crlite_managed_cache_too_large");
  }
  let bytes = fs::read(&filter_path).with_context(|| "crlite_managed_cache_filter_read")?;
  if bytes.len() != metadata.size {
    bail!("crlite_managed_cache_size_mismatch");
  }
  verify_sha256(&metadata.sha256, &bytes).with_context(|| "crlite_managed_cache_hash_mismatch")?;
  Ok(CachedFilter {
    bytes,
    stale: cache_is_stale(metadata.fetched_at, config.max_filter_age_seconds),
    metadata,
  })
}

fn store_cached_filter(config: &CrliteConfig, filter: &RemoteFilter) -> anyhow::Result<()> {
  let dir = cache_dir(config);
  let metadata = CacheMetadata {
    sha256: filter.sha256.clone(),
    size: filter.size,
    fetched_at: unix_now(),
    record_last_modified: filter.record_last_modified,
  };
  let metadata_bytes =
    serde_json::to_vec(&metadata).with_context(|| "crlite_managed_cache_metadata_encode")?;
  if filter.bytes.len() + metadata_bytes.len() > config.managed.max_cache_bytes {
    bail!("crlite_managed_cache_too_large");
  }
  atomic_write(&dir.join(FILTER_CACHE_FILE), &filter.bytes)
    .with_context(|| "crlite_managed_cache_filter_write")?;
  atomic_write(&dir.join(METADATA_CACHE_FILE), &metadata_bytes)
    .with_context(|| "crlite_managed_cache_metadata_write")?;
  Ok(())
}

async fn fetch_filter(
  config: &CrliteConfig,
  remote_client: &ManagedCrliteRemoteClient,
) -> anyhow::Result<RemoteFilter> {
  let timeout = Duration::from_millis(config.managed.request_timeout_ms);
  let root_url = Url::parse(REMOTE_SETTINGS_ROOT).expect("Remote Settings root URL is valid");
  let root: RootResponse = fetch_json(remote_client, root_url.clone(), timeout)
    .await
    .with_context(|| "crlite_managed_root_fetch")?;
  let base_url = attachment_base_url(root)?;
  let records_url = root_url
    .join(CERT_REVOCATIONS_RECORDS_PATH)
    .expect("Remote Settings records path is valid");
  let records: RecordsResponse = fetch_json(remote_client, records_url, timeout)
    .await
    .with_context(|| "crlite_managed_records_fetch")?;
  let record = select_filter_record(&records.data)?;
  let attachment = record
    .attachment
    .as_ref()
    .ok_or_else(|| anyhow!("crlite_managed_missing_attachment"))?;
  let expected_hash = normalize_sha256(&attachment.hash)?;
  let expected_size =
    usize::try_from(attachment.size).map_err(|_| anyhow!("crlite_managed_attachment_too_large"))?;
  if expected_size > config.max_filter_bytes || expected_size > config.managed.max_cache_bytes {
    bail!("crlite_managed_attachment_too_large");
  }
  let attachment_url = attachment_url(&base_url, attachment)?;
  let body = fetch_bytes(remote_client, attachment_url, timeout, expected_size).await?;
  if body.len() != expected_size {
    bail!("crlite_managed_attachment_size_mismatch");
  }
  verify_sha256(&expected_hash, &body)?;
  Ok(RemoteFilter {
    bytes: body,
    sha256: expected_hash,
    size: expected_size,
    record_last_modified: record.last_modified,
  })
}

async fn fetch_json<T>(
  remote_client: &ManagedCrliteRemoteClient,
  url: Url,
  timeout: Duration,
) -> anyhow::Result<T>
where
  T: for<'de> Deserialize<'de>,
{
  let request = http::Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&url)?)
    .header(ACCEPT, "application/json")
    .body(empty_body())
    .context("crlite_managed_request_build")?;
  let response = remote_client
    .request(request, timeout, JSON_MAX_BODY_BYTES)
    .await
    .context("crlite_managed_http")?;
  if response.status != http::StatusCode::OK {
    bail!("crlite_managed_http_status");
  }
  serde_json::from_slice(&response.body).context("crlite_managed_json_parse")
}

async fn fetch_bytes(
  remote_client: &ManagedCrliteRemoteClient,
  url: Url,
  timeout: Duration,
  max_body_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
  if url.scheme() != "https" {
    bail!("crlite_managed_attachment_url_scheme");
  }
  let request = http::Request::builder()
    .method(http::Method::GET)
    .uri(uri_from_url(&url)?)
    .body(empty_body())
    .context("crlite_managed_request_build")?;
  let response = remote_client
    .request(request, timeout, max_body_bytes)
    .await
    .context("crlite_managed_attachment_fetch")?;
  if response.status != http::StatusCode::OK {
    bail!("crlite_managed_attachment_http_status");
  }
  Ok(response.body.to_vec())
}

fn attachment_base_url(root: RootResponse) -> anyhow::Result<Url> {
  let raw = root
    .capabilities
    .and_then(|capabilities| capabilities.attachments)
    .map(|attachments| attachments.base_url)
    .ok_or_else(|| anyhow!("crlite_managed_missing_attachment_base_url"))?;
  let url = Url::parse(&raw).context("crlite_managed_attachment_base_url")?;
  if url.scheme() != "https" {
    bail!("crlite_managed_attachment_base_url_scheme");
  }
  Ok(url)
}

fn select_filter_record(records: &[RemoteRecord]) -> anyhow::Result<RemoteRecord> {
  records
    .iter()
    .filter(|record| {
      record
        .attachment
        .as_ref()
        .is_some_and(attachment_looks_like_filter)
    })
    .max_by_key(|record| record.last_modified.unwrap_or_default())
    .cloned()
    .ok_or_else(|| anyhow!("crlite_managed_no_filter_record"))
}

fn attachment_looks_like_filter(attachment: &RemoteAttachment) -> bool {
  let mut text = attachment.location.to_ascii_lowercase();
  if let Some(filename) = attachment.filename.as_deref() {
    text.push(' ');
    text.push_str(&filename.to_ascii_lowercase());
  }
  text.contains("filter") && !text.contains("stash")
}

fn attachment_url(base_url: &Url, attachment: &RemoteAttachment) -> anyhow::Result<Url> {
  base_url
    .join(&attachment.location)
    .context("crlite_managed_attachment_url")
}

fn cache_dir(config: &CrliteConfig) -> PathBuf {
  match config.managed.storage {
    CrliteManagedStorage::Memory => PathBuf::new(),
    CrliteManagedStorage::Tmpfs => config.managed.tmpfs_dir.clone(),
    CrliteManagedStorage::Disk => config.managed.cache_dir.clone(),
  }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
  let tmp = path.with_extension("tmp");
  fs::write(&tmp, bytes)?;
  fs::rename(&tmp, path)?;
  Ok(())
}

fn cache_is_stale(fetched_at: u64, max_age_seconds: u64) -> bool {
  unix_now().saturating_sub(fetched_at) > max_age_seconds
}

fn normalize_sha256(raw: &str) -> anyhow::Result<String> {
  let hash = raw
    .strip_prefix("sha256:")
    .unwrap_or(raw)
    .to_ascii_lowercase();
  if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("crlite_managed_attachment_hash");
  }
  Ok(hash)
}

fn verify_sha256(expected: &str, bytes: &[u8]) -> anyhow::Result<()> {
  let actual = hex_digest(digest::digest(&digest::SHA256, bytes).as_ref());
  if !actual.eq_ignore_ascii_case(expected) {
    bail!("crlite_managed_sha256_mismatch");
  }
  Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

fn unix_now() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn managed_remote_client_builds_with_webpki_only_trust() {
    ManagedCrliteRemoteClient::new_webpki_only()
      .expect("managed CRLite remote client should build with WebPKI-only trust");
  }

  #[test]
  fn selects_latest_filter_record_and_ignores_stashes() {
    let records = vec![
      record("old-filter", "older-filter", 1),
      record("new-stash", "new-filter.stash", 3),
      record("new-filter", "new-filter", 2),
    ];

    let selected = select_filter_record(&records).expect("filter record");

    assert_eq!(selected.last_modified, Some(2));
  }

  #[test]
  fn cache_round_trip_verifies_hash_size_and_freshness() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let mut tls = test_tls(temp_dir.path().to_path_buf());
    tls.crlite.managed.max_cache_bytes = 1024;
    tls.crlite.max_filter_age_seconds = 60;
    let bytes = b"filter bytes".to_vec();
    let filter = RemoteFilter {
      sha256: hex_digest(digest::digest(&digest::SHA256, &bytes).as_ref()),
      size: bytes.len(),
      bytes: bytes.clone(),
      record_last_modified: Some(42),
    };

    store_cached_filter(&tls.crlite, &filter).expect("cache write");
    let cached = load_cached_filter(&tls.crlite).expect("cache read");

    assert_eq!(cached.bytes, bytes);
    assert!(!cached.stale);
    assert_eq!(cached.metadata.record_last_modified, Some(42));
  }

  #[test]
  fn cache_hash_mismatch_is_rejected() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let tls = test_tls(temp_dir.path().to_path_buf());
    let metadata = CacheMetadata {
      sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
      size: 4,
      fetched_at: unix_now(),
      record_last_modified: None,
    };
    fs::write(
      temp_dir.path().join(METADATA_CACHE_FILE),
      serde_json::to_vec(&metadata).expect("metadata"),
    )
    .expect("metadata write");
    fs::write(temp_dir.path().join(FILTER_CACHE_FILE), b"test").expect("filter write");

    let error = load_cached_filter(&tls.crlite).expect_err("hash mismatch");

    assert!(format!("{error:#}").contains("crlite_managed_cache_hash_mismatch"));
  }

  fn record(_id: &str, location: &str, last_modified: u64) -> RemoteRecord {
    RemoteRecord {
      last_modified: Some(last_modified),
      attachment: Some(RemoteAttachment {
        location: location.to_string(),
        hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        size: 1,
        filename: None,
      }),
    }
  }

  fn test_tls(cache_dir: PathBuf) -> TlsConfig {
    let mut tls = TlsConfig {
      server_names: Vec::new(),
      cert_chain: PathBuf::from("cert.pem"),
      private_key: Some(PathBuf::from("key.pem")),
      remote_signer: crate::config::TlsRemoteSignerConfig::default(),
      require_sni: false,
      reject_unknown_sni: false,
      certificates: Vec::new(),
      min_version: crate::config::TlsVersion::Tls13,
      max_version: crate::config::TlsVersion::Tls13,
      tls12: crate::config::TlsVersionKeyExchangeConfig {
        key_exchange_groups: Vec::new(),
      },
      tls13: crate::config::TlsVersionKeyExchangeConfig {
        key_exchange_groups: Vec::new(),
      },
      key_exchange_groups: Vec::new(),
      session_tickets: true,
      session_ticket_rotation_seconds: 86_400,
      resumption: crate::config::TlsServerResumptionConfig::default(),
      client_auth: crate::config::TlsClientAuthConfig::default(),
      ocsp: crate::config::OcspConfig::default(),
      crlite: crate::config::CrliteConfig::default(),
    };
    tls.crlite.mode = crate::config::CrliteMode::Managed;
    tls.crlite.managed.cache_dir = cache_dir;
    tls
  }
}
