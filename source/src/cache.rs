//! Response cache coordination and cache-key enforcement for proxy traffic.
//! Cache admission remains separate from HTTP forwarding so policy decisions stay auditable.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use http::header::{
  CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, ETAG, EXPIRES, HeaderName, HeaderValue,
  IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, PRAGMA, VARY,
};
use http::{HeaderMap, Method, StatusCode, Uri};
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

use crate::config::{
  CacheAdmissionConfig, CacheConfig, CachePolicyConfig, CacheStaleIfErrorConfig, CacheStore,
  default_cache_tmpfs_dir,
};
use crate::overload::OverloadRuntime;
use crate::runtime_health::{
  PROCESS_GENERATION, RuntimeHealth, RuntimeSubsystem, RuntimeSubsystemError, RuntimeSubsystemState,
};
use crate::shared_state::SharedState;

mod entry;
mod external;
mod external_handler;
mod file_clone;
mod fill;
mod index;
mod insert;
mod key;
mod lookup;
mod metadata;
mod policy;
mod purge;
mod range;
mod recovery;
mod response_metadata;
mod revalidation;
mod shared;
mod shared_async;
pub mod signing;
mod storage;
mod streaming;

pub use entry::{CacheBodyFile, CacheEntry};
pub(crate) use external_handler::ExternalCacheRuntime;
pub(crate) use fill::{CacheFillDecision, CacheFillSuppressionReason};
pub use fill::{CacheFillGuard, CacheFillWaiter};
use key::*;
use metadata::{decode_metadata, encode_metadata, remove_metadata};
use policy::*;
pub(crate) use range::range_entry;
use response_metadata::*;
pub(in crate::cache) use shared::{shared_cache_entry, shared_cache_entry_metadata};
use storage::*;
pub use storage::{detect_memory_limit_bytes, validate_disk_dir, validate_tmpfs_dir};
pub(crate) use streaming::{CacheStreamingInsert, CacheStreamingInsertDecision};

const TMPFS_CACHE_ROOT: &str = "/dev/shm";
const SURROGATE_CONTROL_HEADER: &str = "surrogate-control";
const MAX_VARY_VALUE_BYTES: usize = 8_192;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_metadata_and_key(data: &[u8]) {
  const MAX_INPUT_BYTES: usize = 32 * 1024;
  let data = &data[..data.len().min(MAX_INPUT_BYTES)];
  let raw = String::from_utf8_lossy(data);
  metadata::fuzz_decode_metadata(&raw);

  let mut parts = raw.splitn(6, '\n');
  let template = parts.next().unwrap_or("{scheme}://{host}{uri}");
  let scheme = parts.next().unwrap_or("https");
  let host = parts.next().unwrap_or("cache.example.test");
  let uri_text = parts.next().unwrap_or("/resource?variant=one");
  let cookie = parts.next().unwrap_or("session=fuzz; variant=one");
  let header = parts.next().unwrap_or("fuzz");
  let uri = uri_text
    .parse::<Uri>()
    .unwrap_or_else(|_| Uri::from_static("/"));
  let mut headers = HeaderMap::new();
  if let Ok(value) = HeaderValue::from_str(cookie) {
    headers.insert(http::header::COOKIE, value);
  }
  if let Ok(value) = HeaderValue::from_str(header) {
    headers.insert(HeaderName::from_static("x-fuzz-variant"), value);
  }
  let expanded = expanded_cache_key(template, scheme, host, &uri, &headers);
  let vary = [VaryMatcher {
    name: "x-fuzz-variant".to_string(),
    value: header.to_string(),
  }];
  let _ = variant_key("fuzz", &expanded, &vary);
}
#[derive(Debug, Clone)]
pub struct Revalidation {
  pub entry: CacheEntry,
  pub request_headers: HeaderMap,
  pub serve_stale_on_error: bool,
}

#[derive(Debug, Clone)]
pub struct StaleEntry {
  pub entry: CacheEntry,
  pub request_headers: HeaderMap,
  pub serve_stale_on_error: bool,
  pub background_refresh: bool,
}

#[derive(Debug, Clone)]
pub enum CacheLookup {
  Fresh(CacheEntry),
  Stale(StaleEntry),
  Revalidate(Revalidation),
}

#[derive(Debug)]
pub enum CacheFillPermit {
  Leader(CacheFillGuard),
  Follower(CacheFillWaiter),
  SharedConflict,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
  pub memory_entries: usize,
  pub disk_entries: usize,
  pub tmpfs_entries: usize,
  pub memory_bytes: usize,
  pub disk_bytes: usize,
  pub tmpfs_bytes: usize,
  pub disk_recovered_entries_total: u64,
  pub disk_recovery_errors_total: u64,
  pub disk_recovery_removed_files_total: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CacheInsertOutcome {
  Stored,
  NotCacheable,
  Rejected,
  AdmissionWarming,
  StoreFailed,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CacheResponseHeadDecision {
  Cacheable,
  NotCacheable,
  Rejected,
}

#[derive(Debug)]
pub(crate) enum CachePreparedInsertDecision {
  Cacheable(Box<CachePreparedInsert>),
  NotCacheable(CacheFillSuppressionReason),
  Rejected(CacheFillSuppressionReason),
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

#[derive(Debug, Clone, Serialize)]
pub struct CacheKeyExplain {
  pub policy: String,
  pub enabled: bool,
  pub cacheable_method: bool,
  pub bypassed: bool,
  pub partition: String,
  pub base_key: String,
  pub variant_key: Option<String>,
  pub vary_fields: Vec<String>,
  pub reasons: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct CachePreparedInsert {
  policy: CachePolicyRuntime,
  partition: String,
  base_key: String,
  variant_key: String,
  scheme: String,
  host: String,
  uri: String,
  status: StatusCode,
  stored_headers: HeaderMap,
  metadata: ResponseMetadata,
  header_bytes: usize,
}

#[derive(Debug, Clone)]
pub(in crate::cache) struct StoredEntry {
  policy: String,
  partition: String,
  base_key: String,
  variant_key: String,
  scheme: String,
  host: String,
  uri: String,
  status: StatusCode,
  headers: HeaderMap,
  security_headers_neutral: bool,
  body: StoredBody,
  expires_at: SystemTime,
  stale_if_error_until: Option<SystemTime>,
  stale_while_revalidate_until: Option<SystemTime>,
  must_revalidate: bool,
  stored_at: SystemTime,
  vary: Vec<VaryMatcher>,
  tags: Vec<String>,
  size: usize,
}

#[derive(Debug, Clone)]
enum StoredBody {
  Memory(Bytes),
  Tmpfs(PathBuf),
  Disk(PathBuf),
}

#[derive(Debug, Clone)]
struct CacheOperationContext {
  policy: CachePolicyRuntime,
  partition: String,
  base_key: String,
  lookup_key: index::LookupKey,
  fill_key: String,
  scheme: String,
  host: String,
  uri: String,
}

#[derive(Debug, Clone, Copy)]
enum CacheFileKind {
  Body,
  BodyTmp,
  Meta,
  MetaTmp,
}

impl CacheFileKind {
  fn suffix(self) -> &'static str {
    match self {
      Self::Body => "body",
      Self::BodyTmp => "body.tmp",
      Self::Meta => "meta",
      Self::MetaTmp => "meta.tmp",
    }
  }
}

#[derive(Debug, Clone)]
struct VaryMatcher {
  name: String,
  value: String,
}

#[derive(Debug, Default)]
struct CacheInner {
  entries: HashMap<String, StoredEntry>,
  index: index::CacheIndex,
  order: VecDeque<String>,
  purge_nonces: HashMap<String, SystemTime>,
  purge_nonce_order: VecDeque<String>,
  memory_size: usize,
  disk_size: usize,
  disk_inflight_size: usize,
  tmpfs_size: usize,
  admission_counts: HashMap<String, u32>,
  admission_order: VecDeque<String>,
  disk_recovered_entries_total: u64,
  disk_recovery_errors_total: u64,
  disk_recovery_removed_files_total: u64,
}

#[derive(Debug, Clone)]
struct CachePolicyRuntime {
  name: String,
  store: CacheStore,
  cache_key: String,
  partition_key: String,
  default_ttl_seconds: u64,
  negative_statuses: Vec<StatusCode>,
  negative_ttl_seconds: u64,
  memory_max_size_bytes: usize,
  disk_max_size_bytes: Option<usize>,
  tag_headers: Vec<HeaderName>,
  max_tags_per_entry: usize,
  max_tag_bytes: usize,
  max_vary_fields: usize,
  max_vary_variants_per_key: usize,
  background_refresh: bool,
  background_refresh_max_concurrent: usize,
  lock_wait_timeout: Duration,
  external_handler: Option<String>,
  admission: CacheAdmissionRuntime,
  stale_if_error: CacheStaleIfErrorConfig,
  rules: Vec<CachePolicyRuleRuntime>,
}

#[derive(Debug, Clone)]
struct CacheAdmissionRuntime {
  statuses: Vec<StatusCode>,
  content_types: Vec<String>,
  max_body_bytes: usize,
  min_hits: usize,
  max_tracked_keys: usize,
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
  bypass_request_headers: Vec<HeaderName>,
  refresh_limiters: HashMap<String, Arc<Semaphore>>,
  tmpfs_dir: Option<PathBuf>,
  disk_dir: Option<PathBuf>,
  fills: Arc<fill::CacheFillCoordinator>,
  inner: Mutex<CacheInner>,
  disk_recovery: Mutex<Option<recovery::DiskRecoveryState>>,
  disk_rebuild_requested: AtomicBool,
  runtime_health: Arc<RuntimeHealth>,
  shared_state: Option<Arc<SharedState>>,
  external_cache: ExternalCacheRuntime,
  overload: ArcSwapOption<OverloadRuntime>,
}

impl Drop for ResponseCache {
  fn drop(&mut self) {
    let mut inner = self.inner_guard();
    for (_, entry) in inner.entries.drain() {
      if !matches!(entry.body, StoredBody::Disk(_)) {
        entry.remove_body();
      }
    }
    inner.order.clear();
    inner.index.clear();
    inner.memory_size = 0;
    inner.disk_size = 0;
    inner.disk_inflight_size = 0;
    inner.tmpfs_size = 0;
  }
}

#[cfg(test)]
#[path = "cache/tests.rs"]
mod tests;
