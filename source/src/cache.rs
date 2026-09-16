//! Response cache coordination and cache-key enforcement for proxy traffic.
//! Cache admission remains separate from HTTP forwarding so policy decisions stay auditable.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
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
mod nvs;
pub use nvs::{CacheNvsCandidate, CacheNvsExplain, CacheNvsMetadata, CacheNvsRequest};
mod no_vary_search;
mod policy;
mod proxy_protocol_identity;
pub use proxy_protocol_identity::CacheProxyProtocolIdentity;
mod purge;
mod query_cleanup;
mod query_epoch_disk;
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
pub(crate) use key::*;
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
pub(crate) const QUERY_IDENTITY_METADATA_MAX_BYTES: usize = 8_192;
pub(crate) const QUERY_IDENTITY_MAX_FIELDS: usize = 64;
const MAX_CERTIFICATE_IDENTITY_HEADER_BYTES: usize = 128;
const MAX_CERTIFICATE_IDENTITY_FORMAT_BYTES: usize = 64;
const CERTIFICATE_FINGERPRINT_SHA256_BYTES: usize = 64;
/// Fixed Q1 invalidation buckets bound memory while conservatively coupling
/// colliding targets (a miss/bypass is safe; a stale hit is not).
pub(crate) const QUERY_EPOCH_BUCKETS: u16 = 256;

/// Opaque, verified leaf-certificate identity used only to separate internal
/// response-cache namespaces.
///
/// This deliberately contains no certificate bytes. `None` for `fingerprint`
/// represents an enabled forwarding policy with no client certificate, while
/// a missing [`CacheCertificateIdentity`] represents forwarding being off.
#[derive(Clone, Eq, PartialEq)]
pub struct CacheCertificateIdentity {
  header_name: HeaderName,
  format: String,
  fingerprint_sha256: Option<String>,
}

impl std::fmt::Debug for CacheCertificateIdentity {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("CacheCertificateIdentity")
      .field("header_name", &self.header_name)
      .field("format", &self.format)
      .field("authenticated", &self.is_authenticated())
      .finish()
  }
}

impl CacheCertificateIdentity {
  /// Creates a bounded cache discriminator from already-verified leaf evidence.
  ///
  /// Callers must provide the normalized forwarding header name and a stable
  /// format identifier. The cache validates both again to keep this pure cache
  /// boundary independent from TLS implementation details.
  pub fn new(
    header_name: &str,
    format: &str,
    fingerprint_sha256: Option<&str>,
  ) -> anyhow::Result<Self> {
    if header_name.is_empty() || header_name.len() > MAX_CERTIFICATE_IDENTITY_HEADER_BYTES {
      bail!("cache certificate identity header name is out of bounds");
    }
    let header_name = HeaderName::from_bytes(header_name.as_bytes())?;
    let format = format.trim();
    if format.is_empty()
      || format.len() > MAX_CERTIFICATE_IDENTITY_FORMAT_BYTES
      || !format.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
      })
    {
      bail!("cache certificate identity format must be a lowercase bounded token");
    }
    let fingerprint_sha256 = fingerprint_sha256
      .map(|fingerprint| {
        if fingerprint.len() != CERTIFICATE_FINGERPRINT_SHA256_BYTES
          || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
          bail!("cache certificate identity fingerprint must be a SHA-256 hex digest");
        }
        Ok(fingerprint.to_ascii_lowercase())
      })
      .transpose()?;
    Ok(Self {
      header_name,
      format: format.to_string(),
      fingerprint_sha256,
    })
  }

  /// The configured header name, normalized by `http::HeaderName`.
  pub fn header_name(&self) -> &HeaderName {
    &self.header_name
  }

  /// Stable serialization format selected by the route configuration.
  pub fn format(&self) -> &str {
    &self.format
  }

  /// Whether this cache namespace represents a verified client certificate.
  ///
  /// This intentionally reveals only presence, not the fingerprint or any
  /// certificate material, so response compression can retain identity-safe
  /// behavior for cached responses.
  pub fn is_authenticated(&self) -> bool {
    self.fingerprint_sha256.is_some()
  }

  pub(crate) fn fingerprint_sha256(&self) -> Option<&str> {
    self.fingerprint_sha256.as_deref()
  }
}

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
  pub no_vary_search: Option<&'a CacheNvsRequest>,
  pub proxy_protocol_identity: Option<&'a CacheProxyProtocolIdentity>,
  pub policy_name: Option<&'a str>,
  pub scheme: &'a str,
  pub host: &'a str,
  pub method: &'a Method,
  pub uri: &'a Uri,
  pub request_headers: &'a HeaderMap,
  /// QUERY-only cache identity.  A QUERY request is never cacheable without
  /// this complete, bounded identity.
  pub query_identity: Option<&'a CacheQueryIdentity>,
  /// `None` means client-certificate forwarding is off for this request.
  pub certificate_identity: Option<&'a CacheCertificateIdentity>,
}

#[derive(Debug, Clone)]
pub struct CacheLookupContext<'a> {
  pub no_vary_search: Option<&'a CacheNvsRequest>,
  pub proxy_protocol_identity: Option<&'a CacheProxyProtocolIdentity>,
  pub policy_name: Option<&'a str>,
  pub scheme: &'a str,
  pub host: &'a str,
  pub method: &'a Method,
  pub uri: &'a Uri,
  pub request_headers: &'a HeaderMap,
  /// QUERY-only cache identity.  A QUERY request is never cacheable without
  /// this complete, bounded identity.
  pub query_identity: Option<&'a CacheQueryIdentity>,
  /// `None` means client-certificate forwarding is off for this request.
  pub certificate_identity: Option<&'a CacheCertificateIdentity>,
}

/// The target and representation of one side of a QUERY transformation.
///
/// This contains only bounded request metadata and a body digest; it never
/// owns request content or a replay handle.  The proxy constructs an original
/// representation before request transformations and an effective one after
/// them, then passes both to [`CacheQueryIdentity`].
#[derive(Clone)]
pub struct CacheQueryRepresentation {
  target_scheme: String,
  target_authority: String,
  target_uri: String,
  body_len: u64,
  body_sha256: [u8; 32],
  content_headers: HeaderMap,
  trailers: HeaderMap,
}

impl std::fmt::Debug for CacheQueryRepresentation {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("CacheQueryRepresentation")
      .field("target_scheme", &self.target_scheme)
      .field("target_authority", &self.target_authority)
      .field("target_uri", &self.target_uri)
      .field("body_len", &self.body_len)
      .field("content_header_count", &self.content_headers.len())
      .field("trailer_count", &self.trailers.len())
      .finish_non_exhaustive()
  }
}

impl CacheQueryRepresentation {
  /// Builds one bounded QUERY representation. `headers` is reduced to
  /// Content-* fields except Content-Length; trailers are retained separately
  /// because they have distinct HTTP semantics.
  pub fn new(
    target_scheme: &str,
    target_authority: &str,
    target_uri: &Uri,
    body_len: u64,
    body_sha256: [u8; 32],
    headers: &HeaderMap,
    trailers: &HeaderMap,
  ) -> anyhow::Result<Self> {
    query_representation_from_parts(
      target_scheme,
      target_authority,
      target_uri,
      body_len,
      body_sha256,
      headers,
      trailers,
    )
  }
}

/// Complete cache identity for an exact-uppercase QUERY request.
///
/// `cache_view_headers` are the final headers sent to the origin and are used
/// for configured cache-key/partition tokens and Vary matching.  The original
/// and effective representations remain separate so a WAF or coding transform
/// cannot collapse distinct received queries.
#[derive(Clone)]
pub struct CacheQueryIdentity {
  original: CacheQueryRepresentation,
  effective: CacheQueryRepresentation,
  cache_view_headers: HeaderMap,
  generation: Arc<Mutex<Option<CacheQueryGeneration>>>,
  epoch_authority_failed: Arc<AtomicBool>,
}

impl std::fmt::Debug for CacheQueryIdentity {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("CacheQueryIdentity")
      .field("original", &self.original)
      .field("effective", &self.effective)
      .field("cache_view_header_count", &self.cache_view_headers.len())
      .finish_non_exhaustive()
  }
}

impl CacheQueryIdentity {
  pub fn new(
    original: CacheQueryRepresentation,
    effective: CacheQueryRepresentation,
    cache_view_headers: HeaderMap,
  ) -> anyhow::Result<Self> {
    validate_query_header_map(&cache_view_headers, QUERY_IDENTITY_METADATA_MAX_BYTES)?;
    Ok(Self {
      original,
      effective,
      cache_view_headers,
      generation: Arc::new(Mutex::new(None)),
      epoch_authority_failed: Arc::new(AtomicBool::new(false)),
    })
  }

  pub fn cache_view_headers(&self) -> &HeaderMap {
    &self.cache_view_headers
  }

  pub(crate) fn append_key_material(&self, output: &mut Vec<u8>) {
    append_query_representation(output, &self.original);
    append_query_representation(output, &self.effective);
  }

  pub(crate) fn query_target_epoch(&self) -> Option<u64> {
    self
      .generation
      .lock()
      .unwrap_or_else(|error| error.into_inner())
      .as_ref()
      .map(|generation| generation.value)
  }

  pub(crate) fn reject_query_cache_epoch(&self) {
    self.epoch_authority_failed.store(true, Ordering::Release);
  }

  pub(crate) fn query_cache_epoch_rejected(&self) -> bool {
    self.epoch_authority_failed.load(Ordering::Acquire)
  }
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheKeyExplain {
  pub policy: String,
  pub enabled: bool,
  pub cacheable_method: bool,
  pub bypassed: bool,
  pub no_vary_search: Option<CacheNvsExplain>,
  pub partition: String,
  pub base_key: String,
  pub variant_key: Option<String>,
  pub vary_fields: Vec<String>,
  pub reasons: Vec<String>,
}

fn query_representation_from_parts(
  target_scheme: &str,
  target_authority: &str,
  target_uri: &Uri,
  body_len: u64,
  body_sha256: [u8; 32],
  headers: &HeaderMap,
  trailers: &HeaderMap,
) -> anyhow::Result<CacheQueryRepresentation> {
  if target_scheme.is_empty()
    || target_authority.is_empty()
    || target_uri.path().is_empty()
    || !target_uri.path().starts_with('/')
  {
    bail!("QUERY cache identity target is invalid");
  }
  let mut content_headers = HeaderMap::new();
  for (name, value) in headers {
    if name.as_str().starts_with("content-") && name != http::header::CONTENT_LENGTH {
      content_headers.append(name.clone(), value.clone());
    }
  }
  validate_query_header_map(&content_headers, QUERY_IDENTITY_METADATA_MAX_BYTES)?;
  validate_query_header_map(trailers, QUERY_IDENTITY_METADATA_MAX_BYTES)?;
  Ok(CacheQueryRepresentation {
    target_scheme: target_scheme.to_string(),
    target_authority: target_authority.to_string(),
    target_uri: target_uri.to_string(),
    body_len,
    body_sha256,
    content_headers,
    trailers: trailers.clone(),
  })
}

fn validate_query_header_map(headers: &HeaderMap, max_bytes: usize) -> anyhow::Result<()> {
  if headers.len() > QUERY_IDENTITY_MAX_FIELDS {
    bail!("QUERY cache identity has too many metadata fields");
  }
  let bytes = headers.iter().try_fold(0usize, |total, (name, value)| {
    total
      .checked_add(name.as_str().len())
      .and_then(|total| total.checked_add(value.as_bytes().len()))
      .and_then(|total| total.checked_add(8))
  });
  if bytes.is_none_or(|bytes| bytes > max_bytes) {
    bail!("QUERY cache identity metadata exceeds its bound");
  }
  Ok(())
}

fn append_query_representation(output: &mut Vec<u8>, representation: &CacheQueryRepresentation) {
  append_query_field(output, representation.target_scheme.as_bytes());
  append_query_field(output, representation.target_authority.as_bytes());
  append_query_field(output, representation.target_uri.as_bytes());
  append_query_field(output, &representation.body_len.to_be_bytes());
  append_query_field(output, &representation.body_sha256);
  append_query_headers(output, &representation.content_headers);
  append_query_headers(output, &representation.trailers);
}

fn append_query_headers(output: &mut Vec<u8>, headers: &HeaderMap) {
  let mut fields = headers
    .iter()
    .map(|(name, value)| (name.as_str(), value.as_bytes()))
    .collect::<Vec<_>>();
  // Canonicalize distinct field names while retaining the wire order of
  // repeated values for one name. QUERY identity binds ordered trailers.
  fields.sort_by_key(|(name, _)| *name);
  append_query_field(output, &(fields.len() as u64).to_be_bytes());
  for (name, value) in fields {
    append_query_field(output, name.as_bytes());
    append_query_field(output, value);
  }
}

fn append_query_field(output: &mut Vec<u8>, value: &[u8]) {
  output.extend_from_slice(&(value.len() as u64).to_be_bytes());
  output.extend_from_slice(value);
}

#[derive(Debug)]
pub(crate) struct CachePreparedInsert {
  no_vary_search: Option<CacheNvsMetadata>,
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
  fill_key: String,
  query_target: Option<CacheQueryInvalidationTarget>,
  query_generation: Option<CacheQueryGeneration>,
}

#[derive(Debug, Clone)]
pub(in crate::cache) struct StoredEntry {
  no_vary_search: Option<CacheNvsMetadata>,
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
  /// Persisted Q1 target epoch. `None` is reserved for legacy methods.
  query_target_epoch: Option<u64>,
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
  query_target: Option<CacheQueryInvalidationTarget>,
}

/// Identifies the equivalent resource whose QUERY variants are invalidated.
/// It intentionally has no body material: invalidation covers every QUERY
/// representation of this target in the selected partition.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct CacheQueryInvalidationTarget {
  policy: String,
  scheme: String,
  host: String,
  uri: String,
  partition: Option<String>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct CacheQueryTargetKey {
  policy: String,
  scheme: String,
  host: String,
  uri: String,
}

impl CacheQueryTargetKey {
  fn from_target(target: &CacheQueryInvalidationTarget) -> Self {
    Self {
      policy: target.policy.clone(),
      scheme: target.scheme.clone(),
      host: target.host.clone(),
      uri: target.uri.clone(),
    }
  }

  fn from_entry(entry: &StoredEntry) -> Self {
    Self {
      policy: entry.policy.clone(),
      scheme: entry.scheme.clone(),
      host: entry.host.clone(),
      uri: entry.uri.clone(),
    }
  }
}

#[derive(Debug, Clone)]
struct CacheQueryGeneration {
  target: CacheQueryInvalidationTarget,
  value: u64,
}

impl CacheQueryInvalidationTarget {
  fn new(policy: &str, scheme: &str, host: &str, uri: &str, partition: Option<&str>) -> Self {
    Self {
      policy: policy.to_string(),
      scheme: scheme.to_string(),
      host: host.to_string(),
      uri: uri.to_string(),
      partition: partition.map(str::to_string),
    }
  }

  fn matches(&self, other: &Self) -> bool {
    self.policy == other.policy
      && self.scheme == other.scheme
      && self.host == other.host
      && self.uri == other.uri
      && self
        .partition
        .as_ref()
        .is_none_or(|partition| other.partition.as_ref() == Some(partition))
  }
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
  nvs_index: HashMap<String, HashSet<String>>,
  entries: HashMap<String, StoredEntry>,
  index: index::CacheIndex,
  query_variants_by_target:
    HashMap<CacheQueryTargetKey, HashMap<String, BTreeMap<u64, HashSet<String>>>>,
  order: VecDeque<String>,
  purge_nonces: HashMap<String, SystemTime>,
  purge_nonce_order: VecDeque<String>,
  /// A remote QUERY invalidation failure must not be followed by a stale
  /// shared/external hit or an in-flight reinsert for that target.
  failed_query_invalidations: HashSet<(String, u16)>,
  query_invalidation_generations: HashMap<(String, u16), u64>,
  memory_size: usize,
  disk_size: usize,
  disk_inflight_size: usize,
  tmpfs_size: usize,
  admission_counts: HashMap<String, u32>,
  admission_order: VecDeque<String>,
  disk_recovered_entries_total: u64,
  disk_recovery_errors_total: u64,
  disk_recovery_removed_files_total: u64,
  disk_query_epochs_loaded: bool,
  discard_recovered_query_entries: bool,
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
  query_cleanup: query_cleanup::QueryCleanupDispatcher,
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
    inner.query_variants_by_target.clear();
    inner.memory_size = 0;
    inner.disk_size = 0;
    inner.disk_inflight_size = 0;
    inner.tmpfs_size = 0;
  }
}

#[cfg(test)]
#[path = "cache/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cache/tests_proxy_protocol.rs"]
mod tests_proxy_protocol;
