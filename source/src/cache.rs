//! Response cache coordination and cache-key enforcement for proxy traffic.
//! Cache admission remains separate from HTTP forwarding so policy decisions stay auditable.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
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
use crate::shared_state::SharedState;

mod entry;
mod external;
mod external_handler;
mod fill;
mod index;
mod metadata;
mod range;
mod revalidation;
mod shared;
pub mod signing;
mod streaming;

pub use entry::{CacheBodyFile, CacheEntry};
pub(crate) use external_handler::{ExternalCachePurgeReport, ExternalCacheRuntime};
pub(crate) use fill::{CacheFillDecision, CacheFillSuppressionReason};
pub use fill::{CacheFillGuard, CacheFillWaiter};
use metadata::{decode_metadata, encode_metadata, remove_metadata};
pub(crate) use range::range_entry;
pub(in crate::cache) use shared::{shared_cache_entry, shared_cache_entry_metadata};
pub(crate) use streaming::{CacheStreamingInsert, CacheStreamingInsertDecision};

const TMPFS_CACHE_ROOT: &str = "/dev/shm";
const SURROGATE_CONTROL_HEADER: &str = "surrogate-control";
const MAX_VARY_VALUE_BYTES: usize = 8_192;
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
  shared_state: Option<Arc<SharedState>>,
  external_cache: ExternalCacheRuntime,
}

impl ResponseCache {
  pub fn new(
    config: &CacheConfig,
    shared_state: Option<Arc<SharedState>>,
  ) -> anyhow::Result<Arc<Self>> {
    Self::new_with_external(
      config,
      shared_state,
      ExternalCacheRuntime::disabled(crate::metrics::Metrics::new()),
    )
  }

  pub(crate) fn new_with_external(
    config: &CacheConfig,
    shared_state: Option<Arc<SharedState>>,
    external_cache: ExternalCacheRuntime,
  ) -> anyhow::Result<Arc<Self>> {
    let tmpfs_dir = if config.enabled && config.store == CacheStore::Tmpfs {
      let dir = config
        .tmpfs_dir
        .clone()
        .unwrap_or_else(default_cache_tmpfs_dir);
      Some(validated_tmpfs_dir(&dir)?)
    } else {
      None
    };
    let disk_dir = if config.enabled && cache_needs_disk_dir(config) {
      let dir = config
        .disk_dir
        .as_ref()
        .ok_or_else(|| anyhow!("cache.disk_dir is required when cache.store uses disk"))?;
      Some(validated_disk_dir(dir)?)
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
      partition_key: config.partition_key.clone(),
      default_ttl_seconds: config.default_ttl_seconds,
      negative_statuses: cache_status_codes(&config.negative_statuses),
      negative_ttl_seconds: config.negative_ttl_seconds,
      memory_max_size_bytes: default_memory_limit,
      disk_max_size_bytes: config.disk_max_size_bytes,
      tag_headers: cache_tag_headers(&config.tag_headers),
      max_tags_per_entry: config.max_tags_per_entry,
      max_tag_bytes: config.max_tag_bytes,
      max_vary_fields: config.max_vary_fields,
      max_vary_variants_per_key: config.max_vary_variants_per_key,
      background_refresh: config.background_refresh,
      background_refresh_max_concurrent: config.background_refresh_max_concurrent,
      lock_wait_timeout: Duration::from_millis(config.lock_wait_timeout_ms),
      external_handler: external_handler_selection(config.external_handler.as_deref(), None),
      admission: admission_runtime(&config.admission, &config.negative_statuses),
      stale_if_error: config.stale_if_error.clone(),
      rules: Vec::new(),
    };
    let mut policies = HashMap::new();
    policies.insert(default_policy.name.clone(), default_policy);
    for policy in &config.policies {
      let runtime = policy_runtime(config, policy, default_memory_limit);
      policies.insert(runtime.name.clone(), runtime);
    }
    let refresh_limiters = policies
      .iter()
      .map(|(name, policy)| {
        (
          name.clone(),
          Arc::new(Semaphore::new(policy.background_refresh_max_concurrent)),
        )
      })
      .collect();

    let cache = Arc::new(Self {
      config: config.clone(),
      policies,
      bypass_request_headers: cache_tag_headers(&config.bypass_request_headers),
      refresh_limiters,
      tmpfs_dir,
      disk_dir,
      fills: fill::CacheFillCoordinator::new(),
      inner: Mutex::new(CacheInner::default()),
      shared_state,
      external_cache,
    });
    cache.load_disk_entries();
    Ok(cache)
  }

  pub fn enabled(&self) -> bool {
    self.config.enabled
  }

  pub(crate) fn shared_cache_enabled(&self) -> bool {
    self
      .shared_state
      .as_ref()
      .is_some_and(|shared| shared.has_cache())
  }

  pub fn policy_enabled(&self, policy_name: Option<&str>, method: &Method) -> bool {
    self.config.enabled && self.policy(policy_name).is_some() && self.is_cacheable_method(method)
  }

  pub fn is_cacheable_method(&self, method: &Method) -> bool {
    if method == Method::HEAD {
      return self
        .config
        .cache_methods
        .iter()
        .any(|item| item.eq_ignore_ascii_case(Method::GET.as_str()))
        || self
          .config
          .cache_methods
          .iter()
          .any(|item| item.eq_ignore_ascii_case(Method::HEAD.as_str()));
    }
    self
      .config
      .cache_methods
      .iter()
      .any(|item| item.eq_ignore_ascii_case(method.as_str()))
  }

  fn operation_context(
    &self,
    policy_name: Option<&str>,
    scheme: &str,
    host: &str,
    method: &Method,
    uri: &Uri,
    request_headers: &HeaderMap,
  ) -> Option<CacheOperationContext> {
    let policy = self.policy(policy_name)?.clone();
    let base_key = expanded_cache_key(&policy.cache_key, scheme, host, uri, request_headers);
    let partition = expanded_cache_key(&policy.partition_key, scheme, host, uri, request_headers);
    let uri = uri.to_string();
    let lookup_key = index::LookupKey::new(&policy.name, &partition, scheme, host, &uri, &base_key);
    let fill_key = format!(
      "{}\n{}\n{}\n{}\n{}\n{}",
      policy.name,
      partition,
      method.as_str(),
      scheme,
      host,
      base_key
    );
    Some(CacheOperationContext {
      policy,
      partition,
      base_key,
      lookup_key,
      fill_key,
      scheme: scheme.to_string(),
      host: host.to_string(),
      uri,
    })
  }

  pub fn lookup(&self, ctx: CacheLookupContext<'_>) -> Option<CacheLookup> {
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return None;
    }
    if request_no_store(ctx.request_headers, &self.bypass_request_headers) {
      return None;
    }
    let operation = self.operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
    )?;
    let now = SystemTime::now();
    let (key, entry) = {
      let mut inner = self.inner.lock().expect("cache lock poisoned");
      let key = inner
        .index
        .candidates(&operation.lookup_key)
        .and_then(|candidates| {
          candidates.into_iter().find(|key| {
            inner
              .entries
              .get(key)
              .is_some_and(|entry| vary_matches(&entry.vary, ctx.request_headers))
          })
        });
      let Some(key) = key else {
        drop(inner);
        return self.lookup_shared(
          &operation.policy.name,
          operation.policy.background_refresh,
          &operation.partition,
          &operation.base_key,
          ctx,
        );
      };

      let expired = inner
        .entries
        .get(&key)
        .is_some_and(|entry| entry.stale_if_error_until.unwrap_or(entry.expires_at) <= now);
      if expired {
        remove_entry(&mut inner, &key);
        return None;
      }
      let entry = inner.entries.get(&key).cloned()?;
      (key, entry)
    };
    let Some(cache_entry) = entry.to_cache_entry() else {
      let mut inner = self.inner.lock().expect("cache lock poisoned");
      remove_entry(&mut inner, &key);
      return None;
    };
    if request_no_cache(ctx.request_headers) || entry.must_revalidate || entry.expires_at <= now {
      let validators = validator_headers(&entry.headers);
      if !request_no_cache(ctx.request_headers)
        && !entry.must_revalidate
        && entry
          .stale_while_revalidate_until
          .is_some_and(|until| until > now)
      {
        return Some(CacheLookup::Stale(StaleEntry {
          entry: cache_entry,
          request_headers: validators,
          serve_stale_on_error: entry.stale_if_error_until.is_some_and(|until| until > now),
          background_refresh: operation.policy.background_refresh,
        }));
      }
      if validators.is_empty() {
        if entry
          .stale_while_revalidate_until
          .is_some_and(|until| until > now)
        {
          return Some(CacheLookup::Stale(StaleEntry {
            entry: cache_entry,
            request_headers: HeaderMap::new(),
            serve_stale_on_error: entry.stale_if_error_until.is_some_and(|until| until > now),
            background_refresh: entry
              .stale_while_revalidate_until
              .is_some_and(|until| until > now)
              && operation.policy.background_refresh,
          }));
        }
        if entry.stale_if_error_until.is_some_and(|until| until > now) {
          return Some(CacheLookup::Revalidate(Revalidation {
            entry: cache_entry,
            request_headers: HeaderMap::new(),
            serve_stale_on_error: true,
          }));
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
    background_refresh: bool,
    partition: &str,
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
      partition,
      base_key,
      &uri,
      ctx.method,
      ctx.request_headers,
      request_no_cache(ctx.request_headers),
      background_refresh,
    ) {
      Ok(Some(lookup)) => {
        if matches!(lookup, CacheLookup::Fresh(_)) {
          self.promote_shared_lookup(ctx, &lookup);
        }
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
      CacheLookup::Fresh(entry) => entry.clone(),
      CacheLookup::Stale(stale) => stale.entry.clone(),
      CacheLookup::Revalidate(revalidation) => revalidation.entry.clone(),
    };
    if entry.body_file.is_some() {
      return;
    }
    self.insert_with_external(
      CacheInsertContext {
        policy_name: ctx.policy_name,
        scheme: ctx.scheme,
        host: ctx.host,
        method: ctx.method,
        uri: ctx.uri,
        request_headers: ctx.request_headers,
      },
      entry,
      false,
    );
  }

  pub fn begin_fill(self: &Arc<Self>, ctx: CacheLookupContext<'_>) -> Option<CacheFillPermit> {
    self
      .begin_fill_decision(ctx)
      .and_then(|decision| match decision {
        CacheFillDecision::Leader(guard) => Some(CacheFillPermit::Leader(guard)),
        CacheFillDecision::Follower(waiter) => Some(CacheFillPermit::Follower(waiter)),
        CacheFillDecision::SharedConflict => Some(CacheFillPermit::SharedConflict),
        CacheFillDecision::Suppressed(_) => None,
      })
  }

  pub(crate) fn begin_fill_decision(
    self: &Arc<Self>,
    ctx: CacheLookupContext<'_>,
  ) -> Option<CacheFillDecision> {
    if !self.config.lock {
      return None;
    }
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return None;
    }
    if request_no_store(ctx.request_headers, &self.bypass_request_headers) {
      return None;
    }
    let key = self
      .operation_context(
        ctx.policy_name,
        ctx.scheme,
        ctx.host,
        ctx.method,
        ctx.uri,
        ctx.request_headers,
      )?
      .fill_key;
    match self.fills.begin(key.clone()) {
      CacheFillDecision::Leader(mut guard) => {
        if let Some(shared) = self
          .shared_state
          .as_ref()
          .filter(|shared| shared.has_cache())
        {
          match shared.cache_try_lock_result(&key) {
            Ok(Some(shared_lock)) => guard.set_shared_lock(shared_lock),
            Ok(None) => {
              drop(guard);
              return Some(CacheFillDecision::SharedConflict);
            }
            Err(error) => {
              warn!(error = %error, "shared cache fill lock failed; using local fill lock");
            }
          }
        }
        Some(CacheFillDecision::Leader(guard))
      }
      CacheFillDecision::Follower(waiter) => Some(CacheFillDecision::Follower(waiter)),
      CacheFillDecision::SharedConflict => Some(CacheFillDecision::SharedConflict),
      CacheFillDecision::Suppressed(reason) => Some(CacheFillDecision::Suppressed(reason)),
    }
  }

  pub fn note_fill_not_stored(&self, ctx: CacheInsertContext<'_>) {
    self.note_fill_not_stored_reason(ctx, CacheFillSuppressionReason::Unknown);
  }

  pub(crate) fn note_fill_not_stored_reason(
    &self,
    ctx: CacheInsertContext<'_>,
    reason: CacheFillSuppressionReason,
  ) {
    if !self.config.lock {
      return;
    }
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return;
    }
    if request_no_store(ctx.request_headers, &self.bypass_request_headers) {
      return;
    }
    let Some(key) = self
      .operation_context(
        ctx.policy_name,
        ctx.scheme,
        ctx.host,
        ctx.method,
        ctx.uri,
        ctx.request_headers,
      )
      .map(|operation| operation.fill_key)
    else {
      return;
    };
    self.fills.suppress(key, reason);
  }

  pub fn insert(&self, ctx: CacheInsertContext<'_>, entry: CacheEntry) -> CacheInsertOutcome {
    self.insert_with_external(ctx, entry, true)
  }

  fn insert_with_external(
    &self,
    ctx: CacheInsertContext<'_>,
    entry: CacheEntry,
    publish_external: bool,
  ) -> CacheInsertOutcome {
    match self.prepare_insert(ctx, entry.status, &entry.headers, Some(entry.body.len())) {
      CachePreparedInsertDecision::Cacheable(prepared) => {
        self.insert_prepared_with_external(*prepared, entry, publish_external)
      }
      CachePreparedInsertDecision::NotCacheable(_) => CacheInsertOutcome::NotCacheable,
      CachePreparedInsertDecision::Rejected(_) => CacheInsertOutcome::Rejected,
    }
  }

  pub(crate) fn insert_prepared(
    &self,
    prepared: CachePreparedInsert,
    entry: CacheEntry,
  ) -> CacheInsertOutcome {
    self.insert_prepared_with_external(prepared, entry, true)
  }

  fn insert_prepared_with_external(
    &self,
    prepared: CachePreparedInsert,
    entry: CacheEntry,
    publish_external: bool,
  ) -> CacheInsertOutcome {
    let size = match entry.body.len().checked_add(prepared.header_bytes) {
      Some(size) if size <= self.config.max_size_bytes => size,
      _ => return CacheInsertOutcome::Rejected,
    };
    let (shared_entry, external_entry) = {
      let mut inner = self.inner.lock().expect("cache lock poisoned");
      if variant_count_exceeded(
        &inner,
        &prepared.policy,
        &prepared.partition,
        &prepared.base_key,
        &prepared.variant_key,
      ) {
        return CacheInsertOutcome::Rejected;
      }
      match admit_prepared_body(
        &mut inner,
        &prepared.policy,
        &prepared.variant_key,
        entry.body.len(),
      ) {
        PreparedBodyAdmission::Admitted => {}
        PreparedBodyAdmission::Warming => return CacheInsertOutcome::AdmissionWarming,
        PreparedBodyAdmission::Rejected => return CacheInsertOutcome::Rejected,
      }
      let selected_store = select_store_for_insert(&inner, &prepared.policy, &entry.headers, size);
      let Some(body) = self.store_body(
        &prepared.policy,
        selected_store,
        &prepared.variant_key,
        &entry.body,
        size,
      ) else {
        return CacheInsertOutcome::StoreFailed;
      };
      let tags = extract_tags(&entry.headers, &prepared.policy);
      let stored = StoredEntry {
        policy: prepared.policy.name.clone(),
        partition: prepared.partition,
        base_key: prepared.base_key,
        variant_key: prepared.variant_key.clone(),
        scheme: prepared.scheme,
        host: prepared.host,
        uri: prepared.uri,
        status: prepared.status,
        headers: prepared.stored_headers,
        security_headers_neutral: entry.security_headers_neutral,
        body,
        expires_at: prepared.metadata.expires_at,
        stale_if_error_until: prepared.metadata.stale_if_error_until,
        stale_while_revalidate_until: prepared.metadata.stale_while_revalidate_until,
        must_revalidate: prepared.metadata.must_revalidate,
        stored_at: prepared.metadata.stored_at,
        vary: prepared.metadata.vary,
        tags,
        size,
      };
      if let Err(error) = self.persist_metadata(&stored) {
        warn!(error = %error, "failed to persist cache metadata");
        if matches!(stored.body, StoredBody::Disk(_)) {
          stored.remove_body_files();
          return CacheInsertOutcome::StoreFailed;
        }
      }
      if variant_count_exceeded(
        &inner,
        &prepared.policy,
        &stored.partition,
        &stored.base_key,
        &prepared.variant_key,
      ) {
        remove_metadata(&stored);
        stored.remove_body_files();
        return CacheInsertOutcome::Rejected;
      }
      if let Some(existing) = detach_entry(&mut inner, &prepared.variant_key) {
        remove_replaced_entry_files(existing, &stored);
      }
      add_size(&mut inner, &stored);
      inner.order.push_back(prepared.variant_key.clone());
      index_entry(&mut inner, &stored);
      let shared_entry = self
        .shared_state
        .as_ref()
        .filter(|shared| shared.has_cache())
        .and_then(|_| shared_cache_entry(&stored));
      let external_entry = publish_external
        .then(|| self.external_entry_for_stored(&stored))
        .flatten();
      inner.entries.insert(prepared.variant_key, stored);
      self.evict_if_needed(&mut inner, &prepared.policy);
      (shared_entry, external_entry)
    };
    if let Some(shared) = &self.shared_state
      && shared.has_cache()
      && let Some(shared_entry) = shared_entry
    {
      shared.cache_put(&shared_entry);
    }
    if let Some((handler, metadata, body)) = external_entry {
      self.spawn_external_fill(handler, metadata, body);
    }
    CacheInsertOutcome::Stored
  }

  pub fn update_from_not_modified(
    &self,
    ctx: CacheInsertContext<'_>,
    cached_entry: &CacheEntry,
    not_modified_headers: &HeaderMap,
  ) {
    revalidation::update_from_not_modified(self, ctx, cached_entry, not_modified_headers);
  }

  pub fn response_head_decision(
    &self,
    ctx: CacheInsertContext<'_>,
    status: StatusCode,
    response_headers: &HeaderMap,
    content_length: Option<usize>,
  ) -> CacheResponseHeadDecision {
    match self.prepare_insert(ctx, status, response_headers, content_length) {
      CachePreparedInsertDecision::Cacheable(_) => CacheResponseHeadDecision::Cacheable,
      CachePreparedInsertDecision::NotCacheable(_) => CacheResponseHeadDecision::NotCacheable,
      CachePreparedInsertDecision::Rejected(_) => CacheResponseHeadDecision::Rejected,
    }
  }

  pub(crate) fn prepare_insert(
    &self,
    ctx: CacheInsertContext<'_>,
    status: StatusCode,
    response_headers: &HeaderMap,
    content_length: Option<usize>,
  ) -> CachePreparedInsertDecision {
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    if ctx.method == Method::HEAD {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    if request_no_store(ctx.request_headers, &self.bypass_request_headers) {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    let Some(operation) = self.operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
    ) else {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    };
    let metadata = match cache_metadata(
      &self.config,
      &operation.policy,
      ctx.request_headers,
      status,
      response_headers,
    ) {
      Ok(metadata) => metadata,
      Err(reason) => return CachePreparedInsertDecision::NotCacheable(reason),
    };
    let stored_headers = stored_response_headers(response_headers, &self.config);
    let header_bytes = header_size(&stored_headers);
    if content_length.is_some_and(|body_len| {
      body_len
        .checked_add(header_bytes)
        .is_none_or(|size| size > self.config.max_size_bytes)
    }) {
      return CachePreparedInsertDecision::Rejected(CacheFillSuppressionReason::TooLarge);
    }
    if !admit_response_head(&operation.policy, status, response_headers, content_length) {
      return CachePreparedInsertDecision::Rejected(CacheFillSuppressionReason::AdmissionRejected);
    }
    let variant_key = variant_key(&operation.partition, &operation.base_key, &metadata.vary);
    CachePreparedInsertDecision::Cacheable(Box::new(CachePreparedInsert {
      policy: operation.policy,
      partition: operation.partition,
      base_key: operation.base_key,
      variant_key,
      scheme: operation.scheme,
      host: operation.host,
      uri: operation.uri,
      status,
      stored_headers,
      metadata,
      header_bytes,
    }))
  }

  pub fn purge_exact(&self, policy: &str, scheme: &str, host: &str, uri: &str) -> usize {
    self.purge_exact_partition(policy, scheme, host, uri, None)
  }

  pub fn purge_exact_partition(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> usize {
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    let keys = inner
      .entries
      .iter()
      .filter(|(_, entry)| {
        entry.policy == policy
          && entry.scheme == scheme
          && entry.host == host
          && entry.uri == uri
          && partition.is_none_or(|partition| entry.partition == partition)
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
        .map(|shared| shared.cache_purge_exact(policy, scheme, host, uri, partition))
        .unwrap_or(0)
  }

  pub fn purge_prefix(&self, policy: &str, scheme: &str, host: &str, path_prefix: &str) -> usize {
    self.purge_prefix_partition(policy, scheme, host, path_prefix, None)
  }

  pub fn purge_prefix_partition(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    path_prefix: &str,
    partition: Option<&str>,
  ) -> usize {
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    let keys = inner
      .entries
      .iter()
      .filter(|(_, entry)| {
        entry.policy == policy
          && partition.is_none_or(|partition| entry.partition == partition)
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
        .map(|shared| shared.cache_purge_prefix(policy, scheme, host, path_prefix, partition))
        .unwrap_or(0)
  }

  pub fn purge_tag(
    &self,
    policy: &str,
    tag: &str,
    scheme: Option<&str>,
    host: Option<&str>,
  ) -> usize {
    self.purge_tag_partition(policy, tag, scheme, host, None)
  }

  pub fn purge_tag_partition(
    &self,
    policy: &str,
    tag: &str,
    scheme: Option<&str>,
    host: Option<&str>,
    partition: Option<&str>,
  ) -> usize {
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    let keys = inner
      .entries
      .iter()
      .filter(|(_, entry)| {
        entry.policy == policy
          && partition.is_none_or(|partition| entry.partition == partition)
          && scheme.is_none_or(|scheme| entry.scheme == scheme)
          && host.is_none_or(|host| entry.host == host)
          && entry.tags.iter().any(|candidate| candidate == tag)
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
        .map(|shared| shared.cache_purge_tag(policy, tag, scheme, host, partition))
        .unwrap_or(0)
  }

  pub fn stats(&self) -> CacheStats {
    let inner = self.inner.lock().expect("cache lock poisoned");
    let mut stats = CacheStats {
      memory_bytes: inner.memory_size,
      disk_bytes: inner.disk_size,
      tmpfs_bytes: inner.tmpfs_size,
      disk_recovered_entries_total: inner.disk_recovered_entries_total,
      disk_recovery_errors_total: inner.disk_recovery_errors_total,
      disk_recovery_removed_files_total: inner.disk_recovery_removed_files_total,
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

  pub fn strip_surrogate_control(&self, policy_name: Option<&str>) -> bool {
    self.policy(policy_name).is_some()
      && self.config.surrogate.enabled
      && self.config.surrogate.strip_response_header
  }

  pub fn explain_key(
    &self,
    ctx: CacheLookupContext<'_>,
    response_headers: Option<&HeaderMap>,
  ) -> CacheKeyExplain {
    let policy = self.policy(ctx.policy_name);
    let mut reasons = Vec::new();
    if !self.config.enabled {
      reasons.push("cache disabled".to_string());
    }
    let cacheable_method = self.is_cacheable_method(ctx.method);
    if !cacheable_method {
      reasons.push("method not configured as cacheable".to_string());
    }
    let bypassed = request_no_store(ctx.request_headers, &self.bypass_request_headers);
    if bypassed {
      reasons.push("request carries a bypass header or Cache-Control: no-store".to_string());
    }
    let (policy_name, partition, base_key, vary_fields, variant_key) = if let Some(policy) = policy
    {
      let partition = expanded_cache_key(
        &policy.partition_key,
        ctx.scheme,
        ctx.host,
        ctx.uri,
        ctx.request_headers,
      );
      let base_key = expanded_cache_key(
        &policy.cache_key,
        ctx.scheme,
        ctx.host,
        ctx.uri,
        ctx.request_headers,
      );
      let (vary_fields, variant_key) = if let Some(headers) = response_headers {
        match vary_matchers_result(
          headers,
          ctx.request_headers,
          policy.max_vary_fields,
          MAX_VARY_VALUE_BYTES,
        ) {
          Ok(vary) => {
            let vary_fields = vary.iter().map(|item| item.name.clone()).collect();
            let variant_key = Some(variant_key(&partition, &base_key, &vary));
            (vary_fields, variant_key)
          }
          Err(reason) => {
            reasons.push(reason.to_string());
            (Vec::new(), None)
          }
        }
      } else {
        (Vec::new(), None)
      };
      (
        policy.name.clone(),
        partition,
        base_key,
        vary_fields,
        variant_key,
      )
    } else {
      reasons.push("unknown cache policy".to_string());
      (
        ctx.policy_name.unwrap_or("default").to_string(),
        String::new(),
        String::new(),
        Vec::new(),
        None,
      )
    };
    CacheKeyExplain {
      policy: policy_name,
      enabled: self.config.enabled && policy.is_some(),
      cacheable_method,
      bypassed,
      partition,
      base_key,
      variant_key,
      vary_fields,
      reasons,
    }
  }

  pub fn remember_purge_nonce(&self, nonce: &str, ttl: Duration) -> bool {
    let now = SystemTime::now();
    let expires_at = now + ttl;
    let mut inner = self.inner.lock().expect("cache lock poisoned");
    while let Some(oldest) = inner.purge_nonce_order.front() {
      let expired = inner
        .purge_nonces
        .get(oldest)
        .is_none_or(|expires| *expires <= now);
      if !expired {
        break;
      }
      if let Some(oldest) = inner.purge_nonce_order.pop_front() {
        inner.purge_nonces.remove(&oldest);
      }
    }
    if inner.purge_nonces.contains_key(nonce) {
      return false;
    }
    inner.purge_nonces.insert(nonce.to_string(), expires_at);
    inner.purge_nonce_order.push_back(nonce.to_string());
    while inner.purge_nonces.len() > 16_384 {
      let Some(oldest) = inner.purge_nonce_order.pop_front() else {
        break;
      };
      inner.purge_nonces.remove(&oldest);
    }
    true
  }

  fn policy(&self, policy_name: Option<&str>) -> Option<&CachePolicyRuntime> {
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

  fn store_body(
    &self,
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

  fn persist_metadata(&self, entry: &StoredEntry) -> anyhow::Result<()> {
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
    let mut referenced_bodies = HashSet::new();
    for entry in entries.flatten() {
      let path = entry.path();
      if path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.ends_with("tmp"))
      {
        if std::fs::remove_file(&path).is_ok() {
          inner.disk_recovery_removed_files_total += 1;
        }
        continue;
      }
      if path.extension().and_then(|value| value.to_str()) != Some("meta") {
        continue;
      }
      match decode_metadata(&path, dir) {
        Ok(stored) => {
          if !stored.security_headers_neutral {
            remove_metadata(&stored);
            stored.remove_body();
            inner.disk_recovery_removed_files_total += 2;
            continue;
          }
          let now = SystemTime::now();
          if stored
            .stale_if_error_until
            .unwrap_or(stored.expires_at)
            .duration_since(now)
            .is_err()
          {
            remove_metadata(&stored);
            stored.remove_body();
            inner.disk_recovery_removed_files_total += 2;
            continue;
          }
          let StoredBody::Disk(body_path) = &stored.body else {
            continue;
          };
          if !body_path.is_file() {
            remove_metadata(&stored);
            inner.disk_recovery_errors_total += 1;
            inner.disk_recovery_removed_files_total += 1;
            continue;
          }
          referenced_bodies.insert(body_path.clone());
          add_size(&mut inner, &stored);
          inner.order.push_back(stored.variant_key.clone());
          index_entry(&mut inner, &stored);
          inner.entries.insert(stored.variant_key.clone(), stored);
          inner.disk_recovered_entries_total += 1;
        }
        Err(error) => {
          warn!(error = %error, path = %path.display(), "failed to load disk cache metadata");
          inner.disk_recovery_errors_total += 1;
          if std::fs::remove_file(path).is_ok() {
            inner.disk_recovery_removed_files_total += 1;
          }
        }
      }
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
      for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("body")
          && !referenced_bodies.contains(&path)
          && std::fs::remove_file(&path).is_ok()
        {
          inner.disk_recovery_removed_files_total += 1;
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
    inner.index.clear();
    inner.memory_size = 0;
    inner.disk_size = 0;
    inner.disk_inflight_size = 0;
    inner.tmpfs_size = 0;
  }
}

pub fn validate_tmpfs_dir(path: &Path) -> anyhow::Result<()> {
  validated_tmpfs_dir(path).map(|_| ())
}

pub fn validate_disk_dir(path: &Path) -> anyhow::Result<()> {
  validated_disk_dir(path).map(|_| ())
}

#[derive(Debug)]
struct ResponseMetadata {
  expires_at: SystemTime,
  stale_if_error_until: Option<SystemTime>,
  stale_while_revalidate_until: Option<SystemTime>,
  must_revalidate: bool,
  stored_at: SystemTime,
  vary: Vec<VaryMatcher>,
}

fn cache_metadata(
  config: &CacheConfig,
  policy: &CachePolicyRuntime,
  request_headers: &HeaderMap,
  status: StatusCode,
  response_headers: &HeaderMap,
) -> Result<ResponseMetadata, CacheFillSuppressionReason> {
  if status == StatusCode::PARTIAL_CONTENT {
    return Err(CacheFillSuppressionReason::Unknown);
  }
  if !cacheable_status(policy, status) {
    return Err(CacheFillSuppressionReason::Unknown);
  }
  if response_has_set_cookie(response_headers) {
    return Err(CacheFillSuppressionReason::SetCookie);
  }
  let request_directives = cache_control_directives(request_headers);
  if request_directives.has("no-store") {
    return Err(CacheFillSuppressionReason::Unknown);
  }
  let directives = cache_control_directives(response_headers);
  let surrogate = config
    .surrogate
    .enabled
    .then(|| surrogate_control_directives(response_headers))
    .flatten();
  if surrogate
    .as_ref()
    .is_some_and(|directives| directives.no_store)
  {
    return Err(CacheFillSuppressionReason::ResponseNoStore);
  }
  if surrogate.is_none() && config.respect_cache_control && directives.has("no-store") {
    return Err(CacheFillSuppressionReason::ResponseNoStore);
  }
  if surrogate.is_none() && config.respect_cache_control && directives.has("private") {
    return Err(CacheFillSuppressionReason::ResponsePrivate);
  }
  let vary = vary_matchers_result(
    response_headers,
    request_headers,
    policy.max_vary_fields,
    MAX_VARY_VALUE_BYTES,
  )
  .map_err(|_| CacheFillSuppressionReason::VaryRejected)?;
  if has_non_identity_content_encoding(response_headers)
    && !response_varies_accept_encoding(response_headers)
  {
    return Err(CacheFillSuppressionReason::VaryRejected);
  }
  let now = SystemTime::now();
  let mut ttl = surrogate
    .as_ref()
    .and_then(|directives| directives.max_age)
    .unwrap_or_else(|| {
      if config.respect_cache_control {
        directives
          .seconds("s-maxage")
          .or_else(|| directives.seconds("max-age"))
          .or_else(|| expires_ttl(response_headers, now))
          .unwrap_or(policy.default_ttl_seconds)
      } else {
        policy.default_ttl_seconds
      }
    });
  if policy.negative_statuses.contains(&status) {
    ttl = policy.negative_ttl_seconds;
  }
  if ttl == 0 {
    return Err(CacheFillSuppressionReason::Unknown);
  }
  let must_revalidate = surrogate.is_none()
    && (directives.has("no-cache")
      || directives.has("must-revalidate")
      || directives.has("proxy-revalidate"));
  let expires_at = if must_revalidate {
    now
  } else {
    now + Duration::from_secs(ttl)
  };
  let stale_if_error_seconds = surrogate
    .as_ref()
    .and_then(|directives| directives.stale_if_error)
    .unwrap_or_else(|| {
      if config.respect_cache_control {
        directives
          .seconds("stale-if-error")
          .unwrap_or(config.stale_if_error_seconds)
      } else {
        config.stale_if_error_seconds
      }
    });
  let stale_if_error_seconds = if policy.stale_if_error.max_upstream_stale_seconds > 0 {
    stale_if_error_seconds.min(policy.stale_if_error.max_upstream_stale_seconds)
  } else {
    stale_if_error_seconds
  };
  let stale_while_revalidate_seconds = surrogate
    .as_ref()
    .and_then(|directives| directives.stale_while_revalidate)
    .unwrap_or_else(|| {
      if config.respect_cache_control {
        directives
          .seconds("stale-while-revalidate")
          .unwrap_or(config.stale_while_revalidate_seconds)
      } else {
        config.stale_while_revalidate_seconds
      }
    });
  Ok(ResponseMetadata {
    expires_at,
    stale_if_error_until: (stale_if_error_seconds > 0)
      .then_some(expires_at + Duration::from_secs(stale_if_error_seconds)),
    stale_while_revalidate_until: (stale_while_revalidate_seconds > 0)
      .then_some(expires_at + Duration::from_secs(stale_while_revalidate_seconds)),
    must_revalidate,
    stored_at: now,
    vary,
  })
}

fn cacheable_status(policy: &CachePolicyRuntime, status: StatusCode) -> bool {
  matches!(
    status,
    StatusCode::OK
      | StatusCode::NON_AUTHORITATIVE_INFORMATION
      | StatusCode::NO_CONTENT
      | StatusCode::MOVED_PERMANENTLY
      | StatusCode::PERMANENT_REDIRECT
  ) || policy.negative_statuses.contains(&status)
}

fn response_has_set_cookie(headers: &HeaderMap) -> bool {
  headers.contains_key(http::header::SET_COOKIE)
}

fn has_non_identity_content_encoding(headers: &HeaderMap) -> bool {
  headers.get_all(CONTENT_ENCODING).iter().any(|value| {
    value
      .to_str()
      .map(|value| !value.trim().eq_ignore_ascii_case("identity"))
      .unwrap_or(true)
  })
}

fn response_varies_accept_encoding(headers: &HeaderMap) -> bool {
  headers
    .get_all(VARY)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .any(|item| item == "*" || item.eq_ignore_ascii_case("accept-encoding"))
}

fn request_no_store(headers: &HeaderMap, bypass_headers: &[HeaderName]) -> bool {
  bypass_headers.iter().any(|name| headers.contains_key(name))
    || cache_control_directives(headers).has("no-store")
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

fn vary_matchers_result(
  response_headers: &HeaderMap,
  request_headers: &HeaderMap,
  max_fields: usize,
  max_value_bytes: usize,
) -> Result<Vec<VaryMatcher>, &'static str> {
  let mut result = Vec::new();
  for value in response_headers.get_all(VARY) {
    let value = value.to_str().map_err(|_| "invalid Vary header")?;
    for name in value
      .split(',')
      .map(str::trim)
      .filter(|name| !name.is_empty())
    {
      if name == "*" {
        return Err("Vary: * is not cacheable");
      }
      if result.len() >= max_fields {
        return Err("too many Vary fields");
      }
      let lower = name.to_ascii_lowercase();
      let value = header_values(request_headers, &lower);
      if value.len() > max_value_bytes {
        return Err("Vary value material is too large");
      }
      result.push(VaryMatcher {
        name: lower.clone(),
        value,
      });
    }
  }
  result.sort_by(|left, right| left.name.cmp(&right.name));
  result.dedup_by(|left, right| left.name == right.name);
  Ok(result)
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

#[derive(Debug, Default)]
struct SurrogateControl {
  no_store: bool,
  max_age: Option<u64>,
  stale_if_error: Option<u64>,
  stale_while_revalidate: Option<u64>,
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

fn surrogate_control_directives(headers: &HeaderMap) -> Option<SurrogateControl> {
  let name = HeaderName::from_static(SURROGATE_CONTROL_HEADER);
  let mut result = SurrogateControl::default();
  let mut seen = false;
  for value in headers.get_all(name) {
    let Ok(value) = value.to_str() else {
      continue;
    };
    for item in value.split(',').flat_map(|part| part.split(';')) {
      let item = item.trim();
      if item.is_empty() {
        continue;
      }
      seen = true;
      let (name, value) = item
        .split_once('=')
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), Some(value.trim())))
        .unwrap_or_else(|| (item.to_ascii_lowercase(), None));
      match name.as_str() {
        "no-store" => result.no_store = true,
        "max-age" => result.max_age = value.and_then(|value| value.parse::<u64>().ok()),
        "stale-if-error" => {
          result.stale_if_error = value.and_then(|value| value.parse::<u64>().ok());
        }
        "stale-while-revalidate" => {
          result.stale_while_revalidate = value.and_then(|value| value.parse::<u64>().ok());
        }
        _ => {}
      }
    }
  }
  seen.then_some(result)
}

fn expires_ttl(headers: &HeaderMap, now: SystemTime) -> Option<u64> {
  let expires = headers.get(EXPIRES)?.to_str().ok()?;
  let expires = httpdate::parse_http_date(expires).ok()?;
  Some(
    expires
      .duration_since(now)
      .map(|duration| duration.as_secs())
      .unwrap_or_default(),
  )
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

fn variant_key(partition: &str, base_key: &str, vary: &[VaryMatcher]) -> String {
  let mut key = String::new();
  key.push_str("partition=");
  key.push_str(partition);
  key.push('\n');
  key.push_str(base_key);
  for item in vary {
    key.push('\n');
    key.push_str(&item.name);
    key.push('=');
    key.push_str(&item.value);
  }
  key
}

fn select_store(policy: &CachePolicyRuntime, headers: &HeaderMap) -> CacheStore {
  let content_type = normalized_content_type(headers);
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

fn select_store_for_insert(
  inner: &CacheInner,
  policy: &CachePolicyRuntime,
  headers: &HeaderMap,
  size: usize,
) -> CacheStore {
  match select_store(policy, headers) {
    CacheStore::MemoryThenDisk if inner.memory_size + size <= policy.memory_max_size_bytes => {
      CacheStore::Memory
    }
    CacheStore::MemoryThenDisk => CacheStore::Disk,
    store => store,
  }
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

fn extract_tags(headers: &HeaderMap, policy: &CachePolicyRuntime) -> Vec<String> {
  let mut tags = Vec::new();
  for header in &policy.tag_headers {
    for value in headers.get_all(header) {
      let Ok(value) = value.to_str() else {
        continue;
      };
      for tag in value
        .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
      {
        if tag.len() > policy.max_tag_bytes
          || tag.bytes().any(|byte| byte.is_ascii_control())
          || tags.iter().any(|existing| existing == tag)
        {
          continue;
        }
        tags.push(tag.to_string());
        if tags.len() >= policy.max_tags_per_entry {
          return tags;
        }
      }
    }
  }
  tags
}

fn stored_response_headers(headers: &HeaderMap, config: &CacheConfig) -> HeaderMap {
  let mut headers = headers.clone();
  if config.surrogate.enabled && config.surrogate.strip_response_header {
    headers.remove(HeaderName::from_static(SURROGATE_CONTROL_HEADER));
  }
  headers
}

fn variant_count_exceeded(
  inner: &CacheInner,
  policy: &CachePolicyRuntime,
  partition: &str,
  base_key: &str,
  variant_key: &str,
) -> bool {
  if inner.entries.contains_key(variant_key) {
    return false;
  }
  let group = index::VariantGroupKey::new(&policy.name, partition, base_key);
  inner.index.variant_count(&group) >= policy.max_vary_variants_per_key
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PreparedBodyAdmission {
  Admitted,
  Warming,
  Rejected,
}

fn admit_prepared_body(
  inner: &mut CacheInner,
  policy: &CachePolicyRuntime,
  variant_key: &str,
  body_len: usize,
) -> PreparedBodyAdmission {
  if policy.admission.max_body_bytes > 0 && body_len > policy.admission.max_body_bytes {
    return PreparedBodyAdmission::Rejected;
  }
  if policy.admission.min_hits <= 1 {
    return PreparedBodyAdmission::Admitted;
  }
  if admit_frequency(inner, policy, variant_key) {
    PreparedBodyAdmission::Admitted
  } else {
    PreparedBodyAdmission::Warming
  }
}

fn admit_frequency(inner: &mut CacheInner, policy: &CachePolicyRuntime, variant_key: &str) -> bool {
  let key = format!("{}\n{variant_key}", policy.name);
  let count = {
    let count = inner
      .admission_counts
      .entry(key.clone())
      .and_modify(|count| *count = count.saturating_add(1))
      .or_insert(1);
    *count
  };
  if count == 1 {
    inner.admission_order.push_back(key.clone());
  }
  while inner.admission_counts.len() > policy.admission.max_tracked_keys {
    let Some(oldest) = inner.admission_order.pop_front() else {
      break;
    };
    inner.admission_counts.remove(&oldest);
  }
  count >= policy.admission.min_hits as u32
}

fn admit_response_head(
  policy: &CachePolicyRuntime,
  status: StatusCode,
  headers: &HeaderMap,
  content_length: Option<usize>,
) -> bool {
  if !policy.admission.statuses.contains(&status) {
    return false;
  }
  if policy.admission.max_body_bytes > 0
    && content_length.is_some_and(|length| length > policy.admission.max_body_bytes)
  {
    return false;
  }
  if !policy.admission.content_types.is_empty() {
    let content_type = normalized_content_type(headers);
    if !policy
      .admission
      .content_types
      .iter()
      .any(|pattern| mime_matches(pattern, &content_type))
    {
      return false;
    }
  }
  true
}

fn normalized_content_type(headers: &HeaderMap) -> String {
  headers
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
    .unwrap_or_default()
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
    partition_key: policy
      .partition_key
      .clone()
      .unwrap_or_else(|| config.partition_key.clone()),
    default_ttl_seconds: policy
      .default_ttl_seconds
      .unwrap_or(config.default_ttl_seconds),
    negative_statuses: policy
      .negative_statuses
      .as_ref()
      .map(|statuses| cache_status_codes(statuses))
      .unwrap_or_else(|| cache_status_codes(&config.negative_statuses)),
    negative_ttl_seconds: policy
      .negative_ttl_seconds
      .unwrap_or(config.negative_ttl_seconds),
    memory_max_size_bytes: policy.memory_max_size_bytes.unwrap_or(default_memory_limit),
    disk_max_size_bytes: policy.disk_max_size_bytes.or(config.disk_max_size_bytes),
    tag_headers: cache_tag_headers(policy.tag_headers.as_ref().unwrap_or(&config.tag_headers)),
    max_tags_per_entry: policy
      .max_tags_per_entry
      .unwrap_or(config.max_tags_per_entry),
    max_tag_bytes: policy.max_tag_bytes.unwrap_or(config.max_tag_bytes),
    max_vary_fields: policy.max_vary_fields.unwrap_or(config.max_vary_fields),
    max_vary_variants_per_key: policy
      .max_vary_variants_per_key
      .unwrap_or(config.max_vary_variants_per_key),
    background_refresh: policy
      .background_refresh
      .unwrap_or(config.background_refresh),
    background_refresh_max_concurrent: policy
      .background_refresh_max_concurrent
      .unwrap_or(config.background_refresh_max_concurrent),
    lock_wait_timeout: Duration::from_millis(
      policy
        .lock_wait_timeout_ms
        .unwrap_or(config.lock_wait_timeout_ms),
    ),
    external_handler: external_handler_selection(
      config.external_handler.as_deref(),
      policy.external_handler.as_deref(),
    ),
    admission: admission_runtime(
      policy.admission.as_ref().unwrap_or(&config.admission),
      policy
        .negative_statuses
        .as_deref()
        .unwrap_or(&config.negative_statuses),
    ),
    stale_if_error: policy
      .stale_if_error
      .clone()
      .unwrap_or_else(|| config.stale_if_error.clone()),
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

fn external_handler_selection(
  default: Option<&str>,
  override_value: Option<&str>,
) -> Option<String> {
  match override_value.or(default) {
    Some("off") | None => None,
    Some(name) => Some(name.to_string()),
  }
}

fn cache_tag_headers(headers: &[String]) -> Vec<HeaderName> {
  headers
    .iter()
    .filter_map(|header| HeaderName::from_bytes(header.as_bytes()).ok())
    .collect()
}

fn cache_status_codes(statuses: &[u16]) -> Vec<StatusCode> {
  statuses
    .iter()
    .filter_map(|status| StatusCode::from_u16(*status).ok())
    .collect()
}

fn admission_runtime(
  admission: &CacheAdmissionConfig,
  negative_statuses: &[u16],
) -> CacheAdmissionRuntime {
  let mut statuses = admission
    .statuses
    .iter()
    .chain(negative_statuses)
    .filter_map(|status| StatusCode::from_u16(*status).ok())
    .collect::<Vec<_>>();
  statuses.sort();
  statuses.dedup();
  CacheAdmissionRuntime {
    statuses,
    content_types: admission.content_types.clone(),
    max_body_bytes: admission.max_body_bytes,
    min_hits: admission.min_hits,
    max_tracked_keys: admission.max_tracked_keys,
  }
}

fn cache_needs_disk_dir(config: &CacheConfig) -> bool {
  config.store.uses_disk()
    || config.policies.iter().any(|policy| {
      policy.store.is_some_and(CacheStore::uses_disk)
        || policy.rules.iter().any(|rule| rule.store.uses_disk())
    })
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

fn validated_tmpfs_dir(path: &Path) -> anyhow::Result<PathBuf> {
  let canonical = canonical_cache_dir("cache tmpfs_dir", path)?;
  if !canonical.starts_with(Path::new(TMPFS_CACHE_ROOT)) {
    bail!("cache tmpfs_dir {} must be under /dev/shm", path.display());
  }
  validate_writable_dir("cache tmpfs_dir", &canonical)?;
  Ok(canonical)
}

fn validated_disk_dir(path: &Path) -> anyhow::Result<PathBuf> {
  let canonical = canonical_cache_dir("cache disk_dir", path)?;
  validate_writable_dir("cache disk_dir", &canonical)?;
  Ok(canonical)
}

fn canonical_cache_dir(field_name: &str, path: &Path) -> anyhow::Result<PathBuf> {
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

fn validate_writable_dir(field_name: &str, path: &Path) -> anyhow::Result<()> {
  let probe_name = format!(".oxibelt-write-test-{}", std::process::id());
  let probe = safe_child_path(path, &probe_name)
    .ok_or_else(|| anyhow!("{field_name} write probe file name is invalid"))?;
  std::fs::write(&probe, b"ok")
    .with_context(|| format!("{field_name} {} must be writable", path.display()))?;
  let _ = std::fs::remove_file(probe);
  Ok(())
}

fn remove_entry(inner: &mut CacheInner, key: &str) {
  if let Some(existing) = detach_entry(inner, key) {
    remove_metadata(&existing);
    existing.remove_body();
  }
}

fn detach_entry(inner: &mut CacheInner, key: &str) -> Option<StoredEntry> {
  let existing = inner.entries.remove(key)?;
  unindex_entry(inner, &existing);
  subtract_size(inner, &existing);
  Some(existing)
}

fn remove_replaced_entry_files(existing: StoredEntry, replacement: &StoredEntry) {
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

fn index_entry(inner: &mut CacheInner, entry: &StoredEntry) {
  inner
    .index
    .insert(entry_lookup_key(entry), &entry.variant_key);
}

fn unindex_entry(inner: &mut CacheInner, entry: &StoredEntry) {
  inner
    .index
    .remove(&entry_lookup_key(entry), &entry.variant_key);
}

fn entry_lookup_key(entry: &StoredEntry) -> index::LookupKey {
  index::LookupKey::new(
    &entry.policy,
    &entry.partition,
    &entry.scheme,
    &entry.host,
    &entry.uri,
    &entry.base_key,
  )
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

  fn remove_body(self) {
    match self.body {
      StoredBody::Tmpfs(path) | StoredBody::Disk(path) => {
        let _ = std::fs::remove_file(path);
      }
      StoredBody::Memory(_) => {}
    }
  }

  fn remove_body_files(&self) {
    match &self.body {
      StoredBody::Tmpfs(path) | StoredBody::Disk(path) => {
        let _ = std::fs::remove_file(path);
      }
      StoredBody::Memory(_) => {}
    }
  }
}

fn stored_body_path(body: &StoredBody) -> Option<&Path> {
  match body {
    StoredBody::Tmpfs(path) | StoredBody::Disk(path) => Some(path),
    StoredBody::Memory(_) => None,
  }
}

fn write_body_file(dir: &Path, key: &str, body: &Bytes) -> Option<PathBuf> {
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
  let digest = crate::crypto::sha256(key.as_bytes());
  let mut name = String::with_capacity(digest.len() * 2);
  for byte in digest {
    use std::fmt::Write;
    let _ = write!(&mut name, "{byte:02x}");
  }
  name
}

fn cache_file_path(dir: &Path, key: &str, kind: CacheFileKind) -> Option<PathBuf> {
  let stem = cache_file_name(key);
  cache_file_path_from_stem(dir, &stem, kind)
}

fn cache_file_path_from_stem(dir: &Path, stem: &str, kind: CacheFileKind) -> Option<PathBuf> {
  if !is_cache_file_stem(stem) {
    return None;
  }
  safe_child_path(dir, &format!("{}.{}", stem, kind.suffix()))
}

fn safe_child_path(dir: &Path, file_name: &str) -> Option<PathBuf> {
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

fn is_cache_file_stem(stem: &str) -> bool {
  stem.len() == crate::crypto::SHA256_HEX_LEN && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn header_size(headers: &HeaderMap) -> usize {
  headers
    .iter()
    .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
    .sum()
}

#[cfg(test)]
#[path = "cache/tests.rs"]
mod tests;
