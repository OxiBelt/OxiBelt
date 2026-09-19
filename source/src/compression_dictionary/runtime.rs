//! Runtime ownership for configured and learned RFC 9842 dictionaries.

#[path = "ledger.rs"]
mod ledger;
#[path = "runtime/setup.rs"]
mod setup;

use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Semaphore;
use url::Url;
use urlpattern::{UrlPattern, UrlPatternInit};

use crate::{
  config::{
    CompressionDictionaryProfileConfig, CompressionDictionaryStoreConfig,
    CompressionDictionaryStoreKind, Config,
  },
  shared_state::SharedState,
};

use super::{
  codec::maximum_working_set_bytes,
  fields::{
    DictionaryHash, DictionaryType, MAX_DICTIONARY_ID_CHARS, MAX_MATCH_DESTINATION_BYTES,
    MAX_MATCH_DESTINATIONS, MAX_MATCH_PATTERN_BYTES, StoredDictionary, UseAsDictionary,
    select_dictionary,
  },
};
use ledger::{Ledger, LedgerEntry, key_digest};
use setup::{build_storage, ledger_entry_dictionary, load_configured_dictionaries, reuse_profile};

/// Direction is part of the persistence namespace; upstream and downstream
/// authorities never share learned dictionaries.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DictionaryDirection {
  Downstream,
  Upstream,
}

/// Canonically serializable authority for one dictionary lookup or learning operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DictionaryScope {
  pub direction: DictionaryDirection,
  pub origin: Url,
  pub profile: String,
  pub route_policy_fingerprint: String,
  pub upstream_fingerprint: Option<String>,
}

impl DictionaryScope {
  /// Returns the stable namespace hash used by the ledger.
  pub fn key(&self) -> anyhow::Result<String> {
    validate_scope(self)?;
    #[derive(Serialize)]
    struct CanonicalScope<'a> {
      direction: DictionaryDirection,
      origin: String,
      profile: &'a str,
      route_policy_fingerprint: &'a str,
      upstream_fingerprint: Option<&'a str>,
    }
    let canonical = serde_json::to_vec(&CanonicalScope {
      direction: self.direction,
      origin: self.origin.origin().ascii_serialization(),
      profile: &self.profile,
      route_policy_fingerprint: &self.route_policy_fingerprint,
      upstream_fingerprint: self.upstream_fingerprint.as_deref(),
    })
    .context("serialize dictionary scope")?;
    Ok(format!("scope:{}", key_digest(&canonical)))
  }
}

/// Immutable, hash-bound dictionary bytes pinned for one request lifetime.
#[derive(Clone, Debug)]
pub struct Dictionary {
  pub name: Option<String>,
  /// Only configured public dictionaries may decode ordinary client requests.
  pub public: bool,
  pub bytes: Arc<[u8]>,
  pub hash: DictionaryHash,
  pub url: Url,
  pub declaration: UseAsDictionary,
}

/// A profile's immutable policy and bounded execution resources.
#[derive(Clone)]
pub struct ProfileRuntime {
  pub config: CompressionDictionaryProfileConfig,
  pub codec_permits: Arc<Semaphore>,
  pub prefetch_permits: Arc<Semaphore>,
  store: Arc<StoreRuntime>,
  usage: Arc<Mutex<ProfileUsage>>,
}

#[derive(Default)]
struct ProfileUsage {
  live_bytes: u64,
  pending_bytes: u64,
  jobs: u64,
}

struct StoreRuntime {
  ledger: Ledger,
}

/// Configuration-snapshot runtime for configured and learned dictionaries.
#[derive(Clone)]
pub struct DictionaryRuntime {
  profiles: Arc<HashMap<String, Arc<ProfileRuntime>>>,
  configured: Arc<HashMap<String, Arc<Dictionary>>>,
  stores: Arc<HashMap<String, Arc<StoreRuntime>>>,
  store_configs: Arc<HashMap<String, CompressionDictionaryStoreConfig>>,
  shared_config: crate::config::SharedStateConfig,
}

/// Bounded observability view that never enumerates raw storage keys.
#[derive(Clone, Debug)]
pub struct DictionaryInventory {
  pub entries: usize,
  pub bytes: u64,
  pub pending_bytes: u64,
  pub active_jobs: u64,
}

/// An owned, cancellation-safe reservation for one dictionary learning job.
///
/// Create this before collecting a response body. Dropping it without calling
/// [`Self::commit`] releases the pending byte and job reservations.
pub struct DictionaryLearningReservation {
  profile_name: String,
  profile: Arc<ProfileRuntime>,
  scope_key: String,
  scope_origin: Url,
  scope_generation: u64,
  profile_generation: u64,
  byte_count: u64,
  learned_quota: u64,
  learned_count: usize,
  committed_bytes: Option<u64>,
}

impl DictionaryLearningReservation {
  /// Validates and atomically publishes the bytes reserved for this job.
  pub async fn commit(
    mut self,
    url: Url,
    declaration: UseAsDictionary,
    bytes: Vec<u8>,
    fresh_until_ms: u64,
  ) -> anyhow::Result<Arc<Dictionary>> {
    ensure!(
      self.scope_origin.origin() == url.origin(),
      "dictionary URL does not match its scope origin"
    );
    ensure!(
      u64::try_from(bytes.len())? <= self.byte_count,
      "dictionary bytes exceed the learning reservation"
    );
    validate_dictionary_parts(&url, &declaration, &bytes)?;
    ensure!(
      fresh_until_ms > now_ms()?,
      "learned dictionary is not fresh"
    );
    let hash = hash_bytes(&bytes)?;
    let dictionary = Dictionary {
      name: None,
      public: false,
      bytes: Arc::from(bytes.clone()),
      hash,
      url: url.clone(),
      declaration: declaration.clone(),
    };
    let entry = LedgerEntry {
      profile: self.profile_name.clone(),
      profile_generation: self.profile_generation,
      scope: self.scope_key.clone(),
      scope_generation: self.scope_generation,
      hash,
      url: url.to_string(),
      declaration,
      expires_at_ms: fresh_until_ms,
      fetched_at: now_ms()?,
      bytes: u64::try_from(bytes.len())?,
      chunks: Vec::new(),
    };
    self
      .profile
      .store
      .ledger
      .publish(
        &self.profile_name,
        self.learned_quota,
        self.learned_count,
        entry,
        &bytes,
      )
      .await?;
    self.committed_bytes = Some(u64::try_from(bytes.len())?);
    Ok(Arc::new(dictionary))
  }
}

impl Drop for DictionaryLearningReservation {
  fn drop(&mut self) {
    release(&self.profile, self.byte_count, self.committed_bytes);
  }
}

impl DictionaryRuntime {
  /// Builds a new snapshot, retaining exact-compatible stores from `previous`.
  pub fn new(
    config: &Config,
    previous: Option<&Self>,
    shared: Option<Arc<SharedState>>,
  ) -> anyhow::Result<Self> {
    let dictionary_config = &config.compression_dictionary;
    if !dictionary_config.enabled {
      return Ok(Self {
        profiles: Arc::new(HashMap::new()),
        configured: Arc::new(HashMap::new()),
        stores: Arc::new(HashMap::new()),
        store_configs: Arc::new(HashMap::new()),
        shared_config: config.shared_state.clone(),
      });
    }
    let mut stores = HashMap::new();
    let mut store_configs = HashMap::new();
    for store in &dictionary_config.stores {
      let reused = previous
        .filter(|previous| match store.kind {
          CompressionDictionaryStoreKind::Shared => previous.shared_config == config.shared_state,
          // Rebuild external clients on reload, including environment-backed
          // credentials and TLS material that can change without path changes.
          CompressionDictionaryStoreKind::External => false,
          _ => true,
        })
        .and_then(|previous| {
          previous
            .store_configs
            .get(&store.name)
            .filter(|old| *old == store)
            .and_then(|_| previous.stores.get(&store.name))
        })
        .cloned();
      let runtime = match reused {
        Some(runtime) => runtime,
        None => Arc::new(StoreRuntime {
          ledger: Ledger::new(
            build_storage(config, store, shared.clone())?,
            &store.name,
            store.quota_bytes,
          ),
        }),
      };
      store_configs.insert(store.name.clone(), store.clone());
      stores.insert(store.name.clone(), runtime);
    }
    let configured = load_configured_dictionaries(dictionary_config)?;
    let mut profiles = HashMap::new();
    for profile in &dictionary_config.profiles {
      let configured_bytes = profile
        .dictionaries
        .iter()
        .filter_map(|name| configured.get(name))
        .try_fold(0_u64, |sum, dictionary| {
          sum.checked_add(dictionary.bytes.len() as u64)
        })
        .context("configured dictionary quota overflow")?;
      ensure!(
        configured_bytes <= profile.max_total_dictionary_bytes,
        "configured dictionaries exceed profile storage quota"
      );
      let store = stores
        .get(&profile.store)
        .context("dictionary profile store disappeared after validation")?
        .clone();
      if let Some(reused) = reuse_profile(previous, profile, &store)? {
        profiles.insert(profile.name.clone(), reused);
        continue;
      }
      let memory_permits =
        usize::try_from(profile.max_codec_memory_bytes / maximum_working_set_bytes())
          .unwrap_or(usize::MAX);
      let codec_permits = Arc::new(Semaphore::new(
        profile.max_codec_concurrency.min(memory_permits),
      ));
      let prefetch_permits = Arc::new(Semaphore::new(
        profile
          .prefetch
          .as_ref()
          .map_or(1, |value| value.max_concurrent),
      ));
      profiles.insert(
        profile.name.clone(),
        Arc::new(ProfileRuntime {
          config: profile.clone(),
          codec_permits,
          prefetch_permits,
          store,
          usage: Arc::new(Mutex::new(ProfileUsage::default())),
        }),
      );
    }
    Ok(Self {
      profiles: Arc::new(profiles),
      configured: Arc::new(configured),
      stores: Arc::new(stores),
      store_configs: Arc::new(store_configs),
      shared_config: config.shared_state.clone(),
    })
  }

  pub fn profile(&self, name: &str) -> Option<Arc<ProfileRuntime>> {
    self.profiles.get(name).cloned()
  }
  pub fn configured(&self, name: &str) -> Option<Arc<Dictionary>> {
    self.configured.get(name).cloned()
  }

  /// Reserves learning capacity and captures the scope generation before body
  /// collection. The returned guard may commit up to `bytes` after an
  /// unknown-length body completes.
  pub async fn begin_learning(
    &self,
    profile_name: &str,
    scope: &DictionaryScope,
    bytes: u64,
  ) -> anyhow::Result<DictionaryLearningReservation> {
    let profile = self
      .profile(profile_name)
      .context("unknown compression dictionary profile")?;
    ensure!(
      profile.config.learn,
      "dictionary learning is disabled for this profile"
    );
    ensure!(
      scope.profile == profile_name,
      "dictionary scope profile does not match learning profile"
    );
    validate_scope(scope)?;
    ensure!(
      bytes <= profile.config.max_dictionary_bytes,
      "dictionary exceeds per-dictionary profile limit"
    );
    let (learned_quota, learned_count) = self.learned_limits(&profile)?;
    let scope_key = scope.key()?;
    reserve(&profile, bytes)?;
    let mut reservation = DictionaryLearningReservation {
      profile_name: profile_name.to_owned(),
      profile,
      scope_key,
      scope_origin: scope.origin.clone(),
      scope_generation: 0,
      profile_generation: 0,
      byte_count: bytes,
      learned_quota,
      learned_count,
      committed_bytes: None,
    };
    let (scope_generation, profile_generation) = reservation
      .profile
      .store
      .ledger
      .generations(&reservation.profile_name, &reservation.scope_key)
      .await?;
    reservation.scope_generation = scope_generation;
    reservation.profile_generation = profile_generation;
    Ok(reservation)
  }

  /// Finds one fresh, scope-bound dictionary and pins verified bytes in an `Arc`.
  pub async fn lookup(
    &self,
    profile_name: &str,
    scope: &DictionaryScope,
    hash: Option<&DictionaryHash>,
    request_url: &Url,
    destination: Option<&str>,
  ) -> anyhow::Result<Option<Arc<Dictionary>>> {
    let profile = self
      .profile(profile_name)
      .context("unknown compression dictionary profile")?;
    ensure!(
      scope.profile == profile_name,
      "dictionary scope profile does not match lookup profile"
    );
    ensure!(
      scope.origin.origin() == request_url.origin(),
      "dictionary request URL does not match its scope origin"
    );
    let scope_key = scope.key()?;
    let now = now_ms()?;
    let mut candidates = Vec::new();
    for entry in profile.store.ledger.entries().await? {
      if entry.profile != profile_name
        || entry.scope != scope_key
        || entry.expires_at_ms < now
        || hash.is_some_and(|value| value != &entry.hash)
      {
        continue;
      }
      let dictionary = ledger_entry_dictionary(&entry)?;
      candidates.push((entry, dictionary));
    }
    let selectors = candidates
      .iter()
      .map(|(entry, dictionary)| StoredDictionary {
        hash: dictionary.hash,
        dictionary_url: dictionary.url.clone(),
        use_as_dictionary: dictionary.declaration.clone(),
        fresh_or_stale_allowed: true,
        fetched_at: entry.fetched_at,
      })
      .collect::<Vec<_>>();
    let selected = select_dictionary(&selectors, request_url, destination);
    let Some(selected) = selected else {
      return Ok(self.lookup_configured(&profile, request_url, destination, hash));
    };
    let index = selectors
      .iter()
      .position(|value| {
        value.hash == selected.hash
          && value.dictionary_url == selected.dictionary_url
          && value.use_as_dictionary == selected.use_as_dictionary
      })
      .context("selected dictionary vanished")?;
    let (entry, mut dictionary) = candidates.swap_remove(index);
    let bytes = profile.store.ledger.read_entry_bytes(&entry).await?;
    verify_hash(&bytes, dictionary.hash)?;
    dictionary.bytes = Arc::from(bytes);
    Ok(Some(Arc::new(dictionary)))
  }

  /// Reserves profile capacity before chunk writes, then publishes atomically.
  #[cfg(test)]
  pub async fn learn(
    &self,
    profile_name: &str,
    scope: &DictionaryScope,
    url: Url,
    declaration: UseAsDictionary,
    bytes: Vec<u8>,
    fresh_until_ms: u64,
  ) -> anyhow::Result<Arc<Dictionary>> {
    let byte_count = u64::try_from(bytes.len())?;
    self
      .begin_learning(profile_name, scope, byte_count)
      .await?
      .commit(url, declaration, bytes, fresh_until_ms)
      .await
  }

  /// Fences affected scopes before best-effort chunk collection.
  pub async fn purge(
    &self,
    profile_name: &str,
    scope: Option<&DictionaryScope>,
    origin: Option<&Url>,
    hash: Option<DictionaryHash>,
  ) -> anyhow::Result<usize> {
    let profile = self
      .profile(profile_name)
      .context("unknown compression dictionary profile")?;
    let scope = scope.map(DictionaryScope::key).transpose()?;
    let origin = origin
      .map(Url::origin)
      .map(|value| value.ascii_serialization());
    let report = profile
      .store
      .ledger
      .purge(profile_name, scope.as_deref(), origin.as_deref(), hash)
      .await?;
    if let Ok(mut usage) = profile.usage.lock() {
      usage.live_bytes = usage.live_bytes.saturating_sub(report.bytes);
    }
    Ok(report.entries)
  }

  pub async fn inventory(&self, profile_name: &str) -> anyhow::Result<DictionaryInventory> {
    let profile = self
      .profile(profile_name)
      .context("unknown compression dictionary profile")?;
    let entries = profile.store.ledger.entries().await?;
    let bytes = entries
      .iter()
      .filter(|entry| entry.profile == profile_name)
      .try_fold(0_u64, |sum, entry| sum.checked_add(entry.bytes))
      .context("dictionary inventory overflow")?;
    let usage = profile
      .usage
      .lock()
      .map_err(|_| anyhow::anyhow!("dictionary profile usage poisoned"))?;
    Ok(DictionaryInventory {
      entries: entries
        .iter()
        .filter(|entry| entry.profile == profile_name)
        .count(),
      bytes,
      pending_bytes: usage.pending_bytes,
      active_jobs: usage.jobs,
    })
  }

  fn lookup_configured(
    &self,
    profile: &ProfileRuntime,
    request_url: &Url,
    destination: Option<&str>,
    hash: Option<&DictionaryHash>,
  ) -> Option<Arc<Dictionary>> {
    let candidates = profile
      .config
      .dictionaries
      .iter()
      .filter_map(|name| self.configured(name))
      .filter(|dictionary| hash.is_none_or(|value| value == &dictionary.hash))
      .map(|dictionary| {
        let mut dictionary = (*dictionary).clone();
        dictionary.declaration = configured_declaration(profile, &dictionary);
        Arc::new(dictionary)
      })
      .collect::<Vec<_>>();
    let selectors = candidates
      .iter()
      .map(|dictionary| StoredDictionary {
        hash: dictionary.hash,
        dictionary_url: dictionary.url.clone(),
        use_as_dictionary: configured_declaration(profile, dictionary),
        fresh_or_stale_allowed: true,
        fetched_at: 0,
      })
      .collect::<Vec<_>>();
    let selected = select_dictionary(&selectors, request_url, destination)?;
    candidates.into_iter().find(|dictionary| {
      dictionary.hash == selected.hash && dictionary.url == selected.dictionary_url
    })
  }

  fn learned_limits(&self, profile: &ProfileRuntime) -> anyhow::Result<(u64, usize)> {
    let configured_bytes = profile
      .config
      .dictionaries
      .iter()
      .filter_map(|name| self.configured(name))
      .try_fold(0_u64, |sum, dictionary| {
        sum.checked_add(dictionary.bytes.len() as u64)
      })
      .context("configured dictionary quota overflow")?;
    let learned_quota = profile
      .config
      .max_total_dictionary_bytes
      .checked_sub(configured_bytes)
      .context("configured dictionaries exceed profile quota")?;
    Ok((
      learned_quota,
      profile
        .config
        .max_dictionaries
        .saturating_sub(profile.config.dictionaries.len()),
    ))
  }
}

fn validate_scope(scope: &DictionaryScope) -> anyhow::Result<()> {
  ensure!(
    scope.origin.scheme() == "https" && scope.origin.host_str().is_some(),
    "dictionary scope origin must be HTTPS"
  );
  ensure!(
    !scope.profile.is_empty() && scope.profile.len() <= 128,
    "dictionary scope profile is invalid"
  );
  ensure!(
    !scope.route_policy_fingerprint.is_empty() && scope.route_policy_fingerprint.len() <= 256,
    "dictionary route policy fingerprint is invalid"
  );
  ensure!(
    scope
      .upstream_fingerprint
      .as_ref()
      .is_none_or(|value| !value.is_empty() && value.len() <= 256),
    "dictionary upstream fingerprint is invalid"
  );
  if scope.direction == DictionaryDirection::Downstream {
    ensure!(
      scope.upstream_fingerprint.is_none(),
      "downstream dictionary scope must not carry upstream fingerprint"
    );
  }
  Ok(())
}

fn validate_dictionary_parts(
  url: &Url,
  declaration: &UseAsDictionary,
  bytes: &[u8],
) -> anyhow::Result<()> {
  ensure!(
    !bytes.is_empty() && bytes.len() <= super::codec::MAX_RAW_DICTIONARY_BYTES,
    "dictionary exceeds codec limit"
  );
  validate_dictionary_metadata(url, declaration)
}

fn validate_dictionary_metadata(url: &Url, declaration: &UseAsDictionary) -> anyhow::Result<()> {
  ensure!(
    url.scheme() == "https"
      && url.host_str().is_some()
      && url.username().is_empty()
      && url.password().is_none()
      && url.fragment().is_none(),
    "dictionary URL must be credential-free HTTPS"
  );

  ensure!(
    !declaration.match_pattern.is_empty()
      && declaration.match_pattern.len() <= MAX_MATCH_PATTERN_BYTES,
    "dictionary match pattern is invalid"
  );
  ensure!(
    declaration.id.chars().count() <= MAX_DICTIONARY_ID_CHARS,
    "dictionary ID exceeds limit"
  );
  ensure!(
    declaration
      .id
      .bytes()
      .all(|byte| (0x20..=0x7e).contains(&byte)),
    "dictionary ID is not a structured-field string"
  );
  ensure!(
    declaration.match_destinations.len() <= MAX_MATCH_DESTINATIONS
      && declaration
        .match_destinations
        .iter()
        .all(|value| !value.is_empty()
          && value.len() <= MAX_MATCH_DESTINATION_BYTES
          && value.is_ascii()),
    "dictionary destinations are invalid"
  );
  ensure!(declaration.is_supported(), "dictionary type is unsupported");
  let init = UrlPatternInit::parse_constructor_string::<regex::Regex>(
    &declaration.match_pattern,
    Some(url.clone()),
  )
  .context("dictionary match pattern is invalid")?;
  let pattern = UrlPattern::<regex::Regex>::parse(init, Default::default())
    .context("dictionary match pattern is invalid")?;
  ensure!(
    !pattern.has_regexp_groups()
      && !super::fields::has_regex_group_syntax(&declaration.match_pattern),
    "dictionary match pattern has regex groups"
  );
  ensure!(
    pattern.protocol() == url.scheme(),
    "dictionary match pattern changes origin scheme"
  );
  ensure!(
    pattern.hostname() == url.host_str().unwrap_or_default(),
    "dictionary match pattern changes origin host"
  );
  let expected_port = url
    .port()
    .map(|value| value.to_string())
    .unwrap_or_default();
  ensure!(
    pattern.port() == expected_port,
    "dictionary match pattern changes origin port"
  );
  Ok(())
}

fn hash_bytes(bytes: &[u8]) -> anyhow::Result<DictionaryHash> {
  DictionaryHash::from_slice(&Sha256::digest(bytes)).map_err(anyhow::Error::msg)
}
fn verify_hash(bytes: &[u8], expected: DictionaryHash) -> anyhow::Result<()> {
  ensure!(
    hash_bytes(bytes)? == expected,
    "dictionary bytes do not match ledger digest"
  );
  Ok(())
}
fn now_ms() -> anyhow::Result<u64> {
  Ok(u64::try_from(
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .context("system clock predates epoch")?
      .as_millis(),
  )?)
}
fn reserve(profile: &ProfileRuntime, bytes: u64) -> anyhow::Result<()> {
  let mut usage = profile
    .usage
    .lock()
    .map_err(|_| anyhow::anyhow!("dictionary profile usage poisoned"))?;
  ensure!(
    usage
      .pending_bytes
      .checked_add(bytes)
      .context("dictionary reservation overflow")?
      <= profile.config.max_pending_dictionary_bytes,
    "dictionary pending reservation quota exceeded"
  );
  usage.pending_bytes += bytes;
  usage.jobs += 1;
  Ok(())
}
fn release(profile: &ProfileRuntime, reserved_bytes: u64, committed_bytes: Option<u64>) {
  if let Ok(mut usage) = profile.usage.lock() {
    usage.pending_bytes = usage.pending_bytes.saturating_sub(reserved_bytes);
    usage.jobs = usage.jobs.saturating_sub(1);
    if let Some(bytes) = committed_bytes {
      usage.live_bytes = usage.live_bytes.saturating_add(bytes);
    }
  }
}
fn configured_declaration(profile: &ProfileRuntime, dictionary: &Dictionary) -> UseAsDictionary {
  profile.config.advertise.as_ref().map_or_else(
    || dictionary.declaration.clone(),
    |advertise| UseAsDictionary {
      match_pattern: advertise.r#match.clone(),
      match_destinations: advertise.match_dest.clone(),
      id: advertise.id.clone(),
      dictionary_type: DictionaryType::Raw,
    },
  )
}

#[cfg(test)]
#[path = "runtime/tests.rs"]
mod tests;
