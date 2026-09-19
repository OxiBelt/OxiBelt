//! RFC 9842 compression-dictionary configuration.
//!
//! Dictionaries are immutable, operator-provided files.  Runtime learning can
//! populate only an explicitly named store; it never changes these files.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;
use urlpattern::{UrlPattern, UrlPatternInit};

use super::{
  CacheConfig, ConfigSourcePaths, SharedStateConfig,
  resolve_existing_local_config_file_path_with_logical, validate_runtime_identifier,
};

pub(crate) const COMPRESSION_DICTIONARY_CONFIG_KEYS: &[&str] =
  &["dictionaries", "enabled", "profiles", "stores"];
pub(crate) const COMPRESSION_DICTIONARY_ENTRY_CONFIG_KEYS: &[&str] =
  &["name", "path", "public", "sha256", "url"];
pub(crate) const COMPRESSION_DICTIONARY_STORE_CONFIG_KEYS: &[&str] =
  &["disk", "external", "kind", "name", "quota_bytes", "shared"];
pub(crate) const COMPRESSION_DICTIONARY_STORE_DISK_CONFIG_KEYS: &[&str] = &["root"];
pub(crate) const COMPRESSION_DICTIONARY_STORE_SHARED_CONFIG_KEYS: &[&str] = &["backend"];
pub(crate) const COMPRESSION_DICTIONARY_STORE_EXTERNAL_CONFIG_KEYS: &[&str] = &["handler"];
pub(crate) const COMPRESSION_DICTIONARY_PROFILE_CONFIG_KEYS: &[&str] = &[
  "advertise",
  "codec_timeout_ms",
  "dictionaries",
  "downstream",
  "learn",
  "max_codec_concurrency",
  "max_codec_memory_bytes",
  "max_decoded_size_bytes",
  "max_dictionaries",
  "max_dictionary_bytes",
  "max_expansion_ratio",
  "max_pending_dictionary_bytes",
  "max_total_dictionary_bytes",
  "name",
  "prefetch",
  "request_decode",
  "store",
  "upstream",
];
pub(crate) const COMPRESSION_DICTIONARY_ADVERTISEMENT_CONFIG_KEYS: &[&str] =
  &["id", "match", "match_dest"];
pub(crate) const COMPRESSION_DICTIONARY_PREFETCH_CONFIG_KEYS: &[&str] =
  &["max_bytes", "max_concurrent", "timeout_ms"];

/// The largest raw dictionary that can fit in a `dcb` compression window.
pub const MAX_COMPRESSION_DICTIONARY_BYTES: u64 = 16 * 1024 * 1024 - 16;

const MAX_DICTIONARIES_PER_PROFILE: usize = 4_096;
const MAX_PROFILE_STORAGE_BYTES: u64 = 1 << 40;
const MAX_CODEC_CONCURRENCY: usize = 1_024;
const MAX_CODEC_MEMORY_BYTES: u64 = 1 << 30;
const MAX_DECODED_SIZE_BYTES: u64 = 1 << 40;
const MAX_EXPANSION_RATIO: u32 = 1_000;
const MAX_CODEC_TIMEOUT_MS: u64 = 300_000;
const MAX_PREFETCH_CONCURRENCY: usize = 256;
const MAX_PREFETCH_TIMEOUT_MS: u64 = 300_000;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompressionDictionaryConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub dictionaries: Vec<DictionaryConfig>,
  #[serde(default)]
  pub stores: Vec<CompressionDictionaryStoreConfig>,
  #[serde(default)]
  pub profiles: Vec<CompressionDictionaryProfileConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DictionaryConfig {
  pub name: String,
  /// Relative to the configuration directory and verified during loading.
  pub path: PathBuf,
  /// Lowercase hexadecimal SHA-256 of the immutable dictionary content.
  pub sha256: String,
  #[serde(default)]
  pub public: bool,
  /// The full HTTPS dictionary resource URL, including its path when needed.
  pub url: Url,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CompressionDictionaryStoreKind {
  Memory,
  Disk,
  Shared,
  External,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompressionDictionaryStoreConfig {
  pub name: String,
  pub kind: CompressionDictionaryStoreKind,
  /// An operator-selected, finite byte quota for this store.
  pub quota_bytes: u64,
  #[serde(default)]
  pub disk: Option<CompressionDictionaryDiskStoreConfig>,
  #[serde(default)]
  pub shared: Option<CompressionDictionarySharedStoreConfig>,
  #[serde(default)]
  pub external: Option<CompressionDictionaryExternalStoreConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompressionDictionaryDiskStoreConfig {
  pub root: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompressionDictionarySharedStoreConfig {
  /// Name from `shared_state.backends`.
  pub backend: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompressionDictionaryExternalStoreConfig {
  /// Name from `cache.external_handlers`.
  pub handler: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompressionDictionaryProfileConfig {
  pub name: String,
  #[serde(default)]
  pub downstream: bool,
  #[serde(default)]
  pub upstream: bool,
  #[serde(default)]
  pub learn: bool,
  #[serde(default)]
  pub request_decode: bool,
  #[serde(default)]
  pub prefetch: Option<CompressionDictionaryPrefetchConfig>,
  #[serde(default)]
  pub advertise: Option<DictionaryAdvertisementConfig>,
  #[serde(default)]
  pub dictionaries: Vec<String>,
  pub store: String,
  pub max_dictionary_bytes: u64,
  pub max_dictionaries: usize,
  pub max_total_dictionary_bytes: u64,
  pub max_pending_dictionary_bytes: u64,
  pub max_codec_concurrency: usize,
  pub max_codec_memory_bytes: u64,
  pub max_decoded_size_bytes: u64,
  pub max_expansion_ratio: u32,
  pub codec_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DictionaryAdvertisementConfig {
  /// A same-origin URL Pattern without regular-expression groups.
  pub r#match: String,
  /// RFC 9842 permits the empty default ID.
  #[serde(default)]
  pub id: String,
  /// Fetch destinations; an empty list has RFC 9842's match-all meaning.
  #[serde(default)]
  pub match_dest: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompressionDictionaryPrefetchConfig {
  /// Redirects are never followed; this configuration bounds only direct fetches.
  pub max_concurrent: usize,
  pub max_bytes: u64,
  pub timeout_ms: u64,
}

/// Validate an isolated dictionary configuration against existing shared and
/// external storage names.  The caller owns the ordering of global validation.
pub(crate) fn validate_compression_dictionary(
  config: &CompressionDictionaryConfig,
  shared_state: &SharedStateConfig,
  cache: &CacheConfig,
) -> anyhow::Result<()> {
  if !config.enabled {
    return Ok(());
  }

  let mut dictionary_names = HashSet::new();
  for (index, dictionary) in config.dictionaries.iter().enumerate() {
    validate_dictionary(dictionary, index)?;
    if !dictionary_names.insert(dictionary.name.as_str()) {
      bail!("duplicate compression dictionary name {}", dictionary.name);
    }
  }

  let shared_backend_names = shared_state
    .backends
    .iter()
    .map(|backend| backend.name.as_str())
    .collect::<HashSet<_>>();
  let external_handler_names = cache
    .external_handlers
    .iter()
    .map(|handler| handler.name.as_str())
    .collect::<HashSet<_>>();
  let mut store_names = HashSet::new();
  for (index, store) in config.stores.iter().enumerate() {
    validate_store(
      store,
      index,
      shared_state.enabled,
      &shared_backend_names,
      &external_handler_names,
    )?;
    if !store_names.insert(store.name.as_str()) {
      bail!("duplicate compression dictionary store name {}", store.name);
    }
  }

  let mut profile_names = HashSet::new();
  for (index, profile) in config.profiles.iter().enumerate() {
    validate_profile(
      profile,
      index,
      &dictionary_names,
      &store_names,
      &config.dictionaries,
      config,
    )?;
    if !profile_names.insert(profile.name.as_str()) {
      bail!(
        "duplicate compression dictionary profile name {}",
        profile.name
      );
    }
  }
  Ok(())
}

/// Resolve dictionary files below `config_dir`, verify their declared digest,
/// and make them reload-visible.  Disk store roots are runtime writable paths,
/// so they are deliberately not treated as configuration source files.
pub(crate) fn resolve_compression_dictionary_paths(
  config: &mut CompressionDictionaryConfig,
  config_dir: &Path,
  source_paths: &mut ConfigSourcePaths,
) -> anyhow::Result<()> {
  if !config.enabled {
    return Ok(());
  }

  for (index, dictionary) in config.dictionaries.iter_mut().enumerate() {
    let field = format!("compression_dictionary.dictionaries[{index}].path");
    let (resolved, logical) =
      resolve_existing_local_config_file_path_with_logical(&field, config_dir, &dictionary.path)?;
    let metadata = std::fs::metadata(&resolved)
      .with_context(|| format!("failed to inspect {field} {}", resolved.display()))?;
    if metadata.len() > MAX_COMPRESSION_DICTIONARY_BYTES {
      bail!("{field} must not exceed {MAX_COMPRESSION_DICTIONARY_BYTES} bytes");
    }
    let bytes = std::fs::read(&resolved)
      .with_context(|| format!("failed to read {field} {}", resolved.display()))?;
    let actual = hex_digest(&Sha256::digest(bytes));
    if actual != dictionary.sha256 {
      bail!(
        "{field} does not match compression dictionary {} sha256",
        dictionary.name
      );
    }
    dictionary.path = resolved;
    source_paths.remember_runtime_file(logical);
  }
  Ok(())
}

fn validate_dictionary(dictionary: &DictionaryConfig, index: usize) -> anyhow::Result<()> {
  let prefix = format!("compression_dictionary.dictionaries[{index}]");
  validate_runtime_identifier(&format!("{prefix}.name"), &dictionary.name)?;
  // `Config::load` validates this as a relative path before resolving it below
  // the configuration directory.  Validation runs again on the resolved
  // snapshot, where the trusted file path is necessarily absolute.
  if !dictionary.path.is_absolute() {
    validate_relative_file_path(&format!("{prefix}.path"), &dictionary.path)?;
  }
  validate_sha256(&format!("{prefix}.sha256"), &dictionary.sha256)?;
  validate_dictionary_url(&format!("{prefix}.url"), &dictionary.url)
}

fn validate_store(
  store: &CompressionDictionaryStoreConfig,
  index: usize,
  shared_state_enabled: bool,
  shared_backend_names: &HashSet<&str>,
  external_handler_names: &HashSet<&str>,
) -> anyhow::Result<()> {
  let prefix = format!("compression_dictionary.stores[{index}]");
  validate_runtime_identifier(&format!("{prefix}.name"), &store.name)?;
  validate_bounded_bytes(
    &format!("{prefix}.quota_bytes"),
    store.quota_bytes,
    MAX_PROFILE_STORAGE_BYTES,
  )?;
  match store.kind {
    CompressionDictionaryStoreKind::Memory => {
      require_only_store_config(&prefix, store, false, false, false)?;
    }
    CompressionDictionaryStoreKind::Disk => {
      require_only_store_config(&prefix, store, true, false, false)?;
      let disk = store
        .disk
        .as_ref()
        .context("validated disk store config is absent")?;
      validate_dedicated_absolute_directory(&format!("{prefix}.disk.root"), &disk.root)?;
    }
    CompressionDictionaryStoreKind::Shared => {
      require_only_store_config(&prefix, store, false, true, false)?;
      if !shared_state_enabled {
        bail!("{prefix}.shared requires shared_state.enabled");
      }
      let shared = store
        .shared
        .as_ref()
        .context("validated shared store config is absent")?;
      validate_runtime_identifier(&format!("{prefix}.shared.backend"), &shared.backend)?;
      if !shared_backend_names.contains(shared.backend.as_str()) {
        bail!(
          "{prefix}.shared.backend references unknown shared_state backend {}",
          shared.backend
        );
      }
    }
    CompressionDictionaryStoreKind::External => {
      require_only_store_config(&prefix, store, false, false, true)?;
      let external = store
        .external
        .as_ref()
        .context("validated external store config is absent")?;
      validate_runtime_identifier(&format!("{prefix}.external.handler"), &external.handler)?;
      if !external_handler_names.contains(external.handler.as_str()) {
        bail!(
          "{prefix}.external.handler references unknown cache external handler {}",
          external.handler
        );
      }
    }
  }
  Ok(())
}

fn require_only_store_config(
  prefix: &str,
  store: &CompressionDictionaryStoreConfig,
  disk: bool,
  shared: bool,
  external: bool,
) -> anyhow::Result<()> {
  let supplied = [
    ("disk", store.disk.is_some(), disk),
    ("shared", store.shared.is_some(), shared),
    ("external", store.external.is_some(), external),
  ];
  for (name, present, allowed) in supplied {
    if present && !allowed {
      bail!("{prefix}.{name} is not allowed for this store kind");
    }
    if allowed && !present {
      bail!("{prefix}.{name} is required for this store kind");
    }
  }
  Ok(())
}

fn validate_profile(
  profile: &CompressionDictionaryProfileConfig,
  index: usize,
  dictionary_names: &HashSet<&str>,
  store_names: &HashSet<&str>,
  dictionaries: &[DictionaryConfig],
  config: &CompressionDictionaryConfig,
) -> anyhow::Result<()> {
  let prefix = format!("compression_dictionary.profiles[{index}]");
  validate_runtime_identifier(&format!("{prefix}.name"), &profile.name)?;
  validate_runtime_identifier(&format!("{prefix}.store"), &profile.store)?;
  if !store_names.contains(profile.store.as_str()) {
    bail!(
      "{prefix}.store references unknown compression dictionary store {}",
      profile.store
    );
  }
  if !(profile.downstream
    || profile.upstream
    || profile.learn
    || profile.request_decode
    || profile.prefetch.is_some())
  {
    bail!("{prefix} must enable downstream, upstream, learn, request_decode, or prefetch");
  }

  let mut references = HashSet::new();
  for name in &profile.dictionaries {
    validate_runtime_identifier(&format!("{prefix}.dictionaries"), name)?;
    if !dictionary_names.contains(name.as_str()) {
      bail!("{prefix}.dictionaries references unknown compression dictionary {name}");
    }
    if config
      .dictionaries
      .iter()
      .find(|dictionary| dictionary.name == *name)
      .is_some_and(|dictionary| !dictionary.public)
    {
      bail!("{prefix}.dictionaries must reference explicitly public dictionaries");
    }
    if !references.insert(name.as_str()) {
      bail!("{prefix}.dictionaries contains duplicate compression dictionary {name}");
    }
  }
  if profile.downstream && profile.dictionaries.is_empty() {
    bail!("{prefix}.downstream requires at least one dictionary reference");
  }

  if profile.max_dictionary_bytes == 0
    || profile.max_dictionary_bytes > MAX_COMPRESSION_DICTIONARY_BYTES
  {
    bail!("{prefix}.max_dictionary_bytes must be within 1..={MAX_COMPRESSION_DICTIONARY_BYTES}");
  }
  if profile.max_dictionaries == 0 || profile.max_dictionaries > MAX_DICTIONARIES_PER_PROFILE {
    bail!("{prefix}.max_dictionaries must be within 1..={MAX_DICTIONARIES_PER_PROFILE}");
  }
  if profile.dictionaries.len() > profile.max_dictionaries {
    bail!("{prefix}.max_dictionaries must cover all configured dictionary references");
  }
  validate_bounded_bytes(
    &format!("{prefix}.max_total_dictionary_bytes"),
    profile.max_total_dictionary_bytes,
    MAX_PROFILE_STORAGE_BYTES,
  )?;
  if profile.max_total_dictionary_bytes < profile.max_dictionary_bytes {
    bail!("{prefix}.max_total_dictionary_bytes must be at least max_dictionary_bytes");
  }
  validate_bounded_bytes(
    &format!("{prefix}.max_pending_dictionary_bytes"),
    profile.max_pending_dictionary_bytes,
    MAX_PROFILE_STORAGE_BYTES,
  )?;
  if profile.max_pending_dictionary_bytes > profile.max_total_dictionary_bytes {
    bail!("{prefix}.max_pending_dictionary_bytes must not exceed max_total_dictionary_bytes");
  }
  let store = config
    .stores
    .iter()
    .find(|store| store.name == profile.store)
    .context("validated compression dictionary store reference is absent")?;
  if profile.max_total_dictionary_bytes > store.quota_bytes {
    bail!("{prefix}.max_total_dictionary_bytes must not exceed store quota_bytes");
  }
  if profile.max_codec_concurrency == 0 || profile.max_codec_concurrency > MAX_CODEC_CONCURRENCY {
    bail!("{prefix}.max_codec_concurrency must be within 1..={MAX_CODEC_CONCURRENCY}");
  }
  validate_bounded_bytes(
    &format!("{prefix}.max_codec_memory_bytes"),
    profile.max_codec_memory_bytes,
    MAX_CODEC_MEMORY_BYTES,
  )?;
  if profile.max_codec_memory_bytes
    < crate::compression_dictionary::codec::maximum_working_set_bytes()
  {
    bail!("{prefix}.max_codec_memory_bytes must reserve at least one bounded codec working set");
  }
  validate_bounded_bytes(
    &format!("{prefix}.max_decoded_size_bytes"),
    profile.max_decoded_size_bytes,
    MAX_DECODED_SIZE_BYTES,
  )?;
  if profile.max_expansion_ratio == 0 || profile.max_expansion_ratio > MAX_EXPANSION_RATIO {
    bail!("{prefix}.max_expansion_ratio must be within 1..={MAX_EXPANSION_RATIO}");
  }
  if profile.codec_timeout_ms == 0 || profile.codec_timeout_ms > MAX_CODEC_TIMEOUT_MS {
    bail!("{prefix}.codec_timeout_ms must be within 1..={MAX_CODEC_TIMEOUT_MS}");
  }
  if let Some(prefetch) = &profile.prefetch {
    if !profile.learn {
      bail!("{prefix}.prefetch requires learn");
    }
    validate_prefetch(&format!("{prefix}.prefetch"), prefetch, profile)?;
  }
  if let Some(advertise) = &profile.advertise {
    if !profile.downstream {
      bail!("{prefix}.advertise requires downstream");
    }
    validate_advertisement(
      &format!("{prefix}.advertise"),
      advertise,
      &profile.dictionaries,
      dictionaries,
    )?;
  }
  Ok(())
}

fn validate_prefetch(
  prefix: &str,
  prefetch: &CompressionDictionaryPrefetchConfig,
  profile: &CompressionDictionaryProfileConfig,
) -> anyhow::Result<()> {
  if prefetch.max_concurrent == 0 || prefetch.max_concurrent > MAX_PREFETCH_CONCURRENCY {
    bail!("{prefix}.max_concurrent must be within 1..={MAX_PREFETCH_CONCURRENCY}");
  }
  if prefetch.max_concurrent > profile.max_dictionaries {
    bail!("{prefix}.max_concurrent must not exceed max_dictionaries");
  }
  validate_bounded_bytes(
    &format!("{prefix}.max_bytes"),
    prefetch.max_bytes,
    MAX_PROFILE_STORAGE_BYTES,
  )?;
  if prefetch.max_bytes > profile.max_pending_dictionary_bytes {
    bail!("{prefix}.max_bytes must not exceed max_pending_dictionary_bytes");
  }
  if prefetch.timeout_ms == 0 || prefetch.timeout_ms > MAX_PREFETCH_TIMEOUT_MS {
    bail!("{prefix}.timeout_ms must be within 1..={MAX_PREFETCH_TIMEOUT_MS}");
  }
  Ok(())
}

fn validate_advertisement(
  prefix: &str,
  advertise: &DictionaryAdvertisementConfig,
  references: &[String],
  dictionaries: &[DictionaryConfig],
) -> anyhow::Result<()> {
  if references.is_empty() {
    bail!("{prefix} requires at least one dictionary reference");
  }
  if advertise.id.len() > 1_024 || advertise.id.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("{prefix}.id must contain at most 1024 non-control characters");
  }
  let mut destinations = HashSet::new();
  for destination in &advertise.match_dest {
    if destination.is_empty()
      || destination.len() > 128
      || !destination
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
      bail!("{prefix}.match_dest entries must be non-empty destination tokens");
    }
    if !destinations.insert(destination.as_str()) {
      bail!("{prefix}.match_dest contains duplicate destination {destination}");
    }
  }
  for name in references {
    let dictionary = dictionaries
      .iter()
      .find(|dictionary| dictionary.name == *name)
      .context("validated compression dictionary reference is absent")?;
    validate_same_origin_url_pattern(
      &format!("{prefix}.match"),
      &advertise.r#match,
      &dictionary.url,
    )?;
  }
  Ok(())
}

fn validate_same_origin_url_pattern(
  field: &str,
  pattern: &str,
  base_url: &Url,
) -> anyhow::Result<()> {
  if pattern.is_empty() || pattern.len() > 2_048 || !pattern.starts_with('/') {
    bail!("{field} must be a non-empty same-origin absolute path URL Pattern");
  }
  if crate::compression_dictionary::fields::has_regex_group_syntax(pattern) {
    bail!("{field} must not contain regular-expression groups");
  }
  if pattern.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("{field} must not contain control characters");
  }
  let pattern = UrlPattern::<regex::Regex>::parse(
    UrlPatternInit {
      pathname: Some(pattern.to_owned()),
      base_url: Some(base_url.clone()),
      ..Default::default()
    },
    Default::default(),
  )
  .with_context(|| format!("{field} is not a valid URL Pattern"))?;
  if pattern.has_regexp_groups() {
    bail!("{field} must not contain regular-expression groups");
  }
  Ok(())
}

fn validate_dictionary_url(field: &str, url: &Url) -> anyhow::Result<()> {
  if url.scheme() != "https"
    || url.host_str().is_none()
    || !url.username().is_empty()
    || url.password().is_some()
    || url.fragment().is_some()
  {
    bail!("{field} must be an absolute HTTPS URL without credentials or fragment");
  }
  Ok(())
}

fn validate_relative_file_path(field: &str, path: &Path) -> anyhow::Result<()> {
  if path.as_os_str().is_empty() || path.is_absolute() {
    bail!("{field} must be a non-empty relative file path");
  }
  if path
    .components()
    .any(|component| !matches!(component, Component::Normal(_)))
  {
    bail!("{field} must not contain current-directory or parent-directory components");
  }
  Ok(())
}

fn validate_dedicated_absolute_directory(field: &str, path: &Path) -> anyhow::Result<()> {
  if !path.is_absolute() || path.parent().is_none() {
    bail!("{field} must be an absolute dedicated directory");
  }
  if path
    .components()
    .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
  {
    bail!("{field} must not contain current-directory or parent-directory components");
  }
  Ok(())
}

fn validate_sha256(field: &str, digest: &str) -> anyhow::Result<()> {
  if digest.len() != 64
    || !digest
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit()))
  {
    bail!("{field} must be a lowercase hexadecimal SHA-256 digest");
  }
  Ok(())
}

fn validate_bounded_bytes(field: &str, value: u64, maximum: u64) -> anyhow::Result<()> {
  if value == 0 || value > maximum {
    bail!("{field} must be within 1..={maximum}");
  }
  Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}

#[cfg(test)]
mod tests;
