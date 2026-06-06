//! Client identity configuration for bounded request classification helpers.
//! External identity data stays operator supplied and opt-in.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use url::Url;

use super::{
  ConfigSourcePaths, canonicalize_existing_file,
  resolve_existing_local_config_file_path_with_logical, validate_optional_non_empty,
};

pub(crate) const CLIENT_IDENTITY_CONFIG_KEYS: &[&str] = &["asn"];

pub(crate) const CLIENT_IDENTITY_ASN_CONFIG_KEYS: &[&str] = &[
  "database_file",
  "database_sha256",
  "failure_policy",
  "format",
  "iana_registry",
  "managed",
  "max_database_age_seconds",
  "max_database_bytes",
  "max_entries",
  "mode",
];

pub(crate) const CLIENT_IDENTITY_ASN_MANAGED_CONFIG_KEYS: &[&str] = &[
  "cache_dir",
  "max_cache_bytes",
  "refresh_interval_seconds",
  "request_timeout_ms",
  "source_url",
  "storage",
  "tmpfs_dir",
];

pub(crate) const CLIENT_IDENTITY_ASN_IANA_REGISTRY_CONFIG_KEYS: &[&str] =
  &["enabled", "source_urls"];

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ClientIdentityConfig {
  #[serde(default)]
  pub asn: ClientIdentityAsnConfig,
}

impl ClientIdentityConfig {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    self.asn.validate()
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ClientIdentityAsnConfig {
  #[serde(default)]
  pub mode: ClientIdentityAsnMode,
  #[serde(default)]
  pub database_file: Option<PathBuf>,
  #[serde(default)]
  pub database_sha256: Option<String>,
  #[serde(default)]
  pub format: ClientIdentityAsnFormat,
  #[serde(default = "default_asn_max_database_bytes")]
  pub max_database_bytes: usize,
  #[serde(default = "default_asn_max_entries")]
  pub max_entries: usize,
  #[serde(default = "default_asn_max_database_age_seconds")]
  pub max_database_age_seconds: u64,
  #[serde(default)]
  pub failure_policy: ClientIdentityAsnFailurePolicy,
  #[serde(default)]
  pub managed: ClientIdentityAsnManagedConfig,
  #[serde(default)]
  pub iana_registry: ClientIdentityAsnIanaRegistryConfig,
}

impl Default for ClientIdentityAsnConfig {
  fn default() -> Self {
    Self {
      mode: ClientIdentityAsnMode::Disabled,
      database_file: None,
      database_sha256: None,
      format: ClientIdentityAsnFormat::PrefixAsnCsv,
      max_database_bytes: default_asn_max_database_bytes(),
      max_entries: default_asn_max_entries(),
      max_database_age_seconds: default_asn_max_database_age_seconds(),
      failure_policy: ClientIdentityAsnFailurePolicy::FailClosed,
      managed: ClientIdentityAsnManagedConfig::default(),
      iana_registry: ClientIdentityAsnIanaRegistryConfig::default(),
    }
  }
}

impl ClientIdentityAsnConfig {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    match self.mode {
      ClientIdentityAsnMode::Disabled => return Ok(()),
      ClientIdentityAsnMode::Local => {
        if self.database_file.is_none() {
          bail!(
            "client_identity.asn.database_file is required when client_identity.asn.mode = \"local\""
          );
        }
      }
      ClientIdentityAsnMode::Managed => {
        if self.database_file.is_some() {
          bail!(
            "client_identity.asn.database_file cannot be used when client_identity.asn.mode = \"managed\""
          );
        }
        self.managed.validate()?;
      }
    }
    if self.max_database_bytes == 0 {
      bail!("client_identity.asn.max_database_bytes must be greater than 0");
    }
    if self.max_entries == 0 {
      bail!("client_identity.asn.max_entries must be greater than 0");
    }
    if self.max_database_age_seconds == 0 {
      bail!("client_identity.asn.max_database_age_seconds must be greater than 0");
    }
    if let Some(expected) = self.database_sha256.as_deref()
      && !expected.trim().is_empty()
      && (expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
      bail!("client_identity.asn.database_sha256 must be a 64-character hex SHA-256 digest");
    }
    self.iana_registry.validate()?;
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdentityAsnMode {
  #[default]
  Disabled,
  Local,
  Managed,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdentityAsnFormat {
  #[default]
  PrefixAsnCsv,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdentityAsnFailurePolicy {
  #[default]
  FailClosed,
  DegradedNull,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ClientIdentityAsnManagedConfig {
  #[serde(default)]
  pub source_url: Option<String>,
  #[serde(default = "default_asn_managed_cache_dir")]
  pub cache_dir: PathBuf,
  #[serde(default = "default_asn_managed_tmpfs_dir")]
  pub tmpfs_dir: PathBuf,
  #[serde(default)]
  pub storage: ClientIdentityAsnManagedStorage,
  #[serde(default = "default_asn_managed_max_cache_bytes")]
  pub max_cache_bytes: usize,
  #[serde(default = "default_asn_managed_refresh_interval_seconds")]
  pub refresh_interval_seconds: u64,
  #[serde(default = "default_asn_managed_request_timeout_ms")]
  pub request_timeout_ms: u64,
}

impl Default for ClientIdentityAsnManagedConfig {
  fn default() -> Self {
    Self {
      source_url: None,
      cache_dir: default_asn_managed_cache_dir(),
      tmpfs_dir: default_asn_managed_tmpfs_dir(),
      storage: ClientIdentityAsnManagedStorage::Disk,
      max_cache_bytes: default_asn_managed_max_cache_bytes(),
      refresh_interval_seconds: default_asn_managed_refresh_interval_seconds(),
      request_timeout_ms: default_asn_managed_request_timeout_ms(),
    }
  }
}

impl ClientIdentityAsnManagedConfig {
  fn validate(&self) -> anyhow::Result<()> {
    let source_url = self
      .source_url
      .as_deref()
      .filter(|value| !value.trim().is_empty())
      .ok_or_else(|| anyhow::anyhow!("client_identity.asn.managed.source_url is required"))?;
    validate_https_url("client_identity.asn.managed.source_url", source_url)?;
    if self.max_cache_bytes == 0 {
      bail!("client_identity.asn.managed.max_cache_bytes must be greater than 0");
    }
    if self.refresh_interval_seconds == 0 {
      bail!("client_identity.asn.managed.refresh_interval_seconds must be greater than 0");
    }
    if self.request_timeout_ms == 0 {
      bail!("client_identity.asn.managed.request_timeout_ms must be greater than 0");
    }
    match self.storage {
      ClientIdentityAsnManagedStorage::Memory => {}
      ClientIdentityAsnManagedStorage::Tmpfs => crate::cache::validate_tmpfs_dir(&self.tmpfs_dir)?,
      ClientIdentityAsnManagedStorage::Disk => crate::cache::validate_disk_dir(&self.cache_dir)?,
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdentityAsnManagedStorage {
  Memory,
  Tmpfs,
  #[default]
  Disk,
}

impl ClientIdentityAsnManagedStorage {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Memory => "memory",
      Self::Tmpfs => "tmpfs",
      Self::Disk => "disk",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ClientIdentityAsnIanaRegistryConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_iana_registry_source_urls")]
  pub source_urls: Vec<String>,
}

impl Default for ClientIdentityAsnIanaRegistryConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      source_urls: default_iana_registry_source_urls(),
    }
  }
}

impl ClientIdentityAsnIanaRegistryConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if !self.enabled {
      return Ok(());
    }
    if self.source_urls.is_empty() {
      bail!("client_identity.asn.iana_registry.source_urls must not be empty when enabled");
    }
    for source_url in &self.source_urls {
      validate_https_url("client_identity.asn.iana_registry.source_urls", source_url)?;
    }
    Ok(())
  }
}

pub(crate) fn resolve_asn_database_file(
  config: &mut ClientIdentityAsnConfig,
  source_paths: &mut ConfigSourcePaths,
  config_dir: &Path,
) -> anyhow::Result<()> {
  config.database_file = config
    .database_file
    .take()
    .map(|path| {
      if path.is_absolute() {
        let resolved = canonicalize_existing_file("client_identity.asn.database_file", &path)?;
        source_paths.remember_runtime_file(resolved.clone());
        return Ok::<PathBuf, anyhow::Error>(resolved);
      }
      let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
        "client_identity.asn.database_file",
        config_dir,
        &path,
      )?;
      source_paths.remember_runtime_file(logical);
      Ok::<PathBuf, anyhow::Error>(resolved)
    })
    .transpose()?;
  Ok(())
}

fn validate_https_url(label: &str, value: &str) -> anyhow::Result<()> {
  validate_optional_non_empty(label, Some(value))?;
  let url = Url::parse(value).with_context(|| format!("{label} is invalid"))?;
  if url.scheme() != "https" {
    bail!("{label} must use https://");
  }
  if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
    bail!("{label} must not include credentials or fragments");
  }
  Ok(())
}

fn default_asn_max_database_bytes() -> usize {
  67_108_864
}

fn default_asn_max_entries() -> usize {
  1_000_000
}

fn default_asn_max_database_age_seconds() -> u64 {
  86_400
}

fn default_asn_managed_cache_dir() -> PathBuf {
  PathBuf::from("/var/lib/oxibelt/asn")
}

fn default_asn_managed_tmpfs_dir() -> PathBuf {
  PathBuf::from("/dev/shm/oxibelt-asn")
}

fn default_asn_managed_max_cache_bytes() -> usize {
  134_217_728
}

fn default_asn_managed_refresh_interval_seconds() -> u64 {
  21_600
}

fn default_asn_managed_request_timeout_ms() -> u64 {
  3_000
}

fn default_iana_registry_source_urls() -> Vec<String> {
  vec![
    "https://www.iana.org/assignments/as-numbers/as-numbers-1.csv".to_string(),
    "https://www.iana.org/assignments/as-numbers/as-numbers-2.csv".to_string(),
  ]
}
