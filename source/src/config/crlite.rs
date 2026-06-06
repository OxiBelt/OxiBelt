use std::path::{Path, PathBuf};

use anyhow::bail;
use serde::Deserialize;

use super::{ConfigSourcePaths, resolve_existing_local_config_file_path_with_logical};

pub(crate) const CRLITE_CONFIG_KEYS: &[&str] = &[
  "mode",
  "filter_file",
  "filter_sha256",
  "max_filter_bytes",
  "max_filter_age_seconds",
  "failure_policy",
  "coverage_policy",
  "managed",
];

pub(crate) const CRLITE_MANAGED_CONFIG_KEYS: &[&str] = &[
  "cache_dir",
  "max_cache_bytes",
  "refresh_interval_seconds",
  "request_timeout_ms",
  "storage",
  "tmpfs_dir",
];

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CrliteConfig {
  #[serde(default)]
  pub mode: CrliteMode,
  #[serde(default)]
  pub filter_file: Option<PathBuf>,
  #[serde(default)]
  pub filter_sha256: Option<String>,
  #[serde(default = "default_crlite_max_filter_bytes")]
  pub max_filter_bytes: usize,
  #[serde(default = "default_crlite_max_filter_age_seconds")]
  pub max_filter_age_seconds: u64,
  #[serde(default)]
  pub failure_policy: CrliteFailurePolicy,
  #[serde(default)]
  pub coverage_policy: CrliteCoveragePolicy,
  #[serde(default)]
  pub managed: CrliteManagedConfig,
}

impl Default for CrliteConfig {
  fn default() -> Self {
    Self {
      mode: CrliteMode::Disabled,
      filter_file: None,
      filter_sha256: None,
      max_filter_bytes: default_crlite_max_filter_bytes(),
      max_filter_age_seconds: default_crlite_max_filter_age_seconds(),
      failure_policy: CrliteFailurePolicy::FailClosed,
      coverage_policy: CrliteCoveragePolicy::AllowUnknown,
      managed: CrliteManagedConfig::default(),
    }
  }
}

impl CrliteConfig {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    match self.mode {
      CrliteMode::Disabled => {}
      CrliteMode::Enforce => {
        if self.filter_file.is_none() {
          bail!("tls.crlite.filter_file is required when tls.crlite.mode = \"enforce\"");
        }
      }
      CrliteMode::Managed => {
        if self.filter_file.is_some() {
          bail!("tls.crlite.filter_file cannot be used when tls.crlite.mode = \"managed\"");
        }
        if self.filter_sha256.is_some() {
          bail!("tls.crlite.filter_sha256 cannot be used when tls.crlite.mode = \"managed\"");
        }
      }
    }
    if self.max_filter_bytes == 0 {
      bail!("tls.crlite.max_filter_bytes must be greater than 0");
    }
    if self.max_filter_age_seconds == 0 {
      bail!("tls.crlite.max_filter_age_seconds must be greater than 0");
    }
    if let Some(expected) = self.filter_sha256.as_deref()
      && (expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
      bail!("tls.crlite.filter_sha256 must be a 64-character hex SHA-256 digest");
    }
    if self.mode == CrliteMode::Managed {
      self.managed.validate()?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CrliteMode {
  #[default]
  Disabled,
  Enforce,
  Managed,
}

impl CrliteMode {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Disabled => "disabled",
      Self::Enforce => "enforce",
      Self::Managed => "managed",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CrliteFailurePolicy {
  #[default]
  FailClosed,
  DegradedAllow,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CrliteCoveragePolicy {
  #[default]
  AllowUnknown,
  RequireGood,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CrliteManagedConfig {
  #[serde(default)]
  pub storage: CrliteManagedStorage,
  #[serde(default = "default_crlite_managed_cache_dir")]
  pub cache_dir: PathBuf,
  #[serde(default = "default_crlite_managed_tmpfs_dir")]
  pub tmpfs_dir: PathBuf,
  #[serde(default = "default_crlite_managed_max_cache_bytes")]
  pub max_cache_bytes: usize,
  #[serde(default = "default_crlite_managed_refresh_interval_seconds")]
  pub refresh_interval_seconds: u64,
  #[serde(default = "default_crlite_managed_request_timeout_ms")]
  pub request_timeout_ms: u64,
}

impl Default for CrliteManagedConfig {
  fn default() -> Self {
    Self {
      storage: CrliteManagedStorage::Disk,
      cache_dir: default_crlite_managed_cache_dir(),
      tmpfs_dir: default_crlite_managed_tmpfs_dir(),
      max_cache_bytes: default_crlite_managed_max_cache_bytes(),
      refresh_interval_seconds: default_crlite_managed_refresh_interval_seconds(),
      request_timeout_ms: default_crlite_managed_request_timeout_ms(),
    }
  }
}

impl CrliteManagedConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.max_cache_bytes == 0 {
      bail!("tls.crlite.managed.max_cache_bytes must be greater than 0");
    }
    if self.refresh_interval_seconds == 0 {
      bail!("tls.crlite.managed.refresh_interval_seconds must be greater than 0");
    }
    if self.request_timeout_ms == 0 {
      bail!("tls.crlite.managed.request_timeout_ms must be greater than 0");
    }
    match self.storage {
      CrliteManagedStorage::Memory => {}
      CrliteManagedStorage::Tmpfs => crate::cache::validate_tmpfs_dir(&self.tmpfs_dir)?,
      CrliteManagedStorage::Disk => crate::cache::validate_disk_dir(&self.cache_dir)?,
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CrliteManagedStorage {
  Memory,
  Tmpfs,
  #[default]
  Disk,
}

impl CrliteManagedStorage {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Memory => "memory",
      Self::Tmpfs => "tmpfs",
      Self::Disk => "disk",
    }
  }
}

pub const CRLITE_MODE_WIRE_VALUES: &[&str] = &["disabled", "enforce", "managed"];
pub const CRLITE_FAILURE_POLICY_WIRE_VALUES: &[&str] = &["fail_closed", "degraded_allow"];
pub const CRLITE_COVERAGE_POLICY_WIRE_VALUES: &[&str] = &["allow_unknown", "require_good"];
pub const CRLITE_MANAGED_STORAGE_WIRE_VALUES: &[&str] = &["memory", "tmpfs", "disk"];

pub(crate) fn resolve_filter_file(
  config: &mut CrliteConfig,
  source_paths: &mut ConfigSourcePaths,
  cert_dir: &Path,
) -> anyhow::Result<()> {
  config.filter_file = config
    .filter_file
    .take()
    .map(|path| {
      let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
        "tls.crlite.filter_file",
        cert_dir,
        &path,
      )?;
      source_paths.remember_runtime_file(logical.clone());
      source_paths.remember_downstream_tls_file(logical.clone());
      source_paths.downstream_tls_crlite_filter_file = Some(logical);
      Ok::<PathBuf, anyhow::Error>(resolved)
    })
    .transpose()?;
  Ok(())
}

fn default_crlite_max_filter_bytes() -> usize {
  33_554_432
}

fn default_crlite_max_filter_age_seconds() -> u64 {
  86_400
}

fn default_crlite_managed_cache_dir() -> PathBuf {
  PathBuf::from("/var/lib/oxibelt/crlite")
}

fn default_crlite_managed_tmpfs_dir() -> PathBuf {
  PathBuf::from("/dev/shm/oxibelt-crlite")
}

fn default_crlite_managed_max_cache_bytes() -> usize {
  67_108_864
}

fn default_crlite_managed_refresh_interval_seconds() -> u64 {
  21_600
}

fn default_crlite_managed_request_timeout_ms() -> u64 {
  3_000
}
