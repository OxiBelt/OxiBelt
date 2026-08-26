//! Downstream certificate-transparency verification configuration.

use std::path::{Path, PathBuf};

use anyhow::bail;
use serde::Deserialize;

use super::{ConfigSourcePaths, resolve_existing_local_config_file_path_with_logical};

pub(crate) const DOWNSTREAM_CT_CONFIG_KEYS: &[&str] =
  &["failure_policy", "log_list", "mode", "policy"];
pub(crate) const DOWNSTREAM_CT_CERTIFICATE_CONFIG_KEYS: &[&str] = &["mode"];
pub(crate) const DOWNSTREAM_CT_LOG_LIST_CONFIG_KEYS: &[&str] = &[
  "cache_dir",
  "file",
  "max_download_bytes",
  "mode",
  "refresh_interval_seconds",
  "request_timeout_ms",
  "signature_file",
];

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DownstreamCtConfig {
  #[serde(default)]
  pub mode: DownstreamCtMode,
  #[serde(default)]
  pub policy: DownstreamCtPolicy,
  #[serde(default)]
  pub failure_policy: DownstreamCtFailurePolicy,
  #[serde(default)]
  pub log_list: DownstreamCtLogListConfig,
}

impl Default for DownstreamCtConfig {
  fn default() -> Self {
    Self {
      mode: DownstreamCtMode::Disabled,
      policy: DownstreamCtPolicy::Chrome,
      failure_policy: DownstreamCtFailurePolicy::RejectHandshake,
      log_list: DownstreamCtLogListConfig::default(),
    }
  }
}

impl DownstreamCtConfig {
  pub(crate) fn validate(&self, enabled: bool) -> anyhow::Result<()> {
    if self.log_list.max_download_bytes == 0 || self.log_list.max_download_bytes > 16 * 1024 * 1024
    {
      bail!("tls.ct.log_list.max_download_bytes must be between 1 and 16777216");
    }
    if self.log_list.request_timeout_ms == 0 || self.log_list.request_timeout_ms > 30_000 {
      bail!("tls.ct.log_list.request_timeout_ms must be between 1 and 30000");
    }
    if self.log_list.refresh_interval_seconds < 3_600
      || self.log_list.refresh_interval_seconds > 604_800
    {
      bail!("tls.ct.log_list.refresh_interval_seconds must be between 3600 and 604800");
    }
    match self.log_list.mode {
      DownstreamCtLogListMode::Managed => {
        if self.log_list.file.is_some() || self.log_list.signature_file.is_some() {
          bail!("tls.ct.log_list.file and signature_file cannot be used when mode = \"managed\"");
        }
        if enabled {
          crate::cache::validate_disk_dir(&self.log_list.cache_dir)?;
        }
      }
      DownstreamCtLogListMode::StaticFile => {
        if self.log_list.file.is_none() || self.log_list.signature_file.is_none() {
          bail!("tls.ct.log_list.file and signature_file are required when mode = \"static_file\"");
        }
      }
    }
    Ok(())
  }

  pub fn effective_mode(&self, certificate: &DownstreamCtCertificateConfig) -> DownstreamCtMode {
    certificate.mode.unwrap_or(self.mode)
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DownstreamCtMode {
  #[default]
  Disabled,
  Audit,
  Enforce,
}

impl DownstreamCtMode {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Disabled => "disabled",
      Self::Audit => "audit",
      Self::Enforce => "enforce",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DownstreamCtPolicy {
  #[default]
  Chrome,
  Firefox,
}

impl DownstreamCtPolicy {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Chrome => "chrome",
      Self::Firefox => "firefox",
    }
  }

  pub const fn revision(self) -> &'static str {
    match self {
      Self::Chrome => "chrome-v1",
      Self::Firefox => "firefox-v1",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DownstreamCtFailurePolicy {
  #[default]
  RejectHandshake,
}

impl DownstreamCtFailurePolicy {
  pub const fn as_str(self) -> &'static str {
    "reject_handshake"
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct DownstreamCtCertificateConfig {
  #[serde(default)]
  pub mode: Option<DownstreamCtMode>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DownstreamCtLogListConfig {
  #[serde(default)]
  pub mode: DownstreamCtLogListMode,
  #[serde(default = "default_cache_dir")]
  pub cache_dir: PathBuf,
  #[serde(default = "default_max_download_bytes")]
  pub max_download_bytes: usize,
  #[serde(default = "default_request_timeout_ms")]
  pub request_timeout_ms: u64,
  #[serde(default = "default_refresh_interval_seconds")]
  pub refresh_interval_seconds: u64,
  #[serde(default)]
  pub file: Option<PathBuf>,
  #[serde(default)]
  pub signature_file: Option<PathBuf>,
}

impl Default for DownstreamCtLogListConfig {
  fn default() -> Self {
    Self {
      mode: DownstreamCtLogListMode::Managed,
      cache_dir: default_cache_dir(),
      max_download_bytes: default_max_download_bytes(),
      request_timeout_ms: default_request_timeout_ms(),
      refresh_interval_seconds: default_refresh_interval_seconds(),
      file: None,
      signature_file: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DownstreamCtLogListMode {
  #[default]
  Managed,
  StaticFile,
}

impl DownstreamCtLogListMode {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Managed => "managed",
      Self::StaticFile => "static_file",
    }
  }
}

pub const DOWNSTREAM_CT_MODE_WIRE_VALUES: &[&str] = &["disabled", "audit", "enforce"];
pub const DOWNSTREAM_CT_POLICY_WIRE_VALUES: &[&str] = &["chrome", "firefox"];
pub const DOWNSTREAM_CT_FAILURE_POLICY_WIRE_VALUES: &[&str] = &["reject_handshake"];
pub const DOWNSTREAM_CT_LOG_LIST_MODE_WIRE_VALUES: &[&str] = &["managed", "static_file"];

pub(crate) fn resolve_static_files(
  config: &mut DownstreamCtConfig,
  source_paths: &mut ConfigSourcePaths,
  cert_dir: &Path,
) -> anyhow::Result<()> {
  let (file, file_logical) = resolve_static_file(
    config.log_list.file.take(),
    "tls.ct.log_list.file",
    source_paths,
    cert_dir,
  )?;
  config.log_list.file = file;
  source_paths.downstream_tls_ct_log_list_file = file_logical;
  let (signature_file, signature_logical) = resolve_static_file(
    config.log_list.signature_file.take(),
    "tls.ct.log_list.signature_file",
    source_paths,
    cert_dir,
  )?;
  config.log_list.signature_file = signature_file;
  source_paths.downstream_tls_ct_log_list_signature_file = signature_logical;
  Ok(())
}

fn resolve_static_file(
  path: Option<PathBuf>,
  field: &str,
  source_paths: &mut ConfigSourcePaths,
  cert_dir: &Path,
) -> anyhow::Result<(Option<PathBuf>, Option<PathBuf>)> {
  path
    .map(|path| {
      let (resolved, logical) =
        resolve_existing_local_config_file_path_with_logical(field, cert_dir, &path)?;
      source_paths.remember_runtime_file(logical.clone());
      source_paths.remember_downstream_tls_file(logical.clone());
      Ok((resolved, logical))
    })
    .transpose()
    .map(|value| match value {
      Some((resolved, logical)) => (Some(resolved), Some(logical)),
      None => (None, None),
    })
}

fn default_cache_dir() -> PathBuf {
  PathBuf::from("/var/lib/oxibelt/ct-log-list")
}

const fn default_max_download_bytes() -> usize {
  4_194_304
}

const fn default_request_timeout_ms() -> u64 {
  5_000
}

const fn default_refresh_interval_seconds() -> u64 {
  86_400
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn defaults_are_disabled_with_managed_chrome_profile() {
    let config = DownstreamCtConfig::default();
    assert_eq!(config.mode, DownstreamCtMode::Disabled);
    assert_eq!(config.policy, DownstreamCtPolicy::Chrome);
    assert_eq!(config.log_list.mode, DownstreamCtLogListMode::Managed);
    config.validate(false).expect("default CT config");
  }

  #[test]
  fn static_mode_requires_both_authenticated_inputs() {
    let mut config = DownstreamCtConfig::default();
    config.log_list.mode = DownstreamCtLogListMode::StaticFile;
    assert!(config.validate(true).is_err());
    config.log_list.file = Some(PathBuf::from("log_list.json"));
    assert!(config.validate(true).is_err());
    config.log_list.signature_file = Some(PathBuf::from("log_list.sig"));
    config.validate(true).expect("complete static CT config");
  }
}
