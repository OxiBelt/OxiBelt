use std::path::{Path, PathBuf};

use anyhow::bail;
use serde::Deserialize;

use super::{
  ConfigSourcePaths, CrliteConfig, CrliteFailurePolicy, CrliteManagedConfig, CrliteMode,
  resolve_existing_local_config_file_path_with_logical,
};

pub(crate) const OUTBOUND_REVOCATION_CONFIG_KEYS: &[&str] = &["ocsp", "crlite"];
pub(crate) const OUTBOUND_OCSP_CONFIG_KEYS: &[&str] = &[
  "mode",
  "failure_policy",
  "request_timeout_ms",
  "max_response_bytes",
  "refresh_jitter_pct",
  "clock_skew_seconds",
];

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct OutboundTlsRevocationConfig {
  #[serde(default)]
  pub ocsp: OutboundOcspConfig,
  #[serde(default)]
  pub crlite: CrliteConfig,
}

impl OutboundTlsRevocationConfig {
  pub(crate) fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    self.ocsp.validate(prefix)?;
    self
      .crlite
      .validate_with_prefix(&format!("{prefix}.crlite"))?;
    Ok(())
  }

  pub fn enabled(&self) -> bool {
    self.ocsp.mode != OutboundOcspMode::Disabled || self.crlite.mode != CrliteMode::Disabled
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OutboundOcspConfig {
  #[serde(default)]
  pub mode: OutboundOcspMode,
  #[serde(default)]
  pub failure_policy: CrliteFailurePolicy,
  #[serde(default = "default_outbound_ocsp_request_timeout_ms")]
  pub request_timeout_ms: u64,
  #[serde(default = "default_outbound_ocsp_max_response_bytes")]
  pub max_response_bytes: usize,
  #[serde(default = "default_outbound_ocsp_refresh_jitter_pct")]
  pub refresh_jitter_pct: u8,
  #[serde(default = "default_outbound_ocsp_clock_skew_seconds")]
  pub clock_skew_seconds: u64,
}

impl Default for OutboundOcspConfig {
  fn default() -> Self {
    Self {
      mode: OutboundOcspMode::Disabled,
      failure_policy: CrliteFailurePolicy::FailClosed,
      request_timeout_ms: default_outbound_ocsp_request_timeout_ms(),
      max_response_bytes: default_outbound_ocsp_max_response_bytes(),
      refresh_jitter_pct: default_outbound_ocsp_refresh_jitter_pct(),
      clock_skew_seconds: default_outbound_ocsp_clock_skew_seconds(),
    }
  }
}

impl OutboundOcspConfig {
  fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    if self.request_timeout_ms == 0 {
      bail!("{prefix}.ocsp.request_timeout_ms must be greater than 0");
    }
    if self.max_response_bytes == 0 {
      bail!("{prefix}.ocsp.max_response_bytes must be greater than 0");
    }
    if self.refresh_jitter_pct > 100 {
      bail!("{prefix}.ocsp.refresh_jitter_pct must be between 0 and 100");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundOcspMode {
  #[default]
  Disabled,
  LiveFetch,
}

impl OutboundOcspMode {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Disabled => "disabled",
      Self::LiveFetch => "live_fetch",
    }
  }
}

pub const OUTBOUND_OCSP_MODE_WIRE_VALUES: &[&str] = &["disabled", "live_fetch"];

pub(crate) fn resolve_outbound_crlite_filter_file(
  config: &mut OutboundTlsRevocationConfig,
  source_paths: &mut ConfigSourcePaths,
  cert_dir: &Path,
  prefix: &str,
) -> anyhow::Result<()> {
  config.crlite.filter_file = config
    .crlite
    .filter_file
    .take()
    .map(|path| {
      let (resolved, logical) =
        resolve_existing_local_config_file_path_with_logical(prefix, cert_dir, &path)?;
      source_paths.remember_runtime_file(logical);
      Ok::<PathBuf, anyhow::Error>(resolved)
    })
    .transpose()?;
  Ok(())
}

fn default_outbound_ocsp_request_timeout_ms() -> u64 {
  3_000
}

fn default_outbound_ocsp_max_response_bytes() -> usize {
  16_384
}

fn default_outbound_ocsp_refresh_jitter_pct() -> u8 {
  10
}

fn default_outbound_ocsp_clock_skew_seconds() -> u64 {
  300
}

impl CrliteConfig {
  pub(crate) fn validate_with_prefix(&self, prefix: &str) -> anyhow::Result<()> {
    match self.mode {
      CrliteMode::Disabled => {}
      CrliteMode::Enforce => {
        if self.filter_file.is_none() {
          bail!("{prefix}.filter_file is required when {prefix}.mode = \"enforce\"");
        }
      }
      CrliteMode::Managed => {
        if self.filter_file.is_some() {
          bail!("{prefix}.filter_file cannot be used when {prefix}.mode = \"managed\"");
        }
        if self.filter_sha256.is_some() {
          bail!("{prefix}.filter_sha256 cannot be used when {prefix}.mode = \"managed\"");
        }
      }
    }
    if self.max_filter_bytes == 0 {
      bail!("{prefix}.max_filter_bytes must be greater than 0");
    }
    if self.max_filter_age_seconds == 0 {
      bail!("{prefix}.max_filter_age_seconds must be greater than 0");
    }
    if let Some(expected) = self.filter_sha256.as_deref()
      && (expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
      bail!("{prefix}.filter_sha256 must be a 64-character hex SHA-256 digest");
    }
    if self.mode == CrliteMode::Managed {
      self
        .managed
        .validate_with_prefix(&format!("{prefix}.managed"))?;
    }
    Ok(())
  }
}

impl CrliteManagedConfig {
  pub(crate) fn validate_with_prefix(&self, prefix: &str) -> anyhow::Result<()> {
    if self.max_cache_bytes == 0 {
      bail!("{prefix}.max_cache_bytes must be greater than 0");
    }
    if self.refresh_interval_seconds == 0 {
      bail!("{prefix}.refresh_interval_seconds must be greater than 0");
    }
    if self.request_timeout_ms == 0 {
      bail!("{prefix}.request_timeout_ms must be greater than 0");
    }
    match self.storage {
      super::CrliteManagedStorage::Memory => {}
      super::CrliteManagedStorage::Tmpfs => crate::cache::validate_tmpfs_dir(&self.tmpfs_dir)?,
      super::CrliteManagedStorage::Disk => crate::cache::validate_disk_dir(&self.cache_dir)?,
    }
    Ok(())
  }
}
