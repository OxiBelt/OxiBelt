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
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CrliteMode {
  #[default]
  Disabled,
  Enforce,
}

impl CrliteMode {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Disabled => "disabled",
      Self::Enforce => "enforce",
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

pub const CRLITE_MODE_WIRE_VALUES: &[&str] = &["disabled", "enforce"];
pub const CRLITE_FAILURE_POLICY_WIRE_VALUES: &[&str] = &["fail_closed", "degraded_allow"];
pub const CRLITE_COVERAGE_POLICY_WIRE_VALUES: &[&str] = &["allow_unknown", "require_good"];

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
