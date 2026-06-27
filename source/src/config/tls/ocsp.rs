//! Downstream OCSP staple configuration.
//! Fetch settings are validated before TLS runtimes can contact responders.

use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::Deserialize;
use url::Url;

pub(in crate::config) const OCSP_CONFIG_KEYS: &[&str] = &[
  "clock_skew_seconds",
  "max_response_bytes",
  "mode",
  "refresh_jitter_pct",
  "request_timeout_ms",
  "responder_url",
  "response_file",
];

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OcspConfig {
  #[serde(default)]
  pub mode: OcspMode,
  #[serde(default)]
  pub response_file: Option<PathBuf>,
  #[serde(default)]
  pub responder_url: Option<String>,
  #[serde(default = "default_ocsp_request_timeout_ms")]
  pub request_timeout_ms: u64,
  #[serde(default = "default_ocsp_max_response_bytes")]
  pub max_response_bytes: usize,
  #[serde(default = "default_ocsp_refresh_jitter_pct")]
  pub refresh_jitter_pct: u8,
  #[serde(default = "default_ocsp_clock_skew_seconds")]
  pub clock_skew_seconds: u64,
}

impl Default for OcspConfig {
  fn default() -> Self {
    Self {
      mode: OcspMode::Disabled,
      response_file: None,
      responder_url: None,
      request_timeout_ms: default_ocsp_request_timeout_ms(),
      max_response_bytes: default_ocsp_max_response_bytes(),
      refresh_jitter_pct: default_ocsp_refresh_jitter_pct(),
      clock_skew_seconds: default_ocsp_clock_skew_seconds(),
    }
  }
}

impl OcspConfig {
  pub(in crate::config) fn validate_fetch_settings_with_prefix(
    &self,
    prefix: &str,
  ) -> anyhow::Result<()> {
    if self.request_timeout_ms == 0 {
      bail!("{prefix}.request_timeout_ms must be greater than 0");
    }
    if self.max_response_bytes == 0 {
      bail!("{prefix}.max_response_bytes must be greater than 0");
    }
    if self.refresh_jitter_pct > 100 {
      bail!("{prefix}.refresh_jitter_pct must be between 0 and 100");
    }
    let Some(raw_url) = self.responder_url.as_deref() else {
      return Ok(());
    };
    let url = Url::parse(raw_url).with_context(|| format!("invalid {prefix}.responder_url"))?;
    if !matches!(url.scheme(), "http" | "https") {
      bail!("{prefix}.responder_url scheme must be http or https");
    }
    if url.host_str().is_none() {
      bail!("{prefix}.responder_url must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
      bail!("{prefix}.responder_url must not include credentials");
    }
    if url.fragment().is_some() {
      bail!("{prefix}.responder_url must not include a fragment");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OcspMode {
  #[default]
  Disabled,
  StaticFile,
  LiveFetch,
}

pub const OCSP_MODE_WIRE_VALUES: &[&str] = &["disabled", "static_file", "live_fetch"];

fn default_ocsp_request_timeout_ms() -> u64 {
  3_000
}

fn default_ocsp_max_response_bytes() -> usize {
  16_384
}

fn default_ocsp_refresh_jitter_pct() -> u8 {
  10
}

fn default_ocsp_clock_skew_seconds() -> u64 {
  300
}
