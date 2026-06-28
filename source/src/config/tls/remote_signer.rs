//! TLS remote signer configuration and validation.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use base64::Engine;
use serde::Deserialize;

use super::super::{validate_base64_32_byte_env, validate_optional_non_empty};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsRemoteSignerConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub socket_path: PathBuf,
  #[serde(default)]
  pub key_id: String,
  #[serde(default = "default_tls_remote_signer_token_env")]
  pub token_env: String,
  #[serde(default)]
  pub token_file: Option<PathBuf>,
  #[serde(skip)]
  pub token_file_reload_path: Option<PathBuf>,
  #[serde(skip)]
  pub token_file_reload_base_dir: Option<PathBuf>,
  #[serde(default = "default_tls_remote_signer_token_reload_interval_ms")]
  pub token_reload_interval_ms: u64,
  #[serde(default = "default_tls_remote_signer_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_tls_remote_signer_sign_timeout_ms")]
  pub sign_timeout_ms: u64,
  #[serde(default = "default_tls_remote_signer_pool_max_idle_connections")]
  pub pool_max_idle_connections: usize,
  #[serde(default)]
  pub allow_tls12_unstructured_signing: bool,
}

impl Default for TlsRemoteSignerConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      socket_path: PathBuf::new(),
      key_id: String::new(),
      token_env: default_tls_remote_signer_token_env(),
      token_file: None,
      token_file_reload_path: None,
      token_file_reload_base_dir: None,
      token_reload_interval_ms: default_tls_remote_signer_token_reload_interval_ms(),
      connect_timeout_ms: default_tls_remote_signer_connect_timeout_ms(),
      sign_timeout_ms: default_tls_remote_signer_sign_timeout_ms(),
      pool_max_idle_connections: default_tls_remote_signer_pool_max_idle_connections(),
      allow_tls12_unstructured_signing: false,
    }
  }
}

impl TlsRemoteSignerConfig {
  pub(in crate::config) fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    if self.socket_path.as_os_str().is_empty() {
      bail!("{prefix}.socket_path must not be empty when enabled = true");
    }
    if !self.socket_path.is_absolute() {
      bail!("{prefix}.socket_path must be an absolute Unix socket path");
    }
    validate_optional_non_empty(&format!("{prefix}.key_id"), Some(&self.key_id))?;
    if let Some(token_file) = &self.token_file {
      if token_file.as_os_str().is_empty() {
        bail!("{prefix}.token_file must not be empty");
      }
      validate_base64_32_byte_file(&format!("{prefix}.token_file"), token_file)?;
    } else {
      validate_base64_32_byte_env(&format!("{prefix}.token_env"), &self.token_env)?;
    }
    if self.token_reload_interval_ms == 0 {
      bail!("{prefix}.token_reload_interval_ms must be greater than 0");
    }
    if self.connect_timeout_ms == 0 {
      bail!("{prefix}.connect_timeout_ms must be greater than 0");
    }
    if self.sign_timeout_ms == 0 {
      bail!("{prefix}.sign_timeout_ms must be greater than 0");
    }
    Ok(())
  }
}

fn default_tls_remote_signer_token_env() -> String {
  "OXIBELT_KEYSIGNER_TOKEN".to_string()
}

fn default_tls_remote_signer_token_reload_interval_ms() -> u64 {
  1000
}

fn validate_base64_32_byte_file(field_name: &str, path: &Path) -> anyhow::Result<()> {
  let raw = std::fs::read_to_string(path)
    .with_context(|| format!("failed to read {field_name} {}", path.display()))?;
  let bytes = base64::engine::general_purpose::STANDARD
    .decode(raw.trim())
    .with_context(|| format!("{field_name} must contain base64"))?;
  if bytes.len() != 32 {
    bail!("{field_name} must contain exactly 32 bytes");
  }
  Ok(())
}

fn default_tls_remote_signer_connect_timeout_ms() -> u64 {
  250
}

fn default_tls_remote_signer_sign_timeout_ms() -> u64 {
  1000
}

fn default_tls_remote_signer_pool_max_idle_connections() -> usize {
  64
}
