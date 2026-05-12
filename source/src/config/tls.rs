use std::path::PathBuf;

use anyhow::bail;
use serde::Deserialize;

use super::{default_true, validate_base64_32_byte_env, validate_optional_non_empty};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsConfig {
  pub cert_chain: PathBuf,
  #[serde(default)]
  pub private_key: Option<PathBuf>,
  #[serde(default)]
  pub remote_signer: TlsRemoteSignerConfig,
  #[serde(default = "default_tls_min_version")]
  pub min_version: TlsVersion,
  #[serde(default = "default_tls_max_version")]
  pub max_version: TlsVersion,
  #[serde(default = "default_true")]
  pub session_tickets: bool,
  #[serde(default = "default_session_ticket_rotation_seconds")]
  pub session_ticket_rotation_seconds: u64,
  #[serde(default)]
  pub client_auth: TlsClientAuthConfig,
  #[serde(default)]
  pub ocsp: OcspConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct TlsRemoteSignerConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub socket_path: PathBuf,
  #[serde(default)]
  pub key_id: String,
  #[serde(default = "default_tls_remote_signer_token_env")]
  pub token_env: String,
  #[serde(default = "default_tls_remote_signer_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_tls_remote_signer_sign_timeout_ms")]
  pub sign_timeout_ms: u64,
  #[serde(default)]
  pub allow_tls12_unstructured_signing: bool,
}

impl TlsRemoteSignerConfig {
  pub(super) fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    if self.socket_path.as_os_str().is_empty() {
      bail!("{prefix}.socket_path must not be empty when enabled = true");
    }
    if !self.socket_path.is_absolute() {
      bail!("{prefix}.socket_path must be an absolute Unix socket path");
    }
    validate_optional_non_empty(&format!("{prefix}.key_id"), Some(&self.key_id))?;
    validate_base64_32_byte_env(&format!("{prefix}.token_env"), &self.token_env)?;
    if self.connect_timeout_ms == 0 {
      bail!("{prefix}.connect_timeout_ms must be greater than 0");
    }
    if self.sign_timeout_ms == 0 {
      bail!("{prefix}.sign_timeout_ms must be greater than 0");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
  #[serde(rename = "tls1.2")]
  Tls12,
  #[serde(rename = "tls1.3")]
  Tls13,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsClientAuthConfig {
  #[serde(default)]
  pub mode: TlsClientAuthMode,
  #[serde(default)]
  pub ca_certs: Vec<PathBuf>,
  #[serde(default = "default_tls_client_auth_verify_depth")]
  pub verify_depth: u8,
}

impl Default for TlsClientAuthConfig {
  fn default() -> Self {
    Self {
      mode: TlsClientAuthMode::Off,
      ca_certs: Vec::new(),
      verify_depth: default_tls_client_auth_verify_depth(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TlsClientAuthMode {
  #[default]
  Off,
  Optional,
  Require,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OcspConfig {
  #[serde(default)]
  pub mode: OcspMode,
  #[serde(default)]
  pub response_file: Option<PathBuf>,
}

impl Default for OcspConfig {
  fn default() -> Self {
    Self {
      mode: OcspMode::Disabled,
      response_file: None,
    }
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

pub(super) fn default_tls_min_version() -> TlsVersion {
  TlsVersion::Tls13
}

pub(super) fn default_tls_max_version() -> TlsVersion {
  TlsVersion::Tls13
}

fn default_session_ticket_rotation_seconds() -> u64 {
  86_400
}

fn default_tls_client_auth_verify_depth() -> u8 {
  4
}

fn default_tls_remote_signer_token_env() -> String {
  "OXIBELT_KEYSIGNER_TOKEN".to_string()
}

fn default_tls_remote_signer_connect_timeout_ms() -> u64 {
  250
}

fn default_tls_remote_signer_sign_timeout_ms() -> u64 {
  1000
}
