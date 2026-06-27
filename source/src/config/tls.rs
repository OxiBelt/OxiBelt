//! TLS configuration validation.
//! Certificate, trust, ECH, OCSP, and resumption settings are checked before rustls builders run.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use base64::Engine;
use serde::{Deserialize, Deserializer};

use super::{
  CrliteConfig, default_true, resolve_existing_local_config_file_path_with_logical,
  validate_admin_server_name, validate_base64_32_byte_env, validate_optional_non_empty,
  validate_tls_server_resumption,
};

mod ocsp;
pub(in crate::config) use ocsp::OCSP_CONFIG_KEYS;
pub use ocsp::*;

#[derive(Debug, Clone, PartialEq)]
pub struct TlsConfig {
  pub server_names: Vec<String>,
  pub cert_chain: PathBuf,
  pub private_key: Option<PathBuf>,
  pub remote_signer: TlsRemoteSignerConfig,
  pub require_sni: bool,
  pub reject_unknown_sni: bool,
  pub certificates: Vec<TlsCertificateConfig>,
  pub min_version: TlsVersion,
  pub max_version: TlsVersion,
  pub key_exchange_groups: Vec<TlsKeyExchangeGroup>,
  pub session_tickets: bool,
  pub session_ticket_rotation_seconds: u64,
  pub resumption: TlsServerResumptionConfig,
  pub client_auth: TlsClientAuthConfig,
  pub ocsp: OcspConfig,
  pub crlite: CrliteConfig,
}

impl<'de> Deserialize<'de> for TlsConfig {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    #[derive(Deserialize)]
    struct RawTlsConfig {
      #[serde(default)]
      server_names: Vec<String>,
      cert_chain: PathBuf,
      #[serde(default)]
      private_key: Option<PathBuf>,
      #[serde(default)]
      remote_signer: TlsRemoteSignerConfig,
      #[serde(default)]
      require_sni: bool,
      #[serde(default)]
      reject_unknown_sni: bool,
      #[serde(default)]
      certificates: Vec<TlsCertificateConfig>,
      #[serde(default = "default_tls_min_version")]
      min_version: TlsVersion,
      #[serde(default = "default_tls_max_version")]
      max_version: TlsVersion,
      #[serde(default = "default_tls_key_exchange_groups")]
      key_exchange_groups: Vec<TlsKeyExchangeGroup>,
      #[serde(default)]
      session_tickets: Option<bool>,
      #[serde(default)]
      session_ticket_rotation_seconds: Option<u64>,
      #[serde(default)]
      resumption: Option<RawTlsServerResumptionConfig>,
      #[serde(default)]
      client_auth: TlsClientAuthConfig,
      #[serde(default)]
      ocsp: OcspConfig,
      #[serde(default)]
      crlite: CrliteConfig,
    }

    let raw = RawTlsConfig::deserialize(deserializer)?;
    let (resumption, session_tickets, session_ticket_rotation_seconds) =
      normalize_server_resumption(
        TlsServerResumptionConfig::default(),
        raw.resumption,
        raw.session_tickets,
        raw.session_ticket_rotation_seconds,
      )
      .map_err(serde::de::Error::custom)?;
    Ok(Self {
      server_names: raw.server_names,
      cert_chain: raw.cert_chain,
      private_key: raw.private_key,
      remote_signer: raw.remote_signer,
      require_sni: raw.require_sni,
      reject_unknown_sni: raw.reject_unknown_sni,
      certificates: raw.certificates,
      min_version: raw.min_version,
      max_version: raw.max_version,
      key_exchange_groups: raw.key_exchange_groups,
      session_tickets,
      session_ticket_rotation_seconds,
      resumption,
      client_auth: raw.client_auth,
      ocsp: raw.ocsp,
      crlite: raw.crlite,
    })
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsCertificateConfig {
  #[serde(default)]
  pub server_names: Vec<String>,
  pub cert_chain: PathBuf,
  #[serde(default)]
  pub private_key: Option<PathBuf>,
  #[serde(default)]
  pub remote_signer_key_id: Option<String>,
  #[serde(default)]
  pub ocsp: OcspConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TlsKeyExchangeGroup {
  X25519MlKem768,
  X25519,
  Secp256r1,
  Secp384r1,
}

impl TlsKeyExchangeGroup {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::X25519MlKem768 => "x25519mlkem768",
      Self::X25519 => "x25519",
      Self::Secp256r1 => "secp256r1",
      Self::Secp384r1 => "secp384r1",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsServerResumptionConfig {
  #[serde(default)]
  pub mode: TlsServerResumptionMode,
  #[serde(default = "default_server_session_cache_size")]
  pub session_cache_size: usize,
  #[serde(default = "default_tls13_ticket_count")]
  pub tls13_ticket_count: usize,
  #[serde(default = "default_session_ticket_rotation_seconds")]
  pub rotation_seconds: u64,
}

impl Default for TlsServerResumptionConfig {
  fn default() -> Self {
    Self {
      mode: TlsServerResumptionMode::Stateful,
      session_cache_size: default_server_session_cache_size(),
      tls13_ticket_count: default_tls13_ticket_count(),
      rotation_seconds: default_session_ticket_rotation_seconds(),
    }
  }
}

impl TlsServerResumptionConfig {
  pub fn off() -> Self {
    Self {
      mode: TlsServerResumptionMode::Off,
      ..Self::default()
    }
  }

  pub fn enabled(&self) -> bool {
    self.mode != TlsServerResumptionMode::Off
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TlsServerResumptionMode {
  Off,
  #[default]
  Stateful,
  Stateless,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RawTlsServerResumptionConfig {
  #[serde(default)]
  pub mode: Option<TlsServerResumptionMode>,
  #[serde(default)]
  pub session_cache_size: Option<usize>,
  #[serde(default)]
  pub tls13_ticket_count: Option<usize>,
  #[serde(default)]
  pub rotation_seconds: Option<u64>,
}

pub fn normalize_server_resumption(
  mut base: TlsServerResumptionConfig,
  raw_resumption: Option<RawTlsServerResumptionConfig>,
  legacy_session_tickets: Option<bool>,
  legacy_rotation_seconds: Option<u64>,
) -> anyhow::Result<(TlsServerResumptionConfig, bool, u64)> {
  let raw_resumption = raw_resumption.unwrap_or_default();
  if let Some(mode) = raw_resumption.mode {
    base.mode = mode;
  }
  if let Some(session_cache_size) = raw_resumption.session_cache_size {
    base.session_cache_size = session_cache_size;
  }
  if let Some(tls13_ticket_count) = raw_resumption.tls13_ticket_count {
    base.tls13_ticket_count = tls13_ticket_count;
  }
  if let Some(rotation_seconds) = raw_resumption.rotation_seconds {
    base.rotation_seconds = rotation_seconds;
  }

  if let Some(session_tickets) = legacy_session_tickets {
    if !session_tickets
      && raw_resumption
        .mode
        .is_some_and(|mode| mode != TlsServerResumptionMode::Off)
    {
      bail!("session_tickets = false conflicts with resumption.mode");
    }
    if session_tickets && raw_resumption.mode == Some(TlsServerResumptionMode::Off) {
      bail!("session_tickets = true conflicts with resumption.mode = \"off\"");
    }
    if raw_resumption.mode.is_none() {
      base.mode = if session_tickets {
        TlsServerResumptionMode::Stateful
      } else {
        TlsServerResumptionMode::Off
      };
    }
  }

  if let Some(rotation_seconds) = legacy_rotation_seconds {
    if raw_resumption
      .rotation_seconds
      .is_some_and(|configured| configured != rotation_seconds)
    {
      bail!("session_ticket_rotation_seconds conflicts with resumption.rotation_seconds");
    }
    base.rotation_seconds = rotation_seconds;
  }

  let session_ticket_rotation_seconds = legacy_rotation_seconds.unwrap_or_else(|| {
    if base.rotation_seconds == 0 {
      default_session_ticket_rotation_seconds()
    } else {
      base.rotation_seconds
    }
  });

  Ok((
    base.clone(),
    base.enabled(),
    session_ticket_rotation_seconds,
  ))
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamTlsResumptionConfig {
  #[serde(default)]
  pub mode: UpstreamTlsResumptionMode,
  #[serde(default = "default_upstream_session_cache_size")]
  pub session_cache_size: usize,
  #[serde(default)]
  pub tls12: UpstreamTls12ResumptionMode,
}

impl Default for UpstreamTlsResumptionConfig {
  fn default() -> Self {
    Self {
      mode: UpstreamTlsResumptionMode::Enabled,
      session_cache_size: default_upstream_session_cache_size(),
      tls12: UpstreamTls12ResumptionMode::SessionIdOrTickets,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamTlsResumptionMode {
  #[default]
  Enabled,
  Disabled,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamTls12ResumptionMode {
  Disabled,
  SessionIdOnly,
  #[default]
  SessionIdOrTickets,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdminTlsConfig {
  pub enabled: bool,
  pub min_version: TlsVersion,
  pub max_version: TlsVersion,
  pub session_tickets: bool,
  pub session_ticket_rotation_seconds: u64,
  pub resumption: TlsServerResumptionConfig,
  pub require_sni: bool,
  pub reject_unknown_sni: bool,
  pub certificates: Vec<AdminTlsCertificateConfig>,
  pub client_auth: TlsClientAuthConfig,
}

impl Default for AdminTlsConfig {
  fn default() -> Self {
    let resumption = TlsServerResumptionConfig::off();
    Self {
      enabled: false,
      min_version: TlsVersion::Tls13,
      max_version: TlsVersion::Tls13,
      session_tickets: false,
      session_ticket_rotation_seconds: resumption.rotation_seconds,
      resumption,
      require_sni: true,
      reject_unknown_sni: true,
      certificates: Vec::new(),
      client_auth: TlsClientAuthConfig::default(),
    }
  }
}

impl<'de> Deserialize<'de> for AdminTlsConfig {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    #[derive(Deserialize)]
    struct RawAdminTlsConfig {
      #[serde(default)]
      enabled: bool,
      #[serde(default = "default_tls_min_version")]
      min_version: TlsVersion,
      #[serde(default = "default_tls_max_version")]
      max_version: TlsVersion,
      #[serde(default)]
      session_tickets: Option<bool>,
      #[serde(default)]
      session_ticket_rotation_seconds: Option<u64>,
      #[serde(default)]
      resumption: Option<RawTlsServerResumptionConfig>,
      #[serde(default = "default_true")]
      require_sni: bool,
      #[serde(default = "default_true")]
      reject_unknown_sni: bool,
      #[serde(default)]
      certificates: Vec<AdminTlsCertificateConfig>,
      #[serde(default)]
      client_auth: TlsClientAuthConfig,
    }

    let raw = RawAdminTlsConfig::deserialize(deserializer)?;
    let (resumption, session_tickets, session_ticket_rotation_seconds) =
      normalize_server_resumption(
        TlsServerResumptionConfig::off(),
        raw.resumption,
        raw.session_tickets,
        raw.session_ticket_rotation_seconds,
      )
      .map_err(serde::de::Error::custom)?;
    Ok(Self {
      enabled: raw.enabled,
      min_version: raw.min_version,
      max_version: raw.max_version,
      session_tickets,
      session_ticket_rotation_seconds,
      resumption,
      require_sni: raw.require_sni,
      reject_unknown_sni: raw.reject_unknown_sni,
      certificates: raw.certificates,
      client_auth: raw.client_auth,
    })
  }
}

impl AdminTlsConfig {
  pub(super) fn resolve_relative_paths(&mut self, cert_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut resolved_paths = Vec::new();
    for certificate in &mut self.certificates {
      let (cert_chain, cert_logical) = resolve_existing_local_config_file_path_with_logical(
        "admin.tls.certificates.cert_chain",
        cert_dir,
        &certificate.cert_chain,
      )?;
      certificate.cert_chain = cert_chain;
      resolved_paths.push(cert_logical);
      let (private_key, key_logical) = resolve_existing_local_config_file_path_with_logical(
        "admin.tls.certificates.private_key",
        cert_dir,
        &certificate.private_key,
      )?;
      certificate.private_key = private_key;
      resolved_paths.push(key_logical);
    }
    self.client_auth.ca_certs = self
      .client_auth
      .ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "admin.tls.client_auth.ca_certs",
          cert_dir,
          path,
        )?;
        resolved_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    Ok(resolved_paths)
  }

  pub(super) fn validate(&self) -> anyhow::Result<()> {
    if self.min_version > self.max_version {
      bail!("admin.tls.min_version must be less than or equal to admin.tls.max_version");
    }
    if self.session_ticket_rotation_seconds == 0 {
      bail!("admin.tls.session_ticket_rotation_seconds must be greater than 0");
    }
    validate_tls_server_resumption("admin.tls.resumption", &self.resumption)?;
    self.client_auth.validate("admin.tls.client_auth")?;
    if !self.enabled {
      return Ok(());
    }
    if self.certificates.is_empty() {
      bail!(
        "admin.tls.certificates must include at least one certificate when admin TLS is enabled"
      );
    }
    let defaults = self
      .certificates
      .iter()
      .filter(|certificate| certificate.default)
      .count();
    if self.certificates.len() > 1 && defaults != 1 {
      bail!(
        "exactly one admin.tls.certificates entry must set default = true when multiple certificates are configured"
      );
    }
    let mut names = HashSet::new();
    for certificate in &self.certificates {
      if certificate.server_names.is_empty() {
        bail!("admin.tls.certificates server_names must not be empty");
      }
      for name in &certificate.server_names {
        validate_admin_server_name(name)?;
        if !names.insert(name.to_ascii_lowercase()) {
          bail!("duplicate admin.tls certificate server_name {name}");
        }
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminTlsCertificateConfig {
  #[serde(default)]
  pub server_names: Vec<String>,
  pub cert_chain: PathBuf,
  pub private_key: PathBuf,
  #[serde(default)]
  pub default: bool,
}

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
  pub(super) fn validate(&self, prefix: &str) -> anyhow::Result<()> {
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

impl TlsClientAuthConfig {
  pub(super) fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    if self.mode == TlsClientAuthMode::Off {
      return Ok(());
    }
    if self.ca_certs.is_empty() {
      bail!("{prefix}.ca_certs is required when client_auth mode is not off");
    }
    if self.verify_depth == 0 {
      bail!("{prefix}.verify_depth must be greater than 0 when client_auth mode is not off");
    }
    Ok(())
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

pub(super) fn default_tls_min_version() -> TlsVersion {
  TlsVersion::Tls13
}

pub(super) fn default_tls_max_version() -> TlsVersion {
  TlsVersion::Tls13
}

fn default_tls_key_exchange_groups() -> Vec<TlsKeyExchangeGroup> {
  vec![
    TlsKeyExchangeGroup::X25519MlKem768,
    TlsKeyExchangeGroup::X25519,
    TlsKeyExchangeGroup::Secp256r1,
    TlsKeyExchangeGroup::Secp384r1,
  ]
}

fn default_session_ticket_rotation_seconds() -> u64 {
  86_400
}

fn default_server_session_cache_size() -> usize {
  4_096
}

fn default_upstream_session_cache_size() -> usize {
  1_024
}

fn default_tls13_ticket_count() -> usize {
  2
}

fn default_tls_client_auth_verify_depth() -> u8 {
  4
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
