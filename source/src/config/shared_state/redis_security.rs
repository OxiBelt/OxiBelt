//! Redis transport, authentication, and secret-file configuration.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::bail;
use base64::Engine;
use serde::Deserialize;

use super::super::{
  resolve_existing_local_config_file_path_with_logical, validate_optional_non_empty,
};

const MAX_REDIS_SPKI_PINS: usize = 8;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RedisPlaintextPolicy {
  #[default]
  Allow,
  LoopbackOnly,
  Deny,
}

impl RedisPlaintextPolicy {
  pub(crate) fn validate_url_host(&self, host: &str, backend_name: &str) -> anyhow::Result<()> {
    match self {
      Self::Allow => Ok(()),
      Self::Deny => bail!(
        "shared_state Redis backend {backend_name} plaintext redis:// is forbidden by shared_state.redis_plaintext_policy = \"deny\""
      ),
      Self::LoopbackOnly if redis_host_is_literal_loopback(host) => Ok(()),
      Self::LoopbackOnly => bail!(
        "shared_state Redis backend {backend_name} plaintext redis:// must use a literal loopback IP address when shared_state.redis_plaintext_policy = \"loopback_only\""
      ),
    }
  }
}

fn redis_host_is_literal_loopback(host: &str) -> bool {
  host
    .parse::<IpAddr>()
    .is_ok_and(|address| address.is_loopback())
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RedisTrustStore {
  #[default]
  Webpki,
  Native,
  Custom,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RedisTlsConfig {
  #[serde(default)]
  pub trust_store: RedisTrustStore,
  #[serde(default)]
  pub server_name: Option<String>,
  #[serde(default)]
  pub ca_cert: Option<PathBuf>,
  #[serde(default)]
  pub client_cert: Option<PathBuf>,
  #[serde(default)]
  pub client_key: Option<PathBuf>,
  #[serde(default)]
  pub server_spki_sha256: Vec<String>,
}

impl Default for RedisTlsConfig {
  fn default() -> Self {
    Self {
      trust_store: RedisTrustStore::Webpki,
      server_name: None,
      ca_cert: None,
      client_cert: None,
      client_key: None,
      server_spki_sha256: Vec::new(),
    }
  }
}

impl RedisTlsConfig {
  pub(crate) fn is_configured(&self) -> bool {
    self.trust_store != RedisTrustStore::Webpki
      || self.server_name.is_some()
      || self.ca_cert.is_some()
      || self.client_cert.is_some()
      || self.client_key.is_some()
      || !self.server_spki_sha256.is_empty()
  }

  pub(crate) fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    if self.trust_store == RedisTrustStore::Custom && self.ca_cert.is_none() {
      bail!("{prefix}.ca_cert is required when {prefix}.trust_store is \"custom\"");
    }
    if self.trust_store != RedisTrustStore::Custom && self.ca_cert.is_some() {
      bail!("{prefix}.ca_cert is only valid when {prefix}.trust_store is \"custom\"");
    }
    match (&self.client_cert, &self.client_key) {
      (Some(_), Some(_)) | (None, None) => {}
      (Some(_), None) => bail!("{prefix}.client_key is required when client_cert is configured"),
      (None, Some(_)) => bail!("{prefix}.client_cert is required when client_key is configured"),
    }
    if let Some(server_name) = &self.server_name {
      validate_optional_non_empty(&format!("{prefix}.server_name"), Some(server_name))?;
      rustls::pki_types::ServerName::try_from(server_name.clone())
        .map_err(|error| anyhow::anyhow!("{prefix}.server_name is invalid: {error}"))?;
    }
    if self.server_spki_sha256.len() > MAX_REDIS_SPKI_PINS {
      bail!("{prefix}.server_spki_sha256 supports at most {MAX_REDIS_SPKI_PINS} pins");
    }
    let mut pins = std::collections::HashSet::new();
    for pin in &self.server_spki_sha256 {
      let encoded = pin.strip_prefix("sha256/").ok_or_else(|| {
        anyhow::anyhow!("{prefix}.server_spki_sha256 entries must use sha256/<base64>")
      })?;
      let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| {
          anyhow::anyhow!("{prefix}.server_spki_sha256 entries must use valid base64")
        })?;
      if decoded.len() != 32 {
        bail!("{prefix}.server_spki_sha256 entries must decode to 32 bytes");
      }
      if !pins.insert(decoded) {
        bail!("{prefix}.server_spki_sha256 entries must be unique");
      }
    }
    Ok(())
  }

  pub(crate) fn resolve_relative_paths(
    &mut self,
    prefix: &str,
    base_dir: &Path,
  ) -> anyhow::Result<Vec<PathBuf>> {
    let mut source_paths = Vec::new();
    self.ca_cert = resolve_optional_secret_path(
      self.ca_cert.take(),
      &format!("{prefix}.ca_cert"),
      base_dir,
      &mut source_paths,
    )?;
    self.client_cert = resolve_optional_secret_path(
      self.client_cert.take(),
      &format!("{prefix}.client_cert"),
      base_dir,
      &mut source_paths,
    )?;
    self.client_key = resolve_optional_secret_path(
      self.client_key.take(),
      &format!("{prefix}.client_key"),
      base_dir,
      &mut source_paths,
    )?;
    Ok(source_paths)
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RedisAuthConfig {
  #[serde(default)]
  pub username_file: Option<PathBuf>,
  #[serde(default)]
  pub password_file: Option<PathBuf>,
}

impl RedisAuthConfig {
  pub(crate) fn is_configured(&self) -> bool {
    self.username_file.is_some() || self.password_file.is_some()
  }

  pub(crate) fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    if self.username_file.is_some() && self.password_file.is_none() {
      bail!("{prefix}.password_file is required when username_file is configured");
    }
    Ok(())
  }

  pub(crate) fn resolve_relative_paths(
    &mut self,
    prefix: &str,
    base_dir: &Path,
  ) -> anyhow::Result<Vec<PathBuf>> {
    let mut source_paths = Vec::new();
    self.username_file = resolve_optional_secret_path(
      self.username_file.take(),
      &format!("{prefix}.username_file"),
      base_dir,
      &mut source_paths,
    )?;
    self.password_file = resolve_optional_secret_path(
      self.password_file.take(),
      &format!("{prefix}.password_file"),
      base_dir,
      &mut source_paths,
    )?;
    Ok(source_paths)
  }
}

fn resolve_optional_secret_path(
  path: Option<PathBuf>,
  field_name: &str,
  base_dir: &Path,
  source_paths: &mut Vec<PathBuf>,
) -> anyhow::Result<Option<PathBuf>> {
  path
    .map(|path| {
      let (resolved, logical) =
        resolve_existing_local_config_file_path_with_logical(field_name, base_dir, &path)?;
      source_paths.push(logical);
      Ok::<PathBuf, anyhow::Error>(resolved)
    })
    .transpose()
}
