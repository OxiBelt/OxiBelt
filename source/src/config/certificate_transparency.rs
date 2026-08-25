//! Configuration contract for certificate-transparency log identities and storage.
//!
//! The data-plane implementation is intentionally separate from this module.  This
//! module owns only the epoch-1 shape and the fail-closed configuration checks that
//! must hold before a future CT implementation can consume the configuration.

use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::Deserialize;
use url::Url;

use super::{validate_relative_path, validate_runtime_identifier};

pub(crate) const CERTIFICATE_TRANSPARENCY_CONFIG_KEYS: &[&str] = &["enabled", "logs", "profile"];
pub(crate) const CERTIFICATE_TRANSPARENCY_LOG_CONFIG_KEYS: &[&str] = &[
  "admission",
  "gateway",
  "identity",
  "mmd_seconds",
  "name",
  "protocol",
  "publication",
  "role",
  "shard",
  "signer",
  "signed_root",
  "storage",
];
pub(crate) const CERTIFICATE_TRANSPARENCY_IDENTITY_CONFIG_KEYS: &[&str] =
  &["algorithm", "oid", "public_key_file"];
pub(crate) const CERTIFICATE_TRANSPARENCY_SIGNER_CONFIG_KEYS: &[&str] = &[
  "io_timeout_ms",
  "key_id",
  "socket_path",
  "token_env",
  "token_file",
];
pub(crate) const CERTIFICATE_TRANSPARENCY_STORAGE_CONFIG_KEYS: &[&str] = &[
  "delete_denial_attestation_file",
  "object_lock_enabled",
  "object_source_url",
  "posix_path",
  "postgres_url_env",
  "postgres_url_file",
  "retention_seconds",
  "s3_access_key_env",
  "s3_bucket",
  "s3_endpoint",
  "s3_prefix",
  "s3_region",
  "s3_secret_key_env",
  "s3_session_token_env",
  "s3_virtual_hosted_style",
];
pub(crate) const CERTIFICATE_TRANSPARENCY_SHARD_CONFIG_KEYS: &[&str] = &["end_ms", "start_ms"];
pub(crate) const CERTIFICATE_TRANSPARENCY_SIGNED_ROOT_CONFIG_KEYS: &[&str] = &[
  "bundle_path",
  "bundle_sha256",
  "quorum",
  "trusted_ed25519_keys",
];
pub(crate) const CERTIFICATE_TRANSPARENCY_PUBLICATION_CONFIG_KEYS: &[&str] = &[
  "max_chain_bytes",
  "max_pending_entries",
  "max_pre_chain_bytes",
];
pub(crate) const CERTIFICATE_TRANSPARENCY_GATEWAY_CONFIG_KEYS: &[&str] = &[
  "cache_max_bytes",
  "cache_max_entries",
  "max_entries",
  "max_proof_bytes",
  "max_request_bytes",
  "max_response_bytes",
  "origin_url",
  "static_origin_url",
];
pub(crate) const CERTIFICATE_TRANSPARENCY_ADMISSION_CONFIG_KEYS: &[&str] = &[
  "allow_precert_signing_ca",
  "check_eku",
  "check_revocation",
  "reject_expired",
];

const MAX_LOGS: usize = 64;
const MAX_TRUSTED_ROOT_KEYS: usize = 64;
const MAX_MMD_SECONDS: u64 = 86_400;
const MAX_PUBLICATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_PUBLICATION_ENTRIES: usize = 1_000_000;
const MAX_GATEWAY_ENTRIES: usize = 100_000;
const MAX_GATEWAY_BYTES: usize = 64 * 1024 * 1024;
const MAX_RETENTION_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencyConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub logs: Vec<CertificateTransparencyLogConfig>,
  #[serde(default)]
  pub profile: CertificateTransparencyProfile,
}

impl CertificateTransparencyConfig {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    if self.logs.len() > MAX_LOGS {
      bail!("certificate_transparency.logs supports at most {MAX_LOGS} log definitions");
    }

    let mut names = std::collections::HashSet::new();
    let writable_operator_logs = self
      .logs
      .iter()
      .filter(|log| log.role == CertificateTransparencyLogRole::Operator)
      .count();
    if writable_operator_logs > 1 {
      bail!("certificate_transparency allows at most one writable operator log per process");
    }

    for (index, log) in self.logs.iter().enumerate() {
      let prefix = format!("certificate_transparency.logs[{index}]");
      log.validate(&prefix, self.profile)?;
      if !names.insert(log.name.as_str()) {
        bail!("duplicate certificate transparency log name {}", log.name);
      }
    }

    if !self.enabled {
      return Ok(());
    }
    if self.logs.is_empty() {
      bail!("certificate_transparency.enabled requires at least one log definition");
    }
    Ok(())
  }

  pub(crate) fn log(&self, name: &str) -> Option<&CertificateTransparencyLogConfig> {
    self.logs.iter().find(|log| log.name == name)
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateTransparencyProfile {
  #[default]
  Local,
  Production,
}

impl CertificateTransparencyProfile {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Local => "local",
      Self::Production => "production",
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencyLogConfig {
  pub name: String,
  #[serde(default)]
  pub role: CertificateTransparencyLogRole,
  #[serde(default)]
  pub protocol: CertificateTransparencyProtocol,
  #[serde(default = "default_mmd_seconds")]
  pub mmd_seconds: u64,
  #[serde(default)]
  pub identity: CertificateTransparencyIdentityConfig,
  #[serde(default)]
  pub signer: CertificateTransparencySignerConfig,
  #[serde(default)]
  pub storage: CertificateTransparencyStorageConfig,
  #[serde(default)]
  pub shard: CertificateTransparencyShardConfig,
  #[serde(default)]
  pub signed_root: CertificateTransparencySignedRootConfig,
  #[serde(default)]
  pub publication: CertificateTransparencyPublicationConfig,
  #[serde(default)]
  pub gateway: CertificateTransparencyGatewayConfig,
  #[serde(default)]
  pub admission: CertificateTransparencyAdmissionConfig,
}

impl CertificateTransparencyLogConfig {
  fn validate(&self, prefix: &str, profile: CertificateTransparencyProfile) -> anyhow::Result<()> {
    validate_runtime_identifier(&format!("{prefix}.name"), &self.name)?;
    if self.mmd_seconds == 0 || self.mmd_seconds > MAX_MMD_SECONDS {
      bail!("{prefix}.mmd_seconds must be between 1 and {MAX_MMD_SECONDS}");
    }
    self.identity.validate(prefix, self.protocol)?;
    self.signer.validate(prefix, self.role)?;
    self.storage.validate(prefix, profile, self.role)?;
    self.shard.validate(prefix)?;
    self.signed_root.validate(prefix, profile)?;
    self.publication.validate(prefix)?;
    self.gateway.validate(prefix, self.role)?;
    self.admission.validate(prefix, profile)?;

    if self.role == CertificateTransparencyLogRole::RetiredReadOnly && self.signer.is_configured() {
      bail!("{prefix}.signer is not allowed for retired_read_only logs");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateTransparencyLogRole {
  #[default]
  RetiredReadOnly,
  Operator,
  Gateway,
}

impl CertificateTransparencyLogRole {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Operator => "operator",
      Self::Gateway => "gateway",
      Self::RetiredReadOnly => "retired_read_only",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateTransparencyProtocol {
  #[default]
  StaticRfc6962V1,
  Rfc9162V2,
}

impl CertificateTransparencyProtocol {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::StaticRfc6962V1 => "static_rfc6962_v1",
      Self::Rfc9162V2 => "rfc9162_v2",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateTransparencyIdentityAlgorithm {
  #[default]
  P256,
  Ed25519,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencyIdentityConfig {
  #[serde(default)]
  pub algorithm: CertificateTransparencyIdentityAlgorithm,
  #[serde(default)]
  pub oid: Option<String>,
  #[serde(default)]
  pub public_key_file: Option<PathBuf>,
}

impl CertificateTransparencyIdentityConfig {
  fn validate(
    &self,
    prefix: &str,
    protocol: CertificateTransparencyProtocol,
  ) -> anyhow::Result<()> {
    if self.public_key_file.is_none() {
      bail!("{prefix}.identity.public_key_file is required");
    }
    if protocol == CertificateTransparencyProtocol::StaticRfc6962V1
      && self.algorithm != CertificateTransparencyIdentityAlgorithm::P256
    {
      bail!("{prefix}.identity.algorithm must be \"p256\" for static_rfc6962_v1");
    }
    if protocol == CertificateTransparencyProtocol::Rfc9162V2 {
      let oid = self
        .oid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("{prefix}.identity.oid is required for rfc9162_v2"))?;
      validate_oid(&format!("{prefix}.identity.oid"), oid)?;
    }
    if let Some(path) = &self.public_key_file {
      validate_config_path(&format!("{prefix}.identity.public_key_file"), path)?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencySignerConfig {
  #[serde(default)]
  pub socket_path: Option<PathBuf>,
  #[serde(default)]
  pub key_id: Option<String>,
  #[serde(default)]
  pub token_env: Option<String>,
  #[serde(default)]
  pub token_file: Option<PathBuf>,
  #[serde(default = "default_signer_io_timeout_ms")]
  pub io_timeout_ms: u64,
}

impl Default for CertificateTransparencySignerConfig {
  fn default() -> Self {
    Self {
      socket_path: None,
      key_id: None,
      token_env: None,
      token_file: None,
      io_timeout_ms: default_signer_io_timeout_ms(),
    }
  }
}

impl CertificateTransparencySignerConfig {
  fn is_configured(&self) -> bool {
    self.socket_path.is_some()
      || self.key_id.is_some()
      || self.token_env.is_some()
      || self.token_file.is_some()
  }

  fn validate(&self, prefix: &str, role: CertificateTransparencyLogRole) -> anyhow::Result<()> {
    let token_sources =
      usize::from(self.token_env.is_some()) + usize::from(self.token_file.is_some());
    if role == CertificateTransparencyLogRole::Operator {
      if self.socket_path.is_none() {
        bail!("{prefix}.signer.socket_path is required for operator logs");
      }
      if self.key_id.as_deref().is_none_or(str::is_empty) {
        bail!("{prefix}.signer.key_id is required for operator logs");
      }
      if token_sources != 1 {
        bail!("{prefix}.signer requires exactly one of token_env or token_file for operator logs");
      }
    } else if self.is_configured() {
      bail!("{prefix}.signer is allowed only for operator logs");
    }

    if !(1..=30_000).contains(&self.io_timeout_ms) {
      bail!("{prefix}.signer.io_timeout_ms must be between 1 and 30000");
    }
    if let Some(path) = &self.socket_path {
      validate_config_path(&format!("{prefix}.signer.socket_path"), path)?;
    }
    if let Some(key_id) = self.key_id.as_deref() {
      validate_runtime_identifier(&format!("{prefix}.signer.key_id"), key_id)?;
    }
    if let Some(env) = self.token_env.as_deref() {
      validate_environment_name(&format!("{prefix}.signer.token_env"), env)?;
    }
    if let Some(path) = &self.token_file {
      validate_config_path(&format!("{prefix}.signer.token_file"), path)?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencyStorageConfig {
  #[serde(default)]
  pub posix_path: Option<PathBuf>,
  #[serde(default)]
  pub postgres_url_env: Option<String>,
  #[serde(default)]
  pub postgres_url_file: Option<PathBuf>,
  #[serde(default)]
  pub s3_bucket: Option<String>,
  #[serde(default)]
  pub s3_region: Option<String>,
  #[serde(default)]
  pub s3_endpoint: Option<String>,
  #[serde(default)]
  pub s3_prefix: Option<String>,
  #[serde(default)]
  pub s3_access_key_env: Option<String>,
  #[serde(default)]
  pub s3_secret_key_env: Option<String>,
  #[serde(default)]
  pub s3_session_token_env: Option<String>,
  #[serde(default = "default_s3_virtual_hosted_style")]
  pub s3_virtual_hosted_style: bool,
  #[serde(default = "default_retention_seconds")]
  pub retention_seconds: u64,
  #[serde(default = "default_object_lock_enabled")]
  pub object_lock_enabled: bool,
  #[serde(default)]
  pub delete_denial_attestation_file: Option<PathBuf>,
  #[serde(default)]
  pub object_source_url: Option<String>,
}

impl Default for CertificateTransparencyStorageConfig {
  fn default() -> Self {
    Self {
      posix_path: None,
      postgres_url_env: None,
      postgres_url_file: None,
      s3_bucket: None,
      s3_region: None,
      s3_endpoint: None,
      s3_prefix: None,
      s3_access_key_env: None,
      s3_secret_key_env: None,
      s3_session_token_env: None,
      s3_virtual_hosted_style: default_s3_virtual_hosted_style(),
      retention_seconds: default_retention_seconds(),
      object_lock_enabled: default_object_lock_enabled(),
      delete_denial_attestation_file: None,
      object_source_url: None,
    }
  }
}

impl CertificateTransparencyStorageConfig {
  fn validate(
    &self,
    prefix: &str,
    profile: CertificateTransparencyProfile,
    role: CertificateTransparencyLogRole,
  ) -> anyhow::Result<()> {
    if let Some(path) = &self.posix_path {
      if !path.is_absolute() {
        bail!("{prefix}.storage.posix_path must be absolute for local POSIX storage");
      }
      validate_config_path(&format!("{prefix}.storage.posix_path"), path)?;
    }
    if let Some(env) = self.postgres_url_env.as_deref() {
      validate_environment_name(&format!("{prefix}.storage.postgres_url_env"), env)?;
    }
    if let Some(path) = &self.postgres_url_file {
      validate_config_path(&format!("{prefix}.storage.postgres_url_file"), path)?;
    }
    if let Some(env) = self.s3_access_key_env.as_deref() {
      validate_environment_name(&format!("{prefix}.storage.s3_access_key_env"), env)?;
    }
    if let Some(env) = self.s3_secret_key_env.as_deref() {
      validate_environment_name(&format!("{prefix}.storage.s3_secret_key_env"), env)?;
    }
    if let Some(env) = self.s3_session_token_env.as_deref() {
      validate_environment_name(&format!("{prefix}.storage.s3_session_token_env"), env)?;
    }
    if let Some(endpoint) = self.s3_endpoint.as_deref() {
      validate_pinned_https_url(&format!("{prefix}.storage.s3_endpoint"), endpoint)?;
    }
    if let Some(source) = self.object_source_url.as_deref() {
      validate_pinned_https_url(&format!("{prefix}.storage.object_source_url"), source)?;
    }
    if let Some(path) = &self.delete_denial_attestation_file {
      validate_config_path(
        &format!("{prefix}.storage.delete_denial_attestation_file"),
        path,
      )?;
    }
    if self.retention_seconds == 0 || self.retention_seconds > MAX_RETENTION_SECONDS {
      bail!("{prefix}.storage.retention_seconds must be between 1 and {MAX_RETENTION_SECONDS}");
    }
    if let Some(bucket) = self.s3_bucket.as_deref() {
      validate_s3_bucket(&format!("{prefix}.storage.s3_bucket"), bucket)?;
    }
    if let Some(region) = self.s3_region.as_deref()
      && (region.is_empty()
        || !region
          .bytes()
          .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    {
      bail!("{prefix}.storage.s3_region must be a lowercase AWS region identifier");
    }
    if let Some(prefix_value) = self.s3_prefix.as_deref()
      && (prefix_value.is_empty()
        || prefix_value.starts_with('/')
        || prefix_value
          .split('/')
          .any(|part| part.is_empty() || part == "." || part == ".."))
    {
      bail!("{prefix}.storage.s3_prefix must be a safe non-absolute object prefix");
    }

    let postgres_sources =
      usize::from(self.postgres_url_env.is_some()) + usize::from(self.postgres_url_file.is_some());
    let s3_configured = self.s3_bucket.is_some()
      || self.s3_region.is_some()
      || self.s3_endpoint.is_some()
      || self.s3_prefix.is_some()
      || self.s3_access_key_env.is_some()
      || self.s3_secret_key_env.is_some()
      || self.s3_session_token_env.is_some()
      || self.delete_denial_attestation_file.is_some()
      || self.object_lock_enabled != default_object_lock_enabled()
      || self.retention_seconds != default_retention_seconds()
      || self.s3_virtual_hosted_style != default_s3_virtual_hosted_style();
    match role {
      CertificateTransparencyLogRole::Operator => match profile {
        CertificateTransparencyProfile::Local => {
          if self.posix_path.is_none() || postgres_sources > 0 || s3_configured {
            bail!("{prefix}.storage must use only posix_path for a local operator log");
          }
        }
        CertificateTransparencyProfile::Production => {
          if self.posix_path.is_some() || postgres_sources != 1 {
            bail!(
              "{prefix}.storage production operator logs require exactly one postgres_url_env or postgres_url_file and forbid posix_path"
            );
          }
          if !self.production_s3_is_complete() {
            bail!(
              "{prefix}.storage production operator logs require HTTPS S3 bucket, region, endpoint, prefix, access, secret, and session-token environment references, virtual-hosted style, object lock, retention, and delete-denial attestation"
            );
          }
        }
      },
      CertificateTransparencyLogRole::Gateway => {
        if self.posix_path.is_some() || postgres_sources > 0 || s3_configured {
          bail!("{prefix}.storage gateway logs cannot configure PostgreSQL or S3 storage");
        }
        if self.object_source_url.is_some() {
          bail!("{prefix}.storage.object_source_url is only allowed for retired_read_only logs");
        }
      }
      CertificateTransparencyLogRole::RetiredReadOnly => {
        if self.posix_path.is_some() || postgres_sources > 0 || s3_configured {
          bail!("{prefix}.storage retired_read_only logs require only an immutable object source");
        }
        if self.object_source_url.is_none() {
          bail!("{prefix}.storage.object_source_url is required for retired_read_only logs");
        }
      }
    }
    Ok(())
  }

  fn production_s3_is_complete(&self) -> bool {
    self.s3_bucket.is_some()
      && self.s3_region.is_some()
      && self.s3_endpoint.is_some()
      && self.s3_prefix.is_some()
      && self.s3_access_key_env.is_some()
      && self.s3_secret_key_env.is_some()
      && self.s3_session_token_env.is_some()
      && self.s3_virtual_hosted_style
      && self.object_lock_enabled
      && self.retention_seconds > 0
      && self.delete_denial_attestation_file.is_some()
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencyShardConfig {
  #[serde(default)]
  pub start_ms: u64,
  #[serde(default = "default_shard_end_ms")]
  pub end_ms: u64,
}

impl Default for CertificateTransparencyShardConfig {
  fn default() -> Self {
    Self {
      start_ms: 0,
      end_ms: default_shard_end_ms(),
    }
  }
}

impl CertificateTransparencyShardConfig {
  fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    if self.start_ms >= self.end_ms {
      bail!(
        "{prefix}.shard must define a non-empty Unix-millisecond half-open range [start_ms, end_ms)"
      );
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencySignedRootConfig {
  #[serde(default)]
  pub bundle_path: Option<PathBuf>,
  #[serde(default)]
  pub bundle_sha256: Option<String>,
  #[serde(default = "default_signed_root_quorum")]
  pub quorum: usize,
  #[serde(default)]
  pub trusted_ed25519_keys: Vec<PathBuf>,
}

impl Default for CertificateTransparencySignedRootConfig {
  fn default() -> Self {
    Self {
      bundle_path: None,
      bundle_sha256: None,
      quorum: default_signed_root_quorum(),
      trusted_ed25519_keys: Vec::new(),
    }
  }
}

impl CertificateTransparencySignedRootConfig {
  fn validate(&self, prefix: &str, profile: CertificateTransparencyProfile) -> anyhow::Result<()> {
    let path = self
      .bundle_path
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("{prefix}.signed_root.bundle_path is required"))?;
    validate_config_path(&format!("{prefix}.signed_root.bundle_path"), path)?;
    let digest = self
      .bundle_sha256
      .as_deref()
      .ok_or_else(|| anyhow::anyhow!("{prefix}.signed_root.bundle_sha256 is required"))?;
    let Some(hex_digest) = digest.strip_prefix("sha256:") else {
      bail!(
        "{prefix}.signed_root.bundle_sha256 must use the canonical sha256:<64 lowercase hex> form"
      );
    };
    if hex_digest.len() != 64
      || !hex_digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
      bail!(
        "{prefix}.signed_root.bundle_sha256 must use the canonical sha256:<64 lowercase hex> form"
      );
    }
    if self.trusted_ed25519_keys.is_empty() {
      bail!("{prefix}.signed_root.trusted_ed25519_keys must contain at least one key");
    }
    if self.trusted_ed25519_keys.len() > MAX_TRUSTED_ROOT_KEYS {
      bail!(
        "{prefix}.signed_root.trusted_ed25519_keys supports at most {MAX_TRUSTED_ROOT_KEYS} keys"
      );
    }
    if self.quorum == 0 || self.quorum > self.trusted_ed25519_keys.len() {
      bail!("{prefix}.signed_root.quorum must be between 1 and the number of trusted Ed25519 keys");
    }
    if profile == CertificateTransparencyProfile::Production && self.quorum < 2 {
      bail!("{prefix}.signed_root.quorum must be at least 2 for the production profile");
    }
    for (index, key) in self.trusted_ed25519_keys.iter().enumerate() {
      validate_config_path(
        &format!("{prefix}.signed_root.trusted_ed25519_keys[{index}]"),
        key,
      )?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencyPublicationConfig {
  #[serde(default = "default_max_chain_bytes")]
  pub max_chain_bytes: usize,
  #[serde(default = "default_max_pre_chain_bytes")]
  pub max_pre_chain_bytes: usize,
  #[serde(default = "default_max_pending_entries")]
  pub max_pending_entries: usize,
}

impl Default for CertificateTransparencyPublicationConfig {
  fn default() -> Self {
    Self {
      max_chain_bytes: default_max_chain_bytes(),
      max_pre_chain_bytes: default_max_pre_chain_bytes(),
      max_pending_entries: default_max_pending_entries(),
    }
  }
}

impl CertificateTransparencyPublicationConfig {
  fn validate(&self, prefix: &str) -> anyhow::Result<()> {
    validate_positive_bounded(
      &format!("{prefix}.publication.max_chain_bytes"),
      self.max_chain_bytes,
      MAX_PUBLICATION_BYTES,
    )?;
    validate_positive_bounded(
      &format!("{prefix}.publication.max_pre_chain_bytes"),
      self.max_pre_chain_bytes,
      MAX_PUBLICATION_BYTES,
    )?;
    validate_positive_bounded(
      &format!("{prefix}.publication.max_pending_entries"),
      self.max_pending_entries,
      MAX_PUBLICATION_ENTRIES,
    )?;
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencyGatewayConfig {
  #[serde(default)]
  pub origin_url: Option<String>,
  #[serde(default)]
  pub static_origin_url: Option<String>,
  #[serde(default = "default_gateway_cache_max_bytes")]
  pub cache_max_bytes: usize,
  #[serde(default = "default_gateway_cache_max_entries")]
  pub cache_max_entries: usize,
  #[serde(default = "default_max_gateway_entries")]
  pub max_entries: usize,
  #[serde(default = "default_max_gateway_proof_bytes")]
  pub max_proof_bytes: usize,
  #[serde(default = "default_max_gateway_request_bytes")]
  pub max_request_bytes: usize,
  #[serde(default = "default_max_gateway_response_bytes")]
  pub max_response_bytes: usize,
}

impl Default for CertificateTransparencyGatewayConfig {
  fn default() -> Self {
    Self {
      origin_url: None,
      static_origin_url: None,
      cache_max_bytes: default_gateway_cache_max_bytes(),
      cache_max_entries: default_gateway_cache_max_entries(),
      max_entries: default_max_gateway_entries(),
      max_proof_bytes: default_max_gateway_proof_bytes(),
      max_request_bytes: default_max_gateway_request_bytes(),
      max_response_bytes: default_max_gateway_response_bytes(),
    }
  }
}

impl CertificateTransparencyGatewayConfig {
  fn validate(&self, prefix: &str, role: CertificateTransparencyLogRole) -> anyhow::Result<()> {
    if let Some(origin) = self.origin_url.as_deref() {
      validate_pinned_https_url(&format!("{prefix}.gateway.origin_url"), origin)?;
    }
    if let Some(static_origin) = self.static_origin_url.as_deref() {
      validate_pinned_https_url(
        &format!("{prefix}.gateway.static_origin_url"),
        static_origin,
      )?;
    }
    if role == CertificateTransparencyLogRole::Gateway {
      let origin = self.origin_url.as_deref().ok_or_else(|| {
        anyhow::anyhow!("{prefix}.gateway.origin_url is required for gateway logs")
      })?;
      if self.static_origin_url.as_deref() == Some(origin) {
        bail!("{prefix}.gateway.static_origin_url must differ from origin_url");
      }
    } else if self.origin_url.is_some() || self.static_origin_url.is_some() {
      bail!("{prefix}.gateway origin URLs are allowed only for gateway logs");
    }
    validate_positive_bounded(
      &format!("{prefix}.gateway.cache_max_bytes"),
      self.cache_max_bytes,
      MAX_GATEWAY_BYTES,
    )?;
    validate_positive_bounded(
      &format!("{prefix}.gateway.cache_max_entries"),
      self.cache_max_entries,
      MAX_GATEWAY_ENTRIES,
    )?;
    validate_positive_bounded(
      &format!("{prefix}.gateway.max_entries"),
      self.max_entries,
      MAX_GATEWAY_ENTRIES,
    )?;
    validate_positive_bounded(
      &format!("{prefix}.gateway.max_proof_bytes"),
      self.max_proof_bytes,
      MAX_GATEWAY_BYTES,
    )?;
    validate_positive_bounded(
      &format!("{prefix}.gateway.max_request_bytes"),
      self.max_request_bytes,
      MAX_GATEWAY_BYTES,
    )?;
    validate_positive_bounded(
      &format!("{prefix}.gateway.max_response_bytes"),
      self.max_response_bytes,
      MAX_GATEWAY_BYTES,
    )?;
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateTransparencyAdmissionConfig {
  #[serde(default = "default_reject_expired")]
  pub reject_expired: bool,
  #[serde(default)]
  pub check_revocation: bool,
  #[serde(default)]
  pub check_eku: bool,
  #[serde(default)]
  pub allow_precert_signing_ca: bool,
}

impl Default for CertificateTransparencyAdmissionConfig {
  fn default() -> Self {
    Self {
      reject_expired: default_reject_expired(),
      check_revocation: false,
      check_eku: false,
      allow_precert_signing_ca: false,
    }
  }
}

impl CertificateTransparencyAdmissionConfig {
  fn validate(&self, prefix: &str, _profile: CertificateTransparencyProfile) -> anyhow::Result<()> {
    if self.allow_precert_signing_ca {
      bail!(
        "{prefix}.admission.allow_precert_signing_ca is unsupported because this log rejects RFC 6962 Precertificate Signing Certificates"
      );
    }
    if self.check_revocation {
      bail!(
        "{prefix}.admission.check_revocation is unsupported until a fail-closed revocation source is configured"
      );
    }
    Ok(())
  }
}

fn validate_positive_bounded(field: &str, value: usize, maximum: usize) -> anyhow::Result<()> {
  if value == 0 || value > maximum {
    bail!("{field} must be between 1 and {maximum}");
  }
  Ok(())
}

fn validate_config_path(field: &str, path: &std::path::Path) -> anyhow::Result<()> {
  if path.as_os_str().is_empty() {
    bail!("{field} must not be empty");
  }
  if !path.is_absolute() {
    validate_relative_path(field, path)
      .with_context(|| format!("{field} must be absolute or a safe relative path"))?;
  }
  Ok(())
}

fn validate_environment_name(field: &str, value: &str) -> anyhow::Result<()> {
  let mut bytes = value.bytes();
  let Some(first) = bytes.next() else {
    bail!("{field} must not be empty");
  };
  if !(first.is_ascii_alphabetic() || first == b'_')
    || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
  {
    bail!("{field} must be a shell-safe environment variable name");
  }
  Ok(())
}

fn validate_oid(field: &str, value: &str) -> anyhow::Result<()> {
  let components = value.split('.').collect::<Vec<_>>();
  if components.len() < 2
    || components.iter().any(|component| {
      component.is_empty()
        || (component.len() > 1 && component.starts_with('0'))
        || !component.bytes().all(|byte| byte.is_ascii_digit())
    })
  {
    bail!("{field} must be a dotted-decimal object identifier");
  }
  let arcs = components
    .iter()
    .map(|component| component.parse::<u64>())
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("{field} contains an out-of-range object identifier arc"))?;
  if arcs[0] > 2
    || (arcs[0] < 2 && arcs[1] > 39)
    || arcs[0]
      .checked_mul(40)
      .and_then(|value| value.checked_add(arcs[1]))
      .is_none()
  {
    bail!("{field} contains invalid object identifier arcs");
  }
  Ok(())
}

fn validate_pinned_https_url(field: &str, value: &str) -> anyhow::Result<()> {
  let url = Url::parse(value).with_context(|| format!("{field} must be a valid URL"))?;
  if url.scheme() != "https" || url.host_str().is_none() {
    bail!("{field} must be an HTTPS URL with a host");
  }
  if !url.username().is_empty()
    || url.password().is_some()
    || url.query().is_some()
    || url.fragment().is_some()
  {
    bail!("{field} must not contain credentials, a query, or a fragment");
  }
  Ok(())
}

fn validate_s3_bucket(field: &str, value: &str) -> anyhow::Result<()> {
  if !(3..=63).contains(&value.len())
    || value.starts_with('-')
    || value.ends_with('-')
    || !value.bytes().all(|byte| {
      byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
    })
  {
    bail!("{field} must be a lowercase DNS-compatible S3 bucket name");
  }
  Ok(())
}

fn default_mmd_seconds() -> u64 {
  60
}

fn default_shard_end_ms() -> u64 {
  u64::MAX
}

fn default_signer_io_timeout_ms() -> u64 {
  1_000
}

fn default_s3_virtual_hosted_style() -> bool {
  true
}

fn default_retention_seconds() -> u64 {
  7 * 24 * 60 * 60
}

fn default_object_lock_enabled() -> bool {
  true
}

fn default_signed_root_quorum() -> usize {
  1
}

fn default_max_chain_bytes() -> usize {
  1024 * 1024
}

fn default_max_pre_chain_bytes() -> usize {
  1024 * 1024
}

fn default_max_pending_entries() -> usize {
  1_024
}

fn default_max_gateway_entries() -> usize {
  1_024
}

fn default_max_gateway_proof_bytes() -> usize {
  1024 * 1024
}

fn default_max_gateway_request_bytes() -> usize {
  1024 * 1024
}

fn default_max_gateway_response_bytes() -> usize {
  8 * 1024 * 1024
}

fn default_gateway_cache_max_bytes() -> usize {
  64 * 1024 * 1024
}

fn default_gateway_cache_max_entries() -> usize {
  10_000
}

fn default_reject_expired() -> bool {
  true
}

pub const CERTIFICATE_TRANSPARENCY_PROFILE_WIRE_VALUES: &[&str] = &["local", "production"];
pub const CERTIFICATE_TRANSPARENCY_LOG_ROLE_WIRE_VALUES: &[&str] =
  &["operator", "gateway", "retired_read_only"];
pub const CERTIFICATE_TRANSPARENCY_PROTOCOL_WIRE_VALUES: &[&str] =
  &["static_rfc6962_v1", "rfc9162_v2"];
pub const CERTIFICATE_TRANSPARENCY_IDENTITY_ALGORITHM_WIRE_VALUES: &[&str] = &["p256", "ed25519"];

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn oid_validation_rejects_aliases_and_overflow() {
    assert!(validate_oid("oid", "1.2.840.113549").is_ok());
    for oid in [
      "1.02.840",
      "1.40.1",
      "3.1.1",
      "2.18446744073709551615.1",
      "2.18446744073709551616.1",
    ] {
      assert!(validate_oid("oid", oid).is_err(), "accepted {oid}");
    }
  }

  #[test]
  fn pinned_https_urls_reject_query_credentials() {
    assert!(validate_pinned_https_url("origin", "https://ct.example.test/base").is_ok());
    assert!(
      validate_pinned_https_url("origin", "https://ct.example.test/base?token=secret").is_err()
    );
  }
}
