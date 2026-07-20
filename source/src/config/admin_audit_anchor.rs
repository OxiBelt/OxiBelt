//! External Admin audit-chain checkpoint anchoring configuration.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

use super::{
  AdminAuditAcknowledgement, AdminAuditStoreKind, Config, SharedStateBackendKind,
  resolve_existing_local_config_file_path_with_logical, validate_base64_32_byte_env,
  validate_optional_non_empty, validate_runtime_identifier,
};

const MIN_RECORD_INTERVAL: u64 = 1;
const MAX_RECORD_INTERVAL: u64 = 1_000_000;
const MIN_TIME_INTERVAL_MS: u64 = 1_000;
const MAX_TIME_INTERVAL_MS: u64 = 3_600_000;
const MIN_PENDING_CHECKPOINTS: usize = 2;
const MAX_PENDING_CHECKPOINTS: usize = 65_536;
const MIN_PENDING_BYTES: u64 = 128 * 1024;
const MAX_PENDING_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ANCHORED_EVENT_BYTES: usize = 64 * 1024 * 1024;
const MIN_SUBMIT_TIMEOUT_MS: u64 = 100;
const MAX_SUBMIT_TIMEOUT_MS: u64 = 60_000;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminAuditAnchorConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_record_interval")]
  pub record_interval: u64,
  #[serde(default = "default_time_interval_ms")]
  pub time_interval_ms: u64,
  #[serde(default = "default_deployment_epoch_env")]
  pub deployment_epoch_env: String,
  #[serde(default = "default_max_pending_checkpoints")]
  pub max_pending_checkpoints: usize,
  #[serde(default = "default_max_pending_bytes")]
  pub max_pending_bytes: u64,
  #[serde(default)]
  pub sink: AdminAuditAnchorSinkConfig,
  #[serde(default)]
  pub signer: AdminAuditAnchorSignerConfig,
}

impl Default for AdminAuditAnchorConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      record_interval: default_record_interval(),
      time_interval_ms: default_time_interval_ms(),
      deployment_epoch_env: default_deployment_epoch_env(),
      max_pending_checkpoints: default_max_pending_checkpoints(),
      max_pending_bytes: default_max_pending_bytes(),
      sink: AdminAuditAnchorSinkConfig::default(),
      signer: AdminAuditAnchorSignerConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditAnchorSinkKind {
  #[default]
  Postgres,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminAuditAnchorSinkConfig {
  #[serde(default)]
  pub kind: AdminAuditAnchorSinkKind,
  #[serde(default)]
  pub backend: String,
  #[serde(default)]
  pub authority_id: String,
  #[serde(default = "default_submit_timeout_ms")]
  pub submit_timeout_ms: u64,
}

impl Default for AdminAuditAnchorSinkConfig {
  fn default() -> Self {
    Self {
      kind: AdminAuditAnchorSinkKind::default(),
      backend: String::new(),
      authority_id: String::new(),
      submit_timeout_ms: default_submit_timeout_ms(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditAnchorSignerKind {
  #[default]
  Keysigner,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminAuditAnchorSignerConfig {
  #[serde(default)]
  pub kind: AdminAuditAnchorSignerKind,
  #[serde(default)]
  pub socket_path: PathBuf,
  #[serde(default)]
  pub key_id: String,
  #[serde(default)]
  pub public_key_file: PathBuf,
  #[serde(default = "default_token_env")]
  pub token_env: String,
  #[serde(default)]
  pub token_file: Option<PathBuf>,
  #[serde(default = "default_token_reload_interval_ms")]
  pub token_reload_interval_ms: u64,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_sign_timeout_ms")]
  pub sign_timeout_ms: u64,
}

impl Default for AdminAuditAnchorSignerConfig {
  fn default() -> Self {
    Self {
      kind: AdminAuditAnchorSignerKind::default(),
      socket_path: PathBuf::new(),
      key_id: String::new(),
      public_key_file: PathBuf::new(),
      token_env: default_token_env(),
      token_file: None,
      token_reload_interval_ms: default_token_reload_interval_ms(),
      connect_timeout_ms: default_connect_timeout_ms(),
      sign_timeout_ms: default_sign_timeout_ms(),
    }
  }
}

impl Config {
  pub(super) fn resolve_admin_audit_anchor_paths(&mut self, cert_dir: &Path) -> anyhow::Result<()> {
    if !self.admin.audit.anchor.enabled {
      return Ok(());
    }

    let (public_key, public_key_logical) = resolve_existing_local_config_file_path_with_logical(
      "admin.audit.anchor.signer.public_key_file",
      cert_dir,
      &self.admin.audit.anchor.signer.public_key_file,
    )?;
    self.admin.audit.anchor.signer.public_key_file = public_key;
    self.source_paths.remember_runtime_file(public_key_logical);

    if let Some(token_file) = self.admin.audit.anchor.signer.token_file.take() {
      let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
        "admin.audit.anchor.signer.token_file",
        cert_dir,
        &token_file,
      )?;
      self.admin.audit.anchor.signer.token_file = Some(resolved);
      self.source_paths.remember_runtime_file(logical);
    }
    Ok(())
  }

  pub(super) fn validate_admin_audit_anchor_fields(&self) -> anyhow::Result<()> {
    validate_anchor_bounds(&self.admin.audit.anchor)?;
    if self.admin.audit.anchor.enabled && !self.admin.audit.enabled {
      bail!("admin.audit.anchor.enabled requires admin.audit.enabled = true");
    }
    if self.admin.audit.anchor.enabled
      && self.admin.audit.spool.max_event_bytes > MAX_ANCHORED_EVENT_BYTES
    {
      bail!(
        "admin.audit.spool.max_event_bytes must not exceed {MAX_ANCHORED_EVENT_BYTES} when admin.audit.anchor.enabled = true"
      );
    }
    Ok(())
  }

  pub(super) fn validate_admin_audit_anchor(&self) -> anyhow::Result<()> {
    let anchor = &self.admin.audit.anchor;
    if !anchor.enabled {
      if self.admin.mutations.mode.required() {
        bail!("admin.mutations.mode = \"required\" requires admin.audit.anchor.enabled = true");
      }
      return Ok(());
    }
    if !self.admin.audit.store.enabled
      || self.admin.audit.store.kind != AdminAuditStoreKind::Postgres
    {
      bail!("admin.audit.anchor.enabled requires an enabled PostgreSQL admin.audit.store");
    }
    if self.admin.audit.acknowledgement != AdminAuditAcknowledgement::Postgres {
      bail!("admin.audit.anchor.enabled requires admin.audit.acknowledgement = \"postgres\"");
    }
    if !self.shared_state.enabled {
      bail!("admin.audit.anchor.enabled requires shared_state.enabled = true");
    }

    validate_optional_non_empty(
      "admin.audit.anchor.sink.backend",
      Some(&anchor.sink.backend),
    )?;
    validate_runtime_identifier(
      "admin.audit.anchor.sink.authority_id",
      &anchor.sink.authority_id,
    )?;
    validate_identifier_length(
      "admin.audit.anchor.sink.authority_id",
      &anchor.sink.authority_id,
    )?;
    let store_backend = self.admin.audit.store.backend.as_deref().ok_or_else(|| {
      anyhow::anyhow!("admin.audit.anchor.enabled requires admin.audit.store.backend")
    })?;
    if anchor.sink.backend == store_backend {
      bail!("admin.audit.anchor.sink.backend must differ from admin.audit.store.backend");
    }
    let sink_backend = self
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == anchor.sink.backend)
      .ok_or_else(|| {
        anyhow::anyhow!(
          "admin.audit.anchor.sink.backend references unknown shared_state backend {}",
          anchor.sink.backend
        )
      })?;
    if sink_backend.kind != SharedStateBackendKind::Postgres {
      bail!(
        "admin.audit.anchor.sink.backend {} must use kind = \"postgres\"",
        anchor.sink.backend
      );
    }
    let store_backend = self
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == store_backend)
      .context("admin.audit.store.backend references an unknown shared_state backend")?;
    let store_target = postgres_authority_target(
      &store_backend.connection_url_with_prefix("admin.audit.store.backend")?,
      "admin.audit.store.backend",
    )?;
    let sink_target = postgres_authority_target(
      &sink_backend.connection_url_with_prefix("admin.audit.anchor.sink.backend")?,
      "admin.audit.anchor.sink.backend",
    )?;
    if store_target == sink_target {
      bail!(
        "admin.audit.anchor.sink.backend must use a PostgreSQL database distinct from the local Admin audit store"
      );
    }

    validate_environment_value(
      "shared_state.instance_id_env",
      &self.shared_state.instance_id_env,
      "Admin audit anchor instance ID",
    )?;
    validate_environment_value(
      "admin.audit.anchor.deployment_epoch_env",
      &anchor.deployment_epoch_env,
      "Admin audit anchor deployment epoch",
    )?;

    if anchor.signer.socket_path.as_os_str().is_empty() || !anchor.signer.socket_path.is_absolute()
    {
      bail!("admin.audit.anchor.signer.socket_path must be an absolute Unix socket path");
    }
    validate_runtime_identifier("admin.audit.anchor.signer.key_id", &anchor.signer.key_id)?;
    validate_identifier_length("admin.audit.anchor.signer.key_id", &anchor.signer.key_id)?;
    validate_raw_ed25519_public_key(&anchor.signer.public_key_file)?;
    if let Some(token_file) = &anchor.signer.token_file {
      validate_base64_32_byte_file("admin.audit.anchor.signer.token_file", token_file)?;
    } else {
      validate_environment_name(
        "admin.audit.anchor.signer.token_env",
        &anchor.signer.token_env,
      )?;
      validate_base64_32_byte_env(
        "admin.audit.anchor.signer.token_env",
        &anchor.signer.token_env,
      )?;
    }
    if anchor.signer.token_reload_interval_ms == 0 {
      bail!("admin.audit.anchor.signer.token_reload_interval_ms must be greater than zero");
    }
    if anchor.signer.connect_timeout_ms == 0 {
      bail!("admin.audit.anchor.signer.connect_timeout_ms must be greater than zero");
    }
    if anchor.signer.sign_timeout_ms == 0 {
      bail!("admin.audit.anchor.signer.sign_timeout_ms must be greater than zero");
    }
    Ok(())
  }
}

fn postgres_authority_target(value: &str, field: &str) -> anyhow::Result<(String, u16, String)> {
  let url = url::Url::parse(value).with_context(|| format!("{field} is not a valid URL"))?;
  let host = url
    .host_str()
    .context(format!("{field} must contain a PostgreSQL host"))?
    .to_ascii_lowercase();
  let port = url.port().unwrap_or(5432);
  let database = url.path().trim_start_matches('/').to_string();
  if database.is_empty() {
    bail!("{field} must select a PostgreSQL database");
  }
  Ok((host, port, database))
}

fn validate_anchor_bounds(anchor: &AdminAuditAnchorConfig) -> anyhow::Result<()> {
  validate_bound(
    "admin.audit.anchor.record_interval",
    anchor.record_interval,
    MIN_RECORD_INTERVAL,
    MAX_RECORD_INTERVAL,
  )?;
  validate_bound(
    "admin.audit.anchor.time_interval_ms",
    anchor.time_interval_ms,
    MIN_TIME_INTERVAL_MS,
    MAX_TIME_INTERVAL_MS,
  )?;
  validate_bound(
    "admin.audit.anchor.max_pending_checkpoints",
    anchor.max_pending_checkpoints as u64,
    MIN_PENDING_CHECKPOINTS as u64,
    MAX_PENDING_CHECKPOINTS as u64,
  )?;
  validate_bound(
    "admin.audit.anchor.max_pending_bytes",
    anchor.max_pending_bytes,
    MIN_PENDING_BYTES,
    MAX_PENDING_BYTES,
  )?;
  validate_bound(
    "admin.audit.anchor.sink.submit_timeout_ms",
    anchor.sink.submit_timeout_ms,
    MIN_SUBMIT_TIMEOUT_MS,
    MAX_SUBMIT_TIMEOUT_MS,
  )
}

fn validate_bound(field: &str, value: u64, minimum: u64, maximum: u64) -> anyhow::Result<()> {
  if !(minimum..=maximum).contains(&value) {
    bail!("{field} must be between {minimum} and {maximum}");
  }
  Ok(())
}

fn validate_environment_value(field: &str, env_name: &str, value_name: &str) -> anyhow::Result<()> {
  validate_environment_name(field, env_name)?;
  let value = std::env::var(env_name)
    .with_context(|| format!("failed to read {field} {env_name} for Admin audit anchoring"))?;
  validate_runtime_identifier(value_name, &value)?;
  validate_identifier_length(value_name, &value)
}

fn validate_identifier_length(field: &str, value: &str) -> anyhow::Result<()> {
  if value.len() > 253 {
    bail!("{field} must not exceed 253 bytes");
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

fn validate_raw_ed25519_public_key(path: &Path) -> anyhow::Result<()> {
  let bytes = std::fs::read(path).with_context(|| {
    format!(
      "failed to read admin.audit.anchor.signer.public_key_file {}",
      path.display()
    )
  })?;
  if bytes.len() != 32 {
    bail!("admin.audit.anchor.signer.public_key_file must contain exactly 32 raw bytes");
  }
  Ok(())
}

fn validate_base64_32_byte_file(field: &str, path: &Path) -> anyhow::Result<()> {
  use base64::Engine;

  let raw = std::fs::read_to_string(path)
    .with_context(|| format!("failed to read {field} {}", path.display()))?;
  let bytes = base64::engine::general_purpose::STANDARD
    .decode(raw.trim())
    .with_context(|| format!("{field} must contain base64"))?;
  if bytes.len() != 32 {
    bail!("{field} must contain exactly 32 bytes");
  }
  Ok(())
}

const fn default_record_interval() -> u64 {
  1_024
}

const fn default_time_interval_ms() -> u64 {
  60_000
}

fn default_deployment_epoch_env() -> String {
  "OXIBELT_DEPLOYMENT_EPOCH".to_string()
}

const fn default_max_pending_checkpoints() -> usize {
  1_024
}

const fn default_max_pending_bytes() -> u64 {
  16 * 1024 * 1024
}

const fn default_submit_timeout_ms() -> u64 {
  5_000
}

fn default_token_env() -> String {
  "OXIBELT_AUDIT_KEYSIGNER_TOKEN".to_string()
}

const fn default_token_reload_interval_ms() -> u64 {
  1_000
}

const fn default_connect_timeout_ms() -> u64 {
  250
}

const fn default_sign_timeout_ms() -> u64 {
  1_000
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::AdminMutationMode;

  fn config_for_anchor_validation() -> Config {
    toml::from_str(
      r#"
[listeners]
https_bind = "127.0.0.1:8443"

[tls]
cert_chain = "unused-cert.pem"
private_key = "unused-key.pem"
"#,
    )
    .expect("minimal config should decode")
  }

  #[test]
  fn anchor_defaults_are_bounded_and_disabled() {
    let anchor = AdminAuditAnchorConfig::default();
    assert!(!anchor.enabled);
    assert_eq!(anchor.record_interval, 1_024);
    assert_eq!(anchor.time_interval_ms, 60_000);
    assert_eq!(anchor.max_pending_checkpoints, 1_024);
    assert_eq!(anchor.max_pending_bytes, 16 * 1024 * 1024);
    assert_eq!(anchor.sink.submit_timeout_ms, 5_000);
    assert_eq!(anchor.signer.token_reload_interval_ms, 1_000);
    assert_eq!(anchor.signer.connect_timeout_ms, 250);
    assert_eq!(anchor.signer.sign_timeout_ms, 1_000);
    validate_anchor_bounds(&anchor).expect("defaults should satisfy bounds");
  }

  #[test]
  fn anchor_numeric_bounds_fail_closed() {
    let mut anchor = AdminAuditAnchorConfig::default();
    let mutations: [fn(&mut AdminAuditAnchorConfig); 5] = [
      |value: &mut AdminAuditAnchorConfig| value.record_interval = 0,
      |value: &mut AdminAuditAnchorConfig| value.time_interval_ms = 999,
      |value: &mut AdminAuditAnchorConfig| value.max_pending_checkpoints = 1,
      |value: &mut AdminAuditAnchorConfig| value.max_pending_bytes = 127 * 1024,
      |value: &mut AdminAuditAnchorConfig| value.sink.submit_timeout_ms = 99,
    ];
    for mutate in mutations {
      mutate(&mut anchor);
      assert!(validate_anchor_bounds(&anchor).is_err());
      anchor = AdminAuditAnchorConfig::default();
    }
  }

  #[test]
  fn required_admin_mutations_require_external_anchoring() {
    let mut config = config_for_anchor_validation();
    config.admin.mutations.mode = AdminMutationMode::Required;

    let error = config
      .validate_admin_audit_anchor()
      .expect_err("required mutations must reject disabled anchoring");
    assert!(
      error
        .to_string()
        .contains("admin.mutations.mode = \"required\" requires admin.audit.anchor.enabled")
    );
  }

  #[test]
  fn enabled_anchor_requires_enabled_admin_audit() {
    let mut config = config_for_anchor_validation();
    config.admin.audit.anchor.enabled = true;

    let error = config
      .validate_admin_audit_anchor_fields()
      .expect_err("anchoring without Admin audit must fail");
    assert!(
      error
        .to_string()
        .contains("admin.audit.anchor.enabled requires admin.audit.enabled")
    );
  }

  #[test]
  fn enabled_anchor_bounds_events_to_the_verifier_ceiling() {
    let mut config = config_for_anchor_validation();
    config.admin.audit.enabled = true;
    config.admin.audit.anchor.enabled = true;
    config.admin.audit.spool.max_event_bytes = MAX_ANCHORED_EVENT_BYTES + 1;

    let error = config
      .validate_admin_audit_anchor_fields()
      .expect_err("anchored event size must remain independently verifiable");
    assert!(
      error
        .to_string()
        .contains("admin.audit.spool.max_event_bytes must not exceed")
    );
  }

  #[test]
  fn anchor_authority_must_use_a_separate_backend() {
    let mut config = config_for_anchor_validation();
    config.admin.audit.enabled = true;
    config.admin.audit.store.enabled = true;
    config.admin.audit.store.backend = Some("audit-local".to_string());
    config.admin.audit.anchor.enabled = true;
    config.admin.audit.anchor.sink.backend = "audit-local".to_string();
    config.admin.audit.anchor.sink.authority_id = "audit-authority".to_string();
    config.shared_state.enabled = true;

    let error = config
      .validate_admin_audit_anchor()
      .expect_err("local and external authority backends must differ");
    assert!(
      error
        .to_string()
        .contains("admin.audit.anchor.sink.backend must differ")
    );
  }
}
