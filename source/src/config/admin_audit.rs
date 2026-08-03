//! Admin audit configuration.
//! Durable query storage is separated from standards-oriented export sinks.

use std::collections::HashSet;
use std::path::PathBuf;

use serde::Deserialize;

use anyhow::bail;

use super::{
  AdminAuditAnchorConfig, Config, SharedStateBackendKind, default_admin_audit_queue_capacity,
  validate_optional_non_empty,
};

#[derive(Debug, Clone, PartialEq)]
pub struct AdminAuditConfig {
  pub enabled: bool,
  pub mode: AdminAuditMode,
  pub acknowledgement: AdminAuditAcknowledgement,
  pub required_actions: Vec<String>,
  pub backend: Option<String>,
  pub queue_capacity: usize,
  pub store: AdminAuditStoreConfig,
  pub export: AdminAuditExportConfig,
  pub spool: AdminAuditSpoolConfig,
  pub integrity: AdminAuditIntegrityConfig,
  pub anchor: AdminAuditAnchorConfig,
}

impl Default for AdminAuditConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: AdminAuditMode::default(),
      acknowledgement: AdminAuditAcknowledgement::default(),
      required_actions: Vec::new(),
      backend: None,
      queue_capacity: default_admin_audit_queue_capacity(),
      store: AdminAuditStoreConfig::default(),
      export: AdminAuditExportConfig::default(),
      spool: AdminAuditSpoolConfig::default(),
      integrity: AdminAuditIntegrityConfig::default(),
      anchor: AdminAuditAnchorConfig::default(),
    }
  }
}

impl<'de> Deserialize<'de> for AdminAuditConfig {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let raw = RawAdminAuditConfig::deserialize(deserializer)?;
    let store_was_absent = raw.store.is_none();
    let mut store = raw.store.unwrap_or_default();
    if let Some(backend) = &raw.backend
      && store.backend.is_none()
    {
      store.backend = Some(backend.clone());
    }
    if store_was_absent && raw.backend.is_some() {
      store.enabled = true;
      store.kind = AdminAuditStoreKind::Postgres;
    }

    let mut export = raw.export.unwrap_or_default();
    if store_was_absent
      && raw.backend.is_some()
      && !export
        .required_sinks
        .contains(&AdminAuditRequiredSink::Store)
    {
      export.required_sinks.push(AdminAuditRequiredSink::Store);
    }

    Ok(Self {
      enabled: raw.enabled,
      mode: raw.mode.unwrap_or_default(),
      acknowledgement: raw.acknowledgement,
      required_actions: raw.required_actions,
      backend: raw.backend,
      queue_capacity: raw.queue_capacity,
      store,
      export,
      spool: raw.spool,
      integrity: raw.integrity,
      anchor: raw.anchor,
    })
  }
}

#[derive(Debug, Deserialize)]
struct RawAdminAuditConfig {
  #[serde(default)]
  enabled: bool,
  #[serde(default)]
  mode: Option<AdminAuditMode>,
  #[serde(default)]
  acknowledgement: AdminAuditAcknowledgement,
  #[serde(default)]
  required_actions: Vec<String>,
  #[serde(default)]
  backend: Option<String>,
  #[serde(default = "default_admin_audit_queue_capacity")]
  queue_capacity: usize,
  #[serde(default)]
  store: Option<AdminAuditStoreConfig>,
  #[serde(default)]
  export: Option<AdminAuditExportConfig>,
  #[serde(default)]
  spool: AdminAuditSpoolConfig,
  #[serde(default)]
  integrity: AdminAuditIntegrityConfig,
  #[serde(default)]
  anchor: AdminAuditAnchorConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditMode {
  #[default]
  #[serde(alias = "enforcing")]
  DurableRequired,
  BestEffort,
  DurableRequiredForActions,
}

impl AdminAuditMode {
  #[doc(hidden)]
  #[allow(non_upper_case_globals)]
  pub const Enforcing: Self = Self::DurableRequired;

  pub fn requires_durable_audit(self) -> bool {
    matches!(
      self,
      Self::DurableRequired | Self::DurableRequiredForActions
    )
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditAcknowledgement {
  #[default]
  Postgres,
  FsyncedSpool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminAuditSpoolConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub directory: Option<PathBuf>,
  #[serde(default = "default_admin_audit_spool_max_bytes")]
  pub max_bytes: u64,
  #[serde(default = "default_admin_audit_spool_max_events")]
  pub max_events: usize,
  #[serde(default = "default_admin_audit_spool_max_event_bytes")]
  pub max_event_bytes: usize,
}

impl Default for AdminAuditSpoolConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      directory: None,
      max_bytes: default_admin_audit_spool_max_bytes(),
      max_events: default_admin_audit_spool_max_events(),
      max_event_bytes: default_admin_audit_spool_max_event_bytes(),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct AdminAuditIntegrityConfig {
  #[serde(default)]
  pub hmac_key_env: Option<String>,
  #[serde(default)]
  pub hmac_key_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminAuditStoreConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub backend: Option<String>,
  #[serde(default)]
  pub kind: AdminAuditStoreKind,
}

impl Default for AdminAuditStoreConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      backend: None,
      kind: AdminAuditStoreKind::Postgres,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditStoreKind {
  #[default]
  Postgres,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminAuditExportConfig {
  #[serde(default = "super::default_true")]
  pub enabled: bool,
  #[serde(default = "default_admin_audit_export_sinks")]
  pub sinks: Vec<AdminAuditExportSink>,
  #[serde(default)]
  pub required_sinks: Vec<AdminAuditRequiredSink>,
}

impl Default for AdminAuditExportConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      sinks: default_admin_audit_export_sinks(),
      required_sinks: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditExportSink {
  AccessLog,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditRequiredSink {
  Store,
}

fn default_admin_audit_export_sinks() -> Vec<AdminAuditExportSink> {
  vec![AdminAuditExportSink::AccessLog]
}

const fn default_admin_audit_spool_max_bytes() -> u64 {
  64 * 1024 * 1024
}

const fn default_admin_audit_spool_max_events() -> usize {
  16_384
}

const fn default_admin_audit_spool_max_event_bytes() -> usize {
  64 * 1024
}

pub const ADMIN_AUDIT_PROTECTED_MUTATION_ACTIONS: [&str; 12] = [
  "config.load",
  "config.rollback",
  "config.files_sync",
  "config.downstream_tls_reload",
  "config.key_rotate",
  "config.secret_reference_update",
  "ipm.write",
  "break_glass.activate",
  "break_glass.revoke",
  "membership.propose",
  "membership.activate",
  "membership.cancel",
];

pub const ADMIN_AUDIT_DURABILITY_ACTIONS: [&str; 23] = [
  "config.load",
  "config.rollback",
  "config.files_sync",
  "config.downstream_tls_reload",
  "config.upstream_tls_refresh",
  "config.key_rotate",
  "config.secret_reference_update",
  "ipm.write",
  "break_glass.activate",
  "break_glass.revoke",
  "membership.propose",
  "membership.activate",
  "membership.cancel",
  "operations.write",
  "operations.lifecycle",
  "cache.warm",
  "cache.purge",
  "person_proof.revoke",
  "lifecycle.drain",
  "lifecycle.undrain",
  "dynamic_policy.write",
  "upstream_pool.write",
  "stream_pool.write",
];

impl Config {
  pub(super) fn validate_admin_audit_config_fields(&self) -> anyhow::Result<()> {
    self.validate_admin_audit_anchor_fields()?;
    validate_optional_non_empty("admin.audit.backend", self.admin.audit.backend.as_deref())?;
    validate_optional_non_empty(
      "admin.audit.store.backend",
      self.admin.audit.store.backend.as_deref(),
    )?;
    if self.admin.audit.backend.is_some()
      && self.admin.audit.store.backend.as_deref() != self.admin.audit.backend.as_deref()
    {
      bail!("admin.audit.backend and admin.audit.store.backend must match when both are set");
    }
    validate_optional_non_empty(
      "admin.audit.integrity.hmac_key_env",
      self.admin.audit.integrity.hmac_key_env.as_deref(),
    )?;
    validate_optional_non_empty(
      "admin.audit.integrity.hmac_key_id",
      self.admin.audit.integrity.hmac_key_id.as_deref(),
    )?;
    match (
      self.admin.audit.integrity.hmac_key_env.as_deref(),
      self.admin.audit.integrity.hmac_key_id.as_deref(),
    ) {
      (None, None) | (Some(_), Some(_)) => {}
      _ => bail!(
        "admin.audit.integrity.hmac_key_env and admin.audit.integrity.hmac_key_id must be set together"
      ),
    }
    if self.admin.audit.spool.max_bytes == 0 {
      bail!("admin.audit.spool.max_bytes must be greater than zero");
    }
    if self.admin.audit.spool.max_events == 0 {
      bail!("admin.audit.spool.max_events must be greater than zero");
    }
    if self.admin.audit.spool.max_event_bytes == 0 {
      bail!("admin.audit.spool.max_event_bytes must be greater than zero");
    }
    let max_event_bytes = u64::try_from(self.admin.audit.spool.max_event_bytes)
      .map_err(|_| anyhow::anyhow!("admin.audit.spool.max_event_bytes is too large"))?;
    if max_event_bytes > self.admin.audit.spool.max_bytes {
      bail!("admin.audit.spool.max_event_bytes must not exceed admin.audit.spool.max_bytes");
    }
    if self.admin.audit.spool.enabled {
      let directory = self.admin.audit.spool.directory.as_deref().ok_or_else(|| {
        anyhow::anyhow!("admin.audit.spool.enabled requires admin.audit.spool.directory")
      })?;
      if !directory.is_absolute() {
        bail!("admin.audit.spool.directory must be an absolute path");
      }
    }
    if self.admin.audit.acknowledgement == AdminAuditAcknowledgement::FsyncedSpool
      && !self.admin.audit.spool.enabled
    {
      bail!(
        "admin.audit.acknowledgement = \"fsynced_spool\" requires admin.audit.spool.enabled = true"
      );
    }
    let mut required_actions = HashSet::new();
    for action in &self.admin.audit.required_actions {
      if !ADMIN_AUDIT_DURABILITY_ACTIONS.contains(&action.as_str()) {
        bail!("admin.audit.required_actions contains unknown action {action}");
      }
      if !required_actions.insert(action.as_str()) {
        bail!("admin.audit.required_actions contains duplicate action {action}");
      }
    }
    if self.admin.audit.mode == AdminAuditMode::DurableRequiredForActions {
      if self.admin.audit.required_actions.is_empty() {
        bail!(
          "admin.audit.mode = \"durable_required_for_actions\" requires non-empty admin.audit.required_actions"
        );
      }
    } else if !self.admin.audit.required_actions.is_empty() {
      bail!(
        "admin.audit.required_actions requires admin.audit.mode = \"durable_required_for_actions\""
      );
    }
    Ok(())
  }

  pub(super) fn validate_admin_audit_runtime(&self) -> anyhow::Result<()> {
    self.validate_admin_audit_anchor()?;
    if !self.admin.audit.enabled {
      return Ok(());
    }
    if self.admin.audit.backend.is_some() && !self.admin.audit.store.enabled {
      bail!("admin.audit.backend cannot be set when admin.audit.store.enabled = false");
    }
    if self.admin.audit.backend.is_some()
      && self.admin.audit.acknowledgement != AdminAuditAcknowledgement::Postgres
    {
      bail!("legacy admin.audit.backend requires admin.audit.acknowledgement = \"postgres\"");
    }
    if self.admin.audit.export.enabled && self.admin.audit.export.sinks.is_empty() {
      bail!("admin.audit.export.sinks must not be empty when admin.audit.export.enabled = true");
    }
    if self.admin.audit.mode == AdminAuditMode::BestEffort
      && !self.admin.audit.export.required_sinks.is_empty()
    {
      bail!("admin.audit.export.required_sinks requires a durable Admin audit mode");
    }
    if self
      .admin
      .audit
      .export
      .required_sinks
      .contains(&AdminAuditRequiredSink::Store)
      && !self.admin.audit.store.enabled
    {
      bail!(
        "admin.audit.export.required_sinks = [\"store\"] requires admin.audit.store.enabled = true"
      );
    }
    if self
      .admin
      .audit
      .export
      .required_sinks
      .contains(&AdminAuditRequiredSink::Store)
      && self.admin.audit.acknowledgement != AdminAuditAcknowledgement::Postgres
    {
      bail!(
        "legacy admin.audit.export.required_sinks = [\"store\"] requires admin.audit.acknowledgement = \"postgres\""
      );
    }
    if self.admin.audit.mode.requires_durable_audit()
      && self.admin.audit.acknowledgement == AdminAuditAcknowledgement::Postgres
      && !self.admin.audit.store.enabled
    {
      bail!("admin.audit.acknowledgement = \"postgres\" requires admin.audit.store.enabled = true");
    }
    if self.admin.audit.store.enabled {
      let Some(backend_name) = self.admin.audit.store.backend.as_deref() else {
        bail!("admin.audit.store.enabled requires admin.audit.store.backend");
      };
      if !self.shared_state.enabled {
        bail!("admin.audit.store.backend requires shared_state.enabled = true");
      }
      let Some(backend) = self
        .shared_state
        .backends
        .iter()
        .find(|backend| backend.name == backend_name)
      else {
        bail!("admin.audit.store.backend references unknown shared_state backend {backend_name}");
      };
      if backend.kind != SharedStateBackendKind::Postgres {
        bail!("admin.audit.store.backend {backend_name} must use kind = \"postgres\"");
      }
    }
    Ok(())
  }
}
