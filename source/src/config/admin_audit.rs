//! Admin audit configuration.
//! Durable query storage is separated from standards-oriented export sinks.

use serde::Deserialize;

use anyhow::bail;

use super::{
  Config, SharedStateBackendKind, default_admin_audit_queue_capacity, validate_optional_non_empty,
};

#[derive(Debug, Clone, PartialEq)]
pub struct AdminAuditConfig {
  pub enabled: bool,
  pub mode: AdminAuditMode,
  pub backend: Option<String>,
  pub queue_capacity: usize,
  pub store: AdminAuditStoreConfig,
  pub export: AdminAuditExportConfig,
}

impl Default for AdminAuditConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: AdminAuditMode::default(),
      backend: None,
      queue_capacity: default_admin_audit_queue_capacity(),
      store: AdminAuditStoreConfig::default(),
      export: AdminAuditExportConfig::default(),
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
      backend: raw.backend,
      queue_capacity: raw.queue_capacity,
      store,
      export,
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
  backend: Option<String>,
  #[serde(default = "default_admin_audit_queue_capacity")]
  queue_capacity: usize,
  #[serde(default)]
  store: Option<AdminAuditStoreConfig>,
  #[serde(default)]
  export: Option<AdminAuditExportConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuditMode {
  #[default]
  Enforcing,
  BestEffort,
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

impl Config {
  pub(super) fn validate_admin_audit_config_fields(&self) -> anyhow::Result<()> {
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
    Ok(())
  }

  pub(super) fn validate_admin_audit_runtime(&self) -> anyhow::Result<()> {
    if !self.admin.audit.enabled {
      return Ok(());
    }
    if self.admin.audit.backend.is_some() && !self.admin.audit.store.enabled {
      bail!("admin.audit.backend cannot be set when admin.audit.store.enabled = false");
    }
    if self.admin.audit.export.enabled && self.admin.audit.export.sinks.is_empty() {
      bail!("admin.audit.export.sinks must not be empty when admin.audit.export.enabled = true");
    }
    if self.admin.audit.mode == AdminAuditMode::BestEffort
      && !self.admin.audit.export.required_sinks.is_empty()
    {
      bail!("admin.audit.export.required_sinks requires admin.audit.mode = \"enforcing\"");
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
    if self.admin.audit.mode == AdminAuditMode::Enforcing && !self.admin.audit.store.enabled {
      bail!("admin.audit.mode = \"enforcing\" requires admin.audit.store.enabled = true");
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
