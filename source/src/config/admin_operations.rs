//! Long-running Admin operation persistence and worker-bound configuration.

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use super::{
  AdminAuditAcknowledgement, AdminAuditMode, Config, SharedStateBackendKind,
  validate_base64_32_byte_env, validate_optional_non_empty, validate_runtime_identifier,
};

const MAX_RETENTION_SECONDS: u64 = 2_592_000;
const MAX_LEASE_SECONDS: u64 = 300;
const MAX_LIFETIME_SECONDS: u64 = 2_592_000;
const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminOperationsPersistence {
  #[default]
  Auto,
  Ephemeral,
  Postgres,
}

impl AdminOperationsPersistence {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Auto => "auto",
      Self::Ephemeral => "ephemeral",
      Self::Postgres => "postgres",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminOperationsConfig {
  #[serde(default = "super::default_true")]
  pub enabled: bool,
  #[serde(default)]
  pub persistence: AdminOperationsPersistence,
  #[serde(default)]
  pub backend: Option<String>,
  #[serde(default = "default_artifact_key_env")]
  pub artifact_key_env: String,
  #[serde(default = "default_lease_seconds")]
  pub lease_seconds: u64,
  #[serde(default = "default_lease_renew_seconds")]
  pub lease_renew_seconds: u64,
  #[serde(default = "default_max_lifetime_seconds")]
  pub max_lifetime_seconds: u64,
  #[serde(default = "default_artifact_max_bytes")]
  pub artifact_max_bytes: usize,
  #[serde(default = "default_checkpoint_max_bytes")]
  pub checkpoint_max_bytes: usize,
  #[serde(default = "default_max_running")]
  pub max_running: usize,
  #[serde(default = "default_max_queued")]
  pub max_queued: usize,
  #[serde(default = "default_max_stored")]
  pub max_stored: usize,
  #[serde(default = "default_retention_seconds")]
  pub retention_seconds: u64,
  #[serde(default = "default_event_buffer")]
  pub event_buffer: usize,
  #[serde(default = "default_result_max_bytes")]
  pub result_max_bytes: usize,
  #[serde(default = "super::default_true")]
  pub websocket: bool,
  #[serde(default = "super::default_true")]
  pub webtransport: bool,
  #[serde(default = "default_webtransport_max_sessions")]
  pub webtransport_max_sessions: usize,
}

impl Default for AdminOperationsConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      persistence: AdminOperationsPersistence::Auto,
      backend: None,
      artifact_key_env: default_artifact_key_env(),
      lease_seconds: default_lease_seconds(),
      lease_renew_seconds: default_lease_renew_seconds(),
      max_lifetime_seconds: default_max_lifetime_seconds(),
      artifact_max_bytes: default_artifact_max_bytes(),
      checkpoint_max_bytes: default_checkpoint_max_bytes(),
      max_running: default_max_running(),
      max_queued: default_max_queued(),
      max_stored: default_max_stored(),
      retention_seconds: default_retention_seconds(),
      event_buffer: default_event_buffer(),
      result_max_bytes: default_result_max_bytes(),
      websocket: true,
      webtransport: true,
      webtransport_max_sessions: default_webtransport_max_sessions(),
    }
  }
}

impl Config {
  pub(super) fn validate_admin_operations_config(&self) -> anyhow::Result<()> {
    let operations = &self.admin.operations;
    validate_optional_non_empty("admin.operations.backend", operations.backend.as_deref())?;
    validate_environment_name(
      "admin.operations.artifact_key_env",
      &operations.artifact_key_env,
    )?;

    if operations.max_running == 0 {
      bail!("admin.operations.max_running must be greater than 0");
    }
    if operations.max_queued == 0 {
      bail!("admin.operations.max_queued must be greater than 0");
    }
    if operations.max_stored == 0 {
      bail!("admin.operations.max_stored must be greater than 0");
    }
    if operations.max_stored < operations.max_running {
      bail!("admin.operations.max_stored must be at least admin.operations.max_running");
    }
    if operations.max_stored < operations.max_queued {
      bail!("admin.operations.max_stored must be at least admin.operations.max_queued");
    }
    if !(1..=MAX_RETENTION_SECONDS).contains(&operations.retention_seconds) {
      bail!("admin.operations.retention_seconds must be between 1 and {MAX_RETENTION_SECONDS}");
    }
    if operations.event_buffer == 0 {
      bail!("admin.operations.event_buffer must be greater than 0");
    }
    if operations.result_max_bytes == 0 {
      bail!("admin.operations.result_max_bytes must be greater than 0");
    }
    if operations.webtransport_max_sessions == 0 {
      bail!("admin.operations.webtransport_max_sessions must be greater than 0");
    }
    if !(3..=MAX_LEASE_SECONDS).contains(&operations.lease_seconds) {
      bail!("admin.operations.lease_seconds must be between 3 and {MAX_LEASE_SECONDS}");
    }
    if operations.lease_renew_seconds == 0
      || operations.lease_renew_seconds > operations.lease_seconds / 3
    {
      bail!(
        "admin.operations.lease_renew_seconds must be greater than 0 and no more than one third of admin.operations.lease_seconds"
      );
    }
    if !(60..=MAX_LIFETIME_SECONDS).contains(&operations.max_lifetime_seconds) {
      bail!("admin.operations.max_lifetime_seconds must be between 60 and {MAX_LIFETIME_SECONDS}");
    }
    if operations.max_lifetime_seconds < operations.lease_seconds {
      bail!(
        "admin.operations.max_lifetime_seconds must be at least admin.operations.lease_seconds"
      );
    }
    if !(1..=MAX_ARTIFACT_BYTES).contains(&operations.artifact_max_bytes) {
      bail!("admin.operations.artifact_max_bytes must be between 1 and {MAX_ARTIFACT_BYTES}");
    }
    if operations.checkpoint_max_bytes == 0
      || operations.checkpoint_max_bytes > operations.artifact_max_bytes
    {
      bail!(
        "admin.operations.checkpoint_max_bytes must be greater than 0 and not exceed admin.operations.artifact_max_bytes"
      );
    }

    match operations.persistence {
      AdminOperationsPersistence::Ephemeral => {
        if operations.backend.is_some() {
          bail!(
            "admin.operations.persistence = \"ephemeral\" does not accept admin.operations.backend"
          );
        }
      }
      AdminOperationsPersistence::Auto => {
        if let Some(backend) = operations.backend.as_deref() {
          self.validate_operations_postgres_backend(backend)?;
        }
      }
      AdminOperationsPersistence::Postgres => {
        let backend = operations
          .backend
          .as_deref()
          .or(self.admin.audit.store.backend.as_deref())
          .ok_or_else(|| {
            anyhow::anyhow!(
              "admin.operations.persistence = \"postgres\" requires admin.operations.backend or admin.audit.store.backend"
            )
          })?;
        self.validate_operations_postgres_backend(backend)?;
        self.validate_operations_durable_audit(backend)?;
        validate_base64_32_byte_env(
          "admin.operations.artifact_key_env",
          &operations.artifact_key_env,
        )?;
        validate_environment_name(
          "shared_state.instance_id_env",
          &self.shared_state.instance_id_env,
        )?;
        let instance_id = std::env::var(&self.shared_state.instance_id_env).with_context(|| {
          format!(
            "failed to read shared_state.instance_id_env {} for durable Admin operations",
            self.shared_state.instance_id_env
          )
        })?;
        validate_runtime_identifier("durable Admin operation instance ID", &instance_id)?;
        if instance_id.len() > 253 {
          bail!("durable Admin operation instance ID must not exceed 253 bytes");
        }
      }
    }

    Ok(())
  }

  fn validate_operations_postgres_backend(&self, backend_name: &str) -> anyhow::Result<()> {
    if !self.shared_state.enabled {
      bail!("admin.operations.backend requires shared_state.enabled = true");
    }
    let Some(backend) = self
      .shared_state
      .backends
      .iter()
      .find(|candidate| candidate.name == backend_name)
    else {
      bail!("admin.operations.backend references unknown shared_state backend {backend_name}");
    };
    if backend.kind != SharedStateBackendKind::Postgres {
      bail!("admin.operations.backend {backend_name} must use kind = \"postgres\"");
    }
    Ok(())
  }

  fn validate_operations_durable_audit(&self, backend_name: &str) -> anyhow::Result<()> {
    let audit = &self.admin.audit;
    if !audit.enabled
      || audit.acknowledgement != AdminAuditAcknowledgement::Postgres
      || !audit.store.enabled
      || audit.store.backend.as_deref() != Some(backend_name)
    {
      bail!(
        "durable Admin operations require enabled enforcing PostgreSQL Admin audit on the same backend"
      );
    }
    let actions_are_durable = match audit.mode {
      AdminAuditMode::DurableRequired => true,
      AdminAuditMode::DurableRequiredForActions => ["operations.write", "operations.lifecycle"]
        .iter()
        .all(|action| {
          audit
            .required_actions
            .iter()
            .any(|candidate| candidate == action)
        }),
      AdminAuditMode::BestEffort => false,
    };
    if !actions_are_durable {
      bail!(
        "durable Admin operations require enforcing Admin audit coverage for operations.write and operations.lifecycle"
      );
    }
    Ok(())
  }
}

fn validate_environment_name(field: &str, value: &str) -> anyhow::Result<()> {
  let mut bytes = value.bytes();
  let starts_valid = bytes
    .next()
    .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_');
  if !starts_valid
    || value.len() > 253
    || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
  {
    bail!("{field} must contain a valid environment variable name");
  }
  Ok(())
}

fn default_artifact_key_env() -> String {
  "OXIBELT_ADMIN_OPERATION_ARTIFACT_KEY".to_string()
}

const fn default_lease_seconds() -> u64 {
  15
}

const fn default_lease_renew_seconds() -> u64 {
  5
}

const fn default_max_lifetime_seconds() -> u64 {
  86_400
}

const fn default_artifact_max_bytes() -> usize {
  16 * 1024 * 1024
}

const fn default_checkpoint_max_bytes() -> usize {
  1024 * 1024
}

const fn default_max_running() -> usize {
  4
}

const fn default_max_queued() -> usize {
  64
}

const fn default_max_stored() -> usize {
  256
}

const fn default_retention_seconds() -> u64 {
  3_600
}

const fn default_event_buffer() -> usize {
  256
}

const fn default_result_max_bytes() -> usize {
  16 * 1024 * 1024
}

const fn default_webtransport_max_sessions() -> usize {
  64
}
