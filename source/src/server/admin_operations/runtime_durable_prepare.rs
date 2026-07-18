//! Startup selection and fail-closed prerequisite checks for durable Admin operations.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::Context as _;
use tracing::{info, warn};

use crate::admin_audit::AdminAuditRuntime;
use crate::config::{
  AdminAuditAcknowledgement, AdminAuditMode, AdminOperationsPersistence, Config,
};

use super::runtime_durable::DurableOperationRuntime;
use super::runtime_durable_support::encode_hex;
use super::{OperationArtifactCipher, OperationJournal, WorkerIdentity};

impl DurableOperationRuntime {
  pub(super) async fn prepare(
    config: &Config,
    audit: &AdminAuditRuntime,
  ) -> anyhow::Result<Option<Self>> {
    let persistence = config.admin.operations.persistence;
    if persistence == AdminOperationsPersistence::Ephemeral || !config.admin.operations.enabled {
      return Ok(None);
    }
    match Self::build(config, audit).await {
      Ok(runtime) => {
        runtime.spawn_recovery_sweeper();
        info!("durable Admin operation journal is active");
        Ok(Some(runtime))
      }
      Err(error) if persistence == AdminOperationsPersistence::Auto => {
        warn!(error = %error, "durable Admin operation prerequisites are unavailable; using visible ephemeral mode");
        Ok(None)
      }
      Err(error) => Err(error.context("failed to prepare durable Admin operation runtime")),
    }
  }

  async fn build(config: &Config, audit: &AdminAuditRuntime) -> anyhow::Result<Self> {
    let operations = &config.admin.operations;
    let audit_config = &config.admin.audit;
    anyhow::ensure!(
      audit_config.enabled
        && audit_config.acknowledgement == AdminAuditAcknowledgement::Postgres
        && audit_config.store.enabled,
      "durable Admin operations require enforcing PostgreSQL Admin audit"
    );
    let lifecycle_is_enforced = match audit_config.mode {
      AdminAuditMode::DurableRequired => true,
      AdminAuditMode::DurableRequiredForActions => ["operations.write", "operations.lifecycle"]
        .iter()
        .all(|action| {
          audit_config
            .required_actions
            .iter()
            .any(|value| value == action)
        }),
      AdminAuditMode::BestEffort => false,
    };
    anyhow::ensure!(
      lifecycle_is_enforced,
      "durable Admin operations require enforcing audit for operations.write and operations.lifecycle"
    );
    let audit_backend = audit_config
      .store
      .backend
      .as_deref()
      .context("enforcing PostgreSQL Admin audit backend is not configured")?;
    let selected_backend = operations.backend.as_deref().unwrap_or(audit_backend);
    anyhow::ensure!(
      selected_backend == audit_backend,
      "Admin operation journal and enforcing Admin audit must use the same backend"
    );
    if config.dynamic_policy.enabled {
      anyhow::ensure!(
        config.dynamic_policy_backend_name() == Some(selected_backend),
        "durable Dynamic Policy import requires the Admin operation journal backend"
      );
    }
    let pool = audit
      .critical_postgres_pool()
      .context("enforcing PostgreSQL Admin audit pool is unavailable")?;
    let instance_id = std::env::var(&config.shared_state.instance_id_env)
      .context("failed to read durable Admin operation instance identity")?;
    anyhow::ensure!(
      !instance_id.is_empty()
        && instance_id.len() <= 253
        && instance_id
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
      "durable Admin operation instance identity is invalid"
    );
    let mut boot_random = [0_u8; 16];
    crate::crypto::random_fill(&mut boot_random)
      .context("failed to generate durable Admin operation boot identity")?;
    let cipher = Arc::new(OperationArtifactCipher::from_environment(
      &operations.artifact_key_env,
      operations.artifact_max_bytes,
    )?);
    let journal = OperationJournal::new(pool, config.shared_state.namespace.clone())?;
    journal.initialize().await?;
    let runtime = Self {
      journal,
      cipher,
      audit: audit.clone(),
      worker: WorkerIdentity {
        worker_id: instance_id,
        boot_id: format!("boot-{}", encode_hex(&boot_random)),
      },
      lease_seconds: i64::try_from(operations.lease_seconds)?,
      lease_renew_seconds: operations.lease_renew_seconds,
      max_lifetime_seconds: i64::try_from(operations.max_lifetime_seconds)?,
      retention_seconds: i64::try_from(operations.retention_seconds)?,
      max_queued: operations.max_queued,
      max_stored: operations.max_stored,
      result_max_bytes: operations.result_max_bytes,
      shutting_down: Arc::new(AtomicBool::new(false)),
    };
    runtime.recover_incomplete().await?;
    let _ = runtime.journal.prune_terminal(128).await?;
    Ok(runtime)
  }
}
