//! Runtime trust configuration and durable admission for protected Admin writes.

use std::fmt::Write as _;
use std::fs;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use http::{HeaderMap, Method, StatusCode, Uri};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::admin_audit::{AdminAuditHandle, AdminAuditRuntime};
use crate::config::{
  AdminMutationMode, AdminMutationRolloutMode, AdminMutationSignatureSuite, Config,
};

use super::artifact::{
  ArtifactBinding, MutationArtifactCipher, MutationArtifactPlaintext, MutationArtifactReceipt,
};
use super::artifact_store;
use super::envelope::{MutationTarget, TranscriptContext};
use super::ledger::{ClaimOutcome, MutationClaim, MutationRecord};
use super::rollout::{AdminClusterRolloutController, LocalRolloutStatus, RolloutSettings};
use super::rollout_store::{self, InstanceHeartbeat};
use super::store::{
  BreakGlassActivation, MutationStore, create_break_glass_activation_tx, init_postgres,
  load_active_break_glass_for_principal, revoke_break_glass_activation_tx,
};
use super::{
  MUTATION_HEADER, MutationProtocolError, MutationProtocolErrorKind, SignerBinding, SignerRegistry,
};

const EMPTY_DIGEST: &str =
  "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone)]
pub(crate) struct AdminMutationRuntime {
  inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
  mode: AdminMutationMode,
  signers: SignerRegistry,
  store: Option<MutationStore>,
  namespace: String,
  maximum_validity_seconds: u64,
  maximum_clock_skew_seconds: u64,
  retention_seconds: i64,
  target: MutationTarget,
  rollout_mode: AdminMutationRolloutMode,
  cluster_id: String,
  members: Vec<String>,
  #[allow(dead_code)]
  artifact_cipher: Option<MutationArtifactCipher>,
  #[allow(dead_code)]
  cluster_controller: OnceLock<AdminClusterRolloutController>,
}

#[derive(Debug)]
pub(crate) enum MutationAdmission {
  Bypass,
  Claimed(MutationExecution),
  Replay(MutationRecord),
  InProgress(MutationRecord),
  Conflict(MutationConflict),
}

#[derive(Debug)]
pub(crate) struct MutationExecution {
  pub(crate) request_id: String,
  pub(crate) new_revision: String,
}

#[derive(Debug)]
pub(crate) enum MutationConflict {
  RequestId,
  Expired,
  Revision { actual_revision: Option<String> },
  Busy { request_id: String },
  Target,
}

impl AdminMutationRuntime {
  pub(crate) async fn new(config: &Config, audit: &AdminAuditRuntime) -> anyhow::Result<Self> {
    let mutation_config = &config.admin.mutations;
    if !mutation_config.mode.enabled() {
      return Ok(Self::disabled(&config.ipm.namespace));
    }

    let bindings = mutation_config
      .signers
      .iter()
      .map(load_signer)
      .collect::<anyhow::Result<Vec<_>>>()?;
    let signers = SignerRegistry::new(bindings).map_err(anyhow::Error::new)?;
    let pool = audit
      .critical_postgres_pool()
      .context("Admin mutation ledger requires the enforcing Admin audit PostgreSQL pool")?;
    init_postgres(&pool)
      .await
      .context("failed to initialize Admin mutation PostgreSQL tables")?;
    let store = MutationStore::new(pool, config.shared_state.namespace.clone())?;
    let target = configured_target(config);
    let artifact_cipher = if mutation_config.rollout.mode.is_cluster() {
      Some(MutationArtifactCipher::from_environment(
        &mutation_config.artifact_key_env,
        mutation_config.max_response_bytes,
      )?)
    } else {
      None
    };

    Ok(Self {
      inner: Arc::new(RuntimeInner {
        mode: mutation_config.mode,
        signers,
        store: Some(store),
        namespace: config.ipm.namespace.clone(),
        maximum_validity_seconds: mutation_config.max_validity_seconds,
        maximum_clock_skew_seconds: mutation_config.max_clock_skew_seconds,
        retention_seconds: i64::try_from(mutation_config.retention_seconds)
          .context("Admin mutation retention exceeds the supported range")?,
        target,
        rollout_mode: mutation_config.rollout.mode,
        cluster_id: mutation_config.rollout.cluster_id.clone(),
        members: mutation_config.rollout.members.clone(),
        artifact_cipher,
        cluster_controller: OnceLock::new(),
      }),
    })
  }

  fn disabled(namespace: &str) -> Self {
    Self {
      inner: Arc::new(RuntimeInner {
        mode: AdminMutationMode::Off,
        signers: SignerRegistry::default(),
        store: None,
        namespace: namespace.to_string(),
        maximum_validity_seconds: 1,
        maximum_clock_skew_seconds: 0,
        retention_seconds: 1,
        target: MutationTarget {
          cluster_id: "single".to_string(),
          membership_revision: digest_parts(["single"]),
        },
        rollout_mode: AdminMutationRolloutMode::SingleInstance,
        cluster_id: String::new(),
        members: Vec::new(),
        artifact_cipher: None,
        cluster_controller: OnceLock::new(),
      }),
    }
  }

  pub(crate) fn enabled(&self) -> bool {
    self.inner.mode.enabled()
  }

  pub(crate) fn required(&self) -> bool {
    self.inner.mode.required()
  }

  pub(crate) fn has_envelope(&self, headers: &HeaderMap) -> bool {
    headers.contains_key(MUTATION_HEADER)
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn admit(
    &self,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    authenticated_principal: &str,
    body: &[u8],
    action: &str,
    resource: &str,
    current_revision: &str,
    precondition_revision: &str,
    audit: &AdminAuditHandle,
    audit_runtime: &AdminAuditRuntime,
  ) -> Result<MutationAdmission, MutationAdmissionError> {
    if !self.enabled() {
      return Ok(MutationAdmission::Bypass);
    }
    if !self.has_envelope(headers) {
      return if self.required() {
        Err(
          MutationProtocolError::new(
            MutationProtocolErrorKind::MissingHeader,
            "mutation envelope header is required",
          )
          .into(),
        )
      } else {
        Ok(MutationAdmission::Bypass)
      };
    }

    let store = self.store()?;
    let now_unix_seconds: i64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::bigint")
      .fetch_one(store.pool())
      .await
      .context("failed to read authoritative mutation time")?;
    let path_and_query = uri
      .path_and_query()
      .map(|value| value.as_str())
      .unwrap_or_else(|| uri.path());
    let verified = self.inner.signers.verify(
      headers,
      &TranscriptContext {
        method,
        path_and_query,
        ipm_namespace: &self.inner.namespace,
        authenticated_principal,
        body,
        precondition_revision,
        now_unix_seconds,
        maximum_validity_seconds: self.inner.maximum_validity_seconds,
        maximum_clock_skew_seconds: self.inner.maximum_clock_skew_seconds,
      },
    )?;
    if verified.envelope.unsigned.target != self.inner.target {
      return Ok(MutationAdmission::Conflict(MutationConflict::Target));
    }

    let unsigned = &verified.envelope.unsigned;
    audit.record_mutation_context(
      &unsigned.signer_id,
      action,
      resource,
      &unsigned.expected_previous_revision,
      &unsigned.new_revision,
      &unsigned.content_digest,
      &unsigned.target.cluster_id,
      &unsigned.target.membership_revision,
    );
    let request_id = &verified.envelope.unsigned.request_id;
    let intent = audit.critical_mutation_event(request_id, StatusCode::ACCEPTED, "attempted", None);
    let audit_record_id = audit_runtime
      .persist_critical_mutation(intent)
      .await
      .context("failed to persist critical mutation audit intent")?;
    if let Err(error) = store.delete_expired_terminal_records(128).await {
      tracing::warn!(error = %error, "failed to prune expired Admin mutation receipts");
    }
    if store
      .load_revision(resource)
      .await
      .context("failed to load Admin mutation logical revision")?
      .is_none()
    {
      store
        .initialize_revision(
          resource,
          current_revision,
          EMPTY_DIGEST,
          Some(&self.inner.target.cluster_id),
          Some(&self.inner.target.membership_revision),
        )
        .await
        .context("failed to initialize Admin mutation logical revision")?;
    }
    let logical_revision = store
      .load_revision(resource)
      .await
      .context("failed to reload Admin mutation logical revision")?
      .context("Admin mutation logical revision disappeared")?;
    if unsigned.expected_previous_revision != logical_revision.committed_revision {
      return Ok(MutationAdmission::Conflict(MutationConflict::Revision {
        actual_revision: Some(logical_revision.committed_revision),
      }));
    }
    let claim = MutationClaim {
      request_id: unsigned.request_id.clone(),
      fingerprint: verified.fingerprint,
      principal: authenticated_principal.to_string(),
      signer_id: unsigned.signer_id.clone(),
      action: action.to_string(),
      resource: resource.to_string(),
      expected_previous_revision: unsigned.expected_previous_revision.clone(),
      new_revision: unsigned.new_revision.clone(),
      content_digest: unsigned.content_digest.clone(),
      cluster_id: Some(unsigned.target.cluster_id.clone()),
      membership_revision: Some(unsigned.target.membership_revision.clone()),
      issued_at: unsigned.issued_at.clone(),
      expires_at: unsigned.expires_at.clone(),
      allowed_clock_skew_seconds: i64::try_from(self.inner.maximum_clock_skew_seconds)
        .context("Admin mutation clock skew exceeds the supported range")?,
      retention_seconds: self.inner.retention_seconds,
      audit_record_id,
    };
    Ok(
      match store
        .claim(&claim)
        .await
        .context("failed to claim Admin mutation")?
      {
        ClaimOutcome::Claimed(record) => MutationAdmission::Claimed(MutationExecution {
          request_id: record.request_id,
          new_revision: record.new_revision,
        }),
        ClaimOutcome::Replay(record) => MutationAdmission::Replay(record),
        ClaimOutcome::InProgress(record) => MutationAdmission::InProgress(record),
        ClaimOutcome::RequestConflict => MutationAdmission::Conflict(MutationConflict::RequestId),
        ClaimOutcome::Expired => MutationAdmission::Conflict(MutationConflict::Expired),
        ClaimOutcome::RevisionConflict { actual_revision } => {
          MutationAdmission::Conflict(MutationConflict::Revision { actual_revision })
        }
        ClaimOutcome::RevisionBusy { request_id } => {
          MutationAdmission::Conflict(MutationConflict::Busy { request_id })
        }
        ClaimOutcome::TargetConflict => MutationAdmission::Conflict(MutationConflict::Target),
      },
    )
  }

  pub(crate) async fn load_mutation(
    &self,
    request_id: &str,
  ) -> anyhow::Result<Option<MutationRecord>> {
    match &self.inner.store {
      Some(store) => store.load_mutation(request_id).await,
      None => Ok(None),
    }
  }

  pub(crate) async fn live_instances(&self) -> anyhow::Result<Vec<InstanceHeartbeat>> {
    if self.inner.rollout_mode != AdminMutationRolloutMode::AdminCluster {
      return Ok(Vec::new());
    }
    rollout_store::load_live_members(
      self.store()?,
      &self.inner.cluster_id,
      &self.inner.target.membership_revision,
    )
    .await
  }

  pub(crate) fn configured_members(&self) -> &[String] {
    &self.inner.members
  }

  pub(crate) fn cluster_mode(&self) -> bool {
    self.inner.rollout_mode == AdminMutationRolloutMode::AdminCluster
  }

  #[allow(dead_code)]
  pub(crate) fn initialize_cluster_controller(
    &self,
    config: &Config,
    boot_id: String,
    applied_revision: String,
    applied_digest: String,
  ) -> anyhow::Result<bool> {
    if !self.cluster_mode() {
      return Ok(false);
    }
    let rollout = &config.admin.mutations.rollout;
    let instance_id = std::env::var(&rollout.instance_id_env).with_context(|| {
      format!(
        "Admin cluster instance environment variable {} is not set",
        rollout.instance_id_env
      )
    })?;
    let controller = AdminClusterRolloutController::new(
      self.store()?.clone(),
      RolloutSettings {
        cluster_id: self.inner.cluster_id.clone(),
        membership_revision: self.inner.target.membership_revision.clone(),
        members: self.inner.members.clone(),
        instance_id,
        boot_id,
        build_version: env!("CARGO_PKG_VERSION").to_string(),
        heartbeat_interval: Duration::from_secs(rollout.heartbeat_interval_seconds),
        stale_after: Duration::from_secs(rollout.stale_after_seconds),
        phase_timeout: Duration::from_secs(rollout.phase_timeout_seconds),
        rollback_timeout: Duration::from_secs(rollout.rollback_timeout_seconds),
        canary_observation: Duration::from_secs(rollout.canary_observation_seconds),
      },
      LocalRolloutStatus {
        assigned_revision: None,
        applied_revision,
        applied_digest,
        ready: true,
      },
    )?;
    ensure!(
      controller.cluster_id() == self.inner.target.cluster_id
        && controller.membership_revision() == self.inner.target.membership_revision,
      "Admin cluster controller target does not match the mutation runtime"
    );
    self
      .inner
      .cluster_controller
      .set(controller)
      .map_err(|_| anyhow::anyhow!("Admin cluster controller is already initialized"))?;
    Ok(true)
  }

  #[allow(dead_code)]
  pub(crate) fn installed_cluster_controller(&self) -> Option<AdminClusterRolloutController> {
    self.inner.cluster_controller.get().cloned()
  }

  #[allow(dead_code)]
  pub(crate) fn cluster_rollout_ready(&self) -> bool {
    !self.cluster_mode()
      || self
        .inner
        .cluster_controller
        .get()
        .is_some_and(AdminClusterRolloutController::ready)
  }

  #[allow(dead_code)]
  pub(crate) async fn publish_cluster_artifact(
    &self,
    record: &MutationRecord,
    plaintext: MutationArtifactPlaintext,
  ) -> anyhow::Result<MutationArtifactReceipt> {
    let controller = self.cluster_controller_ref()?;
    ensure_cluster_member(self, controller.instance_id())?;
    let binding = self.artifact_binding(record)?;
    let sealed = self.artifact_cipher()?.seal(&binding, plaintext)?;
    artifact_store::publish(
      self.store()?,
      controller.instance_id(),
      controller.boot_id(),
      &binding,
      &sealed,
    )
    .await
  }

  #[allow(dead_code)]
  pub(crate) async fn fetch_cluster_artifact(
    &self,
    record: &MutationRecord,
  ) -> anyhow::Result<MutationArtifactPlaintext> {
    let controller = self.cluster_controller_ref()?;
    ensure_cluster_member(self, controller.instance_id())?;
    let binding = self.artifact_binding(record)?;
    let cipher = self.artifact_cipher()?;
    let stored = artifact_store::fetch_for_member(
      self.store()?,
      controller.instance_id(),
      controller.boot_id(),
      &binding,
      cipher.maximum_plaintext_bytes(),
    )
    .await?;
    cipher.open(&binding, stored)
  }

  #[allow(dead_code)]
  fn artifact_binding(&self, record: &MutationRecord) -> anyhow::Result<ArtifactBinding> {
    ensure!(
      record.cluster_id.as_deref() == Some(self.inner.target.cluster_id.as_str())
        && record.membership_revision.as_deref()
          == Some(self.inner.target.membership_revision.as_str()),
      "mutation artifact target does not match this runtime"
    );
    ArtifactBinding::from_record(self.store()?.namespace(), record)
  }

  #[allow(dead_code)]
  fn artifact_cipher(&self) -> anyhow::Result<&MutationArtifactCipher> {
    self
      .inner
      .artifact_cipher
      .as_ref()
      .context("encrypted mutation artifacts require admin_cluster rollout mode")
  }

  #[allow(dead_code)]
  fn cluster_controller_ref(&self) -> anyhow::Result<&AdminClusterRolloutController> {
    self
      .inner
      .cluster_controller
      .get()
      .context("Admin cluster controller is not initialized")
  }

  pub(crate) async fn status(&self) -> anyhow::Result<Value> {
    let mut revisions = serde_json::Map::new();
    if let Some(store) = &self.inner.store {
      for resource in ["config", "ipm", "break-glass"] {
        if let Some(revision) = store.load_revision(resource).await? {
          revisions.insert(resource.to_string(), serde_json::to_value(revision)?);
        }
      }
    }
    Ok(json!({
      "enabled": self.enabled(),
      "required": self.required(),
      "target": self.inner.target,
      "logical_revisions": revisions,
    }))
  }

  pub(crate) async fn active_break_glass_activation(
    &self,
    principal: &str,
  ) -> anyhow::Result<Option<BreakGlassActivation>> {
    load_active_break_glass_for_principal(self.store()?, principal).await
  }

  pub(crate) async fn create_break_glass_activation(
    &self,
    mutation_request_id: &str,
    activation_id: &str,
    principal: &str,
    scopes: &[String],
    ttl_seconds: u64,
    maximum_ttl_seconds: u64,
  ) -> anyhow::Result<BreakGlassActivation> {
    if ttl_seconds == 0 || ttl_seconds > maximum_ttl_seconds {
      bail!("break-glass activation TTL is outside the configured bound");
    }
    let ttl = i64::try_from(ttl_seconds).context("break-glass activation TTL is too large")?;
    let store = self.store()?;
    let mut tx = store.pool().begin().await?;
    let expires_at: String =
      sqlx::query_scalar("SELECT (now() + make_interval(secs => $1::double precision))::text")
        .bind(ttl as f64)
        .fetch_one(&mut *tx)
        .await?;
    let activation = create_break_glass_activation_tx(
      &mut tx,
      store.namespace(),
      activation_id,
      principal,
      scopes,
      mutation_request_id,
      &expires_at,
    )
    .await?;
    tx.commit().await?;
    Ok(activation)
  }

  pub(crate) async fn revoke_break_glass_activation(
    &self,
    activation_id: &str,
    principal: &str,
  ) -> anyhow::Result<bool> {
    let store = self.store()?;
    let mut tx = store.pool().begin().await?;
    let revoked =
      revoke_break_glass_activation_tx(&mut tx, store.namespace(), activation_id, principal)
        .await?;
    tx.commit().await?;
    Ok(revoked)
  }

  fn store(&self) -> anyhow::Result<&MutationStore> {
    self
      .inner
      .store
      .as_ref()
      .context("Admin mutation ledger is disabled")
  }
}

#[derive(Debug)]
pub(crate) enum MutationAdmissionError {
  Protocol(MutationProtocolError),
  Runtime(anyhow::Error),
}

impl From<MutationProtocolError> for MutationAdmissionError {
  fn from(value: MutationProtocolError) -> Self {
    Self::Protocol(value)
  }
}

impl From<anyhow::Error> for MutationAdmissionError {
  fn from(value: anyhow::Error) -> Self {
    Self::Runtime(value)
  }
}

impl MutationAdmissionError {
  pub(crate) fn status(&self) -> StatusCode {
    match self {
      Self::Protocol(error) => error.http_status(),
      Self::Runtime(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
  }

  pub(crate) fn code(&self) -> &'static str {
    match self {
      Self::Protocol(error) => error.code(),
      Self::Runtime(_) => "mutation_store_unavailable",
    }
  }
}

impl MutationConflict {
  pub(crate) fn status(&self) -> StatusCode {
    match self {
      Self::Expired => StatusCode::BAD_REQUEST,
      _ => StatusCode::CONFLICT,
    }
  }

  pub(crate) fn code(&self) -> &'static str {
    match self {
      Self::RequestId => "mutation_request_id_conflict",
      Self::Expired => "mutation_expired",
      Self::Revision { .. } => "mutation_revision_conflict",
      Self::Busy { .. } => "mutation_in_progress",
      Self::Target => "mutation_target_conflict",
    }
  }

  pub(crate) fn details(&self) -> Value {
    match self {
      Self::Revision { actual_revision } => json!({ "actual_revision": actual_revision }),
      Self::Busy { request_id } => json!({ "blocking_request_id": request_id }),
      _ => json!({}),
    }
  }
}

fn load_signer(config: &crate::config::AdminMutationSignerConfig) -> anyhow::Result<SignerBinding> {
  let ed25519 = fs::read(&config.ed25519_public_key_file).with_context(|| {
    format!(
      "failed to read Admin mutation Ed25519 public key {}",
      config.ed25519_public_key_file.display()
    )
  })?;
  match config.suite {
    AdminMutationSignatureSuite::Ed25519 => {
      SignerBinding::ed25519(&config.id, &config.principal, ed25519).map_err(anyhow::Error::new)
    }
    AdminMutationSignatureSuite::Ed25519MlDsa44 => {
      #[cfg(feature = "mutation-pqc")]
      {
        let path = config
          .ml_dsa_44_public_key_file
          .as_ref()
          .context("hybrid Admin mutation signer is missing its ML-DSA-44 public key")?;
        let ml_dsa = fs::read(path).with_context(|| {
          format!(
            "failed to read Admin mutation ML-DSA-44 public key {}",
            path.display()
          )
        })?;
        SignerBinding::ed25519_ml_dsa_44(&config.id, &config.principal, ed25519, ml_dsa)
          .map_err(anyhow::Error::new)
      }
      #[cfg(not(feature = "mutation-pqc"))]
      {
        let _ = ed25519;
        bail!("hybrid Admin mutation signer requires the mutation-pqc feature")
      }
    }
  }
}

fn configured_target(config: &Config) -> MutationTarget {
  let rollout = &config.admin.mutations.rollout;
  let cluster_id = if rollout.cluster_id.is_empty() {
    "single".to_string()
  } else {
    rollout.cluster_id.clone()
  };
  let mut digest_fields = vec![cluster_id.as_str(), rollout.instance_id_env.as_str()];
  digest_fields.extend(rollout.members.iter().map(String::as_str));
  let membership_revision = digest_parts(digest_fields);
  MutationTarget {
    cluster_id,
    membership_revision,
  }
}

fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
  let mut hasher = Sha256::new();
  hasher.update(b"OXIBELT-ADMIN-MUTATION-MEMBERSHIP\0");
  for part in parts {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part.as_bytes());
  }
  let mut output = String::with_capacity(71);
  output.push_str("sha256:");
  for byte in hasher.finalize() {
    let _ = write!(output, "{byte:02x}");
  }
  output
}

#[allow(dead_code)]
fn ensure_cluster_member(runtime: &AdminMutationRuntime, instance_id: &str) -> anyhow::Result<()> {
  ensure!(
    runtime.cluster_mode(),
    "Admin mutation runtime is not in admin_cluster mode"
  );
  ensure!(
    runtime
      .inner
      .members
      .iter()
      .any(|member| member == instance_id),
    "instance is not in the configured Admin cluster membership"
  );
  Ok(())
}

#[path = "runtime/terminal.rs"]
mod terminal;
#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
