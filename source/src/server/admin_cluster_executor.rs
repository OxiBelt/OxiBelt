use anyhow::{Context, bail, ensure};
use http::{Method, StatusCode};
use std::fmt;
use zeroize::Zeroizing;

use crate::admin_mutation::{
  ClusterAuthorizationCheck, ClusterExecutionModel, ClusterMutationCommand,
};
use crate::config::Config;
use crate::ipm::IpmActor;
use crate::reload::{reload_downstream_tls_paths, validate_full_reload_runtime_compatibility};
use crate::state::AppHandle;

use super::admin_control::checkpoint::{CheckpointOperation, MutationCheckpoint};
use super::admin_control::{
  self, AdminApplyMode, AdminConfigPayload, AdminControlHandle, AdminFilesSyncRequest,
  ControlPlaneConfigPermissions, validate_control_plane_config_scope,
};
use super::admin_resource;

mod checkpoint_binding;
use checkpoint_binding::checkpoint_binding;
mod file_authorization;
use file_authorization::derive_file_checks;
mod key_rotation;
use key_rotation::{decode_key_rotation, validate_key_rotation_state};
mod shared_staged;
use shared_staged::decode_shared_operation;
pub(crate) use shared_staged::{
  BreakGlassStagedMutation, SharedPublishResult, SharedStagedOperation, SharedStagedPublisher,
};
mod shared_publisher;
pub(crate) use shared_publisher::RuntimeSharedPublisher;
mod shared_api;

#[derive(Clone)]
pub(crate) struct AdminClusterExecutor {
  state: AppHandle,
  control: AdminControlHandle,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum OperationKind {
  ConfigLoad,
  ConfigRollback,
  FileSync,
  DownstreamTlsReload,
  KeyRotation,
  SharedStaged,
}

#[derive(Clone)]
pub(crate) struct ValidatedOperation {
  kind: OperationKind,
  actor: IpmActor,
  previous_revision: String,
  operational_precondition_revision: String,
  candidate_revision: String,
  candidate_digest: String,
  body: Zeroizing<Vec<u8>>,
  permissions: ControlPlaneConfigPermissions,
  file_apply: Option<AdminApplyMode>,
  shared: Option<SharedStagedOperation>,
}

impl fmt::Debug for ValidatedOperation {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ValidatedOperation")
      .field("kind", &self.kind)
      .field("previous_revision", &self.previous_revision)
      .field(
        "operational_precondition_revision",
        &self.operational_precondition_revision,
      )
      .field("candidate_revision", &self.candidate_revision)
      .field("candidate_digest", &self.candidate_digest)
      .field("body_len", &self.body.len())
      .finish_non_exhaustive()
  }
}

impl ValidatedOperation {
  pub(crate) fn candidate_evidence(&self) -> ExecutionEvidence {
    candidate_evidence(self)
  }

  pub(crate) fn is_shared_staged(&self) -> bool {
    self.kind == OperationKind::SharedStaged
  }

  pub(crate) fn is_token_producing_shared(&self) -> bool {
    self
      .shared
      .as_ref()
      .is_some_and(SharedStagedOperation::token_producing)
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ExecutionEvidence {
  pub(crate) revision: String,
  pub(crate) digest: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct PreviousEvidence {
  pub(crate) revision: String,
  pub(crate) digest: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum RecoveryOutcome {
  CandidateApplied(ExecutionEvidence),
  PreviousRestored(ExecutionEvidence),
  SharedStaged(SharedStagedOperation),
  Indeterminate(String),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ExecutionErrorKind {
  Rejected,
  Indeterminate,
  SharedStagedRequired,
}

#[derive(Debug)]
pub(crate) struct ExecutionError {
  pub(crate) kind: ExecutionErrorKind,
  message: String,
}

impl fmt::Display for ExecutionError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::error::Error for ExecutionError {}

impl AdminClusterExecutor {
  pub(crate) fn new(state: AppHandle, control: AdminControlHandle) -> Self {
    Self { state, control }
  }

  pub(crate) async fn validate(
    &self,
    command: &ClusterMutationCommand,
  ) -> Result<ValidatedOperation, ExecutionError> {
    let path = command.path_and_query.split('?').next().unwrap_or_default();
    let (kind, checks, file_apply) =
      derive_operation(&command.method, path, command.body(), &command.principal)
        .map_err(|error| rejected(error.to_string()))?;
    if !command.authorization.matches_checks(&checks) {
      return Err(rejected(
        "authenticated authorization evidence does not match the recovered Admin operation",
      ));
    }
    if path.starts_with("/admin/v1/break-glass/") && !command.actor.authenticated_with_break_glass {
      return Err(rejected(
        "break-glass mutation requires authenticated break-glass credential evidence",
      ));
    }
    if (kind == OperationKind::SharedStaged)
      != (command.execution_model == ClusterExecutionModel::SharedStaged)
    {
      return Err(rejected(
        "cluster execution model does not match the typed operation",
      ));
    }
    let permissions = ControlPlaneConfigPermissions {
      admin_update_config: command.authorization.admin_update_config,
      ipm_update_config: command.authorization.ipm_update_config,
    };
    let candidate_digest = command.signed_content_digest();
    let shared = if kind == OperationKind::SharedStaged {
      let (evidence, _) =
        decode_shared_operation(&command.method, path, command.body(), &command.principal)
          .map_err(|error| rejected(error.to_string()))?;
      Some(evidence.attach(command, path, &candidate_digest))
    } else {
      None
    };
    self
      .validate_candidate(kind, command.body(), permissions)
      .await?;
    Ok(ValidatedOperation {
      kind,
      actor: command.actor.ipm_actor(),
      previous_revision: command.expected_previous_revision.clone(),
      operational_precondition_revision: command.precondition_revision.clone(),
      candidate_revision: command.new_revision.clone(),
      candidate_digest,
      body: Zeroizing::new(command.body().to_vec()),
      permissions,
      file_apply,
      shared,
    })
  }

  pub(crate) async fn checkpoint(
    &self,
    operation: &ValidatedOperation,
    previous: &PreviousEvidence,
  ) -> Result<MutationCheckpoint, ExecutionError> {
    if operation.kind == OperationKind::SharedStaged {
      return Err(shared_staged_required());
    }
    if previous.revision != operation.previous_revision {
      return Err(indeterminate(
        "durable logical head does not match the assigned previous revision",
      ));
    }
    self
      .require_revision(&operation.operational_precondition_revision)
      .await?;
    let snapshot = self.state.snapshot();
    let files = if operation.kind == OperationKind::FileSync {
      let request =
        decode_file_sync(&operation.body).map_err(|error| rejected(error.to_string()))?;
      admin_control::file_sync::capture_cluster_before_images(&request, &snapshot.config)
        .map_err(|error| rejected(error.to_string()))?
    } else {
      Vec::new()
    };
    MutationCheckpoint::new(
      checkpoint_binding(operation, previous.digest.clone()),
      snapshot.as_ref().clone(),
      files,
    )
    .map_err(|error| rejected(error.to_string()))
  }

  pub(crate) fn decode_checkpoint(
    &self,
    operation: &ValidatedOperation,
    plaintext: Zeroizing<Vec<u8>>,
    integrity_digest: &str,
    previous_digest: &str,
  ) -> Result<MutationCheckpoint, ExecutionError> {
    if operation.is_shared_staged() {
      return Err(shared_staged_required());
    }
    MutationCheckpoint::decode_authenticated(
      checkpoint_binding(operation, previous_digest.to_string()),
      plaintext,
      integrity_digest,
    )
    .map_err(|error| indeterminate(error.to_string()))
  }

  pub(crate) async fn apply(
    &self,
    operation: &ValidatedOperation,
    checkpoint: &MutationCheckpoint,
  ) -> Result<ExecutionEvidence, ExecutionError> {
    self.verify_checkpoint(operation, checkpoint)?;
    self
      .require_revision(&operation.operational_precondition_revision)
      .await?;
    let if_match = Some(quoted_revision(
      &operation.operational_precondition_revision,
    ));
    let response = match operation.kind {
      OperationKind::ConfigLoad => {
        let payload = decode_config_load(&operation.body).map_err(|e| rejected(e.to_string()))?;
        self
          .control
          .load_config(
            operation.actor.name.clone(),
            operation.permissions,
            if_match,
            payload.config,
          )
          .await
      }
      OperationKind::ConfigRollback => {
        self
          .control
          .rollback_config(
            operation.actor.name.clone(),
            operation.permissions,
            if_match,
          )
          .await
      }
      OperationKind::FileSync => {
        let request = decode_file_sync(&operation.body).map_err(|e| rejected(e.to_string()))?;
        self
          .control
          .sync_files(
            operation.actor.name.clone(),
            operation.permissions,
            if_match,
            request,
          )
          .await
      }
      OperationKind::DownstreamTlsReload | OperationKind::KeyRotation => {
        self
          .control
          .reload_downstream_tls(operation.actor.name.clone(), if_match)
          .await
      }
      OperationKind::SharedStaged => return Err(shared_staged_required()),
    };
    require_success(response.status, &response.body)?;
    self
      .observe(operation, &candidate_evidence(operation))
      .await
  }

  pub(crate) async fn observe(
    &self,
    operation: &ValidatedOperation,
    evidence: &ExecutionEvidence,
  ) -> Result<ExecutionEvidence, ExecutionError> {
    if evidence != &candidate_evidence(operation) {
      return Err(indeterminate(
        "candidate evidence does not match its assigned command",
      ));
    }
    match operation.kind {
      OperationKind::ConfigLoad => {
        let payload = decode_config_load(&operation.body).map_err(|e| rejected(e.to_string()))?;
        let current = self.state.snapshot();
        let candidate = Config::load_admin_inline_toml(&payload.config, &current.config)
          .map_err(|error| indeterminate(error.to_string()))?;
        if current.config != candidate {
          return Err(indeterminate(
            "active configuration does not match the applied candidate",
          ));
        }
      }
      OperationKind::FileSync => {}
      OperationKind::KeyRotation => validate_key_rotation_state(&self.state, &operation.body)
        .map_err(|error| indeterminate(error.to_string()))?,
      OperationKind::ConfigRollback | OperationKind::DownstreamTlsReload => {}
      OperationKind::SharedStaged => return Err(shared_staged_required()),
    }
    Ok(evidence.clone())
  }

  pub(crate) async fn rollback(
    &self,
    checkpoint: &MutationCheckpoint,
  ) -> Result<ExecutionEvidence, ExecutionError> {
    if matches!(
      checkpoint.binding().operation,
      CheckpointOperation::DownstreamTlsReload | CheckpointOperation::KeyRotation
    ) {
      return Err(indeterminate(
        "TLS reload state has no exact reversible before-image; rollback cannot be proven",
      ));
    }
    if checkpoint.binding().operation == CheckpointOperation::FileSync {
      let current = self.state.snapshot();
      admin_control::file_sync::restore_cluster_before_images(checkpoint.files(), &current.config)
        .map_err(|error| indeterminate(error.to_string()))?;
    }
    if checkpoint.binding().runtime_rollback {
      let current = current_etag(&self.control).await?;
      let response = self
        .control
        .rollback_config(
          checkpoint.binding().actor_name.clone(),
          ControlPlaneConfigPermissions {
            admin_update_config: checkpoint.binding().admin_update_config,
            ipm_update_config: checkpoint.binding().ipm_update_config,
          },
          Some(current),
        )
        .await;
      if !response.status.is_success() {
        return Err(indeterminate(
          response
            .body
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("checkpoint rollback could not be proven"),
        ));
      }
    }
    if checkpoint
      .snapshot()
      .is_some_and(|snapshot| self.state.snapshot().config != snapshot.config)
    {
      return Err(indeterminate(
        "rollback did not restore the checkpointed configuration",
      ));
    }
    Ok(ExecutionEvidence {
      revision: checkpoint.binding().previous_revision.clone(),
      digest: checkpoint.binding().previous_digest.clone(),
    })
  }

  pub(crate) async fn recover(
    &self,
    checkpoint: &MutationCheckpoint,
    command: &ClusterMutationCommand,
  ) -> RecoveryOutcome {
    let operation = match self.validate(command).await {
      Ok(operation) => operation,
      Err(error) => return RecoveryOutcome::Indeterminate(error.to_string()),
    };
    if let Err(error) = self.verify_checkpoint(&operation, checkpoint) {
      return RecoveryOutcome::Indeterminate(error.to_string());
    }
    if operation.kind == OperationKind::SharedStaged {
      return operation.shared.map_or_else(
        || RecoveryOutcome::Indeterminate("shared operation was not decoded".to_string()),
        RecoveryOutcome::SharedStaged,
      );
    }
    if operation.kind == OperationKind::FileSync {
      let current = self.state.snapshot();
      if admin_control::file_sync::verify_cluster_file_state(
        checkpoint.files(),
        &current.config,
        true,
      )
      .is_ok()
      {
        return RecoveryOutcome::CandidateApplied(candidate_evidence(&operation));
      }
      if admin_control::file_sync::verify_cluster_file_state(
        checkpoint.files(),
        &current.config,
        false,
      )
      .is_ok()
        && checkpoint
          .snapshot()
          .is_none_or(|snapshot| current.config == snapshot.config)
      {
        return RecoveryOutcome::PreviousRestored(previous_evidence(checkpoint));
      }
      return RecoveryOutcome::Indeterminate(
        "file state matches neither candidate nor authenticated before-image".to_string(),
      );
    }
    if matches!(
      operation.kind,
      OperationKind::DownstreamTlsReload | OperationKind::KeyRotation
    ) {
      return RecoveryOutcome::Indeterminate(
        "TLS reload state cannot be reconstructed after an interrupted external side effect"
          .to_string(),
      );
    }
    if checkpoint
      .snapshot()
      .is_some_and(|snapshot| self.state.snapshot().config == snapshot.config)
    {
      RecoveryOutcome::PreviousRestored(previous_evidence(checkpoint))
    } else {
      RecoveryOutcome::Indeterminate(
        "runtime state cannot prove candidate application or checkpoint restoration".to_string(),
      )
    }
  }

  async fn validate_candidate(
    &self,
    kind: OperationKind,
    body: &[u8],
    permissions: ControlPlaneConfigPermissions,
  ) -> Result<(), ExecutionError> {
    let active = self.state.snapshot();
    match kind {
      OperationKind::ConfigLoad => {
        let payload = decode_config_load(body).map_err(|error| rejected(error.to_string()))?;
        let candidate = Config::load_admin_inline_toml(&payload.config, &active.config)
          .map_err(|error| rejected(error.to_string()))?;
        candidate
          .validate()
          .map_err(|error| rejected(error.to_string()))?;
        validate_control_plane_config_scope(permissions, &active.config, &candidate)
          .map_err(|response| rejected(response.body.to_string()))?;
        validate_full_reload_runtime_compatibility(&active.config, &candidate)
          .map_err(|error| rejected(error.to_string()))?;
      }
      OperationKind::ConfigRollback => {
        if self.control.status().await["rollback_available"] != true {
          return Err(rejected("no rollback snapshot is available"));
        }
      }
      OperationKind::FileSync => {
        let request = decode_file_sync(body).map_err(|error| rejected(error.to_string()))?;
        admin_control::file_sync::capture_cluster_before_images(&request, &active.config)
          .map_err(|error| rejected(error.to_string()))?;
      }
      OperationKind::DownstreamTlsReload => {
        let mut config = active.config.clone();
        reload_downstream_tls_paths(&mut config).map_err(|error| rejected(error.to_string()))?;
      }
      OperationKind::KeyRotation => validate_key_rotation_state(&self.state, body)
        .map_err(|error| rejected(error.to_string()))?,
      OperationKind::SharedStaged => {}
    }
    Ok(())
  }

  fn verify_checkpoint(
    &self,
    operation: &ValidatedOperation,
    checkpoint: &MutationCheckpoint,
  ) -> Result<(), ExecutionError> {
    checkpoint
      .verify_binding(&checkpoint_binding(
        operation,
        checkpoint.binding().previous_digest.clone(),
      ))
      .map_err(|error| indeterminate(error.to_string()))
  }

  async fn require_revision(&self, expected: &str) -> Result<(), ExecutionError> {
    let actual = current_etag(&self.control).await?;
    if actual.trim_matches('"') == expected {
      Ok(())
    } else {
      Err(rejected(
        "active revision does not match the assigned rollout",
      ))
    }
  }
}

fn derive_operation(
  method: &Method,
  path: &str,
  body: &[u8],
  principal: &str,
) -> anyhow::Result<(
  OperationKind,
  Vec<ClusterAuthorizationCheck>,
  Option<AdminApplyMode>,
)> {
  if !path.starts_with("/admin/v1/ipm/") && !path.starts_with("/admin/v1/break-glass/") {
    ensure!(
      *method == Method::POST,
      "per-member cluster mutation must use POST"
    );
  }
  let mut checks = Vec::new();
  let (kind, file_apply) = match path {
    "/admin/v1/config/load" => {
      push_check(&mut checks, "config:Load", "*");
      (OperationKind::ConfigLoad, None)
    }
    "/admin/v1/config/rollback" => {
      push_check(&mut checks, "config:Rollback", "*");
      (OperationKind::ConfigRollback, None)
    }
    "/admin/v1/tls/downstream/reload" => {
      push_check(&mut checks, "config:ReloadDownstreamTls", "*");
      (OperationKind::DownstreamTlsReload, None)
    }
    "/admin/v1/keys/rotate" => {
      let request = decode_key_rotation(body)?;
      push_check(
        &mut checks,
        "config:RotateKey",
        &format!(
          "key/{}/{}",
          request.target.as_str(),
          admin_resource::component(request.name.as_deref().unwrap_or("default"))
        ),
      );
      (OperationKind::KeyRotation, None)
    }
    "/admin/v1/files/sync" => {
      let request = decode_file_sync(body)?;
      derive_file_checks(&request, &mut checks)?;
      (OperationKind::FileSync, Some(request.apply))
    }
    "/admin/v1/config/secret-references/update" => {
      bail!("secret_reference_activation_unavailable")
    }
    value if value.starts_with("/admin/v1/ipm/") || value.starts_with("/admin/v1/break-glass/") => {
      let (_, derived) = decode_shared_operation(method, value, body, principal)?;
      checks = derived;
      (OperationKind::SharedStaged, None)
    }
    _ => bail!("route is not eligible for fixed-member Admin rollout"),
  };
  checks.sort();
  checks.dedup();
  Ok((kind, checks, file_apply))
}

pub(crate) fn authorization_checks(
  method: &Method,
  path: &str,
  body: &[u8],
  principal: &str,
) -> anyhow::Result<Vec<ClusterAuthorizationCheck>> {
  derive_operation(method, path, body, principal).map(|(_, checks, _)| checks)
}

fn push_check(checks: &mut Vec<ClusterAuthorizationCheck>, action: &str, resource: &str) {
  checks.push(ClusterAuthorizationCheck {
    action: action.to_string(),
    resource: resource.to_string(),
  });
}

fn decode_config_load(body: &[u8]) -> anyhow::Result<AdminConfigPayload> {
  let payload: AdminConfigPayload =
    serde_json::from_slice(body).context("invalid config load body")?;
  ensure!(payload.format == "toml", "format must be toml");
  ensure!(
    payload.config.len() <= admin_control::ADMIN_CONFIG_BODY_LIMIT,
    "config payload is too large"
  );
  Ok(payload)
}

fn decode_file_sync(body: &[u8]) -> anyhow::Result<AdminFilesSyncRequest> {
  serde_json::from_slice(body).context("invalid file sync body")
}

async fn current_etag(control: &AdminControlHandle) -> Result<String, ExecutionError> {
  control.status().await["etag"]
    .as_str()
    .map(str::to_string)
    .ok_or_else(|| indeterminate("Admin control revision is unavailable"))
}

fn quoted_revision(revision: &str) -> String {
  format!("\"{revision}\"")
}
fn candidate_evidence(operation: &ValidatedOperation) -> ExecutionEvidence {
  ExecutionEvidence {
    revision: operation.candidate_revision.clone(),
    digest: operation.candidate_digest.clone(),
  }
}
fn previous_evidence(checkpoint: &MutationCheckpoint) -> ExecutionEvidence {
  ExecutionEvidence {
    revision: checkpoint.binding().previous_revision.clone(),
    digest: checkpoint.binding().previous_digest.clone(),
  }
}

fn require_success(status: StatusCode, body: &serde_json::Value) -> Result<(), ExecutionError> {
  if status.is_success() {
    return Ok(());
  }
  let message = body
    .get("error")
    .and_then(|value| value.as_str())
    .unwrap_or("Admin control operation failed");
  if status == StatusCode::SERVICE_UNAVAILABLE {
    Err(indeterminate(message))
  } else {
    Err(rejected(message))
  }
}

fn rejected(message: impl Into<String>) -> ExecutionError {
  ExecutionError {
    kind: ExecutionErrorKind::Rejected,
    message: message.into(),
  }
}
fn indeterminate(message: impl Into<String>) -> ExecutionError {
  ExecutionError {
    kind: ExecutionErrorKind::Indeterminate,
    message: message.into(),
  }
}
fn shared_staged_required() -> ExecutionError {
  ExecutionError {
    kind: ExecutionErrorKind::SharedStagedRequired,
    message: "shared Admin mutation requires the durable staged-state publisher".to_string(),
  }
}

#[cfg(test)]
mod tests;
