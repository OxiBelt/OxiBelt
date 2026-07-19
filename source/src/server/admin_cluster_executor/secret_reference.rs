//! Fixed-member secret-reference validation and activation evidence.

use crate::admin_mutation::{ClusterAuthorizationCheck, ClusterMutationCommand};
use crate::secret_activation::{
  SecretReferenceField, SecretReferenceUpdateRequest, build_candidate_snapshot,
  validate_update_request,
};
use crate::state::AppHandle;

use super::super::admin_control::{AdminControlHandle, AdminControlResponse};
use super::{ExecutionError, ValidatedOperation, indeterminate, push_check, rejected};

pub(super) async fn validate(
  state: &AppHandle,
  command: &ClusterMutationCommand,
) -> Result<String, ExecutionError> {
  let request = decode(command.body()).map_err(|error| rejected(error.to_string()))?;
  let (request_id, cluster_id, _) = command
    .mutation_identity()
    .map_err(|error| rejected(error.to_string()))?;
  let target_revision = format!("cluster:{cluster_id}:{}", command.new_revision);
  let active = state.snapshot();
  let snapshot = build_candidate_snapshot(
    active.as_ref(),
    &request,
    request_id,
    command.new_revision.clone(),
    target_revision,
    Some(command.new_revision.clone()),
  )
  .await
  .map_err(|error| rejected(error.code()))?;
  Ok(
    snapshot
      .secret_references
      .reference_set_digest()
      .to_string(),
  )
}

pub(super) async fn apply(
  control: &AdminControlHandle,
  operation: &ValidatedOperation,
  if_match: Option<String>,
) -> Result<AdminControlResponse, ExecutionError> {
  let request = decode(&operation.body).map_err(|error| rejected(error.to_string()))?;
  Ok(
    control
      .activate_secret_reference(
        operation.actor.name.clone(),
        if_match,
        operation.mutation_request_id.clone(),
        Some(operation.candidate_revision.clone()),
        Some(operation.validation_digest.clone()),
        request,
      )
      .await,
  )
}

pub(super) fn observe(
  state: &AppHandle,
  operation: &ValidatedOperation,
) -> Result<(), ExecutionError> {
  let current = state.snapshot();
  let binding = current
    .secret_references
    .binding()
    .ok_or_else(|| indeterminate("active secret-reference snapshot is missing rollout binding"))?;
  if binding.reference_set_digest != operation.validation_digest
    || binding.runtime_snapshot_revision != operation.candidate_revision
    || binding.mutation_request_id != operation.mutation_request_id
  {
    return Err(indeterminate(
      "active secret-reference snapshot does not match validated rollout evidence",
    ));
  }
  Ok(())
}

pub(super) fn authorization_checks(
  body: &[u8],
  checks: &mut Vec<ClusterAuthorizationCheck>,
) -> anyhow::Result<()> {
  let request = decode(body)?;
  let field = validate_update_request(&request).map_err(anyhow::Error::new)?;
  push_check(
    checks,
    "config:UpdateSecretReference",
    &format!(
      "secret-reference/{}",
      super::super::admin_resource::component(&request.field)
    ),
  );
  if matches!(field, SecretReferenceField::IpmCredentialBearerTokenEnv(_)) {
    push_check(checks, "ipm:UpdateConfig", "config");
  }
  Ok(())
}

fn decode(body: &[u8]) -> anyhow::Result<SecretReferenceUpdateRequest> {
  serde_json::from_slice(body).map_err(|error| error.into())
}
