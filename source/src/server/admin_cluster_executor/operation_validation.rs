//! Typed operation reconstruction for validation, apply, and recovery.

use zeroize::Zeroizing;

use super::*;

impl AdminClusterExecutor {
  pub(crate) async fn validate(
    &self,
    command: &ClusterMutationCommand,
  ) -> Result<ValidatedOperation, ExecutionError> {
    self.build_validated_operation(command, None).await
  }

  pub(crate) async fn validate_recovery(
    &self,
    command: &ClusterMutationCommand,
    validation_revision: Option<&str>,
    validation_digest: Option<&str>,
  ) -> Result<ValidatedOperation, ExecutionError> {
    self
      .build_validated_operation(command, Some((validation_revision, validation_digest)))
      .await
  }

  async fn build_validated_operation(
    &self,
    command: &ClusterMutationCommand,
    durable_validation: Option<(Option<&str>, Option<&str>)>,
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
    let validation_digest = if kind == OperationKind::SecretReference {
      if let Some((revision, digest)) = durable_validation {
        if revision != Some(command.new_revision.as_str()) {
          return Err(indeterminate(
            "durable secret validation revision does not match the assigned rollout",
          ));
        }
        digest
          .map(str::to_string)
          .ok_or_else(|| indeterminate("durable secret validation digest is unavailable"))?
      } else {
        self
          .validate_candidate(kind, command.body(), permissions, command)
          .await?
          .ok_or_else(|| rejected("secret validation did not produce a reference-set digest"))?
      }
    } else {
      self
        .validate_candidate(kind, command.body(), permissions, command)
        .await?
        .unwrap_or_else(|| candidate_digest.clone())
    };
    let (mutation_request_id, _, _) = command
      .mutation_identity()
      .map_err(|error| rejected(error.to_string()))?;
    Ok(ValidatedOperation {
      kind,
      actor: command.actor.ipm_actor(),
      previous_revision: command.expected_previous_revision.clone(),
      operational_precondition_revision: command.precondition_revision.clone(),
      candidate_revision: command.new_revision.clone(),
      candidate_digest,
      validation_digest,
      mutation_request_id,
      body: Zeroizing::new(command.body().to_vec()),
      permissions,
      file_apply,
      shared,
    })
  }
}
