//! Canonical binding between a validated member operation and its checkpoint.

use super::{AdminApplyMode, OperationKind, ValidatedOperation};
use crate::server::admin_control::checkpoint::{CheckpointBinding, CheckpointOperation};

pub(super) fn checkpoint_binding(
  operation: &ValidatedOperation,
  previous_digest: String,
) -> CheckpointBinding {
  CheckpointBinding {
    operation: checkpoint_operation(operation.kind),
    principal: operation.actor.principal.clone(),
    actor_name: operation.actor.name.clone(),
    admin_update_config: operation.permissions.admin_update_config,
    ipm_update_config: operation.permissions.ipm_update_config,
    runtime_rollback: operation.kind != OperationKind::FileSync
      || operation.file_apply != Some(AdminApplyMode::None),
    previous_revision: operation.previous_revision.clone(),
    previous_digest,
    candidate_revision: operation.candidate_revision.clone(),
    candidate_digest: operation.candidate_digest.clone(),
  }
}

fn checkpoint_operation(kind: OperationKind) -> CheckpointOperation {
  match kind {
    OperationKind::ConfigLoad => CheckpointOperation::ConfigLoad,
    OperationKind::ConfigRollback => CheckpointOperation::ConfigRollback,
    OperationKind::FileSync => CheckpointOperation::FileSync,
    OperationKind::DownstreamTlsReload => CheckpointOperation::DownstreamTlsReload,
    OperationKind::KeyRotation => CheckpointOperation::KeyRotation,
    OperationKind::SecretReference => CheckpointOperation::SecretReference,
    OperationKind::SharedStaged => CheckpointOperation::ConfigLoad,
  }
}
