//! Executor-facing shared publication, observation, and restore operations.

use crate::admin_mutation::CoordinatorFence;

use super::{
  AdminClusterExecutor, ExecutionError, ExecutionEvidence, SharedPublishResult,
  SharedStagedPublisher, ValidatedOperation, candidate_evidence, indeterminate,
  shared_staged_required,
};

impl AdminClusterExecutor {
  pub(crate) async fn publish_shared(
    &self,
    operation: &ValidatedOperation,
    fence: &CoordinatorFence,
    publisher: &dyn SharedStagedPublisher,
  ) -> Result<SharedPublishResult, ExecutionError> {
    let shared = operation
      .shared
      .as_ref()
      .ok_or_else(shared_staged_required)?;
    let result = publisher
      .publish_once(fence, &operation.actor, shared)
      .await
      .map_err(|error| indeterminate(error.to_string()))?;
    if result.revision != operation.candidate_revision
      || result.digest != operation.candidate_digest
    {
      return Err(indeterminate(
        "shared publisher returned conflicting revision evidence",
      ));
    }
    Ok(result)
  }

  pub(crate) async fn observe_shared(
    &self,
    request_id: &str,
    operation: &ValidatedOperation,
    publisher: &dyn SharedStagedPublisher,
  ) -> Result<ExecutionEvidence, ExecutionError> {
    let shared = operation
      .shared
      .as_ref()
      .ok_or_else(shared_staged_required)?;
    if publisher
      .observe(request_id, shared)
      .await
      .map_err(|error| indeterminate(error.to_string()))?
    {
      Ok(candidate_evidence(operation))
    } else {
      Err(indeterminate(
        "shared state does not expose the exact committed revision and digest",
      ))
    }
  }

  pub(crate) async fn rollback_shared(
    &self,
    operation: &ValidatedOperation,
    fence: &CoordinatorFence,
    publisher: &dyn SharedStagedPublisher,
  ) -> Result<ExecutionEvidence, ExecutionError> {
    let shared = operation
      .shared
      .as_ref()
      .ok_or_else(shared_staged_required)?;
    let result = publisher
      .restore_once(fence, &operation.actor, shared)
      .await
      .map_err(|error| indeterminate(error.to_string()))?;
    Ok(ExecutionEvidence {
      revision: result.revision,
      digest: result.digest,
    })
  }

  pub(crate) async fn observe_shared_restored(
    &self,
    request_id: &str,
    operation: &ValidatedOperation,
    publisher: &dyn SharedStagedPublisher,
  ) -> Result<bool, ExecutionError> {
    let shared = operation
      .shared
      .as_ref()
      .ok_or_else(shared_staged_required)?;
    publisher
      .observe_restored(request_id, shared)
      .await
      .map_err(|error| indeterminate(error.to_string()))
  }
}
