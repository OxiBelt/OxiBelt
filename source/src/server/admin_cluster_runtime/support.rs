use anyhow::Context;

use crate::admin_mutation::{
  AdminMutationRuntime, FencedTargetTransition, MutationRecord, ResourceHeadUpdate, RolloutTarget,
  TargetState,
};

use super::super::admin_cluster_executor::ExecutionErrorKind;

pub(super) async fn current_target(
  runtime: &AdminMutationRuntime,
  record: &MutationRecord,
  target: &RolloutTarget,
) -> anyhow::Result<RolloutTarget> {
  runtime
    .cluster_targets(&record.request_id)
    .await?
    .into_iter()
    .find(|value| value.instance_id == target.instance_id)
    .context("cluster target disappeared")
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn transition(
  runtime: &AdminMutationRuntime,
  request_id: &str,
  target: &RolloutTarget,
  next_state: TargetState,
  effect_started: bool,
  applied_revision: Option<String>,
  applied_digest: Option<String>,
  restored_revision: Option<String>,
  restored_digest: Option<String>,
  error_code: Option<&str>,
) -> anyhow::Result<()> {
  runtime
    .cluster_transition_target(
      request_id,
      &FencedTargetTransition {
        expected_state: target.state,
        expected_state_version: target.state_version,
        assignment_epoch: target.assignment_epoch,
        next_state,
        effect_started,
        applied_revision,
        applied_digest,
        restored_revision,
        restored_digest,
        error_code: error_code.map(str::to_string),
      },
    )
    .await
}

pub(super) async fn publish_head(
  runtime: &AdminMutationRuntime,
  resource: &str,
  assigned_revision: Option<&str>,
  applied_revision: &str,
  applied_digest: &str,
  ready: bool,
) -> anyhow::Result<()> {
  runtime
    .cluster_publish_resource_head(ResourceHeadUpdate {
      resource: resource.to_string(),
      assigned_revision: assigned_revision.map(str::to_string),
      applied_revision: applied_revision.to_string(),
      applied_digest: applied_digest.to_string(),
      ready,
    })
    .await
}

pub(super) fn error_code(kind: ExecutionErrorKind) -> &'static str {
  match kind {
    ExecutionErrorKind::Rejected => "member_rejected",
    ExecutionErrorKind::Indeterminate => "member_indeterminate",
    ExecutionErrorKind::SharedStagedRequired => "shared_publish_required",
  }
}
