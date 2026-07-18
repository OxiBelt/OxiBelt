//! Member-side observation and acknowledgement for centrally published effects.

use anyhow::{Context, ensure};

use crate::admin_mutation::{AdminMutationRuntime, MutationRecord, RolloutTarget, TargetState};
use crate::server::admin_cluster_executor::{
  AdminClusterExecutor, RuntimeSharedPublisher, ValidatedOperation,
};

use super::support::{current_target, publish_head, transition};

const SHARED_OBSERVER_CHECKPOINT: &[u8] = b"OXIBELT-ADMIN-SHARED-OBSERVER-V1";

pub(super) async fn apply_shared_observation(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  record: &MutationRecord,
  target: &RolloutTarget,
  operation: &ValidatedOperation,
) -> anyhow::Result<()> {
  if executor
    .observe_shared(&record.request_id, operation, publisher)
    .await
    .is_err()
  {
    // The coordinator publishes after assigning the canary, so a member may
    // legitimately observe the assignment one poll before the durable marker.
    return Ok(());
  }
  let logical = runtime
    .cluster_logical_revision(&record.resource)
    .await?
    .context("shared logical head is missing")?;
  ensure_observer_checkpoint(runtime, record, target, &logical.content_digest).await?;
  publish_head(
    runtime,
    &record.resource,
    Some(&record.new_revision),
    &record.expected_previous_revision,
    &logical.content_digest,
    false,
  )
  .await?;
  transition(
    runtime,
    &record.request_id,
    target,
    TargetState::Applying,
    true,
    None,
    None,
    None,
    None,
    None,
  )
  .await?;
  publish_head(
    runtime,
    &record.resource,
    Some(&record.new_revision),
    &record.new_revision,
    &record.content_digest,
    true,
  )
  .await?;
  let current = current_target(runtime, record, target).await?;
  transition(
    runtime,
    &record.request_id,
    &current,
    TargetState::Acked,
    false,
    Some(record.new_revision.clone()),
    Some(record.content_digest.clone()),
    None,
    None,
    None,
  )
  .await
}

pub(super) async fn recover_shared(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  record: &MutationRecord,
  target: &RolloutTarget,
  operation: &ValidatedOperation,
) -> anyhow::Result<()> {
  if executor
    .observe_shared(&record.request_id, operation, publisher)
    .await
    .is_ok()
  {
    publish_head(
      runtime,
      &record.resource,
      Some(&record.new_revision),
      &record.new_revision,
      &record.content_digest,
      true,
    )
    .await?;
    return transition(
      runtime,
      &record.request_id,
      target,
      TargetState::Acked,
      false,
      Some(record.new_revision.clone()),
      Some(record.content_digest.clone()),
      None,
      None,
      None,
    )
    .await;
  }
  Ok(())
}

pub(super) async fn observe_shared_rollback(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  record: &MutationRecord,
  target: &RolloutTarget,
  operation: &ValidatedOperation,
) -> anyhow::Result<()> {
  anyhow::ensure!(
    executor
      .observe_shared_restored(&record.request_id, operation, publisher)
      .await
      .map_err(anyhow::Error::new)?,
    "shared prior state is not durably restored"
  );
  let logical = runtime
    .cluster_logical_revision(&record.resource)
    .await?
    .context("shared rollback logical head is unavailable")?;
  let current = if target.state == TargetState::RollbackAssigned {
    transition(
      runtime,
      &record.request_id,
      target,
      TargetState::RollingBack,
      true,
      None,
      None,
      None,
      None,
      None,
    )
    .await?;
    current_target(runtime, record, target).await?
  } else {
    target.clone()
  };
  publish_head(
    runtime,
    &record.resource,
    None,
    &record.expected_previous_revision,
    &logical.content_digest,
    true,
  )
  .await?;
  transition(
    runtime,
    &record.request_id,
    &current,
    TargetState::RolledBack,
    false,
    None,
    None,
    Some(record.expected_previous_revision.clone()),
    Some(logical.content_digest),
    None,
  )
  .await
}

async fn ensure_observer_checkpoint(
  runtime: &AdminMutationRuntime,
  record: &MutationRecord,
  target: &RolloutTarget,
  prior_digest: &str,
) -> anyhow::Result<()> {
  match runtime
    .fetch_cluster_checkpoint(record, target.assignment_epoch)
    .await
  {
    Ok(checkpoint) => {
      ensure!(
        checkpoint.candidate_revision == record.new_revision
          && checkpoint.candidate_digest == record.content_digest
          && checkpoint.prior_revision == record.expected_previous_revision
          && checkpoint.prior_digest == prior_digest,
        "shared observer checkpoint conflicts with its rollout binding"
      );
    }
    Err(_) => {
      runtime
        .publish_cluster_checkpoint(
          record,
          target.assignment_epoch,
          &record.expected_previous_revision,
          prior_digest,
          SHARED_OBSERVER_CHECKPOINT,
        )
        .await?;
      let checkpoint = runtime
        .fetch_cluster_checkpoint(record, target.assignment_epoch)
        .await?;
      ensure!(
        checkpoint.plaintext.as_slice() == SHARED_OBSERVER_CHECKPOINT,
        "shared observer checkpoint replay conflict"
      );
    }
  }
  Ok(())
}
