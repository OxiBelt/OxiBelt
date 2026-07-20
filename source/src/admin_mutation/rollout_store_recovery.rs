//! Recovery scans and guarded cluster terminal transitions.

use anyhow::ensure;
use serde::Serialize;
use sqlx::{Postgres, Row, Transaction};

use super::fencing::{CoordinatorFence, MemberFence, lock_coordinator};
use super::{RolloutTarget, target_from_row};
use crate::admin_mutation::ledger::{MutationRecord, MutationState, TerminalMutation};
use crate::admin_mutation::store::{MutationStore, finish_cluster_tx_authorized};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RecoveryMutation {
  pub(crate) request_id: String,
  pub(crate) state: MutationState,
  pub(crate) state_version: i64,
  pub(crate) coordinator_epoch: i64,
  pub(crate) coordinator_lease_live: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MemberWork {
  pub(crate) request_id: String,
  pub(crate) resource: String,
  pub(crate) new_revision: String,
  pub(crate) content_digest: String,
  pub(crate) target: RolloutTarget,
}

pub(crate) async fn release_member_fence(
  store: &MutationStore,
  fence: &MemberFence,
) -> anyhow::Result<bool> {
  let result = sqlx::query(
    "UPDATE oxibelt_admin_instance_heartbeats SET ready=false, lease_expires_at=now(),
            updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND membership_revision=$3
        AND instance_id=$4 AND boot_id=$5 AND instance_epoch=$6",
  )
  .bind(store.namespace())
  .bind(&fence.cluster_id)
  .bind(&fence.membership_revision)
  .bind(&fence.instance_id)
  .bind(&fence.boot_id)
  .bind(fence.instance_epoch)
  .execute(store.pool())
  .await?;
  Ok(result.rows_affected() == 1)
}

pub(crate) async fn load_recoverable_mutations(
  store: &MutationStore,
  limit: i64,
) -> anyhow::Result<Vec<RecoveryMutation>> {
  ensure!((1..=1024).contains(&limit), "recovery limit out of range");
  let rows = sqlx::query(
    "SELECT request_id,state,state_version,coordinator_epoch,
            COALESCE(coordinator_lease_expires_at>now(),false) AS coordinator_lease_live
       FROM oxibelt_admin_mutations WHERE namespace=$1 AND rollout_mode='admin_cluster'
        AND admission_audit_confirmed_at IS NOT NULL
        AND state NOT IN('committed','failed','rolled_back','rollback_failed','indeterminate')
      ORDER BY updated_at,request_id LIMIT $2",
  )
  .bind(store.namespace())
  .bind(limit)
  .fetch_all(store.pool())
  .await?;
  rows
    .iter()
    .map(|row| {
      Ok(RecoveryMutation {
        request_id: row.try_get("request_id")?,
        state: MutationState::parse(&row.try_get::<String, _>("state")?)?,
        state_version: row.try_get("state_version")?,
        coordinator_epoch: row.try_get("coordinator_epoch")?,
        coordinator_lease_live: row.try_get("coordinator_lease_live")?,
      })
    })
    .collect()
}

pub(crate) async fn load_member_work(
  store: &MutationStore,
  member: &MemberFence,
  limit: i64,
) -> anyhow::Result<Vec<MemberWork>> {
  ensure!(
    (1..=1024).contains(&limit),
    "member work limit out of range"
  );
  let rows = sqlx::query(
    "SELECT mutation.request_id,mutation.resource,mutation.new_revision,mutation.content_digest,
            target.instance_id,target.state,target.state_version,target.assignment_epoch,target.boot_id,
            target.instance_epoch,target.effect_started_at::text AS effect_started_at,
            target.applied_revision,target.applied_digest,target.restored_revision,target.restored_digest,
            target.error_code,target.updated_at::text AS updated_at
       FROM oxibelt_admin_mutation_targets target JOIN oxibelt_admin_mutations mutation USING(namespace,request_id)
      WHERE target.namespace=$1 AND target.instance_id=$2 AND mutation.cluster_id=$3
        AND mutation.membership_revision=$4 AND mutation.rollout_mode='admin_cluster'
        AND mutation.admission_audit_confirmed_at IS NOT NULL
        AND mutation.state NOT IN('committed','failed','rolled_back','rollback_failed','indeterminate')
        AND target.state IN('validating','apply_assigned','applying','rollback_assigned','rolling_back')
      ORDER BY target.updated_at,mutation.request_id LIMIT $5",
  )
  .bind(store.namespace())
  .bind(&member.instance_id)
  .bind(&member.cluster_id)
  .bind(&member.membership_revision)
  .bind(limit)
  .fetch_all(store.pool())
  .await?;
  rows
    .iter()
    .map(|row| {
      Ok(MemberWork {
        request_id: row.try_get("request_id")?,
        resource: row.try_get("resource")?,
        new_revision: row.try_get("new_revision")?,
        content_digest: row.try_get("content_digest")?,
        target: target_from_row(row)?,
      })
    })
    .collect()
}

pub(crate) async fn guarded_cluster_finish_tx(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  fence: &CoordinatorFence,
  terminal: &TerminalMutation,
) -> anyhow::Result<MutationRecord> {
  terminal.validate()?;
  let require_exact = terminal.state == MutationState::Committed;
  let row = lock_coordinator(tx, store, fence, None, require_exact).await?;
  let current = MutationState::parse(&row.try_get::<String, _>("state")?)?;
  match terminal.state {
    MutationState::Committed => verify_commit(tx, store, fence, current).await?,
    MutationState::Failed => verify_not_applied(tx, store, fence).await?,
    MutationState::RolledBack => verify_restored(tx, store, fence).await?,
    MutationState::RollbackFailed | MutationState::Indeterminate => {}
    _ => anyhow::bail!("unsupported cluster terminal state"),
  }
  finish_cluster_tx_authorized(tx, store.namespace(), &fence.request_id, terminal).await
}

async fn verify_commit(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  fence: &CoordinatorFence,
  current: MutationState,
) -> anyhow::Result<()> {
  ensure!(
    current == MutationState::FullyApplied,
    "cluster commit requires fully_applied state"
  );
  let target_count: i64 = sqlx::query_scalar(
    "SELECT count(*) FROM oxibelt_admin_mutation_targets WHERE namespace=$1 AND request_id=$2",
  )
  .bind(store.namespace())
  .bind(&fence.request_id)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(
    (2..=1024).contains(&target_count),
    "cluster commit target set is incomplete"
  );
  let invalid: i64 = sqlx::query_scalar(
    "SELECT count(*) FROM oxibelt_admin_mutation_targets target
      JOIN oxibelt_admin_mutations mutation USING(namespace,request_id)
      LEFT JOIN oxibelt_admin_instance_heartbeats heartbeat ON heartbeat.namespace=target.namespace
       AND heartbeat.cluster_id=mutation.cluster_id AND heartbeat.instance_id=target.instance_id
      LEFT JOIN oxibelt_admin_instance_resource_heads head ON head.namespace=target.namespace
       AND head.cluster_id=mutation.cluster_id AND head.instance_id=target.instance_id
       AND head.resource=mutation.resource AND head.boot_id=heartbeat.boot_id
       AND head.instance_epoch=heartbeat.instance_epoch
     WHERE target.namespace=$1 AND target.request_id=$2 AND (target.state<>'acked'
       OR target.applied_revision<>mutation.new_revision OR target.applied_digest<>mutation.content_digest
       OR heartbeat.boot_id<>target.boot_id OR heartbeat.instance_epoch<>target.instance_epoch
       OR heartbeat.ready=false OR heartbeat.membership_revision<>mutation.membership_revision
       OR heartbeat.lease_expires_at<=now() OR head.ready IS DISTINCT FROM true
       OR head.applied_revision IS DISTINCT FROM mutation.new_revision
       OR head.applied_digest IS DISTINCT FROM mutation.content_digest)",
  ).bind(store.namespace()).bind(&fence.request_id).fetch_one(&mut **tx).await?;
  ensure!(invalid == 0, "cluster commit lacks exact live ACK evidence");
  let unexpected: bool = sqlx::query_scalar(
    "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_instance_heartbeats heartbeat
      JOIN oxibelt_admin_mutations mutation ON mutation.namespace=heartbeat.namespace
       AND mutation.cluster_id=heartbeat.cluster_id WHERE mutation.namespace=$1
       AND mutation.request_id=$2 AND heartbeat.lease_expires_at>now()
       AND (heartbeat.membership_revision<>mutation.membership_revision OR NOT EXISTS(
         SELECT 1 FROM oxibelt_admin_mutation_targets target WHERE target.namespace=mutation.namespace
          AND target.request_id=mutation.request_id AND target.instance_id=heartbeat.instance_id)))",
  ).bind(store.namespace()).bind(&fence.request_id).fetch_one(&mut **tx).await?;
  ensure!(!unexpected, "cluster commit membership is not exact");
  Ok(())
}

async fn verify_not_applied(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  fence: &CoordinatorFence,
) -> anyhow::Result<()> {
  let started: bool = sqlx::query_scalar(
    "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_mutation_targets
      WHERE namespace=$1 AND request_id=$2 AND effect_started_at IS NOT NULL)",
  )
  .bind(store.namespace())
  .bind(&fence.request_id)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(!started, "failed is unsafe after a target may have applied");
  Ok(())
}

async fn verify_restored(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  fence: &CoordinatorFence,
) -> anyhow::Result<()> {
  let invalid: bool = sqlx::query_scalar(
    "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_mutation_targets target
      JOIN oxibelt_admin_mutations mutation USING(namespace,request_id)
      JOIN oxibelt_admin_mutation_revisions revision ON revision.namespace=mutation.namespace
       AND revision.resource=mutation.resource
      LEFT JOIN oxibelt_admin_instance_resource_heads head ON head.namespace=target.namespace
       AND head.cluster_id=mutation.cluster_id AND head.instance_id=target.instance_id
       AND head.resource=mutation.resource AND head.boot_id=target.boot_id
       AND head.instance_epoch=target.instance_epoch
      WHERE target.namespace=$1 AND target.request_id=$2
       AND target.effect_started_at IS NOT NULL AND (target.state<>'rolled_back'
         OR target.restored_revision<>mutation.expected_previous_revision
         OR target.restored_digest<>revision.content_digest OR head.ready IS DISTINCT FROM true
         OR head.applied_revision IS DISTINCT FROM mutation.expected_previous_revision
         OR head.applied_digest IS DISTINCT FROM revision.content_digest))",
  )
  .bind(store.namespace())
  .bind(&fence.request_id)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(
    !invalid,
    "cluster rollback lacks exact restoration evidence"
  );
  Ok(())
}
