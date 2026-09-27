//! Durable evidence validation for fenced Admin-cluster transitions.

use anyhow::ensure;
use sqlx::{Postgres, Transaction};

use super::fencing::ExactMembership;
use crate::admin_mutation::store::MutationStore;

pub(super) async fn validate_active_member_evidence(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  request_id: &str,
  exact: &ExactMembership,
) -> anyhow::Result<()> {
  let target_count: i64 = sqlx::query_scalar(
    "SELECT count(*) FROM oxibelt_admin_mutation_targets
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(store.namespace())
  .bind(request_id)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(
    usize::try_from(target_count).ok() == Some(exact.members.len()),
    "active rollout target membership is not exact"
  );
  let invalid: i64 = sqlx::query_scalar(
    "SELECT count(*) FROM oxibelt_admin_mutation_targets target
      JOIN oxibelt_admin_mutations mutation USING(namespace,request_id)
      JOIN oxibelt_admin_instance_heartbeats heartbeat ON heartbeat.namespace=target.namespace
       AND heartbeat.cluster_id=mutation.cluster_id AND heartbeat.instance_id=target.instance_id
      LEFT JOIN oxibelt_admin_instance_resource_heads head ON head.namespace=target.namespace
       AND head.cluster_id=mutation.cluster_id AND head.instance_id=target.instance_id
       AND head.resource=mutation.resource AND head.boot_id=heartbeat.boot_id
       AND head.instance_epoch=heartbeat.instance_epoch
     WHERE target.namespace=$1 AND target.request_id=$2 AND CASE
       WHEN target.state IN('pending','validating','validated','apply_assigned')
         THEN head.applied_revision IS DISTINCT FROM mutation.expected_previous_revision
           OR head.applied_digest IS DISTINCT FROM $3 OR head.ready IS DISTINCT FROM true
       WHEN target.state='acked'
         THEN head.applied_revision IS DISTINCT FROM mutation.new_revision
           OR head.applied_digest IS DISTINCT FROM mutation.content_digest
           OR head.ready IS DISTINCT FROM true
       WHEN target.state='rolled_back'
         THEN head.applied_revision IS DISTINCT FROM mutation.expected_previous_revision
           OR head.applied_digest IS DISTINCT FROM $3 OR head.ready IS DISTINCT FROM true
       WHEN target.state IN('applying','nacked','rollback_assigned','rolling_back','rollback_failed')
         THEN NOT ((head.applied_revision=mutation.expected_previous_revision
                    AND head.applied_digest=$3)
                OR (head.applied_revision=mutation.new_revision
                    AND head.applied_digest=mutation.content_digest))
       ELSE true END",
  )
  .bind(store.namespace())
  .bind(request_id)
  .bind(&exact.baseline_digest)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(
    invalid == 0,
    "active rollout member evidence is inconsistent"
  );
  Ok(())
}
