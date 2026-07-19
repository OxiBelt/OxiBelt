//! Member-fenced target evidence transitions.

use anyhow::{Context, ensure};
use sqlx::Row;

use super::fencing::{FencedTargetTransition, MemberFence, require_live_member};
use super::{RolloutTarget, TargetState, target_from_row};
use crate::admin_mutation::ledger::validate_identifier;
use crate::admin_mutation::store::MutationStore;

pub(crate) async fn transition_target_fenced(
  store: &MutationStore,
  member: &MemberFence,
  request_id: &str,
  transition: &FencedTargetTransition,
) -> anyhow::Result<RolloutTarget> {
  ensure!(
    transition
      .expected_state
      .may_transition_to(transition.next_state),
    "invalid fenced target transition"
  );
  for (name, value) in [
    (
      "validation_revision",
      transition.validation_revision.as_deref(),
    ),
    ("validation_digest", transition.validation_digest.as_deref()),
    ("applied_revision", transition.applied_revision.as_deref()),
    ("applied_digest", transition.applied_digest.as_deref()),
    ("restored_revision", transition.restored_revision.as_deref()),
    ("restored_digest", transition.restored_digest.as_deref()),
    ("error_code", transition.error_code.as_deref()),
  ] {
    if let Some(value) = value {
      validate_identifier(name, value, 256)?;
    }
  }
  let mut tx = store.pool().begin().await?;
  require_live_member(&mut tx, store, member).await?;
  let row = sqlx::query(
    "SELECT target.*,mutation.resource,mutation.new_revision,mutation.content_digest,
            mutation.expected_previous_revision,revision.content_digest AS prior_digest
       FROM oxibelt_admin_mutation_targets target
       JOIN oxibelt_admin_mutations mutation USING(namespace,request_id)
       JOIN oxibelt_admin_mutation_revisions revision
         ON revision.namespace=mutation.namespace AND revision.resource=mutation.resource
      WHERE target.namespace=$1 AND target.request_id=$2 AND target.instance_id=$3 FOR UPDATE OF target",
  ).bind(store.namespace()).bind(request_id).bind(&member.instance_id)
    .fetch_optional(&mut *tx).await?.context("assigned rollout target missing")?;
  ensure!(
    TargetState::parse(&row.try_get::<String, _>("state")?)? == transition.expected_state
      && row.try_get::<i64, _>("state_version")? == transition.expected_state_version
      && row.try_get::<i64, _>("assignment_epoch")? == transition.assignment_epoch,
    "target assignment was fenced"
  );
  if transition.next_state == TargetState::Validated {
    let validation_revision = transition
      .validation_revision
      .as_deref()
      .context("validated target must provide its runtime revision")?;
    let validation_digest = transition
      .validation_digest
      .as_deref()
      .context("validated target must provide its reference-set digest")?;
    ensure!(
      validation_revision == row.try_get::<String, _>("new_revision")?,
      "validated target runtime revision does not match the durable mutation"
    );
    ensure!(
      validation_digest.len() == 71
        && validation_digest.starts_with("sha256:")
        && validation_digest[7..]
          .bytes()
          .all(|byte| { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }),
      "validated target reference-set digest is invalid"
    );
  }
  if matches!(
    transition.next_state,
    TargetState::Applying | TargetState::RollingBack
  ) {
    ensure!(
      transition.effect_started,
      "side-effect transitions must durably mark effect_started"
    );
    let checkpoint: bool = sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_mutation_checkpoints checkpoint
        WHERE checkpoint.namespace=$1 AND checkpoint.request_id=$2 AND checkpoint.instance_id=$3
          AND checkpoint.assignment_epoch=$4
          AND checkpoint.candidate_revision=$5 AND checkpoint.candidate_digest=$6
          AND checkpoint.prior_revision=$7 AND checkpoint.prior_digest=$8)",
    )
    .bind(store.namespace())
    .bind(request_id)
    .bind(&member.instance_id)
    .bind(transition.assignment_epoch)
    .bind(row.try_get::<String, _>("new_revision")?)
    .bind(row.try_get::<String, _>("content_digest")?)
    .bind(row.try_get::<String, _>("expected_previous_revision")?)
    .bind(row.try_get::<String, _>("prior_digest")?)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
      checkpoint,
      "side-effect transition requires a bound rollback checkpoint"
    );
  }
  if transition.next_state == TargetState::Acked {
    verify_evidence(
      store,
      &mut tx,
      member,
      TargetEvidence {
        revision: transition.applied_revision.as_deref(),
        digest: transition.applied_digest.as_deref(),
        resource: &row.try_get::<String, _>("resource")?,
        expected_revision: &row.try_get::<String, _>("new_revision")?,
        expected_digest: &row.try_get::<String, _>("content_digest")?,
        kind: "ACK",
      },
    )
    .await?;
  }
  if transition.next_state == TargetState::RolledBack {
    verify_evidence(
      store,
      &mut tx,
      member,
      TargetEvidence {
        revision: transition.restored_revision.as_deref(),
        digest: transition.restored_digest.as_deref(),
        resource: &row.try_get::<String, _>("resource")?,
        expected_revision: &row.try_get::<String, _>("expected_previous_revision")?,
        expected_digest: &row.try_get::<String, _>("prior_digest")?,
        kind: "rollback",
      },
    )
    .await?;
  }
  if matches!(
    transition.next_state,
    TargetState::Nacked | TargetState::RollbackFailed
  ) {
    ensure!(
      transition.error_code.is_some(),
      "failure transition requires an error code"
    );
  }
  let result = sqlx::query(
    "UPDATE oxibelt_admin_mutation_targets SET state=$4,state_version=state_version+1,
            boot_id=$5,instance_epoch=$6,
            effect_started_at=CASE WHEN $7 THEN COALESCE(effect_started_at,now()) ELSE effect_started_at END,
            validation_revision=COALESCE($8,validation_revision),
            validation_digest=COALESCE($9,validation_digest),
            applied_revision=COALESCE($10,applied_revision),applied_digest=COALESCE($11,applied_digest),
            restored_revision=COALESCE($12,restored_revision),restored_digest=COALESCE($13,restored_digest),
            error_code=$14,updated_at=now()
      WHERE namespace=$1 AND request_id=$2 AND instance_id=$3 AND state_version=$15",
  ).bind(store.namespace()).bind(request_id).bind(&member.instance_id).bind(transition.next_state.as_str())
    .bind(&member.boot_id).bind(member.instance_epoch).bind(transition.effect_started)
    .bind(&transition.validation_revision).bind(&transition.validation_digest)
    .bind(&transition.applied_revision).bind(&transition.applied_digest)
    .bind(&transition.restored_revision).bind(&transition.restored_digest).bind(&transition.error_code)
    .bind(transition.expected_state_version).execute(&mut *tx).await?;
  ensure!(result.rows_affected() == 1, "target transition was fenced");
  let selected = sqlx::query(
    "SELECT instance_id,state,state_version,assignment_epoch,boot_id,instance_epoch,
            effect_started_at::text AS effect_started_at,validation_revision,validation_digest,
            applied_revision,applied_digest,
            restored_revision,restored_digest,error_code,updated_at::text AS updated_at
       FROM oxibelt_admin_mutation_targets WHERE namespace=$1 AND request_id=$2 AND instance_id=$3",
  )
  .bind(store.namespace())
  .bind(request_id)
  .bind(&member.instance_id)
  .fetch_one(&mut *tx)
  .await?;
  tx.commit().await?;
  target_from_row(&selected)
}

struct TargetEvidence<'a> {
  revision: Option<&'a str>,
  digest: Option<&'a str>,
  resource: &'a str,
  expected_revision: &'a str,
  expected_digest: &'a str,
  kind: &'static str,
}

async fn verify_evidence(
  store: &MutationStore,
  tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
  member: &MemberFence,
  evidence: TargetEvidence<'_>,
) -> anyhow::Result<()> {
  ensure!(
    evidence.revision == Some(evidence.expected_revision)
      && evidence.digest == Some(evidence.expected_digest),
    "{} evidence does not match the durable mutation",
    evidence.kind
  );
  let (head_revision, head_digest): (String, String) = sqlx::query_as(
    "SELECT applied_revision,applied_digest FROM oxibelt_admin_instance_resource_heads
      WHERE namespace=$1 AND cluster_id=$2 AND instance_id=$3 AND boot_id=$4
        AND instance_epoch=$5 AND resource=$6 AND ready=true",
  )
  .bind(store.namespace())
  .bind(&member.cluster_id)
  .bind(&member.instance_id)
  .bind(&member.boot_id)
  .bind(member.instance_epoch)
  .bind(evidence.resource)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(
    evidence.revision == Some(head_revision.as_str())
      && evidence.digest == Some(head_digest.as_str()),
    "{} evidence does not match the live member resource head",
    evidence.kind
  );
  Ok(())
}
