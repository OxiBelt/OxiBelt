use anyhow::{Context, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeSet;

use super::fencing_evidence::validate_active_member_evidence;
use super::{HeartbeatUpdate, TargetState};
use crate::admin_mutation::ledger::{MutationState, validate_identifier};
use crate::admin_mutation::store::{MutationStore, StoreRolloutMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct MemberFence {
  pub(crate) cluster_id: String,
  pub(crate) membership_revision: String,
  pub(crate) instance_id: String,
  pub(crate) boot_id: String,
  pub(crate) instance_epoch: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactMembership {
  pub(crate) cluster_id: String,
  pub(crate) membership_revision: String,
  pub(crate) build_version: String,
  pub(crate) capability_version: String,
  pub(crate) artifact_key_fingerprint: String,
  pub(crate) resource: String,
  pub(crate) baseline_revision: String,
  pub(crate) baseline_digest: String,
  pub(crate) members: Vec<MemberFence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoordinatorFence {
  pub(crate) request_id: String,
  pub(crate) member: MemberFence,
  pub(crate) exact_membership: ExactMembership,
  pub(crate) coordinator_epoch: i64,
  pub(crate) mutation_state_version: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct TargetPlan {
  pub(crate) instance_id: String,
  pub(crate) expected_state: TargetState,
  pub(crate) expected_state_version: i64,
  pub(crate) next_state: TargetState,
}

#[derive(Debug, Clone)]
pub(crate) struct RolloutTransitionPlan {
  pub(crate) expected_state: MutationState,
  pub(crate) next_state: Option<MutationState>,
  pub(crate) canary_instance_id: Option<String>,
  pub(crate) phase_timeout_seconds: i32,
  pub(crate) rollback_timeout_seconds: i32,
  pub(crate) targets: Vec<TargetPlan>,
}

#[derive(Debug, Clone)]
pub(crate) struct FencedTargetTransition {
  pub(crate) expected_state: TargetState,
  pub(crate) expected_state_version: i64,
  pub(crate) assignment_epoch: i64,
  pub(crate) next_state: TargetState,
  pub(crate) effect_started: bool,
  pub(crate) validation_revision: Option<String>,
  pub(crate) validation_digest: Option<String>,
  pub(crate) applied_revision: Option<String>,
  pub(crate) applied_digest: Option<String>,
  pub(crate) restored_revision: Option<String>,
  pub(crate) restored_digest: Option<String>,
  pub(crate) error_code: Option<String>,
}

pub(crate) async fn heartbeat_fenced(
  store: &MutationStore,
  update: &HeartbeatUpdate,
) -> anyhow::Result<MemberFence> {
  update.validate()?;
  ensure!(
    store.rollout_mode() == StoreRolloutMode::AdminCluster,
    "fenced heartbeat requires an admin_cluster mutation store"
  );
  let mut tx = store.pool().begin().await?;
  // Staged-membership deployments serialize heartbeat authority with the
  // durable membership head. Fixed-membership deployments have no head row.
  // Taking this lock before the heartbeat row preserves the same lock order as
  // admission and membership cutover.
  let membership_head = sqlx::query(
    "SELECT head.active_epoch_digest,epoch.artifact_key_fingerprint,
            CASE WHEN head.active_epoch_digest IS NULL THEN false ELSE EXISTS(
              SELECT 1 FROM oxibelt_admin_membership_epoch_members member
               WHERE member.namespace=head.namespace AND member.cluster_id=head.cluster_id
                 AND member.epoch_digest=head.active_epoch_digest
                 AND member.instance_id=$3) END AS target_member
       FROM oxibelt_admin_membership_heads head
       LEFT JOIN oxibelt_admin_membership_epochs epoch
         ON epoch.namespace=head.namespace AND epoch.cluster_id=head.cluster_id
        AND epoch.epoch_digest=head.active_epoch_digest
      WHERE head.namespace=$1 AND head.cluster_id=$2 FOR SHARE OF head",
  )
  .bind(store.namespace())
  .bind(&update.cluster_id)
  .bind(&update.instance_id)
  .fetch_optional(&mut *tx)
  .await?;
  let staged_active_epoch = membership_head
    .as_ref()
    .map(|row| row.try_get::<Option<String>, _>("active_epoch_digest"))
    .transpose()?
    .flatten();
  if let Some(active_epoch) = staged_active_epoch.as_deref() {
    ensure!(
      update.membership_revision == active_epoch,
      "member heartbeat targets a superseded membership epoch"
    );
    let head = membership_head
      .as_ref()
      .context("staged membership head disappeared")?;
    ensure!(
      head.try_get::<bool, _>("target_member")?,
      "member heartbeat identity is outside the active membership epoch"
    );
    if let Some(fingerprint) = head.try_get::<Option<String>, _>("artifact_key_fingerprint")? {
      ensure!(
        update.artifact_key_fingerprint == fingerprint,
        "member heartbeat artifact key differs from the active membership epoch"
      );
    }
  }
  let current = sqlx::query(
    "SELECT boot_id, instance_epoch, build_version, capability_version,
            artifact_key_fingerprint, membership_revision,
            lease_expires_at > now() AS live
       FROM oxibelt_admin_instance_heartbeats
      WHERE namespace = $1 AND cluster_id = $2 AND instance_id = $3 FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(&update.cluster_id)
  .bind(&update.instance_id)
  .fetch_optional(&mut *tx)
  .await?;

  let instance_epoch = if let Some(row) = current.as_ref() {
    let current_boot: String = row.try_get("boot_id")?;
    if current_boot == update.boot_id {
      let same_build = row.try_get::<String, _>("build_version")? == update.build_version;
      let same_capability =
        row.try_get::<String, _>("capability_version")? == update.capability_version;
      let same_key = row
        .try_get::<Option<String>, _>("artifact_key_fingerprint")?
        .as_deref()
        == Some(update.artifact_key_fingerprint.as_str());
      let same_membership =
        row.try_get::<String, _>("membership_revision")? == update.membership_revision;
      if !(same_build && same_capability && same_key && same_membership) {
        ensure!(
          !row.try_get::<bool, _>("live")?
            && same_build
            && same_capability
            && staged_active_epoch.as_deref() == Some(update.membership_revision.as_str()),
          "member boot identity changed outside an exact membership cutover"
        );
      }
      row.try_get("instance_epoch")?
    } else {
      ensure!(
        !row.try_get::<bool, _>("live")?,
        "duplicate Admin cluster instance_id has a live boot"
      );
      retire_boot(&mut tx, store, update, &current_boot).await?;
      allocate_epoch(&mut tx, store, update).await?
    }
  } else {
    allocate_epoch(&mut tx, store, update).await?
  };

  let result = sqlx::query(
    "INSERT INTO oxibelt_admin_instance_heartbeats
       (namespace, cluster_id, instance_id, boot_id, instance_epoch, build_version,
        capability_version, artifact_key_fingerprint, membership_revision,
        assigned_revision, applied_revision, applied_digest, ready, lease_expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
             now() + make_interval(secs => $14::double precision))
     ON CONFLICT (namespace, cluster_id, instance_id) DO UPDATE
       SET boot_id = EXCLUDED.boot_id,
           instance_epoch = EXCLUDED.instance_epoch,
           build_version = EXCLUDED.build_version,
           capability_version = EXCLUDED.capability_version,
           artifact_key_fingerprint = EXCLUDED.artifact_key_fingerprint,
           membership_revision = EXCLUDED.membership_revision,
           assigned_revision = EXCLUDED.assigned_revision,
           applied_revision = EXCLUDED.applied_revision,
           applied_digest = EXCLUDED.applied_digest,
           ready = EXCLUDED.ready,
           lease_expires_at = EXCLUDED.lease_expires_at,
           updated_at = now()
     WHERE (oxibelt_admin_instance_heartbeats.boot_id = EXCLUDED.boot_id
            AND oxibelt_admin_instance_heartbeats.instance_epoch = EXCLUDED.instance_epoch)
        OR oxibelt_admin_instance_heartbeats.lease_expires_at <= now()",
  )
  .bind(store.namespace())
  .bind(&update.cluster_id)
  .bind(&update.instance_id)
  .bind(&update.boot_id)
  .bind(instance_epoch)
  .bind(&update.build_version)
  .bind(&update.capability_version)
  .bind(&update.artifact_key_fingerprint)
  .bind(&update.membership_revision)
  .bind(&update.assigned_revision)
  .bind(&update.applied_revision)
  .bind(&update.applied_digest)
  .bind(update.ready)
  .bind(f64::from(update.lease_seconds))
  .execute(&mut *tx)
  .await?;
  ensure!(result.rows_affected() == 1, "member heartbeat was fenced");
  tx.commit().await?;
  Ok(MemberFence {
    cluster_id: update.cluster_id.clone(),
    membership_revision: update.membership_revision.clone(),
    instance_id: update.instance_id.clone(),
    boot_id: update.boot_id.clone(),
    instance_epoch,
  })
}

async fn allocate_epoch(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  update: &HeartbeatUpdate,
) -> anyhow::Result<i64> {
  let reused: bool = sqlx::query_scalar(
    "SELECT EXISTS (SELECT 1 FROM oxibelt_admin_instance_boot_history
      WHERE namespace=$1 AND cluster_id=$2 AND instance_id=$3 AND boot_id=$4)",
  )
  .bind(store.namespace())
  .bind(&update.cluster_id)
  .bind(&update.instance_id)
  .bind(&update.boot_id)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(!reused, "retired Admin cluster boot_id cannot be reused");
  let epoch: i64 = sqlx::query_scalar(
    "SELECT COALESCE(max(instance_epoch),0)+1
       FROM oxibelt_admin_instance_boot_history
      WHERE namespace=$1 AND cluster_id=$2 AND instance_id=$3",
  )
  .bind(store.namespace())
  .bind(&update.cluster_id)
  .bind(&update.instance_id)
  .fetch_one(&mut **tx)
  .await?;
  sqlx::query(
    "INSERT INTO oxibelt_admin_instance_boot_history
       (namespace,cluster_id,instance_id,boot_id,instance_epoch)
     VALUES ($1,$2,$3,$4,$5)",
  )
  .bind(store.namespace())
  .bind(&update.cluster_id)
  .bind(&update.instance_id)
  .bind(&update.boot_id)
  .bind(epoch)
  .execute(&mut **tx)
  .await?;
  Ok(epoch)
}

async fn retire_boot(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  update: &HeartbeatUpdate,
  boot_id: &str,
) -> anyhow::Result<()> {
  sqlx::query(
    "UPDATE oxibelt_admin_instance_boot_history SET retired_at=COALESCE(retired_at,now())
      WHERE namespace=$1 AND cluster_id=$2 AND instance_id=$3 AND boot_id=$4",
  )
  .bind(store.namespace())
  .bind(&update.cluster_id)
  .bind(&update.instance_id)
  .bind(boot_id)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

pub(crate) async fn prove_exact_live_membership(
  store: &MutationStore,
  cluster_id: &str,
  membership_revision: &str,
  expected_members: &[String],
  build_version: &str,
  capability_version: &str,
  artifact_key_fingerprint: &str,
) -> anyhow::Result<ExactMembership> {
  ensure!(
    crate::admin_mutation::artifact::is_sha256_digest(membership_revision)
      && crate::admin_mutation::artifact::is_sha256_digest(artifact_key_fingerprint),
    "membership and artifact-key fingerprints must be canonical SHA-256"
  );
  validate_expected_members(expected_members)?;
  let rows = sqlx::query(
    "SELECT instance_id,boot_id,instance_epoch,membership_revision,build_version,
            capability_version,artifact_key_fingerprint,applied_revision,applied_digest,ready
       FROM oxibelt_admin_instance_heartbeats
      WHERE namespace=$1 AND cluster_id=$2 AND lease_expires_at>now()
      ORDER BY instance_id",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .fetch_all(store.pool())
  .await?;
  let actual = rows
    .iter()
    .map(|row| row.try_get::<String, _>("instance_id"))
    .collect::<Result<Vec<_>, _>>()?;
  ensure!(
    actual == expected_members,
    "live Admin membership is not exact"
  );
  let mut members = Vec::with_capacity(rows.len());
  let mut baseline_revision = None;
  let mut baseline_digest = None;
  for row in rows {
    ensure!(
      row.try_get::<String, _>("membership_revision")? == membership_revision
        && row.try_get::<String, _>("build_version")? == build_version
        && row.try_get::<String, _>("capability_version")? == capability_version
        && row
          .try_get::<Option<String>, _>("artifact_key_fingerprint")?
          .as_deref()
          == Some(artifact_key_fingerprint)
        && row.try_get::<bool, _>("ready")?,
      "Admin cluster member compatibility or readiness mismatch"
    );
    let applied_revision: String = row.try_get("applied_revision")?;
    let applied_digest: String = row.try_get("applied_digest")?;
    ensure!(
      baseline_revision
        .as_deref()
        .is_none_or(|value| value == applied_revision.as_str())
        && baseline_digest
          .as_deref()
          .is_none_or(|value| value == applied_digest.as_str()),
      "Admin cluster members do not share an exact applied baseline"
    );
    baseline_revision.get_or_insert(applied_revision);
    baseline_digest.get_or_insert(applied_digest);
    members.push(MemberFence {
      cluster_id: cluster_id.to_string(),
      membership_revision: membership_revision.to_string(),
      instance_id: row.try_get("instance_id")?,
      boot_id: row.try_get("boot_id")?,
      instance_epoch: row.try_get("instance_epoch")?,
    });
  }
  Ok(ExactMembership {
    cluster_id: cluster_id.to_string(),
    membership_revision: membership_revision.to_string(),
    build_version: build_version.to_string(),
    capability_version: capability_version.to_string(),
    artifact_key_fingerprint: artifact_key_fingerprint.to_string(),
    resource: String::new(),
    baseline_revision: baseline_revision.context("Admin cluster baseline is missing")?,
    baseline_digest: baseline_digest.context("Admin cluster baseline is missing")?,
    members,
  })
}

fn validate_expected_members(members: &[String]) -> anyhow::Result<()> {
  ensure!(
    (2..=1024).contains(&members.len()),
    "Admin cluster must have 2 to 1024 members"
  );
  let mut sorted = BTreeSet::new();
  for member in members {
    validate_identifier("instance_id", member, 256)?;
    ensure!(
      sorted.insert(member.clone()),
      "duplicate Admin cluster member"
    );
  }
  ensure!(
    sorted.into_iter().eq(members.iter().cloned()),
    "Admin cluster members must be sorted"
  );
  Ok(())
}

pub(crate) async fn acquire_coordinator_fence(
  store: &MutationStore,
  request_id: &str,
  member: &MemberFence,
  exact: &ExactMembership,
  lease_seconds: i32,
) -> anyhow::Result<Option<CoordinatorFence>> {
  validate_identifier("request_id", request_id, 256)?;
  ensure!(
    (1..=300).contains(&lease_seconds),
    "coordinator lease must be 1 to 300 seconds"
  );
  ensure!(
    exact.members.contains(member),
    "coordinator member is outside exact membership"
  );
  let mut tx = store.pool().begin().await?;
  lock_exact_membership(&mut tx, store, exact, false).await?;
  let row = sqlx::query(
    "SELECT state,state_version,cluster_id,membership_revision,coordinator_instance_id,
            coordinator_boot_id,coordinator_instance_epoch,coordinator_epoch,
            admission_audit_confirmed_at IS NOT NULL AS admission_audit_confirmed,
            COALESCE(coordinator_lease_expires_at>now(),false) AS coordinator_live
       FROM oxibelt_admin_mutations
      WHERE namespace=$1 AND request_id=$2 AND rollout_mode='admin_cluster' FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(request_id)
  .fetch_optional(&mut *tx)
  .await?
  .context("cluster mutation not found")?;
  let state = MutationState::parse(&row.try_get::<String, _>("state")?)?;
  ensure!(
    row.try_get::<bool, _>("admission_audit_confirmed")?,
    "cluster mutation admission is not externally anchored"
  );
  ensure!(
    !state.is_terminal(),
    "terminal mutation cannot acquire coordinator authority"
  );
  ensure!(
    row.try_get::<Option<String>, _>("cluster_id")?.as_deref() == Some(member.cluster_id.as_str())
      && row
        .try_get::<Option<String>, _>("membership_revision")?
        .as_deref()
        == Some(member.membership_revision.as_str()),
    "coordinator target mismatch"
  );
  validate_active_member_evidence(&mut tx, store, request_id, exact).await?;
  let same = row
    .try_get::<Option<String>, _>("coordinator_instance_id")?
    .as_deref()
    == Some(member.instance_id.as_str())
    && row
      .try_get::<Option<String>, _>("coordinator_boot_id")?
      .as_deref()
      == Some(member.boot_id.as_str())
    && row.try_get::<Option<i64>, _>("coordinator_instance_epoch")? == Some(member.instance_epoch);
  if row.try_get::<bool, _>("coordinator_live")? && !same {
    tx.rollback().await?;
    return Ok(None);
  }
  let current_epoch: i64 = row.try_get("coordinator_epoch")?;
  let epoch = if same && row.try_get::<bool, _>("coordinator_live")? {
    current_epoch
  } else {
    current_epoch
      .checked_add(1)
      .context("coordinator epoch overflow")?
  };
  let state_version: i64 = row.try_get("state_version")?;
  let result = sqlx::query(
    "UPDATE oxibelt_admin_mutations SET coordinator_instance_id=$3,coordinator_boot_id=$4,
            coordinator_instance_epoch=$5,coordinator_epoch=$6,
            coordinator_lease_expires_at=now()+make_interval(secs=>$7::double precision)
      WHERE namespace=$1 AND request_id=$2 AND state_version=$8",
  )
  .bind(store.namespace())
  .bind(request_id)
  .bind(&member.instance_id)
  .bind(&member.boot_id)
  .bind(member.instance_epoch)
  .bind(epoch)
  .bind(f64::from(lease_seconds))
  .bind(state_version)
  .execute(&mut *tx)
  .await?;
  ensure!(
    result.rows_affected() == 1,
    "coordinator acquisition lost its CAS"
  );
  tx.commit().await?;
  Ok(Some(CoordinatorFence {
    request_id: request_id.to_string(),
    member: member.clone(),
    exact_membership: exact.clone(),
    coordinator_epoch: epoch,
    mutation_state_version: state_version,
  }))
}

pub(super) async fn lock_exact_membership(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  exact: &ExactMembership,
  require_baseline: bool,
) -> anyhow::Result<()> {
  let rows = sqlx::query(
    "SELECT instance_id,boot_id,instance_epoch,membership_revision,build_version,
            capability_version,artifact_key_fingerprint,applied_revision,applied_digest,
            ready,lease_expires_at>now() AS live
       FROM oxibelt_admin_instance_heartbeats
      WHERE namespace=$1 AND cluster_id=$2 AND lease_expires_at>now()
      ORDER BY instance_id FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(&exact.cluster_id)
  .fetch_all(&mut **tx)
  .await?;
  ensure!(
    rows.len() == exact.members.len(),
    "live Admin membership changed"
  );
  for (row, expected) in rows.iter().zip(&exact.members) {
    ensure!(
      row.try_get::<String, _>("instance_id")? == expected.instance_id
        && row.try_get::<String, _>("boot_id")? == expected.boot_id
        && row.try_get::<i64, _>("instance_epoch")? == expected.instance_epoch
        && row.try_get::<String, _>("membership_revision")? == exact.membership_revision
        && row.try_get::<String, _>("build_version")? == exact.build_version
        && row.try_get::<String, _>("capability_version")? == exact.capability_version
        && row
          .try_get::<Option<String>, _>("artifact_key_fingerprint")?
          .as_deref()
          == Some(exact.artifact_key_fingerprint.as_str())
        && (!require_baseline
          || (row.try_get::<String, _>("applied_revision")? == exact.baseline_revision
            && row.try_get::<String, _>("applied_digest")? == exact.baseline_digest))
        && row.try_get::<bool, _>("ready")?
        && row.try_get::<bool, _>("live")?,
      "live Admin membership changed"
    );
  }
  Ok(())
}

pub(crate) async fn apply_transition_plan(
  store: &MutationStore,
  fence: &CoordinatorFence,
  plan: &RolloutTransitionPlan,
) -> anyhow::Result<CoordinatorFence> {
  ensure!(
    (1..=3600).contains(&plan.phase_timeout_seconds),
    "phase timeout out of range"
  );
  ensure!(
    (1..=3600).contains(&plan.rollback_timeout_seconds),
    "rollback timeout out of range"
  );
  let mut tx = store.pool().begin().await?;
  let compensating = plan.next_state == Some(MutationState::RollingBack)
    || plan.expected_state == MutationState::RollingBack
    || (!plan.targets.is_empty()
      && plan.targets.iter().all(|target| {
        matches!(
          target.next_state,
          TargetState::RollbackAssigned | TargetState::RollingBack
        )
      }));
  let mutation = lock_coordinator(
    &mut tx,
    store,
    fence,
    Some(plan.expected_state),
    !compensating,
  )
  .await?;
  if let Some(canary) = plan.canary_instance_id.as_deref() {
    let target_ids: Vec<String> = sqlx::query_scalar(
      "SELECT instance_id FROM oxibelt_admin_mutation_targets
        WHERE namespace=$1 AND request_id=$2 ORDER BY instance_id",
    )
    .bind(store.namespace())
    .bind(&fence.request_id)
    .fetch_all(&mut *tx)
    .await?;
    ensure!(
      deterministic_canary(&fence.request_id, &target_ids).as_deref() == Some(canary),
      "rollout canary is not the deterministic fixed-member selection"
    );
    ensure!(
      mutation
        .try_get::<Option<String>, _>("canary_instance_id")?
        .as_deref()
        .is_none_or(|persisted| persisted == canary),
      "rollout canary conflicts with the persisted selection"
    );
  }
  for target in &plan.targets {
    let row = sqlx::query(
      "SELECT state,state_version FROM oxibelt_admin_mutation_targets
        WHERE namespace=$1 AND request_id=$2 AND instance_id=$3 FOR UPDATE",
    )
    .bind(store.namespace())
    .bind(&fence.request_id)
    .bind(&target.instance_id)
    .fetch_optional(&mut *tx)
    .await?
    .context("rollout target missing")?;
    let current = TargetState::parse(&row.try_get::<String, _>("state")?)?;
    ensure!(
      current == target.expected_state
        && row.try_get::<i64, _>("state_version")? == target.expected_state_version,
      "rollout target plan CAS conflict"
    );
    ensure!(
      current.may_transition_to(target.next_state),
      "invalid target plan transition"
    );
    let assignment = matches!(
      target.next_state,
      TargetState::Validating | TargetState::ApplyAssigned
    );
    let result = sqlx::query(
      "UPDATE oxibelt_admin_mutation_targets SET state=$4,state_version=state_version+1,
              assignment_epoch=CASE WHEN $5 THEN $6 ELSE assignment_epoch END,updated_at=now()
        WHERE namespace=$1 AND request_id=$2 AND instance_id=$3 AND state_version=$7",
    )
    .bind(store.namespace())
    .bind(&fence.request_id)
    .bind(&target.instance_id)
    .bind(target.next_state.as_str())
    .bind(assignment)
    .bind(fence.coordinator_epoch)
    .bind(target.expected_state_version)
    .execute(&mut *tx)
    .await?;
    ensure!(
      result.rows_affected() == 1,
      "rollout target plan was fenced"
    );
  }
  let next_version = if let Some(next) = plan.next_state {
    ensure!(
      plan.expected_state.may_transition_to(next),
      "invalid mutation plan transition"
    );
    if let Some(canary) = plan.canary_instance_id.as_deref() {
      validate_identifier("canary_instance_id", canary, 256)?;
    }
    let rollback = next == MutationState::RollingBack;
    let result = sqlx::query(
      "UPDATE oxibelt_admin_mutations SET state=$3,state_version=state_version+1,
              canary_instance_id=COALESCE(canary_instance_id,$4),phase_started_at=now(),
              phase_deadline_at=now()+make_interval(secs=>$5::double precision),
              rollback_deadline_at=CASE WHEN $6 THEN
                now()+make_interval(secs=>$7::double precision) ELSE rollback_deadline_at END,
              updated_at=now()
        WHERE namespace=$1 AND request_id=$2 AND state_version=$8",
    )
    .bind(store.namespace())
    .bind(&fence.request_id)
    .bind(next.as_str())
    .bind(&plan.canary_instance_id)
    .bind(f64::from(plan.phase_timeout_seconds))
    .bind(rollback)
    .bind(f64::from(plan.rollback_timeout_seconds))
    .bind(fence.mutation_state_version)
    .execute(&mut *tx)
    .await?;
    ensure!(
      result.rows_affected() == 1,
      "mutation transition plan was fenced"
    );
    fence.mutation_state_version + 1
  } else {
    fence.mutation_state_version
  };
  tx.commit().await?;
  let mut renewed = fence.clone();
  renewed.mutation_state_version = next_version;
  Ok(renewed)
}

pub(super) async fn lock_coordinator(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  fence: &CoordinatorFence,
  expected_state: Option<MutationState>,
  require_exact_membership: bool,
) -> anyhow::Result<sqlx::postgres::PgRow> {
  if require_exact_membership {
    lock_exact_membership(tx, store, &fence.exact_membership, false).await?;
  }
  let row = sqlx::query(
    "SELECT state,state_version,canary_instance_id FROM oxibelt_admin_mutations WHERE namespace=$1 AND request_id=$2
       AND rollout_mode='admin_cluster' AND coordinator_instance_id=$3
       AND coordinator_boot_id=$4 AND coordinator_instance_epoch=$5 AND coordinator_epoch=$6
       AND coordinator_lease_expires_at>now() FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(&fence.request_id)
  .bind(&fence.member.instance_id)
  .bind(&fence.member.boot_id)
  .bind(fence.member.instance_epoch)
  .bind(fence.coordinator_epoch)
  .fetch_optional(&mut **tx)
  .await?
  .context("coordinator authority was fenced")?;
  if require_exact_membership {
    validate_active_member_evidence(tx, store, &fence.request_id, &fence.exact_membership).await?;
  }
  ensure!(
    row.try_get::<i64, _>("state_version")? == fence.mutation_state_version,
    "coordinator mutation version was fenced"
  );
  if let Some(expected) = expected_state {
    ensure!(
      MutationState::parse(&row.try_get::<String, _>("state")?)? == expected,
      "coordinator mutation state changed"
    );
  }
  Ok(row)
}

fn deterministic_canary(request_id: &str, members: &[String]) -> Option<String> {
  members
    .iter()
    .min_by_key(|member| {
      let mut hasher = Sha256::new();
      hasher.update(b"oxibelt-admin-mutation-canary-v1\0");
      hasher.update(request_id.as_bytes());
      hasher.update(b"\0");
      hasher.update(member.as_bytes());
      hasher.finalize()
    })
    .cloned()
}

pub(super) async fn require_live_member(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  member: &MemberFence,
) -> anyhow::Result<()> {
  let current: Option<i32> = sqlx::query_scalar(
    "SELECT 1 FROM oxibelt_admin_instance_heartbeats WHERE namespace=$1
      AND cluster_id=$2 AND membership_revision=$3 AND instance_id=$4 AND boot_id=$5
      AND instance_epoch=$6 AND ready=true AND lease_expires_at>now() FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(&member.cluster_id)
  .bind(&member.membership_revision)
  .bind(&member.instance_id)
  .bind(&member.boot_id)
  .bind(member.instance_epoch)
  .fetch_optional(&mut **tx)
  .await?;
  ensure!(current.is_some(), "member authority was fenced");
  Ok(())
}
