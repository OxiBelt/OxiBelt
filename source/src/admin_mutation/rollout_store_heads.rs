//! Per-member, per-resource applied-state evidence.

use anyhow::{Context, ensure};
use serde::Serialize;
use sqlx::{Postgres, Row, Transaction};

use super::fencing::{ExactMembership, MemberFence};
use crate::admin_mutation::artifact::is_sha256_digest;
use crate::admin_mutation::ledger::validate_identifier;
use crate::admin_mutation::store::MutationStore;

#[derive(Debug, Clone)]
pub(crate) struct ResourceHeadUpdate {
  pub(crate) resource: String,
  pub(crate) assigned_revision: Option<String>,
  pub(crate) applied_revision: String,
  pub(crate) applied_digest: String,
  pub(crate) ready: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InstanceResourceHead {
  pub(crate) instance_id: String,
  pub(crate) resource: String,
  pub(crate) boot_id: String,
  pub(crate) instance_epoch: i64,
  pub(crate) assigned_revision: Option<String>,
  pub(crate) applied_revision: String,
  pub(crate) applied_digest: String,
  pub(crate) ready: bool,
  pub(crate) updated_at: String,
}

impl ResourceHeadUpdate {
  fn validate(&self) -> anyhow::Result<()> {
    validate_identifier("resource", &self.resource, 256)?;
    validate_identifier("applied_revision", &self.applied_revision, 256)?;
    validate_identifier("applied_digest", &self.applied_digest, 256)?;
    ensure!(
      is_sha256_digest(&self.applied_digest),
      "resource head digest must be canonical SHA-256"
    );
    if let Some(assigned) = self.assigned_revision.as_deref() {
      validate_identifier("assigned_revision", assigned, 256)?;
      ensure!(
        !self.ready || assigned == self.applied_revision,
        "ready resource head has not applied its assignment"
      );
    }
    Ok(())
  }
}

pub(crate) async fn publish_resource_head(
  store: &MutationStore,
  member: &MemberFence,
  update: &ResourceHeadUpdate,
) -> anyhow::Result<()> {
  update.validate()?;
  let mut tx = store.pool().begin().await?;
  require_current_member_boot(&mut tx, store, member).await?;
  let result = sqlx::query(
    "INSERT INTO oxibelt_admin_instance_resource_heads
       (namespace,cluster_id,membership_revision,instance_id,resource,boot_id,instance_epoch,
        assigned_revision,applied_revision,applied_digest,ready)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     ON CONFLICT(namespace,cluster_id,instance_id,resource) DO UPDATE SET
       membership_revision=EXCLUDED.membership_revision,boot_id=EXCLUDED.boot_id,
       instance_epoch=EXCLUDED.instance_epoch,assigned_revision=EXCLUDED.assigned_revision,
       applied_revision=EXCLUDED.applied_revision,applied_digest=EXCLUDED.applied_digest,
       ready=EXCLUDED.ready,updated_at=now()",
  )
  .bind(store.namespace())
  .bind(&member.cluster_id)
  .bind(&member.membership_revision)
  .bind(&member.instance_id)
  .bind(&update.resource)
  .bind(&member.boot_id)
  .bind(member.instance_epoch)
  .bind(&update.assigned_revision)
  .bind(&update.applied_revision)
  .bind(&update.applied_digest)
  .bind(update.ready)
  .execute(&mut *tx)
  .await?;
  ensure!(
    result.rows_affected() == 1,
    "resource head publication was fenced"
  );
  tx.commit().await?;
  Ok(())
}

/// Resource heads are what allow a freshly started member to become ready, so
/// their publication fence intentionally does not require the heartbeat's
/// readiness bit. It still locks the exact live boot and epoch; a retired or
/// otherwise stale process cannot use this bootstrap seam.
async fn require_current_member_boot(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  member: &MemberFence,
) -> anyhow::Result<()> {
  let current: Option<i32> = sqlx::query_scalar(
    "SELECT 1 FROM oxibelt_admin_instance_heartbeats WHERE namespace=$1
      AND cluster_id=$2 AND membership_revision=$3 AND instance_id=$4 AND boot_id=$5
      AND instance_epoch=$6 AND lease_expires_at>now() FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(&member.cluster_id)
  .bind(&member.membership_revision)
  .bind(&member.instance_id)
  .bind(&member.boot_id)
  .bind(member.instance_epoch)
  .fetch_optional(&mut **tx)
  .await?;
  ensure!(current.is_some(), "resource head publisher was fenced");
  Ok(())
}

pub(crate) async fn load_resource_heads(
  store: &MutationStore,
  cluster_id: &str,
  resource: &str,
) -> anyhow::Result<Vec<InstanceResourceHead>> {
  let rows = sqlx::query(
    "SELECT instance_id,resource,boot_id,instance_epoch,assigned_revision,applied_revision,
            applied_digest,ready,updated_at::text AS updated_at
       FROM oxibelt_admin_instance_resource_heads
      WHERE namespace=$1 AND cluster_id=$2 AND resource=$3 ORDER BY instance_id",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(resource)
  .fetch_all(store.pool())
  .await?;
  rows.iter().map(from_row).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn prove_exact_resource_membership(
  store: &MutationStore,
  cluster_id: &str,
  membership_revision: &str,
  expected_members: &[String],
  build_version: &str,
  capability_version: &str,
  artifact_key_fingerprint: &str,
  resource: &str,
) -> anyhow::Result<ExactMembership> {
  validate_identifier("resource", resource, 256)?;
  ensure!(
    is_sha256_digest(membership_revision) && is_sha256_digest(artifact_key_fingerprint),
    "membership and artifact-key fingerprints must be canonical SHA-256"
  );
  ensure!(
    (2..=1024).contains(&expected_members.len()),
    "invalid fixed membership size"
  );
  let rows = sqlx::query(
    "SELECT heartbeat.instance_id,heartbeat.boot_id,heartbeat.instance_epoch,
            heartbeat.membership_revision,heartbeat.build_version,heartbeat.capability_version,
            heartbeat.artifact_key_fingerprint,heartbeat.ready AS member_ready,
            head.applied_revision,head.applied_digest,head.ready AS head_ready
       FROM oxibelt_admin_instance_heartbeats heartbeat
       LEFT JOIN oxibelt_admin_instance_resource_heads head ON head.namespace=heartbeat.namespace
        AND head.cluster_id=heartbeat.cluster_id AND head.instance_id=heartbeat.instance_id
        AND head.resource=$3 AND head.boot_id=heartbeat.boot_id
        AND head.instance_epoch=heartbeat.instance_epoch
      WHERE heartbeat.namespace=$1 AND heartbeat.cluster_id=$2
        AND heartbeat.lease_expires_at>now() ORDER BY heartbeat.instance_id",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(resource)
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
        && row.try_get::<String, _>("artifact_key_fingerprint")? == artifact_key_fingerprint
        && row.try_get::<bool, _>("member_ready")?
        && row.try_get::<Option<bool>, _>("head_ready")? == Some(true),
      "resource member identity, capability, key, or readiness mismatch"
    );
    let revision: String = row.try_get("applied_revision")?;
    let digest: String = row.try_get("applied_digest")?;
    ensure!(
      is_sha256_digest(&digest),
      "resource head contains a malformed digest"
    );
    ensure!(
      baseline_revision
        .as_deref()
        .is_none_or(|value| value == revision.as_str())
        && baseline_digest
          .as_deref()
          .is_none_or(|value| value == digest.as_str()),
      "resource heads do not share an exact baseline"
    );
    baseline_revision.get_or_insert(revision);
    baseline_digest.get_or_insert(digest);
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
    resource: resource.to_string(),
    baseline_revision: baseline_revision.context("resource baseline missing")?,
    baseline_digest: baseline_digest.context("resource baseline missing")?,
    members,
  })
}

pub(super) async fn lock_resource_baseline(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  exact: &ExactMembership,
) -> anyhow::Result<()> {
  ensure!(
    !exact.resource.is_empty(),
    "resource membership proof is required"
  );
  let rows = sqlx::query(
    "SELECT instance_id,boot_id,instance_epoch,membership_revision,applied_revision,
            applied_digest,ready FROM oxibelt_admin_instance_resource_heads
      WHERE namespace=$1 AND cluster_id=$2 AND resource=$3 ORDER BY instance_id FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(&exact.cluster_id)
  .bind(&exact.resource)
  .fetch_all(&mut **tx)
  .await?;
  ensure!(
    rows.len() == exact.members.len(),
    "resource membership changed"
  );
  for (row, member) in rows.iter().zip(&exact.members) {
    ensure!(
      row.try_get::<String, _>("instance_id")? == member.instance_id
        && row.try_get::<String, _>("boot_id")? == member.boot_id
        && row.try_get::<i64, _>("instance_epoch")? == member.instance_epoch
        && row.try_get::<String, _>("membership_revision")? == exact.membership_revision
        && row.try_get::<String, _>("applied_revision")? == exact.baseline_revision
        && row.try_get::<String, _>("applied_digest")? == exact.baseline_digest
        && row.try_get::<bool, _>("ready")?,
      "resource baseline changed"
    );
  }
  Ok(())
}

fn from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<InstanceResourceHead> {
  let applied_digest: String = row.try_get("applied_digest")?;
  ensure!(
    is_sha256_digest(&applied_digest),
    "resource head contains a malformed digest"
  );
  Ok(InstanceResourceHead {
    instance_id: row.try_get("instance_id")?,
    resource: row.try_get("resource")?,
    boot_id: row.try_get("boot_id")?,
    instance_epoch: row.try_get("instance_epoch")?,
    assigned_revision: row.try_get("assigned_revision")?,
    applied_revision: row.try_get("applied_revision")?,
    applied_digest,
    ready: row.try_get("ready")?,
    updated_at: row.try_get("updated_at")?,
  })
}
