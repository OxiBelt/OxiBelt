//! Fixed-member rollout targets, instance heartbeats, and coordinator leases.

use std::collections::BTreeSet;

use anyhow::{Context, ensure};
use serde::Serialize;
use sqlx::{Postgres, Row, Transaction};

use super::ledger::{MAX_ERROR_CODE_BYTES, validate_identifier};
use super::store::MutationStore;

const ACQUIRE_COORDINATOR_LEASE_SQL: &str = "UPDATE oxibelt_admin_mutations AS mutation
      SET coordinator_instance_id = $3,
          coordinator_lease_expires_at = now() + make_interval(secs => $4::double precision)
    WHERE mutation.namespace = $1 AND mutation.request_id = $2
      AND mutation.state NOT IN
        ('committed', 'failed', 'rolled_back', 'rollback_failed', 'indeterminate')
      AND (mutation.coordinator_instance_id = $3
           OR mutation.coordinator_lease_expires_at IS NULL
           OR mutation.coordinator_lease_expires_at <= now())
      AND EXISTS (
        SELECT 1 FROM oxibelt_admin_instance_heartbeats heartbeat
         WHERE heartbeat.namespace = mutation.namespace
           AND heartbeat.cluster_id = mutation.cluster_id
           AND heartbeat.membership_revision = mutation.membership_revision
           AND heartbeat.instance_id = $3
           AND heartbeat.ready = true
           AND heartbeat.lease_expires_at > now()
      )
      AND EXISTS (
        SELECT 1 FROM oxibelt_admin_mutation_targets target
         WHERE target.namespace = mutation.namespace
           AND target.request_id = mutation.request_id
           AND target.instance_id = $3
      )";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetState {
  Pending,
  Validating,
  Applying,
  Acked,
  Nacked,
  RollingBack,
  RolledBack,
  RollbackFailed,
}

impl TargetState {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Pending => "pending",
      Self::Validating => "validating",
      Self::Applying => "applying",
      Self::Acked => "acked",
      Self::Nacked => "nacked",
      Self::RollingBack => "rolling_back",
      Self::RolledBack => "rolled_back",
      Self::RollbackFailed => "rollback_failed",
    }
  }

  fn parse(value: &str) -> anyhow::Result<Self> {
    Ok(match value {
      "pending" => Self::Pending,
      "validating" => Self::Validating,
      "applying" => Self::Applying,
      "acked" => Self::Acked,
      "nacked" => Self::Nacked,
      "rolling_back" => Self::RollingBack,
      "rolled_back" => Self::RolledBack,
      "rollback_failed" => Self::RollbackFailed,
      _ => anyhow::bail!("unknown mutation target state"),
    })
  }

  pub(crate) const fn may_transition_to(self, next: Self) -> bool {
    match self {
      Self::Pending => matches!(next, Self::Validating | Self::Nacked),
      Self::Validating => matches!(next, Self::Applying | Self::Nacked),
      Self::Applying => matches!(next, Self::Acked | Self::Nacked | Self::RollingBack),
      Self::Acked => matches!(next, Self::RollingBack),
      Self::Nacked => matches!(next, Self::RollingBack),
      Self::RollingBack => matches!(next, Self::RolledBack | Self::RollbackFailed),
      Self::RolledBack | Self::RollbackFailed => false,
    }
  }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RolloutTarget {
  pub(crate) instance_id: String,
  pub(crate) state: TargetState,
  pub(crate) boot_id: Option<String>,
  pub(crate) applied_revision: Option<String>,
  pub(crate) applied_digest: Option<String>,
  pub(crate) error_code: Option<String>,
  pub(crate) updated_at: String,
}

#[derive(Debug, Clone)]
pub(crate) struct TargetTransition {
  pub(crate) next: TargetState,
  pub(crate) boot_id: Option<String>,
  pub(crate) applied_revision: Option<String>,
  pub(crate) applied_digest: Option<String>,
  pub(crate) error_code: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct HeartbeatUpdate {
  pub(crate) cluster_id: String,
  pub(crate) instance_id: String,
  pub(crate) boot_id: String,
  pub(crate) build_version: String,
  pub(crate) capability_version: String,
  pub(crate) membership_revision: String,
  pub(crate) assigned_revision: Option<String>,
  pub(crate) applied_revision: String,
  pub(crate) applied_digest: String,
  pub(crate) ready: bool,
  pub(crate) lease_seconds: i32,
}

impl HeartbeatUpdate {
  fn validate(&self) -> anyhow::Result<()> {
    for (name, value) in [
      ("cluster_id", self.cluster_id.as_str()),
      ("instance_id", self.instance_id.as_str()),
      ("boot_id", self.boot_id.as_str()),
      ("build_version", self.build_version.as_str()),
      ("capability_version", self.capability_version.as_str()),
      ("membership_revision", self.membership_revision.as_str()),
      ("applied_revision", self.applied_revision.as_str()),
      ("applied_digest", self.applied_digest.as_str()),
    ] {
      validate_identifier(name, value, 256)?;
    }
    if let Some(value) = self.assigned_revision.as_deref() {
      validate_identifier("assigned_revision", value, 256)?;
    }
    ensure!(
      (1..=300).contains(&self.lease_seconds),
      "heartbeat lease must be between 1 and 300 seconds"
    );
    if self.ready {
      ensure!(
        self
          .assigned_revision
          .as_deref()
          .is_none_or(|assigned| assigned == self.applied_revision),
        "ready heartbeat must have applied its assigned revision"
      );
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InstanceHeartbeat {
  pub(crate) cluster_id: String,
  pub(crate) instance_id: String,
  pub(crate) boot_id: String,
  pub(crate) build_version: String,
  pub(crate) capability_version: String,
  pub(crate) membership_revision: String,
  pub(crate) assigned_revision: Option<String>,
  pub(crate) applied_revision: String,
  pub(crate) applied_digest: String,
  pub(crate) ready: bool,
  pub(crate) lease_expires_at: String,
  pub(crate) updated_at: String,
}

pub(crate) async fn register_targets(
  store: &MutationStore,
  request_id: &str,
  instance_ids: &[String],
) -> anyhow::Result<Vec<RolloutTarget>> {
  validate_identifier("request_id", request_id, 256)?;
  let desired = normalized_instances(instance_ids)?;
  let mut tx = store.pool().begin().await?;
  let mutation = sqlx::query(
    "SELECT request_id, cluster_id, membership_revision, state FROM oxibelt_admin_mutations
      WHERE namespace = $1 AND request_id = $2 FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(request_id)
  .fetch_optional(&mut *tx)
  .await?
  .context("mutation record not found")?;
  ensure!(
    mutation
      .try_get::<Option<String>, _>("cluster_id")?
      .is_some()
      && mutation
        .try_get::<Option<String>, _>("membership_revision")?
        .is_some(),
    "rollout targets require a cluster-bound mutation"
  );
  let mutation_state: String = mutation.try_get("state")?;
  ensure!(
    matches!(mutation_state.as_str(), "claimed" | "validating"),
    "rollout targets can only be registered before apply"
  );

  let existing = load_target_ids_tx(&mut tx, store.namespace(), request_id).await?;
  if existing.is_empty() {
    for instance_id in &desired {
      sqlx::query(
        "INSERT INTO oxibelt_admin_mutation_targets
           (namespace, request_id, instance_id)
         VALUES ($1, $2, $3)",
      )
      .bind(store.namespace())
      .bind(request_id)
      .bind(instance_id)
      .execute(&mut *tx)
      .await?;
    }
  } else {
    ensure!(existing == desired, "rollout target membership conflict");
  }
  tx.commit().await?;
  load_targets(store, request_id).await
}

pub(crate) async fn transition_target(
  store: &MutationStore,
  request_id: &str,
  instance_id: &str,
  transition: &TargetTransition,
) -> anyhow::Result<RolloutTarget> {
  let boot_id = transition.boot_id.as_deref();
  let applied_revision = transition.applied_revision.as_deref();
  let applied_digest = transition.applied_digest.as_deref();
  let error_code = transition.error_code.as_deref();
  validate_identifier("request_id", request_id, 256)?;
  validate_identifier("instance_id", instance_id, 256)?;
  for (name, value) in [
    ("boot_id", boot_id),
    ("applied_revision", applied_revision),
    ("applied_digest", applied_digest),
  ] {
    if let Some(value) = value {
      validate_identifier(name, value, 256)?;
    }
  }
  if let Some(error_code) = error_code {
    validate_identifier("error_code", error_code, MAX_ERROR_CODE_BYTES)?;
  }
  let mut tx = store.pool().begin().await?;
  let row = sqlx::query(
    "SELECT target.state, mutation.new_revision, mutation.content_digest,
            heartbeat.boot_id AS heartbeat_boot_id,
            heartbeat.applied_revision AS heartbeat_applied_revision,
            heartbeat.applied_digest AS heartbeat_applied_digest,
            heartbeat.ready AS heartbeat_ready,
            (heartbeat.lease_expires_at > now()) AS heartbeat_live
       FROM oxibelt_admin_mutation_targets target
       JOIN oxibelt_admin_mutations mutation
         ON mutation.namespace = target.namespace AND mutation.request_id = target.request_id
       LEFT JOIN oxibelt_admin_instance_heartbeats heartbeat
         ON heartbeat.namespace = mutation.namespace
        AND heartbeat.cluster_id = mutation.cluster_id
        AND heartbeat.membership_revision = mutation.membership_revision
        AND heartbeat.instance_id = target.instance_id
      WHERE target.namespace = $1 AND target.request_id = $2 AND target.instance_id = $3
      FOR UPDATE OF target",
  )
  .bind(store.namespace())
  .bind(request_id)
  .bind(instance_id)
  .fetch_optional(&mut *tx)
  .await?
  .context("rollout target not found")?;
  let current = TargetState::parse(&row.try_get::<String, _>("state")?)?;
  ensure!(
    current.may_transition_to(transition.next),
    "invalid rollout target transition"
  );
  if transition.next == TargetState::Acked {
    ensure!(boot_id.is_some(), "ACK requires boot_id");
    ensure!(applied_revision.is_some(), "ACK requires applied_revision");
    ensure!(applied_digest.is_some(), "ACK requires applied_digest");
    ensure!(error_code.is_none(), "ACK cannot include error_code");
    let new_revision: String = row.try_get("new_revision")?;
    let content_digest: String = row.try_get("content_digest")?;
    let heartbeat_boot_id: Option<String> = row.try_get("heartbeat_boot_id")?;
    let heartbeat_revision: Option<String> = row.try_get("heartbeat_applied_revision")?;
    let heartbeat_digest: Option<String> = row.try_get("heartbeat_applied_digest")?;
    ensure!(
      applied_revision == Some(new_revision.as_str()),
      "ACK revision does not match the mutation"
    );
    ensure!(
      applied_digest == Some(content_digest.as_str()),
      "ACK digest does not match the mutation"
    );
    ensure!(
      heartbeat_boot_id.as_deref() == boot_id
        && heartbeat_revision.as_deref() == applied_revision
        && heartbeat_digest.as_deref() == applied_digest
        && row
          .try_get::<Option<bool>, _>("heartbeat_ready")?
          .unwrap_or(false)
        && row
          .try_get::<Option<bool>, _>("heartbeat_live")?
          .unwrap_or(false),
      "ACK requires a matching live and ready heartbeat"
    );
  }
  if transition.next == TargetState::Nacked || transition.next == TargetState::RollbackFailed {
    ensure!(
      error_code.is_some(),
      "failed target transition requires error_code"
    );
  }
  sqlx::query(
    "UPDATE oxibelt_admin_mutation_targets
        SET state = $4, boot_id = COALESCE($5, boot_id),
            applied_revision = COALESCE($6, applied_revision),
            applied_digest = COALESCE($7, applied_digest), error_code = $8,
            updated_at = now()
      WHERE namespace = $1 AND request_id = $2 AND instance_id = $3",
  )
  .bind(store.namespace())
  .bind(request_id)
  .bind(instance_id)
  .bind(transition.next.as_str())
  .bind(boot_id)
  .bind(applied_revision)
  .bind(applied_digest)
  .bind(error_code)
  .execute(&mut *tx)
  .await?;
  let row = select_target_tx(&mut tx, store.namespace(), request_id, instance_id).await?;
  tx.commit().await?;
  target_from_row(&row)
}

pub(crate) async fn load_targets(
  store: &MutationStore,
  request_id: &str,
) -> anyhow::Result<Vec<RolloutTarget>> {
  let rows = sqlx::query(
    "SELECT instance_id, state, boot_id, applied_revision, applied_digest,
            error_code, updated_at::text AS updated_at
       FROM oxibelt_admin_mutation_targets
      WHERE namespace = $1 AND request_id = $2 ORDER BY instance_id ASC",
  )
  .bind(store.namespace())
  .bind(request_id)
  .fetch_all(store.pool())
  .await?;
  rows.iter().map(target_from_row).collect()
}

pub(crate) async fn heartbeat(
  store: &MutationStore,
  update: &HeartbeatUpdate,
) -> anyhow::Result<()> {
  update.validate()?;
  sqlx::query(
    "INSERT INTO oxibelt_admin_instance_heartbeats
       (namespace, cluster_id, instance_id, boot_id, build_version,
        capability_version, membership_revision, assigned_revision,
        applied_revision, applied_digest, ready, lease_expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
             now() + make_interval(secs => $12::double precision))
     ON CONFLICT (namespace, cluster_id, instance_id)
     DO UPDATE SET boot_id = EXCLUDED.boot_id,
                   build_version = EXCLUDED.build_version,
                   capability_version = EXCLUDED.capability_version,
                   membership_revision = EXCLUDED.membership_revision,
                   assigned_revision = EXCLUDED.assigned_revision,
                   applied_revision = EXCLUDED.applied_revision,
                   applied_digest = EXCLUDED.applied_digest,
                   ready = EXCLUDED.ready,
                   lease_expires_at = EXCLUDED.lease_expires_at,
                   updated_at = now()",
  )
  .bind(store.namespace())
  .bind(&update.cluster_id)
  .bind(&update.instance_id)
  .bind(&update.boot_id)
  .bind(&update.build_version)
  .bind(&update.capability_version)
  .bind(&update.membership_revision)
  .bind(&update.assigned_revision)
  .bind(&update.applied_revision)
  .bind(&update.applied_digest)
  .bind(update.ready)
  .bind(f64::from(update.lease_seconds))
  .execute(store.pool())
  .await?;
  Ok(())
}

pub(crate) async fn load_live_members(
  store: &MutationStore,
  cluster_id: &str,
  membership_revision: &str,
) -> anyhow::Result<Vec<InstanceHeartbeat>> {
  let rows = sqlx::query(
    "SELECT cluster_id, instance_id, boot_id, build_version, capability_version,
            membership_revision, assigned_revision, applied_revision, applied_digest,
            ready, lease_expires_at::text AS lease_expires_at,
            updated_at::text AS updated_at
       FROM oxibelt_admin_instance_heartbeats
      WHERE namespace = $1 AND cluster_id = $2 AND membership_revision = $3
        AND lease_expires_at > now()
      ORDER BY instance_id ASC",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(membership_revision)
  .fetch_all(store.pool())
  .await?;
  rows.iter().map(heartbeat_from_row).collect()
}

pub(crate) async fn acquire_coordinator_lease(
  store: &MutationStore,
  request_id: &str,
  instance_id: &str,
  lease_seconds: i32,
) -> anyhow::Result<bool> {
  validate_identifier("instance_id", instance_id, 256)?;
  ensure!(
    (1..=300).contains(&lease_seconds),
    "coordinator lease must be between 1 and 300 seconds"
  );
  let result = sqlx::query(ACQUIRE_COORDINATOR_LEASE_SQL)
    .bind(store.namespace())
    .bind(request_id)
    .bind(instance_id)
    .bind(f64::from(lease_seconds))
    .execute(store.pool())
    .await?;
  Ok(result.rows_affected() == 1)
}

fn normalized_instances(instance_ids: &[String]) -> anyhow::Result<Vec<String>> {
  ensure!(
    !instance_ids.is_empty(),
    "rollout requires at least one target"
  );
  ensure!(instance_ids.len() <= 1024, "rollout has too many targets");
  let mut unique = BTreeSet::new();
  for instance_id in instance_ids {
    validate_identifier("instance_id", instance_id, 256)?;
    ensure!(
      unique.insert(instance_id.clone()),
      "duplicate rollout target"
    );
  }
  Ok(unique.into_iter().collect())
}

async fn load_target_ids_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  request_id: &str,
) -> anyhow::Result<Vec<String>> {
  sqlx::query_scalar(
    "SELECT instance_id FROM oxibelt_admin_mutation_targets
      WHERE namespace = $1 AND request_id = $2 ORDER BY instance_id ASC FOR UPDATE",
  )
  .bind(namespace)
  .bind(request_id)
  .fetch_all(&mut **tx)
  .await
  .map_err(Into::into)
}

async fn select_target_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  request_id: &str,
  instance_id: &str,
) -> anyhow::Result<sqlx::postgres::PgRow> {
  sqlx::query(
    "SELECT instance_id, state, boot_id, applied_revision, applied_digest,
            error_code, updated_at::text AS updated_at
       FROM oxibelt_admin_mutation_targets
      WHERE namespace = $1 AND request_id = $2 AND instance_id = $3",
  )
  .bind(namespace)
  .bind(request_id)
  .bind(instance_id)
  .fetch_optional(&mut **tx)
  .await?
  .context("rollout target disappeared")
}

fn target_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<RolloutTarget> {
  Ok(RolloutTarget {
    instance_id: row.try_get("instance_id")?,
    state: TargetState::parse(&row.try_get::<String, _>("state")?)?,
    boot_id: row.try_get("boot_id")?,
    applied_revision: row.try_get("applied_revision")?,
    applied_digest: row.try_get("applied_digest")?,
    error_code: row.try_get("error_code")?,
    updated_at: row.try_get("updated_at")?,
  })
}

fn heartbeat_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<InstanceHeartbeat> {
  Ok(InstanceHeartbeat {
    cluster_id: row.try_get("cluster_id")?,
    instance_id: row.try_get("instance_id")?,
    boot_id: row.try_get("boot_id")?,
    build_version: row.try_get("build_version")?,
    capability_version: row.try_get("capability_version")?,
    membership_revision: row.try_get("membership_revision")?,
    assigned_revision: row.try_get("assigned_revision")?,
    applied_revision: row.try_get("applied_revision")?,
    applied_digest: row.try_get("applied_digest")?,
    ready: row.try_get("ready")?,
    lease_expires_at: row.try_get("lease_expires_at")?,
    updated_at: row.try_get("updated_at")?,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn target_state_machine_requires_validation_and_apply_before_ack() {
    assert!(TargetState::Pending.may_transition_to(TargetState::Validating));
    assert!(TargetState::Validating.may_transition_to(TargetState::Applying));
    assert!(TargetState::Applying.may_transition_to(TargetState::Acked));
    assert!(!TargetState::Pending.may_transition_to(TargetState::Acked));
    assert!(!TargetState::Acked.may_transition_to(TargetState::Applying));
  }

  #[test]
  fn fixed_membership_is_sorted_and_rejects_duplicates() {
    let members = vec!["proxy-b".to_string(), "proxy-a".to_string()];
    assert_eq!(
      normalized_instances(&members).unwrap(),
      vec!["proxy-a".to_string(), "proxy-b".to_string()]
    );
    let duplicate = vec!["proxy-a".to_string(), "proxy-a".to_string()];
    assert!(normalized_instances(&duplicate).is_err());
  }

  #[test]
  fn coordinator_lease_renewal_does_not_reset_the_phase_clock() {
    assert!(!ACQUIRE_COORDINATOR_LEASE_SQL.contains("updated_at"));
  }
}
