//! Local PostgreSQL chain and checkpoint outbox state.

use anyhow::{Context, ensure};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};

use super::{
  AUDIT_CHECKPOINT_FORMAT_VERSION, AUDIT_CHECKPOINT_GENESIS_DIGEST,
  AUDIT_CHECKPOINT_SIGNING_ALGORITHM, AuditCheckpointBodyV1, SignedAuditCheckpointV1,
};
use crate::admin_audit::AdminAuditEvent;

#[derive(Debug, Clone)]
pub(crate) struct AnchorStreamIdentity {
  pub(crate) namespace: String,
  pub(crate) stream_id: String,
  pub(crate) instance_id: String,
  pub(crate) cluster_id: Option<String>,
  pub(crate) membership_epoch: String,
  pub(crate) deployment_epoch: String,
  pub(crate) signing_key_id: String,
  pub(crate) record_interval: u64,
  pub(crate) time_interval_ms: u64,
  pub(crate) max_pending_checkpoints: u64,
  pub(crate) max_pending_bytes: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct AnchorOutboxEntry {
  pub(crate) ordinal: u64,
  pub(crate) body: AuditCheckpointBodyV1,
  pub(crate) signed: Option<SignedAuditCheckpointV1>,
}

#[derive(Debug, Clone)]
pub(crate) enum AnchorCandidateOutcome {
  Pending,
  Sealed(Box<AnchorOutboxEntry>),
  CapacityExceeded,
}

pub(crate) async fn initialize_local_anchor(pool: &sqlx::Pool<Postgres>) -> anyhow::Result<()> {
  for statement in [
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_audit_anchor_state (
       namespace text NOT NULL,
       stream_id text NOT NULL,
       instance_id text NOT NULL,
       checkpoint_ordinal bigint NOT NULL DEFAULT 0,
       previous_checkpoint_digest text NOT NULL,
       candidate_chain_id text NULL,
       candidate_cluster_id text NULL,
       candidate_membership_epoch text NULL,
       candidate_deployment_epoch text NULL,
       candidate_signing_key_id text NULL,
       candidate_first_sequence bigint NULL,
       candidate_last_sequence bigint NULL,
       candidate_chain_head text NULL,
       candidate_wall_timestamp text NULL,
       candidate_started_at timestamptz NULL,
       candidate_events bigint NOT NULL DEFAULT 0,
       last_anchored_checkpoint_ordinal bigint NOT NULL DEFAULT 0,
       last_anchored_chain_id text NULL,
       last_anchored_sequence bigint NULL,
       updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
       PRIMARY KEY(namespace, stream_id)
     )",
    "CREATE TABLE IF NOT EXISTS oxibelt_admin_audit_anchor_outbox (
       namespace text NOT NULL,
       stream_id text NOT NULL,
       checkpoint_ordinal bigint NOT NULL,
       body jsonb NOT NULL,
       signed_checkpoint jsonb NULL,
       checkpoint_digest text NULL,
       authority_receipt jsonb NULL,
       body_bytes bigint NOT NULL,
       created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
       submitted_at timestamptz NULL,
       PRIMARY KEY(namespace, stream_id, checkpoint_ordinal)
     )",
    "ALTER TABLE oxibelt_admin_audit_anchor_state
       ADD COLUMN IF NOT EXISTS last_anchored_chain_id text NULL",
    "ALTER TABLE oxibelt_admin_audit_anchor_state
       ADD COLUMN IF NOT EXISTS last_anchored_checkpoint_ordinal bigint NOT NULL DEFAULT 0",
    "UPDATE oxibelt_admin_audit_anchor_state
        SET last_anchored_checkpoint_ordinal=checkpoint_ordinal
      WHERE last_anchored_checkpoint_ordinal=0 AND last_anchored_sequence IS NOT NULL",
    "ALTER TABLE oxibelt_admin_audit_anchor_state
       ADD COLUMN IF NOT EXISTS candidate_cluster_id text NULL",
    "ALTER TABLE oxibelt_admin_audit_anchor_state
       ADD COLUMN IF NOT EXISTS candidate_membership_epoch text NULL",
    "ALTER TABLE oxibelt_admin_audit_anchor_state
       ADD COLUMN IF NOT EXISTS candidate_deployment_epoch text NULL",
    "ALTER TABLE oxibelt_admin_audit_anchor_state
       ADD COLUMN IF NOT EXISTS candidate_signing_key_id text NULL",
    "CREATE INDEX IF NOT EXISTS oxibelt_admin_audit_anchor_pending_idx
       ON oxibelt_admin_audit_anchor_outbox(namespace, stream_id, checkpoint_ordinal)
       WHERE submitted_at IS NULL",
  ] {
    sqlx::query(statement).execute(pool).await?;
  }
  Ok(())
}

pub(crate) async fn record_event_in_transaction(
  tx: &mut Transaction<'_, Postgres>,
  identity: &AnchorStreamIdentity,
  event: &AdminAuditEvent,
  force: bool,
) -> anyhow::Result<AnchorCandidateOutcome> {
  let integrity = event
    .integrity
    .as_ref()
    .context("anchored Admin audit event is missing integrity metadata")?;
  let sequence =
    i64::try_from(integrity.sequence).context("audit sequence exceeds PostgreSQL bigint")?;
  ensure!(
    event.instance_id == identity.instance_id,
    "audit anchor instance identity changed"
  );
  ensure_state_row(tx, identity).await?;
  let row = sqlx::query(
    "SELECT instance_id, checkpoint_ordinal, previous_checkpoint_digest, candidate_chain_id,
            candidate_cluster_id, candidate_membership_epoch,
            candidate_deployment_epoch, candidate_signing_key_id,
            candidate_first_sequence, candidate_events,
            (extract(epoch from (clock_timestamp() - candidate_started_at)) * 1000)::bigint AS candidate_age_ms
       FROM oxibelt_admin_audit_anchor_state
      WHERE namespace=$1 AND stream_id=$2 FOR UPDATE",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(
    row.try_get::<String, _>("instance_id")? == identity.instance_id,
    "stored Admin audit anchor stream identity changed"
  );
  let current_chain: Option<String> = row.try_get("candidate_chain_id")?;
  if let Some(current_chain) = current_chain.as_deref() {
    ensure!(
      current_chain == integrity.chain_id,
      "audit integrity chain changed before its pending checkpoint was sealed"
    );
    ensure!(
      row.try_get::<Option<String>, _>("candidate_cluster_id")? == identity.cluster_id
        && row
          .try_get::<Option<String>, _>("candidate_membership_epoch")?
          .as_deref()
          == Some(identity.membership_epoch.as_str())
        && row
          .try_get::<Option<String>, _>("candidate_deployment_epoch")?
          .as_deref()
          == Some(identity.deployment_epoch.as_str())
        && row
          .try_get::<Option<String>, _>("candidate_signing_key_id")?
          .as_deref()
          == Some(identity.signing_key_id.as_str()),
      "audit anchor candidate identity changed before it was sealed"
    );
  }
  let candidate_events: i64 = row.try_get("candidate_events")?;
  let candidate_age_ms: Option<i64> = row.try_get("candidate_age_ms")?;
  let first_sequence = row
    .try_get::<Option<i64>, _>("candidate_first_sequence")?
    .unwrap_or(sequence);
  sqlx::query(
    "UPDATE oxibelt_admin_audit_anchor_state
        SET candidate_chain_id=$3, candidate_cluster_id=$4,
            candidate_membership_epoch=$5, candidate_deployment_epoch=$6,
            candidate_signing_key_id=$7, candidate_first_sequence=$8,
            candidate_last_sequence=$9, candidate_chain_head=$10,
            candidate_wall_timestamp=$11,
            candidate_started_at=COALESCE(candidate_started_at, clock_timestamp()),
            candidate_events=candidate_events+1, updated_at=clock_timestamp()
      WHERE namespace=$1 AND stream_id=$2",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .bind(&integrity.chain_id)
  .bind(&identity.cluster_id)
  .bind(&identity.membership_epoch)
  .bind(&identity.deployment_epoch)
  .bind(&identity.signing_key_id)
  .bind(first_sequence)
  .bind(sequence)
  .bind(format!("sha256:{}", integrity.event_hash))
  .bind(&event.timestamp)
  .execute(&mut **tx)
  .await?;

  let next_count = u64::try_from(candidate_events.saturating_add(1)).unwrap_or(u64::MAX);
  let age_due = candidate_age_ms
    .and_then(|value| u64::try_from(value).ok())
    .is_some_and(|value| value >= identity.time_interval_ms);
  if force || next_count >= identity.record_interval || age_due {
    return seal_locked_candidate(tx, identity).await;
  }
  Ok(AnchorCandidateOutcome::Pending)
}

pub(crate) async fn seal_due_candidate(
  pool: &sqlx::Pool<Postgres>,
  identity: &AnchorStreamIdentity,
) -> anyhow::Result<Option<AnchorOutboxEntry>> {
  let mut tx = pool.begin().await?;
  ensure_state_row(&mut tx, identity).await?;
  let due = sqlx::query(
    "SELECT candidate_events > 0
            AND clock_timestamp() - candidate_started_at >= ($3::bigint * interval '1 millisecond') AS due
       FROM oxibelt_admin_audit_anchor_state
      WHERE namespace=$1 AND stream_id=$2 FOR UPDATE",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .bind(i64::try_from(identity.time_interval_ms).unwrap_or(i64::MAX))
  .fetch_one(&mut *tx)
  .await?
  .try_get::<bool, _>("due")?;
  let result = if due {
    match seal_locked_candidate(&mut tx, identity).await? {
      AnchorCandidateOutcome::Sealed(entry) => Some(*entry),
      AnchorCandidateOutcome::Pending | AnchorCandidateOutcome::CapacityExceeded => None,
    }
  } else {
    None
  };
  tx.commit().await?;
  Ok(result)
}

pub(crate) async fn seal_candidate(
  pool: &sqlx::Pool<Postgres>,
  identity: &AnchorStreamIdentity,
) -> anyhow::Result<AnchorCandidateOutcome> {
  let mut tx = pool.begin().await?;
  ensure_state_row(&mut tx, identity).await?;
  let result = seal_locked_candidate(&mut tx, identity).await?;
  tx.commit().await?;
  Ok(result)
}

pub(crate) async fn load_pending_outbox(
  pool: &sqlx::Pool<Postgres>,
  identity: &AnchorStreamIdentity,
) -> anyhow::Result<Vec<AnchorOutboxEntry>> {
  let rows = sqlx::query(
    "SELECT checkpoint_ordinal, body::text AS body,
            signed_checkpoint::text AS signed_checkpoint
       FROM oxibelt_admin_audit_anchor_outbox
      WHERE namespace=$1 AND stream_id=$2 AND submitted_at IS NULL
      ORDER BY checkpoint_ordinal",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .fetch_all(pool)
  .await?;
  rows
    .iter()
    .map(|row| {
      let ordinal = u64::try_from(row.try_get::<i64, _>("checkpoint_ordinal")?)?;
      let body = serde_json::from_str(&row.try_get::<String, _>("body")?)?;
      let signed = row
        .try_get::<Option<String>, _>("signed_checkpoint")?
        .map(|value| serde_json::from_str(&value))
        .transpose()?;
      Ok(AnchorOutboxEntry {
        ordinal,
        body,
        signed,
      })
    })
    .collect()
}

pub(crate) async fn pending_usage(
  pool: &sqlx::Pool<Postgres>,
  identity: &AnchorStreamIdentity,
) -> anyhow::Result<(u64, u64, Option<(String, u64)>)> {
  let row = sqlx::query(
    "SELECT count(outbox.*)::bigint AS checkpoints,
            COALESCE(sum(outbox.body_bytes),0)::bigint AS bytes,
            state.last_anchored_chain_id, state.last_anchored_sequence
       FROM oxibelt_admin_audit_anchor_state state
       LEFT JOIN oxibelt_admin_audit_anchor_outbox outbox
         ON outbox.namespace=state.namespace AND outbox.stream_id=state.stream_id
        AND outbox.submitted_at IS NULL
      WHERE state.namespace=$1 AND state.stream_id=$2
      GROUP BY state.last_anchored_chain_id, state.last_anchored_sequence",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .fetch_optional(pool)
  .await?;
  let Some(row) = row else {
    return Ok((0, 0, None));
  };
  Ok((
    u64::try_from(row.try_get::<i64, _>("checkpoints")?)?,
    u64::try_from(row.try_get::<i64, _>("bytes")?)?,
    match (
      row.try_get::<Option<String>, _>("last_anchored_chain_id")?,
      row.try_get::<Option<i64>, _>("last_anchored_sequence")?,
    ) {
      (Some(chain_id), Some(sequence)) => Some((chain_id, u64::try_from(sequence)?)),
      (None, None) => None,
      _ => anyhow::bail!("Admin audit anchor position is partially populated"),
    },
  ))
}

pub(crate) async fn observed_position(
  pool: &sqlx::Pool<Postgres>,
  identity: &AnchorStreamIdentity,
) -> anyhow::Result<Option<(String, u64)>> {
  let row = sqlx::query(
    "SELECT state.candidate_chain_id, state.candidate_last_sequence,
            state.last_anchored_chain_id, state.last_anchored_sequence,
            (SELECT outbox.body::text
               FROM oxibelt_admin_audit_anchor_outbox outbox
              WHERE outbox.namespace=state.namespace AND outbox.stream_id=state.stream_id
              ORDER BY outbox.checkpoint_ordinal DESC LIMIT 1) AS latest_body
       FROM oxibelt_admin_audit_anchor_state state
      WHERE state.namespace=$1 AND state.stream_id=$2",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .fetch_optional(pool)
  .await?;
  let Some(row) = row else {
    return Ok(None);
  };
  let candidate = paired_position(
    row.try_get("candidate_chain_id")?,
    row.try_get("candidate_last_sequence")?,
    "candidate",
  )?;
  if candidate.is_some() {
    return Ok(candidate);
  }
  if let Some(body) = row.try_get::<Option<String>, _>("latest_body")? {
    let body: AuditCheckpointBodyV1 =
      serde_json::from_str(&body).context("stored Admin audit anchor outbox body is malformed")?;
    return Ok(Some((body.chain_id, body.last_sequence)));
  }
  paired_position(
    row.try_get("last_anchored_chain_id")?,
    row.try_get("last_anchored_sequence")?,
    "last anchored",
  )
}

fn paired_position(
  chain_id: Option<String>,
  sequence: Option<i64>,
  label: &str,
) -> anyhow::Result<Option<(String, u64)>> {
  match (chain_id, sequence) {
    (Some(chain_id), Some(sequence)) => Ok(Some((chain_id, u64::try_from(sequence)?))),
    (None, None) => Ok(None),
    _ => anyhow::bail!("Admin audit anchor {label} position is partially populated"),
  }
}

async fn ensure_state_row(
  tx: &mut Transaction<'_, Postgres>,
  identity: &AnchorStreamIdentity,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO oxibelt_admin_audit_anchor_state
       (namespace, stream_id, instance_id, previous_checkpoint_digest)
     VALUES ($1,$2,$3,$4)
     ON CONFLICT(namespace, stream_id) DO NOTHING",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .bind(&identity.instance_id)
  .bind(AUDIT_CHECKPOINT_GENESIS_DIGEST)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

async fn seal_locked_candidate(
  tx: &mut Transaction<'_, Postgres>,
  identity: &AnchorStreamIdentity,
) -> anyhow::Result<AnchorCandidateOutcome> {
  let usage = sqlx::query(
    "SELECT count(*)::bigint AS checkpoints, COALESCE(sum(body_bytes),0)::bigint AS bytes
       FROM oxibelt_admin_audit_anchor_outbox
      WHERE namespace=$1 AND stream_id=$2 AND submitted_at IS NULL",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .fetch_one(&mut **tx)
  .await?;
  let pending = u64::try_from(usage.try_get::<i64, _>("checkpoints")?).unwrap_or(u64::MAX);
  let pending_bytes = u64::try_from(usage.try_get::<i64, _>("bytes")?).unwrap_or(u64::MAX);
  if pending >= identity.max_pending_checkpoints || pending_bytes >= identity.max_pending_bytes {
    return Ok(AnchorCandidateOutcome::CapacityExceeded);
  }
  let row = sqlx::query(
    "SELECT checkpoint_ordinal, previous_checkpoint_digest, candidate_chain_id,
            candidate_cluster_id, candidate_membership_epoch,
            candidate_deployment_epoch, candidate_signing_key_id,
            candidate_first_sequence, candidate_last_sequence, candidate_chain_head,
            candidate_wall_timestamp, candidate_events,
            (SELECT checkpoint_digest FROM oxibelt_admin_audit_anchor_outbox outbox
              WHERE outbox.namespace=$1 AND outbox.stream_id=$2
                AND outbox.submitted_at IS NULL
              ORDER BY checkpoint_ordinal DESC LIMIT 1) AS latest_pending_digest,
            clock_timestamp()::text AS database_timestamp
       FROM oxibelt_admin_audit_anchor_state
      WHERE namespace=$1 AND stream_id=$2 FOR UPDATE",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .fetch_one(&mut **tx)
  .await?;
  if pending > 0 {
    let latest_pending_digest: Option<String> = row.try_get("latest_pending_digest")?;
    let Some(latest_pending_digest) = latest_pending_digest else {
      let candidate_events =
        u64::try_from(row.try_get::<i64, _>("candidate_events")?).unwrap_or(u64::MAX);
      return Ok(if candidate_events >= identity.record_interval {
        AnchorCandidateOutcome::CapacityExceeded
      } else {
        AnchorCandidateOutcome::Pending
      });
    };
    ensure!(
      row.try_get::<String, _>("previous_checkpoint_digest")? == latest_pending_digest,
      "Admin audit anchor pending checkpoint chain head is inconsistent"
    );
  }
  let Some(chain_id) = row.try_get::<Option<String>, _>("candidate_chain_id")? else {
    return Ok(AnchorCandidateOutcome::Pending);
  };
  let ordinal = u64::try_from(row.try_get::<i64, _>("checkpoint_ordinal")?)
    .context("stored audit checkpoint ordinal is negative")?
    .checked_add(1)
    .context("audit checkpoint ordinal is exhausted")?;
  let body = AuditCheckpointBodyV1 {
    format_version: AUDIT_CHECKPOINT_FORMAT_VERSION.to_string(),
    namespace: identity.namespace.clone(),
    stream_id: identity.stream_id.clone(),
    instance_id: identity.instance_id.clone(),
    cluster_id: row.try_get("candidate_cluster_id")?,
    membership_epoch: row
      .try_get::<Option<String>, _>("candidate_membership_epoch")?
      .context("audit anchor candidate membership epoch is missing")?,
    deployment_epoch: row
      .try_get::<Option<String>, _>("candidate_deployment_epoch")?
      .context("audit anchor candidate deployment epoch is missing")?,
    checkpoint_ordinal: ordinal,
    chain_id,
    first_sequence: u64::try_from(row.try_get::<i64, _>("candidate_first_sequence")?)?,
    last_sequence: u64::try_from(row.try_get::<i64, _>("candidate_last_sequence")?)?,
    chain_head: row.try_get("candidate_chain_head")?,
    previous_checkpoint_digest: row.try_get("previous_checkpoint_digest")?,
    wall_timestamp: row.try_get("candidate_wall_timestamp")?,
    source_database_timestamp: row.try_get("database_timestamp")?,
    signing_key_id: row
      .try_get::<Option<String>, _>("candidate_signing_key_id")?
      .context("audit anchor candidate signing key ID is missing")?,
    signing_algorithm: AUDIT_CHECKPOINT_SIGNING_ALGORITHM.to_string(),
  };
  let value: Value = serde_json::to_value(&body)?;
  let bytes = serde_json::to_vec(&value)?;
  let body_bytes = i64::try_from(bytes.len()).context("audit checkpoint body is too large")?;
  if pending_bytes.saturating_add(u64::try_from(body_bytes).unwrap_or(u64::MAX))
    > identity.max_pending_bytes
  {
    return Ok(AnchorCandidateOutcome::CapacityExceeded);
  }
  sqlx::query(
    "INSERT INTO oxibelt_admin_audit_anchor_outbox
       (namespace, stream_id, checkpoint_ordinal, body, body_bytes)
     VALUES ($1,$2,$3,$4::jsonb,$5)",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .bind(i64::try_from(ordinal)?)
  .bind(serde_json::to_string(&value)?)
  .bind(body_bytes)
  .execute(&mut **tx)
  .await?;
  sqlx::query(
    "UPDATE oxibelt_admin_audit_anchor_state
        SET checkpoint_ordinal=$3, candidate_chain_id=NULL,
            candidate_cluster_id=NULL, candidate_membership_epoch=NULL,
            candidate_deployment_epoch=NULL, candidate_signing_key_id=NULL,
            candidate_first_sequence=NULL, candidate_last_sequence=NULL,
            candidate_chain_head=NULL, candidate_wall_timestamp=NULL,
            candidate_started_at=NULL, candidate_events=0, updated_at=clock_timestamp()
      WHERE namespace=$1 AND stream_id=$2",
  )
  .bind(&identity.namespace)
  .bind(&identity.stream_id)
  .bind(i64::try_from(ordinal)?)
  .execute(&mut **tx)
  .await?;
  Ok(AnchorCandidateOutcome::Sealed(Box::new(
    AnchorOutboxEntry {
      ordinal,
      body,
      signed: None,
    },
  )))
}
