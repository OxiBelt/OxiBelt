//! Coordinator-fenced transaction seam for shared PostgreSQL mutations.

use anyhow::Context;
use serde::Serialize;
use serde_json::Value;
use sqlx::Row;
use sqlx::{Postgres, Transaction};

use super::fencing::{CoordinatorFence, lock_coordinator};
use crate::admin_mutation::artifact::is_sha256_digest;
use crate::admin_mutation::ledger::{validate_identifier, validate_safe_response};
use crate::admin_mutation::store::MutationStore;

#[derive(Debug, Clone)]
pub(crate) struct SharedPublicationClaim {
  pub(crate) operation_kind: String,
  pub(crate) operation_fingerprint: String,
  pub(crate) candidate_revision: String,
  pub(crate) candidate_digest: String,
  pub(crate) checkpoint_reference: String,
  pub(crate) token_producing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SharedPublicationState {
  Applying,
  Applied,
  Restored,
  Indeterminate,
}

impl SharedPublicationState {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Applying => "applying",
      Self::Applied => "applied",
      Self::Restored => "restored",
      Self::Indeterminate => "indeterminate",
    }
  }

  fn parse(value: &str) -> anyhow::Result<Self> {
    Ok(match value {
      "applying" => Self::Applying,
      "applied" => Self::Applied,
      "restored" => Self::Restored,
      "indeterminate" => Self::Indeterminate,
      _ => anyhow::bail!("unknown shared publication state"),
    })
  }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SharedPublicationRecord {
  pub(crate) state: SharedPublicationState,
  pub(crate) candidate_revision: String,
  pub(crate) candidate_digest: String,
  pub(crate) checkpoint_reference: String,
  pub(crate) token_producing: bool,
  pub(crate) safe_response: Option<Value>,
  pub(crate) winner_response_consumed: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum SharedPublicationOutcome {
  FirstPublisher,
  Replay(SharedPublicationRecord),
}

pub(crate) struct FencedCoordinatorTransaction<'a> {
  tx: Transaction<'a, Postgres>,
  store: &'a MutationStore,
  fence: CoordinatorFence,
}

impl<'a> FencedCoordinatorTransaction<'a> {
  pub(crate) fn transaction(&mut self) -> &mut Transaction<'a, Postgres> {
    &mut self.tx
  }

  pub(crate) const fn store(&self) -> &MutationStore {
    self.store
  }

  pub(super) const fn fence(&self) -> &CoordinatorFence {
    &self.fence
  }

  /// Rechecks database-time lease and exact live identity immediately before
  /// commit. Callers cannot commit the inner transaction directly.
  pub(crate) async fn commit(mut self) -> anyhow::Result<()> {
    lock_coordinator(&mut self.tx, self.store, &self.fence, None, true)
      .await
      .context("shared mutation authority expired before commit")?;
    self.tx.commit().await?;
    Ok(())
  }
}

pub(crate) async fn begin_coordinator_transaction<'a>(
  store: &'a MutationStore,
  fence: &CoordinatorFence,
) -> anyhow::Result<FencedCoordinatorTransaction<'a>> {
  let mut tx = store.pool().begin().await?;
  lock_coordinator(&mut tx, store, fence, None, true)
    .await
    .context("shared mutation requires current exact coordinator authority")?;
  Ok(FencedCoordinatorTransaction {
    tx,
    store,
    fence: fence.clone(),
  })
}

pub(crate) async fn claim_shared_publication(
  transaction: &mut FencedCoordinatorTransaction<'_>,
  claim: &SharedPublicationClaim,
) -> anyhow::Result<SharedPublicationOutcome> {
  validate_publication_claim(claim)?;
  let namespace = transaction.store.namespace().to_string();
  let request_id = transaction.fence.request_id.clone();
  let origin = transaction.fence.member.clone();
  let inserted = sqlx::query(
    "INSERT INTO oxibelt_admin_shared_publications
       (namespace,request_id,operation_kind,operation_fingerprint,candidate_revision,
        candidate_digest,checkpoint_reference,token_producing)
     SELECT $1,$2,$3,$4,$5,$6,$7,$8 FROM oxibelt_admin_mutations mutation
      WHERE mutation.namespace=$1 AND mutation.request_id=$2 AND mutation.fingerprint=$4
        AND mutation.action=$3 AND mutation.new_revision=$5 AND mutation.content_digest=$6
        AND (NOT $8 OR (mutation.admission_instance_id=$9 AND mutation.admission_boot_id=$10
          AND mutation.admission_instance_epoch=$11 AND EXISTS(
            SELECT 1 FROM oxibelt_admin_instance_heartbeats heartbeat
             WHERE heartbeat.namespace=mutation.namespace
               AND heartbeat.cluster_id=mutation.cluster_id
               AND heartbeat.membership_revision=mutation.membership_revision
               AND heartbeat.instance_id=$9 AND heartbeat.boot_id=$10
               AND heartbeat.instance_epoch=$11 AND heartbeat.ready=true
               AND heartbeat.lease_expires_at>now())))
     ON CONFLICT(namespace,request_id) DO NOTHING",
  )
  .bind(&namespace)
  .bind(&request_id)
  .bind(&claim.operation_kind)
  .bind(&claim.operation_fingerprint)
  .bind(&claim.candidate_revision)
  .bind(&claim.candidate_digest)
  .bind(&claim.checkpoint_reference)
  .bind(claim.token_producing)
  .bind(&origin.instance_id)
  .bind(&origin.boot_id)
  .bind(origin.instance_epoch)
  .execute(&mut **transaction.transaction())
  .await?;
  if inserted.rows_affected() == 1 {
    return Ok(SharedPublicationOutcome::FirstPublisher);
  }
  let row = load_publication(transaction).await?;
  let immutable = sqlx::query(
    "SELECT operation_kind,operation_fingerprint,candidate_revision,candidate_digest,
            checkpoint_reference,token_producing FROM oxibelt_admin_shared_publications
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(&namespace)
  .bind(&request_id)
  .fetch_one(&mut **transaction.transaction())
  .await?;
  anyhow::ensure!(
    immutable.try_get::<String, _>("operation_kind")? == claim.operation_kind
      && immutable.try_get::<String, _>("operation_fingerprint")? == claim.operation_fingerprint
      && immutable.try_get::<String, _>("candidate_revision")? == claim.candidate_revision
      && immutable.try_get::<String, _>("candidate_digest")? == claim.candidate_digest
      && immutable.try_get::<String, _>("checkpoint_reference")? == claim.checkpoint_reference
      && immutable.try_get::<bool, _>("token_producing")? == claim.token_producing,
    "shared publication replay binding conflict"
  );
  Ok(SharedPublicationOutcome::Replay(row))
}

pub(crate) async fn finish_shared_publication(
  transaction: &mut FencedCoordinatorTransaction<'_>,
  next: SharedPublicationState,
  safe_response: Option<Value>,
) -> anyhow::Result<SharedPublicationRecord> {
  anyhow::ensure!(
    next != SharedPublicationState::Applying,
    "terminal shared publication required"
  );
  if let Some(response) = safe_response.as_ref() {
    validate_safe_response(response)?;
  }
  let encoded = safe_response
    .as_ref()
    .map(serde_json::to_string)
    .transpose()?;
  let namespace = transaction.store.namespace().to_string();
  let request_id = transaction.fence.request_id.clone();
  let allowed_prior = match next {
    SharedPublicationState::Applied => "applying",
    SharedPublicationState::Restored | SharedPublicationState::Indeterminate => {
      "applying_or_applied"
    }
    SharedPublicationState::Applying => unreachable!(),
  };
  let result = sqlx::query(
    "UPDATE oxibelt_admin_shared_publications SET state=$3,safe_response=$4::jsonb,updated_at=now()
      WHERE namespace=$1 AND request_id=$2 AND
       (state='applying' OR ($5='applying_or_applied' AND state='applied'))
       AND EXISTS(SELECT 1 FROM oxibelt_admin_mutation_checkpoints checkpoint
         WHERE checkpoint.namespace=oxibelt_admin_shared_publications.namespace
           AND checkpoint.request_id=oxibelt_admin_shared_publications.request_id
           AND checkpoint.instance_id=oxibelt_admin_shared_publications.checkpoint_reference
           AND checkpoint.candidate_revision=oxibelt_admin_shared_publications.candidate_revision
           AND checkpoint.candidate_digest=oxibelt_admin_shared_publications.candidate_digest)",
  )
  .bind(&namespace)
  .bind(&request_id)
  .bind(next.as_str())
  .bind(encoded)
  .bind(allowed_prior)
  .execute(&mut **transaction.transaction())
  .await?;
  if result.rows_affected() == 0 {
    let existing = load_publication(transaction).await?;
    anyhow::ensure!(
      existing.state == next && existing.safe_response == safe_response,
      "shared publication terminal replay conflict"
    );
    return Ok(existing);
  }
  load_publication(transaction).await
}

/// Atomically marks the winner-only response slot as consumed. Callers may
/// return any non-replayable credential only when this returns `true`; every
/// retry receives `false` and must use the persisted safe response instead.
pub(crate) async fn consume_shared_winner_response(
  transaction: &mut FencedCoordinatorTransaction<'_>,
) -> anyhow::Result<bool> {
  let namespace = transaction.store.namespace().to_string();
  let request_id = transaction.fence.request_id.clone();
  let origin = transaction.fence.member.clone();
  let result = sqlx::query(
    "UPDATE oxibelt_admin_shared_publications SET winner_response_consumed=true,updated_at=now()
      WHERE namespace=$1 AND request_id=$2 AND state='applied'
        AND winner_response_consumed=false AND (NOT token_producing OR EXISTS(
          SELECT 1 FROM oxibelt_admin_mutations mutation
          JOIN oxibelt_admin_instance_heartbeats heartbeat
            ON heartbeat.namespace=mutation.namespace AND heartbeat.cluster_id=mutation.cluster_id
           AND heartbeat.membership_revision=mutation.membership_revision
           AND heartbeat.instance_id=mutation.admission_instance_id
           AND heartbeat.boot_id=mutation.admission_boot_id
           AND heartbeat.instance_epoch=mutation.admission_instance_epoch
          WHERE mutation.namespace=$1 AND mutation.request_id=$2
            AND mutation.admission_instance_id=$3 AND mutation.admission_boot_id=$4
            AND mutation.admission_instance_epoch=$5 AND heartbeat.ready=true
            AND heartbeat.lease_expires_at>now()))",
  )
  .bind(namespace)
  .bind(request_id)
  .bind(&origin.instance_id)
  .bind(&origin.boot_id)
  .bind(origin.instance_epoch)
  .execute(&mut **transaction.transaction())
  .await?;
  Ok(result.rows_affected() == 1)
}

async fn load_publication(
  transaction: &mut FencedCoordinatorTransaction<'_>,
) -> anyhow::Result<SharedPublicationRecord> {
  let namespace = transaction.store.namespace().to_string();
  let request_id = transaction.fence.request_id.clone();
  let row = sqlx::query(
    "SELECT state,candidate_revision,candidate_digest,checkpoint_reference,token_producing,safe_response::text AS safe_response,
            winner_response_consumed
       FROM oxibelt_admin_shared_publications WHERE namespace=$1 AND request_id=$2 FOR UPDATE",
  )
  .bind(namespace)
  .bind(request_id)
  .fetch_one(&mut **transaction.transaction())
  .await?;
  Ok(SharedPublicationRecord {
    state: SharedPublicationState::parse(&row.try_get::<String, _>("state")?)?,
    candidate_revision: row.try_get("candidate_revision")?,
    candidate_digest: row.try_get("candidate_digest")?,
    checkpoint_reference: row.try_get("checkpoint_reference")?,
    token_producing: row.try_get("token_producing")?,
    safe_response: row
      .try_get::<Option<String>, _>("safe_response")?
      .map(|value| serde_json::from_str(&value))
      .transpose()?,
    winner_response_consumed: row.try_get("winner_response_consumed")?,
  })
}

pub(crate) async fn load_shared_publication(
  store: &MutationStore,
  request_id: &str,
) -> anyhow::Result<Option<SharedPublicationRecord>> {
  validate_identifier("request_id", request_id, 256)?;
  let row = sqlx::query(
    "SELECT state,candidate_revision,candidate_digest,checkpoint_reference,token_producing,safe_response::text AS safe_response,
            winner_response_consumed FROM oxibelt_admin_shared_publications
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(store.namespace())
  .bind(request_id)
  .fetch_optional(store.pool())
  .await?;
  row
    .map(|row| {
      Ok(SharedPublicationRecord {
        state: SharedPublicationState::parse(&row.try_get::<String, _>("state")?)?,
        candidate_revision: row.try_get("candidate_revision")?,
        candidate_digest: row.try_get("candidate_digest")?,
        checkpoint_reference: row.try_get("checkpoint_reference")?,
        token_producing: row.try_get("token_producing")?,
        safe_response: row
          .try_get::<Option<String>, _>("safe_response")?
          .map(|value| serde_json::from_str(&value))
          .transpose()?,
        winner_response_consumed: row.try_get("winner_response_consumed")?,
      })
    })
    .transpose()
}

pub(crate) async fn load_applied_shared_publication_tx(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  fence: &CoordinatorFence,
) -> anyhow::Result<Option<SharedPublicationRecord>> {
  let row = sqlx::query(
    "SELECT publication.state,publication.candidate_revision,publication.candidate_digest,
            publication.checkpoint_reference,publication.token_producing,
            publication.safe_response::text AS safe_response,
            publication.winner_response_consumed
       FROM oxibelt_admin_shared_publications publication
       JOIN oxibelt_admin_mutations mutation USING(namespace,request_id)
      WHERE publication.namespace=$1 AND publication.request_id=$2
        AND publication.state='applied'
        AND publication.candidate_revision=mutation.new_revision
        AND publication.candidate_digest=mutation.content_digest
      FOR UPDATE OF publication",
  )
  .bind(store.namespace())
  .bind(&fence.request_id)
  .fetch_optional(&mut **tx)
  .await?;
  row.map(|row| publication_from_row(&row)).transpose()
}

fn publication_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<SharedPublicationRecord> {
  Ok(SharedPublicationRecord {
    state: SharedPublicationState::parse(&row.try_get::<String, _>("state")?)?,
    candidate_revision: row.try_get("candidate_revision")?,
    candidate_digest: row.try_get("candidate_digest")?,
    checkpoint_reference: row.try_get("checkpoint_reference")?,
    token_producing: row.try_get("token_producing")?,
    safe_response: row
      .try_get::<Option<String>, _>("safe_response")?
      .map(|value| serde_json::from_str(&value))
      .transpose()?,
    winner_response_consumed: row.try_get("winner_response_consumed")?,
  })
}

fn validate_publication_claim(claim: &SharedPublicationClaim) -> anyhow::Result<()> {
  for (name, value) in [
    ("operation_kind", &claim.operation_kind),
    ("operation_fingerprint", &claim.operation_fingerprint),
    ("candidate_revision", &claim.candidate_revision),
    ("checkpoint_reference", &claim.checkpoint_reference),
  ] {
    validate_identifier(name, value, 256)?;
  }
  anyhow::ensure!(
    is_sha256_digest(&claim.candidate_digest),
    "shared publication candidate digest must be canonical SHA-256"
  );
  Ok(())
}
