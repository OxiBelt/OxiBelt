//! Separately administered PostgreSQL checkpoint authority.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, ensure};
use serde_json::Value;
use sqlx::{AssertSqlSafe, Pool, Postgres, Row};

use super::{AnchorReceiptV1, SignedAuditCheckpointV1};

type SinkFuture<'a, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

pub(crate) trait AuditAnchorSink: Send + Sync {
  fn preflight(&self) -> SinkFuture<'_, ()>;
  fn submit<'a>(
    &'a self,
    checkpoint: &'a SignedAuditCheckpointV1,
  ) -> SinkFuture<'a, AnchorReceiptV1>;
  fn lookup<'a>(
    &'a self,
    namespace: &'a str,
    stream_id: &'a str,
    ordinal: u64,
  ) -> SinkFuture<'a, Option<AnchorReceiptV1>>;
  fn authority_id(&self) -> &str;
}

#[derive(Clone)]
pub(crate) struct PostgresAnchorSink {
  pool: Pool<Postgres>,
  authority_id: String,
  submit_timeout: Duration,
  forbidden_database: Option<PostgresDatabaseIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PostgresDatabaseIdentity {
  database: String,
  postmaster_started_at: String,
}

impl PostgresAnchorSink {
  #[cfg(test)]
  pub(crate) fn new(pool: Pool<Postgres>, authority_id: String, submit_timeout: Duration) -> Self {
    Self {
      pool,
      authority_id,
      submit_timeout,
      forbidden_database: None,
    }
  }

  pub(crate) fn new_with_forbidden_database(
    pool: Pool<Postgres>,
    authority_id: String,
    submit_timeout: Duration,
    forbidden_database: PostgresDatabaseIdentity,
  ) -> Self {
    Self {
      pool,
      authority_id,
      submit_timeout,
      forbidden_database: Some(forbidden_database),
    }
  }

  pub(crate) async fn preflight(&self) -> anyhow::Result<()> {
    let row = tokio::time::timeout(
      self.submit_timeout,
      sqlx::query(
        "SELECT authority_id, schema_version, current_database() AS database,
                pg_postmaster_start_time()::text AS postmaster_started_at
           FROM oxibelt_audit_anchor_v1.authority_info()",
      )
      .fetch_one(&self.pool),
    )
    .await
    .context("Admin audit anchor authority preflight timed out")??;
    let authority_id: String = row.try_get("authority_id")?;
    let schema_version: String = row.try_get("schema_version")?;
    ensure!(
      authority_id == self.authority_id,
      "Admin audit anchor authority ID mismatch"
    );
    ensure!(
      schema_version == "oxibelt.audit-anchor.postgres/v1",
      "unsupported Admin audit anchor authority schema"
    );
    let identity = PostgresDatabaseIdentity {
      database: row.try_get("database")?,
      postmaster_started_at: row.try_get("postmaster_started_at")?,
    };
    ensure!(
      self.forbidden_database.as_ref() != Some(&identity),
      "Admin audit anchor authority resolves to the local Admin audit PostgreSQL database"
    );
    Ok(())
  }

  pub(crate) async fn submit(
    &self,
    checkpoint: &SignedAuditCheckpointV1,
  ) -> anyhow::Result<AnchorReceiptV1> {
    let value = serde_json::to_value(checkpoint)?;
    let row = tokio::time::timeout(
      self.submit_timeout,
      sqlx::query(
        "SELECT authority_id, namespace, stream_id, checkpoint_ordinal,
                checkpoint_digest, authority_received_at
           FROM oxibelt_audit_anchor_v1.append_checkpoint($1::jsonb)",
      )
      .bind(serde_json::to_string(&value)?)
      .fetch_one(&self.pool),
    )
    .await
    .context("Admin audit anchor submission timed out")??;
    receipt_from_row(&row)
  }

  pub(crate) async fn lookup(
    &self,
    namespace: &str,
    stream_id: &str,
    ordinal: u64,
  ) -> anyhow::Result<Option<AnchorReceiptV1>> {
    let row = tokio::time::timeout(
      self.submit_timeout,
      sqlx::query(
        "SELECT authority_id, namespace, stream_id, checkpoint_ordinal,
                checkpoint_digest, authority_received_at
           FROM oxibelt_audit_anchor_v1.lookup_checkpoint($1,$2,$3)",
      )
      .bind(namespace)
      .bind(stream_id)
      .bind(i64::try_from(ordinal)?)
      .fetch_optional(&self.pool),
    )
    .await
    .context("Admin audit anchor lookup timed out")??;
    row.as_ref().map(receipt_from_row).transpose()
  }

  pub(crate) fn authority_id(&self) -> &str {
    &self.authority_id
  }
}

pub(crate) async fn postgres_database_identity(
  pool: &Pool<Postgres>,
) -> anyhow::Result<PostgresDatabaseIdentity> {
  let row = sqlx::query(
    "SELECT current_database() AS database,
            pg_postmaster_start_time()::text AS postmaster_started_at",
  )
  .fetch_one(pool)
  .await?;
  Ok(PostgresDatabaseIdentity {
    database: row.try_get("database")?,
    postmaster_started_at: row.try_get("postmaster_started_at")?,
  })
}

impl AuditAnchorSink for PostgresAnchorSink {
  fn preflight(&self) -> SinkFuture<'_, ()> {
    Box::pin(PostgresAnchorSink::preflight(self))
  }

  fn submit<'a>(
    &'a self,
    checkpoint: &'a SignedAuditCheckpointV1,
  ) -> SinkFuture<'a, AnchorReceiptV1> {
    Box::pin(PostgresAnchorSink::submit(self, checkpoint))
  }

  fn lookup<'a>(
    &'a self,
    namespace: &'a str,
    stream_id: &'a str,
    ordinal: u64,
  ) -> SinkFuture<'a, Option<AnchorReceiptV1>> {
    Box::pin(PostgresAnchorSink::lookup(
      self, namespace, stream_id, ordinal,
    ))
  }

  fn authority_id(&self) -> &str {
    PostgresAnchorSink::authority_id(self)
  }
}

fn receipt_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<AnchorReceiptV1> {
  Ok(AnchorReceiptV1 {
    authority_id: row.try_get("authority_id")?,
    namespace: row.try_get("namespace")?,
    stream_id: row.try_get("stream_id")?,
    checkpoint_ordinal: u64::try_from(row.try_get::<i64, _>("checkpoint_ordinal")?)
      .context("anchor authority returned a negative checkpoint ordinal")?,
    checkpoint_digest: row.try_get("checkpoint_digest")?,
    authority_received_at: row.try_get("authority_received_at")?,
  })
}

pub(crate) async fn store_signed_checkpoint(
  pool: &Pool<Postgres>,
  checkpoint: &SignedAuditCheckpointV1,
) -> anyhow::Result<()> {
  let value: Value = serde_json::to_value(checkpoint)?;
  let mut tx = pool.begin().await?;
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_audit_anchor_outbox
        SET signed_checkpoint=$4::jsonb, checkpoint_digest=$5
      WHERE namespace=$1 AND stream_id=$2 AND checkpoint_ordinal=$3
        AND submitted_at IS NULL
        AND (signed_checkpoint IS NULL OR signed_checkpoint=$4::jsonb)",
  )
  .bind(&checkpoint.body.namespace)
  .bind(&checkpoint.body.stream_id)
  .bind(i64::try_from(checkpoint.body.checkpoint_ordinal)?)
  .bind(serde_json::to_string(&value)?)
  .bind(&checkpoint.checkpoint_digest)
  .execute(&mut *tx)
  .await?;
  ensure!(
    updated.rows_affected() == 1,
    "Admin audit anchor outbox changed before its signature was stored"
  );
  let state = sqlx::query(
    "UPDATE oxibelt_admin_audit_anchor_state
        SET previous_checkpoint_digest=$4, updated_at=clock_timestamp()
      WHERE namespace=$1 AND stream_id=$2 AND checkpoint_ordinal=$3
        AND previous_checkpoint_digest IN ($5, $4)",
  )
  .bind(&checkpoint.body.namespace)
  .bind(&checkpoint.body.stream_id)
  .bind(i64::try_from(checkpoint.body.checkpoint_ordinal)?)
  .bind(&checkpoint.checkpoint_digest)
  .bind(&checkpoint.body.previous_checkpoint_digest)
  .execute(&mut *tx)
  .await?;
  ensure!(
    state.rows_affected() == 1,
    "Admin audit anchor state changed before its signature was stored"
  );
  tx.commit().await?;
  Ok(())
}

pub(crate) async fn store_receipt(
  pool: &Pool<Postgres>,
  checkpoint: &SignedAuditCheckpointV1,
  receipt: &AnchorReceiptV1,
) -> anyhow::Result<()> {
  ensure!(
    receipt.namespace == checkpoint.body.namespace
      && receipt.stream_id == checkpoint.body.stream_id
      && receipt.checkpoint_ordinal == checkpoint.body.checkpoint_ordinal
      && receipt.checkpoint_digest == checkpoint.checkpoint_digest,
    "Admin audit anchor receipt does not match the submitted checkpoint"
  );
  let mut tx = pool.begin().await?;
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_audit_anchor_outbox
        SET authority_receipt=$4::jsonb, submitted_at=clock_timestamp()
      WHERE namespace=$1 AND stream_id=$2 AND checkpoint_ordinal=$3
        AND checkpoint_digest=$5 AND submitted_at IS NULL",
  )
  .bind(&receipt.namespace)
  .bind(&receipt.stream_id)
  .bind(i64::try_from(receipt.checkpoint_ordinal)?)
  .bind(serde_json::to_string(receipt)?)
  .bind(&receipt.checkpoint_digest)
  .execute(&mut *tx)
  .await?;
  if updated.rows_affected() == 0 {
    tx.commit().await?;
    return Ok(());
  }
  let state = sqlx::query(
    "UPDATE oxibelt_admin_audit_anchor_state
        SET last_anchored_checkpoint_ordinal=$3, last_anchored_chain_id=$4,
            last_anchored_sequence=$5,
            updated_at=clock_timestamp()
      WHERE namespace=$1 AND stream_id=$2
        AND last_anchored_checkpoint_ordinal=$6",
  )
  .bind(&receipt.namespace)
  .bind(&receipt.stream_id)
  .bind(i64::try_from(receipt.checkpoint_ordinal)?)
  .bind(&checkpoint.body.chain_id)
  .bind(i64::try_from(checkpoint.body.last_sequence)?)
  .bind(i64::try_from(receipt.checkpoint_ordinal.saturating_sub(1))?)
  .execute(&mut *tx)
  .await?;
  ensure!(
    state.rows_affected() == 1,
    "Admin audit anchor state changed before its receipt was stored"
  );
  tx.commit().await?;
  Ok(())
}

/// Load only signed checkpoints that could promote a currently hidden
/// terminal response. Callers must verify each signature and confirm the
/// digest through the external authority before promotion.
pub(crate) async fn load_terminal_confirmation_checkpoints(
  pool: &Pool<Postgres>,
) -> anyhow::Result<Vec<SignedAuditCheckpointV1>> {
  let mut checkpoints = HashMap::<String, SignedAuditCheckpointV1>::new();
  for (table, id_column, audit_column, confirmation_column) in [
    (
      "oxibelt_admin_mutations",
      "request_id",
      "terminal_audit_record_id",
      "terminal_audit_confirmed_at",
    ),
    (
      "oxibelt_admin_mutations",
      "request_id",
      "audit_record_id",
      "admission_audit_confirmed_at",
    ),
    (
      "oxibelt_admin_operations",
      "operation_id",
      "terminal_audit_record_id",
      "terminal_audit_confirmed_at",
    ),
  ] {
    if !confirmation_column_exists(pool, table, confirmation_column).await? {
      continue;
    }
    let statement = format!(
      "SELECT DISTINCT outbox.signed_checkpoint::text AS signed_checkpoint
         FROM {table} AS terminal
         JOIN oxibelt_admin_audit AS audit
           ON audit.namespace=terminal.namespace
          AND audit.id=terminal.{audit_column}
         JOIN oxibelt_admin_audit_anchor_outbox AS outbox
           ON outbox.namespace=audit.namespace
          AND outbox.signed_checkpoint IS NOT NULL
          AND outbox.signed_checkpoint->'body'->>'instance_id'=audit.instance_id
          AND outbox.signed_checkpoint->'body'->>'chain_id'=audit.integrity->>'chain_id'
          AND (audit.integrity->>'sequence')::bigint
              BETWEEN (outbox.signed_checkpoint->'body'->>'first_sequence')::bigint
                  AND (outbox.signed_checkpoint->'body'->>'last_sequence')::bigint
        WHERE terminal.{audit_column} IS NOT NULL
          AND terminal.{confirmation_column} IS NULL
          AND terminal.{id_column} IS NOT NULL",
    );
    for row in sqlx::query(AssertSqlSafe(statement))
      .fetch_all(pool)
      .await?
    {
      let checkpoint: SignedAuditCheckpointV1 =
        serde_json::from_str(&row.try_get::<String, _>("signed_checkpoint")?)?;
      checkpoints.insert(checkpoint.checkpoint_digest.clone(), checkpoint);
    }
  }
  Ok(checkpoints.into_values().collect())
}

pub(crate) async fn promote_terminal_confirmations(
  pool: &Pool<Postgres>,
  checkpoint: &SignedAuditCheckpointV1,
) -> anyhow::Result<()> {
  for table in ["oxibelt_admin_mutations", "oxibelt_admin_operations"] {
    if !confirmation_column_exists(pool, table, "terminal_audit_confirmed_at").await? {
      continue;
    }
    let statement = format!(
      "UPDATE {table} AS terminal
          SET terminal_audit_confirmed_at=COALESCE(
                terminal.terminal_audit_confirmed_at, clock_timestamp())
         FROM oxibelt_admin_audit AS audit
        WHERE terminal.namespace=$1
          AND terminal.terminal_audit_record_id=audit.id
          AND audit.namespace=terminal.namespace
          AND terminal.terminal_audit_confirmed_at IS NULL
          AND audit.instance_id=$2
          AND audit.integrity->>'chain_id'=$3
          AND (audit.integrity->>'sequence')::bigint BETWEEN $4 AND $5",
    );
    sqlx::query(AssertSqlSafe(statement))
      .bind(&checkpoint.body.namespace)
      .bind(&checkpoint.body.instance_id)
      .bind(&checkpoint.body.chain_id)
      .bind(i64::try_from(checkpoint.body.first_sequence)?)
      .bind(i64::try_from(checkpoint.body.last_sequence)?)
      .execute(pool)
      .await?;
  }
  if confirmation_column_exists(
    pool,
    "oxibelt_admin_mutations",
    "admission_audit_confirmed_at",
  )
  .await?
  {
    sqlx::query(
      "UPDATE oxibelt_admin_mutations AS mutation
          SET admission_audit_confirmed_at=COALESCE(
                mutation.admission_audit_confirmed_at, clock_timestamp())
         FROM oxibelt_admin_audit AS audit
        WHERE mutation.namespace=$1 AND mutation.audit_record_id=audit.id
          AND audit.namespace=mutation.namespace
          AND mutation.admission_audit_confirmed_at IS NULL
          AND audit.instance_id=$2 AND audit.integrity->>'chain_id'=$3
          AND (audit.integrity->>'sequence')::bigint BETWEEN $4 AND $5",
    )
    .bind(&checkpoint.body.namespace)
    .bind(&checkpoint.body.instance_id)
    .bind(&checkpoint.body.chain_id)
    .bind(i64::try_from(checkpoint.body.first_sequence)?)
    .bind(i64::try_from(checkpoint.body.last_sequence)?)
    .execute(pool)
    .await?;
  }
  Ok(())
}

async fn confirmation_column_exists(
  pool: &Pool<Postgres>,
  table: &str,
  column: &str,
) -> anyhow::Result<bool> {
  Ok(
    sqlx::query_scalar::<_, bool>(
      "SELECT EXISTS(
         SELECT 1 FROM information_schema.columns
          WHERE table_schema=current_schema()
            AND table_name=$1 AND column_name=$2)",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await?,
  )
}
