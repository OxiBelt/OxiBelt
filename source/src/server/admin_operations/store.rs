//! PostgreSQL authority for long-running Admin-operation state.

use std::str::FromStr as _;

use anyhow::{Context, ensure};
use serde_json::Value;
use sqlx::{AssertSqlSafe, PgPool, Postgres, Row, Transaction};

use super::artifact::{
  OPERATION_ARTIFACT_ALGORITHM, OperationArtifactBinding, SealedOperationArtifact,
  StoredOperationArtifact, is_sha256_digest,
};
use super::types::{
  AdminOperationKind, AdminOperationRecoveryClass, AdminOperationSafeErrorClass,
  AdminOperationState,
};

#[path = "store_anchor.rs"]
mod anchor;
#[path = "store_rows.rs"]
mod rows;
#[path = "store_schema.rs"]
mod schema;
#[path = "store_terminal.rs"]
mod terminal;
#[path = "store_validation.rs"]
mod validation;
use rows::*;
use validation::*;

#[cfg(test)]
#[path = "store_postgres_tests.rs"]
mod postgres_tests;

const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(in crate::server) struct OperationJournal {
  pool: PgPool,
  namespace: String,
}

#[derive(Debug, Clone)]
pub(in crate::server) struct NewJournalOperation {
  pub operation_id: String,
  pub actor: String,
  pub request_id: String,
  pub submitter_worker_id: String,
  pub submitter_boot_id: String,
  pub principal: String,
  #[allow(
    dead_code,
    reason = "retained for recovery authorization and audit reconstruction"
  )]
  pub permission_action: String,
  #[allow(
    dead_code,
    reason = "retained for durable API and audit reconstruction"
  )]
  pub redacted_resource: Option<String>,
  #[allow(
    dead_code,
    reason = "binds sealed recovery artifacts to the authorized resource"
  )]
  pub resource_digest: String,
  pub idempotency_key_digest: Option<String>,
  pub request_fingerprint: String,
  pub kind: AdminOperationKind,
  pub schema_version: u16,
  pub recovery_class: AdminOperationRecoveryClass,
  pub progress: Option<Value>,
  pub maximum_lifetime_seconds: i64,
  pub retention_seconds: i64,
}

#[derive(Debug, Clone)]
pub(in crate::server) struct JournalOperation {
  pub operation_id: String,
  pub actor: String,
  pub request_id: String,
  #[allow(
    dead_code,
    reason = "the database recovery predicate consumes submitter identity without exposing it"
  )]
  pub submitter_worker_id: Option<String>,
  #[allow(
    dead_code,
    reason = "the database recovery predicate consumes submitter identity without exposing it"
  )]
  pub submitter_boot_id: Option<String>,
  pub principal: String,
  #[allow(
    dead_code,
    reason = "sealed checkpoint recovery binds the original action"
  )]
  pub permission_action: String,
  #[allow(
    dead_code,
    reason = "retained for durable API and audit reconstruction"
  )]
  pub redacted_resource: Option<String>,
  #[allow(
    dead_code,
    reason = "sealed checkpoint recovery binds the redacted resource digest"
  )]
  pub resource_digest: String,
  pub request_fingerprint: String,
  pub kind: AdminOperationKind,
  pub schema_version: u16,
  pub recovery_class: AdminOperationRecoveryClass,
  pub state: AdminOperationState,
  pub revision: u64,
  pub owner_worker_id: Option<String>,
  pub owner_boot_id: Option<String>,
  pub lease_epoch: u64,
  pub progress: Option<Value>,
  #[allow(
    dead_code,
    reason = "restart recovery opens the authenticated checkpoint reference"
  )]
  pub checkpoint_artifact_id: Option<String>,
  pub terminal_result: Option<Value>,
  pub terminal_receipt: Option<Vec<u8>>,
  #[allow(
    dead_code,
    reason = "retained for enforcing audit correlation and receipt replay"
  )]
  pub terminal_audit_record_id: Option<i64>,
  pub terminal_audit_confirmed: bool,
  pub safe_error_class: Option<String>,
  pub error_code: Option<String>,
  pub created_at_unix_ms: u64,
  pub updated_at_unix_ms: u64,
  pub expires_at_unix_ms: u64,
  pub retention_until_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub(in crate::server) struct JournalEvent {
  pub revision: u64,
  pub event: String,
  pub state: AdminOperationState,
  pub progress: Option<Value>,
  #[allow(
    dead_code,
    reason = "reserved for bounded versioned durable event metadata"
  )]
  pub payload: Option<Value>,
  pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(in crate::server) struct WorkerIdentity {
  pub worker_id: String,
  pub boot_id: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(in crate::server) struct LeaseGuard {
  pub operation_id: String,
  pub worker_id: String,
  pub boot_id: String,
  pub lease_epoch: u64,
  pub expected_revision: u64,
}

#[derive(Debug, Clone)]
pub(in crate::server) struct TerminalUpdate {
  pub state: AdminOperationState,
  pub result: Option<Value>,
  pub receipt: Vec<u8>,
  pub terminal_audit_record_id: i64,
  pub safe_error_class: Option<String>,
  pub error_code: Option<String>,
  pub audit_anchor_required: bool,
}

#[derive(Debug, Clone)]
pub(in crate::server) enum InsertOutcome {
  Inserted(JournalOperation),
  Replay(JournalOperation),
  #[allow(
    dead_code,
    reason = "conflicting durable row is available for audit diagnostics"
  )]
  Conflict(JournalOperation),
  QueueFull,
  StoreFull,
}

#[derive(Debug, Clone)]
pub(in crate::server) enum CancelOutcome {
  Requested(JournalOperation),
  AlreadyRequested(JournalOperation),
  #[allow(
    dead_code,
    reason = "terminal row supports idempotent cancellation responses"
  )]
  Terminal(JournalOperation),
  RevisionConflict(JournalOperation),
}

impl OperationJournal {
  pub fn new(pool: PgPool, namespace: String) -> anyhow::Result<Self> {
    validate_text("namespace", &namespace, 256)?;
    Ok(Self { pool, namespace })
  }

  pub fn pool(&self) -> &PgPool {
    &self.pool
  }

  pub fn namespace(&self) -> &str {
    &self.namespace
  }

  #[allow(
    dead_code,
    reason = "convenience wrapper retained for focused journal users and tests"
  )]
  pub async fn insert_accepted(
    &self,
    operation: &NewJournalOperation,
    max_queued: usize,
    max_stored: usize,
  ) -> anyhow::Result<InsertOutcome> {
    let mut tx = self.pool.begin().await?;
    let outcome = self
      .insert_accepted_tx(&mut tx, operation, max_queued, max_stored)
      .await?;
    tx.commit().await?;
    Ok(outcome)
  }

  pub async fn insert_accepted_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    operation: &NewJournalOperation,
    max_queued: usize,
    max_stored: usize,
  ) -> anyhow::Result<InsertOutcome> {
    operation.validate()?;
    ensure!(
      max_queued > 0 && max_stored >= max_queued,
      "invalid operation journal capacity"
    );
    sqlx::query(
      "SELECT pg_advisory_xact_lock(
         hashtextextended('oxibelt-admin-operations-capacity:' || $1, 0))",
    )
    .bind(&self.namespace)
    .execute(&mut **tx)
    .await?;
    let existing = self
      .load_tx(tx, &operation.operation_id)
      .await?
      .or(self.load_idempotent_tx(tx, operation).await?);
    if let Some(existing) = existing {
      return Ok(classify_existing(existing, operation));
    }
    let (queued, stored): (i64, i64) = sqlx::query_as(
      "SELECT count(*) FILTER (WHERE state IN ('accepted','queued','cancellation_requested')),
              count(*) FROM oxibelt_admin_operations WHERE namespace = $1",
    )
    .bind(&self.namespace)
    .fetch_one(&mut **tx)
    .await?;
    if usize::try_from(queued)? >= max_queued {
      return Ok(InsertOutcome::QueueFull);
    }
    if usize::try_from(stored)? >= max_stored {
      return Ok(InsertOutcome::StoreFull);
    }
    let inserted = sqlx::query(
      "INSERT INTO oxibelt_admin_operations
         (namespace, operation_id, actor, request_id, submitter_worker_id, submitter_boot_id,
          principal, permission_action, redacted_resource, resource_digest, idempotency_key_digest,
          request_fingerprint, kind, schema_version, recovery_class, progress, retention_seconds,
          expires_at, retention_until)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,
         now() + make_interval(secs => $18::double precision),
         now() + make_interval(secs => ($18 + $17)::double precision))
       ON CONFLICT DO NOTHING",
    )
    .bind(&self.namespace)
    .bind(&operation.operation_id)
    .bind(&operation.actor)
    .bind(&operation.request_id)
    .bind(&operation.submitter_worker_id)
    .bind(&operation.submitter_boot_id)
    .bind(&operation.principal)
    .bind(&operation.permission_action)
    .bind(&operation.redacted_resource)
    .bind(&operation.resource_digest)
    .bind(&operation.idempotency_key_digest)
    .bind(&operation.request_fingerprint)
    .bind(operation.kind.as_str())
    .bind(i32::from(operation.schema_version))
    .bind(operation.recovery_class.as_str())
    .bind(
      operation
        .progress
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?,
    )
    .bind(i32::try_from(operation.retention_seconds)?)
    .bind(operation.maximum_lifetime_seconds as f64)
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() == 1 {
      insert_event_tx(
        tx,
        &self.namespace,
        &operation.operation_id,
        1,
        "operation.accepted",
        AdminOperationState::Accepted,
        operation.progress.as_ref(),
        None,
      )
      .await?;
      return Ok(InsertOutcome::Inserted(
        self
          .load_tx(tx, &operation.operation_id)
          .await?
          .context("inserted Admin operation is missing")?,
      ));
    }
    let existing = self.load_tx(tx, &operation.operation_id).await?;
    let existing = match existing {
      Some(row) => row,
      None => self
        .load_idempotent_tx(tx, operation)
        .await?
        .context("conflicting Admin operation disappeared")?,
    };
    Ok(classify_existing(existing, operation))
  }

  pub async fn load(&self, operation_id: &str) -> anyhow::Result<Option<JournalOperation>> {
    validate_text("operation_id", operation_id, 256)?;
    select_operation(&self.pool, &self.namespace, operation_id).await
  }

  async fn load_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    operation_id: &str,
  ) -> anyhow::Result<Option<JournalOperation>> {
    select_operation(&mut **tx, &self.namespace, operation_id).await
  }

  async fn load_idempotent_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    operation: &NewJournalOperation,
  ) -> anyhow::Result<Option<JournalOperation>> {
    let Some(digest) = operation.idempotency_key_digest.as_deref() else {
      return Ok(None);
    };
    let statement = operation_select(
      "WHERE namespace = $1 AND actor = $2 AND principal = $3 AND permission_action = $4
         AND idempotency_key_digest = $5",
    );
    let row = sqlx::query(AssertSqlSafe(statement))
      .bind(&self.namespace)
      .bind(&operation.actor)
      .bind(&operation.principal)
      .bind(&operation.permission_action)
      .bind(digest)
      .fetch_optional(&mut **tx)
      .await?;
    row.as_ref().map(operation_from_row).transpose()
  }

  pub async fn list(&self, limit: i64) -> anyhow::Result<Vec<JournalOperation>> {
    ensure!(
      (1..=1000).contains(&limit),
      "list limit must be between 1 and 1000"
    );
    let statement =
      operation_select("WHERE namespace = $1 ORDER BY created_at DESC, operation_id DESC LIMIT $2");
    sqlx::query(AssertSqlSafe(statement))
      .bind(&self.namespace)
      .bind(limit)
      .fetch_all(&self.pool)
      .await?
      .iter()
      .map(operation_from_row)
      .collect()
  }

  pub async fn queue(
    &self,
    operation_id: &str,
    expected_revision: u64,
  ) -> anyhow::Result<Option<JournalOperation>> {
    let mut tx = self.pool.begin().await?;
    let operation = self
      .queue_tx(&mut tx, operation_id, expected_revision)
      .await?;
    tx.commit().await?;
    Ok(operation)
  }

  pub async fn queue_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    operation_id: &str,
    expected_revision: u64,
  ) -> anyhow::Result<Option<JournalOperation>> {
    validate_text("operation_id", operation_id, 256)?;
    let row = sqlx::query(AssertSqlSafe(format!(
      "UPDATE oxibelt_admin_operations SET state = 'queued', revision = revision + 1,
          updated_at = now()
        WHERE namespace = $1 AND operation_id = $2 AND revision = $3 AND state = 'accepted'
          AND owner_worker_id IS NULL RETURNING {}",
      RETURNING_COLUMNS
    )))
    .bind(&self.namespace)
    .bind(operation_id)
    .bind(i64::try_from(expected_revision)?)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let operation = operation_from_row(&row)?;
    insert_event_tx(
      tx,
      &self.namespace,
      operation_id,
      operation.revision,
      "operation.queued",
      AdminOperationState::Queued,
      operation.progress.as_ref(),
      None,
    )
    .await?;
    Ok(Some(operation))
  }

  #[allow(
    dead_code,
    reason = "generic worker loop uses this once reconstructable executors land"
  )]
  pub async fn claim(
    &self,
    worker: &WorkerIdentity,
    lease_seconds: i64,
  ) -> anyhow::Result<Option<(JournalOperation, LeaseGuard)>> {
    self.claim_inner(None, worker, lease_seconds).await
  }

  pub async fn claim_id(
    &self,
    operation_id: &str,
    worker: &WorkerIdentity,
    lease_seconds: i64,
  ) -> anyhow::Result<Option<(JournalOperation, LeaseGuard)>> {
    validate_text("operation_id", operation_id, 256)?;
    self
      .claim_inner(Some(operation_id), worker, lease_seconds)
      .await
  }

  async fn claim_inner(
    &self,
    operation_id: Option<&str>,
    worker: &WorkerIdentity,
    lease_seconds: i64,
  ) -> anyhow::Result<Option<(JournalOperation, LeaseGuard)>> {
    worker.validate()?;
    ensure!(
      (3..=300).contains(&lease_seconds),
      "lease must be between 3 and 300 seconds"
    );
    let mut tx = self.pool.begin().await?;
    let candidate = sqlx::query(
      "SELECT operation_id, state FROM oxibelt_admin_operations
        WHERE namespace = $1 AND ($2::text IS NULL OR operation_id = $2)
          AND state IN ('queued', 'compensating') AND owner_worker_id IS NULL
          AND expires_at > now()
        ORDER BY created_at, operation_id FOR UPDATE SKIP LOCKED LIMIT 1",
    )
    .bind(&self.namespace)
    .bind(operation_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(candidate) = candidate else {
      tx.commit().await?;
      return Ok(None);
    };
    let operation_id: String = candidate.try_get("operation_id")?;
    let prior_state: String = candidate.try_get("state")?;
    let state = if prior_state == "queued" {
      "claimed"
    } else {
      "compensating"
    };
    let row = sqlx::query(AssertSqlSafe(format!(
      "UPDATE oxibelt_admin_operations SET state = $3, revision = revision + 1,
         owner_worker_id = $4, owner_boot_id = $5, lease_epoch = lease_epoch + 1,
         lease_expires_at = now() + make_interval(secs => $6::double precision), updated_at = now()
       WHERE namespace = $1 AND operation_id = $2 RETURNING {}",
      RETURNING_COLUMNS
    )))
    .bind(&self.namespace)
    .bind(&operation_id)
    .bind(state)
    .bind(&worker.worker_id)
    .bind(&worker.boot_id)
    .bind(lease_seconds as f64)
    .fetch_one(&mut *tx)
    .await?;
    let operation = operation_from_row(&row)?;
    let event = if state == "claimed" {
      "operation.claimed"
    } else {
      "operation.compensation_claimed"
    };
    insert_event_tx(
      &mut tx,
      &self.namespace,
      &operation_id,
      operation.revision,
      event,
      operation.state,
      operation.progress.as_ref(),
      None,
    )
    .await?;
    tx.commit().await?;
    let guard = operation
      .lease_guard()
      .context("claimed operation has no owner")?;
    Ok(Some((operation, guard)))
  }

  pub async fn start(&self, guard: &LeaseGuard) -> anyhow::Result<Option<JournalOperation>> {
    self
      .leased_transition(
        guard,
        AdminOperationState::Claimed,
        AdminOperationState::Running,
        "operation.running",
        None,
      )
      .await
  }

  #[allow(
    dead_code,
    reason = "generic recovery and compensation workers use this transition"
  )]
  pub async fn transition(
    &self,
    guard: &LeaseGuard,
    from: AdminOperationState,
    next: AdminOperationState,
    event: &str,
    payload: Option<&Value>,
  ) -> anyhow::Result<Option<JournalOperation>> {
    ensure!(
      legal_transition(from, next),
      "illegal Admin operation state transition"
    );
    self
      .leased_transition(guard, from, next, event, payload)
      .await
  }

  async fn leased_transition(
    &self,
    guard: &LeaseGuard,
    from: AdminOperationState,
    next: AdminOperationState,
    event: &str,
    payload: Option<&Value>,
  ) -> anyhow::Result<Option<JournalOperation>> {
    validate_event(event)?;
    let mut tx = self.pool.begin().await?;
    let operation = self
      .leased_transition_tx(&mut tx, guard, from, next, event, payload)
      .await?;
    tx.commit().await?;
    Ok(operation)
  }

  pub async fn leased_transition_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    guard: &LeaseGuard,
    from: AdminOperationState,
    next: AdminOperationState,
    event: &str,
    payload: Option<&Value>,
  ) -> anyhow::Result<Option<JournalOperation>> {
    guard.validate()?;
    ensure!(
      legal_transition(from, next),
      "illegal Admin operation state transition"
    );
    validate_event(event)?;
    let row = sqlx::query(AssertSqlSafe(format!(
      "UPDATE oxibelt_admin_operations SET state = $8, revision = revision + 1, updated_at = now()
       WHERE namespace = $1 AND operation_id = $2 AND owner_worker_id = $3 AND owner_boot_id = $4
         AND lease_epoch = $5 AND revision = $6 AND state = $7 AND lease_expires_at > now()
       RETURNING {}",
      RETURNING_COLUMNS
    )))
    .bind(&self.namespace)
    .bind(&guard.operation_id)
    .bind(&guard.worker_id)
    .bind(&guard.boot_id)
    .bind(i64::try_from(guard.lease_epoch)?)
    .bind(i64::try_from(guard.expected_revision)?)
    .bind(from.as_str())
    .bind(next.as_str())
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let operation = operation_from_row(&row)?;
    insert_event_tx(
      tx,
      &self.namespace,
      &guard.operation_id,
      operation.revision,
      event,
      next,
      operation.progress.as_ref(),
      payload,
    )
    .await?;
    Ok(Some(operation))
  }

  pub async fn renew_lease(&self, guard: &LeaseGuard, lease_seconds: i64) -> anyhow::Result<bool> {
    guard.validate()?;
    ensure!(
      (3..=300).contains(&lease_seconds),
      "lease must be between 3 and 300 seconds"
    );
    let result = sqlx::query(
      "UPDATE oxibelt_admin_operations
          SET lease_expires_at = now() + make_interval(secs => $7::double precision),
              updated_at = now()
        WHERE namespace = $1 AND operation_id = $2 AND owner_worker_id = $3
          AND owner_boot_id = $4 AND lease_epoch = $5 AND revision = $6
          AND lease_expires_at > now()",
    )
    .bind(&self.namespace)
    .bind(&guard.operation_id)
    .bind(&guard.worker_id)
    .bind(&guard.boot_id)
    .bind(i64::try_from(guard.lease_epoch)?)
    .bind(i64::try_from(guard.expected_revision)?)
    .bind(lease_seconds as f64)
    .execute(&self.pool)
    .await?;
    Ok(result.rows_affected() == 1)
  }

  pub async fn update_progress(
    &self,
    guard: &LeaseGuard,
    progress: &Value,
    checkpoint_artifact_id: Option<&str>,
  ) -> anyhow::Result<Option<JournalOperation>> {
    guard.validate()?;
    validate_json("progress", progress, MAX_JSON_BYTES)?;
    if let Some(value) = checkpoint_artifact_id {
      validate_text("checkpoint_artifact_id", value, 256)?;
    }
    let progress_json = serde_json::to_string(progress)?;
    let mut tx = self.pool.begin().await?;
    let row = sqlx::query(AssertSqlSafe(format!(
      "UPDATE oxibelt_admin_operations SET progress = $7::jsonb, checkpoint_artifact_id = $8,
         revision = revision + 1, updated_at = now()
       WHERE namespace = $1 AND operation_id = $2 AND owner_worker_id = $3 AND owner_boot_id = $4
         AND lease_epoch = $5 AND revision = $6 AND state IN ('running', 'compensating')
         AND lease_expires_at > now() RETURNING {}",
      RETURNING_COLUMNS
    )))
    .bind(&self.namespace)
    .bind(&guard.operation_id)
    .bind(&guard.worker_id)
    .bind(&guard.boot_id)
    .bind(i64::try_from(guard.lease_epoch)?)
    .bind(i64::try_from(guard.expected_revision)?)
    .bind(&progress_json)
    .bind(checkpoint_artifact_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
      tx.commit().await?;
      return Ok(None);
    };
    let operation = operation_from_row(&row)?;
    insert_event_tx(
      &mut tx,
      &self.namespace,
      &guard.operation_id,
      operation.revision,
      "operation.progress",
      operation.state,
      operation.progress.as_ref(),
      None,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(operation))
  }
}
