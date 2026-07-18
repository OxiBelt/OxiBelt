//! Terminal, cancellation, recovery, retention, and artifact journal paths.

use super::*;

#[derive(Debug, Clone, Default)]
pub(in crate::server) struct RecoveryBatch {
  pub recovered: Vec<JournalOperation>,
  /// These rows require a caller-supplied durable receipt and staged audit.
  pub requires_terminalization: Vec<JournalOperation>,
}

impl OperationJournal {
  #[allow(
    dead_code,
    reason = "convenience wrapper retained for focused journal users and tests"
  )]
  pub async fn finish(
    &self,
    guard: &LeaseGuard,
    terminal: &TerminalUpdate,
  ) -> anyhow::Result<Option<JournalOperation>> {
    let mut tx = self.pool.begin().await?;
    let operation = self.finish_tx(&mut tx, guard, terminal).await?;
    tx.commit().await?;
    Ok(operation)
  }

  /// Writes a terminal state inside a caller-owned transaction so enforcing
  /// Admin audit can be inserted and committed atomically with the receipt.
  pub async fn finish_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    guard: &LeaseGuard,
    terminal: &TerminalUpdate,
  ) -> anyhow::Result<Option<JournalOperation>> {
    guard.validate()?;
    terminal.validate()?;
    let allowed_predecessors = match terminal.state {
      AdminOperationState::Succeeded => &["running", "cancellation_requested"][..],
      AdminOperationState::Failed => &["running", "cancellation_requested", "compensating"],
      AdminOperationState::Cancelled => &["cancellation_requested", "compensating"],
      AdminOperationState::Indeterminate => &["running", "cancellation_requested", "compensating"],
      _ => unreachable!("validated terminal state"),
    };
    let result_json = terminal
      .result
      .as_ref()
      .map(serde_json::to_string)
      .transpose()?;
    let row = sqlx::query(AssertSqlSafe(format!(
      "UPDATE oxibelt_admin_operations
          SET state = $7, revision = revision + 1, terminal_result = $8::jsonb,
              terminal_receipt = $9, terminal_audit_record_id = $10,
              safe_error_class = $11, error_code = $12, owner_worker_id = NULL,
              owner_boot_id = NULL, lease_expires_at = NULL, updated_at = now(),
              retention_until = now() + make_interval(secs => retention_seconds::double precision)
        WHERE namespace = $1 AND operation_id = $2 AND owner_worker_id = $3
          AND owner_boot_id = $4 AND lease_epoch = $5 AND revision = $6
          AND state = ANY($13::text[]) AND lease_expires_at > now()
        RETURNING {}",
      RETURNING_COLUMNS
    )))
    .bind(&self.namespace)
    .bind(&guard.operation_id)
    .bind(&guard.worker_id)
    .bind(&guard.boot_id)
    .bind(i64::try_from(guard.lease_epoch)?)
    .bind(i64::try_from(guard.expected_revision)?)
    .bind(terminal.state.as_str())
    .bind(&result_json)
    .bind(&terminal.receipt)
    .bind(terminal.terminal_audit_record_id)
    .bind(&terminal.safe_error_class)
    .bind(&terminal.error_code)
    .bind(allowed_predecessors)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let operation = operation_from_row(&row)?;
    insert_event_tx(
      tx,
      &self.namespace,
      &guard.operation_id,
      operation.revision,
      terminal_event(terminal.state),
      terminal.state,
      operation.progress.as_ref(),
      None,
    )
    .await?;
    Ok(Some(operation))
  }

  pub async fn request_cancel(
    &self,
    operation_id: &str,
    expected_revision: Option<u64>,
  ) -> anyhow::Result<Option<CancelOutcome>> {
    validate_text("operation_id", operation_id, 256)?;
    let mut tx = self.pool.begin().await?;
    let statement = operation_select("WHERE namespace = $1 AND operation_id = $2 FOR UPDATE");
    let row = sqlx::query(AssertSqlSafe(statement))
      .bind(&self.namespace)
      .bind(operation_id)
      .fetch_optional(&mut *tx)
      .await?;
    let Some(row) = row else {
      tx.commit().await?;
      return Ok(None);
    };
    let current = operation_from_row(&row)?;
    let outcome = if current.state.is_terminal() {
      CancelOutcome::Terminal(current)
    } else if current.state == AdminOperationState::CancellationRequested
      || current.state == AdminOperationState::Compensating
    {
      CancelOutcome::AlreadyRequested(current)
    } else if expected_revision.is_some_and(|revision| revision != current.revision) {
      CancelOutcome::RevisionConflict(current)
    } else {
      let row = sqlx::query(AssertSqlSafe(format!(
        "UPDATE oxibelt_admin_operations
            SET state = 'cancellation_requested', revision = revision + 1, updated_at = now()
          WHERE namespace = $1 AND operation_id = $2 RETURNING {}",
        RETURNING_COLUMNS
      )))
      .bind(&self.namespace)
      .bind(operation_id)
      .fetch_one(&mut *tx)
      .await?;
      let updated = operation_from_row(&row)?;
      insert_event_tx(
        &mut tx,
        &self.namespace,
        operation_id,
        updated.revision,
        "operation.cancellation_requested",
        updated.state,
        updated.progress.as_ref(),
        None,
      )
      .await?;
      CancelOutcome::Requested(updated)
    };
    tx.commit().await?;
    Ok(Some(outcome))
  }

  /// Atomically cancels work that has no execution owner. The caller stages
  /// enforcing Admin audit in the same transaction before committing.
  pub async fn cancel_unstarted_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    operation_id: &str,
    expected_revision: u64,
    receipt: &[u8],
    terminal_audit_record_id: i64,
  ) -> anyhow::Result<Option<JournalOperation>> {
    validate_text("operation_id", operation_id, 256)?;
    validate_terminal_material(
      receipt,
      terminal_audit_record_id,
      Some("operation_cancelled"),
      Some("cancelled"),
    )?;
    let statement = operation_select(
      "WHERE namespace = $1 AND operation_id = $2 AND revision = $3
         AND state IN ('accepted','queued','cancellation_requested')
         AND owner_worker_id IS NULL FOR UPDATE",
    );
    let row = sqlx::query(AssertSqlSafe(statement))
      .bind(&self.namespace)
      .bind(operation_id)
      .bind(i64::try_from(expected_revision)?)
      .fetch_optional(&mut **tx)
      .await?;
    let Some(row) = row else { return Ok(None) };
    let mut current = operation_from_row(&row)?;
    if current.state != AdminOperationState::CancellationRequested {
      let row = sqlx::query(AssertSqlSafe(format!(
        "UPDATE oxibelt_admin_operations
            SET state = 'cancellation_requested', revision = revision + 1, updated_at = now()
          WHERE namespace = $1 AND operation_id = $2 AND revision = $3
          RETURNING {}",
        RETURNING_COLUMNS
      )))
      .bind(&self.namespace)
      .bind(operation_id)
      .bind(i64::try_from(current.revision)?)
      .fetch_one(&mut **tx)
      .await?;
      current = operation_from_row(&row)?;
      insert_event_tx(
        tx,
        &self.namespace,
        operation_id,
        current.revision,
        "operation.cancellation_requested",
        current.state,
        current.progress.as_ref(),
        None,
      )
      .await?;
    }
    let row = sqlx::query(AssertSqlSafe(format!(
      "UPDATE oxibelt_admin_operations
          SET state = 'cancelled', revision = revision + 1, terminal_receipt = $4,
              terminal_audit_record_id = $5, safe_error_class = 'cancelled',
              error_code = 'operation_cancelled', updated_at = now(),
              retention_until = now() + make_interval(secs => retention_seconds::double precision)
        WHERE namespace = $1 AND operation_id = $2 AND revision = $3
          AND state = 'cancellation_requested' AND owner_worker_id IS NULL RETURNING {}",
      RETURNING_COLUMNS
    )))
    .bind(&self.namespace)
    .bind(operation_id)
    .bind(i64::try_from(current.revision)?)
    .bind(receipt)
    .bind(terminal_audit_record_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let operation = operation_from_row(&row)?;
    insert_event_tx(
      tx,
      &self.namespace,
      operation_id,
      operation.revision,
      "operation.cancelled",
      operation.state,
      operation.progress.as_ref(),
      None,
    )
    .await?;
    Ok(Some(operation))
  }

  /// Terminalizes an orphan with a caller-provided receipt and audit row. This
  /// deliberately has no worker lease, but still requires an exact revision.
  pub async fn mark_incomplete_indeterminate_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    operation_id: &str,
    expected_revision: u64,
    receipt: &[u8],
    terminal_audit_record_id: i64,
    error_code: &str,
  ) -> anyhow::Result<Option<JournalOperation>> {
    validate_terminal_material(receipt, terminal_audit_record_id, Some(error_code), None)?;
    let statement = operation_select(
      "WHERE namespace = $1 AND operation_id = $2 AND revision = $3
         AND state NOT IN ('succeeded','failed','cancelled','indeterminate') FOR UPDATE",
    );
    let row = sqlx::query(AssertSqlSafe(statement))
      .bind(&self.namespace)
      .bind(operation_id)
      .bind(i64::try_from(expected_revision)?)
      .fetch_optional(&mut **tx)
      .await?;
    let Some(row) = row else { return Ok(None) };
    let mut current = operation_from_row(&row)?;
    if matches!(
      current.state,
      AdminOperationState::Accepted | AdminOperationState::Queued | AdminOperationState::Claimed
    ) {
      let row = sqlx::query(AssertSqlSafe(format!(
        "UPDATE oxibelt_admin_operations
            SET state = 'cancellation_requested', revision = revision + 1, updated_at = now()
          WHERE namespace = $1 AND operation_id = $2 AND revision = $3 RETURNING {}",
        RETURNING_COLUMNS
      )))
      .bind(&self.namespace)
      .bind(operation_id)
      .bind(i64::try_from(current.revision)?)
      .fetch_one(&mut **tx)
      .await?;
      current = operation_from_row(&row)?;
      insert_event_tx(
        tx,
        &self.namespace,
        operation_id,
        current.revision,
        "operation.cancellation_requested",
        current.state,
        current.progress.as_ref(),
        None,
      )
      .await?;
    }
    let row = sqlx::query(AssertSqlSafe(format!(
      "UPDATE oxibelt_admin_operations
          SET state = 'indeterminate', revision = revision + 1, terminal_receipt = $4,
              terminal_audit_record_id = $5, safe_error_class = 'indeterminate', error_code = $6,
              owner_worker_id = NULL, owner_boot_id = NULL, lease_expires_at = NULL,
              updated_at = now(),
              retention_until = now() + make_interval(secs => retention_seconds::double precision)
        WHERE namespace = $1 AND operation_id = $2 AND revision = $3
          AND state IN ('running','cancellation_requested','compensating')
        RETURNING {}",
      RETURNING_COLUMNS
    )))
    .bind(&self.namespace)
    .bind(operation_id)
    .bind(i64::try_from(current.revision)?)
    .bind(receipt)
    .bind(terminal_audit_record_id)
    .bind(error_code)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let operation = operation_from_row(&row)?;
    insert_event_tx(
      tx,
      &self.namespace,
      operation_id,
      operation.revision,
      "operation.indeterminate",
      operation.state,
      operation.progress.as_ref(),
      None,
    )
    .await?;
    Ok(Some(operation))
  }

  /// Recovers only operations whose next action is provably safe. Rows needing
  /// a terminal receipt and audit are returned unchanged to the caller.
  pub async fn recover_expired(
    &self,
    supported_schema_version: u16,
    limit: i64,
  ) -> anyhow::Result<RecoveryBatch> {
    ensure!(
      supported_schema_version > 0,
      "supported schema version must be positive"
    );
    ensure!(
      (1..=1000).contains(&limit),
      "recovery limit must be between 1 and 1000"
    );
    let mut tx = self.pool.begin().await?;
    let mut statement = operation_select(
      "WHERE namespace = $1
         AND ((owner_worker_id IS NOT NULL AND lease_expires_at <= now()) OR expires_at <= now())
         AND state NOT IN ('succeeded','failed','cancelled','indeterminate')
       ORDER BY updated_at, operation_id FOR UPDATE SKIP LOCKED LIMIT $2",
    );
    statement = statement.replacen(
      " FROM oxibelt_admin_operations",
      ", now() >= expires_at AS lifetime_expired FROM oxibelt_admin_operations",
      1,
    );
    let rows = sqlx::query(AssertSqlSafe(statement))
      .bind(&self.namespace)
      .bind(limit)
      .fetch_all(&mut *tx)
      .await?;
    let mut batch = RecoveryBatch::default();
    for row in rows {
      let lifetime_expired: bool = row.try_get("lifetime_expired")?;
      let current = operation_from_row(&row)?;
      let next = if current.schema_version == supported_schema_version {
        recoverable_state(&current, lifetime_expired)
      } else {
        None
      };
      let Some(next) = next else {
        batch.requires_terminalization.push(current);
        continue;
      };
      let row = sqlx::query(AssertSqlSafe(format!(
        "UPDATE oxibelt_admin_operations SET state = $4, revision = revision + 1,
           owner_worker_id = NULL, owner_boot_id = NULL, lease_expires_at = NULL, updated_at = now()
         WHERE namespace = $1 AND operation_id = $2 AND revision = $3 RETURNING {}",
        RETURNING_COLUMNS
      )))
      .bind(&self.namespace)
      .bind(&current.operation_id)
      .bind(i64::try_from(current.revision)?)
      .bind(next.as_str())
      .fetch_one(&mut *tx)
      .await?;
      let updated = operation_from_row(&row)?;
      insert_event_tx(
        &mut tx,
        &self.namespace,
        &updated.operation_id,
        updated.revision,
        "operation.recovered",
        updated.state,
        updated.progress.as_ref(),
        None,
      )
      .await?;
      batch.recovered.push(updated);
    }
    tx.commit().await?;
    Ok(batch)
  }

  pub async fn recover_orphaned_nonterminal(
    &self,
    current_worker: &WorkerIdentity,
    limit: i64,
  ) -> anyhow::Result<Vec<JournalOperation>> {
    current_worker.validate()?;
    ensure!(
      (1..=1000).contains(&limit),
      "orphan limit must be between 1 and 1000"
    );
    let statement = operation_select(
      "WHERE namespace = $1 AND state NOT IN ('succeeded','failed','cancelled','indeterminate')
         AND ((owner_worker_id = $2 AND owner_boot_id <> $3)
           OR (owner_worker_id IS NULL AND submitter_worker_id = $2 AND submitter_boot_id <> $3))
       ORDER BY updated_at, operation_id LIMIT $4",
    );
    sqlx::query(AssertSqlSafe(statement))
      .bind(&self.namespace)
      .bind(&current_worker.worker_id)
      .bind(&current_worker.boot_id)
      .bind(limit)
      .fetch_all(&self.pool)
      .await?
      .iter()
      .map(operation_from_row)
      .collect()
  }

  pub async fn prune_terminal(&self, limit: i64) -> anyhow::Result<u64> {
    ensure!(
      (1..=10_000).contains(&limit),
      "prune limit must be between 1 and 10000"
    );
    let result = sqlx::query(
      "DELETE FROM oxibelt_admin_operations WHERE (namespace, operation_id) IN (
         SELECT namespace, operation_id FROM oxibelt_admin_operations
          WHERE namespace = $1 AND retention_until <= now()
            AND state IN ('succeeded','failed','cancelled','indeterminate')
          ORDER BY retention_until, operation_id FOR UPDATE SKIP LOCKED LIMIT $2
       )",
    )
    .bind(&self.namespace)
    .bind(limit)
    .execute(&self.pool)
    .await?;
    Ok(result.rows_affected())
  }

  #[allow(
    dead_code,
    reason = "convenience wrapper retained for focused journal users and tests"
  )]
  pub async fn put_artifact(&self, artifact: &SealedOperationArtifact) -> anyhow::Result<bool> {
    let mut tx = self.pool.begin().await?;
    let inserted = self.put_artifact_tx(&mut tx, artifact).await?;
    tx.commit().await?;
    Ok(inserted)
  }

  /// Stores sealed input/checkpoint bytes in a caller-owned journal/audit
  /// transaction. All binding values are rechecked against the operation row.
  pub async fn put_artifact_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    artifact: &SealedOperationArtifact,
  ) -> anyhow::Result<bool> {
    ensure!(
      artifact.binding.namespace == self.namespace,
      "artifact namespace mismatch"
    );
    ensure!(
      artifact.plaintext_len <= 16 * 1024 * 1024,
      "artifact exceeds journal bound"
    );
    let inserted = sqlx::query(
      "INSERT INTO oxibelt_admin_operation_artifacts
         (namespace, operation_id, artifact_id, artifact_kind, operation_kind, schema_version,
          principal, permission_action, resource_digest, request_fingerprint, algorithm,
          key_fingerprint, nonce, ciphertext, ciphertext_digest, plaintext_len)
       SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
         FROM oxibelt_admin_operations operation
        WHERE operation.namespace = $1 AND operation.operation_id = $2
          AND operation.kind = $5 AND operation.schema_version = $6
          AND operation.principal = $7 AND operation.permission_action = $8
          AND operation.resource_digest = $9 AND operation.request_fingerprint = $10
       ON CONFLICT DO NOTHING",
    )
    .bind(&artifact.binding.namespace)
    .bind(&artifact.binding.operation_id)
    .bind(&artifact.binding.artifact_id)
    .bind(&artifact.binding.artifact_kind)
    .bind(&artifact.binding.operation_kind)
    .bind(i32::from(artifact.binding.schema_version))
    .bind(&artifact.binding.principal)
    .bind(&artifact.binding.permission_action)
    .bind(&artifact.binding.resource_digest)
    .bind(&artifact.binding.request_fingerprint)
    .bind(OPERATION_ARTIFACT_ALGORITHM)
    .bind(&artifact.key_fingerprint)
    .bind(artifact.nonce.as_slice())
    .bind(artifact.ciphertext.as_slice())
    .bind(&artifact.ciphertext_digest)
    .bind(i32::try_from(artifact.plaintext_len)?)
    .execute(&mut **tx)
    .await?;
    Ok(inserted.rows_affected() == 1)
  }

  #[allow(
    dead_code,
    reason = "restart recovery reads sealed commands and checkpoints"
  )]
  pub async fn load_artifact(
    &self,
    operation_id: &str,
    artifact_id: &str,
  ) -> anyhow::Result<Option<StoredOperationArtifact>> {
    validate_text("operation_id", operation_id, 256)?;
    validate_text("artifact_id", artifact_id, 256)?;
    let row = sqlx::query(
      "SELECT namespace, operation_id, artifact_id, artifact_kind, operation_kind,
              schema_version, principal, permission_action, resource_digest, request_fingerprint,
              key_fingerprint, nonce, ciphertext, ciphertext_digest, plaintext_len
         FROM oxibelt_admin_operation_artifacts
        WHERE namespace = $1 AND operation_id = $2 AND artifact_id = $3",
    )
    .bind(&self.namespace)
    .bind(operation_id)
    .bind(artifact_id)
    .fetch_optional(&self.pool)
    .await?;
    row.as_ref().map(stored_artifact_from_row).transpose()
  }
}

impl TerminalUpdate {
  fn validate(&self) -> anyhow::Result<()> {
    ensure!(
      matches!(
        self.state,
        AdminOperationState::Succeeded
          | AdminOperationState::Failed
          | AdminOperationState::Cancelled
          | AdminOperationState::Indeterminate
      ),
      "terminal update must use a terminal durable state"
    );
    if let Some(result) = self.result.as_ref() {
      validate_json("terminal result", result, MAX_JSON_BYTES)?;
    }
    validate_terminal_material(
      &self.receipt,
      self.terminal_audit_record_id,
      self.error_code.as_deref(),
      self.safe_error_class.as_deref(),
    )
  }
}

fn validate_terminal_material(
  receipt: &[u8],
  audit_record_id: i64,
  error_code: Option<&str>,
  safe_error_class: Option<&str>,
) -> anyhow::Result<()> {
  ensure!(
    audit_record_id > 0,
    "terminal audit record ID must be positive"
  );
  ensure!(
    !receipt.is_empty() && receipt.len() <= MAX_RECEIPT_BYTES,
    "terminal receipt is invalid"
  );
  ensure!(
    serde_json::from_slice::<Value>(receipt)?.is_object(),
    "terminal receipt must be a JSON object"
  );
  if let Some(value) = error_code {
    validate_text("error_code", value, 128)?;
  }
  if let Some(value) = safe_error_class {
    AdminOperationSafeErrorClass::from_str(value).map_err(anyhow::Error::msg)?;
  }
  Ok(())
}

fn terminal_event(state: AdminOperationState) -> &'static str {
  match state {
    AdminOperationState::Succeeded => "operation.succeeded",
    AdminOperationState::Failed => "operation.failed",
    AdminOperationState::Cancelled => "operation.cancelled",
    AdminOperationState::Indeterminate => "operation.indeterminate",
    _ => unreachable!("validated terminal state"),
  }
}

fn recoverable_state(
  operation: &JournalOperation,
  lifetime_expired: bool,
) -> Option<AdminOperationState> {
  use crate::server::admin_operations::state_machine::{
    AdminOperationRecoveryAction as Action, admin_operation_recovery_action,
  };
  if lifetime_expired {
    return None;
  }
  match admin_operation_recovery_action(operation.state, operation.recovery_class) {
    Action::Requeue | Action::Reclaim => Some(AdminOperationState::Queued),
    Action::ReclaimCancellation => Some(AdminOperationState::CancellationRequested),
    Action::Compensate => Some(AdminOperationState::Compensating),
    Action::None | Action::MarkIndeterminate => None,
  }
}

#[allow(
  dead_code,
  reason = "restart recovery decodes sealed commands and checkpoints"
)]
fn stored_artifact_from_row(
  row: &sqlx::postgres::PgRow,
) -> anyhow::Result<StoredOperationArtifact> {
  Ok(StoredOperationArtifact {
    binding: OperationArtifactBinding {
      namespace: row.try_get("namespace")?,
      operation_id: row.try_get("operation_id")?,
      artifact_id: row.try_get("artifact_id")?,
      artifact_kind: row.try_get("artifact_kind")?,
      operation_kind: row.try_get("operation_kind")?,
      schema_version: u16::try_from(row.try_get::<i32, _>("schema_version")?)?,
      principal: row.try_get("principal")?,
      permission_action: row.try_get("permission_action")?,
      resource_digest: row.try_get("resource_digest")?,
      request_fingerprint: row.try_get("request_fingerprint")?,
    },
    key_fingerprint: row.try_get("key_fingerprint")?,
    nonce: row.try_get("nonce")?,
    ciphertext: row.try_get("ciphertext")?,
    ciphertext_digest: row.try_get("ciphertext_digest")?,
    plaintext_len: usize::try_from(row.try_get::<i32, _>("plaintext_len")?)?,
  })
}
