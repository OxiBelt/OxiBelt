//! SQL row decoding shared by the Admin-operation journal paths.

use sqlx::{AssertSqlSafe, Executor, Postgres, Row};

use super::*;

pub(super) const RETURNING_COLUMNS: &str =
  "operation_id, actor, request_id, submitter_worker_id, submitter_boot_id, principal,
   permission_action, redacted_resource, resource_digest,
   request_fingerprint, kind, schema_version, recovery_class, state, revision,
   owner_worker_id, owner_boot_id, lease_epoch, progress::text AS progress, checkpoint_artifact_id,
   terminal_result::text AS terminal_result, terminal_receipt, terminal_audit_record_id,
   terminal_audit_confirmed_at IS NOT NULL AS terminal_audit_confirmed,
   safe_error_class, error_code,
   floor(extract(epoch FROM created_at) * 1000)::bigint AS created_at_ms,
   floor(extract(epoch FROM updated_at) * 1000)::bigint AS updated_at_ms,
   floor(extract(epoch FROM expires_at) * 1000)::bigint AS expires_at_ms,
   floor(extract(epoch FROM retention_until) * 1000)::bigint AS retention_until_ms";

pub(super) fn operation_select(suffix: &str) -> String {
  format!("SELECT {RETURNING_COLUMNS} FROM oxibelt_admin_operations {suffix}")
}

pub(super) async fn select_operation<'executor, E>(
  executor: E,
  namespace: &str,
  operation_id: &str,
) -> anyhow::Result<Option<JournalOperation>>
where
  E: Executor<'executor, Database = Postgres>,
{
  let statement = operation_select("WHERE namespace = $1 AND operation_id = $2");
  let row = sqlx::query(AssertSqlSafe(statement))
    .bind(namespace)
    .bind(operation_id)
    .fetch_optional(executor)
    .await?;
  row.as_ref().map(operation_from_row).transpose()
}

pub(super) fn operation_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<JournalOperation> {
  let kind =
    AdminOperationKind::from_str(row.try_get::<&str, _>("kind")?).map_err(anyhow::Error::msg)?;
  let recovery_class =
    AdminOperationRecoveryClass::from_str(row.try_get::<&str, _>("recovery_class")?)
      .map_err(anyhow::Error::msg)?;
  let state =
    AdminOperationState::from_str(row.try_get::<&str, _>("state")?).map_err(anyhow::Error::msg)?;
  Ok(JournalOperation {
    operation_id: row.try_get("operation_id")?,
    actor: row.try_get("actor")?,
    request_id: row.try_get("request_id")?,
    submitter_worker_id: row.try_get("submitter_worker_id")?,
    submitter_boot_id: row.try_get("submitter_boot_id")?,
    principal: row.try_get("principal")?,
    permission_action: row.try_get("permission_action")?,
    redacted_resource: row.try_get("redacted_resource")?,
    resource_digest: row.try_get("resource_digest")?,
    request_fingerprint: row.try_get("request_fingerprint")?,
    kind,
    schema_version: positive_u16(row.try_get("schema_version")?, "schema_version")?,
    recovery_class,
    state,
    revision: positive_u64(row.try_get("revision")?, "revision")?,
    owner_worker_id: row.try_get("owner_worker_id")?,
    owner_boot_id: row.try_get("owner_boot_id")?,
    lease_epoch: nonnegative_u64(row.try_get("lease_epoch")?, "lease_epoch")?,
    progress: parse_json_column(row, "progress")?,
    checkpoint_artifact_id: row.try_get("checkpoint_artifact_id")?,
    terminal_result: parse_json_column(row, "terminal_result")?,
    terminal_receipt: row.try_get("terminal_receipt")?,
    terminal_audit_record_id: row.try_get("terminal_audit_record_id")?,
    terminal_audit_confirmed: row.try_get("terminal_audit_confirmed")?,
    safe_error_class: row.try_get("safe_error_class")?,
    error_code: row.try_get("error_code")?,
    created_at_unix_ms: nonnegative_u64(row.try_get("created_at_ms")?, "created_at")?,
    updated_at_unix_ms: nonnegative_u64(row.try_get("updated_at_ms")?, "updated_at")?,
    expires_at_unix_ms: nonnegative_u64(row.try_get("expires_at_ms")?, "expires_at")?,
    retention_until_unix_ms: nonnegative_u64(
      row.try_get("retention_until_ms")?,
      "retention_until",
    )?,
  })
}

pub(super) fn event_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<JournalEvent> {
  Ok(JournalEvent {
    revision: positive_u64(row.try_get("revision")?, "revision")?,
    event: row.try_get("event")?,
    state: AdminOperationState::from_str(row.try_get::<&str, _>("state")?)
      .map_err(anyhow::Error::msg)?,
    progress: parse_json_column(row, "progress")?,
    payload: parse_json_column(row, "payload")?,
    created_at_unix_ms: nonnegative_u64(row.try_get("created_at_ms")?, "created_at")?,
  })
}

#[allow(
  clippy::too_many_arguments,
  reason = "the append-only event row is bound explicitly to every journal identity field"
)]
pub(super) async fn insert_event_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  operation_id: &str,
  revision: u64,
  event: &str,
  state: AdminOperationState,
  progress: Option<&Value>,
  payload: Option<&Value>,
) -> anyhow::Result<()> {
  validate_event(event)?;
  if let Some(value) = payload {
    validate_json("event payload", value, MAX_RECEIPT_BYTES)?;
  }
  let progress = progress.map(serde_json::to_string).transpose()?;
  let payload = payload.map(serde_json::to_string).transpose()?;
  sqlx::query(
    "INSERT INTO oxibelt_admin_operation_events
       (namespace, operation_id, revision, event, state, progress, payload)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb)",
  )
  .bind(namespace)
  .bind(operation_id)
  .bind(i64::try_from(revision)?)
  .bind(event)
  .bind(state.as_str())
  .bind(&progress)
  .bind(&payload)
  .execute(&mut **tx)
  .await?;
  Ok(())
}

fn parse_json_column(row: &sqlx::postgres::PgRow, name: &str) -> anyhow::Result<Option<Value>> {
  row
    .try_get::<Option<String>, _>(name)?
    .map(|value| serde_json::from_str(&value))
    .transpose()
    .map_err(Into::into)
}

fn positive_u64(value: i64, field: &str) -> anyhow::Result<u64> {
  ensure!(value > 0, "stored {field} must be positive");
  Ok(u64::try_from(value)?)
}

fn nonnegative_u64(value: i64, field: &str) -> anyhow::Result<u64> {
  ensure!(value >= 0, "stored {field} must not be negative");
  Ok(u64::try_from(value)?)
}

fn positive_u16(value: i32, field: &str) -> anyhow::Result<u16> {
  ensure!(value > 0, "stored {field} must be positive");
  Ok(u16::try_from(value)?)
}
