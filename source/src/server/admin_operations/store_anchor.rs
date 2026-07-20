//! External audit-anchor visibility gates for durable Admin-operation history.

use anyhow::ensure;

use super::rows::event_from_row;
use super::validation::validate_text;
use super::{JournalEvent, OperationJournal};

impl OperationJournal {
  pub async fn events_since(
    &self,
    operation_id: &str,
    after_revision: u64,
    limit: i64,
  ) -> anyhow::Result<Vec<JournalEvent>> {
    validate_text("operation_id", operation_id, 256)?;
    ensure!(
      (1..=10_000).contains(&limit),
      "event limit must be between 1 and 10000"
    );
    let after_revision = i64::try_from(after_revision)?;
    sqlx::query(
      "SELECT revision, event, state, progress::text AS progress, payload::text AS payload,
              floor(extract(epoch FROM created_at) * 1000)::bigint AS created_at_ms
         FROM oxibelt_admin_operation_events
        WHERE namespace = $1 AND operation_id = $2 AND revision > $3
          AND (state NOT IN ('succeeded','failed','cancelled','indeterminate')
            OR EXISTS (
              SELECT 1 FROM oxibelt_admin_operations operation
               WHERE operation.namespace=oxibelt_admin_operation_events.namespace
                 AND operation.operation_id=oxibelt_admin_operation_events.operation_id
                 AND operation.terminal_audit_confirmed_at IS NOT NULL))
        ORDER BY revision ASC LIMIT $4",
    )
    .bind(self.namespace())
    .bind(operation_id)
    .bind(after_revision)
    .bind(limit)
    .fetch_all(self.pool())
    .await?
    .iter()
    .map(event_from_row)
    .collect()
  }

  pub async fn confirm_terminal_audit(
    &self,
    operation_id: &str,
    terminal_audit_record_id: i64,
  ) -> anyhow::Result<()> {
    validate_text("operation_id", operation_id, 256)?;
    ensure!(
      terminal_audit_record_id > 0,
      "terminal audit record ID must be positive"
    );
    let confirmed = sqlx::query(
      "UPDATE oxibelt_admin_operations
          SET terminal_audit_confirmed_at=COALESCE(
                terminal_audit_confirmed_at, clock_timestamp())
        WHERE namespace=$1 AND operation_id=$2
          AND terminal_audit_record_id=$3
          AND state IN ('succeeded','failed','cancelled','indeterminate')",
    )
    .bind(self.namespace())
    .bind(operation_id)
    .bind(terminal_audit_record_id)
    .execute(self.pool())
    .await?;
    ensure!(
      confirmed.rows_affected() == 1,
      "terminal Admin operation changed before audit anchor confirmation"
    );
    Ok(())
  }
}
