//! External audit-anchor confirmation gates for durable Admin mutations.

use anyhow::ensure;

use super::ledger::validate_identifier;
use super::store::MutationStore;

impl MutationStore {
  pub(crate) async fn confirm_terminal_audit(
    &self,
    request_id: &str,
    terminal_audit_record_id: i64,
  ) -> anyhow::Result<()> {
    validate_identifier("request_id", request_id, 256)?;
    ensure!(
      terminal_audit_record_id > 0,
      "terminal_audit_record_id must be positive"
    );
    let confirmed = sqlx::query(
      "UPDATE oxibelt_admin_mutations
          SET terminal_audit_confirmed_at=COALESCE(
                terminal_audit_confirmed_at, clock_timestamp())
        WHERE namespace=$1 AND request_id=$2
          AND terminal_audit_record_id=$3
          AND state IN ('committed','failed','rolled_back',
                        'rollback_failed','indeterminate')",
    )
    .bind(self.namespace())
    .bind(request_id)
    .bind(terminal_audit_record_id)
    .execute(self.pool())
    .await?;
    ensure!(
      confirmed.rows_affected() == 1,
      "terminal Admin mutation changed before audit anchor confirmation"
    );
    Ok(())
  }

  pub(crate) async fn confirm_admission_audit(
    &self,
    request_id: &str,
    audit_record_id: i64,
  ) -> anyhow::Result<()> {
    validate_identifier("request_id", request_id, 256)?;
    ensure!(audit_record_id > 0, "audit_record_id must be positive");
    let confirmed = sqlx::query(
      "UPDATE oxibelt_admin_mutations
          SET admission_audit_confirmed_at=COALESCE(
                admission_audit_confirmed_at, clock_timestamp())
        WHERE namespace=$1 AND request_id=$2 AND audit_record_id=$3",
    )
    .bind(self.namespace())
    .bind(request_id)
    .bind(audit_record_id)
    .execute(self.pool())
    .await?;
    ensure!(
      confirmed.rows_affected() == 1,
      "Admin mutation changed before admission audit anchor confirmation"
    );
    Ok(())
  }
}
