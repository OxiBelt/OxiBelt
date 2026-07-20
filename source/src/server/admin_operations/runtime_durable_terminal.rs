//! Terminal audit commit and external-anchor visibility for durable Admin operations.

use anyhow::Context as _;
use serde_json::Value;

use super::runtime::AdminOperationError;
use super::runtime_durable::DurableOperationRuntime;
use super::runtime_durable_support::receipt_bytes;
use super::types::{AdminOperationSafeErrorClass, AdminOperationState};
use super::{JournalOperation, LeaseGuard, TerminalUpdate};

impl DurableOperationRuntime {
  pub(super) async fn finish_with_audit(
    &self,
    initial_guard: &LeaseGuard,
    state: AdminOperationState,
    result: Option<Value>,
    error_class: Option<AdminOperationSafeErrorClass>,
    error_code: Option<&str>,
  ) -> anyhow::Result<Option<JournalOperation>> {
    for _ in 0..4 {
      let current = self
        .journal
        .load(&initial_guard.operation_id)
        .await?
        .context("leased Admin operation disappeared")?;
      let Some(guard) = current.lease_guard() else {
        return Ok(None);
      };
      if guard.worker_id != initial_guard.worker_id
        || guard.boot_id != initial_guard.boot_id
        || guard.lease_epoch != initial_guard.lease_epoch
      {
        return Ok(None);
      }
      let revision = guard.expected_revision.saturating_add(1);
      let event = self.audit.operation_lifecycle_event(
        &current.operation_id,
        current.kind.as_str(),
        &current.actor,
        &current.principal,
        &current.request_id,
        state.as_str(),
        revision,
        error_code,
      );
      let mut staged = self.audit.stage_critical_mutation(event).await?;
      let mut tx = self.journal.pool().begin().await?;
      let audit_id = staged.insert(&mut tx).await?;
      let receipt = receipt_bytes(
        &current,
        state,
        revision,
        result.as_ref(),
        error_class,
        error_code,
        audit_id,
      )?;
      let terminal = TerminalUpdate {
        state,
        result: result.clone(),
        receipt,
        terminal_audit_record_id: audit_id,
        safe_error_class: error_class.map(|value| value.as_str().to_string()),
        error_code: error_code.map(str::to_string),
        audit_anchor_required: self.audit.anchoring_required(),
      };
      let updated = self.journal.finish_tx(&mut tx, &guard, &terminal).await?;
      if let Some(mut updated) = updated {
        tx.commit().await?;
        staged.publish().await?;
        if self.audit.anchoring_required() {
          self
            .journal
            .confirm_terminal_audit(&current.operation_id, audit_id)
            .await?;
          updated = self
            .journal
            .load(&current.operation_id)
            .await?
            .context("confirmed terminal Admin operation disappeared")?;
        }
        return Ok(Some(updated));
      }
    }
    Ok(None)
  }
}

pub(super) fn terminal_cancel_error(terminal_audit_confirmed: bool) -> AdminOperationError {
  if terminal_audit_confirmed {
    AdminOperationError::AlreadyTerminal
  } else {
    AdminOperationError::Unavailable
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cancellation_does_not_disclose_unconfirmed_terminal_state() {
    assert!(matches!(
      terminal_cancel_error(false),
      AdminOperationError::Unavailable
    ));
    assert!(matches!(
      terminal_cancel_error(true),
      AdminOperationError::AlreadyTerminal
    ));
  }
}
