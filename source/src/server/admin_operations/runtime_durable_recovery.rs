//! Restart reconciliation and cancellation terminalization for durable Admin operations.

use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context as _;
use tokio::time::MissedTickBehavior;
use tracing::warn;

use super::JournalOperation;
use super::runtime_durable::DurableOperationRuntime;
use super::runtime_durable_support::receipt_bytes;
use super::types::{
  ADMIN_OPERATION_SCHEMA_VERSION, AdminOperationSafeErrorClass, AdminOperationState,
};

impl DurableOperationRuntime {
  pub(super) fn spawn_recovery_sweeper(&self) {
    let runtime = self.clone();
    tokio::spawn(async move {
      let mut interval =
        tokio::time::interval(Duration::from_secs(runtime.lease_renew_seconds.max(1)));
      interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
      interval.tick().await;
      loop {
        interval.tick().await;
        if runtime.shutting_down.load(Ordering::SeqCst) {
          return;
        }
        if runtime.recover_incomplete().await.is_err() {
          warn!("durable Admin operation recovery sweep failed");
        }
      }
    });
  }

  pub(super) async fn cancel_unstarted(
    &self,
    current: &JournalOperation,
  ) -> anyhow::Result<JournalOperation> {
    let state = AdminOperationState::Cancelled;
    let revision = current.incomplete_terminal_revision();
    let event = self.audit.operation_lifecycle_event(
      &current.operation_id,
      current.kind.as_str(),
      &current.actor,
      &current.principal,
      &current.request_id,
      state.as_str(),
      revision,
      Some("operation_cancelled"),
    );
    let staged = self.audit.stage_critical_mutation(event).await?;
    let mut tx = self.journal.pool().begin().await?;
    let audit_id = staged.insert(&mut tx).await?;
    let receipt = receipt_bytes(
      current,
      state,
      revision,
      None,
      Some(AdminOperationSafeErrorClass::Cancelled),
      Some("operation_cancelled"),
      audit_id,
    )?;
    let updated = self
      .journal
      .cancel_unstarted_tx(
        &mut tx,
        &current.operation_id,
        current.revision,
        &receipt,
        audit_id,
      )
      .await?
      .context("unstarted Admin operation cancellation lost its revision race")?;
    tx.commit().await?;
    staged.publish();
    Ok(updated)
  }

  pub(super) async fn recover_incomplete(&self) -> anyhow::Result<()> {
    let batch = self
      .journal
      .recover_expired(ADMIN_OPERATION_SCHEMA_VERSION, 1000)
      .await?;
    let mut incomplete = batch.requires_terminalization;
    incomplete.extend(batch.recovered);
    let orphans = self
      .journal
      .recover_orphaned_nonterminal(&self.worker, 1000)
      .await?;
    incomplete.extend(orphans);
    incomplete.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    incomplete.dedup_by(|left, right| left.operation_id == right.operation_id);
    for operation in incomplete {
      let Some(current) = self.journal.load(&operation.operation_id).await? else {
        continue;
      };
      if current.state.is_terminal() {
        continue;
      }
      self
        .terminalize_incomplete(&current, "executor_recovery_unavailable")
        .await?;
    }
    Ok(())
  }

  async fn terminalize_incomplete(
    &self,
    current: &JournalOperation,
    error_code: &str,
  ) -> anyhow::Result<Option<JournalOperation>> {
    let state = AdminOperationState::Indeterminate;
    let revision = current.incomplete_terminal_revision();
    let event = self.audit.operation_lifecycle_event(
      &current.operation_id,
      current.kind.as_str(),
      &current.actor,
      &current.principal,
      &current.request_id,
      state.as_str(),
      revision,
      Some(error_code),
    );
    let staged = self.audit.stage_critical_mutation(event).await?;
    let mut tx = self.journal.pool().begin().await?;
    let audit_id = staged.insert(&mut tx).await?;
    let receipt = receipt_bytes(
      current,
      state,
      revision,
      None,
      Some(AdminOperationSafeErrorClass::Indeterminate),
      Some(error_code),
      audit_id,
    )?;
    let updated = self
      .journal
      .mark_incomplete_indeterminate_tx(
        &mut tx,
        &current.operation_id,
        current.revision,
        &receipt,
        audit_id,
        error_code,
      )
      .await?;
    if updated.is_none() {
      return Ok(None);
    }
    tx.commit().await?;
    staged.publish();
    Ok(updated)
  }
}
