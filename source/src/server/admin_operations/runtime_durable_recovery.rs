//! Restart reconciliation and cancellation terminalization for durable Admin operations.

use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context as _;
use tokio::time::MissedTickBehavior;
use tracing::warn;

use crate::state::AppHandle;

use super::runtime::AdminOperationRuntime;
use super::runtime_durable::DurableOperationRuntime;
use super::runtime_durable_support::{receipt_bytes, snapshot_from_journal};
use super::types::{
  ADMIN_OPERATION_SCHEMA_VERSION, AdminOperationKind, AdminOperationRecoveryClass,
  AdminOperationSafeErrorClass, AdminOperationState,
};
use super::{JournalOperation, OperationArtifactBinding, TerminalUpdate};

impl DurableOperationRuntime {
  pub(super) async fn activate_recovery(
    &self,
    operations: AdminOperationRuntime,
    state: AppHandle,
  ) -> anyhow::Result<()> {
    self
      .recover_incomplete(operations.clone(), state.clone())
      .await?;
    self.spawn_recovery_sweeper(operations, state);
    Ok(())
  }

  fn spawn_recovery_sweeper(&self, operations: AdminOperationRuntime, state: AppHandle) {
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
        if runtime
          .recover_incomplete(operations.clone(), state.clone())
          .await
          .is_err()
        {
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
    let mut staged = self.audit.stage_critical_mutation(event).await?;
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
    let mut updated = self
      .journal
      .cancel_unstarted_tx(
        &mut tx,
        &current.operation_id,
        current.revision,
        &receipt,
        audit_id,
        self.audit.anchoring_required(),
      )
      .await?
      .context("unstarted Admin operation cancellation lost its revision race")?;
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
        .context("confirmed cancelled Admin operation disappeared")?;
    }
    Ok(updated)
  }

  async fn recover_incomplete(
    &self,
    operations: AdminOperationRuntime,
    state: AppHandle,
  ) -> anyhow::Result<()> {
    let batch = self
      .journal
      .recover_expired(ADMIN_OPERATION_SCHEMA_VERSION, 1000)
      .await?;
    // Preserve the journal's lifetime and recovery classification. These
    // rows cannot be deferred or resumed even if their former lease remains.
    let must_terminalize = batch
      .requires_terminalization
      .iter()
      .map(|operation| operation.operation_id.clone())
      .collect::<std::collections::HashSet<_>>();
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
      if !must_terminalize.contains(&current.operation_id)
        && current.kind == AdminOperationKind::CacheWarm
        && current.recovery_class == AdminOperationRecoveryClass::Resumable
      {
        match current.state {
          AdminOperationState::Queued => {
            if self
              .resume_cache_warm(&operations, state.clone(), &current)
              .await
              .is_ok()
            {
              continue;
            }
          }
          AdminOperationState::CancellationRequested => {
            // A cancellation recovered from an expired lease has no owner.
            // Commit its fenced terminal receipt; never dispatch another item.
            if current.owner_worker_id.is_none() {
              self.cancel_unstarted(&current).await?;
            }
            // An old boot may still own an unexpired lease. Leave it alone
            // until recover_expired fences that owner and clears it.
            continue;
          }
          AdminOperationState::Claimed | AdminOperationState::Running => {
            // A same-instance restart sees its former boot as an orphan
            // before the lease expires. Deferring avoids terminalizing work
            // that recover_expired will safely requeue under a new fence.
            continue;
          }
          _ => {}
        }
      }
      self
        .terminalize_incomplete(&current, "executor_recovery_unavailable")
        .await?;
    }
    Ok(())
  }

  /// Reclaim the normal lease and run through the same executor used by a
  /// local submission. The command artifact is authenticated against every
  /// journal binding before it is deserialized; a crash can therefore repeat
  /// at most the in-flight item, never synthesize a new command.
  async fn resume_cache_warm(
    &self,
    operations: &AdminOperationRuntime,
    state: AppHandle,
    current: &JournalOperation,
  ) -> anyhow::Result<()> {
    let stored = self
      .journal
      .load_artifact(&current.operation_id, "command-v1")
      .await?
      .ok_or_else(|| anyhow::anyhow!("cache warm command artifact is absent"))?;
    validate_command_binding(self.journal.namespace(), current, &stored.binding)?;
    let plaintext = self.cipher.open(stored)?;
    let command = serde_json::from_slice(plaintext.as_bytes())?;
    let checkpoint = self.cache_warm_checkpoint(current).await?;
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if !operations
      .insert_durable_local(
        snapshot_from_journal(current),
        std::sync::Arc::clone(&cancel),
      )
      .await
    {
      return Ok(());
    }
    let backend = self.clone();
    let operation_id = current.operation_id.clone();
    let principal = current.principal.clone();
    let operations = operations.clone();
    tokio::spawn(async move {
      backend
        .run_once(
          operations,
          operation_id,
          cancel,
          move |context| async move {
            crate::server::admin::recover_cache_warm_command(
              command, state, principal, context, checkpoint,
            )
            .await
          },
        )
        .await;
    });
    Ok(())
  }

  async fn cache_warm_checkpoint(
    &self,
    current: &JournalOperation,
  ) -> anyhow::Result<serde_json::Value> {
    let Some(artifact_id) = current.checkpoint_artifact_id.as_deref() else {
      return Ok(serde_json::json!({
        "version": 1,
        "next_index": 0,
        "results": [],
      }));
    };
    let stored = self
      .journal
      .load_artifact(&current.operation_id, artifact_id)
      .await?
      .context("cache warm checkpoint artifact is absent")?;
    validate_checkpoint_binding(
      self.journal.namespace(),
      current,
      &stored.binding,
      artifact_id,
    )?;
    let plaintext = self.cipher.open(stored)?;
    let checkpoint: serde_json::Value = serde_json::from_slice(plaintext.as_bytes())?;
    let object = checkpoint
      .as_object()
      .filter(|value| {
        value.len() == 3
          && value.get("version") == Some(&serde_json::json!(1))
          && value
            .get("results")
            .is_some_and(serde_json::Value::is_array)
      })
      .context("cache warm checkpoint is invalid")?;
    let next_index = object
      .get("next_index")
      .and_then(serde_json::Value::as_u64)
      .filter(|value| *value <= 128)
      .and_then(|value| usize::try_from(value).ok())
      .context("cache warm checkpoint is invalid")?;
    anyhow::ensure!(
      object
        .get("results")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|results| results.len() == next_index),
      "cache warm checkpoint is invalid"
    );
    Ok(checkpoint)
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
    let mut staged = self.audit.stage_critical_mutation(event).await?;
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
    let terminal = TerminalUpdate {
      state,
      result: None,
      receipt,
      terminal_audit_record_id: audit_id,
      safe_error_class: Some(
        AdminOperationSafeErrorClass::Indeterminate
          .as_str()
          .to_string(),
      ),
      error_code: Some(error_code.to_string()),
      audit_anchor_required: self.audit.anchoring_required(),
    };
    let mut updated = self
      .journal
      .mark_incomplete_indeterminate_tx(&mut tx, &current.operation_id, current.revision, &terminal)
      .await?;
    if updated.is_none() {
      return Ok(None);
    }
    tx.commit().await?;
    staged.publish().await?;
    if self.audit.anchoring_required() {
      self
        .journal
        .confirm_terminal_audit(&current.operation_id, audit_id)
        .await?;
      updated = self.journal.load(&current.operation_id).await?;
    }
    Ok(updated)
  }
}

fn validate_command_binding(
  namespace: &str,
  operation: &JournalOperation,
  binding: &OperationArtifactBinding,
) -> anyhow::Result<()> {
  anyhow::ensure!(
    binding.namespace == namespace
      && binding.operation_id == operation.operation_id
      && binding.artifact_id == "command-v1"
      && binding.artifact_kind == "command"
      && binding.operation_kind == operation.kind.as_str()
      && binding.schema_version == operation.schema_version
      && binding.principal == operation.principal
      && binding.permission_action == operation.permission_action
      && binding.resource_digest == operation.resource_digest
      && binding.request_fingerprint == operation.request_fingerprint,
    "cache warm command artifact binding does not match its journal operation"
  );
  Ok(())
}

fn validate_checkpoint_binding(
  namespace: &str,
  operation: &JournalOperation,
  binding: &OperationArtifactBinding,
  artifact_id: &str,
) -> anyhow::Result<()> {
  anyhow::ensure!(
    binding.namespace == namespace
      && binding.operation_id == operation.operation_id
      && binding.artifact_id == artifact_id
      && binding.artifact_kind == "checkpoint"
      && binding.operation_kind == operation.kind.as_str()
      && binding.schema_version == operation.schema_version
      && binding.principal == operation.principal
      && binding.permission_action == operation.permission_action
      && binding.resource_digest == operation.resource_digest
      && binding.request_fingerprint == operation.request_fingerprint,
    "cache warm checkpoint artifact binding does not match its journal operation"
  );
  Ok(())
}
