//! Durable Admin-operation execution backed by the PostgreSQL journal.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::{Mutex, broadcast};
use tracing::warn;

use crate::admin_audit::AdminAuditRuntime;

use super::artifact::{OperationArtifactPlaintext, sha256_digest};
use super::id::new_operation_id;
use super::runtime::{
  AdminOperationContext, AdminOperationError, AdminOperationRuntime, AdminOperationSubmission,
  AdminOperationWorkResult,
};
use super::runtime_durable_support::{
  event_from_journal, request_fingerprint, snapshot_from_journal, terminal_event,
  terminal_or_cancel_event, terminal_outcome, unavailable,
};
use super::runtime_durable_terminal::terminal_cancel_error;
use super::types::{
  ADMIN_OPERATION_SCHEMA_VERSION, AdminOperationEvent, AdminOperationProgress,
  AdminOperationSafeErrorClass, AdminOperationSnapshot, AdminOperationState,
};
use super::{
  CancelOutcome, InsertOutcome, LeaseGuard, NewJournalOperation, OperationArtifactBinding,
  OperationArtifactCipher, OperationJournal, WorkerIdentity,
};
use crate::server::admin_auth::AdminActor;

#[derive(Clone)]
pub(super) struct DurableOperationRuntime {
  pub(super) journal: OperationJournal,
  pub(super) cipher: Arc<OperationArtifactCipher>,
  pub(super) audit: AdminAuditRuntime,
  pub(super) worker: WorkerIdentity,
  pub(super) lease_seconds: i64,
  pub(super) lease_renew_seconds: u64,
  pub(super) max_lifetime_seconds: i64,
  pub(super) retention_seconds: i64,
  pub(super) max_queued: usize,
  pub(super) max_stored: usize,
  pub(super) result_max_bytes: usize,
  pub(super) shutting_down: Arc<AtomicBool>,
}

impl DurableOperationRuntime {
  pub(super) async fn shutdown(&self) {
    self.shutting_down.store(true, Ordering::SeqCst);
  }

  pub(super) async fn enqueue<F, Fut>(
    &self,
    runtime: AdminOperationRuntime,
    submission: AdminOperationSubmission,
    actor: &AdminActor,
    request_id: String,
    work: F,
  ) -> Result<AdminOperationSnapshot, AdminOperationError>
  where
    F: FnOnce(AdminOperationContext) -> Fut + Send + 'static,
    Fut: Future<Output = AdminOperationWorkResult> + Send + 'static,
  {
    if self.shutting_down.load(Ordering::SeqCst) {
      return Err(AdminOperationError::Unavailable);
    }
    let operation_id = new_operation_id().map_err(|_| AdminOperationError::Internal)?;
    let command_bytes = serde_json::to_vec(&submission.command.clone().unwrap_or(Value::Null))
      .map_err(|_| AdminOperationError::Internal)?;
    let resource = submission
      .redacted_resource
      .clone()
      .unwrap_or_else(|| format!("operation/{}", submission.kind.as_str()));
    let resource_digest = sha256_digest(resource.as_bytes());
    let request_fingerprint = request_fingerprint(&submission, &resource_digest, &command_bytes);
    let idempotency_key_digest = submission
      .idempotency_key
      .as_deref()
      .map(|key| self.cipher.idempotency_key_digest(key.as_bytes()))
      .transpose()
      .map_err(|_| AdminOperationError::Internal)?;
    let initial_progress = json!({"phase":"accepted"});
    let new_operation = NewJournalOperation {
      operation_id: operation_id.clone(),
      actor: actor.name.clone(),
      request_id: request_id.clone(),
      submitter_worker_id: self.worker.worker_id.clone(),
      submitter_boot_id: self.worker.boot_id.clone(),
      principal: actor.principal.clone(),
      permission_action: submission.permission_action.clone(),
      redacted_resource: submission.redacted_resource.clone(),
      resource_digest: resource_digest.clone(),
      idempotency_key_digest,
      request_fingerprint: request_fingerprint.clone(),
      kind: submission.kind,
      schema_version: ADMIN_OPERATION_SCHEMA_VERSION,
      recovery_class: submission.recovery_class,
      progress: Some(initial_progress),
      maximum_lifetime_seconds: self.max_lifetime_seconds,
      retention_seconds: self.retention_seconds,
    };
    let sealed_command = if submission.command.is_some() {
      let binding = OperationArtifactBinding {
        namespace: self.journal.namespace().to_string(),
        operation_id: operation_id.clone(),
        artifact_id: "command-v1".to_string(),
        artifact_kind: "command".to_string(),
        operation_kind: submission.kind.as_str().to_string(),
        schema_version: ADMIN_OPERATION_SCHEMA_VERSION,
        principal: actor.principal.clone(),
        permission_action: submission.permission_action,
        resource_digest,
        request_fingerprint,
      };
      Some(
        self
          .cipher
          .seal(binding, OperationArtifactPlaintext::new(command_bytes))
          .map_err(|_| AdminOperationError::Internal)?,
      )
    } else {
      None
    };
    let accepted_event = self.audit.operation_lifecycle_event(
      &operation_id,
      submission.kind.as_str(),
      &actor.name,
      &actor.principal,
      &request_id,
      AdminOperationState::Accepted.as_str(),
      1,
      None,
    );
    let mut staged = self
      .audit
      .stage_critical_mutation(accepted_event)
      .await
      .map_err(unavailable)?;
    let mut tx = self
      .journal
      .pool()
      .begin()
      .await
      .map_err(|error| unavailable(error.into()))?;
    let accepted = self
      .journal
      .insert_accepted_tx(&mut tx, &new_operation, self.max_queued, self.max_stored)
      .await
      .map_err(unavailable)?;
    let accepted = match accepted {
      InsertOutcome::Replay(existing) => {
        drop(tx);
        drop(staged);
        let operation = if existing.state == AdminOperationState::Accepted {
          if self.audit.anchoring_enabled() {
            let retry_event = self.audit.operation_lifecycle_event(
              &existing.operation_id,
              existing.kind.as_str(),
              &existing.actor,
              &existing.principal,
              &existing.request_id,
              AdminOperationState::Accepted.as_str(),
              existing.revision,
              None,
            );
            let mut retry_audit = self
              .audit
              .stage_critical_mutation(retry_event)
              .await
              .map_err(unavailable)?;
            let mut retry_tx = self
              .journal
              .pool()
              .begin()
              .await
              .map_err(|error| unavailable(error.into()))?;
            retry_audit
              .insert(&mut retry_tx)
              .await
              .map_err(unavailable)?;
            retry_tx
              .commit()
              .await
              .map_err(|error| unavailable(error.into()))?;
            retry_audit.publish().await.map_err(unavailable)?;
          }
          self
            .journal
            .queue(&existing.operation_id, existing.revision)
            .await
            .map_err(unavailable)?
            .ok_or(AdminOperationError::Unavailable)?
        } else {
          existing
        };
        let snapshot = snapshot_from_journal(&operation);
        if operation.state == AdminOperationState::Queued {
          self
            .spawn_local_work(runtime, operation.operation_id, snapshot.clone(), work)
            .await;
        }
        return Ok(snapshot);
      }
      InsertOutcome::Conflict(_) => return Err(AdminOperationError::IdempotencyConflict),
      InsertOutcome::QueueFull => return Err(AdminOperationError::QueueFull),
      InsertOutcome::StoreFull => return Err(AdminOperationError::StoreFull),
      InsertOutcome::Inserted(operation) => operation,
    };
    if let Some(sealed) = sealed_command.as_ref()
      && !self
        .journal
        .put_artifact_tx(&mut tx, sealed)
        .await
        .map_err(unavailable)?
    {
      return Err(AdminOperationError::Unavailable);
    }
    let _accepted_audit_id = staged.insert(&mut tx).await.map_err(unavailable)?;
    let queued = if self.audit.anchoring_enabled() {
      None
    } else {
      Some(
        self
          .journal
          .queue_tx(&mut tx, &operation_id, accepted.revision)
          .await
          .map_err(unavailable)?
          .ok_or(AdminOperationError::Unavailable)?,
      )
    };
    tx.commit()
      .await
      .map_err(|error| unavailable(error.into()))?;
    staged.publish().await.map_err(unavailable)?;
    let queued = match queued {
      Some(queued) => queued,
      None => self
        .journal
        .queue(&operation_id, accepted.revision)
        .await
        .map_err(unavailable)?
        .ok_or(AdminOperationError::Unavailable)?,
    };
    let snapshot = snapshot_from_journal(&queued);
    self
      .spawn_local_work(runtime, operation_id, snapshot.clone(), work)
      .await;
    Ok(snapshot)
  }

  async fn spawn_local_work<F, Fut>(
    &self,
    runtime: AdminOperationRuntime,
    operation_id: String,
    snapshot: AdminOperationSnapshot,
    work: F,
  ) where
    F: FnOnce(AdminOperationContext) -> Fut + Send + 'static,
    Fut: Future<Output = AdminOperationWorkResult> + Send + 'static,
  {
    let cancel = Arc::new(AtomicBool::new(false));
    if !runtime
      .insert_durable_local(snapshot, Arc::clone(&cancel))
      .await
    {
      return;
    }
    let backend = self.clone();
    tokio::spawn(async move {
      backend.run_once(runtime, operation_id, cancel, work).await;
    });
  }

  async fn run_once<F, Fut>(
    self,
    runtime: AdminOperationRuntime,
    operation_id: String,
    cancel: Arc<AtomicBool>,
    work: F,
  ) where
    F: FnOnce(AdminOperationContext) -> Fut + Send + 'static,
    Fut: Future<Output = AdminOperationWorkResult> + Send + 'static,
  {
    let Ok(_permit) = runtime.running_semaphore().acquire_owned().await else {
      return;
    };
    let claimed = match self
      .journal
      .claim_id(&operation_id, &self.worker, self.lease_seconds)
      .await
    {
      Ok(Some(value)) => value,
      Ok(None) => return,
      Err(error) => {
        warn!(operation_id, error = %error, "failed to claim durable Admin operation");
        return;
      }
    };
    runtime
      .publish_durable(snapshot_from_journal(&claimed.0), "operation.claimed")
      .await;
    let guard = Arc::new(Mutex::new(claimed.1));
    runtime
      .set_durable_guard(&operation_id, Arc::clone(&guard))
      .await;
    let started = {
      let current = guard.lock().await.clone();
      self.journal.start(&current).await
    };
    let started = match started {
      Ok(Some(value)) => value,
      Ok(None) => {
        if let Ok(Some(current)) = self.journal.load(&operation_id).await
          && current.state == AdminOperationState::CancellationRequested
          && let Some(cancel_guard) = current.lease_guard()
          && let Ok(Some(cancelled)) = self
            .finish_with_audit(
              &cancel_guard,
              AdminOperationState::Cancelled,
              None,
              Some(AdminOperationSafeErrorClass::Cancelled),
              Some("operation_cancelled"),
            )
            .await
        {
          runtime
            .publish_durable(snapshot_from_journal(&cancelled), "operation.cancelled")
            .await;
        }
        return;
      }
      Err(error) => {
        warn!(operation_id, error = %error, "failed to start durable Admin operation");
        return;
      }
    };
    let Some(started_guard) = started.lease_guard() else {
      warn!(
        operation_id,
        "started Admin operation lost its durable lease metadata"
      );
      return;
    };
    *guard.lock().await = started_guard;
    runtime
      .publish_durable(snapshot_from_journal(&started), "operation.running")
      .await;

    let stop_renewal = Arc::new(AtomicBool::new(false));
    let authority_lost = Arc::new(AtomicBool::new(false));
    let renewal = self.spawn_lease_renewal(
      Arc::clone(&guard),
      Arc::clone(&cancel),
      Arc::clone(&stop_renewal),
      Arc::clone(&authority_lost),
    );
    let context = AdminOperationContext {
      id: operation_id.clone(),
      runtime: runtime.clone(),
      cancel: Arc::clone(&cancel),
      durable_guard: Some(Arc::clone(&guard)),
    };
    let result = work(context).await;
    stop_renewal.store(true, Ordering::SeqCst);
    let _ = renewal.await;
    if authority_lost.load(Ordering::SeqCst) || self.shutting_down.load(Ordering::SeqCst) {
      return;
    }
    match self.refresh_owned_guard(&guard, &cancel).await {
      Ok(true) => {}
      Ok(false) | Err(_) => return,
    }
    let guard = guard.lock().await.clone();
    let (state, result, class, code) =
      terminal_outcome(result, cancel.load(Ordering::SeqCst), self.result_max_bytes);
    match self
      .finish_with_audit(&guard, state, result, class, code)
      .await
    {
      Ok(Some(operation)) => {
        runtime
          .publish_durable(snapshot_from_journal(&operation), terminal_event(state))
          .await;
      }
      Ok(None) => {}
      Err(error) => {
        warn!(operation_id, error = %error, "failed to commit durable Admin operation terminal receipt")
      }
    }
  }

  fn spawn_lease_renewal(
    &self,
    guard: Arc<Mutex<LeaseGuard>>,
    cancel: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    authority_lost: Arc<AtomicBool>,
  ) -> tokio::task::JoinHandle<()> {
    let backend = self.clone();
    tokio::spawn(async move {
      let mut interval = tokio::time::interval(Duration::from_secs(backend.lease_renew_seconds));
      interval.tick().await;
      loop {
        interval.tick().await;
        if stop.load(Ordering::SeqCst) {
          return;
        }
        let current = guard.lock().await.clone();
        match backend
          .journal
          .renew_lease(&current, backend.lease_seconds)
          .await
        {
          Ok(true) => {}
          Ok(false) => match backend.refresh_owned_guard(&guard, &cancel).await {
            Ok(true) => continue,
            Ok(false) | Err(_) => {
              authority_lost.store(true, Ordering::SeqCst);
              cancel.store(true, Ordering::SeqCst);
              return;
            }
          },
          Err(_) => {
            authority_lost.store(true, Ordering::SeqCst);
            cancel.store(true, Ordering::SeqCst);
            return;
          }
        }
      }
    })
  }

  async fn refresh_owned_guard(
    &self,
    guard: &Arc<Mutex<LeaseGuard>>,
    cancel: &Arc<AtomicBool>,
  ) -> anyhow::Result<bool> {
    let previous = guard.lock().await.clone();
    let Some(operation) = self.journal.load(&previous.operation_id).await? else {
      return Ok(false);
    };
    let Some(current) = operation.lease_guard() else {
      return Ok(false);
    };
    if current.worker_id != previous.worker_id
      || current.boot_id != previous.boot_id
      || current.lease_epoch != previous.lease_epoch
    {
      return Ok(false);
    }
    if operation.state == AdminOperationState::CancellationRequested {
      cancel.store(true, Ordering::SeqCst);
    }
    *guard.lock().await = current;
    Ok(true)
  }

  pub(super) async fn progress(
    &self,
    runtime: &AdminOperationRuntime,
    operation_id: &str,
    guard: &Arc<Mutex<LeaseGuard>>,
    progress: AdminOperationProgress,
  ) {
    let progress_value = match serde_json::to_value(&progress) {
      Ok(value) => value,
      Err(_) => return,
    };
    let mut current = guard.lock().await;
    match self
      .journal
      .update_progress(&current, &progress_value, None)
      .await
    {
      Ok(Some(operation)) => {
        if let Some(next) = operation.lease_guard() {
          *current = next;
        }
        drop(current);
        runtime
          .publish_durable(snapshot_from_journal(&operation), "operation.progress")
          .await;
      }
      Ok(None) => {
        drop(current);
        if let Some((cancel, _, _)) = runtime.durable_local_parts(operation_id).await
          && !matches!(self.refresh_owned_guard(guard, &cancel).await, Ok(true))
        {
          cancel.store(true, Ordering::SeqCst);
        }
      }
      Err(error) => {
        drop(current);
        if let Some((cancel, _, _)) = runtime.durable_local_parts(operation_id).await {
          cancel.store(true, Ordering::SeqCst);
        }
        warn!(operation_id, error = %error, "failed to persist durable Admin operation progress")
      }
    }
  }

  pub(super) async fn contains(&self, operation_id: &str) -> Result<bool, AdminOperationError> {
    self
      .journal
      .load(operation_id)
      .await
      .map(|row| row.is_some())
      .map_err(unavailable)
  }

  pub(super) async fn get(
    &self,
    operation_id: &str,
  ) -> Result<Option<AdminOperationSnapshot>, AdminOperationError> {
    self
      .journal
      .load(operation_id)
      .await
      .map(|row| row.as_ref().map(snapshot_from_journal))
      .map_err(unavailable)
  }

  pub(super) async fn list(
    &self,
    limit: usize,
  ) -> Result<Vec<AdminOperationSnapshot>, AdminOperationError> {
    self
      .journal
      .list(i64::try_from(limit.min(1000)).map_err(|_| AdminOperationError::Internal)?)
      .await
      .map(|rows| rows.iter().map(snapshot_from_journal).collect())
      .map_err(unavailable)
  }

  pub(super) async fn subscribe(
    &self,
    _runtime: &AdminOperationRuntime,
    operation_id: &str,
  ) -> Result<
    Option<(
      Vec<AdminOperationEvent>,
      broadcast::Receiver<AdminOperationEvent>,
      AdminOperationSnapshot,
    )>,
    AdminOperationError,
  > {
    let Some(operation) = self.journal.load(operation_id).await.map_err(unavailable)? else {
      return Ok(None);
    };
    let snapshot = snapshot_from_journal(&operation);
    let journal_events = self
      .journal
      .events_since(operation_id, 0, 10_000)
      .await
      .map_err(unavailable)?;
    let next_revision = journal_events.last().map_or(0, |event| event.revision);
    let history = journal_events
      .iter()
      .map(|event| event_from_journal(event, &snapshot))
      .collect();
    let (sender, receiver) = broadcast::channel(256);
    if !snapshot.state.is_terminal() {
      let backend = self.clone();
      let operation_id = operation_id.to_string();
      tokio::spawn(async move {
        let mut next_revision = next_revision;
        loop {
          if sender.receiver_count() == 0 {
            return;
          }
          let events = match backend
            .journal
            .events_since(&operation_id, next_revision, 1_000)
            .await
          {
            Ok(events) => events,
            Err(_) => {
              tokio::time::sleep(Duration::from_millis(250)).await;
              continue;
            }
          };
          let current = match backend.journal.load(&operation_id).await {
            Ok(Some(current)) => current,
            Ok(None) => return,
            Err(_) => {
              tokio::time::sleep(Duration::from_millis(250)).await;
              continue;
            }
          };
          let current_snapshot = snapshot_from_journal(&current);
          for event in events {
            next_revision = event.revision;
            let _ = sender.send(event_from_journal(&event, &current_snapshot));
          }
          if current.state.is_terminal() && next_revision >= current.revision {
            return;
          }
          tokio::time::sleep(Duration::from_millis(250)).await;
        }
      });
    }
    Ok(Some((history, receiver, snapshot)))
  }

  pub(super) async fn cancel(
    &self,
    runtime: &AdminOperationRuntime,
    operation_id: &str,
  ) -> Result<AdminOperationSnapshot, AdminOperationError> {
    let current = self
      .journal
      .load(operation_id)
      .await
      .map_err(unavailable)?
      .ok_or(AdminOperationError::NotFound)?;
    if current.state.is_terminal() {
      return Err(terminal_cancel_error(current.terminal_audit_confirmed));
    }
    let mut expected_revision = current.revision;
    let mut remaining_attempts = 8_u8;
    let outcome = loop {
      let outcome = self
        .journal
        .request_cancel(operation_id, Some(expected_revision))
        .await
        .map_err(unavailable)?
        .ok_or(AdminOperationError::NotFound)?;
      match outcome {
        CancelOutcome::RevisionConflict(latest) if remaining_attempts > 1 => {
          expected_revision = latest.revision;
          remaining_attempts -= 1;
        }
        CancelOutcome::RevisionConflict(_) => return Err(AdminOperationError::Unavailable),
        outcome => break outcome,
      }
    };
    let operation = match outcome {
      CancelOutcome::Terminal(operation) => {
        return Err(terminal_cancel_error(operation.terminal_audit_confirmed));
      }
      CancelOutcome::Requested(operation) | CancelOutcome::AlreadyRequested(operation) => operation,
      CancelOutcome::RevisionConflict(_) => unreachable!("revision conflicts are retried above"),
    };
    if let Some((cancel, guard, _)) = runtime.durable_local_parts(operation_id).await {
      cancel.store(true, Ordering::SeqCst);
      if let Some(guard) = guard
        && operation.owner_worker_id.is_some()
      {
        *guard.lock().await = operation
          .lease_guard()
          .ok_or(AdminOperationError::Unavailable)?;
      }
    }
    let operation = if operation.owner_worker_id.is_none() {
      self
        .cancel_unstarted(&operation)
        .await
        .map_err(unavailable)?
    } else {
      operation
    };
    let snapshot = snapshot_from_journal(&operation);
    runtime
      .publish_durable(snapshot.clone(), terminal_or_cancel_event(snapshot.state))
      .await;
    Ok(snapshot)
  }
}
