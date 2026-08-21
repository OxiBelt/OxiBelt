//! Opt-in PostgreSQL fault and fencing tests for the Admin-operation journal.

use sqlx::postgres::PgPoolOptions;

use super::*;
use crate::server::admin_operations::artifact::{
  OperationArtifactCipher, OperationArtifactPlaintext, sha256_digest,
};

const URL_ENV: &str = "OXIBELT_TEST_ADMIN_OPERATION_POSTGRES_URL";
const REQUIRE_ENV: &str = "OXIBELT_REQUIRE_ADMIN_OPERATION_POSTGRES_TESTS";

async fn test_journal(label: &str) -> Option<OperationJournal> {
  let url = match std::env::var(URL_ENV) {
    Ok(value) if !value.trim().is_empty() => value,
    _ => {
      assert_ne!(
        std::env::var(REQUIRE_ENV).as_deref(),
        Ok("1"),
        "{URL_ENV} must be set when PostgreSQL Admin-operation tests are required"
      );
      return None;
    }
  };
  let options = sqlx::postgres::PgConnectOptions::from_str(&url)
    .expect("Admin-operation PostgreSQL test URL must be valid");
  let pool = PgPoolOptions::new()
    .max_connections(4)
    .connect_with(options)
    .await
    .expect("connect Admin-operation PostgreSQL test database");
  let mut random = [0u8; 8];
  crate::crypto::random_fill(&mut random).expect("test namespace entropy");
  let namespace = format!(
    "admin-operation-test-{label}-{}",
    random
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect::<String>()
  );
  let journal = OperationJournal::new(pool, namespace).expect("test journal");
  journal
    .initialize()
    .await
    .expect("initialize journal schema");
  Some(journal)
}

fn new_operation(id: &str, idempotency: Option<String>) -> NewJournalOperation {
  NewJournalOperation {
    operation_id: id.to_string(),
    actor: "test-admin".to_string(),
    request_id: "request-1".to_string(),
    submitter_worker_id: "worker-a".to_string(),
    submitter_boot_id: "worker-a-boot".to_string(),
    principal: "spiffe://example.test/admin".to_string(),
    permission_action: "operations.write".to_string(),
    redacted_resource: Some("support-bundle".to_string()),
    resource_digest: sha256_digest(b"support-bundle"),
    idempotency_key_digest: idempotency,
    request_fingerprint: sha256_digest(b"support-bundle-request-v1"),
    kind: AdminOperationKind::SupportBundle,
    schema_version: 1,
    recovery_class: AdminOperationRecoveryClass::Restartable,
    progress: Some(serde_json::json!({"phase":"accepted"})),
    maximum_lifetime_seconds: 3600,
    retention_seconds: 3600,
  }
}

fn worker(name: &str) -> WorkerIdentity {
  WorkerIdentity {
    worker_id: name.to_string(),
    boot_id: format!("{name}-boot"),
  }
}

async fn cleanup(journal: &OperationJournal) {
  sqlx::query("DELETE FROM oxibelt_admin_operations WHERE namespace = $1")
    .bind(journal.namespace())
    .execute(journal.pool())
    .await
    .expect("clean test journal namespace");
}

#[tokio::test]
async fn fenced_owner_and_stable_terminal_receipt_survive_reload() {
  let Some(journal) = test_journal("fencing").await else {
    return;
  };
  let operation = new_operation("op_00000000-0000-4000-8000-000000000001", None);
  let InsertOutcome::Inserted(accepted) = journal
    .insert_accepted(&operation, 8, 32)
    .await
    .expect("insert operation")
  else {
    panic!("operation must be inserted");
  };
  let queued = journal
    .queue(&accepted.operation_id, accepted.revision)
    .await
    .expect("queue operation")
    .expect("queued row");
  let (_claimed, claim_guard) = journal
    .claim_id(&queued.operation_id, &worker("worker-a"), 15)
    .await
    .expect("claim operation")
    .expect("claim row");
  assert!(
    journal
      .claim_id(&queued.operation_id, &worker("worker-b"), 15)
      .await
      .expect("competing claim")
      .is_none()
  );
  let running = journal
    .start(&claim_guard)
    .await
    .expect("start operation")
    .expect("running row");
  assert_eq!(running.state, AdminOperationState::Running);
  sqlx::query(
    "UPDATE oxibelt_admin_operations SET lease_expires_at = now() - interval '1 second'
      WHERE namespace = $1 AND operation_id = $2",
  )
  .bind(journal.namespace())
  .bind(&running.operation_id)
  .execute(journal.pool())
  .await
  .expect("expire execution lease");
  let recovered = journal
    .recover_expired(1, 8)
    .await
    .expect("recover expired lease");
  assert_eq!(recovered.recovered.len(), 1);
  assert_eq!(recovered.recovered[0].state, AdminOperationState::Queued);
  let (reclaimed, reclaim_guard) = journal
    .claim_id(&running.operation_id, &worker("worker-b"), 15)
    .await
    .expect("reclaim operation")
    .expect("reclaimed row");
  let rerunning = journal
    .start(&reclaim_guard)
    .await
    .expect("restart operation")
    .expect("restarted row");
  assert!(
    !journal
      .renew_lease(&claim_guard, 15)
      .await
      .expect("stale renewal check"),
    "the claim revision must be fenced after starting"
  );
  assert!(
    journal
      .finish(
        &running.lease_guard().expect("stale running guard"),
        &TerminalUpdate {
          state: AdminOperationState::Succeeded,
          result: None,
          receipt: br#"{"state":"succeeded"}"#.to_vec(),
          terminal_audit_record_id: 1,
          safe_error_class: None,
          error_code: None,
          audit_anchor_required: false,
        },
      )
      .await
      .expect("stale completion")
      .is_none(),
    "expired owner must not commit completion"
  );
  assert!(reclaimed.lease_epoch > running.lease_epoch);
  let running_guard = rerunning.lease_guard().expect("running guard");
  let receipt = br#"{"operation_id":"op_00000000-0000-4000-8000-000000000001","schema_version":1,"state":"succeeded"}"#.to_vec();
  let terminal = journal
    .finish(
      &running_guard,
      &TerminalUpdate {
        state: AdminOperationState::Succeeded,
        result: Some(serde_json::json!({"ok":true})),
        receipt: receipt.clone(),
        terminal_audit_record_id: 1,
        safe_error_class: None,
        error_code: None,
        audit_anchor_required: false,
      },
    )
    .await
    .expect("finish operation")
    .expect("terminal row");
  assert_eq!(
    terminal.terminal_receipt.as_deref(),
    Some(receipt.as_slice())
  );
  let reloaded = journal
    .load(&terminal.operation_id)
    .await
    .expect("reload operation")
    .expect("durable operation");
  assert_eq!(reloaded.terminal_receipt, terminal.terminal_receipt);
  assert_eq!(reloaded.revision, terminal.revision);
  cleanup(&journal).await;
}

#[tokio::test]
async fn idempotency_capacity_cancellation_and_pruning_are_atomic() {
  let Some(journal) = test_journal("idempotency").await else {
    return;
  };
  let cipher = OperationArtifactCipher::new(&[7; 32], 1024).expect("test cipher");
  let digest = cipher
    .idempotency_key_digest(b"retry-1")
    .expect("idempotency digest");
  let operation = new_operation("op_00000000-0000-4000-8000-000000000002", Some(digest));
  let InsertOutcome::Inserted(inserted) = journal
    .insert_accepted(&operation, 1, 1)
    .await
    .expect("insert operation")
  else {
    panic!("operation must be inserted");
  };
  let sealed = cipher
    .seal(
      OperationArtifactBinding {
        namespace: journal.namespace().to_string(),
        operation_id: inserted.operation_id.clone(),
        artifact_id: "input-v1".to_string(),
        artifact_kind: "command".to_string(),
        operation_kind: inserted.kind.as_str().to_string(),
        schema_version: inserted.schema_version,
        principal: inserted.principal.clone(),
        permission_action: inserted.permission_action.clone(),
        resource_digest: inserted.resource_digest.clone(),
        request_fingerprint: inserted.request_fingerprint.clone(),
      },
      OperationArtifactPlaintext::new(b"sealed support bundle options".to_vec()),
    )
    .expect("seal operation artifact");
  assert!(journal.put_artifact(&sealed).await.expect("store artifact"));
  let opened = cipher
    .open(
      journal
        .load_artifact(&inserted.operation_id, "input-v1")
        .await
        .expect("load artifact")
        .expect("stored artifact"),
    )
    .expect("open stored artifact");
  assert_eq!(opened.as_bytes(), b"sealed support bundle options");
  assert!(matches!(
    journal
      .insert_accepted(&operation, 1, 1)
      .await
      .expect("replay"),
    InsertOutcome::Replay(_)
  ));
  let mut conflicting = operation.clone();
  conflicting.operation_id = "op_00000000-0000-4000-8000-000000000004".to_string();
  conflicting.request_fingerprint = sha256_digest(b"different-request");
  assert!(matches!(
    journal
      .insert_accepted(&conflicting, 1, 1)
      .await
      .expect("idempotency conflict"),
    InsertOutcome::Conflict(_)
  ));
  let other = new_operation("op_00000000-0000-4000-8000-000000000003", None);
  assert!(matches!(
    journal
      .insert_accepted(&other, 1, 1)
      .await
      .expect("capacity"),
    InsertOutcome::QueueFull
  ));
  sqlx::query(
    "UPDATE oxibelt_admin_operations
        SET created_at = now() - interval '2 hours', retention_until = now() - interval '1 second'
      WHERE namespace = $1 AND operation_id = $2",
  )
  .bind(journal.namespace())
  .bind(&inserted.operation_id)
  .execute(journal.pool())
  .await
  .expect("age active operation retention");
  assert_eq!(
    journal
      .prune_terminal(8)
      .await
      .expect("do not prune active"),
    0,
    "retention must never prune a nonterminal row"
  );
  let CancelOutcome::Requested(requested) = journal
    .request_cancel(&inserted.operation_id, Some(inserted.revision))
    .await
    .expect("request cancellation")
    .expect("operation exists")
  else {
    panic!("cancellation must be requested");
  };
  let receipt = br#"{"operation_id":"op_00000000-0000-4000-8000-000000000002","schema_version":1,"state":"cancelled"}"#;
  let mut tx = journal.pool().begin().await.expect("terminal transaction");
  let cancelled = journal
    .cancel_unstarted_tx(
      &mut tx,
      &requested.operation_id,
      requested.revision,
      receipt,
      2,
      false,
    )
    .await
    .expect("cancel operation")
    .expect("cancelled row");
  tx.commit().await.expect("commit cancellation");
  assert_eq!(cancelled.state, AdminOperationState::Cancelled);
  sqlx::query(
    "UPDATE oxibelt_admin_operations SET retention_until = now() - interval '1 second'
      WHERE namespace = $1 AND operation_id = $2",
  )
  .bind(journal.namespace())
  .bind(&cancelled.operation_id)
  .execute(journal.pool())
  .await
  .expect("expire retained operation");
  assert_eq!(journal.prune_terminal(8).await.expect("prune terminal"), 1);
  assert!(
    journal
      .load(&cancelled.operation_id)
      .await
      .expect("load pruned")
      .is_none()
  );
  cleanup(&journal).await;
}

#[tokio::test]
async fn cancellation_wins_completion_revision_race() {
  let Some(journal) = test_journal("cancel-race").await else {
    return;
  };
  let operation = new_operation("op_00000000-0000-4000-8000-000000000005", None);
  let InsertOutcome::Inserted(accepted) = journal
    .insert_accepted(&operation, 8, 32)
    .await
    .expect("insert operation")
  else {
    panic!("operation must be inserted");
  };
  let queued = journal
    .queue(&accepted.operation_id, accepted.revision)
    .await
    .expect("queue")
    .expect("queued row");
  let (_, claim_guard) = journal
    .claim_id(&queued.operation_id, &worker("worker-a"), 15)
    .await
    .expect("claim")
    .expect("claimed row");
  let running = journal
    .start(&claim_guard)
    .await
    .expect("start")
    .expect("running row");
  let running_guard = running.lease_guard().expect("running guard");
  let CancelOutcome::Requested(cancel_requested) = journal
    .request_cancel(&running.operation_id, Some(running.revision))
    .await
    .expect("request cancel")
    .expect("operation exists")
  else {
    panic!("cancellation request must win");
  };
  assert!(
    journal
      .finish(
        &running_guard,
        &TerminalUpdate {
          state: AdminOperationState::Succeeded,
          result: None,
          receipt: br#"{"state":"succeeded"}"#.to_vec(),
          terminal_audit_record_id: 3,
          safe_error_class: None,
          error_code: None,
          audit_anchor_required: false,
        },
      )
      .await
      .expect("stale completion")
      .is_none()
  );
  let cancelled = journal
    .finish(
      &cancel_requested.lease_guard().expect("cancel lease guard"),
      &TerminalUpdate {
        state: AdminOperationState::Cancelled,
        result: None,
        receipt: br#"{"state":"cancelled"}"#.to_vec(),
        terminal_audit_record_id: 4,
        safe_error_class: Some("cancelled".to_string()),
        error_code: Some("operation_cancelled".to_string()),
        audit_anchor_required: false,
      },
    )
    .await
    .expect("finish cancellation")
    .expect("cancelled row");
  assert_eq!(cancelled.state, AdminOperationState::Cancelled);
  cleanup(&journal).await;
}

#[tokio::test]
async fn completed_work_wins_late_cancellation_after_revision_retry() {
  let Some(journal) = test_journal("completion-cancel-race").await else {
    return;
  };
  let operation = new_operation("op_00000000-0000-4000-8000-000000000009", None);
  let InsertOutcome::Inserted(accepted) = journal
    .insert_accepted(&operation, 8, 32)
    .await
    .expect("insert operation")
  else {
    panic!("operation must be inserted");
  };
  let queued = journal
    .queue(&accepted.operation_id, accepted.revision)
    .await
    .expect("queue")
    .expect("queued row");
  let (_, claim_guard) = journal
    .claim_id(&queued.operation_id, &worker("worker-a"), 15)
    .await
    .expect("claim")
    .expect("claimed row");
  let running = journal
    .start(&claim_guard)
    .await
    .expect("start")
    .expect("running row");
  let progressed = journal
    .update_progress(
      &running.lease_guard().expect("running guard"),
      &serde_json::json!({"phase":"committing"}),
      None,
    )
    .await
    .expect("update progress")
    .expect("progressed row");
  let CancelOutcome::RevisionConflict(latest) = journal
    .request_cancel(&running.operation_id, Some(running.revision))
    .await
    .expect("stale cancellation attempt")
    .expect("operation exists")
  else {
    panic!("stale cancellation must expose the current revision");
  };
  assert_eq!(latest.revision, progressed.revision);
  let CancelOutcome::Requested(cancel_requested) = journal
    .request_cancel(&latest.operation_id, Some(latest.revision))
    .await
    .expect("retry cancellation")
    .expect("operation exists")
  else {
    panic!("cancellation retry must use the current revision");
  };
  let succeeded = journal
    .finish(
      &cancel_requested
        .lease_guard()
        .expect("cancellation-requested lease guard"),
      &TerminalUpdate {
        state: AdminOperationState::Succeeded,
        result: Some(serde_json::json!({"applied": true})),
        receipt: br#"{"state":"succeeded"}"#.to_vec(),
        terminal_audit_record_id: 5,
        safe_error_class: None,
        error_code: None,
        audit_anchor_required: false,
      },
    )
    .await
    .expect("finish completed work")
    .expect("succeeded row");
  assert_eq!(succeeded.state, AdminOperationState::Succeeded);
  cleanup(&journal).await;
}

#[tokio::test]
async fn restarted_submitter_recovers_ownerless_queued_work() {
  let Some(journal) = test_journal("submitter-recovery").await else {
    return;
  };
  let operation = new_operation("op_00000000-0000-4000-8000-000000000010", None);
  let InsertOutcome::Inserted(accepted) = journal
    .insert_accepted(&operation, 8, 32)
    .await
    .expect("insert operation")
  else {
    panic!("operation must be inserted");
  };
  let queued = journal
    .queue(&accepted.operation_id, accepted.revision)
    .await
    .expect("queue")
    .expect("queued row");
  assert!(queued.owner_worker_id.is_none());
  let restarted_worker = WorkerIdentity {
    worker_id: operation.submitter_worker_id.clone(),
    boot_id: "worker-a-new-boot".to_string(),
  };
  let orphans = journal
    .recover_orphaned_nonterminal(&restarted_worker, 8)
    .await
    .expect("load submitter orphans");
  assert_eq!(orphans.len(), 1);
  assert_eq!(orphans[0].operation_id, queued.operation_id);
  cleanup(&journal).await;
}

#[tokio::test]
async fn unsupported_non_resumable_recovery_requires_indeterminate_receipt() {
  let Some(journal) = test_journal("indeterminate").await else {
    return;
  };
  let mut operation = new_operation("op_00000000-0000-4000-8000-000000000006", None);
  operation.schema_version = 2;
  operation.recovery_class = AdminOperationRecoveryClass::NonResumable;
  let InsertOutcome::Inserted(accepted) = journal
    .insert_accepted(&operation, 8, 32)
    .await
    .expect("insert operation")
  else {
    panic!("operation must be inserted");
  };
  let queued = journal
    .queue(&accepted.operation_id, accepted.revision)
    .await
    .expect("queue")
    .expect("queued row");
  let (_, claim_guard) = journal
    .claim_id(&queued.operation_id, &worker("old-worker"), 15)
    .await
    .expect("claim")
    .expect("claimed row");
  let running = journal
    .start(&claim_guard)
    .await
    .expect("start")
    .expect("running row");
  sqlx::query(
    "UPDATE oxibelt_admin_operations SET lease_expires_at = now() - interval '1 second'
      WHERE namespace = $1 AND operation_id = $2",
  )
  .bind(journal.namespace())
  .bind(&running.operation_id)
  .execute(journal.pool())
  .await
  .expect("expire lease");
  let recovery = journal
    .recover_expired(1, 8)
    .await
    .expect("inspect unsupported recovery");
  assert!(recovery.recovered.is_empty());
  assert_eq!(recovery.requires_terminalization.len(), 1);
  assert_eq!(recovery.requires_terminalization[0].schema_version, 2);
  let receipt = br#"{"schema_version":1,"state":"indeterminate"}"#;
  let terminal_update = TerminalUpdate {
    state: AdminOperationState::Indeterminate,
    result: None,
    receipt: receipt.to_vec(),
    terminal_audit_record_id: 5,
    safe_error_class: Some("indeterminate".to_string()),
    error_code: Some("unsupported_operation_checkpoint_version".to_string()),
    audit_anchor_required: false,
  };
  let mut tx = journal.pool().begin().await.expect("terminal transaction");
  let terminal = journal
    .mark_incomplete_indeterminate_tx(
      &mut tx,
      &running.operation_id,
      running.revision,
      &terminal_update,
    )
    .await
    .expect("mark indeterminate")
    .expect("indeterminate row");
  tx.commit().await.expect("commit indeterminate");
  assert_eq!(terminal.state, AdminOperationState::Indeterminate);
  assert_eq!(
    terminal.error_code.as_deref(),
    Some("unsupported_operation_checkpoint_version")
  );
  cleanup(&journal).await;
}

#[tokio::test]
async fn database_disconnect_never_serves_cached_journal_state() {
  let Some(journal) = test_journal("disconnect").await else {
    return;
  };
  journal.pool().close().await;
  assert!(
    journal
      .load("op_00000000-0000-4000-8000-000000000007")
      .await
      .is_err(),
    "closed PostgreSQL authority must fail rather than synthesize state"
  );
}
