//! Opt-in PostgreSQL fault and fencing tests for the Admin-operation journal.

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;

use super::*;
use crate::admin_audit::AdminAuditRuntime;
use crate::config::{
  AdminAuditAcknowledgement, AdminAuditMode, AdminOperationsPersistence, Config,
};
use crate::ipm::IpmRequestContext;
use crate::server::AdminOperationRuntime;
use crate::server::admin_operations::artifact::{
  OperationArtifactCipher, OperationArtifactPlaintext, sha256_digest,
};
use crate::state::{AppHandle, AppSnapshot};

const URL_ENV: &str = "OXIBELT_TEST_ADMIN_OPERATION_POSTGRES_URL";
const REQUIRE_ENV: &str = "OXIBELT_REQUIRE_ADMIN_OPERATION_POSTGRES_TESTS";
const RECOVERY_ARTIFACT_KEY_ENV: &str = "OXIBELT_TEST_ADMIN_OPERATION_RECOVERY_ARTIFACT_KEY";
const RECOVERY_INSTANCE_ID_ENV: &str = "OXIBELT_TEST_ADMIN_OPERATION_RECOVERY_INSTANCE_ID";

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

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

struct RecoveryFixture {
  _temp_dir: common::TempDir,
  journal: OperationJournal,
  audit: AdminAuditRuntime,
  config: Config,
  state: AppHandle,
}

async fn recovery_fixture(label: &str) -> Option<RecoveryFixture> {
  let journal = test_journal(label).await?;
  let audit =
    AdminAuditRuntime::test_with_postgres(journal.pool().clone(), journal.namespace().to_string())
      .await
      .expect("initialize durable Admin audit runtime");
  let temp_dir = common::TempDir::new(&format!("admin-operation-recovery-{label}"));
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), label);
  let mut raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("https://app.internal.example", "http://127.0.0.1:1")
    .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"")
    .replace(
      "upstream = \"app\"",
      "upstream = \"app\"\ncache = \"recovery\"",
    );
  raw.push_str(
    r#"

[cache]
enabled = true
store = "memory"
cache_methods = ["GET", "HEAD", "QUERY"]

[[cache.policies]]
name = "recovery"

[ipm]
enabled = true
namespace = "oxibelt"

[[ipm.principals]]
id = "operator"
subject = "operator@example.com"

[[ipm.credentials]]
name = "operator-token"
principal = "operator"
bearer_token_env = "PATH"

[[ipm.policies]]
name = "recover-cache-warm"

[[ipm.policies.statements]]
effect = "allow"
actions = ["cache:Warm"]
resources = [
  "oxibelt:oxibelt:cache:policy/recovery",
  "oxibelt:oxibelt:cache:host/example.com",
]

[[ipm.bindings]]
principal = "operator"
policy = "recover-cache-warm"
"#,
  );
  let mut config: Config = toml::from_str(&raw).expect("recovery state configuration parses");
  config
    .validate()
    .expect("recovery state configuration validates");
  config.shared_state.namespace = journal.namespace().to_string();
  config.shared_state.instance_id_env = RECOVERY_INSTANCE_ID_ENV.to_string();
  let state = AppHandle::new(
    AppSnapshot::new(config.clone())
      .await
      .expect("recovery AppHandle snapshot initializes"),
  );

  config.admin.operations.persistence = AdminOperationsPersistence::Postgres;
  config.admin.operations.artifact_key_env = RECOVERY_ARTIFACT_KEY_ENV.to_string();
  config.admin.operations.lease_seconds = 3;
  config.admin.operations.lease_renew_seconds = 1;
  config.admin.operations.max_lifetime_seconds = 60;
  config.admin.audit.enabled = true;
  config.admin.audit.mode = AdminAuditMode::DurableRequired;
  config.admin.audit.acknowledgement = AdminAuditAcknowledgement::Postgres;
  config.admin.audit.store.enabled = true;
  config.admin.audit.store.backend = Some("recovery-postgres".to_string());
  Some(RecoveryFixture {
    _temp_dir: temp_dir,
    journal,
    audit,
    config,
    state,
  })
}

fn recovery_operation(id: &str) -> NewJournalOperation {
  NewJournalOperation {
    operation_id: id.to_string(),
    actor: "operator-token".to_string(),
    request_id: format!("request-{id}"),
    submitter_worker_id: "crashed-worker".to_string(),
    submitter_boot_id: "crashed-boot".to_string(),
    principal: "operator".to_string(),
    permission_action: "cache:Warm".to_string(),
    redacted_resource: Some("cache/warm".to_string()),
    resource_digest: sha256_digest(b"cache/warm"),
    idempotency_key_digest: None,
    request_fingerprint: sha256_digest(b"cache-warm-recovery-query-v1"),
    kind: AdminOperationKind::CacheWarm,
    schema_version: 1,
    recovery_class: AdminOperationRecoveryClass::Resumable,
    progress: Some(serde_json::json!({"phase":"accepted"})),
    maximum_lifetime_seconds: 60,
    retention_seconds: 60,
  }
}

fn recovery_binding(
  namespace: &str,
  operation: &JournalOperation,
  artifact_id: &str,
  artifact_kind: &str,
) -> OperationArtifactBinding {
  OperationArtifactBinding {
    namespace: namespace.to_string(),
    operation_id: operation.operation_id.clone(),
    artifact_id: artifact_id.to_string(),
    artifact_kind: artifact_kind.to_string(),
    operation_kind: operation.kind.as_str().to_string(),
    schema_version: operation.schema_version,
    principal: operation.principal.clone(),
    permission_action: operation.permission_action.clone(),
    resource_digest: operation.resource_digest.clone(),
    request_fingerprint: operation.request_fingerprint.clone(),
  }
}

fn recovery_command() -> serde_json::Value {
  serde_json::json!({
    "version": 1,
    "request": {
      "items": [
        {
          "scheme": "http",
          "host": "example.com",
          "uri": "/already",
          "method": "QUERY",
          "headers": { "content-type": "application/json" },
          "query_body_base64": "e30=",
          "query_trailers": []
        },
        {
          "scheme": "http",
          "host": "example.com",
          "uri": "/remaining",
          "method": "QUERY",
          "headers": { "content-type": "application/json" },
          "query_body_base64": "e30=",
          "query_trailers": []
        }
      ]
    },
    "submitting_peer_addr": "127.0.0.1:12345",
    "request_context": serde_json::to_value(IpmRequestContext::default())
      .expect("serialize empty recovery request context")
  })
}

async fn insert_running_recovery_operation(
  fixture: &RecoveryFixture,
  operation_id: &str,
  command_binding: Option<OperationArtifactBinding>,
  checkpoint: Option<serde_json::Value>,
) -> JournalOperation {
  let operation = recovery_operation(operation_id);
  let InsertOutcome::Inserted(accepted) = fixture
    .journal
    .insert_accepted(&operation, 8, 32)
    .await
    .expect("insert resumable recovery operation")
  else {
    panic!("recovery operation must be inserted");
  };
  let queued = fixture
    .journal
    .queue(&accepted.operation_id, accepted.revision)
    .await
    .expect("queue resumable recovery operation")
    .expect("recovery operation must queue");
  let (_claimed, guard) = fixture
    .journal
    .claim_id(
      &queued.operation_id,
      &WorkerIdentity {
        worker_id: "crashed-worker".to_string(),
        boot_id: "crashed-boot".to_string(),
      },
      3,
    )
    .await
    .expect("claim resumable recovery operation")
    .expect("recovery operation must claim");
  let running = fixture
    .journal
    .start(&guard)
    .await
    .expect("start resumable recovery operation")
    .expect("recovery operation must start");
  let cipher =
    OperationArtifactCipher::new(&[1; 32], fixture.config.admin.operations.artifact_max_bytes)
      .expect("recovery artifact cipher");
  if let Some(binding) = command_binding {
    let command = serde_json::to_vec(&recovery_command()).expect("serialize recovery command");
    let sealed = cipher
      .seal(binding, OperationArtifactPlaintext::new(command))
      .expect("seal recovery command");
    assert!(
      fixture
        .journal
        .put_artifact(&sealed)
        .await
        .expect("store recovery command"),
      "recovery command must be stored"
    );
  }
  if let Some(checkpoint) = checkpoint {
    let artifact_id = format!("checkpoint-v1-{}", running.revision.saturating_add(1));
    let sealed = cipher
      .seal(
        recovery_binding(
          fixture.journal.namespace(),
          &running,
          &artifact_id,
          "checkpoint",
        ),
        OperationArtifactPlaintext::new(
          serde_json::to_vec(&checkpoint).expect("serialize recovery checkpoint"),
        ),
      )
      .expect("seal recovery checkpoint");
    assert!(
      fixture
        .journal
        .put_artifact(&sealed)
        .await
        .expect("store recovery checkpoint"),
      "recovery checkpoint must be stored"
    );
    return fixture
      .journal
      .update_progress(
        &running.lease_guard().expect("running recovery guard"),
        &serde_json::json!({"phase":"warming","processed":1,"total":2}),
        Some(&artifact_id),
      )
      .await
      .expect("advance committed recovery checkpoint")
      .expect("recovery checkpoint must retain its owner");
  }
  running
}

async fn expire_operation(journal: &OperationJournal, operation_id: &str) {
  sqlx::query(
    "UPDATE oxibelt_admin_operations SET lease_expires_at = now() - interval '1 second'
      WHERE namespace = $1 AND operation_id = $2",
  )
  .bind(journal.namespace())
  .bind(operation_id)
  .execute(journal.pool())
  .await
  .expect("expire crashed recovery owner");
}

async fn wait_for_terminal(journal: &OperationJournal, operation_id: &str) -> JournalOperation {
  tokio::time::timeout(Duration::from_secs(5), async {
    loop {
      let operation = journal
        .load(operation_id)
        .await
        .expect("load recovering operation")
        .expect("recovering operation remains retained");
      if operation.state.is_terminal() {
        return operation;
      }
      tokio::time::sleep(Duration::from_millis(20)).await;
    }
  })
  .await
  .expect("recovery must terminalize within its bounded test window")
}

async fn activate_recovery(fixture: &RecoveryFixture) -> AdminOperationRuntime {
  let runtime = AdminOperationRuntime::prepare(&fixture.config, &fixture.audit)
    .await
    .expect("prepare durable recovery runtime");
  runtime
    .activate_recovery(fixture.state.clone())
    .await
    .expect("activate durable recovery");
  runtime
}

async fn cleanup_recovery_fixture(fixture: &RecoveryFixture) {
  cleanup(&fixture.journal).await;
  sqlx::query("DELETE FROM oxibelt_admin_audit WHERE namespace = $1")
    .bind(fixture.journal.namespace())
    .execute(fixture.journal.pool())
    .await
    .expect("clean recovery audit namespace");
}

#[tokio::test]
async fn activate_recovery_resumes_only_remaining_query_item_after_postgres_restart() {
  let Some(fixture) = recovery_fixture("query-resume").await else {
    return;
  };
  let operation_id = "op_00000000-0000-4000-8000-000000000101";
  let accepted = recovery_operation(operation_id);
  let command_binding = OperationArtifactBinding {
    namespace: fixture.journal.namespace().to_string(),
    operation_id: operation_id.to_string(),
    artifact_id: "command-v1".to_string(),
    artifact_kind: "command".to_string(),
    operation_kind: AdminOperationKind::CacheWarm.as_str().to_string(),
    schema_version: 1,
    principal: accepted.principal.clone(),
    permission_action: accepted.permission_action.clone(),
    resource_digest: accepted.resource_digest.clone(),
    request_fingerprint: accepted.request_fingerprint.clone(),
  };
  let checkpoint = serde_json::json!({
    "version": 1,
    "next_index": 1,
    "results": [{"uri":"/already","result":"stored"}]
  });
  let running = insert_running_recovery_operation(
    &fixture,
    operation_id,
    Some(command_binding),
    Some(checkpoint),
  )
  .await;
  expire_operation(&fixture.journal, &running.operation_id).await;

  let runtime = activate_recovery(&fixture).await;
  let terminal = wait_for_terminal(&fixture.journal, operation_id).await;
  runtime.shutdown().await;

  assert_eq!(terminal.state, AdminOperationState::Succeeded);
  assert_eq!(
    terminal.terminal_result,
    Some(serde_json::json!({"items":[
      {"uri":"/already","result":"stored"},
      {"uri":"/remaining","policy":null,"status":502,"result":"upstream_error"}
    ]}))
  );
  assert!(terminal.terminal_audit_record_id.is_some());
  cleanup_recovery_fixture(&fixture).await;
}

#[tokio::test]
async fn activate_recovery_terminalizes_ownerless_cancellation_without_query_dispatch() {
  let Some(fixture) = recovery_fixture("query-cancel").await else {
    return;
  };
  let operation_id = "op_00000000-0000-4000-8000-000000000102";
  let running = insert_running_recovery_operation(&fixture, operation_id, None, None).await;
  let CancelOutcome::Requested(cancelled) = fixture
    .journal
    .request_cancel(&running.operation_id, Some(running.revision))
    .await
    .expect("request recovery cancellation")
    .expect("recovery operation remains present")
  else {
    panic!("cancellation must acquire the recovery revision");
  };
  expire_operation(&fixture.journal, &cancelled.operation_id).await;

  let runtime = activate_recovery(&fixture).await;
  let terminal = wait_for_terminal(&fixture.journal, operation_id).await;
  runtime.shutdown().await;

  assert_eq!(terminal.state, AdminOperationState::Cancelled);
  assert!(terminal.terminal_result.is_none());
  assert_eq!(terminal.error_code.as_deref(), Some("operation_cancelled"));
  assert!(terminal.terminal_audit_record_id.is_some());
  cleanup_recovery_fixture(&fixture).await;
}

#[tokio::test]
async fn activate_recovery_fences_bad_query_artifacts_and_expired_lifetime() {
  let Some(fixture) = recovery_fixture("query-reject").await else {
    return;
  };
  let binding_id = "op_00000000-0000-4000-8000-000000000103";
  let lifetime_id = "op_00000000-0000-4000-8000-000000000104";
  let revoked_id = "op_00000000-0000-4000-8000-000000000105";
  let accepted = recovery_operation(binding_id);
  let binding = OperationArtifactBinding {
    namespace: fixture.journal.namespace().to_string(),
    operation_id: binding_id.to_string(),
    artifact_id: "command-v1".to_string(),
    artifact_kind: "command".to_string(),
    operation_kind: AdminOperationKind::CacheWarm.as_str().to_string(),
    schema_version: 1,
    principal: accepted.principal.clone(),
    permission_action: accepted.permission_action.clone(),
    resource_digest: accepted.resource_digest.clone(),
    request_fingerprint: accepted.request_fingerprint.clone(),
  };
  let binding_running =
    insert_running_recovery_operation(&fixture, binding_id, Some(binding), None).await;
  let tampered = sqlx::query(
    "UPDATE oxibelt_admin_operation_artifacts
        SET permission_action = 'cache:Read'
      WHERE namespace = $1 AND operation_id = $2 AND artifact_id = 'command-v1'",
  )
  .bind(fixture.journal.namespace())
  .bind(binding_id)
  .execute(fixture.journal.pool())
  .await
  .expect("tamper stored recovery command binding");
  assert_eq!(
    tampered.rows_affected(),
    1,
    "recovery command must be present"
  );
  let lifetime_running = insert_running_recovery_operation(&fixture, lifetime_id, None, None).await;
  let revoked = recovery_operation(revoked_id);
  let revoked_binding = OperationArtifactBinding {
    namespace: fixture.journal.namespace().to_string(),
    operation_id: revoked_id.to_string(),
    artifact_id: "command-v1".to_string(),
    artifact_kind: "command".to_string(),
    operation_kind: AdminOperationKind::CacheWarm.as_str().to_string(),
    schema_version: 1,
    principal: revoked.principal.clone(),
    permission_action: revoked.permission_action.clone(),
    resource_digest: revoked.resource_digest.clone(),
    request_fingerprint: revoked.request_fingerprint.clone(),
  };
  let revoked_running =
    insert_running_recovery_operation(&fixture, revoked_id, Some(revoked_binding), None).await;
  expire_operation(&fixture.journal, &binding_running.operation_id).await;
  expire_operation(&fixture.journal, &revoked_running.operation_id).await;
  sqlx::query(
    "UPDATE oxibelt_admin_operations
        SET created_at = now() - interval '2 minutes',
            expires_at = now() - interval '1 second'
      WHERE namespace = $1 AND operation_id = $2",
  )
  .bind(fixture.journal.namespace())
  .bind(&lifetime_running.operation_id)
  .execute(fixture.journal.pool())
  .await
  .expect("expire recovery lifetime");
  let mut revoked_config = fixture.state.snapshot().config.clone();
  revoked_config.ipm.bindings.clear();
  fixture.state.replace(
    AppSnapshot::new(revoked_config)
      .await
      .expect("revoked recovery snapshot initializes"),
  );

  let runtime = activate_recovery(&fixture).await;
  let bad_binding = wait_for_terminal(&fixture.journal, binding_id).await;
  let expired = wait_for_terminal(&fixture.journal, lifetime_id).await;
  let revoked = wait_for_terminal(&fixture.journal, revoked_id).await;
  runtime.shutdown().await;

  for operation in [bad_binding, expired] {
    assert_eq!(operation.state, AdminOperationState::Indeterminate);
    assert!(operation.terminal_result.is_none());
    assert_eq!(
      operation.error_code.as_deref(),
      Some("executor_recovery_unavailable")
    );
    assert!(operation.terminal_audit_record_id.is_some());
  }
  assert_eq!(revoked.state, AdminOperationState::Failed);
  assert!(revoked.terminal_result.is_none());
  assert_eq!(revoked.error_code.as_deref(), Some("operation_failed"));
  assert!(revoked.terminal_audit_record_id.is_some());
  cleanup_recovery_fixture(&fixture).await;
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
async fn encrypted_checkpoint_and_progress_cursor_commit_atomically() {
  let Some(journal) = test_journal("cache-warm-checkpoint").await else {
    return;
  };
  let cipher = OperationArtifactCipher::new(&[9; 32], 1024).expect("checkpoint cipher");
  let mut operation = new_operation("op_00000000-0000-4000-8000-000000000008", None);
  operation.kind = AdminOperationKind::CacheWarm;
  operation.recovery_class = AdminOperationRecoveryClass::Resumable;
  operation.permission_action = "cache:Warm".to_string();
  operation.redacted_resource = Some("cache/warm".to_string());
  operation.resource_digest = sha256_digest(b"cache/warm");
  operation.request_fingerprint = sha256_digest(b"cache/warm-command-v1");
  let InsertOutcome::Inserted(accepted) = journal
    .insert_accepted(&operation, 8, 32)
    .await
    .expect("insert cache warm")
  else {
    panic!("cache warm must be inserted");
  };
  let queued = journal
    .queue(&accepted.operation_id, accepted.revision)
    .await
    .expect("queue cache warm")
    .expect("queued cache warm");
  let (_, guard) = journal
    .claim_id(&queued.operation_id, &worker("checkpoint-worker"), 15)
    .await
    .expect("claim cache warm")
    .expect("claimed cache warm");
  let running = journal
    .start(&guard)
    .await
    .expect("start cache warm")
    .expect("running cache warm");
  let running_guard = running.lease_guard().expect("running guard");
  let artifact_id = format!("checkpoint-v1-{}", running.revision.saturating_add(1));
  let payload =
    br#"{"version":1,"next_index":1,"results":[{"uri":"/cached","result":"stored"}]}"#.to_vec();
  let checkpoint = cipher
    .seal(
      OperationArtifactBinding {
        namespace: journal.namespace().to_string(),
        operation_id: running.operation_id.clone(),
        artifact_id: artifact_id.clone(),
        artifact_kind: "checkpoint".to_string(),
        operation_kind: running.kind.as_str().to_string(),
        schema_version: running.schema_version,
        principal: running.principal.clone(),
        permission_action: running.permission_action.clone(),
        resource_digest: running.resource_digest.clone(),
        request_fingerprint: running.request_fingerprint.clone(),
      },
      OperationArtifactPlaintext::new(payload.clone()),
    )
    .expect("seal checkpoint");
  let mut tx = journal
    .pool()
    .begin()
    .await
    .expect("checkpoint transaction");
  assert!(
    journal
      .put_artifact_tx(&mut tx, &checkpoint)
      .await
      .expect("insert checkpoint")
  );
  let updated = journal
    .update_progress_tx(
      &mut tx,
      &running_guard,
      &serde_json::json!({"phase":"warming","processed":1,"total":2}),
      Some(&artifact_id),
    )
    .await
    .expect("advance checkpoint cursor")
    .expect("checkpoint cursor must advance");
  tx.commit().await.expect("commit checkpoint");
  assert_eq!(
    updated.checkpoint_artifact_id.as_deref(),
    Some(artifact_id.as_str())
  );
  let opened = cipher
    .open(
      journal
        .load_artifact(&running.operation_id, &artifact_id)
        .await
        .expect("load checkpoint")
        .expect("checkpoint must be retained"),
    )
    .expect("authenticate checkpoint");
  assert_eq!(opened.as_bytes(), payload);

  // A cursor must never reference an artifact from a transaction that did
  // not commit. This models a crash between sealing a later item checkpoint
  // and PostgreSQL commit.
  let rollback_artifact_id = format!("checkpoint-v1-{}", updated.revision.saturating_add(1));
  let rollback = cipher
    .seal(
      OperationArtifactBinding {
        namespace: journal.namespace().to_string(),
        operation_id: updated.operation_id.clone(),
        artifact_id: rollback_artifact_id.clone(),
        artifact_kind: "checkpoint".to_string(),
        operation_kind: updated.kind.as_str().to_string(),
        schema_version: updated.schema_version,
        principal: updated.principal.clone(),
        permission_action: updated.permission_action.clone(),
        resource_digest: updated.resource_digest.clone(),
        request_fingerprint: updated.request_fingerprint.clone(),
      },
      OperationArtifactPlaintext::new(
        br#"{"version":1,"next_index":2,"results":[{},{}]}"#.to_vec(),
      ),
    )
    .expect("seal rollback checkpoint");
  let updated_guard = updated.lease_guard().expect("updated running guard");
  {
    let mut rollback_tx = journal.pool().begin().await.expect("rollback transaction");
    assert!(
      journal
        .put_artifact_tx(&mut rollback_tx, &rollback)
        .await
        .expect("insert rollback checkpoint")
    );
    assert!(
      journal
        .update_progress_tx(
          &mut rollback_tx,
          &updated_guard,
          &serde_json::json!({"phase":"warming","processed":2,"total":2}),
          Some(&rollback_artifact_id),
        )
        .await
        .expect("advance rollback cursor")
        .is_some()
    );
  }
  let retained = journal
    .load(&updated.operation_id)
    .await
    .expect("load after rollback")
    .expect("operation retained after rollback");
  assert_eq!(
    retained.checkpoint_artifact_id.as_deref(),
    Some(artifact_id.as_str())
  );
  assert!(
    journal
      .load_artifact(&updated.operation_id, &rollback_artifact_id)
      .await
      .expect("load rollback artifact")
      .is_none()
  );

  // A crash after a committed checkpoint and cancellation request must retain
  // that cursor while recovery fences the former worker. The runtime then
  // terminalizes this ownerless cancellation without dispatching another item.
  let CancelOutcome::Requested(cancellation) = journal
    .request_cancel(&updated.operation_id, Some(updated.revision))
    .await
    .expect("request cancellation")
    .expect("operation exists")
  else {
    panic!("cancellation must win after checkpoint");
  };
  assert_eq!(
    cancellation.state,
    AdminOperationState::CancellationRequested
  );
  sqlx::query(
    "UPDATE oxibelt_admin_operations SET lease_expires_at = now() - interval '1 second'
       WHERE namespace = $1 AND operation_id = $2",
  )
  .bind(journal.namespace())
  .bind(&updated.operation_id)
  .execute(journal.pool())
  .await
  .expect("expire crashed worker lease");
  let recovered = journal
    .recover_expired(1, 8)
    .await
    .expect("recover expired cancellation");
  assert_eq!(recovered.recovered.len(), 1);
  let recovered = &recovered.recovered[0];
  assert_eq!(recovered.state, AdminOperationState::CancellationRequested);
  assert!(recovered.owner_worker_id.is_none());
  assert_eq!(
    recovered.checkpoint_artifact_id.as_deref(),
    Some(artifact_id.as_str())
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
