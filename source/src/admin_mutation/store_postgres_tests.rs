//! Opt-in PostgreSQL integration checks for durable mutation atomicity.

use std::time::{SystemTime, UNIX_EPOCH};

use http::{Method, StatusCode};
use serde_json::json;

use super::ledger::{ClaimOutcome, MutationClaim, MutationState, TerminalMutation};
use super::store::{
  MutationStore, create_break_glass_activation_tx, finish_tx, init_postgres,
  load_active_break_glass_for_principal,
};
use crate::admin_audit::{AdminAuditHandle, AdminAuditRuntime};

#[tokio::test]
async fn postgres_claim_is_atomic_and_terminal_replay_is_retained() {
  Box::pin(postgres_atomicity_test_body()).await;
}

async fn postgres_atomicity_test_body() {
  let Some(pool) = super::postgres_test_support::connect("mutation store tests").await else {
    return;
  };
  init_postgres(&pool)
    .await
    .expect("mutation test schema initialization");
  let namespace = format!(
    "mutation-test-{}-{}",
    std::process::id(),
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("test clock")
      .as_nanos()
  );
  let store = MutationStore::new(pool.clone(), namespace.clone()).expect("mutation test store");
  let audit_runtime = AdminAuditRuntime::test_with_postgres(pool.clone(), namespace.clone())
    .await
    .expect("audit test schema initialization");
  store
    .initialize_revision(
      "config",
      "r-1",
      digest('0'),
      Some("single"),
      Some(digest('1')),
    )
    .await
    .expect("initial logical revision");

  let claim = sample_claim();
  let (first, duplicate) = tokio::join!(store.claim(&claim), store.claim(&claim));
  let first = first.expect("first concurrent claim");
  let duplicate = duplicate.expect("duplicate concurrent claim");
  assert!(
    matches!(first, ClaimOutcome::Claimed(_)) ^ matches!(duplicate, ClaimOutcome::Claimed(_)),
    "exactly one concurrent caller must own the side effect"
  );
  assert!(
    matches!(first, ClaimOutcome::InProgress(_))
      || matches!(duplicate, ClaimOutcome::InProgress(_)),
    "the losing concurrent caller must observe the in-progress claim"
  );

  Box::pin(async {
    let staged_audit = audit_runtime
      .stage_critical_mutation(mutation_audit_event(&claim, StatusCode::OK, "applied"))
      .await
      .expect("stage terminal audit");
    let mut tx = store.pool().begin().await.expect("terminal transaction");
    let terminal_audit_record_id = staged_audit
      .insert(&mut tx)
      .await
      .expect("insert terminal audit");
    let terminal_record = finish_tx(
      &mut tx,
      store.namespace(),
      &claim.request_id,
      &TerminalMutation {
        state: MutationState::Committed,
        http_status: 200,
        safe_response: Some(json!({ "ok": true, "token_recoverable": false })),
        error_code: None,
        terminal_audit_record_id,
      },
    )
    .await
    .expect("stage terminal mutation commit");
    tx.commit().await.expect("terminal transaction commit");
    staged_audit.publish();
    assert_eq!(
      terminal_record.terminal_audit_record_id,
      Some(terminal_audit_record_id)
    );
    let stored_audit_id: i64 =
      sqlx::query_scalar("SELECT id FROM oxibelt_admin_audit WHERE namespace = $1 AND id = $2")
        .bind(&namespace)
        .bind(terminal_audit_record_id)
        .fetch_one(&pool)
        .await
        .expect("transactional terminal audit row");
    assert_eq!(stored_audit_id, terminal_audit_record_id);
  })
  .await;
  assert!(matches!(
    store.claim(&claim).await.expect("terminal replay"),
    ClaimOutcome::Replay(_)
  ));

  let mut conflicting = claim.clone();
  conflicting.fingerprint = digest('f').to_string();
  assert!(matches!(
    store.claim(&conflicting).await.expect("conflicting replay"),
    ClaimOutcome::RequestConflict
  ));

  Box::pin(rolled_back_terminal_audit_does_not_update_the_receipt(
    &store,
    &audit_runtime,
    &pool,
    &namespace,
  ))
  .await;
  committed_parent_is_required_before_break_glass_is_active(&store).await;
  indeterminate_result_keeps_the_resource_reserved(&store).await;

  cleanup(&pool, &namespace).await;
}

async fn rolled_back_terminal_audit_does_not_update_the_receipt(
  store: &MutationStore,
  audit_runtime: &AdminAuditRuntime,
  pool: &sqlx::PgPool,
  namespace: &str,
) {
  store
    .initialize_revision(
      "rollback",
      "rollback-r1",
      digest('0'),
      Some("single"),
      Some(digest('1')),
    )
    .await
    .expect("rollback logical revision");
  let mut claim = sample_claim();
  claim.request_id = "018f47a2-7b2c-7b25-8f31-d13db7b4c127".to_string();
  claim.resource = "rollback".to_string();
  claim.expected_previous_revision = "rollback-r1".to_string();
  claim.new_revision = "rollback-r2".to_string();
  claim.audit_record_id = 401;
  assert!(matches!(
    store.claim(&claim).await.expect("rollback claim"),
    ClaimOutcome::Claimed(_)
  ));

  let staged_audit = audit_runtime
    .stage_critical_mutation(mutation_audit_event(
      &claim,
      StatusCode::INTERNAL_SERVER_ERROR,
      "indeterminate",
    ))
    .await
    .expect("stage rollback audit");
  let mut tx = store.pool().begin().await.expect("rollback transaction");
  let audit_id = staged_audit
    .insert(&mut tx)
    .await
    .expect("insert rollback audit");
  let error = finish_tx(
    &mut tx,
    store.namespace(),
    "missing-mutation-request",
    &TerminalMutation {
      state: MutationState::Indeterminate,
      http_status: 500,
      safe_response: None,
      error_code: Some("mutation_indeterminate".to_string()),
      terminal_audit_record_id: audit_id,
    },
  )
  .await
  .expect_err("missing mutation must abort the transaction");
  assert!(error.to_string().contains("mutation record not found"));
  tx.rollback().await.expect("rollback terminal transaction");
  drop(staged_audit);

  let audit_rows: i64 =
    sqlx::query_scalar("SELECT count(*) FROM oxibelt_admin_audit WHERE namespace = $1 AND id = $2")
      .bind(namespace)
      .bind(audit_id)
      .fetch_one(pool)
      .await
      .expect("rolled-back audit count");
  assert_eq!(audit_rows, 0);
  assert_eq!(
    store
      .load_mutation(&claim.request_id)
      .await
      .expect("rollback mutation read")
      .expect("rollback mutation record")
      .state,
    MutationState::Claimed
  );
}

async fn committed_parent_is_required_before_break_glass_is_active(store: &MutationStore) {
  store
    .initialize_revision(
      "break-glass",
      "b-1",
      digest('0'),
      Some("single"),
      Some(digest('1')),
    )
    .await
    .expect("initial break-glass logical revision");
  let mut claim = sample_claim();
  claim.request_id = "018f47a2-7b2c-7b25-8f31-d13db7b4c124".to_string();
  claim.resource = "break-glass".to_string();
  claim.expected_previous_revision = "b-1".to_string();
  claim.new_revision = "b-2".to_string();
  claim.audit_record_id = 201;
  assert!(matches!(
    store.claim(&claim).await.expect("break-glass claim"),
    ClaimOutcome::Claimed(_)
  ));

  let mut tx = store.pool().begin().await.expect("activation transaction");
  create_break_glass_activation_tx(
    &mut tx,
    store.namespace(),
    "activation-1",
    "controller",
    &["admin".to_string()],
    &claim.request_id,
    "2099-01-01T00:00:00Z",
  )
  .await
  .expect("activation insert");
  tx.commit().await.expect("activation transaction commit");
  assert!(
    load_active_break_glass_for_principal(store, "controller")
      .await
      .expect("pre-terminal activation read")
      .is_none(),
    "a claimed parent mutation must not authorize the activation"
  );

  store
    .finish(
      &claim.request_id,
      &TerminalMutation {
        state: MutationState::Committed,
        http_status: 201,
        safe_response: Some(json!({ "ok": true, "token_recoverable": false })),
        error_code: None,
        terminal_audit_record_id: 202,
      },
    )
    .await
    .expect("break-glass terminal commit");
  assert!(
    load_active_break_glass_for_principal(store, "controller")
      .await
      .expect("committed activation read")
      .is_some(),
    "only a committed parent mutation may authorize the activation"
  );
}

async fn indeterminate_result_keeps_the_resource_reserved(store: &MutationStore) {
  store
    .initialize_revision("ipm", "i-1", digest('0'), Some("single"), Some(digest('1')))
    .await
    .expect("initial IPM logical revision");
  let mut claim = sample_claim();
  claim.request_id = "018f47a2-7b2c-7b25-8f31-d13db7b4c125".to_string();
  claim.resource = "ipm".to_string();
  claim.expected_previous_revision = "i-1".to_string();
  claim.new_revision = "i-2".to_string();
  claim.audit_record_id = 301;
  assert!(matches!(
    store.claim(&claim).await.expect("IPM claim"),
    ClaimOutcome::Claimed(_)
  ));
  store
    .finish(
      &claim.request_id,
      &TerminalMutation {
        state: MutationState::Indeterminate,
        http_status: 503,
        safe_response: None,
        error_code: Some("mutation_indeterminate".to_string()),
        terminal_audit_record_id: 302,
      },
    )
    .await
    .expect("indeterminate terminal result");

  let mut next = claim.clone();
  next.request_id = "018f47a2-7b2c-7b25-8f31-d13db7b4c126".to_string();
  next.fingerprint = digest('f').to_string();
  next.new_revision = "i-3".to_string();
  next.audit_record_id = 303;
  assert!(matches!(
    store.claim(&next).await.expect("claim after uncertainty"),
    ClaimOutcome::RevisionBusy { .. }
  ));
}

fn sample_claim() -> MutationClaim {
  MutationClaim {
    request_id: "018f47a2-7b2c-7b25-8f31-d13db7b4c123".to_string(),
    fingerprint: digest('a').to_string(),
    principal: "controller".to_string(),
    signer_id: "controller-1".to_string(),
    action: "config.load".to_string(),
    resource: "config".to_string(),
    expected_previous_revision: "r-1".to_string(),
    new_revision: "r-2".to_string(),
    content_digest: digest('b').to_string(),
    cluster_id: Some("single".to_string()),
    membership_revision: Some(digest('1').to_string()),
    issued_at: "2020-01-01T00:00:00Z".to_string(),
    expires_at: "2099-01-01T00:00:00Z".to_string(),
    allowed_clock_skew_seconds: 30,
    retention_seconds: 86_400,
    audit_record_id: 101,
  }
}

fn mutation_audit_event(
  claim: &MutationClaim,
  status: StatusCode,
  outcome: &str,
) -> crate::admin_audit::AdminAuditEvent {
  let audit = AdminAuditHandle::new(
    "127.0.0.1:1234".parse().unwrap(),
    "https",
    &Method::POST,
    "/admin/v1/config/load",
    None,
  );
  audit.record_mutation_context(
    &claim.signer_id,
    &claim.action,
    &claim.resource,
    &claim.expected_previous_revision,
    &claim.new_revision,
    &claim.content_digest,
    claim.cluster_id.as_deref().unwrap(),
    claim.membership_revision.as_deref().unwrap(),
  );
  audit.critical_mutation_event(&claim.request_id, status, outcome, None)
}

fn digest(character: char) -> &'static str {
  match character {
    '0' => "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    '1' => "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    'a' => "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    'b' => "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    'f' => "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    _ => unreachable!("test digest selector"),
  }
}

async fn cleanup(pool: &sqlx::PgPool, namespace: &str) {
  sqlx::query("DELETE FROM oxibelt_admin_mutations WHERE namespace = $1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete mutation test rows");
  sqlx::query("DELETE FROM oxibelt_admin_mutation_revisions WHERE namespace = $1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete mutation revision test rows");
  sqlx::query("DELETE FROM oxibelt_admin_audit WHERE namespace = $1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete audit test rows");
}
