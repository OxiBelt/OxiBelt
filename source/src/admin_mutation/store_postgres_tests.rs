//! Opt-in PostgreSQL integration checks for durable mutation atomicity.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use sqlx::postgres::PgPoolOptions;

use super::ledger::{ClaimOutcome, MutationClaim, MutationState, TerminalMutation};
use super::store::{
  MutationStore, create_break_glass_activation_tx, init_postgres,
  load_active_break_glass_for_principal,
};

#[tokio::test]
async fn postgres_claim_is_atomic_and_terminal_replay_is_retained() {
  let Ok(url) = std::env::var("OXIBELT_TEST_MUTATION_POSTGRES_URL") else {
    return;
  };
  let pool = PgPoolOptions::new()
    .max_connections(4)
    .connect(&url)
    .await
    .expect("mutation test PostgreSQL connection");
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

  store
    .finish(
      &claim.request_id,
      &TerminalMutation {
        state: MutationState::Committed,
        http_status: 200,
        safe_response: Some(json!({ "ok": true, "token_recoverable": false })),
        error_code: None,
        terminal_audit_record_id: 102,
      },
    )
    .await
    .expect("terminal mutation commit");
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

  committed_parent_is_required_before_break_glass_is_active(&store).await;
  indeterminate_result_keeps_the_resource_reserved(&store).await;

  cleanup(&pool, &namespace).await;
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
}
