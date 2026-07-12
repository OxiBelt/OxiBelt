use super::super::person_proof_admin::{
  MAX_LOCAL_ADMIN_IDEMPOTENCY_RECORDS, PersonProofRevocationReplay,
};
use super::*;

#[test]
fn cookie_clearance_metadata_omits_token() {
  let policy = clearance_policy(PersonProofClearanceIssueTarget::Cookie);
  let issued = policy
    .issue("clearance.v2.test-token".to_string(), 1_700_000_000_000, 60)
    .unwrap();

  assert_eq!(issued.token, "clearance.v2.test-token");
  assert_eq!(
    issued
      .metadata
      .get("issue_to")
      .and_then(serde_json::Value::as_str),
    Some("cookie")
  );
  assert!(issued.metadata.get("token").is_none());
  assert_eq!(
    issued
      .metadata
      .get("expires_unix_ms")
      .and_then(serde_json::Value::as_i64),
    Some(1_700_000_000_000)
  );
  assert_eq!(
    issued
      .metadata
      .get("max_age_seconds")
      .and_then(serde_json::Value::as_u64),
    Some(60)
  );

  assert!(matches!(
    issued.response_header.as_ref(),
    Some(HeaderMutation::Append { name, value })
      if name == SET_COOKIE
        && value
          .to_str()
          .map(|cookie| {
            cookie.contains("__oxibelt_person_proof=clearance.v2.test-token")
              && cookie.contains("Secure")
              && cookie.contains("HttpOnly")
          })
          .unwrap_or(false)
  ));
}

#[test]
fn json_visible_clearance_targets_include_token() {
  for issue_to in [
    PersonProofClearanceIssueTarget::LocalStorage,
    PersonProofClearanceIssueTarget::ResponseJson,
  ] {
    let policy = clearance_policy(issue_to);
    let issued = policy
      .issue(
        "clearance.v2.visible-token".to_string(),
        1_700_000_000_000,
        60,
      )
      .unwrap();

    assert_eq!(
      issued
        .metadata
        .get("token")
        .and_then(serde_json::Value::as_str),
      Some("clearance.v2.visible-token")
    );
  }
}

#[tokio::test]
async fn shared_state_shares_secret_and_single_use_replay_state() {
  let shared = SharedState::test_memory("person-proof-test");
  let mut first =
    PersonProofEngine::from_policies_with_previous(Vec::new(), 16, None, Some(shared.clone()))
      .unwrap();
  let mut second =
    PersonProofEngine::from_policies_with_previous(Vec::new(), 16, None, Some(shared)).unwrap();
  first.load_shared_secret().await.unwrap();
  second.load_shared_secret().await.unwrap();

  assert_eq!(first.secret, second.secret);

  let now = now_unix_ms().unwrap();
  first
    .remember_reuse_token_async("challenge:test-token", now + 60_000, now)
    .await
    .unwrap();
  assert!(
    second
      .consume_reuse_token_async("challenge:test-token", now)
      .await
      .unwrap()
  );
  assert!(
    !first
      .consume_reuse_token_async("challenge:test-token", now)
      .await
      .unwrap()
  );
}

#[tokio::test]
async fn local_admin_revocation_idempotency_replays_without_storing_the_raw_key() {
  let engine = PersonProofEngine::from_policies_with_previous(Vec::new(), 16, None, None).unwrap();
  let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  let now = now_unix_ms().unwrap();
  engine
    .remember_reuse_token_async(&format!("clearance:{hash}"), now + 60_000, now)
    .await
    .unwrap();

  let first = engine
    .admin_revoke_clearance_with_idempotency_async(hash, Some(60), Some("retry-key"))
    .await
    .unwrap();
  let replay = engine
    .admin_revoke_clearance_with_idempotency_async(hash, Some(60), Some("retry-key"))
    .await
    .unwrap();
  assert!(first.removed_active);
  assert_eq!(first.expires_at_unix_ms, replay.expires_at_unix_ms);
  assert!(
    engine
      .revocation_idempotency
      .lock()
      .unwrap()
      .keys()
      .all(|key| key != "retry-key"),
    "only the idempotency-key digest may be retained"
  );

  let error = engine
    .admin_revoke_clearance_with_idempotency_async(
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      Some(60),
      Some("retry-key"),
    )
    .await
    .expect_err("different request data must conflict");
  assert!(
    error
      .downcast_ref::<crate::shared_state::PersonProofIdempotencyConflict>()
      .is_some()
  );
}

#[tokio::test]
async fn local_admin_revocation_never_evicts_a_live_idempotency_record() {
  let engine = PersonProofEngine::from_policies_with_previous(Vec::new(), 16, None, None).unwrap();
  let now = now_unix_ms().unwrap();
  let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  engine
    .remember_reuse_token_async(&format!("clearance:{hash}"), now + 60_000, now)
    .await
    .unwrap();
  {
    let mut replay = engine.revocation_idempotency.lock().unwrap();
    for index in 0..MAX_LOCAL_ADMIN_IDEMPOTENCY_RECORDS {
      replay.insert(
        format!("digest-{index}"),
        PersonProofRevocationReplay {
          fingerprint: "fingerprint".to_string(),
          removed_active: false,
          expires_at_ms: now + 60_000,
        },
      );
    }
  }

  let error = engine
    .admin_revoke_clearance_with_idempotency_async(hash, Some(60), Some("new-retry-key"))
    .await
    .expect_err("a full local idempotency store must reject a new keyed mutation");
  assert!(
    error
      .to_string()
      .contains("person proof idempotency record capacity exhausted")
  );
  assert_eq!(
    engine.revocation_idempotency.lock().unwrap().len(),
    MAX_LOCAL_ADMIN_IDEMPOTENCY_RECORDS
  );
  assert!(
    engine
      .active_reuse_tokens
      .lock()
      .unwrap()
      .contains_key(&format!("clearance:{hash}"))
  );
  assert!(!engine.revoked_clearances.lock().unwrap().contains_key(hash));
}

fn clearance_policy(issue_to: PersonProofClearanceIssueTarget) -> PersonProofClearancePolicy {
  PersonProofClearancePolicy::from_config(&PersonProofClearanceConfig {
    issue_to,
    ..PersonProofClearanceConfig::default()
  })
}
