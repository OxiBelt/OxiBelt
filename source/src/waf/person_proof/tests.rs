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

#[test]
fn shared_state_shares_secret_and_single_use_replay_state() {
  let shared = SharedState::test_memory("person-proof-test");
  let first =
    PersonProofEngine::from_policies_with_previous(Vec::new(), 16, None, Some(shared.clone()))
      .unwrap();
  let second =
    PersonProofEngine::from_policies_with_previous(Vec::new(), 16, None, Some(shared)).unwrap();

  assert_eq!(first.secret, second.secret);

  let now = now_unix_ms().unwrap();
  first
    .remember_reuse_token("challenge:test-token", now + 60_000, now)
    .unwrap();
  assert!(
    second
      .consume_reuse_token("challenge:test-token", now)
      .unwrap()
  );
  assert!(
    !first
      .consume_reuse_token("challenge:test-token", now)
      .unwrap()
  );
}

fn clearance_policy(issue_to: PersonProofClearanceIssueTarget) -> PersonProofClearancePolicy {
  PersonProofClearancePolicy::from_config(&PersonProofClearanceConfig {
    issue_to,
    ..PersonProofClearanceConfig::default()
  })
}
