use super::*;

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
