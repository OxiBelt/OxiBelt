use std::time::Duration;

use http::StatusCode;
use tokio::task::JoinSet;

use super::super::{Backend, HealthRecord, now_unix_ms};
use super::{apply_health_report, expiry_after, ttl_millis};
use crate::shared_state::{
  ConnectionScope, PersonProofIdempotencyConflict, PersonProofRevocationIdempotency,
  SharedConnectionAcquire, SharedState,
};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn health_transition_respects_thresholds_and_saturates() {
  let mut record = HealthRecord::default();
  record = apply_health_report(record, false, true, 2, 2);
  assert!(record.healthy);
  record = apply_health_report(record, false, true, 2, 2);
  assert!(!record.healthy);
  record = apply_health_report(record, true, true, 2, 2);
  assert!(!record.healthy);
  record = apply_health_report(record, true, true, 2, 2);
  assert!(record.healthy);
  let saturated = apply_health_report(
    HealthRecord {
      healthy: true,
      consecutive_successes: u32::MAX,
      consecutive_failures: 0,
    },
    true,
    true,
    1,
    1,
  );
  assert_eq!(saturated.consecutive_successes, u32::MAX);
}

#[test]
fn expiry_calculation_never_wraps() {
  assert_eq!(
    expiry_after(i64::MAX - 1, Duration::from_millis(2)),
    i64::MAX
  );
  assert_eq!(ttl_millis(Duration::ZERO), 1);
}

#[test]
fn person_proof_idempotency_fingerprint_is_unambiguously_delimited() {
  let idempotency = PersonProofRevocationIdempotency::new("retry-key", HASH_A, Some(60));
  assert_eq!(
    idempotency.request_fingerprint,
    super::super::hex_encode(&crate::crypto::sha256(
      b"person-proof-revoke:v1\0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0ttl:60",
    )),
  );
}

#[tokio::test]
async fn connection_leases_admit_once_and_release_idempotently() {
  let state = SharedState::test_memory("atomic-connection-lease");
  let scope = [ConnectionScope {
    key: "global",
    limit: 1,
    status: StatusCode::SERVICE_UNAVAILABLE,
  }];
  let first = state
    .acquire_connections(&scope)
    .await
    .expect("first lease should acquire");
  let lease = match first {
    SharedConnectionAcquire::Acquired(lease) => lease,
    SharedConnectionAcquire::Denied(_) => panic!("first lease unexpectedly denied"),
  };
  assert!(matches!(
    state
      .acquire_connections(&scope)
      .await
      .expect("denied lease should be a normal result"),
    SharedConnectionAcquire::Denied(StatusCode::SERVICE_UNAVAILABLE)
  ));

  let backend = state
    .connection_limits
    .as_ref()
    .expect("test state has connection backend");
  let counter_key = state.key("conn:global");
  assert_eq!(backend.counter_get(&counter_key).await.unwrap(), 1);

  state.release_connections(lease.clone()).await;
  state.release_connections(lease).await;
  assert_eq!(backend.counter_get(&counter_key).await.unwrap(), 0);
}

#[tokio::test]
async fn concurrent_connection_acquires_never_exceed_the_limit() {
  let state = SharedState::test_memory("atomic-connection-concurrency");
  let mut tasks = JoinSet::new();
  for _ in 0..32 {
    let state = state.clone();
    tasks.spawn(async move {
      let scope = [ConnectionScope {
        key: "global",
        limit: 1,
        status: StatusCode::SERVICE_UNAVAILABLE,
      }];
      state.acquire_connections(&scope).await
    });
  }
  let mut leases = Vec::new();
  while let Some(result) = tasks.join_next().await {
    match result
      .expect("connection acquire task should not panic")
      .unwrap()
    {
      SharedConnectionAcquire::Acquired(lease) => leases.push(lease),
      SharedConnectionAcquire::Denied(StatusCode::SERVICE_UNAVAILABLE) => {}
      SharedConnectionAcquire::Denied(status) => panic!("unexpected denial status {status}"),
    }
  }
  assert_eq!(leases.len(), 1);
  state.release_connections(leases.pop().unwrap()).await;
}

#[tokio::test]
async fn counter_updates_clamp_at_zero_and_attach_the_lease_expiry() {
  let state = SharedState::test_memory("atomic-counter");
  assert_eq!(
    state.pool_active_add("upstream-a", -1).await.unwrap(),
    Some(0)
  );
  assert_eq!(
    state.pool_active_add("upstream-a", 1).await.unwrap(),
    Some(1)
  );

  let backend = state
    .upstream_health
    .as_ref()
    .expect("test state has upstream health backend");
  let Backend::Memory(memory) = backend.as_ref() else {
    panic!("test state should use the memory backend");
  };
  let counters = memory.counters.lock().unwrap();
  let counter = counters
    .get(&state.key("pool:active:upstream-a"))
    .expect("counter should remain present");
  assert_eq!(counter.counter, 1);
  assert!(
    counter
      .expires_at_ms
      .is_some_and(|expiry| expiry > now_unix_ms())
  );
}

#[tokio::test]
async fn get_or_init_and_health_updates_share_one_memory_transition() {
  let state = SharedState::test_memory("atomic-value-health");
  let mut tasks = JoinSet::new();
  for _ in 0..16 {
    let state = state.clone();
    tasks.spawn(async move { state.person_proof_secret().await.unwrap().unwrap() });
  }
  let mut secret = None;
  while let Some(result) = tasks.join_next().await {
    let value = result.expect("secret task should not panic");
    assert!(secret.is_none_or(|expected| expected == value));
    secret = Some(value);
  }
  assert!(
    state
      .pool_report("upstream-a", false, true, 2, 2)
      .await
      .unwrap()
      .unwrap()
  );
  assert!(
    !state
      .pool_report("upstream-a", false, true, 2, 2)
      .await
      .unwrap()
      .unwrap()
  );
}

#[tokio::test]
async fn person_proof_revocation_replays_and_rejects_conflicts_atomically() {
  let state = SharedState::test_memory("atomic-person-proof");
  let expires = now_unix_ms().saturating_add(60_000);
  assert!(
    state
      .person_proof_remember(&format!("clearance:{HASH_A}"), expires)
      .await
      .unwrap()
  );
  let idempotency = PersonProofRevocationIdempotency::new("retry-key", HASH_A, None);
  let first = state
    .person_proof_revoke_clearance_hash(HASH_A, expires, Some(&idempotency))
    .await
    .unwrap();
  let replay = state
    .person_proof_revoke_clearance_hash(HASH_A, expires.saturating_add(1_000), Some(&idempotency))
    .await
    .unwrap();
  assert_eq!(first, replay);
  assert!(first.removed_active);
  assert!(
    !state
      .person_proof_consume_clearance("legacy-clearance", HASH_A)
      .await
      .unwrap()
  );

  let conflict = PersonProofRevocationIdempotency::new("retry-key", HASH_B, None);
  let error = state
    .person_proof_revoke_clearance_hash(HASH_B, expires, Some(&conflict))
    .await
    .expect_err("a reused key with a different hash must conflict");
  assert!(
    error
      .downcast_ref::<PersonProofIdempotencyConflict>()
      .is_some()
  );
}

#[tokio::test]
async fn challenge_hash_transition_honors_an_existing_legacy_marker() {
  let state = SharedState::test_memory("atomic-person-proof-legacy");
  let expires = now_unix_ms().saturating_add(60_000);
  assert!(
    state
      .person_proof_remember("challenge:legacy-token", expires)
      .await
      .unwrap()
  );
  assert!(
    !state
      .person_proof_mark_challenge_used("legacy-token", HASH_A, expires)
      .await
      .unwrap()
  );
}
