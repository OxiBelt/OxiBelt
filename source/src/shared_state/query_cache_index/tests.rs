use super::*;

fn target_key() -> String {
  format!("ns:cache:q1-target-v1:{}", "a".repeat(64))
}

fn member(epoch: u64) -> QueryCacheIndexMember {
  let storage_variant = format!("q1-epoch:{epoch}:variant");
  QueryCacheIndexMember {
    version: QUERY_CACHE_INDEX_VERSION,
    epoch,
    entry_key: format!("ns:cache:entry:{storage_variant}"),
    lookup_index_key: format!("ns:cache:index:{}:{}", "b".repeat(64), "c".repeat(64)),
    chunk_key_prefix: format!(
      "ns:cache:chunk:{}:",
      hex_encode(&crate::crypto::sha256(storage_variant.as_bytes()))
    ),
    chunk_count: 2,
    expires_at_ms: now_unix_ms().saturating_add(60_000),
    storage_variant,
  }
}

#[test]
fn redis_members_sort_by_epoch_and_round_trip() {
  let member = member(42);
  let encoded = encode_redis_member(&member).unwrap();
  assert!(encoded.starts_with(b"000000000000002a:"));
  let mut expected = member;
  expected.expires_at_ms = 0;
  assert_eq!(decode_redis_member(&encoded).unwrap(), expected);
  assert!(validate_redis_member(&target_key(), &encoded, &expected).is_ok());
}

#[test]
fn redis_member_validation_rejects_tampered_keys_and_cross_namespace_expiry_refs() {
  let mut tampered = member(7);
  tampered.entry_key = "other:cache:entry:q1-epoch:7:variant".to_string();
  let encoded = encode_redis_member(&tampered).unwrap();
  assert!(validate_redis_member(&target_key(), &encoded, &tampered).is_err());

  let expiry_ref = RedisQueryCacheExpiryRef {
    target_key: format!("other:cache:q1-target-v1:{}", "a".repeat(64)),
    member: encoded,
  };
  assert!(validate_redis_expiry_ref("ns:cache:q1-expiry-v1", &expiry_ref).is_err());
}

#[test]
fn postgres_namespace_uses_the_logical_shared_state_namespace() {
  assert_eq!(
    query_cache_namespace("ns:cache:q1-expiry-v1").unwrap(),
    "ns"
  );
  assert!(validate_target_logical_namespace("ns", &target_key()).is_ok());
  assert!(validate_target_logical_namespace("other", &target_key()).is_err());
  assert!(query_cache_namespace("ns:cache:q1-expiry-v2").is_err());
}

#[test]
fn memory_cleanup_is_bounded_and_preserves_a_newer_lookup_pointer() {
  let backend = MemoryBackend::default();
  let target = target_key();
  let old = member(1);
  let current = member(2);
  backend
    .query_cache_publish(&target, &old, b"entry")
    .unwrap();
  backend.values.lock().unwrap().insert(
    old.lookup_index_key.clone(),
    MemoryValue {
      value: current.storage_variant.as_bytes().to_vec(),
      expires_at_ms: None,
    },
  );

  let first = backend.query_cache_cleanup_before(&target, 2, 1).unwrap();
  assert_eq!(first.removed, 1);
  assert!(!first.remaining);
  let values = backend.values.lock().unwrap();
  assert!(!values.contains_key(&old.entry_key));
  assert_eq!(
    values.get(&old.lookup_index_key).unwrap().value,
    current.storage_variant.as_bytes()
  );
}

#[test]
fn memory_cleanup_drops_tampered_members_without_deleting_named_keys() {
  let backend = MemoryBackend::default();
  let target = target_key();
  let mut tampered = member(1);
  tampered.entry_key = "other:protected".to_string();
  backend.values.lock().unwrap().insert(
    tampered.entry_key.clone(),
    MemoryValue {
      value: b"keep".to_vec(),
      expires_at_ms: None,
    },
  );
  backend
    .query_cache_indexes
    .lock()
    .unwrap()
    .entry(target.clone())
    .or_default()
    .insert(tampered.storage_variant.clone(), tampered.clone());

  let batch = backend.query_cache_cleanup_before(&target, 2, 1).unwrap();
  assert_eq!(batch.removed, 0);
  assert!(!batch.remaining);
  assert!(
    backend
      .values
      .lock()
      .unwrap()
      .contains_key(&tampered.entry_key)
  );
}

#[tokio::test]
async fn write_threshold_runs_expiry_cleanup_off_the_publication_path() {
  let shared = SharedState::test_memory("ns");
  let Backend::Memory(backend) = shared.cache.as_deref().unwrap() else {
    panic!("expected memory backend");
  };
  let target = target_key();
  let mut expired = member(1);
  expired.expires_at_ms = now_unix_ms().saturating_sub(1);
  backend
    .query_cache_publish(&target, &expired, b"expired")
    .unwrap();

  for _ in 1..QUERY_CACHE_EXPIRY_TRIGGER_WRITES {
    shared.schedule_query_cache_expiry_cleanup(false);
  }
  tokio::task::yield_now().await;
  assert!(
    backend
      .query_cache_indexes
      .lock()
      .unwrap()
      .contains_key(&target)
  );

  shared.schedule_query_cache_expiry_cleanup(false);
  tokio::time::timeout(Duration::from_secs(1), async {
    while shared
      .query_cache_expiry_scheduler
      .running
      .load(Ordering::Acquire)
    {
      tokio::task::yield_now().await;
    }
  })
  .await
  .unwrap();
  assert!(
    !backend
      .query_cache_indexes
      .lock()
      .unwrap()
      .contains_key(&target)
  );
}
