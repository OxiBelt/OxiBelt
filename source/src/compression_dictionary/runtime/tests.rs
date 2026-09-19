use std::{
  collections::HashMap,
  sync::{Arc, Mutex},
};

use super::*;
use crate::compression_dictionary::storage::DictionaryStorage;

fn profile_config(max_dictionary_bytes: u64) -> CompressionDictionaryProfileConfig {
  CompressionDictionaryProfileConfig {
    name: "profile".to_owned(),
    downstream: true,
    upstream: false,
    learn: true,
    request_decode: false,
    prefetch: None,
    advertise: None,
    dictionaries: Vec::new(),
    store: "store".to_owned(),
    max_dictionary_bytes,
    max_dictionaries: 4,
    max_total_dictionary_bytes: 128,
    max_pending_dictionary_bytes: 64,
    max_codec_concurrency: 1,
    max_codec_memory_bytes: crate::compression_dictionary::codec::maximum_working_set_bytes(),
    max_decoded_size_bytes: 128,
    max_expansion_ratio: 1,
    codec_timeout_ms: 1,
  }
}

fn runtime(max_dictionary_bytes: u64) -> DictionaryRuntime {
  let store_config = CompressionDictionaryStoreConfig {
    name: "store".to_owned(),
    kind: CompressionDictionaryStoreKind::Memory,
    quota_bytes: 128,
    disk: None,
    shared: None,
    external: None,
  };
  let store = Arc::new(StoreRuntime {
    ledger: Ledger::new(DictionaryStorage::memory(), "store", 128),
  });
  let profile = Arc::new(ProfileRuntime {
    config: profile_config(max_dictionary_bytes),
    codec_permits: Arc::new(Semaphore::new(1)),
    prefetch_permits: Arc::new(Semaphore::new(1)),
    store: store.clone(),
    usage: Arc::new(Mutex::new(ProfileUsage::default())),
  });
  DictionaryRuntime {
    profiles: Arc::new(HashMap::from([("profile".to_owned(), profile)])),
    configured: Arc::new(HashMap::new()),
    shared_config: Default::default(),
    stores: Arc::new(HashMap::from([("store".to_owned(), store)])),
    store_configs: Arc::new(HashMap::from([("store".to_owned(), store_config)])),
  }
}

fn scope() -> DictionaryScope {
  DictionaryScope {
    direction: DictionaryDirection::Downstream,
    origin: Url::parse("https://example.test/base").unwrap(),
    profile: "profile".to_owned(),
    route_policy_fingerprint: "route-policy-v1".to_owned(),
    upstream_fingerprint: None,
  }
}

fn declaration() -> UseAsDictionary {
  UseAsDictionary {
    match_pattern: "/assets/*".to_owned(),
    match_destinations: vec!["script".to_owned()],
    id: String::new(),
    dictionary_type: DictionaryType::Raw,
  }
}

#[tokio::test]
async fn learn_then_lookup_pins_verified_fresh_bytes_and_purge_fences_them() {
  let runtime = runtime(64);
  let scope = scope();
  let url = Url::parse("https://example.test/dictionary").unwrap();
  let learned = runtime
    .learn(
      "profile",
      &scope,
      url,
      declaration(),
      b"dictionary bytes".to_vec(),
      now_ms().unwrap() + 60_000,
    )
    .await
    .unwrap();
  let request = Url::parse("https://example.test/assets/main.js").unwrap();
  let found = runtime
    .lookup(
      "profile",
      &scope,
      Some(&learned.hash),
      &request,
      Some("script"),
    )
    .await
    .unwrap()
    .unwrap();
  assert_eq!(found.bytes.as_ref(), b"dictionary bytes");
  assert_eq!(
    runtime
      .purge("profile", Some(&scope), None, None)
      .await
      .unwrap(),
    1
  );
  assert!(
    runtime
      .lookup(
        "profile",
        &scope,
        Some(&learned.hash),
        &request,
        Some("script")
      )
      .await
      .unwrap()
      .is_none()
  );
}

#[tokio::test]
async fn learn_respects_per_dictionary_quota_before_publication() {
  let runtime = runtime(3);
  let scope = scope();
  assert!(
    runtime
      .learn(
        "profile",
        &scope,
        Url::parse("https://example.test/dictionary").unwrap(),
        declaration(),
        b"four".to_vec(),
        now_ms().unwrap() + 60_000,
      )
      .await
      .is_err()
  );
  assert_eq!(runtime.inventory("profile").await.unwrap().entries, 0);
}

#[tokio::test]
async fn reservation_commits_a_short_unknown_length_body_without_leaking_capacity() {
  let runtime = runtime(64);
  let scope = scope();
  runtime
    .begin_learning("profile", &scope, 32)
    .await
    .unwrap()
    .commit(
      Url::parse("https://example.test/dictionary").unwrap(),
      declaration(),
      b"short".to_vec(),
      now_ms().unwrap() + 60_000,
    )
    .await
    .unwrap();
  let inventory = runtime.inventory("profile").await.unwrap();
  assert_eq!(inventory.bytes, 5);
  assert_eq!(inventory.pending_bytes, 0);
  assert_eq!(inventory.active_jobs, 0);
}

#[test]
fn unchanged_profile_reuses_active_reservation_accounting() {
  let previous = runtime(64);
  let profile = previous.profile("profile").unwrap();
  reserve(&profile, 32).unwrap();
  let store = previous.stores.get("store").unwrap().clone();
  let reused = reuse_profile(Some(&previous), &profile.config, &store)
    .unwrap()
    .unwrap();
  assert!(Arc::ptr_eq(&profile, &reused));
  assert_eq!(reused.usage.lock().unwrap().pending_bytes, 32);
  release(&profile, 32, None);
}

#[tokio::test]
async fn changed_store_cannot_reset_active_learning_budget() {
  let runtime = runtime(64);
  let _reservation = runtime
    .begin_learning("profile", &scope(), 32)
    .await
    .unwrap();
  let replacement = Arc::new(StoreRuntime {
    ledger: Ledger::new(DictionaryStorage::memory(), "store", 128),
  });
  assert!(reuse_profile(Some(&runtime), &profile_config(64), &replacement).is_err());
}

#[tokio::test]
async fn changed_profile_cannot_reset_active_codec_budget() {
  let runtime = runtime(64);
  let profile = runtime.profile("profile").unwrap();
  let _permit = profile.codec_permits.clone().try_acquire_owned().unwrap();
  let mut changed = profile.config.clone();
  changed.codec_timeout_ms += 1;
  assert!(reuse_profile(Some(&runtime), &changed, &profile.store).is_err());
}
