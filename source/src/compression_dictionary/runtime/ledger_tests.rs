use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::compression_dictionary::{
  fields::{DictionaryHash, DictionaryType, UseAsDictionary},
  storage::DictionaryStorage,
};

fn hash(byte: u8) -> DictionaryHash {
  DictionaryHash::from_slice(&[byte; 32]).unwrap()
}

fn entry(
  profile: &str,
  scope: &str,
  generation: u64,
  hash: DictionaryHash,
  bytes: usize,
) -> LedgerEntry {
  LedgerEntry {
    profile: profile.to_owned(),
    profile_generation: 0,
    scope: scope.to_owned(),
    scope_generation: generation,
    hash,
    url: "https://example.test/dictionary".to_owned(),
    declaration: UseAsDictionary {
      match_pattern: "/assets/*".to_owned(),
      match_destinations: vec!["script".to_owned()],
      id: String::new(),
      dictionary_type: DictionaryType::Raw,
    },
    expires_at_ms: now_ms() + 60_000,
    fetched_at: now_ms(),
    bytes: bytes as u64,
    chunks: Vec::new(),
  }
}

fn now_ms() -> u64 {
  u64::try_from(
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_millis(),
  )
  .unwrap()
}

#[tokio::test]
async fn memory_manifest_cas_publishes_only_ready_chunks() {
  let ledger = Ledger::new(DictionaryStorage::memory(), "memory", 1_024);
  let bytes = b"ready dictionary";
  let entry = entry("profile", "scope", 0, hash(1), bytes.len());
  ledger
    .publish("profile", 1_024, 4, entry, bytes)
    .await
    .unwrap();
  let entries = ledger.entries().await.unwrap();
  assert_eq!(entries.len(), 1);
  assert_eq!(ledger.read_entry_bytes(&entries[0]).await.unwrap(), bytes);
}

#[tokio::test]
async fn disk_manifest_recovers_after_runtime_recreation() {
  let root = tempfile::tempdir().unwrap();
  let first = Ledger::new(DictionaryStorage::disk(root.path()).unwrap(), "disk", 1_024);
  let bytes = b"durable dictionary";
  first
    .publish(
      "profile",
      1_024,
      4,
      entry("profile", "scope", 0, hash(2), bytes.len()),
      bytes,
    )
    .await
    .unwrap();
  let recovered = Ledger::new(DictionaryStorage::disk(root.path()).unwrap(), "disk", 1_024);
  let entries = recovered.entries().await.unwrap();
  assert_eq!(entries.len(), 1);
  assert_eq!(
    recovered.read_entry_bytes(&entries[0]).await.unwrap(),
    bytes
  );
}

#[tokio::test]
async fn purge_fences_even_an_empty_scope_against_stale_publication() {
  let ledger = Ledger::new(DictionaryStorage::memory(), "fence", 1_024);
  assert_eq!(
    ledger
      .purge("profile", Some("scope"), None, None)
      .await
      .unwrap()
      .entries,
    0
  );
  assert_eq!(ledger.generations("profile", "scope").await.unwrap().0, 1);
  let stale = entry("profile", "scope", 0, hash(3), 4);
  assert!(
    ledger
      .publish("profile", 1_024, 4, stale, b"test")
      .await
      .is_err()
  );
  assert!(ledger.entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn profile_purge_isolated_and_fences_unknown_scopes() {
  let ledger = Ledger::new(DictionaryStorage::memory(), "profiles", 1_024);
  ledger
    .publish(
      "other",
      1_024,
      4,
      entry("other", "other-scope", 0, hash(7), 5),
      b"other",
    )
    .await
    .unwrap();
  assert_eq!(
    ledger
      .purge("profile", None, None, None)
      .await
      .unwrap()
      .entries,
    0
  );
  assert_eq!(
    ledger.generations("profile", "new-scope").await.unwrap().1,
    1
  );
  assert!(
    ledger
      .publish(
        "profile",
        1_024,
        4,
        entry("profile", "new-scope", 0, hash(8), 5),
        b"stale"
      )
      .await
      .is_err()
  );
  let entries = ledger.entries().await.unwrap();
  assert_eq!(entries.len(), 1);
  assert_eq!(entries[0].profile, "other");
}

#[tokio::test]
async fn quotas_are_checked_before_chunks_are_published() {
  let ledger = Ledger::new(DictionaryStorage::memory(), "quota", 8);
  let too_large = entry("profile", "scope", 0, hash(4), 9);
  assert!(
    ledger
      .publish("profile", 8, 1, too_large, b"123456789")
      .await
      .is_err()
  );
  assert!(ledger.entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn recovery_reclaims_expired_pending_chunks_without_storage_enumeration() {
  let storage = DictionaryStorage::memory();
  let ledger = Ledger::new(storage.clone(), "recovery", 1_024);
  let mut pending_entry = entry("profile", "scope", 0, hash(6), 4);
  pending_entry.chunks = vec!["cdl-chunk-expired-0".to_owned()];
  storage
    .compare_exchange(&pending_entry.chunks[0], None, b"gone")
    .await
    .unwrap();
  let manifest = Manifest {
    format: MANIFEST_FORMAT,
    pending: vec![PendingPublication {
      id: "expired".to_owned(),
      entry: pending_entry.clone(),
      lease_until_ms: 0,
    }],
    ..Manifest::default()
  };
  storage
    .compare_exchange(
      &ledger.manifest_key,
      None,
      &encode_manifest(&manifest).unwrap(),
    )
    .await
    .unwrap();
  assert!(ledger.entries().await.unwrap().is_empty());
  assert!(
    storage
      .read(&pending_entry.chunks[0])
      .await
      .unwrap()
      .is_none()
  );
}

#[tokio::test]
async fn replacement_collects_only_manifest_tracked_old_chunks() {
  let storage = DictionaryStorage::memory();
  let ledger = Ledger::new(storage.clone(), "replace", 1_024);
  ledger
    .publish(
      "profile",
      1_024,
      4,
      entry("profile", "scope", 0, hash(9), 4),
      b"old!",
    )
    .await
    .unwrap();
  let old_chunks = ledger.entries().await.unwrap().remove(0).chunks;
  ledger
    .publish(
      "profile",
      1_024,
      4,
      entry("profile", "scope", 0, hash(9), 4),
      b"new!",
    )
    .await
    .unwrap();
  for key in old_chunks {
    assert!(storage.read(&key).await.unwrap().is_none());
  }
}

#[tokio::test]
async fn origin_purge_does_not_match_a_prefix_host() {
  let ledger = Ledger::new(DictionaryStorage::memory(), "origin", 1_024);
  let mut other = entry("profile", "scope-other", 0, hash(5), 4);
  other.url = "https://example.test.evil/dictionary".to_owned();
  ledger
    .publish("profile", 1_024, 4, other, b"evil")
    .await
    .unwrap();
  assert_eq!(
    ledger
      .purge("profile", None, Some("https://example.test"), None)
      .await
      .unwrap()
      .entries,
    0
  );
  assert_eq!(ledger.entries().await.unwrap().len(), 1);
}

#[tokio::test]
async fn replacement_requires_capacity_for_both_physical_versions() {
  let ledger = Ledger::new(DictionaryStorage::memory(), "replacement-quota", 4);
  ledger
    .publish(
      "profile",
      4,
      1,
      entry("profile", "scope", 0, hash(1), 4),
      b"old!",
    )
    .await
    .unwrap();
  assert!(
    ledger
      .publish(
        "profile",
        4,
        1,
        entry("profile", "scope", 0, hash(1), 4),
        b"new!"
      )
      .await
      .is_err()
  );
  let entries = ledger.entries().await.unwrap();
  assert_eq!(ledger.read_entry_bytes(&entries[0]).await.unwrap(), b"old!");
}

#[tokio::test]
async fn failed_deletion_keeps_payload_charged_until_recovery() {
  let root = tempfile::tempdir().unwrap();
  let storage = DictionaryStorage::disk(root.path()).unwrap();
  let ledger = Ledger::new(storage.clone(), "failed-gc", 4);
  let mut garbage = entry("profile", "old-scope", 0, hash(1), 4);
  garbage.chunks = vec!["cdl-chunk-blocked-0".to_owned()];
  // A directory at the chunk pathname deterministically makes unlink fail.
  std::fs::create_dir(root.path().join(&garbage.chunks[0])).unwrap();
  let manifest = Manifest {
    format: MANIFEST_FORMAT,
    garbage: vec![garbage.clone()],
    ..Manifest::default()
  };
  storage
    .compare_exchange(
      &ledger.manifest_key,
      None,
      &encode_manifest(&manifest).unwrap(),
    )
    .await
    .unwrap();
  assert!(
    ledger
      .publish(
        "other",
        4,
        4,
        entry("other", "new-scope", 0, hash(2), 4),
        b"next"
      )
      .await
      .is_err()
  );
  assert_eq!(ledger.read_manifest().await.unwrap().1.garbage.len(), 1);
  std::fs::remove_dir(root.path().join(&garbage.chunks[0])).unwrap();
  ledger
    .publish(
      "other",
      4,
      4,
      entry("other", "new-scope", 0, hash(2), 4),
      b"next",
    )
    .await
    .unwrap();
  assert!(ledger.read_manifest().await.unwrap().1.garbage.is_empty());
}

#[test]
fn garbage_is_charged_to_both_profile_and_store() {
  let manifest = Manifest {
    garbage: vec![entry("profile", "scope", 0, hash(1), 4)],
    ..Manifest::default()
  };
  let next = entry("profile", "next-scope", 0, hash(2), 4);
  assert!(enforce_quotas(&manifest, &next, "profile", 4, 8, 100).is_err());
  assert!(enforce_quotas(&manifest, &next, "profile", 100, 8, 4).is_err());
  assert!(enforce_quotas(&manifest, &next, "profile", 8, 8, 8).is_ok());
}

async fn stale_writer_after_reclaim(storage: DictionaryStorage, expired: bool) {
  let ledger = Ledger::new(storage.clone(), "late-writer", 4);
  let mut candidate = entry("profile", "scope", 0, hash(1), 4);
  candidate.chunks = planned_chunks("pending", 4);
  ledger
    .reserve("pending", candidate.clone(), "profile", 4, 4)
    .await
    .unwrap();
  if expired {
    let (raw, mut manifest) = ledger.read_manifest().await.unwrap();
    manifest.pending[0].lease_until_ms = 0;
    storage
      .compare_exchange(
        &ledger.manifest_key,
        raw.as_deref(),
        &encode_manifest(&manifest).unwrap(),
      )
      .await
      .unwrap();
  }
  let snapshot = ledger.read_manifest().await.unwrap().0.unwrap();
  if expired {
    ledger.recover().await.unwrap();
  } else {
    ledger.purge("profile", None, None, None).await.unwrap();
  }
  assert!(ledger.read_manifest().await.unwrap().1.garbage.is_empty());
  // Simulate an in-flight write that reaches the backend after GC completed.
  assert!(
    !storage
      .write_if_manifest_matches(
        &ledger.manifest_key,
        &snapshot,
        &candidate.chunks[0],
        b"late",
        Duration::from_secs(60)
      )
      .await
      .unwrap()
  );
  assert!(storage.read(&candidate.chunks[0]).await.unwrap().is_none());
  assert!(ledger.finalize("pending", candidate).await.is_err());
}

#[tokio::test]
async fn memory_late_writes_cannot_resurrect_purged_or_expired_chunks() {
  stale_writer_after_reclaim(DictionaryStorage::memory(), false).await;
  stale_writer_after_reclaim(DictionaryStorage::memory(), true).await;
}

#[tokio::test]
async fn disk_late_writes_cannot_resurrect_purged_or_expired_chunks() {
  for expired in [false, true] {
    let root = tempfile::tempdir().unwrap();
    stale_writer_after_reclaim(DictionaryStorage::disk(root.path()).unwrap(), expired).await;
  }
}

#[tokio::test]
async fn concurrent_reclaim_and_chunk_write_never_leave_orphans() {
  let root = tempfile::tempdir().unwrap();
  for storage in [
    DictionaryStorage::memory(),
    DictionaryStorage::disk(root.path()).unwrap(),
  ] {
    for round in 0..16 {
      let ledger = Ledger::new(storage.clone(), &format!("race-{round}"), 4);
      let mut candidate = entry("profile", "scope", 0, hash(1), 4);
      candidate.chunks = planned_chunks(&format!("race-{round}"), 4);
      ledger
        .reserve("race", candidate.clone(), "profile", 4, 4)
        .await
        .unwrap();
      let snapshot = ledger.read_manifest().await.unwrap().0.unwrap();
      let (write, purge) = tokio::join!(
        storage.write_if_manifest_matches(
          &ledger.manifest_key,
          &snapshot,
          &candidate.chunks[0],
          b"race",
          Duration::from_secs(60)
        ),
        ledger.purge("profile", None, None, None),
      );
      write.unwrap();
      purge.unwrap();
      assert!(storage.read(&candidate.chunks[0]).await.unwrap().is_none());
      assert!(ledger.read_manifest().await.unwrap().1.garbage.is_empty());
    }
  }
}

#[tokio::test]
async fn disk_recovery_collects_a_crashed_partial_chunk_by_reserved_name() {
  let root = tempfile::tempdir().unwrap();
  let storage = DictionaryStorage::disk(root.path()).unwrap();
  let ledger = Ledger::new(storage.clone(), "partial-crash", 16);
  let mut candidate = entry("profile", "scope", 0, hash(1), 16);
  candidate.chunks = planned_chunks("partial", 16);
  let manifest = Manifest {
    format: MANIFEST_FORMAT,
    pending: vec![PendingPublication {
      id: "partial".to_owned(),
      entry: candidate.clone(),
      lease_until_ms: 0,
    }],
    ..Manifest::default()
  };
  storage
    .compare_exchange(
      &ledger.manifest_key,
      None,
      &encode_manifest(&manifest).unwrap(),
    )
    .await
    .unwrap();
  // Crash left only the first bytes under the pre-reserved final pathname.
  std::fs::write(root.path().join(&candidate.chunks[0]), b"part").unwrap();
  let restarted = Ledger::new(
    DictionaryStorage::disk(root.path()).unwrap(),
    "partial-crash",
    16,
  );
  assert!(restarted.entries().await.unwrap().is_empty());
  assert!(!root.path().join(&candidate.chunks[0]).exists());
  assert!(
    restarted
      .read_manifest()
      .await
      .unwrap()
      .1
      .garbage
      .is_empty()
  );
}
