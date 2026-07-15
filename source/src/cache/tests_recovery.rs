use super::*;
use crate::cache::recovery::DISK_REBUILD_BATCH_SIZE;

#[test]
fn poisoned_cache_state_recovers_in_bounded_disk_batches() {
  let temp_dir = TestTempDir::new();
  for index in 0..300 {
    std::fs::write(
      temp_dir.path.join(format!("ignored-{index}.txt")),
      b"ignored",
    )
    .unwrap();
  }
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(temp_dir.path.clone()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let poison_target = cache.clone();
  let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
    let _guard = poison_target.inner.lock().unwrap();
    panic!("injected cache lock poison");
  }));
  assert!(poisoned.is_err());
  assert!(cache.inner.is_poisoned());

  drop(cache.inner_guard());
  assert!(!cache.inner.is_poisoned());
  assert_eq!(
    cache
      .disk_recovery_guard()
      .as_ref()
      .map(|recovery| recovery.scanned_files),
    Some(DISK_REBUILD_BATCH_SIZE)
  );

  while cache.disk_rebuild_in_progress() {
    drop(cache.inner_guard());
  }
  let mut metrics = String::new();
  cache.runtime_health.append_prometheus(&mut metrics);
  assert!(
    metrics.contains("oxibelt_runtime_lock_recoveries_total{subsystem=\"response_cache\"} 1")
  );
  assert!(
    metrics.contains(
      "oxibelt_runtime_subsystem_state{subsystem=\"response_cache\",state=\"healthy\"} 1"
    )
  );
}
