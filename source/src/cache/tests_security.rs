use super::*;

#[test]
fn disk_cache_recovery_rejects_legacy_security_header_metadata() {
  let temp_dir = TestTempDir::new();
  let cache_dir = temp_dir.path.join("cache");
  std::fs::create_dir_all(&cache_dir).unwrap();

  let variant_key = "partition=\nhttps:example.test:/asset/legacy.css";
  let body_path = cache_file_path(&cache_dir, variant_key, CacheFileKind::Body).unwrap();
  let meta_path = cache_file_path(&cache_dir, variant_key, CacheFileKind::Meta).unwrap();
  std::fs::write(&body_path, b"body").unwrap();
  let stored = StoredEntry {
    policy: "default".to_string(),
    partition: String::new(),
    base_key: "https:example.test:/asset/legacy.css".to_string(),
    variant_key: variant_key.to_string(),
    scheme: "https".to_string(),
    host: "example.test".to_string(),
    uri: "/asset/legacy.css".to_string(),
    status: StatusCode::OK,
    headers: HeaderMap::new(),
    security_headers_neutral: true,
    body: StoredBody::Disk(body_path.clone()),
    expires_at: SystemTime::now() + Duration::from_secs(60),
    stale_if_error_until: None,
    stale_while_revalidate_until: None,
    must_revalidate: false,
    stored_at: SystemTime::now(),
    vary: Vec::new(),
    tags: Vec::new(),
    size: 4,
  };
  let legacy_metadata = encode_metadata(&stored)
    .unwrap()
    .lines()
    .filter(|line| !line.starts_with("security_headers_neutral="))
    .collect::<Vec<_>>()
    .join("\n");
  std::fs::write(&meta_path, legacy_metadata).unwrap();

  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(cache_dir),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let stats = cache.stats();

  assert_eq!(stats.disk_recovered_entries_total, 0);
  assert!(stats.disk_recovery_removed_files_total >= 2);
  assert!(!body_path.exists());
  assert!(!meta_path.exists());
}
