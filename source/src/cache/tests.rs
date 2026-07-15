use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "tests_core.rs"]
mod core;
#[path = "tests_external.rs"]
mod external;
#[path = "tests_fill.rs"]
mod fill;
#[path = "tests_index.rs"]
mod index;
#[path = "tests_recovery.rs"]
mod recovery;
#[path = "tests_revalidation.rs"]
mod revalidation;
#[path = "tests_security.rs"]
mod security;
#[path = "tests_semantics.rs"]
mod semantics;
#[path = "tests_shared.rs"]
mod shared;

fn cache_config_with_disabled_named_background_refresh() -> CacheConfig {
  CacheConfig {
    enabled: true,
    policies: vec![crate::config::CachePolicyConfig {
      name: "no-background-refresh".to_string(),
      store: None,
      cache_key: None,
      partition_key: None,
      default_ttl_seconds: None,
      negative_statuses: None,
      negative_ttl_seconds: None,
      memory_max_size_bytes: None,
      disk_max_size_bytes: None,
      tag_headers: None,
      max_tags_per_entry: None,
      max_tag_bytes: None,
      max_vary_fields: None,
      max_vary_variants_per_key: None,
      background_refresh: Some(false),
      background_refresh_max_concurrent: None,
      lock_wait_timeout_ms: None,
      admission: None,
      stale_if_error: None,
      external_handler: None,
      rules: Vec::new(),
    }],
    ..CacheConfig::default()
  }
}

fn test_cache_policy_with_negative_status() -> crate::config::CachePolicyConfig {
  crate::config::CachePolicyConfig {
    name: "negative".to_string(),
    store: None,
    cache_key: None,
    partition_key: None,
    default_ttl_seconds: None,
    negative_statuses: Some(vec![404]),
    negative_ttl_seconds: Some(30),
    memory_max_size_bytes: None,
    disk_max_size_bytes: None,
    tag_headers: None,
    max_tags_per_entry: None,
    max_tag_bytes: None,
    max_vary_fields: None,
    max_vary_variants_per_key: None,
    background_refresh: None,
    background_refresh_max_concurrent: None,
    lock_wait_timeout_ms: None,
    admission: None,
    stale_if_error: None,
    external_handler: None,
    rules: Vec::new(),
  }
}

async fn insert_stale_revalidate_entry(
  cache: &ResponseCache,
  uri: &Uri,
  request_headers: &HeaderMap,
  body: Bytes,
  include_validator: bool,
) {
  let mut headers = HeaderMap::new();
  headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=1, stale-while-revalidate=60, stale-if-error=60"),
  );
  if include_validator {
    headers.insert(ETAG, HeaderValue::from_static("\"v1\""));
  }

  assert_eq!(
    cache
      .insert_async(
        CacheInsertContext {
          policy_name: Some("no-background-refresh"),
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri,
          request_headers,
        },
        CacheEntry::memory(StatusCode::OK, headers, body),
      )
      .await,
    CacheInsertOutcome::Stored
  );
}

async fn assert_stale_background_refresh_disabled(
  cache: &ResponseCache,
  uri: &Uri,
  request_headers: &HeaderMap,
) {
  match cache
    .lookup_async(CacheLookupContext {
      policy_name: Some("no-background-refresh"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri,
      request_headers,
    })
    .await
  {
    Some(CacheLookup::Stale(stale)) => assert!(
      !stale.background_refresh,
      "stale hit ignored disabled background_refresh policy"
    ),
    other => panic!("expected stale cache hit, got {other:?}"),
  }
}

struct TestTempDir {
  path: PathBuf,
}

static NEXT_TEST_DIR_ID: AtomicU64 = AtomicU64::new(0);

impl TestTempDir {
  fn new() -> Self {
    let id = NEXT_TEST_DIR_ID.fetch_add(1, Ordering::Relaxed);
    let path = Path::new("/tmp").join(format!(
      "oxibelt-cache-test-{}-{}-{}",
      std::process::id(),
      SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos(),
      id
    ));
    std::fs::create_dir_all(&path).unwrap();
    Self { path }
  }
}

impl Drop for TestTempDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.path);
  }
}
