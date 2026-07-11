use super::*;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, HeaderName, HeaderValue};

#[test]
fn disk_not_modified_update_preserves_file_backed_body() {
  let temp_dir = TestTempDir::new();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(temp_dir.path.clone()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };

  assert_not_modified_update_preserves_file_backed_body(config);
}

#[test]
fn memory_then_disk_not_modified_update_preserves_file_backed_body_after_disk_fallback() {
  let temp_dir = TestTempDir::new();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::MemoryThenDisk,
    memory_max_size_bytes: Some(1),
    disk_dir: Some(temp_dir.path.clone()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };

  assert_not_modified_update_preserves_file_backed_body(config);
}

#[tokio::test]
async fn shared_not_modified_update_republishes_l2_entry() {
  let shared = crate::shared_state::SharedState::test_memory("cache-revalidation-l2");
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared)).unwrap();
  let uri = "/asset/revalidated-l2.css".parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();
  let context = CacheInsertContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  };
  let mut response_headers = HeaderMap::new();
  response_headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  response_headers.insert(
    HeaderName::from_static("etag"),
    HeaderValue::from_static("\"v1\""),
  );
  assert_eq!(
    first
      .insert_async(
        context.clone(),
        CacheEntry::memory(
          StatusCode::OK,
          response_headers,
          Bytes::from_static(b"shared-revalidated"),
        ),
      )
      .await,
    CacheInsertOutcome::Stored
  );

  let cached_entry = match first.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => entry,
    other => panic!("expected local cache entry before revalidation, got {other:?}"),
  };
  let mut not_modified_headers = HeaderMap::new();
  not_modified_headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=120"),
  );
  not_modified_headers.insert(
    HeaderName::from_static("etag"),
    HeaderValue::from_static("\"v2\""),
  );
  first
    .update_from_not_modified_async(context, &cached_entry, &not_modified_headers)
    .await;

  match second
    .lookup_async(CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &request_headers,
    })
    .await
  {
    Some(CacheLookup::Fresh(entry)) => {
      assert_eq!(
        entry.headers.get(CACHE_CONTROL).unwrap(),
        "public, max-age=120"
      );
      assert_eq!(entry.headers.get("etag").unwrap(), "\"v2\"");
      assert_eq!(entry.body, Bytes::from_static(b"shared-revalidated"));
    }
    other => panic!("expected revalidated L2 entry, got {other:?}"),
  }
}

fn assert_not_modified_update_preserves_file_backed_body(config: CacheConfig) {
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/revalidated.css".parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  response_headers.insert(CONTENT_LENGTH, HeaderValue::from_static("12"));
  response_headers.insert(
    HeaderName::from_static("etag"),
    HeaderValue::from_static("\"v1\""),
  );

  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &request_headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers,
        Bytes::from_static(b"disk-body-12"),
      ),
    ),
    CacheInsertOutcome::Stored
  );

  let cached_entry = match cache.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => entry,
    other => panic!("expected fresh file-backed cache hit, got {other:?}"),
  };
  assert!(cached_entry.body_file.is_some());
  assert!(cached_entry.body.is_empty());
  assert_eq!(cached_entry.body_len(), 12);

  let mut not_modified_headers = HeaderMap::new();
  not_modified_headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=120"),
  );
  cache.update_from_not_modified(
    CacheInsertContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &request_headers,
    },
    &cached_entry,
    &not_modified_headers,
  );

  match cache.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => {
      assert_eq!(
        entry.headers.get(CACHE_CONTROL).unwrap(),
        "public, max-age=120"
      );
      assert_eq!(entry.body_len(), 12);
      let file = entry
        .body_file
        .expect("updated entry should stay file-backed");
      assert_eq!(std::fs::read(file.path).unwrap(), b"disk-body-12");
    }
    other => panic!("expected revalidated file-backed cache hit, got {other:?}"),
  }
  assert_eq!(cache.stats().disk_entries, 1);
}
