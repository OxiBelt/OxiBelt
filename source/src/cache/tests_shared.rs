use super::*;

#[test]
fn shared_cache_tag_purge_removes_l2_entry() {
  let shared = crate::shared_state::SharedState::test_memory("cache-tag-test");
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();
  let mut response_headers = HeaderMap::new();
  response_headers.insert("cache-tag", HeaderValue::from_static("release-1"));
  first.insert(
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
      Bytes::from_static(b"tagged"),
    ),
  );
  assert!(matches!(
    second.lookup(CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &request_headers,
    }),
    Some(CacheLookup::Fresh(_))
  ));
  assert_eq!(second.purge_tag("default", "release-1", None, None), 2);
  assert!(
    second
      .lookup(CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &request_headers,
      })
      .is_none()
  );
}

#[test]
fn shared_cache_entries_are_visible_across_instances_and_purgeable() {
  let shared = crate::shared_state::SharedState::test_memory("cache-test");
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let uri = "/asset/app.css?body=shared".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let ctx = CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  };

  first.insert(
    CacheInsertContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &headers,
    },
    CacheEntry::memory(
      StatusCode::OK,
      HeaderMap::new(),
      Bytes::from_static(b"shared-cache"),
    ),
  );
  assert_eq!(first.stats().memory_entries, 1);
  let index_keys = shared.test_cache_raw_keys("cache:index:");
  assert!(
    !index_keys.is_empty(),
    "shared cache writes should maintain lookup index pointers"
  );

  match second.lookup(ctx.clone()) {
    Some(CacheLookup::Fresh(entry)) => {
      assert_eq!(entry.body, Bytes::from_static(b"shared-cache"))
    }
    other => panic!("expected shared cache hit, got {other:?}"),
  }

  assert_eq!(
    second.purge_exact(
      "default",
      "https",
      "example.test",
      "/asset/app.css?body=shared"
    ),
    2
  );
  assert!(second.lookup(ctx).is_none());
}

#[test]
fn shared_cache_legacy_entry_scan_backfills_lookup_index() {
  let shared = crate::shared_state::SharedState::test_memory("cache-index-backfill");
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let uri = "/asset/legacy.css?body=shared".parse::<Uri>().unwrap();
  let mut headers = HeaderMap::new();
  headers.insert("accept-language", HeaderValue::from_static("en"));
  let mut response_headers = HeaderMap::new();
  response_headers.insert(
    http::header::VARY,
    HeaderValue::from_static("Accept-Language"),
  );

  assert_eq!(
    first.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers,
        Bytes::from_static(b"legacy-cache")
      ),
    ),
    CacheInsertOutcome::Stored
  );

  for key in shared.test_cache_raw_keys("cache:index:") {
    shared.test_delete_raw_key(&key);
  }
  assert!(shared.test_cache_raw_keys("cache:index:").is_empty());

  match second.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body, Bytes::from_static(b"legacy-cache")),
    other => panic!("expected legacy shared cache hit, got {other:?}"),
  }
  assert!(
    !shared.test_cache_raw_keys("cache:index:").is_empty(),
    "legacy full-scan lookup should backfill shared cache index"
  );
}

#[test]
fn shared_cache_vary_lookup_uses_indexed_variant() {
  let shared = crate::shared_state::SharedState::test_memory("cache-vary-index");
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let mut request_headers = HeaderMap::new();
  request_headers.insert("accept-language", HeaderValue::from_static("en"));
  let mut response_headers = HeaderMap::new();
  response_headers.insert(
    http::header::VARY,
    HeaderValue::from_static("Accept-Language"),
  );

  assert_eq!(
    first.insert(
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
        Bytes::from_static(b"vary-en")
      ),
    ),
    CacheInsertOutcome::Stored
  );
  assert!(
    !shared.test_cache_raw_keys("cache:index:").is_empty(),
    "vary shared cache entries should write lookup index pointers"
  );

  match second.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body, Bytes::from_static(b"vary-en")),
    other => panic!("expected indexed vary shared cache hit, got {other:?}"),
  }
}

#[test]
fn shared_cache_large_body_uses_retrievable_chunks() {
  let shared = crate::shared_state::SharedState::test_memory("cache-large-chunks");
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared)).unwrap();
  let uri = "/asset/large.bin".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let body = Bytes::from(vec![b'x'; 1_048_577]);

  assert_eq!(
    first.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &headers,
      },
      CacheEntry::memory(StatusCode::OK, HeaderMap::new(), body.clone()),
    ),
    CacheInsertOutcome::Stored
  );

  match second.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => {
      assert_eq!(entry.body_len(), body.len());
      assert_eq!(read_cache_entry_body(&entry), body);
      assert!(entry.body_file.is_some());
    }
    other => panic!("expected chunked shared cache hit, got {other:?}"),
  }
  assert_eq!(
    second.purge_exact("default", "https", "example.test", "/asset/large.bin"),
    1
  );
}

#[tokio::test]
async fn shared_cache_streaming_disk_fill_writes_chunked_l2_entry() {
  let temp_dir = TestTempDir::new();
  let shared = crate::shared_state::SharedState::test_memory("cache-streaming-l2");
  let config = streaming_disk_cache_config(&temp_dir);
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let uri = "/asset/streaming-shared.bin".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let body = Bytes::from(vec![b's'; 1_048_577]);

  stream_disk_fill(&first, &uri, &headers, body.clone()).await;

  let chunk_keys = shared.test_cache_raw_keys("cache:chunk:");
  assert!(
    chunk_keys.len() >= 2,
    "streaming disk shared fill should write chunked L2 body"
  );
  match second.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => {
      assert_eq!(entry.body_len(), body.len());
      assert_eq!(read_cache_entry_body(&entry), body);
      assert!(entry.body_file.is_some());
    }
    other => panic!("expected shared streaming disk L2 hit, got {other:?}"),
  }
}

#[tokio::test]
async fn shared_cache_missing_streaming_chunk_is_safe_miss_without_losing_l1() {
  let temp_dir = TestTempDir::new();
  let shared = crate::shared_state::SharedState::test_memory("cache-streaming-missing-chunk");
  let config = streaming_disk_cache_config(&temp_dir);
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let uri = "/asset/streaming-shared-missing.bin"
    .parse::<Uri>()
    .unwrap();
  let headers = HeaderMap::new();
  let body = Bytes::from(vec![b'm'; 1_048_577]);

  stream_disk_fill(&first, &uri, &headers, body.clone()).await;
  let chunk_keys = shared.test_cache_raw_keys("cache:chunk:");
  assert!(!chunk_keys.is_empty(), "expected shared body chunks");
  shared.test_delete_raw_key(&chunk_keys[0]);

  match first.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => {
      assert_eq!(entry.body_len(), body.len());
      assert!(entry.body_file.is_some());
    }
    other => panic!("expected local L1 hit after shared chunk loss, got {other:?}"),
  }
  assert!(
    second
      .lookup(CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &headers,
      })
      .is_none(),
    "missing shared chunks should produce a safe shared miss"
  );
}

#[test]
fn shared_cache_requires_exact_uri_when_cache_key_collides() {
  let shared = crate::shared_state::SharedState::test_memory("cache-uri-isolation");
  let config = CacheConfig {
    enabled: true,
    cache_key: "{scheme}:{host}:{path}".to_string(),
    ..CacheConfig::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared)).unwrap();
  let secret_uri = "/profile?token=secret".parse::<Uri>().unwrap();
  let other_uri = "/profile?token=other".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();

  first.insert(
    CacheInsertContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &secret_uri,
      request_headers: &headers,
    },
    CacheEntry::memory(
      StatusCode::OK,
      HeaderMap::new(),
      Bytes::from_static(b"secret-token-response"),
    ),
  );

  let other_ctx = CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &other_uri,
    request_headers: &headers,
  };
  assert!(second.lookup(other_ctx).is_none());

  let secret_ctx = CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &secret_uri,
    request_headers: &headers,
  };
  match second.lookup(secret_ctx) {
    Some(CacheLookup::Fresh(entry)) => {
      assert_eq!(entry.body, Bytes::from_static(b"secret-token-response"))
    }
    other => panic!("expected exact URI shared cache hit, got {other:?}"),
  }
}

fn read_cache_entry_body(entry: &CacheEntry) -> Bytes {
  if let Some(file) = &entry.body_file {
    let body = std::fs::read(&file.path).unwrap();
    let start: usize = file.offset.try_into().unwrap();
    let end = start.checked_add(file.len).unwrap();
    return Bytes::from(body[start..end].to_vec());
  }
  entry.body.clone()
}

fn streaming_disk_cache_config(temp_dir: &TestTempDir) -> CacheConfig {
  CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(temp_dir.path.clone()),
    max_size_bytes: 2_500_000,
    disk_max_size_bytes: Some(2_500_000),
    default_ttl_seconds: 60,
    stream_large_objects: true,
    ..CacheConfig::default()
  }
}

async fn stream_disk_fill(
  cache: &std::sync::Arc<ResponseCache>,
  uri: &Uri,
  request_headers: &HeaderMap,
  body: Bytes,
) {
  let mut response_headers = HeaderMap::new();
  response_headers.insert(
    http::header::CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  response_headers.insert(
    http::header::CONTENT_TYPE,
    HeaderValue::from_static("application/octet-stream"),
  );
  response_headers.insert(
    http::header::CONTENT_LENGTH,
    HeaderValue::from_str(&body.len().to_string()).unwrap(),
  );
  let prepared = match cache.prepare_insert(
    CacheInsertContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri,
      request_headers,
    },
    StatusCode::OK,
    &response_headers,
    Some(body.len()),
  ) {
    CachePreparedInsertDecision::Cacheable(prepared) => prepared,
    other => panic!("expected cacheable streaming insert, got {other:?}"),
  };
  let mut insert = match cache.begin_streaming_insert(*prepared, body.len(), None) {
    CacheStreamingInsertDecision::Started(insert) => insert,
    other => panic!("expected streaming insert to start, got {other:?}"),
  };
  for chunk in body.chunks(262_144) {
    assert!(insert.write_data(Bytes::copy_from_slice(chunk)));
  }
  insert.finish();
  wait_for_fresh(cache, uri, request_headers).await;
}

async fn wait_for_fresh(
  cache: &std::sync::Arc<ResponseCache>,
  uri: &Uri,
  request_headers: &HeaderMap,
) {
  for _ in 0..100 {
    if matches!(
      cache.lookup(CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri,
        request_headers,
      }),
      Some(CacheLookup::Fresh(_))
    ) {
      return;
    }
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
  }
  panic!("expected fresh local cache entry");
}
