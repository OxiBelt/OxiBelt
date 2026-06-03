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
    Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body.len(), body.len()),
    other => panic!("expected chunked shared cache hit, got {other:?}"),
  }
  assert_eq!(
    second.purge_exact("default", "https", "example.test", "/asset/large.bin"),
    2
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
