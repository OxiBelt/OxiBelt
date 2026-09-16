use super::*;
use http::header::{CACHE_CONTROL, CONTENT_TYPE, IF_MATCH};

fn query_identity(uri: &Uri, original: &[u8], effective: &[u8]) -> CacheQueryIdentity {
  let mut original_headers = HeaderMap::new();
  original_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
  let mut effective_headers = HeaderMap::new();
  effective_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
  CacheQueryIdentity::new(
    CacheQueryRepresentation::new(
      "https",
      "example.test",
      uri,
      original.len() as u64,
      crate::crypto::sha256(original),
      &original_headers,
      &HeaderMap::new(),
    )
    .unwrap(),
    CacheQueryRepresentation::new(
      "https",
      "origin.internal",
      uri,
      effective.len() as u64,
      crate::crypto::sha256(effective),
      &effective_headers,
      &HeaderMap::new(),
    )
    .unwrap(),
    effective_headers,
  )
  .unwrap()
}

fn query_identity_with_trailers(uri: &Uri, trailers: &HeaderMap) -> CacheQueryIdentity {
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
  CacheQueryIdentity::new(
    CacheQueryRepresentation::new(
      "https",
      "example.test",
      uri,
      0,
      crate::crypto::sha256(b""),
      &headers,
      trailers,
    )
    .unwrap(),
    CacheQueryRepresentation::new(
      "https",
      "origin.internal",
      uri,
      0,
      crate::crypto::sha256(b""),
      &headers,
      trailers,
    )
    .unwrap(),
    headers,
  )
  .unwrap()
}

fn query_cache() -> Arc<ResponseCache> {
  let config = CacheConfig {
    enabled: true,
    cache_methods: vec!["GET".to_string(), "HEAD".to_string(), "QUERY".to_string()],
    // Prove Q1 still binds the target when an operator intentionally uses a
    // template that omits every target component.
    cache_key: "constant".to_string(),
    ..CacheConfig::default()
  };
  ResponseCache::new(&config, None).unwrap()
}

fn shared_query_cache(shared: Arc<crate::shared_state::SharedState>) -> Arc<ResponseCache> {
  let config = CacheConfig {
    enabled: true,
    cache_methods: vec!["GET".to_string(), "HEAD".to_string(), "QUERY".to_string()],
    cache_key: "constant".to_string(),
    ..CacheConfig::default()
  };
  ResponseCache::new(&config, Some(shared)).unwrap()
}

fn query_headers() -> HeaderMap {
  HeaderMap::new()
}

#[test]
fn query_requires_exact_method_and_complete_identity() {
  let cache = query_cache();
  let uri = "/lookup?tenant=a".parse::<Uri>().unwrap();
  let headers = query_headers();
  let identity = query_identity(&uri, b"one", b"one");
  let lowercase = Method::from_bytes(b"query").unwrap();

  assert!(!cache.is_cacheable_method(&lowercase));
  assert!(
    cache
      .lookup(CacheLookupContext {
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::from_bytes(b"QUERY").unwrap(),
        uri: &uri,
        request_headers: &headers,
        query_identity: None,
        certificate_identity: None,
      })
      .is_none()
  );
  assert!(
    cache
      .lookup(CacheLookupContext {
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &lowercase,
        uri: &uri,
        request_headers: &headers,
        query_identity: Some(&identity),
        certificate_identity: None,
      })
      .is_none()
  );
}

#[test]
fn query_key_separates_original_effective_body_and_target() {
  let cache = query_cache();
  let first_uri = "/lookup?tenant=a".parse::<Uri>().unwrap();
  let second_uri = "/lookup?tenant=b".parse::<Uri>().unwrap();
  let headers = query_headers();
  let first = query_identity(&first_uri, b"original-a", b"effective-a");
  let transformed = query_identity(&first_uri, b"original-a", b"effective-b");
  let target_changed = query_identity(&second_uri, b"original-a", b"effective-a");
  let method = Method::from_bytes(b"QUERY").unwrap();

  let first_key = cache
    .operation_context(
      Some("default"),
      "https",
      "example.test",
      &method,
      &first_uri,
      &headers,
      Some(&first),
      None,
      None,
    )
    .unwrap()
    .base_key;
  let transformed_key = cache
    .operation_context(
      Some("default"),
      "https",
      "example.test",
      &method,
      &first_uri,
      &headers,
      Some(&transformed),
      None,
      None,
    )
    .unwrap()
    .base_key;
  let target_key = cache
    .operation_context(
      Some("default"),
      "https",
      "example.test",
      &method,
      &second_uri,
      &headers,
      Some(&target_changed),
      None,
      None,
    )
    .unwrap()
    .base_key;
  assert_ne!(first_key, transformed_key);
  assert_ne!(first_key, target_key);
  assert!(is_query_v1_base_key(&first_key));
}

#[test]
fn query_key_preserves_duplicate_trailer_value_order() {
  let cache = query_cache();
  let uri = "/lookup?tenant=a".parse::<Uri>().unwrap();
  let headers = query_headers();
  let method = Method::from_bytes(b"QUERY").unwrap();
  let mut first_trailers = HeaderMap::new();
  first_trailers.append("x-query-proof", HeaderValue::from_static("first"));
  first_trailers.append("x-query-proof", HeaderValue::from_static("second"));
  let mut second_trailers = HeaderMap::new();
  second_trailers.append("x-query-proof", HeaderValue::from_static("second"));
  second_trailers.append("x-query-proof", HeaderValue::from_static("first"));

  let first_key = cache
    .operation_context(
      Some("default"),
      "https",
      "example.test",
      &method,
      &uri,
      &headers,
      Some(&query_identity_with_trailers(&uri, &first_trailers)),
      None,
      None,
    )
    .unwrap()
    .base_key;
  let second_key = cache
    .operation_context(
      Some("default"),
      "https",
      "example.test",
      &method,
      &uri,
      &headers,
      Some(&query_identity_with_trailers(&uri, &second_trailers)),
      None,
      None,
    )
    .unwrap()
    .base_key;

  assert_ne!(first_key, second_key);
}

#[test]
fn query_origin_preconditions_bypass_cache_and_fill_lock() {
  let cache = query_cache();
  let uri = "/lookup".parse::<Uri>().unwrap();
  let identity = query_identity(&uri, b"query", b"query");
  let method = Method::from_bytes(b"QUERY").unwrap();
  let mut headers = query_headers();
  headers.insert(IF_MATCH, HeaderValue::from_static("\"current\""));
  let ctx = CacheLookupContext {
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &method,
    uri: &uri,
    request_headers: &headers,
    query_identity: Some(&identity),
    certificate_identity: None,
  };
  assert!(cache.lookup(ctx.clone()).is_none());
  assert!(cache.begin_fill(ctx).is_none());
}

#[test]
fn query_identity_rejects_unbounded_content_metadata() {
  let uri = "/lookup".parse::<Uri>().unwrap();
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
  headers.insert(
    "content-query-options",
    HeaderValue::from_str(&"x".repeat(QUERY_IDENTITY_METADATA_MAX_BYTES)).unwrap(),
  );
  assert!(
    CacheQueryRepresentation::new(
      "https",
      "example.test",
      &uri,
      0,
      crate::crypto::sha256(b""),
      &headers,
      &HeaderMap::new()
    )
    .is_err()
  );
}

#[test]
fn query_entry_is_invalidated_without_touching_get_at_same_target() {
  let cache = query_cache();
  let uri = "/lookup".parse::<Uri>().unwrap();
  let method = Method::from_bytes(b"QUERY").unwrap();
  let headers = query_headers();
  let identity = query_identity(&uri, b"query", b"query");
  let mut response_headers = HeaderMap::new();
  response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
  assert_eq!(
    cache.insert(
      CacheInsertContext {
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &method,
        uri: &uri,
        request_headers: &headers,
        query_identity: Some(&identity),
        certificate_identity: None,
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers.clone(),
        Bytes::from_static(b"query")
      )
    ),
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    cache.insert(
      CacheInsertContext {
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &headers,
        query_identity: None,
        certificate_identity: None,
      },
      CacheEntry::memory(StatusCode::OK, response_headers, Bytes::from_static(b"get"))
    ),
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    cache.invalidate_query_target("default", "https", "example.test", "/lookup", None),
    1
  );
  assert!(matches!(
    cache.lookup(CacheLookupContext {
      no_vary_search: None,
      proxy_protocol_identity: None,
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &headers,
      query_identity: None,
      certificate_identity: None,
    }),
    Some(CacheLookup::Fresh(_))
  ));
}

#[test]
fn absent_query_target_does_not_examine_unrelated_cache_entries() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      cache_methods: vec!["GET".to_string(), "QUERY".to_string()],
      cache_key: "{scheme}:{host}:{uri}".to_string(),
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let headers = HeaderMap::new();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
  for index in 0..4096 {
    let uri = format!("/unrelated/{index}").parse::<Uri>().unwrap();
    assert_eq!(
      cache.insert(
        CacheInsertContext {
          no_vary_search: None,
          proxy_protocol_identity: None,
          policy_name: Some("default"),
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri: &uri,
          request_headers: &headers,
          query_identity: None,
          certificate_identity: None,
        },
        CacheEntry::memory(
          StatusCode::OK,
          response_headers.clone(),
          Bytes::from_static(b"x"),
        ),
      ),
      CacheInsertOutcome::Stored,
    );
  }
  assert_eq!(cache.inner_guard().entries.len(), 4096);
  assert_eq!(
    cache.invalidate_query_target("default", "https", "example.test", "/missing", None),
    0,
  );
  assert_eq!(cache.inner_guard().entries.len(), 4096);
}

#[tokio::test]
async fn automatic_query_invalidation_returns_after_fencing_and_reclaims_in_background() {
  let cache = query_cache();
  let uri = "/background-cleanup".parse::<Uri>().unwrap();
  let method = Method::from_bytes(b"QUERY").unwrap();
  let headers = HeaderMap::new();
  let identity = query_identity(&uri, b"query", b"query");
  let mut response_headers = HeaderMap::new();
  response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
  assert_eq!(
    cache.insert(
      CacheInsertContext {
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &method,
        uri: &uri,
        request_headers: &headers,
        query_identity: Some(&identity),
        certificate_identity: None,
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers,
        Bytes::from_static(b"query"),
      ),
    ),
    CacheInsertOutcome::Stored,
  );

  assert_eq!(
    cache
      .invalidate_query_target_async(
        "default",
        "https",
        "example.test",
        "/background-cleanup",
        None,
      )
      .await
      .unwrap(),
    0,
  );
  let fresh_identity = query_identity(&uri, b"query", b"query");
  assert!(
    cache
      .lookup(CacheLookupContext {
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &method,
        uri: &uri,
        request_headers: &headers,
        query_identity: Some(&fresh_identity),
        certificate_identity: None,
      })
      .is_none(),
    "epoch fencing must make the stale entry unreachable before cleanup completes",
  );
  for _ in 0..100 {
    if cache.inner_guard().entries.is_empty() {
      return;
    }
    tokio::task::yield_now().await;
  }
  panic!("background QUERY cleanup did not reclaim the stale local entry");
}

#[tokio::test]
async fn shared_query_epoch_rejects_a_delayed_replica_publish() {
  let shared = crate::shared_state::SharedState::test_memory("query-target-epoch");
  let first = shared_query_cache(shared.clone());
  let second = shared_query_cache(shared.clone());
  let observer = shared_query_cache(shared);
  let uri = "/lookup".parse::<Uri>().unwrap();
  let headers = query_headers();
  let method = Method::from_bytes(b"QUERY").unwrap();
  let old_identity = query_identity(&uri, b"old", b"old");
  let old_ctx = CacheLookupContext {
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &method,
    uri: &uri,
    request_headers: &headers,
    query_identity: Some(&old_identity),
    certificate_identity: None,
  };
  assert!(first.lookup_async(old_ctx.clone()).await.is_none());
  let mut response_headers = HeaderMap::new();
  response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
  let prepared = match first.prepare_insert(
    CacheInsertContext {
      no_vary_search: None,
      proxy_protocol_identity: None,
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &method,
      uri: &uri,
      request_headers: &headers,
      query_identity: Some(&old_identity),
      certificate_identity: None,
    },
    StatusCode::OK,
    &response_headers,
    Some(3),
  ) {
    CachePreparedInsertDecision::Cacheable(prepared) => *prepared,
    other => panic!("old QUERY fill should prepare, got {other:?}"),
  };
  second
    .invalidate_query_target_async("default", "https", "example.test", "/lookup", None)
    .await
    .expect("invalidation should advance the shared epoch");
  assert_eq!(
    first
      .insert_prepared_async(
        prepared,
        CacheEntry::memory(StatusCode::OK, response_headers, Bytes::from_static(b"old")),
      )
      .await,
    CacheInsertOutcome::Stored,
  );
  let new_identity = query_identity(&uri, b"old", b"old");
  let observer_ctx = CacheLookupContext {
    no_vary_search: None,
    query_identity: Some(&new_identity),
    ..old_ctx
  };
  assert!(
    observer.lookup_async(observer_ctx).await.is_none(),
    "a generation-zero shared entry must not survive epoch one"
  );
}

#[tokio::test]
async fn shared_query_epochs_use_a_fixed_target_bucket_set() {
  let shared = crate::shared_state::SharedState::test_memory("query-epoch-bounds");
  for index in 0..(usize::from(QUERY_EPOCH_BUCKETS) * 3) {
    shared
      .cache_advance_query_epoch("default", "https", "example.test", &format!("/q/{index}"))
      .await
      .expect("bounded epoch update should succeed");
  }
  assert!(
    shared.test_cache_raw_keys("cache:query-epoch:").len() <= usize::from(QUERY_EPOCH_BUCKETS),
    "target epochs must remain bounded; collisions only cause conservative Q1 misses"
  );
}

#[test]
fn query_invalidation_fences_active_fill_until_owner_finishes() {
  let cache = query_cache();
  let uri = "/lookup".parse::<Uri>().unwrap();
  let identity = query_identity(&uri, b"query", b"query");
  let method = Method::from_bytes(b"QUERY").unwrap();
  let headers = query_headers();
  let context = CacheLookupContext {
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &method,
    uri: &uri,
    request_headers: &headers,
    query_identity: Some(&identity),
    certificate_identity: None,
  };
  let guard = match cache.begin_fill_decision(context).unwrap() {
    CacheFillDecision::Leader(guard) => guard,
    other => panic!("expected QUERY fill leader, got {other:?}"),
  };
  assert_eq!(
    cache.invalidate_query_target("default", "https", "example.test", "/lookup", None),
    0
  );
  assert!(matches!(
    cache.prepare_insert(
      CacheInsertContext {
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &method,
        uri: &uri,
        request_headers: &headers,
        query_identity: Some(&identity),
        certificate_identity: None,
      },
      StatusCode::OK,
      &HeaderMap::new(),
      Some(5),
    ),
    CachePreparedInsertDecision::NotCacheable(_)
  ));
  drop(guard);
}

#[test]
fn failed_query_invalidation_bypasses_only_that_query_target() {
  let cache = query_cache();
  let uri = "/lookup".parse::<Uri>().unwrap();
  let identity = query_identity(&uri, b"query", b"query");
  let method = Method::from_bytes(b"QUERY").unwrap();
  let headers = query_headers();
  let operation = cache
    .operation_context(
      Some("default"),
      "https",
      "example.test",
      &method,
      &uri,
      &headers,
      Some(&identity),
      None,
      None,
    )
    .unwrap();
  let target = operation.query_target.clone().unwrap();
  cache.mark_query_invalidation_failed(target);
  assert!(
    cache
      .lookup(CacheLookupContext {
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &method,
        uri: &uri,
        request_headers: &headers,
        query_identity: Some(&identity),
        certificate_identity: None,
      })
      .is_none()
  );
  let different_uri = "/other".parse::<Uri>().unwrap();
  let different_identity = query_identity(&different_uri, b"query", b"query");
  let other_operation = cache
    .operation_context(
      Some("default"),
      "https",
      "example.test",
      &method,
      &different_uri,
      &headers,
      Some(&different_identity),
      None,
      None,
    )
    .unwrap();
  assert!(!cache.query_target_cache_bypassed(&other_operation));
}

#[test]
fn query_disk_epoch_survives_invalidation_and_restart() {
  let directory = tempfile::tempdir().unwrap();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(directory.path().to_path_buf()),
    cache_methods: vec!["GET".into(), "HEAD".into(), "QUERY".into()],
    ..CacheConfig::default()
  };
  let uri: Uri = "/disk-query".parse().unwrap();
  let method = Method::from_bytes(b"QUERY").unwrap();
  let headers = query_headers();
  let response = || {
    let mut headers = HeaderMap::new();
    headers.insert(
      CACHE_CONTROL,
      HeaderValue::from_static("public, max-age=3600"),
    );
    CacheEntry::memory(StatusCode::OK, headers, Bytes::from_static(b"result"))
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  cache.invalidate_query_target("default", "https", "example.test", "/disk-query", None);
  let identity = query_identity(&uri, b"query", b"query");
  assert_eq!(
    cache.insert(
      CacheInsertContext {
        no_vary_search: None,
        proxy_protocol_identity: None,
        certificate_identity: None,
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &method,
        uri: &uri,
        request_headers: &headers,
        query_identity: Some(&identity),
      },
      response()
    ),
    CacheInsertOutcome::Stored
  );
  drop(cache);
  let cache = ResponseCache::new(&config, None).unwrap();
  let identity = query_identity(&uri, b"query", b"query");
  let context = CacheLookupContext {
    no_vary_search: None,
    proxy_protocol_identity: None,
    certificate_identity: None,
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &method,
    uri: &uri,
    request_headers: &headers,
    query_identity: Some(&identity),
  };
  assert!(matches!(
    cache.lookup(context.clone()),
    Some(CacheLookup::Fresh(_))
  ));
  cache.invalidate_query_target("default", "https", "example.test", "/disk-query", None);
  drop(cache);
  let cache = ResponseCache::new(&config, None).unwrap();
  let identity = query_identity(&uri, b"query", b"query");
  assert!(
    cache
      .lookup(CacheLookupContext {
        no_vary_search: None,
        query_identity: Some(&identity),
        ..context
      })
      .is_none()
  );
}

#[test]
fn query_disk_epoch_corruption_fails_closed_without_following_temporary_symlinks() {
  let directory = tempfile::tempdir().unwrap();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(directory.path().to_path_buf()),
    cache_methods: vec!["QUERY".into()],
    ..CacheConfig::default()
  };
  std::fs::write(
    directory.path().join(".oxibelt-query-epochs-v1"),
    b"invalid",
  )
  .unwrap();
  let cache = ResponseCache::new(&config, None).unwrap();
  assert_eq!(
    cache.inner_guard().failed_query_invalidations.len(),
    QUERY_EPOCH_BUCKETS as usize
  );
  #[cfg(unix)]
  {
    let outside = directory.path().join("must-not-overwrite");
    std::fs::write(&outside, b"unchanged").unwrap();
    std::os::unix::fs::symlink(
      &outside,
      directory.path().join(".oxibelt-query-epochs-v1.tmp"),
    )
    .unwrap();
    cache.invalidate_query_target("default", "https", "example.test", "/x", None);
    assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");
  }
}
