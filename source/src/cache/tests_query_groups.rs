use super::query::query_identity_with_cache_headers;
use super::*;
use http::header::CACHE_CONTROL;
use std::collections::HashSet;

fn grouped_shared_query_cache(shared: Arc<crate::shared_state::SharedState>) -> Arc<ResponseCache> {
  let config = CacheConfig {
    enabled: true,
    groups: crate::config::CacheGroupsConfig { enabled: true },
    cache_methods: vec!["GET".to_string(), "HEAD".to_string(), "QUERY".to_string()],
    cache_key: "constant".to_string(),
    partition_key: "{header:x-tenant}".to_string(),
    query_cleanup: crate::config::CacheQueryCleanupConfig {
      queue_capacity: 8,
      batch_size: 1,
      max_concurrent: 1,
    },
    policies: vec![toml::from_str("name = 'named'").expect("named cache policy")],
    ..CacheConfig::default()
  };
  ResponseCache::new(&config, Some(shared)).unwrap()
}

#[tokio::test]
async fn all_policy_query_invalidation_fences_grouped_shared_partitions_and_reclaims_in_batches() {
  let shared = crate::shared_state::SharedState::test_memory("grouped-query-all-policies");
  let cache = grouped_shared_query_cache(shared.clone());
  let uri = "/all-policies".parse::<Uri>().unwrap();
  let method = Method::from_bytes(b"QUERY").unwrap();
  let origin = crate::cache::CacheGroupOrigin::new("https", "example.test").unwrap();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=60"));
  let mut partitions = HashSet::new();

  for policy in ["default", "named"] {
    for tenant in ["a", "b"] {
      let mut headers = HeaderMap::new();
      headers.insert("x-tenant", HeaderValue::from_static(tenant));
      let identity = query_identity_with_cache_headers(
        &uri,
        policy.as_bytes(),
        tenant.as_bytes(),
        headers.clone(),
      );
      let group_request = crate::cache::CacheGroupRequest::new(origin.clone());
      let context = CacheLookupContext {
        group_request: Some(&group_request),
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: Some(policy),
        scheme: "https",
        host: "example.test",
        method: &method,
        uri: &uri,
        request_headers: &headers,
        query_identity: Some(&identity),
        certificate_identity: None,
        dictionary_identity: None,
        origin_vary_headers: None,
      };
      assert!(cache.lookup_async(context.clone()).await.is_none());
      let operation = cache
        .operation_context(
          Some(policy),
          "https",
          "example.test",
          &method,
          &uri,
          &headers,
          Some(&identity),
          None,
          None,
          Some(&group_request),
        )
        .expect("bound groups-enabled QUERY operation should have a cache scope");
      partitions.insert((policy, operation.partition));
      assert_eq!(
        cache
          .insert_async(
            CacheInsertContext {
              group_request: Some(&group_request),
              no_vary_search: None,
              proxy_protocol_identity: None,
              policy_name: Some(policy),
              scheme: "https",
              host: "example.test",
              method: &method,
              uri: &uri,
              request_headers: &headers,
              query_identity: Some(&identity),
              certificate_identity: None,
              dictionary_identity: None,
              origin_vary_headers: None,
            },
            CacheEntry::memory(
              StatusCode::OK,
              response_headers.clone(),
              Bytes::from_static(b"query"),
            ),
          )
          .await,
        CacheInsertOutcome::Stored
      );
    }
  }
  assert_eq!(
    partitions.len(),
    4,
    "each policy and tenant must use a distinct partitioned QUERY cache scope"
  );

  let mut delayed_headers = HeaderMap::new();
  delayed_headers.insert("x-tenant", HeaderValue::from_static("a"));
  let delayed_identity =
    query_identity_with_cache_headers(&uri, b"delayed", b"delayed", delayed_headers.clone());
  let delayed_request = crate::cache::CacheGroupRequest::new(origin.clone());
  let delayed_context = CacheLookupContext {
    group_request: Some(&delayed_request),
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &method,
    uri: &uri,
    request_headers: &delayed_headers,
    query_identity: Some(&delayed_identity),
    certificate_identity: None,
    dictionary_identity: None,
    origin_vary_headers: None,
  };
  assert!(cache.lookup_async(delayed_context.clone()).await.is_none());
  let delayed = match cache.prepare_insert(
    CacheInsertContext {
      group_request: Some(&delayed_request),
      no_vary_search: None,
      proxy_protocol_identity: None,
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &method,
      uri: &uri,
      request_headers: &delayed_headers,
      query_identity: Some(&delayed_identity),
      certificate_identity: None,
      dictionary_identity: None,
      origin_vary_headers: None,
    },
    StatusCode::OK,
    &response_headers,
    Some(b"delayed".len()),
  ) {
    CachePreparedInsertDecision::Cacheable(prepared) => *prepared,
    other => panic!("pre-invalidation QUERY fill should prepare, got {other:?}"),
  };

  assert_eq!(
    cache
      .invalidate_query_target_async_all_policies("https", "example.test", "/all-policies")
      .await
      .expect("all enabled policies should advance their shared epochs"),
    0
  );
  for policy in ["default", "named"] {
    assert_eq!(
      shared
        .cache_query_epoch(policy, "https", "example.test", "/all-policies")
        .await
        .expect("shared QUERY epoch should be readable"),
      1,
      "{policy} must fence every partition before cleanup"
    );
  }
  assert_eq!(
    cache
      .insert_prepared_async(
        delayed,
        CacheEntry::memory(
          StatusCode::OK,
          response_headers.clone(),
          Bytes::from_static(b"delayed"),
        ),
      )
      .await,
    CacheInsertOutcome::NotCacheable,
    "a fill prepared before all-policy fencing must not publish into the old epoch"
  );
  let fresh_delayed_identity =
    query_identity_with_cache_headers(&uri, b"delayed", b"delayed", delayed_headers.clone());
  assert!(
    cache
      .lookup_async(CacheLookupContext {
        query_identity: Some(&fresh_delayed_identity),
        ..delayed_context
      })
      .await
      .is_none(),
    "a fill prepared before all-policy invalidation must remain fenced"
  );

  for _ in 0..100 {
    if cache.inner_guard().entries.is_empty()
      && shared.test_cache_raw_keys("cache:entry:").is_empty()
    {
      return;
    }
    tokio::task::yield_now().await;
  }
  panic!("bounded QUERY cleanup did not reclaim every grouped partition");
}
