use super::*;

#[tokio::test]
async fn fill_permit_coalesces_followers_until_leader_drops() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css?v=1".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let ctx = CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  };
  let guard = match cache.begin_fill(ctx.clone()).unwrap() {
    CacheFillPermit::Leader(guard) => guard,
    CacheFillPermit::Follower(_) | CacheFillPermit::SharedConflict => {
      panic!("first fill should lead")
    }
  };
  let waiter = match cache.begin_fill(ctx.clone()).unwrap() {
    CacheFillPermit::Follower(waiter) => waiter,
    CacheFillPermit::Leader(_) | CacheFillPermit::SharedConflict => {
      panic!("second fill should wait")
    }
  };
  let wait_task = tokio::spawn(waiter.wait());
  tokio::task::yield_now().await;
  assert!(!wait_task.is_finished());
  drop(guard);
  tokio::time::timeout(Duration::from_secs(1), wait_task)
    .await
    .unwrap()
    .unwrap();
  assert!(matches!(
    cache.begin_fill(ctx).unwrap(),
    CacheFillPermit::Leader(_) | CacheFillPermit::SharedConflict
  ));
}

#[tokio::test]
async fn fill_waiter_times_out_without_leader_drop() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css?v=1".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let ctx = CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  };
  let _guard = match cache.begin_fill(ctx.clone()).unwrap() {
    CacheFillPermit::Leader(guard) => guard,
    CacheFillPermit::Follower(_) | CacheFillPermit::SharedConflict => {
      panic!("first fill should lead")
    }
  };
  let waiter = match cache.begin_fill(ctx).unwrap() {
    CacheFillPermit::Follower(waiter) => waiter,
    CacheFillPermit::Leader(_) | CacheFillPermit::SharedConflict => {
      panic!("second fill should wait")
    }
  };
  assert!(!waiter.wait_timeout(Duration::from_millis(5)).await);
}

#[test]
fn not_stored_fill_suppression_skips_short_lived_locks() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/no-store.css".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let insert_ctx = CacheInsertContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  };
  let lookup_ctx = CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  };

  cache.note_fill_not_stored(insert_ctx.clone());
  assert!(cache.begin_fill(lookup_ctx.clone()).is_none());

  std::thread::sleep(CacheFillSuppressionReason::Unknown.ttl() + Duration::from_millis(25));
  match cache.begin_fill(lookup_ctx).unwrap() {
    CacheFillPermit::Leader(_) => {}
    other => panic!("expected fill suppression to expire, got {other:?}"),
  }
}

#[test]
fn not_stored_fill_suppression_uses_long_ttl_for_semantic_rejections() {
  assert_eq!(
    CacheFillSuppressionReason::ResponseNoStore.ttl(),
    Duration::from_secs(10)
  );
  assert_eq!(
    CacheFillSuppressionReason::StoreFailed.ttl(),
    Duration::from_secs(1)
  );

  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/no-store.css".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let insert_ctx = CacheInsertContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  };
  let lookup_ctx = CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  };

  cache.note_fill_not_stored_reason(insert_ctx, CacheFillSuppressionReason::ResponseNoStore);
  assert!(cache.begin_fill(lookup_ctx).is_none());
}
