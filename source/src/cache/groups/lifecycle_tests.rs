use super::tests::{cache, insert_context, lookup_context, request, response};
use super::{CacheGroupOrigin, CacheGroupRequest};
use crate::cache::{CacheInsertOutcome, CacheLookup, ResponseCache};
use http::header::VARY;
use http::{HeaderMap, HeaderValue, Method, Uri};

#[tokio::test]
async fn revalidation_replaces_memberships_and_checks_the_old_owner() {
  let cache = cache(true);
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let uri = Uri::from_static("/owner");
  let headers = HeaderMap::new();
  let initial = request(&cache, origin.clone(), &Method::GET, &uri, &headers).await;
  assert_eq!(
    cache
      .insert_async(
        insert_context(Some(&initial), &Method::GET, &uri, &headers),
        response(Some("\"old\""))
      )
      .await,
    CacheInsertOutcome::Stored
  );
  let Some(CacheLookup::Fresh(owner)) = cache
    .lookup_async(lookup_context(Some(&initial), &Method::GET, &uri, &headers))
    .await
  else {
    panic!("owner missing");
  };
  let mut changed = HeaderMap::new();
  changed.insert("cache-groups", HeaderValue::from_static("\"new\""));
  let refresh = request(&cache, origin.clone(), &Method::GET, &uri, &headers).await;
  assert!(
    cache
      .update_from_not_modified_async(
        insert_context(Some(&refresh), &Method::GET, &uri, &headers),
        &owner,
        &changed
      )
      .await
  );
  cache
    .purge_group_async("default", &origin, "old", None)
    .await
    .unwrap();
  let fresh = request(&cache, origin.clone(), &Method::GET, &uri, &headers).await;
  assert!(
    cache
      .lookup_async(lookup_context(Some(&fresh), &Method::GET, &uri, &headers))
      .await
      .is_some()
  );
  // A different replacement membership cannot launder an invalidated owner.
  assert!(
    !cache
      .update_from_not_modified_async(
        insert_context(Some(&fresh), &Method::GET, &uri, &headers),
        &owner,
        &changed
      )
      .await
  );
  cache
    .purge_group_async("default", &origin, "new", None)
    .await
    .unwrap();
  assert!(
    cache
      .lookup_async(lookup_context(Some(&fresh), &Method::GET, &uri, &headers))
      .await
      .is_none()
  );
}

#[tokio::test]
async fn shared_authority_rejects_other_node_hits_and_late_fills() {
  let shared = crate::shared_state::SharedState::test_memory("group-multi-node");
  let config = crate::config::CacheConfig {
    enabled: true,
    ..Default::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared)).unwrap();
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let uri = Uri::from_static("/shared");
  let headers = HeaderMap::new();
  let fill = request(&first, origin.clone(), &Method::GET, &uri, &headers).await;
  assert_eq!(
    first
      .insert_async(
        insert_context(Some(&fill), &Method::GET, &uri, &headers),
        response(Some("\"shared\""))
      )
      .await,
    CacheInsertOutcome::Stored
  );
  let peer = request(&second, origin.clone(), &Method::GET, &uri, &headers).await;
  assert!(
    second
      .lookup_async(lookup_context(Some(&peer), &Method::GET, &uri, &headers))
      .await
      .is_some()
  );
  second
    .purge_group_async("default", &origin, "shared", None)
    .await
    .unwrap();
  assert!(
    first
      .lookup_async(lookup_context(Some(&fill), &Method::GET, &uri, &headers))
      .await
      .is_none()
  );
  assert_eq!(
    first
      .insert_async(
        insert_context(Some(&fill), &Method::GET, &uri, &headers),
        response(Some("\"shared\""))
      )
      .await,
    CacheInsertOutcome::NotCacheable
  );
}

#[tokio::test]
async fn failure_fence_recovery_rotates_generation_and_rejects_pre_failure_fill() {
  let cache = cache(true);
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let uri = Uri::from_static("/old-fill");
  let headers = HeaderMap::new();
  let old = request(&cache, origin.clone(), &Method::GET, &uri, &headers).await;
  cache.groups.fence("default");
  assert_eq!(
    cache
      .insert_async(
        insert_context(Some(&old), &Method::GET, &uri, &headers),
        response(None)
      )
      .await,
    CacheInsertOutcome::NotCacheable
  );
  let next = CacheGroupRequest::new(origin);
  assert!(
    cache
      .bind_group_request(lookup_context(Some(&next), &Method::GET, &uri, &headers))
      .await
  );
  assert!(!cache.groups.fenced("default"));
  assert_eq!(
    cache
      .insert_async(
        insert_context(Some(&old), &Method::GET, &uri, &headers),
        response(None)
      )
      .await,
    CacheInsertOutcome::NotCacheable
  );
  assert_eq!(
    cache
      .insert_async(
        insert_context(Some(&next), &Method::GET, &uri, &headers),
        response(None)
      )
      .await,
    CacheInsertOutcome::Stored
  );
}

#[tokio::test]
async fn invalidated_group_variants_release_the_default_vary_budget() {
  let cache = cache(true);
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let method = Method::GET;
  let uri = Uri::from_static("/generation-budget");
  let headers = HeaderMap::new();

  // The default limit is 64. Each purge makes the preceding generation
  // obsolete; the 65th fill must reclaim that obsolete variant before it is
  // admitted.
  for _ in 0..65 {
    let fill = request(&cache, origin.clone(), &method, &uri, &headers).await;
    assert_eq!(
      cache
        .insert_async(
          insert_context(Some(&fill), &method, &uri, &headers),
          response(Some("\"release\""))
        )
        .await,
      CacheInsertOutcome::Stored
    );
    assert!(matches!(
      cache
        .lookup_async(lookup_context(Some(&fill), &method, &uri, &headers))
        .await,
      Some(CacheLookup::Fresh(_))
    ));
    assert_eq!(
      cache
        .purge_group_async("default", &origin, "release", None)
        .await
        .unwrap(),
      1
    );
  }

  let current = request(&cache, origin, &method, &uri, &headers).await;
  assert_eq!(
    cache
      .insert_async(
        insert_context(Some(&current), &method, &uri, &headers),
        response(Some("\"release\""))
      )
      .await,
    CacheInsertOutcome::Stored
  );
  assert!(matches!(
    cache
      .lookup_async(lookup_context(Some(&current), &method, &uri, &headers))
      .await,
    Some(CacheLookup::Fresh(_))
  ));
}

#[tokio::test]
async fn current_group_variants_still_enforce_the_vary_budget() {
  let config = crate::config::CacheConfig {
    enabled: true,
    groups: crate::config::CacheGroupsConfig { enabled: true },
    max_vary_variants_per_key: 1,
    ..crate::config::CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let method = Method::GET;
  let uri = Uri::from_static("/current-vary-budget");
  let mut first_headers = HeaderMap::new();
  first_headers.insert("x-variant", HeaderValue::from_static("a"));
  let mut second_headers = HeaderMap::new();
  second_headers.insert("x-variant", HeaderValue::from_static("b"));
  let mut entry = response(Some("\"release\""));
  entry
    .headers
    .insert(VARY, HeaderValue::from_static("x-variant"));

  let first = request(&cache, origin.clone(), &method, &uri, &first_headers).await;
  assert_eq!(
    cache
      .insert_async(
        insert_context(Some(&first), &method, &uri, &first_headers),
        entry
      )
      .await,
    CacheInsertOutcome::Stored
  );
  let second = request(&cache, origin, &method, &uri, &second_headers).await;
  let mut rejected = response(Some("\"release\""));
  rejected
    .headers
    .insert(VARY, HeaderValue::from_static("x-variant"));
  assert_eq!(
    cache
      .insert_async(
        insert_context(Some(&second), &method, &uri, &second_headers),
        rejected
      )
      .await,
    CacheInsertOutcome::Rejected
  );
  assert!(matches!(
    cache
      .lookup_async(lookup_context(Some(&first), &method, &uri, &first_headers))
      .await,
    Some(CacheLookup::Fresh(_))
  ));
}

#[tokio::test]
async fn disk_restart_preserves_invalidation_and_disabled_generation_stays_retired() {
  let directory = tempfile::tempdir().unwrap();
  let mut config = crate::config::CacheConfig {
    enabled: true,
    store: crate::config::CacheStore::Disk,
    disk_dir: Some(directory.path().to_path_buf()),
    ..Default::default()
  };
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let uri = Uri::from_static("/disk");
  let headers = HeaderMap::new();
  {
    let cache = ResponseCache::new(&config, None).unwrap();
    let fill = request(&cache, origin.clone(), &Method::GET, &uri, &headers).await;
    assert_eq!(
      cache
        .insert_async(
          insert_context(Some(&fill), &Method::GET, &uri, &headers),
          response(Some("\"disk\""))
        )
        .await,
      CacheInsertOutcome::Stored
    );
  }
  {
    let cache = ResponseCache::new(&config, None).unwrap();
    let hit = request(&cache, origin.clone(), &Method::GET, &uri, &headers).await;
    assert!(
      cache
        .lookup_async(lookup_context(Some(&hit), &Method::GET, &uri, &headers))
        .await
        .is_some()
    );
    cache
      .purge_group_async("default", &origin, "disk", None)
      .await
      .unwrap();
  }
  config.groups.enabled = false;
  drop(ResponseCache::new(&config, None).unwrap());
  config.groups.enabled = true;
  let cache = ResponseCache::new(&config, None).unwrap();
  let hit = request(&cache, origin, &Method::GET, &uri, &headers).await;
  assert!(
    cache
      .lookup_async(lookup_context(Some(&hit), &Method::GET, &uri, &headers))
      .await
      .is_none()
  );
}
