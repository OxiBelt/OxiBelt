use super::{CacheGroupOrigin, CacheGroupRequest};
use crate::cache::{CacheEntry, CacheInsertOutcome, CacheLookup, ResponseCache};
use bytes::Bytes;
use http::header::{CACHE_CONTROL, HeaderValue};
use http::{HeaderMap, Method, StatusCode, Uri};

pub(super) fn cache(groups_enabled: bool) -> std::sync::Arc<ResponseCache> {
  ResponseCache::new(
    &crate::config::CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig {
        enabled: groups_enabled,
      },
      ..crate::config::CacheConfig::default()
    },
    None,
  )
  .unwrap()
}

pub(super) fn lookup_context<'a>(
  request: Option<&'a CacheGroupRequest>,
  method: &'a Method,
  uri: &'a Uri,
  headers: &'a HeaderMap,
) -> crate::cache::CacheLookupContext<'a> {
  crate::cache::CacheLookupContext {
    group_request: request,
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: None,
    scheme: "https",
    host: "cache.example.test",
    method,
    uri,
    request_headers: headers,
    query_identity: None,
    certificate_identity: None,
  }
}

pub(super) fn insert_context<'a>(
  request: Option<&'a CacheGroupRequest>,
  method: &'a Method,
  uri: &'a Uri,
  headers: &'a HeaderMap,
) -> crate::cache::CacheInsertContext<'a> {
  crate::cache::CacheInsertContext {
    group_request: request,
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: None,
    scheme: "https",
    host: "cache.example.test",
    method,
    uri,
    request_headers: headers,
    query_identity: None,
    certificate_identity: None,
  }
}

pub(super) async fn request(
  cache: &ResponseCache,
  origin: CacheGroupOrigin,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
) -> CacheGroupRequest {
  let request = CacheGroupRequest::new(origin);
  assert!(
    cache
      .bind_group_request(lookup_context(Some(&request), method, uri, headers))
      .await
  );
  request
}

pub(super) fn response(groups: Option<&str>) -> CacheEntry {
  let mut headers = HeaderMap::new();
  headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=120"),
  );
  if let Some(groups) = groups {
    headers.insert("cache-groups", HeaderValue::from_str(groups).unwrap());
  }
  CacheEntry::memory(StatusCode::OK, headers, Bytes::from_static(b"grouped"))
}

#[tokio::test]
async fn group_get_stale_entry_preserves_membership_in_memory_and_after_disk_recovery() {
  for disk in [false, true] {
    let directory = tempfile::tempdir().unwrap();
    let config = crate::config::CacheConfig {
      enabled: true,
      store: if disk {
        crate::config::CacheStore::Disk
      } else {
        crate::config::CacheStore::Memory
      },
      disk_dir: disk.then(|| directory.path().to_path_buf()),
      background_refresh: true,
      ..crate::config::CacheConfig::default()
    };
    let cache = ResponseCache::new(&config, None).unwrap();
    let uri: Uri = "/stale-group".parse().unwrap();
    let headers = HeaderMap::new();
    let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
    let token = request(&cache, origin.clone(), &Method::GET, &uri, &headers).await;
    let mut entry = response(Some("\"stale\""));
    entry.headers.insert(
      CACHE_CONTROL,
      HeaderValue::from_static("public, max-age=1, stale-while-revalidate=60, stale-if-error=60"),
    );
    assert_eq!(
      cache
        .insert_async(
          insert_context(Some(&token), &Method::GET, &uri, &headers),
          entry
        )
        .await,
      CacheInsertOutcome::Stored
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(matches!(
      cache
        .lookup_async(lookup_context(Some(&token), &Method::GET, &uri, &headers))
        .await,
      Some(CacheLookup::Stale(_))
    ));
    if disk {
      drop(cache);
      let recovered = ResponseCache::new(&config, None).unwrap();
      let token = request(&recovered, origin, &Method::GET, &uri, &headers).await;
      assert!(matches!(
        recovered
          .lookup_async(lookup_context(Some(&token), &Method::GET, &uri, &headers))
          .await,
        Some(CacheLookup::Stale(_))
      ));
    }
  }
}

async fn store(
  cache: &ResponseCache,
  request: Option<&CacheGroupRequest>,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
  groups: Option<&str>,
) -> CacheInsertOutcome {
  cache
    .insert_async(
      insert_context(request, method, uri, headers),
      response(groups),
    )
    .await
}

async fn hit(
  cache: &ResponseCache,
  request: Option<&CacheGroupRequest>,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
) -> Option<CacheLookup> {
  cache
    .lookup_async(lookup_context(request, method, uri, headers))
    .await
}

async fn origin_response(
  cache: &ResponseCache,
  request: &CacheGroupRequest,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
  status: StatusCode,
  response_headers: &HeaderMap,
) {
  cache
    .groups_after_origin_response(
      lookup_context(Some(request), method, uri, headers),
      status,
      response_headers,
    )
    .await;
}

#[tokio::test]
async fn copies_valid_groups_and_rejects_invalid_fields_when_enabled() {
  let cache = cache(true);
  let method = Method::GET;
  let uri = Uri::from_static("/asset");
  let headers = HeaderMap::new();
  let bound_request = request(
    &cache,
    CacheGroupOrigin::new("https", "origin.example.test").unwrap(),
    &method,
    &uri,
    &headers,
  )
  .await;

  assert_eq!(
    store(
      &cache,
      Some(&bound_request),
      &method,
      &uri,
      &headers,
      Some("\"a\", \"b\""),
    )
    .await,
    CacheInsertOutcome::Stored
  );
  let Some(CacheLookup::Fresh(entry)) =
    hit(&cache, Some(&bound_request), &method, &uri, &headers).await
  else {
    panic!("grouped entry must be reusable");
  };
  assert_eq!(
    entry.group_stamp.unwrap().groups,
    vec!["a".to_string(), "b".to_string()]
  );

  let invalid_uri = Uri::from_static("/invalid");
  let invalid_request = request(
    &cache,
    CacheGroupOrigin::new("https", "origin.example.test").unwrap(),
    &method,
    &invalid_uri,
    &headers,
  )
  .await;
  assert_eq!(
    store(
      &cache,
      Some(&invalid_request),
      &method,
      &invalid_uri,
      &headers,
      Some("(\"not-an-item\")"),
    )
    .await,
    CacheInsertOutcome::NotCacheable
  );
}

#[tokio::test]
async fn disabled_groups_preserve_ordinary_cache_behavior() {
  let cache = cache(false);
  let method = Method::GET;
  let uri = Uri::from_static("/disabled");
  let headers = HeaderMap::new();
  assert_eq!(
    store(&cache, None, &method, &uri, &headers, Some("(\"ignored\")")).await,
    CacheInsertOutcome::Stored
  );
  assert!(hit(&cache, None, &method, &uri, &headers).await.is_some());
}

#[tokio::test]
async fn accepts_sixty_four_groups_and_bounds_sixty_five() {
  let cache = cache(true);
  let method = Method::GET;
  let headers = HeaderMap::new();
  let uri = Uri::from_static("/limit");
  let bound_request = request(
    &cache,
    CacheGroupOrigin::new("https", "origin.example.test").unwrap(),
    &method,
    &uri,
    &headers,
  )
  .await;
  let max = (0..64)
    .map(|index| format!("\"group-{index}\""))
    .collect::<Vec<_>>()
    .join(", ");
  assert_eq!(
    store(
      &cache,
      Some(&bound_request),
      &method,
      &uri,
      &headers,
      Some(&max)
    )
    .await,
    CacheInsertOutcome::Stored
  );

  let too_many_uri = Uri::from_static("/too-many");
  let too_many_request = request(
    &cache,
    CacheGroupOrigin::new("https", "origin.example.test").unwrap(),
    &method,
    &too_many_uri,
    &headers,
  )
  .await;
  let too_many = (0..65)
    .map(|index| format!("\"group-{index}\""))
    .collect::<Vec<_>>()
    .join(", ");
  assert_eq!(
    store(
      &cache,
      Some(&too_many_request),
      &method,
      &too_many_uri,
      &headers,
      Some(&too_many),
    )
    .await,
    CacheInsertOutcome::NotCacheable
  );
}

#[tokio::test]
async fn origin_ports_are_isolated_case_is_canonical_and_exact_invalidation_does_not_cascade() {
  let cache = cache(true);
  let method = Method::GET;
  let headers = HeaderMap::new();
  let a = Uri::from_static("/a");
  let b = Uri::from_static("/b");
  let c = Uri::from_static("/c");
  let canonical = request(
    &cache,
    CacheGroupOrigin::new("HTTPS", "ORIGIN.EXAMPLE.TEST:443").unwrap(),
    &method,
    &a,
    &headers,
  )
  .await;
  assert_eq!(
    store(
      &cache,
      Some(&canonical),
      &method,
      &a,
      &headers,
      Some("\"x\"")
    )
    .await,
    CacheInsertOutcome::Stored
  );
  let case_equivalent = request(
    &cache,
    CacheGroupOrigin::new("https", "origin.example.test").unwrap(),
    &method,
    &a,
    &headers,
  )
  .await;
  assert!(
    hit(&cache, Some(&case_equivalent), &method, &a, &headers)
      .await
      .is_some()
  );

  let b_request = request(
    &cache,
    CacheGroupOrigin::new("https", "origin.example.test").unwrap(),
    &method,
    &b,
    &headers,
  )
  .await;
  let c_request = request(
    &cache,
    CacheGroupOrigin::new("https", "origin.example.test").unwrap(),
    &method,
    &c,
    &headers,
  )
  .await;
  assert_eq!(
    store(
      &cache,
      Some(&b_request),
      &method,
      &b,
      &headers,
      Some("\"x\", \"y\"")
    )
    .await,
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    store(
      &cache,
      Some(&c_request),
      &method,
      &c,
      &headers,
      Some("\"y\"")
    )
    .await,
    CacheInsertOutcome::Stored
  );

  let mutation = Method::POST;
  origin_response(
    &cache,
    &canonical,
    &mutation,
    &a,
    &headers,
    StatusCode::OK,
    &HeaderMap::new(),
  )
  .await;
  assert!(
    hit(&cache, Some(&case_equivalent), &method, &a, &headers)
      .await
      .is_none()
  );
  assert!(
    hit(&cache, Some(&b_request), &method, &b, &headers)
      .await
      .is_none()
  );
  assert!(
    hit(&cache, Some(&c_request), &method, &c, &headers)
      .await
      .is_some()
  );

  let other_port = request(
    &cache,
    CacheGroupOrigin::new("https", "origin.example.test:8443").unwrap(),
    &method,
    &c,
    &headers,
  )
  .await;
  assert!(
    hit(&cache, Some(&other_port), &method, &c, &headers)
      .await
      .is_none()
  );
}

#[tokio::test]
async fn purge_group_is_scoped_to_the_exact_origin_and_partition() {
  let mut config = crate::config::CacheConfig {
    enabled: true,
    partition_key: "{header:x-tenant}".to_string(),
    ..crate::config::CacheConfig::default()
  };
  config.groups.enabled = true;
  let cache = ResponseCache::new(&config, None).unwrap();
  let method = Method::GET;
  let uri = Uri::from_static("/partitioned");
  let mut tenant_a = HeaderMap::new();
  tenant_a.insert("x-tenant", HeaderValue::from_static("a"));
  let mut tenant_b = HeaderMap::new();
  tenant_b.insert("x-tenant", HeaderValue::from_static("b"));
  let origin = CacheGroupOrigin::new("https", "origin.example.test").unwrap();
  let request_a = request(&cache, origin.clone(), &method, &uri, &tenant_a).await;
  let request_b = request(&cache, origin.clone(), &method, &uri, &tenant_b).await;
  assert_eq!(
    store(
      &cache,
      Some(&request_a),
      &method,
      &uri,
      &tenant_a,
      Some("\"release\"")
    )
    .await,
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    store(
      &cache,
      Some(&request_b),
      &method,
      &uri,
      &tenant_b,
      Some("\"release\"")
    )
    .await,
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    cache
      .purge_group_async("default", &origin, "release", Some("a"))
      .await
      .unwrap(),
    1
  );
  assert!(
    hit(&cache, Some(&request_a), &method, &uri, &tenant_a)
      .await
      .is_none()
  );
  assert!(
    hit(&cache, Some(&request_b), &method, &uri, &tenant_b)
      .await
      .is_some()
  );
}

#[tokio::test]
async fn only_unsafe_responses_invalidate_and_a_late_fill_cannot_publish() {
  let cache = cache(true);
  let get = Method::GET;
  let uri = Uri::from_static("/mutable");
  let headers = HeaderMap::new();
  let origin = CacheGroupOrigin::new("https", "origin.example.test").unwrap();
  let stored_request = request(&cache, origin.clone(), &get, &uri, &headers).await;
  assert_eq!(
    store(
      &cache,
      Some(&stored_request),
      &get,
      &uri,
      &headers,
      Some("\"release\"")
    )
    .await,
    CacheInsertOutcome::Stored
  );

  for safe in [
    Method::GET,
    Method::HEAD,
    Method::OPTIONS,
    Method::TRACE,
    Method::from_bytes(b"QUERY").unwrap(),
  ] {
    let safe_request = request(&cache, origin.clone(), &safe, &uri, &headers).await;
    origin_response(
      &cache,
      &safe_request,
      &safe,
      &uri,
      &headers,
      StatusCode::OK,
      &HeaderMap::new(),
    )
    .await;
    assert!(
      hit(&cache, Some(&stored_request), &get, &uri, &headers)
        .await
        .is_some(),
      "{safe} must not invalidate"
    );
  }

  let post = Method::POST;
  let error_mutation = request(&cache, origin.clone(), &post, &uri, &headers).await;
  let mut explicit = HeaderMap::new();
  explicit.insert(
    "cache-group-invalidation",
    HeaderValue::from_static("\"release\""),
  );
  origin_response(
    &cache,
    &error_mutation,
    &post,
    &uri,
    &headers,
    StatusCode::INTERNAL_SERVER_ERROR,
    &explicit,
  )
  .await;
  assert!(
    hit(&cache, Some(&stored_request), &get, &uri, &headers)
      .await
      .is_none()
  );

  let current = request(&cache, origin.clone(), &get, &uri, &headers).await;
  assert_eq!(
    store(
      &cache,
      Some(&current),
      &get,
      &uri,
      &headers,
      Some("\"release\""),
    )
    .await,
    CacheInsertOutcome::Stored
  );
  let late_fill = request(&cache, origin.clone(), &get, &uri, &headers).await;
  let mutation = request(&cache, origin, &post, &uri, &headers).await;
  origin_response(
    &cache,
    &mutation,
    &post,
    &uri,
    &headers,
    StatusCode::NOT_MODIFIED,
    &HeaderMap::new(),
  )
  .await;
  assert!(
    hit(&cache, Some(&stored_request), &get, &uri, &headers)
      .await
      .is_none()
  );
  assert_eq!(
    store(
      &cache,
      Some(&late_fill),
      &get,
      &uri,
      &headers,
      Some("\"release\"")
    )
    .await,
    CacheInsertOutcome::NotCacheable
  );
}
