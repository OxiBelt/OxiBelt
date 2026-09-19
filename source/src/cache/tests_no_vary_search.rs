use super::*;

#[path = "tests_no_vary_search_external.rs"]
mod external;

fn response(field: &str) -> CacheEntry {
  let mut headers = HeaderMap::new();
  headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=3600"),
  );
  headers.insert("no-vary-search", HeaderValue::from_str(field).unwrap());
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  headers.insert(http::header::ETAG, HeaderValue::from_static("\"owner-v1\""));
  CacheEntry::memory(
    StatusCode::OK,
    headers,
    Bytes::from_static(b"owner representation"),
  )
}

fn context<'a>(
  uri: &'a Uri,
  request: &'a CacheNvsRequest,
  headers: &'a HeaderMap,
) -> CacheLookupContext<'a> {
  CacheLookupContext {
    group_request: None,
    no_vary_search: Some(request),
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri,
    request_headers: headers,
    query_identity: None,
    certificate_identity: None,
    dictionary_identity: None,
    origin_vary_headers: None,
    proxy_protocol_identity: None,
  }
}

async fn seed(cache: &ResponseCache, uri: &Uri, effective: &str, field: &str) {
  let request = CacheNvsRequest::new(effective.parse().unwrap(), b"route-v1").unwrap();
  let headers = HeaderMap::new();
  let ctx = context(uri, &request, &headers);
  cache.bind_nvs_epoch(ctx).await;
  let entry = response(field);
  request.capture_origin(&entry.headers);
  assert_eq!(
    cache
      .insert_async(
        CacheInsertContext {
          group_request: None,
          no_vary_search: Some(&request),
          policy_name: None,
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri,
          request_headers: &headers,
          query_identity: None,
          certificate_identity: None,
          dictionary_identity: None,
          origin_vary_headers: None,
          proxy_protocol_identity: None
        },
        entry
      )
      .await,
    CacheInsertOutcome::Stored
  );
}

async fn alias(cache: &ResponseCache, uri: &str, effective: &str) -> Option<CacheLookup> {
  let uri = uri.parse().unwrap();
  let request = CacheNvsRequest::new(effective.parse().unwrap(), b"route-v1").unwrap();
  let headers = HeaderMap::new();
  cache
    .lookup_nvs_async(context(&uri, &request, &headers), None)
    .await
}

fn context_with_options<'a>(
  uri: &'a Uri,
  request: &'a CacheNvsRequest,
  headers: &'a HeaderMap,
  method: &'a Method,
  query_identity: Option<&'a CacheQueryIdentity>,
  certificate_identity: Option<&'a CacheCertificateIdentity>,
) -> CacheLookupContext<'a> {
  CacheLookupContext {
    group_request: None,
    no_vary_search: Some(request),
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method,
    uri,
    request_headers: headers,
    query_identity,
    certificate_identity,
    dictionary_identity: None,
    origin_vary_headers: None,
    proxy_protocol_identity: None,
  }
}

#[allow(clippy::too_many_arguments)]
async fn seed_with_options(
  cache: &ResponseCache,
  uri: &Uri,
  effective: &str,
  field: &str,
  context_material: &[u8],
  method: &Method,
  headers: &HeaderMap,
  query_identity: Option<&CacheQueryIdentity>,
  certificate_identity: Option<&CacheCertificateIdentity>,
) {
  let request = CacheNvsRequest::new(effective.parse().unwrap(), context_material).unwrap();
  cache
    .bind_nvs_epoch(context_with_options(
      uri,
      &request,
      headers,
      method,
      query_identity,
      certificate_identity,
    ))
    .await;
  let entry = response(field);
  request.capture_origin(&entry.headers);
  assert_eq!(
    cache
      .insert_async(
        CacheInsertContext {
          group_request: None,
          no_vary_search: Some(&request),
          policy_name: None,
          scheme: "https",
          host: "example.test",
          method,
          uri,
          request_headers: headers,
          query_identity,
          certificate_identity,
          dictionary_identity: None,
          origin_vary_headers: None,
          proxy_protocol_identity: None,
        },
        entry
      )
      .await,
    CacheInsertOutcome::Stored
  );
}

#[allow(clippy::too_many_arguments)]
async fn alias_with_options(
  cache: &ResponseCache,
  uri: &Uri,
  effective: &str,
  context_material: &[u8],
  method: &Method,
  headers: &HeaderMap,
  query_identity: Option<&CacheQueryIdentity>,
  certificate_identity: Option<&CacheCertificateIdentity>,
) -> Option<CacheLookup> {
  let request = CacheNvsRequest::new(effective.parse().unwrap(), context_material).unwrap();
  cache
    .lookup_nvs_async(
      context_with_options(
        uri,
        &request,
        headers,
        method,
        query_identity,
        certificate_identity,
      ),
      None,
    )
    .await
}

fn query_identity_fixture(
  uri: &Uri,
  body: &[u8],
  content_type: &str,
  trailer: &str,
) -> CacheQueryIdentity {
  let mut content_headers = HeaderMap::new();
  content_headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
  let mut trailers = HeaderMap::new();
  trailers.insert("x-query-trailer", HeaderValue::from_str(trailer).unwrap());
  CacheQueryIdentity::new(
    CacheQueryRepresentation::new(
      "https",
      "example.test",
      uri,
      body.len() as u64,
      crate::crypto::sha256(body),
      &content_headers,
      &trailers,
    )
    .unwrap(),
    CacheQueryRepresentation::new(
      "https",
      "origin.test",
      uri,
      body.len() as u64,
      crate::crypto::sha256(body),
      &content_headers,
      &trailers,
    )
    .unwrap(),
    content_headers,
  )
  .unwrap()
}

#[tokio::test]
async fn aliases_preserve_both_targets_and_custom_query_dimensions() {
  for template in [
    "{scheme}:{host}:{uri}",
    "{scheme}:{host}:{query}",
    "{scheme}:{host}:{uri}:{query:tracking}",
  ] {
    let cache = ResponseCache::new(
      &CacheConfig {
        enabled: true,
        groups: crate::config::CacheGroupsConfig { enabled: false },
        cache_key: template.into(),
        ..CacheConfig::default()
      },
      None,
    )
    .unwrap();
    seed(
      &cache,
      &"/page?id=1&tracking=a".parse().unwrap(),
      "https://origin.test/page?id=1&tracking=a",
      "params=(\"tracking\")",
    )
    .await;
    let hit = alias(
      &cache,
      "/page?id=1&tracking=b",
      "https://origin.test/page?id=1&tracking=b",
    )
    .await;
    assert_eq!(hit.is_some(), !template.contains("{query:tracking}"));
    assert!(
      alias(
        &cache,
        "/page?id=2&tracking=b",
        "https://origin.test/page?id=2&tracking=b"
      )
      .await
      .is_none()
    );
    assert!(
      alias(
        &cache,
        "/page?id=1&tracking=b",
        "https://origin.test/other?id=1&tracking=b"
      )
      .await
      .is_none()
    );
    assert!(
      alias(
        &cache,
        "/page?id=1&tracking=b",
        "https://origin.test/page?id=2&tracking=b"
      )
      .await
      .is_none()
    );
  }
}

#[tokio::test]
async fn query_rewrites_require_equivalence_on_each_side() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  seed(
    &cache,
    &"/page?tracking=a".parse().unwrap(),
    "https://origin.test/page?important=a",
    "params=(\"tracking\")",
  )
  .await;
  assert!(
    alias(
      &cache,
      "/page?tracking=b",
      "https://origin.test/page?important=b"
    )
    .await
    .is_none()
  );
  seed(
    &cache,
    &"/other?utm=a".parse().unwrap(),
    "https://origin.test/other?tracking=a",
    "params=(\"tracking\")",
  )
  .await;
  assert!(
    alias(
      &cache,
      "/other?utm=b",
      "https://origin.test/other?tracking=b"
    )
    .await
    .is_none()
  );
}

#[tokio::test]
async fn exact_purge_fences_equivalent_objects_and_inflight_fills() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let uri: Uri = "/page?tracking=a".parse().unwrap();
  seed(
    &cache,
    &uri,
    "https://origin.test/page?tracking=a",
    "params=(\"tracking\")",
  )
  .await;
  let request = CacheNvsRequest::new(
    "https://origin.test/page?tracking=a".parse().unwrap(),
    b"route-v1",
  )
  .unwrap();
  let headers = HeaderMap::new();
  cache
    .bind_nvs_epoch(context(&uri, &request, &headers))
    .await;
  let entry = response("params=(\"tracking\")");
  request.capture_origin(&entry.headers);
  assert_eq!(
    cache
      .purge_exact_partition_async("default", "https", "example.test", "/page?tracking=b", None)
      .await
      .unwrap(),
    1
  );
  assert!(
    alias(
      &cache,
      "/page?tracking=b",
      "https://origin.test/page?tracking=b"
    )
    .await
    .is_none()
  );
  assert_eq!(
    cache
      .insert_async(
        CacheInsertContext {
          group_request: None,
          no_vary_search: Some(&request),
          policy_name: None,
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri: &uri,
          request_headers: &headers,
          query_identity: None,
          certificate_identity: None,
          dictionary_identity: None,
          origin_vary_headers: None,
          proxy_protocol_identity: None
        },
        entry
      )
      .await,
    CacheInsertOutcome::NotCacheable
  );
}

#[tokio::test]
async fn invalid_headers_and_changed_origin_fields_never_authorize_aliases() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  seed(
    &cache,
    &"/page?tracking=a".parse().unwrap(),
    "https://origin.test/page?tracking=a",
    "params",
  )
  .await;
  assert!(
    alias(
      &cache,
      "/page?tracking=b",
      "https://origin.test/page?tracking=b"
    )
    .await
    .is_none()
  );
  let uri = "/changed?tracking=a".parse().unwrap();
  let request = CacheNvsRequest::new(
    "https://origin.test/changed?tracking=a".parse().unwrap(),
    b"route-v1",
  )
  .unwrap();
  let headers = HeaderMap::new();
  cache
    .bind_nvs_epoch(context(&uri, &request, &headers))
    .await;
  request.capture_origin(&HeaderMap::new());
  let entry = response("except=()");
  assert_eq!(
    cache
      .insert_async(
        CacheInsertContext {
          group_request: None,
          no_vary_search: Some(&request),
          policy_name: None,
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri: &uri,
          request_headers: &headers,
          query_identity: None,
          certificate_identity: None,
          dictionary_identity: None,
          origin_vary_headers: None,
          proxy_protocol_identity: None
        },
        entry
      )
      .await,
    CacheInsertOutcome::Stored
  );
  assert!(
    alias(
      &cache,
      "/changed?tracking=b",
      "https://origin.test/changed?tracking=b"
    )
    .await
    .is_none()
  );
}

#[tokio::test]
async fn disk_recovery_preserves_only_generation_qualified_aliases() {
  let directory = tempfile::tempdir().unwrap();
  let config = CacheConfig {
    enabled: true,
    groups: crate::config::CacheGroupsConfig { enabled: false },
    store: CacheStore::Disk,
    disk_dir: Some(directory.path().to_path_buf()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };
  let uri = "/page?tracking=a".parse().unwrap();
  let cache = ResponseCache::new(&config, None).unwrap();
  seed(
    &cache,
    &uri,
    "https://origin.test/page?tracking=a",
    "params=(\"tracking\")",
  )
  .await;
  drop(cache);
  let recovered = ResponseCache::new(&config, None).unwrap();
  assert!(
    alias(
      &recovered,
      "/page?tracking=b",
      "https://origin.test/page?tracking=b"
    )
    .await
    .is_some()
  );
  recovered
    .invalidate_nvs_all_policies("https", "example.test", &uri)
    .await
    .unwrap();
  drop(recovered);
  let recovered = ResponseCache::new(&config, None).unwrap();
  assert!(
    alias(
      &recovered,
      "/page?tracking=b",
      "https://origin.test/page?tracking=b"
    )
    .await
    .is_none()
  );
}

#[tokio::test]
async fn same_process_config_toggle_disables_nvs_aliases_but_keeps_exact_cache() {
  let mut config = CacheConfig {
    enabled: true,
    groups: crate::config::CacheGroupsConfig { enabled: false },
    ..CacheConfig::default()
  };
  let enabled = ResponseCache::new(&config, None).unwrap();
  assert!(enabled.no_vary_search_enabled());
  let uri: Uri = "/toggle?ignored=one".parse().unwrap();
  seed(
    &enabled,
    &uri,
    "https://origin.test/toggle?ignored=one",
    "params=(\"ignored\")",
  )
  .await;
  assert!(
    alias(
      &enabled,
      "/toggle?ignored=two",
      "https://origin.test/toggle?ignored=two"
    )
    .await
    .is_some()
  );

  config.no_vary_search = false;
  let disabled = ResponseCache::new(&config, None).unwrap();
  assert!(!disabled.no_vary_search_enabled());
  seed(
    &disabled,
    &uri,
    "https://origin.test/toggle?ignored=one",
    "params=(\"ignored\")",
  )
  .await;
  let empty_headers = HeaderMap::new();
  assert!(
    alias(
      &disabled,
      "/toggle?ignored=two",
      "https://origin.test/toggle?ignored=two"
    )
    .await
    .is_none()
  );
  assert!(
    disabled
      .lookup(CacheLookupContext {
        group_request: None,
        no_vary_search: None,
        policy_name: None,
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &empty_headers,
        query_identity: None,
        certificate_identity: None,
        dictionary_identity: None,
        origin_vary_headers: None,
        proxy_protocol_identity: None,
      })
      .is_some()
  );
}

#[tokio::test]
async fn shared_memory_nvs_owner_and_alias_cross_cache_instances() {
  let shared = crate::shared_state::SharedState::test_memory("nvs-shared-two-instance");
  let config = CacheConfig {
    enabled: true,
    groups: crate::config::CacheGroupsConfig { enabled: false },
    ..CacheConfig::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared)).unwrap();
  let owner: Uri = "/shared-nvs?ignored=one".parse().unwrap();
  seed(
    &first,
    &owner,
    "https://origin.test/shared-nvs?ignored=one",
    "params=(\"ignored\")",
  )
  .await;
  let alias_uri: Uri = "/shared-nvs?ignored=two".parse().unwrap();
  assert!(
    alias_with_options(
      &second,
      &alias_uri,
      "https://origin.test/shared-nvs?ignored=two",
      b"route-v1",
      &Method::GET,
      &HeaderMap::new(),
      None,
      None
    )
    .await
    .is_some()
  );
}

#[path = "tests_no_vary_search_revalidation.rs"]
mod revalidation;

#[path = "tests_no_vary_search_identity.rs"]
mod identity;
