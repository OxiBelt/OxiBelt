use super::*;

#[tokio::test]
async fn no_vary_search_not_modified_reindexes_changed_rules_and_vary() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let owner: Uri = "/page?id=1&tracking=a".parse().unwrap();
  seed(
    &cache,
    &owner,
    "https://origin.test/page?id=1&tracking=a",
    "params=(\"tracking\")",
  )
  .await;
  let CacheLookup::Fresh(entry) = alias(
    &cache,
    "/page?id=1&tracking=b",
    "https://origin.test/page?id=1&tracking=b",
  )
  .await
  .unwrap() else {
    panic!("fresh owner expected")
  };
  let alias_uri: Uri = "/page?id=1&tracking=b".parse().unwrap();
  let alias_request = CacheNvsRequest::new(
    "https://origin.test/page?id=1&tracking=b".parse().unwrap(),
    b"route-v1",
  )
  .unwrap();
  let headers = HeaderMap::new();
  cache
    .bind_nvs_epoch(context(&alias_uri, &alias_request, &headers))
    .await;
  let owner_request = alias_request
    .for_owner(entry.no_vary_search.as_ref().unwrap())
    .unwrap();
  let mut update = HeaderMap::new();
  update.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=7200"),
  );
  update.insert(
    "no-vary-search",
    HeaderValue::from_static("except=(\"id\" \"tracking\")"),
  );
  update.insert(
    http::header::VARY,
    HeaderValue::from_static("accept-language"),
  );
  alias_request.capture_origin(&update);
  owner_request.capture_origin(&update);
  assert!(!cache.nvs_revalidation_allows_alias(&entry, &alias_uri, &alias_request, &update));
  cache
    .update_from_not_modified_async(
      CacheInsertContext {
        no_vary_search: Some(&owner_request),
        policy_name: None,
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &owner,
        request_headers: &headers,
        query_identity: None,
        certificate_identity: None,
        proxy_protocol_identity: None,
      },
      &entry,
      &update,
    )
    .await;
  assert!(
    alias(
      &cache,
      "/page?id=1&tracking=b",
      "https://origin.test/page?id=1&tracking=b"
    )
    .await
    .is_none()
  );
  let CacheLookup::Fresh(updated) = cache
    .lookup_async(context(&owner, &owner_request, &headers))
    .await
    .unwrap()
  else {
    panic!("updated owner expected")
  };
  assert_eq!(updated.body, entry.body);
  assert_eq!(updated.headers["no-vary-search"], update["no-vary-search"]);
  assert_eq!(updated.headers[http::header::VARY], "accept-language");
}

#[tokio::test]
async fn no_vary_search_not_modified_preserves_absent_rule_for_shared_only_owner() {
  let shared = crate::shared_state::SharedState::test_memory("nvs-revalidation-shared");
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let first = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let second = ResponseCache::new(&config, Some(shared)).unwrap();
  let owner: Uri = "/page?tracking=a".parse().unwrap();
  seed(
    &first,
    &owner,
    "https://origin.test/page?tracking=a",
    "params=(\"tracking\")",
  )
  .await;
  let request = CacheNvsRequest::new(
    "https://origin.test/page?tracking=b".parse().unwrap(),
    b"route-v1",
  )
  .unwrap();
  let alias_uri: Uri = "/page?tracking=b".parse().unwrap();
  let mut headers = HeaderMap::new();
  headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
  second
    .bind_nvs_epoch(context(&alias_uri, &request, &headers))
    .await;
  let lookup = second
    .lookup_nvs_async(context(&alias_uri, &request, &headers), None)
    .await
    .unwrap();
  let entry = match lookup {
    CacheLookup::Revalidate(item) => item.entry,
    CacheLookup::Stale(item) => item.entry,
    CacheLookup::Fresh(_) => panic!("must revalidate"),
  };
  assert!(second.inner_guard().entries.is_empty());
  let owner_request = request
    .for_owner(entry.no_vary_search.as_ref().unwrap())
    .unwrap();
  let mut update = HeaderMap::new();
  update.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=7200"),
  );
  request.capture_origin(&update);
  owner_request.capture_origin(&update);
  assert!(second.nvs_revalidation_allows_alias(&entry, &alias_uri, &request, &update));
  second
    .update_from_not_modified_async(
      CacheInsertContext {
        no_vary_search: Some(&owner_request),
        policy_name: None,
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &owner,
        request_headers: &headers,
        query_identity: None,
        certificate_identity: None,
        proxy_protocol_identity: None,
      },
      &entry,
      &update,
    )
    .await;
  assert!(!second.inner_guard().entries.is_empty());
  assert!(
    alias(
      &second,
      "/page?tracking=c",
      "https://origin.test/page?tracking=c"
    )
    .await
    .is_some()
  );
}

#[tokio::test]
async fn no_vary_search_missing_disk_epochs_cannot_resurrect_after_two_restarts() {
  let directory = tempfile::tempdir().unwrap();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(directory.path().to_path_buf()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };
  let uri: Uri = "/lost-epochs?tracking=a".parse().unwrap();
  let cache = ResponseCache::new(&config, None).unwrap();
  seed(
    &cache,
    &uri,
    "https://origin.test/lost-epochs?tracking=a",
    "params=(\"tracking\")",
  )
  .await;
  drop(cache);
  std::fs::remove_file(directory.path().join(".oxibelt-query-epochs-v1")).unwrap();
  for _ in 0..2 {
    let cache = ResponseCache::new(&config, None).unwrap();
    assert!(
      alias(
        &cache,
        "/lost-epochs?tracking=b",
        "https://origin.test/lost-epochs?tracking=b"
      )
      .await
      .is_none()
    );
    let headers = HeaderMap::new();
    let request = CacheNvsRequest::new(
      "https://origin.test/lost-epochs?tracking=a"
        .parse()
        .unwrap(),
      b"route-v1",
    )
    .unwrap();
    assert!(
      cache
        .lookup_async(context(&uri, &request, &headers))
        .await
        .is_some()
    );
  }
}

#[tokio::test]
async fn no_vary_search_policy_replacement_fences_declined_fills_and_loses_to_unsafe_races() {
  for invalidate_during_origin in [false, true] {
    let cache = ResponseCache::new(
      &CacheConfig {
        enabled: true,
        ..CacheConfig::default()
      },
      None,
    )
    .unwrap();
    let owner: Uri = "/replace?a=1&b=1".parse().unwrap();
    seed(
      &cache,
      &owner,
      "https://origin.test/replace?a=1&b=1",
      "params=(\"a\" \"b\")",
    )
    .await;
    let CacheLookup::Fresh(entry) = alias(
      &cache,
      "/replace?a=2&b=1",
      "https://origin.test/replace?a=2&b=1",
    )
    .await
    .unwrap() else {
      panic!("fresh alias expected")
    };
    let request = CacheNvsRequest::new(
      "https://origin.test/replace?a=1&b=1".parse().unwrap(),
      b"route-v1",
    )
    .unwrap();
    let headers = HeaderMap::new();
    cache
      .bind_nvs_epoch(context(&owner, &request, &headers))
      .await;
    if invalidate_during_origin {
      cache
        .invalidate_nvs_all_policies("https", "example.test", &owner)
        .await
        .unwrap();
    }
    let allowed = cache
      .replace_nvs_policy(context(&owner, &request, &headers), &entry)
      .await;
    assert_eq!(allowed, !invalidate_during_origin);
    let mut update = HeaderMap::new();
    update.insert("no-vary-search", HeaderValue::from_static("params=(\"a\")"));
    update.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    request.capture_origin(&update);
    if allowed {
      cache
        .update_from_not_modified_async(
          CacheInsertContext {
            no_vary_search: Some(&request),
            policy_name: None,
            scheme: "https",
            host: "example.test",
            method: &Method::GET,
            uri: &owner,
            request_headers: &headers,
            query_identity: None,
            certificate_identity: None,
            proxy_protocol_identity: None,
          },
          &entry,
          &update,
        )
        .await;
    }
    assert!(
      alias(
        &cache,
        "/replace?a=1&b=2",
        "https://origin.test/replace?a=1&b=2"
      )
      .await
      .is_none()
    );
  }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn no_vary_search_tmpfs_alias_uses_the_original_body_file() {
  let directory = tempfile::tempdir_in("/dev/shm").unwrap();
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      store: CacheStore::Tmpfs,
      tmpfs_dir: Some(directory.path().to_path_buf()),
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let owner: Uri = "/tmpfs?tracking=a".parse().unwrap();
  seed(
    &cache,
    &owner,
    "https://origin.test/tmpfs?tracking=a",
    "params=(\"tracking\")",
  )
  .await;
  let CacheLookup::Fresh(entry) = alias(
    &cache,
    "/tmpfs?tracking=b",
    "https://origin.test/tmpfs?tracking=b",
  )
  .await
  .unwrap() else {
    panic!("fresh alias expected")
  };
  let file = entry.body_file.unwrap();
  assert_eq!(std::fs::read(file.path).unwrap(), b"owner representation");
  assert_eq!(cache.stats().tmpfs_entries, 1);
}

#[tokio::test]
async fn no_vary_search_oversized_owner_metadata_preserves_exact_reuse() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let owner: Uri = format!("/large?tracking={}", "x".repeat(17_000))
    .parse()
    .unwrap();
  seed(
    &cache,
    &owner,
    "https://origin.test/large?tracking=a",
    "params=(\"tracking\")",
  )
  .await;
  let request = CacheNvsRequest::new(
    "https://origin.test/large?tracking=a".parse().unwrap(),
    b"route-v1",
  )
  .unwrap();
  let headers = HeaderMap::new();
  let CacheLookup::Fresh(entry) = cache
    .lookup_async(context(&owner, &request, &headers))
    .await
    .unwrap()
  else {
    panic!("exact response expected")
  };
  assert!(entry.no_vary_search.is_none());
  assert!(
    alias(
      &cache,
      "/large?tracking=b",
      "https://origin.test/large?tracking=b"
    )
    .await
    .is_none()
  );
}
