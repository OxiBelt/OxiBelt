use super::tests::{
  cache, hit, insert_context, lookup_context, origin_response, request, response, store,
};
use super::{CacheGroupOrigin, CacheGroupRequest};
use crate::cache::{CacheInsertOutcome, CacheNvsMetadata, CacheNvsRequest, ResponseCache};
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method, StatusCode, Uri};

#[tokio::test]
async fn absolute_and_origin_form_requests_share_exact_group_target_identity() {
  let cache = cache(true);
  let get = Method::GET;
  let post = Method::POST;
  let headers = HeaderMap::new();
  let origin = CacheGroupOrigin::new("https", "origin.example.test").unwrap();
  let first = Uri::from_static("/mutable?version=one");
  let sibling = Uri::from_static("/mutable?version=two");
  let group_peer = Uri::from_static("/peer");
  let chain_only = Uri::from_static("/chain-only");
  let absolute = Uri::from_static("https://origin.example.test/mutable?version=one");

  let first_request = request(&cache, origin.clone(), &get, &first, &headers).await;
  let sibling_request = request(&cache, origin.clone(), &get, &sibling, &headers).await;
  let peer_request = request(&cache, origin.clone(), &get, &group_peer, &headers).await;
  let chain_request = request(&cache, origin.clone(), &get, &chain_only, &headers).await;
  assert_eq!(
    store(
      &cache,
      Some(&first_request),
      &get,
      &first,
      &headers,
      Some("\"seed\"")
    )
    .await,
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    store(
      &cache,
      Some(&sibling_request),
      &get,
      &sibling,
      &headers,
      None
    )
    .await,
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    store(
      &cache,
      Some(&peer_request),
      &get,
      &group_peer,
      &headers,
      Some("\"seed\", \"leaf\"")
    )
    .await,
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    store(
      &cache,
      Some(&chain_request),
      &get,
      &chain_only,
      &headers,
      Some("\"leaf\"")
    )
    .await,
    CacheInsertOutcome::Stored
  );
  let mutation = request(&cache, origin.clone(), &post, &absolute, &headers).await;
  origin_response(
    &cache,
    &mutation,
    &post,
    &absolute,
    &headers,
    StatusCode::OK,
    &HeaderMap::new(),
  )
  .await;
  assert!(
    hit(&cache, Some(&first_request), &get, &first, &headers)
      .await
      .is_none()
  );
  assert!(
    hit(&cache, Some(&sibling_request), &get, &sibling, &headers)
      .await
      .is_some()
  );
  assert!(
    hit(&cache, Some(&peer_request), &get, &group_peer, &headers)
      .await
      .is_none()
  );
  assert!(
    hit(&cache, Some(&chain_request), &get, &chain_only, &headers)
      .await
      .is_some()
  );

  let absolute_stored = Uri::from_static("https://origin.example.test/reverse");
  let origin_mutation = Uri::from_static("/reverse");
  let stored_request = request(&cache, origin.clone(), &get, &absolute_stored, &headers).await;
  assert_eq!(
    store(
      &cache,
      Some(&stored_request),
      &get,
      &absolute_stored,
      &headers,
      None,
    )
    .await,
    CacheInsertOutcome::Stored
  );
  let mutation = request(&cache, origin, &post, &origin_mutation, &headers).await;
  origin_response(
    &cache,
    &mutation,
    &post,
    &origin_mutation,
    &headers,
    StatusCode::OK,
    &HeaderMap::new(),
  )
  .await;
  assert!(
    hit(
      &cache,
      Some(&stored_request),
      &get,
      &absolute_stored,
      &headers
    )
    .await
    .is_none()
  );
}

#[tokio::test]
async fn authority_form_maps_to_root_while_asterisk_form_fences_group_reuse() {
  let cache = cache(true);
  let get = Method::GET;
  let post = Method::POST;
  let headers = HeaderMap::new();
  let origin = CacheGroupOrigin::new("https", "origin.example.test").unwrap();
  let root = Uri::from_static("/");
  let other = Uri::from_static("/other");
  let root_request = request(&cache, origin.clone(), &get, &root, &headers).await;
  let other_request = request(&cache, origin.clone(), &get, &other, &headers).await;
  assert_eq!(
    store(&cache, Some(&root_request), &get, &root, &headers, None).await,
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    store(&cache, Some(&other_request), &get, &other, &headers, None).await,
    CacheInsertOutcome::Stored
  );

  let authority = Uri::from_static("origin.example.test:443");
  let mutation = request(&cache, origin.clone(), &post, &authority, &headers).await;
  origin_response(
    &cache,
    &mutation,
    &post,
    &authority,
    &headers,
    StatusCode::OK,
    &HeaderMap::new(),
  )
  .await;
  assert!(
    hit(&cache, Some(&root_request), &get, &root, &headers)
      .await
      .is_none()
  );
  assert!(
    hit(&cache, Some(&other_request), &get, &other, &headers)
      .await
      .is_some()
  );

  let asterisk = Uri::from_static("*");
  let mutation = request(&cache, origin, &post, &asterisk, &headers).await;
  origin_response(
    &cache,
    &mutation,
    &post,
    &asterisk,
    &headers,
    StatusCode::OK,
    &HeaderMap::new(),
  )
  .await;
  assert!(
    hit(&cache, Some(&other_request), &get, &other, &headers)
      .await
      .is_none(),
    "an unsafe successful asterisk-form target must fail closed"
  );
}

#[tokio::test]
async fn nvs_alias_group_match_canonicalizes_an_absolute_owner_uri() {
  let cache = cache(true);
  let method = Method::GET;
  let headers = HeaderMap::new();
  let alias_uri = Uri::from_static("/owner?tracking=removed");
  let request = request(
    &cache,
    CacheGroupOrigin::new("https", "origin.example.test").unwrap(),
    &method,
    &alias_uri,
    &headers,
  )
  .await;
  let mut stamp = request.snapshot().unwrap();
  stamp.target = "/owner?tracking=kept".to_string();
  let mut entry = response(None);
  entry.group_stamp = Some(stamp);
  entry.nvs_alias = true;
  entry.no_vary_search = Some(CacheNvsMetadata {
    version: 1,
    scope: "a".repeat(64),
    owner_uri: "https://origin.example.test/owner?tracking=kept".to_string(),
    effective_uri: "https://origin.example.test/owner?tracking=kept".to_string(),
    epoch: 0,
    policy_epoch: 0,
    candidate_limit: 16,
  });

  assert!(cache.group_entry_matches(
    &lookup_context(Some(&request), &method, &alias_uri, &headers),
    &entry,
  ));
}

#[tokio::test]
async fn disk_nvs_alias_with_an_absolute_owner_obeys_canonical_group_invalidation() {
  let directory = tempfile::tempdir().unwrap();
  let config = crate::config::CacheConfig {
    enabled: true,
    groups: crate::config::CacheGroupsConfig { enabled: true },
    no_vary_search: true,
    store: crate::config::CacheStore::Disk,
    disk_dir: Some(directory.path().to_path_buf()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..crate::config::CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let owner_uri = Uri::from_static("https://cache.example.test/owner?tracking=a");
  let owner_nvs = CacheNvsRequest::new(owner_uri.clone(), b"group-nvs-v1").unwrap();
  let group = CacheGroupRequest::new(CacheGroupOrigin::new("https", "cache.example.test").unwrap());
  let headers = HeaderMap::new();
  let owner_lookup = crate::cache::CacheLookupContext {
    no_vary_search: Some(&owner_nvs),
    ..lookup_context(Some(&group), &Method::GET, &owner_uri, &headers)
  };
  assert!(cache.bind_group_request(owner_lookup.clone()).await);
  cache.bind_nvs_epoch(owner_lookup).await;
  let mut entry = response(Some("\"owner\""));
  entry.headers.insert(
    "no-vary-search",
    HeaderValue::from_static("params=(\"tracking\")"),
  );
  entry
    .headers
    .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  owner_nvs.capture_origin(&entry.headers);
  assert_eq!(
    cache
      .insert_async(
        crate::cache::CacheInsertContext {
          no_vary_search: Some(&owner_nvs),
          ..insert_context(Some(&group), &Method::GET, &owner_uri, &headers)
        },
        entry,
      )
      .await,
    CacheInsertOutcome::Stored
  );
  drop(cache);

  let recovered = ResponseCache::new(&config, None).unwrap();
  let alias_uri = Uri::from_static("https://cache.example.test/owner?tracking=b");
  let alias_nvs = CacheNvsRequest::new(
    Uri::from_static("https://cache.example.test/owner?tracking=b"),
    b"group-nvs-v1",
  )
  .unwrap();
  let alias_group =
    CacheGroupRequest::new(CacheGroupOrigin::new("https", "cache.example.test").unwrap());
  let alias_lookup = crate::cache::CacheLookupContext {
    no_vary_search: Some(&alias_nvs),
    ..lookup_context(Some(&alias_group), &Method::GET, &alias_uri, &headers)
  };
  assert!(recovered.bind_group_request(alias_lookup.clone()).await);
  assert!(
    recovered
      .lookup_nvs_async(alias_lookup.clone(), None)
      .await
      .is_some()
  );

  let mutation_uri = Uri::from_static("/owner?tracking=b");
  let mutation = request(
    &recovered,
    CacheGroupOrigin::new("https", "cache.example.test").unwrap(),
    &Method::POST,
    &mutation_uri,
    &headers,
  )
  .await;
  origin_response(
    &recovered,
    &mutation,
    &Method::POST,
    &mutation_uri,
    &headers,
    StatusCode::OK,
    &HeaderMap::new(),
  )
  .await;
  assert!(
    recovered
      .lookup_nvs_async(alias_lookup, None)
      .await
      .is_none()
  );
}
