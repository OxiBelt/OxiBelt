use std::sync::Arc;

use super::model::{Authority, digest};
use super::tests::{insert_context, lookup_context, request, response};
use super::{CacheGroupOrigin, CacheGroupRequest};
use crate::cache::{CacheInsertOutcome, ExternalCacheRuntime, ResponseCache};
use crate::runtime_health::RuntimeHealth;
use http::{HeaderMap, Method, Uri};

fn config(enabled: bool) -> crate::config::CacheConfig {
  crate::config::CacheConfig {
    enabled: true,
    groups: crate::config::CacheGroupsConfig { enabled },
    ..crate::config::CacheConfig::default()
  }
}

fn reloaded(
  config: &crate::config::CacheConfig,
  shared: Arc<crate::shared_state::SharedState>,
  previous: &ResponseCache,
) -> Arc<ResponseCache> {
  let metrics = crate::metrics::Metrics::new();
  ResponseCache::new_with_external_and_health_with_previous(
    config,
    Some(shared),
    ExternalCacheRuntime::disabled(metrics.clone()),
    Arc::new(RuntimeHealth::default()),
    metrics,
    Some(previous),
  )
  .unwrap()
}

#[tokio::test]
async fn disabled_reload_retires_shared_authority_for_draining_snapshot() {
  let shared = crate::shared_state::SharedState::test_memory("group-activation-retire");
  let first = ResponseCache::new(&config(true), Some(shared.clone())).unwrap();
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let uri = Uri::from_static("/reload");
  let headers = HeaderMap::new();
  let fill = request(&first, origin.clone(), &Method::GET, &uri, &headers).await;
  assert_eq!(
    first
      .insert_async(
        insert_context(Some(&fill), &Method::GET, &uri, &headers),
        response(Some("\"reload\"")),
      )
      .await,
    CacheInsertOutcome::Stored
  );

  let next = reloaded(&config(false), shared, &first);
  next
    .initialize_group_activation(Some(&first))
    .await
    .unwrap();
  assert!(!next.group_authority_read("default").await.unwrap().enabled);

  let old_request = CacheGroupRequest::new(origin);
  assert!(
    !first
      .bind_group_request(lookup_context(
        Some(&old_request),
        &Method::GET,
        &uri,
        &headers
      ))
      .await
  );
  assert_eq!(
    first
      .insert_async(
        insert_context(Some(&fill), &Method::GET, &uri, &headers),
        response(Some("\"reload\"")),
      )
      .await,
    CacheInsertOutcome::NotCacheable
  );
}

#[tokio::test]
async fn fresh_activation_replaces_a_retired_shared_authority_once() {
  let shared = crate::shared_state::SharedState::test_memory("group-activation-fresh");
  let mut retired = Authority::new("a".repeat(64));
  retired.enabled = false;
  let key = digest(b"default");
  assert!(
    shared
      .cache_group_compare_exchange(&key, None, &retired.encode().unwrap())
      .await
      .unwrap()
  );

  let cache = ResponseCache::new(&config(true), Some(shared)).unwrap();
  cache.initialize_group_activation(None).await.unwrap();
  let activated = cache.group_authority_read("default").await.unwrap();
  assert!(activated.enabled);
  assert_ne!(activated.incarnation, retired.incarnation);
}

#[tokio::test]
async fn removing_and_readding_a_policy_retires_its_old_generation() {
  let shared = crate::shared_state::SharedState::test_memory("group-policy-removal");
  let mut named = config(true);
  named
    .policies
    .push(toml::from_str("name = 'named'").unwrap());
  let first = ResponseCache::new(&named, Some(shared.clone())).unwrap();
  first.initialize_group_activation(None).await.unwrap();
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let uri = Uri::from_static("/removed");
  let headers = HeaderMap::new();
  let old_request = CacheGroupRequest::new(origin);
  let mut lookup = lookup_context(Some(&old_request), &Method::GET, &uri, &headers);
  lookup.policy_name = Some("named");
  assert!(first.bind_group_request(lookup).await);
  let old_generation = first
    .group_authority_read("named")
    .await
    .unwrap()
    .incarnation;

  let removed = reloaded(&config(true), shared.clone(), &first);
  removed
    .initialize_group_activation(Some(&first))
    .await
    .unwrap();
  let retired = shared
    .cache_group_read(&digest(b"named"))
    .await
    .unwrap()
    .unwrap();
  assert!(!Authority::decode(&retired).unwrap().enabled);

  let restored = reloaded(&named, shared, &removed);
  restored
    .initialize_group_activation(Some(&removed))
    .await
    .unwrap();
  assert_ne!(
    restored
      .group_authority_read("named")
      .await
      .unwrap()
      .incarnation,
    old_generation
  );
  let mut insert = insert_context(Some(&old_request), &Method::GET, &uri, &headers);
  insert.policy_name = Some("named");
  assert_eq!(
    restored
      .insert_async(insert, response(Some("\"old\"")))
      .await,
    CacheInsertOutcome::NotCacheable
  );
}
