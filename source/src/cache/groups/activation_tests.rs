use std::sync::Arc;

use super::model::{AUTHORITY_VERSION, Authority, LEGACY_AUTHORITY_VERSION, digest};
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
async fn activation_rotates_a_legacy_shared_authority_exactly_once() {
  let shared = crate::shared_state::SharedState::test_memory("group-activation-v1-migration");
  let mut legacy = Authority::new("a".repeat(64));
  legacy.version = LEGACY_AUTHORITY_VERSION;
  let key = digest(b"default");
  assert!(
    shared
      .cache_group_compare_exchange(&key, None, &serde_json::to_vec(&legacy).unwrap())
      .await
      .unwrap()
  );

  let cache = ResponseCache::new(&config(true), Some(shared)).unwrap();
  assert!(cache.group_authority_read("default").await.is_err());
  cache.initialize_group_activation(None).await.unwrap();
  let migrated = cache.group_authority_read("default").await.unwrap();
  assert_eq!(migrated.version, AUTHORITY_VERSION);
  assert_ne!(migrated.incarnation, legacy.incarnation);

  cache.initialize_group_activation(None).await.unwrap();
  assert_eq!(
    cache
      .group_authority_read("default")
      .await
      .unwrap()
      .incarnation,
    migrated.incarnation
  );
}

#[test]
fn startup_rotates_a_legacy_local_authority_in_place() {
  let directory = tempfile::tempdir().unwrap();
  let mut cache_config = config(true);
  cache_config.store = crate::config::CacheStore::Disk;
  cache_config.disk_dir = Some(directory.path().to_path_buf());
  let mut legacy = Authority::new("a".repeat(64));
  legacy.version = LEGACY_AUTHORITY_VERSION;
  let path = directory
    .path()
    .join(format!(".oxibelt-groups-{}-v1", digest(b"default")));
  std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();

  let cache = ResponseCache::new(&cache_config, None).unwrap();
  let migrated = cache.groups.local_read("default").unwrap();
  assert_eq!(migrated.version, AUTHORITY_VERSION);
  assert_ne!(migrated.incarnation, legacy.incarnation);
  assert_eq!(
    Authority::decode(&std::fs::read(path).unwrap())
      .unwrap()
      .incarnation,
    migrated.incarnation
  );
}

#[tokio::test]
async fn disk_entry_from_a_legacy_authority_cold_misses_after_rotation() {
  let directory = tempfile::tempdir().unwrap();
  let mut cache_config = config(true);
  cache_config.store = crate::config::CacheStore::Disk;
  cache_config.disk_dir = Some(directory.path().to_path_buf());
  let cache = ResponseCache::new(&cache_config, None).unwrap();
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let uri = Uri::from_static("/legacy-disk");
  let headers = HeaderMap::new();
  let fill = request(&cache, origin.clone(), &Method::GET, &uri, &headers).await;
  assert_eq!(
    cache
      .insert_async(
        insert_context(Some(&fill), &Method::GET, &uri, &headers),
        response(Some("\"legacy\"")),
      )
      .await,
    CacheInsertOutcome::Stored
  );
  let mut legacy = cache.groups.local_read("default").unwrap();
  legacy.version = LEGACY_AUTHORITY_VERSION;
  let old_incarnation = legacy.incarnation.clone();
  drop(cache);
  let authority_path = directory
    .path()
    .join(format!(".oxibelt-groups-{}-v1", digest(b"default")));
  std::fs::write(&authority_path, serde_json::to_vec(&legacy).unwrap()).unwrap();

  let migrated = ResponseCache::new(&cache_config, None).unwrap();
  assert_ne!(
    migrated.groups.local_read("default").unwrap().incarnation,
    old_incarnation
  );
  let lookup = request(&migrated, origin, &Method::GET, &uri, &headers).await;
  assert!(
    migrated
      .lookup_async(lookup_context(Some(&lookup), &Method::GET, &uri, &headers))
      .await
      .is_none()
  );
}

#[tokio::test]
async fn shared_entry_from_a_legacy_authority_cold_misses_after_rotation() {
  let shared = crate::shared_state::SharedState::test_memory("group-v1-entry-migration");
  let cache_config = config(true);
  let first = ResponseCache::new(&cache_config, Some(shared.clone())).unwrap();
  first.initialize_group_activation(None).await.unwrap();
  let origin = CacheGroupOrigin::new("https", "cache.example.test").unwrap();
  let uri = Uri::from_static("/legacy-shared");
  let headers = HeaderMap::new();
  let fill = request(&first, origin.clone(), &Method::GET, &uri, &headers).await;
  assert_eq!(
    first
      .insert_async(
        insert_context(Some(&fill), &Method::GET, &uri, &headers),
        response(Some("\"legacy\"")),
      )
      .await,
    CacheInsertOutcome::Stored
  );
  let current = first.group_authority_read("default").await.unwrap();
  let mut legacy = current.clone();
  legacy.version = LEGACY_AUTHORITY_VERSION;
  let key = digest(b"default");
  assert!(
    shared
      .cache_group_compare_exchange(
        &key,
        Some(&current.encode().unwrap()),
        &serde_json::to_vec(&legacy).unwrap(),
      )
      .await
      .unwrap()
  );
  assert!(first.group_authority_read("default").await.is_err());

  let migrated = ResponseCache::new(&cache_config, Some(shared)).unwrap();
  migrated.initialize_group_activation(None).await.unwrap();
  assert_ne!(
    migrated
      .group_authority_read("default")
      .await
      .unwrap()
      .incarnation,
    current.incarnation
  );
  let lookup = request(&migrated, origin, &Method::GET, &uri, &headers).await;
  assert!(
    migrated
      .lookup_async(lookup_context(Some(&lookup), &Method::GET, &uri, &headers))
      .await
      .is_none()
  );
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
