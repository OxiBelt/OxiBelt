use super::external_handler::{
  CACHE_KEY_VERSION, ExternalCacheBody, ExternalCacheEntryMetadata, ExternalCacheHeader,
  ExternalCacheLookupHit, ExternalCacheVary, PROTOCOL_VERSION,
};
use super::*;
use http::header::AUTHORIZATION;

fn cache_with_external_handler() -> Arc<ResponseCache> {
  ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      external_handler: Some("massive".to_string()),
      ..CacheConfig::default()
    },
    None,
  )
  .expect("cache should build")
}

fn external_hit(
  operation: &CacheOperationContext,
  body: Bytes,
  uri: &str,
  vary: Vec<ExternalCacheVary>,
) -> ExternalCacheLookupHit {
  let now = SystemTime::now();
  let vary_matchers = vary
    .iter()
    .map(|item| VaryMatcher {
      name: item.name.to_ascii_lowercase(),
      value: item.value.clone(),
    })
    .collect::<Vec<_>>();
  ExternalCacheLookupHit {
    metadata: ExternalCacheEntryMetadata {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: CACHE_KEY_VERSION.to_string(),
      policy: operation.policy.name.clone(),
      partition: operation.partition.clone(),
      base_key: operation.base_key.clone(),
      variant_key: variant_key(&operation.partition, &operation.base_key, &vary_matchers),
      scheme: operation.scheme.clone(),
      host: operation.host.clone(),
      uri: uri.to_string(),
      status: StatusCode::OK.as_u16(),
      headers: vec![ExternalCacheHeader::new(
        "cache-control".to_string(),
        b"public, max-age=60",
      )],
      security_headers_neutral: true,
      body_len: body.len(),
      stored_at_ms: system_time_ms(now),
      expires_at_ms: system_time_ms(now + Duration::from_secs(60)),
      stale_if_error_until_ms: None,
      stale_while_revalidate_until_ms: None,
      must_revalidate: false,
      vary,
      tags: Vec::new(),
      query_target_epoch: None,
      no_vary_search: None,
      group_stamp: None,
      capabilities: Vec::new(),
    },
    body: ExternalCacheBody::Memory(body),
  }
}

#[test]
fn external_memory_hit_is_promoted_after_validation() {
  let cache = cache_with_external_handler();
  let uri = "/asset.css".parse::<Uri>().expect("uri should parse");
  let request_headers = HeaderMap::new();
  let ctx = CacheLookupContext {
    group_request: None,
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
    query_identity: None,
    certificate_identity: None,
  };
  let operation = cache
    .operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
      ctx.query_identity,
      ctx.certificate_identity,
      ctx.proxy_protocol_identity,
      ctx.group_request,
    )
    .expect("operation context should build");

  let hit = external_hit(
    &operation,
    Bytes::from_static(b"body"),
    "/asset.css",
    Vec::new(),
  );
  let lookup = cache
    .external_lookup_result(operation, ctx.clone(), hit)
    .expect("external hit should validate");

  match lookup {
    CacheLookup::Fresh(entry) => assert_eq!(entry.body, Bytes::from_static(b"body")),
    other => panic!("expected fresh external hit, got {other:?}"),
  }
  match cache.lookup(ctx) {
    Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body, Bytes::from_static(b"body")),
    other => panic!("expected promoted local hit, got {other:?}"),
  }
}

#[test]
fn external_memory_hit_without_security_neutral_marker_is_safe_miss() {
  let cache = cache_with_external_handler();
  let uri = "/asset.css".parse::<Uri>().expect("uri should parse");
  let request_headers = HeaderMap::new();
  let ctx = CacheLookupContext {
    group_request: None,
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
    query_identity: None,
    certificate_identity: None,
  };
  let operation = cache
    .operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
      ctx.query_identity,
      ctx.certificate_identity,
      ctx.proxy_protocol_identity,
      ctx.group_request,
    )
    .expect("operation context should build");

  let mut hit = external_hit(
    &operation,
    Bytes::from_static(b"body"),
    "/asset.css",
    Vec::new(),
  );
  hit.metadata.security_headers_neutral = false;

  assert!(cache.external_lookup_result(operation, ctx, hit).is_none());
}

#[tokio::test]
async fn external_group_generation_round_trips_and_rejects_a_changed_variant() {
  for (uri_value, membership) in [
    ("/grouped.css", None),
    ("/grouped.css", Some("\"alpha\"")),
    ("https://example.test/grouped.css", None),
    ("https://example.test/grouped.css", Some("\"alpha\"")),
  ] {
    let cache = ResponseCache::new(
      &CacheConfig {
        enabled: true,
        ..CacheConfig::default()
      },
      None,
    )
    .unwrap();
    let uri: Uri = uri_value.parse().unwrap();
    let headers = HeaderMap::new();
    let request =
      CacheGroupRequest::new(CacheGroupOrigin::new("https", "example.test:8443").unwrap());
    let ctx = CacheLookupContext {
      group_request: Some(&request),
      no_vary_search: None,
      proxy_protocol_identity: None,
      policy_name: None,
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &headers,
      query_identity: None,
      certificate_identity: None,
    };
    assert!(cache.bind_group_request(ctx.clone()).await);
    let operation = cache
      .operation_context(
        None,
        "https",
        "example.test",
        &Method::GET,
        &uri,
        &headers,
        None,
        None,
        None,
        Some(&request),
      )
      .unwrap();
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
      CACHE_CONTROL,
      HeaderValue::from_static("public, max-age=60"),
    );
    if let Some(membership) = membership {
      response_headers.insert("cache-groups", HeaderValue::from_str(membership).unwrap());
    }
    let CachePreparedInsertDecision::Cacheable(prepared) = cache.prepare_insert(
      CacheInsertContext {
        group_request: Some(&request),
        no_vary_search: None,
        proxy_protocol_identity: None,
        policy_name: None,
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &headers,
        query_identity: None,
        certificate_identity: None,
      },
      StatusCode::OK,
      &response_headers,
      Some(4),
    ) else {
      panic!("group-aware response should be admitted")
    };
    let mut hit = external_hit(&operation, Bytes::from_static(b"body"), uri_value, vec![]);
    hit.metadata.cache_key_version = key::GROUP_EXTERNAL_CACHE_KEY_VERSION.into();
    hit.metadata.capabilities = vec!["cache-groups-v1".into()];
    hit.metadata.variant_key = prepared.variant_key;
    hit.metadata.group_stamp = prepared.group_stamp;
    let mut wrong = ExternalCacheLookupHit {
      metadata: hit.metadata.clone(),
      body: ExternalCacheBody::Memory(Bytes::from_static(b"body")),
    };
    wrong.metadata.variant_key.push_str("changed");
    assert!(
      cache
        .external_lookup_result(operation.clone(), ctx.clone(), wrong)
        .is_none()
    );
    assert!(matches!(
      cache.external_lookup_result(operation, ctx.clone(), hit),
      Some(CacheLookup::Fresh(_))
    ));
    assert!(matches!(cache.lookup(ctx), Some(CacheLookup::Fresh(_))));
  }
}

#[test]
fn external_mismatched_uri_is_safe_miss() {
  let cache = cache_with_external_handler();
  let uri = "/asset.css".parse::<Uri>().expect("uri should parse");
  let request_headers = HeaderMap::new();
  let ctx = CacheLookupContext {
    group_request: None,
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
    query_identity: None,
    certificate_identity: None,
  };
  let operation = cache
    .operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
      ctx.query_identity,
      ctx.certificate_identity,
      ctx.proxy_protocol_identity,
      ctx.group_request,
    )
    .expect("operation context should build");

  let hit = external_hit(
    &operation,
    Bytes::from_static(b"body"),
    "/other.css",
    Vec::new(),
  );
  assert!(
    cache
      .external_lookup_result(operation, ctx.clone(), hit)
      .is_none()
  );
  assert!(cache.lookup(ctx).is_none());
}

#[test]
fn external_sensitive_vary_is_safe_miss() {
  let cache = cache_with_external_handler();
  let uri = "/asset.css".parse::<Uri>().expect("uri should parse");
  let mut request_headers = HeaderMap::new();
  request_headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
  let ctx = CacheLookupContext {
    group_request: None,
    no_vary_search: None,
    proxy_protocol_identity: None,
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
    query_identity: None,
    certificate_identity: None,
  };
  let operation = cache
    .operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
      ctx.query_identity,
      ctx.certificate_identity,
      ctx.proxy_protocol_identity,
      ctx.group_request,
    )
    .expect("operation context should build");

  let hit = external_hit(
    &operation,
    Bytes::from_static(b"body"),
    "/asset.css",
    vec![ExternalCacheVary {
      name: "authorization".to_string(),
      value: "Bearer secret".to_string(),
    }],
  );
  assert!(cache.external_lookup_result(operation, ctx, hit).is_none());
}

#[test]
fn external_certificate_vary_with_a_value_is_safe_miss() {
  let identity = CacheCertificateIdentity::new(
    "client-cert",
    "rfc9440",
    Some("a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d"),
  )
  .expect("certificate identity should be valid");
  assert!(
    crate::cache::external::external_vary_matchers(
      &[ExternalCacheVary {
        name: "client-cert".to_string(),
        value: "must-not-be-retained".to_string(),
      }],
      Some(&identity),
    )
    .is_none()
  );
}

#[tokio::test]
async fn external_query_cleanup_is_a_best_effort_separate_operation() {
  let cache = cache_with_external_handler();
  assert!(
    cache
      .cleanup_external_query_before_epoch("default", "https", "example.test", "/asset", 7, 128,)
      .await
      .is_none(),
    "a missing runtime handler must not make cleanup behave like an admin purge"
  );
}

#[cfg(feature = "admin-runtime")]
#[tokio::test]
async fn legacy_external_purges_do_not_emit_query_protocol_requests() {
  let cache = cache_with_external_handler();
  assert_eq!(
    cache
      .purge_external_exact_partition("default", "https", "example.test", "/asset", None)
      .await
      .len(),
    1
  );
  assert_eq!(
    cache
      .purge_external_prefix_partition("default", "https", "example.test", "/", None)
      .await
      .len(),
    1
  );
  assert_eq!(
    cache
      .purge_external_tag_partition("default", "tag", None, None, None)
      .await
      .len(),
    1
  );
}
