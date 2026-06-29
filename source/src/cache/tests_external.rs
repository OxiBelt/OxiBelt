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
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  };
  let operation = cache
    .operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
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
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  };
  let operation = cache
    .operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
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

#[test]
fn external_mismatched_uri_is_safe_miss() {
  let cache = cache_with_external_handler();
  let uri = "/asset.css".parse::<Uri>().expect("uri should parse");
  let request_headers = HeaderMap::new();
  let ctx = CacheLookupContext {
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  };
  let operation = cache
    .operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
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
    policy_name: None,
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  };
  let operation = cache
    .operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
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
