use super::*;

#[test]
fn indexed_lookup_preserves_vary_variants_and_purge() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let mut english_request = HeaderMap::new();
  english_request.insert("accept-language", HeaderValue::from_static("en"));
  let mut french_request = HeaderMap::new();
  french_request.insert("accept-language", HeaderValue::from_static("fr"));
  let mut response_headers = HeaderMap::new();
  response_headers.insert(VARY, HeaderValue::from_static("accept-language"));

  for (request_headers, body) in [
    (&english_request, Bytes::from_static(b"hello")),
    (&french_request, Bytes::from_static(b"bonjour")),
  ] {
    assert_eq!(
      cache.insert(
        CacheInsertContext {
          policy_name: Some("default"),
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri: &uri,
          request_headers,
        },
        CacheEntry::memory(StatusCode::OK, response_headers.clone(), body),
      ),
      CacheInsertOutcome::Stored
    );
  }

  for (request_headers, expected) in [
    (&english_request, b"hello".as_slice()),
    (&french_request, b"bonjour".as_slice()),
  ] {
    match cache.lookup(CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers,
    }) {
      Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body.as_ref(), expected),
      other => panic!("expected indexed cache hit, got {other:?}"),
    }
  }

  assert_eq!(
    cache.purge_exact("default", "https", "example.test", "/asset/app.css"),
    2
  );
  assert!(
    cache
      .lookup(CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &english_request,
      })
      .is_none()
  );
}

#[test]
fn vary_variant_count_updates_after_replace_and_purge() {
  let config = CacheConfig {
    enabled: true,
    max_vary_variants_per_key: 1,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(VARY, HeaderValue::from_static("X-Variant"));
  response_headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  let mut first_headers = HeaderMap::new();
  first_headers.insert("x-variant", HeaderValue::from_static("a"));
  let mut second_headers = HeaderMap::new();
  second_headers.insert("x-variant", HeaderValue::from_static("b"));

  for body in [Bytes::from_static(b"a1"), Bytes::from_static(b"a2")] {
    assert_eq!(
      cache.insert(
        CacheInsertContext {
          policy_name: Some("default"),
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri: &uri,
          request_headers: &first_headers,
        },
        CacheEntry::memory(StatusCode::OK, response_headers.clone(), body),
      ),
      CacheInsertOutcome::Stored
    );
  }
  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &second_headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers.clone(),
        Bytes::from_static(b"b")
      ),
    ),
    CacheInsertOutcome::Rejected
  );

  assert_eq!(
    cache.purge_exact("default", "https", "example.test", "/asset/app.css"),
    1
  );
  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &second_headers,
      },
      CacheEntry::memory(StatusCode::OK, response_headers, Bytes::from_static(b"b")),
    ),
    CacheInsertOutcome::Stored
  );
}

#[test]
fn vary_variant_count_updates_after_eviction() {
  let config = CacheConfig {
    enabled: true,
    max_size_bytes: 96,
    memory_max_size_bytes: Some(96),
    max_vary_variants_per_key: 1,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let filler_uri = "/asset/filler.css".parse::<Uri>().unwrap();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(VARY, HeaderValue::from_static("X-Variant"));
  response_headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  let mut first_headers = HeaderMap::new();
  first_headers.insert("x-variant", HeaderValue::from_static("a"));
  let mut second_headers = HeaderMap::new();
  second_headers.insert("x-variant", HeaderValue::from_static("b"));
  let request_headers = HeaderMap::new();

  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &first_headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers.clone(),
        Bytes::from(vec![b'a'; 20])
      ),
    ),
    CacheInsertOutcome::Stored
  );
  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &filler_uri,
        request_headers: &request_headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        HeaderMap::new(),
        Bytes::from(vec![b'f'; 80])
      ),
    ),
    CacheInsertOutcome::Stored
  );
  assert!(
    cache
      .lookup(CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &first_headers,
      })
      .is_none()
  );
  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &second_headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers,
        Bytes::from(vec![b'b'; 20])
      ),
    ),
    CacheInsertOutcome::Stored
  );
}

#[test]
fn response_head_decision_rejects_uncacheable_or_unadmitted_heads() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      admission: CacheAdmissionConfig {
        content_types: vec!["text/css".to_string()],
        max_body_bytes: 4,
        ..CacheAdmissionConfig::default()
      },
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();
  let ctx = CacheInsertContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  };
  let mut no_store = HeaderMap::new();
  no_store.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
  assert_eq!(
    cache.response_head_decision(ctx.clone(), StatusCode::OK, &no_store, Some(4)),
    CacheResponseHeadDecision::NotCacheable
  );

  let mut wrong_type = HeaderMap::new();
  wrong_type.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
  assert_eq!(
    cache.response_head_decision(ctx.clone(), StatusCode::OK, &wrong_type, Some(4)),
    CacheResponseHeadDecision::Rejected
  );

  let mut too_large = HeaderMap::new();
  too_large.insert(CONTENT_TYPE, HeaderValue::from_static("text/css"));
  assert_eq!(
    cache.response_head_decision(ctx, StatusCode::OK, &too_large, Some(5)),
    CacheResponseHeadDecision::Rejected
  );
}
