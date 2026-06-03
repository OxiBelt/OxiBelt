use super::*;
use http::header::{
  CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, EXPIRES, HeaderValue, IF_NONE_MATCH, PRAGMA,
  RANGE,
};

#[test]
fn range_entry_returns_multipart_body() {
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_LENGTH, HeaderValue::from_static("10"));
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  let entry = CacheEntry::memory(StatusCode::OK, headers, Bytes::from_static(b"0123456789"));
  let mut request_headers = HeaderMap::new();
  request_headers.insert(RANGE, HeaderValue::from_static("bytes=0-1,8-"));

  let entry = range_entry(entry, &Method::GET, &request_headers);

  assert_eq!(entry.status, StatusCode::PARTIAL_CONTENT);
  assert!(entry.body_file.is_none());
  assert!(
    entry
      .headers
      .get(CONTENT_TYPE)
      .unwrap()
      .to_str()
      .unwrap()
      .starts_with("multipart/byteranges; boundary=")
  );
  let body = std::str::from_utf8(&entry.body).unwrap();
  assert!(body.contains("Content-Range: bytes 0-1/10"));
  assert!(body.contains("01"));
  assert!(body.contains("Content-Range: bytes 8-9/10"));
  assert!(body.contains("89"));
}

#[test]
fn excessive_multi_range_count_is_ignored() {
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_LENGTH, HeaderValue::from_static("10"));
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  let entry = CacheEntry::memory(StatusCode::OK, headers, Bytes::from_static(b"0123456789"));
  let mut request_headers = HeaderMap::new();
  let ranges = (0..17).map(|_| "0-0").collect::<Vec<_>>().join(",");
  request_headers.insert(
    RANGE,
    HeaderValue::from_str(&format!("bytes={ranges}")).unwrap(),
  );

  let entry = range_entry(entry, &Method::GET, &request_headers);

  assert_eq!(entry.status, StatusCode::OK);
  assert_eq!(entry.body, Bytes::from_static(b"0123456789"));
  assert!(!entry.headers.contains_key("content-range"));
  assert_eq!(entry.headers.get(CONTENT_TYPE).unwrap(), "text/plain");
}

#[test]
fn excessive_multi_range_payload_is_ignored() {
  let body_len = 4 * 1024 * 1024 + 1;
  let body = Bytes::from(vec![b'R'; body_len]);
  let mut headers = HeaderMap::new();
  headers.insert(
    CONTENT_LENGTH,
    HeaderValue::from_str(&body_len.to_string()).unwrap(),
  );
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  let entry = CacheEntry::memory(StatusCode::OK, headers, body.clone());
  let mut request_headers = HeaderMap::new();
  request_headers.insert(
    RANGE,
    HeaderValue::from_str(&format!("bytes=0-{},0-{}", body_len - 1, body_len - 1)).unwrap(),
  );

  let entry = range_entry(entry, &Method::GET, &request_headers);

  assert_eq!(entry.status, StatusCode::OK);
  assert_eq!(entry.body.len(), body_len);
  assert_eq!(entry.body, body);
  assert_eq!(entry.headers.get(CONTENT_TYPE).unwrap(), "text/plain");
}

#[test]
fn if_range_mismatch_serves_full_cached_body() {
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_LENGTH, HeaderValue::from_static("10"));
  headers.insert(ETAG, HeaderValue::from_static("\"v1\""));
  let entry = CacheEntry::memory(StatusCode::OK, headers, Bytes::from_static(b"0123456789"));
  let mut request_headers = HeaderMap::new();
  request_headers.insert(RANGE, HeaderValue::from_static("bytes=2-5"));
  request_headers.insert("if-range", HeaderValue::from_static("\"v2\""));

  let entry = range_entry(entry, &Method::GET, &request_headers);

  assert_eq!(entry.status, StatusCode::OK);
  assert_eq!(entry.body, Bytes::from_static(b"0123456789"));
}

#[test]
fn head_can_read_get_cache_but_head_miss_does_not_store() {
  let config = CacheConfig {
    enabled: true,
    cache_methods: vec!["GET".to_string()],
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let get_uri = "/asset/head.css".parse::<Uri>().unwrap();
  let head_uri = "/asset/head-miss.css".parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );

  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &get_uri,
        request_headers: &request_headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers.clone(),
        Bytes::from_static(b"head-safe"),
      ),
    ),
    CacheInsertOutcome::Stored
  );

  match cache.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::HEAD,
    uri: &get_uri,
    request_headers: &request_headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body, Bytes::from_static(b"head-safe")),
    other => panic!("expected HEAD lookup to reuse GET entry, got {other:?}"),
  }

  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::HEAD,
        uri: &head_uri,
        request_headers: &request_headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers,
        Bytes::from_static(b"poison"),
      ),
    ),
    CacheInsertOutcome::NotCacheable
  );
  assert!(
    cache
      .lookup(CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &head_uri,
        request_headers: &request_headers,
      })
      .is_none()
  );
}

#[test]
fn rfc9111_freshness_directives_are_stable() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/freshness.css".parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();

  for (name, cache_control, expires, expected) in [
    (
      "s-maxage beats zero max-age",
      Some("public, max-age=0, s-maxage=60"),
      None,
      CacheResponseHeadDecision::Cacheable,
    ),
    (
      "zero max-age rejects storage",
      Some("public, max-age=0"),
      None,
      CacheResponseHeadDecision::NotCacheable,
    ),
    (
      "no-cache stores as must-revalidate",
      Some("public, no-cache, max-age=60"),
      None,
      CacheResponseHeadDecision::Cacheable,
    ),
    (
      "proxy-revalidate stores as must-revalidate",
      Some("public, proxy-revalidate, max-age=60"),
      None,
      CacheResponseHeadDecision::Cacheable,
    ),
    (
      "past expires rejects storage",
      None,
      Some("Tue, 01 Jan 1980 00:00:00 GMT"),
      CacheResponseHeadDecision::NotCacheable,
    ),
  ] {
    let mut response_headers = HeaderMap::new();
    if let Some(cache_control) = cache_control {
      response_headers.insert(CACHE_CONTROL, HeaderValue::from_static(cache_control));
    }
    if let Some(expires) = expires {
      response_headers.insert(EXPIRES, HeaderValue::from_static(expires));
    }

    assert_eq!(
      cache.response_head_decision(
        CacheInsertContext {
          policy_name: Some("default"),
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri: &uri,
          request_headers: &request_headers,
        },
        StatusCode::OK,
        &response_headers,
        None,
      ),
      expected,
      "{name}"
    );
  }
}

#[test]
fn pragma_no_cache_request_revalidates_fresh_entry() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/pragma.css".parse::<Uri>().unwrap();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  response_headers.insert(ETAG, HeaderValue::from_static("\"v1\""));

  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &HeaderMap::new(),
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers,
        Bytes::from_static(b"fresh"),
      ),
    ),
    CacheInsertOutcome::Stored
  );

  let mut request_headers = HeaderMap::new();
  request_headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
  match cache.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  }) {
    Some(CacheLookup::Revalidate(revalidation)) => {
      assert_eq!(
        revalidation.request_headers.get(IF_NONE_MATCH).unwrap(),
        "\"v1\"",
      );
    }
    other => panic!("expected pragma no-cache revalidation, got {other:?}"),
  }
}
