use super::super::body::ProxyBody;
use super::*;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderValue, IF_NONE_MATCH};
use pretty_assertions::assert_eq;
use std::time::{Duration, SystemTime};

async fn wait_for_fresh_cache_entry(
  state: &AppSnapshot,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
  request_headers: &HeaderMap,
) -> crate::cache::CacheEntry {
  for _ in 0..50 {
    if let Some(crate::cache::CacheLookup::Fresh(entry)) =
      state.cache.lookup(crate::cache::CacheLookupContext {
        policy_name: Some("default"),
        scheme,
        host,
        method,
        uri,
        request_headers,
      })
    {
      return entry;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  panic!("expected fresh cache entry");
}

#[tokio::test]
async fn cached_entry_response_handles_conditional_hit_with_age() {
  let mut headers = HeaderMap::new();
  headers.insert(ETAG, HeaderValue::from_static("\"v1\""));
  let entry = crate::cache::CacheEntry::memory(
    StatusCode::OK,
    headers,
    bytes::Bytes::from_static(b"cached body"),
  )
  .with_stored_at(SystemTime::now() - Duration::from_secs(2));
  let mut request_headers = HeaderMap::new();
  request_headers.insert(IF_NONE_MATCH, HeaderValue::from_static("\"v1\""));

  let response =
    super::super::cache_status::cached_entry_response(entry, &Method::GET, &request_headers);

  assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
  assert!(
    response
      .headers()
      .get("age")
      .and_then(|value| value.to_str().ok())
      .and_then(|value| value.parse::<u64>().ok())
      .is_some_and(|age| age >= 2)
  );
  let body = response
    .into_body()
    .collect()
    .await
    .expect("304 body should collect")
    .to_bytes();
  assert!(body.is_empty());
}

#[tokio::test]
async fn cache_fill_streams_large_disk_body_and_serves_file_backed_ranges() {
  let temp_dir = common::TempDir::new("cache-fill-streaming-disk");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-fill-streaming-disk");
  let raw = format!(
    r#"
{}

[proxy.buffering]
max_memory_body_bytes = 16

[cache]
enabled = true
store = "disk"
disk_dir = "{}"
max_size_bytes = 4096
disk_max_size_bytes = 4096
default_ttl_seconds = 60
cache_methods = ["GET"]
respect_cache_control = true
stream_large_objects = true
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    temp_dir.path().display()
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let method = Method::GET;
  let uri: http::Uri = "/large-disk?item=1".parse().expect("URI should parse");
  let request_headers = HeaderMap::new();
  let body = bytes::Bytes::from(vec![b'D'; 96]);
  let mut response = Response::new(full_body(body.clone()));
  response.headers_mut().insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  response
    .headers_mut()
    .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));

  let response = maybe_cache_response(
    response,
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &uri,
    &request_headers,
    None,
  )
  .await;

  assert_cache_status(&response, "miss", "stored");
  let delivered = response
    .into_body()
    .collect()
    .await
    .expect("streaming response body should collect")
    .to_bytes();
  assert_eq!(delivered, body);

  let entry = wait_for_fresh_cache_entry(
    &state,
    "https",
    "example.com",
    &method,
    &uri,
    &request_headers,
  )
  .await;
  assert!(entry.body_file.is_some());
  assert_eq!(state.cache.stats().disk_entries, 1);

  let mut single_range_headers = HeaderMap::new();
  single_range_headers.insert("range", HeaderValue::from_static("bytes=4-9"));
  let response = super::super::cache_status::cached_entry_response(
    entry.clone(),
    &method,
    &single_range_headers,
  );
  assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
  assert_eq!(
    response.headers().get("content-range").unwrap(),
    "bytes 4-9/96"
  );
  let single_range = response
    .into_body()
    .collect()
    .await
    .expect("single range cached body should collect")
    .to_bytes();
  assert_eq!(single_range, bytes::Bytes::from_static(b"DDDDDD"));

  let mut range_headers = HeaderMap::new();
  range_headers.insert("range", HeaderValue::from_static("bytes=0-1,94-95"));
  let response = super::super::cache_status::cached_entry_response(entry, &method, &range_headers);
  assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
  assert!(
    response
      .headers()
      .get(CONTENT_TYPE)
      .unwrap()
      .to_str()
      .unwrap()
      .starts_with("multipart/byteranges; boundary=")
  );
  let multipart = response
    .into_body()
    .collect()
    .await
    .expect("multipart cached body should collect")
    .to_bytes();
  let multipart = std::str::from_utf8(&multipart).expect("multipart body should be utf-8");
  assert!(multipart.contains("Content-Range: bytes 0-1/96"));
  assert!(multipart.contains("Content-Range: bytes 94-95/96"));
}

#[tokio::test]
async fn streaming_fill_reserves_disk_budget_for_inflight_files() {
  let temp_dir = common::TempDir::new("cache-fill-streaming-disk-reservation");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-fill-streaming-disk-reservation");
  let raw = format!(
    r#"
{}

[proxy.buffering]
max_memory_body_bytes = 16

[cache]
enabled = true
store = "disk"
disk_dir = "{}"
max_size_bytes = 256
disk_max_size_bytes = 256
default_ttl_seconds = 60
cache_methods = ["GET"]
respect_cache_control = true
stream_large_objects = true
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    temp_dir.path().display()
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let method = Method::GET;
  let request_headers = HeaderMap::new();
  let first_uri: http::Uri = "/large-disk-reserve-a".parse().expect("URI should parse");
  let second_uri: http::Uri = "/large-disk-reserve-b".parse().expect("URI should parse");
  let first_body = bytes::Bytes::from(vec![b'A'; 96]);
  let second_body = bytes::Bytes::from(vec![b'B'; 96]);

  let first_response = maybe_cache_response(
    cacheable_streaming_response(first_body.clone()),
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &first_uri,
    &request_headers,
    None,
  )
  .await;
  assert_cache_status(&first_response, "miss", "stored");

  let second_response = maybe_cache_response(
    cacheable_streaming_response(second_body.clone()),
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &second_uri,
    &request_headers,
    None,
  )
  .await;
  assert_cache_status(&second_response, "miss", "admission_rejected");
  let delivered_second = second_response
    .into_body()
    .collect()
    .await
    .expect("rejected streaming response should still forward")
    .to_bytes();
  assert_eq!(delivered_second, second_body);

  let delivered_first = first_response
    .into_body()
    .collect()
    .await
    .expect("reserved streaming response should collect")
    .to_bytes();
  assert_eq!(delivered_first, first_body);
  wait_for_fresh_cache_entry(
    &state,
    "https",
    "example.com",
    &method,
    &first_uri,
    &request_headers,
  )
  .await;
  assert!(
    state
      .cache
      .lookup(crate::cache::CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.com",
        method: &method,
        uri: &second_uri,
        request_headers: &request_headers,
      })
      .is_none()
  );
  assert_eq!(state.cache.stats().disk_entries, 1);
}

#[tokio::test]
async fn dropped_streaming_fill_releases_disk_reservation() {
  let temp_dir = common::TempDir::new("cache-fill-streaming-disk-release");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-fill-streaming-disk-release");
  let raw = format!(
    r#"
{}

[proxy.buffering]
max_memory_body_bytes = 16

[cache]
enabled = true
store = "disk"
disk_dir = "{}"
max_size_bytes = 256
disk_max_size_bytes = 256
default_ttl_seconds = 60
cache_methods = ["GET"]
respect_cache_control = true
stream_large_objects = true
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    temp_dir.path().display()
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let method = Method::GET;
  let request_headers = HeaderMap::new();
  let dropped_uri: http::Uri = "/large-disk-drop".parse().expect("URI should parse");
  let response = maybe_cache_response(
    cacheable_streaming_response(bytes::Bytes::from(vec![b'D'; 96])),
    &state,
    Some("default"),
    "https",
    "example.com",
    &method,
    &dropped_uri,
    &request_headers,
    None,
  )
  .await;
  assert_cache_status(&response, "miss", "stored");
  drop(response);

  for attempt in 0..50 {
    let uri: http::Uri = format!("/large-disk-after-drop-{attempt}")
      .parse()
      .expect("URI should parse");
    let body = bytes::Bytes::from(vec![b'R'; 96]);
    let response = maybe_cache_response(
      cacheable_streaming_response(body.clone()),
      &state,
      Some("default"),
      "https",
      "example.com",
      &method,
      &uri,
      &request_headers,
      None,
    )
    .await;
    let stored = response
      .headers()
      .get("x-oxibelt-cache-reason")
      .is_some_and(|value| value == "stored");
    let delivered = response
      .into_body()
      .collect()
      .await
      .expect("streaming response should forward")
      .to_bytes();
    assert_eq!(delivered, body);
    if stored {
      wait_for_fresh_cache_entry(
        &state,
        "https",
        "example.com",
        &method,
        &uri,
        &request_headers,
      )
      .await;
      return;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  panic!("expected dropped streaming fill to release disk reservation");
}

#[tokio::test]
async fn missing_file_backed_body_fails_closed() {
  let temp_dir = common::TempDir::new("cache-file-missing-fails-closed");
  let missing_path = temp_dir.path().join("missing.body");
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_LENGTH, HeaderValue::from_static("128"));
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  let entry = crate::cache::CacheEntry::file(
    StatusCode::OK,
    headers,
    missing_path,
    128,
    SystemTime::now(),
  );

  let response =
    super::super::cache_status::cached_entry_response(entry, &Method::GET, &HeaderMap::new());

  assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
  assert_cache_status(&response, "miss", "store_failed");
  assert_ne!(response.headers().get(CONTENT_LENGTH).unwrap(), "128");
  let body = response
    .into_body()
    .collect()
    .await
    .expect("fail-closed response body should collect")
    .to_bytes();
  assert_eq!(
    body,
    bytes::Bytes::from_static(b"cached response body is unavailable")
  );
}

fn cacheable_streaming_response(body: bytes::Bytes) -> Response<ProxyBody> {
  let mut response = Response::new(full_body(body));
  response.headers_mut().insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  response
    .headers_mut()
    .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  response
}
