use super::*;
use http::header::{
  CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, HeaderName, HeaderValue, RANGE,
  VARY,
};

#[test]
fn cache_key_expands_dynamic_tokens() {
  let uri = "/asset/app.css?v=1&lang=en".parse::<Uri>().unwrap();
  let mut headers = HeaderMap::new();
  headers.insert("accept-language", HeaderValue::from_static("en-US"));
  headers.insert(
    "cookie",
    HeaderValue::from_static("session=abc; theme=dark"),
  );
  let key = expanded_cache_key(
    "{scheme}:{host}:{path}:{query:v}:{header:Accept-Language}:{cookie:theme}",
    "https",
    "example.test",
    &uri,
    &headers,
  );
  assert_eq!(key, "https:example.test:/asset/app.css:1:en-US:dark");
}

#[test]
fn range_entry_returns_partial_body() {
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_LENGTH, HeaderValue::from_static("10"));
  let entry = CacheEntry::memory(StatusCode::OK, headers, Bytes::from_static(b"0123456789"));
  let mut request_headers = HeaderMap::new();
  request_headers.insert(RANGE, HeaderValue::from_static("bytes=2-5"));
  let entry = range_entry(entry, &Method::GET, &request_headers);
  assert_eq!(entry.status, StatusCode::PARTIAL_CONTENT);
  assert_eq!(entry.body, Bytes::from_static(b"2345"));
  assert_eq!(entry.headers.get(CONTENT_RANGE).unwrap(), "bytes 2-5/10");
}

#[test]
fn surrogate_control_overrides_origin_cache_control_and_strips_header() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
  response_headers.insert(
    HeaderName::from_static(SURROGATE_CONTROL_HEADER),
    HeaderValue::from_static("max-age=60"),
  );

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
        Bytes::from_static(b"surrogate")
      ),
    ),
    CacheInsertOutcome::Stored
  );

  match cache.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &HeaderMap::new(),
  }) {
    Some(CacheLookup::Fresh(entry)) => {
      assert_eq!(entry.body, Bytes::from_static(b"surrogate"));
      assert!(!entry.headers.contains_key(SURROGATE_CONTROL_HEADER));
    }
    other => panic!("expected surrogate cache hit, got {other:?}"),
  }
}

#[test]
fn cache_key_explain_includes_partition_and_variant() {
  let config = CacheConfig {
    enabled: true,
    partition_key: "{header:X-Tenant-ID}".to_string(),
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css?v=1".parse::<Uri>().unwrap();
  let mut request_headers = HeaderMap::new();
  request_headers.insert("x-tenant-id", HeaderValue::from_static("tenant-a"));
  request_headers.insert("accept-language", HeaderValue::from_static("en-US"));
  let mut response_headers = HeaderMap::new();
  response_headers.insert(VARY, HeaderValue::from_static("Accept-Language"));

  let explain = cache.explain_key(
    CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &request_headers,
    },
    Some(&response_headers),
  );

  assert_eq!(explain.partition, "tenant-a");
  assert_eq!(explain.base_key, "https:example.test:/asset/app.css?v=1");
  assert_eq!(explain.vary_fields, vec!["accept-language"]);
  assert!(
    explain
      .variant_key
      .as_deref()
      .is_some_and(|key| key.contains("partition=tenant-a"))
  );
}

#[test]
fn cache_key_explain_reports_vary_rejection_reason() {
  let config = CacheConfig {
    enabled: true,
    max_vary_fields: 1,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(VARY, HeaderValue::from_static("Accept-Language, X-Variant"));

  let explain = cache.explain_key(
    CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &request_headers,
    },
    Some(&response_headers),
  );

  assert!(explain.variant_key.is_none());
  assert_eq!(explain.reasons, vec!["too many Vary fields"]);
}

#[test]
fn vary_variant_cap_rejects_exploding_variants() {
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
        Bytes::from_static(b"a")
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
        uri: &uri,
        request_headers: &second_headers,
      },
      CacheEntry::memory(StatusCode::OK, response_headers, Bytes::from_static(b"b")),
    ),
    CacheInsertOutcome::Rejected
  );
}

#[test]
fn encoded_response_without_accept_encoding_vary_is_not_cacheable() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
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
        uri: &uri,
        request_headers: &HeaderMap::new(),
      },
      CacheEntry::memory(StatusCode::OK, response_headers, Bytes::from_static(b"gz")),
    ),
    CacheInsertOutcome::NotCacheable
  );

  let mut response_headers = HeaderMap::new();
  response_headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
  response_headers.insert(VARY, HeaderValue::from_static("Accept-Encoding"));
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
        uri: &uri,
        request_headers: &HeaderMap::new(),
      },
      CacheEntry::memory(StatusCode::OK, response_headers, Bytes::from_static(b"gz")),
    ),
    CacheInsertOutcome::Stored
  );
}

#[test]
fn cookie_requests_bypass_cache_by_default() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/profile".parse::<Uri>().unwrap();
  let mut request_headers = HeaderMap::new();
  request_headers.insert(
    http::header::COOKIE,
    HeaderValue::from_static("session=secret"),
  );

  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &request_headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        HeaderMap::new(),
        Bytes::from_static(b"profile")
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
        uri: &uri,
        request_headers: &request_headers,
      })
      .is_none()
  );
}

#[test]
fn named_policy_can_define_negative_cache_defaults() {
  let config = CacheConfig {
    enabled: true,
    policies: vec![test_cache_policy_with_negative_status()],
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/missing".parse::<Uri>().unwrap();

  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("negative"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &HeaderMap::new(),
      },
      CacheEntry::memory(
        StatusCode::NOT_FOUND,
        HeaderMap::new(),
        Bytes::from_static(b"missing")
      ),
    ),
    CacheInsertOutcome::Stored
  );
  assert!(matches!(
    cache.lookup(CacheLookupContext {
      policy_name: Some("negative"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &HeaderMap::new(),
    }),
    Some(CacheLookup::Fresh(_))
  ));
}

#[test]
fn disk_cache_replacement_preserves_new_body() {
  let temp_dir = TestTempDir::new();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(temp_dir.path.clone()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };

  assert_file_backed_replacement_preserves_new_body(config, &temp_dir.path);
}

#[test]
fn memory_then_disk_replacement_preserves_new_body_after_disk_fallback() {
  let temp_dir = TestTempDir::new();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::MemoryThenDisk,
    memory_max_size_bytes: Some(1),
    disk_dir: Some(temp_dir.path.clone()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };

  assert_file_backed_replacement_preserves_new_body(config, &temp_dir.path);
}

fn assert_file_backed_replacement_preserves_new_body(config: CacheConfig, disk_dir: &Path) {
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );

  for body in [
    Bytes::from_static(b"first-body"),
    Bytes::from_static(b"second-body"),
  ] {
    assert_eq!(
      cache.insert(
        CacheInsertContext {
          policy_name: Some("default"),
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri: &uri,
          request_headers: &request_headers,
        },
        CacheEntry::memory(StatusCode::OK, response_headers.clone(), body),
      ),
      CacheInsertOutcome::Stored
    );
  }

  match cache.lookup(CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &request_headers,
  }) {
    Some(CacheLookup::Fresh(entry)) => {
      let body = if let Some(file) = entry.body_file {
        std::fs::read(file.path).unwrap()
      } else {
        entry.body.to_vec()
      };
      assert_eq!(body, b"second-body");
    }
    other => panic!("expected replacement cache hit, got {other:?}"),
  }

  let variant_key = variant_key("", "https:example.test:/asset/app.css", &[]);
  let body_path = cache_file_path(disk_dir, &variant_key, CacheFileKind::Body).unwrap();
  assert_eq!(std::fs::read(body_path).unwrap(), b"second-body");
  assert_eq!(cache.stats().disk_entries, 1);
}

#[test]
fn disk_cache_lookup_removes_entry_when_body_file_disappears() {
  let temp_dir = TestTempDir::new();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(temp_dir.path.clone()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &headers,
      },
      CacheEntry::memory(
        StatusCode::OK,
        HeaderMap::new(),
        Bytes::from_static(b"disk-body")
      ),
    ),
    CacheInsertOutcome::Stored
  );
  let variant_key = variant_key("", "https:example.test:/asset/app.css", &[]);
  let body_path = cache_file_path(&temp_dir.path, &variant_key, CacheFileKind::Body).unwrap();
  std::fs::remove_file(body_path).unwrap();

  assert!(
    cache
      .lookup(CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &headers,
      })
      .is_none()
  );
  assert_eq!(cache.stats().disk_entries, 0);
}

#[test]
fn cache_tag_purge_removes_matching_entries_only() {
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let headers = HeaderMap::new();
  let first_uri = "/asset/a.css".parse::<Uri>().unwrap();
  let second_uri = "/asset/b.css".parse::<Uri>().unwrap();
  let mut first_response_headers = HeaderMap::new();
  first_response_headers.insert("surrogate-key", HeaderValue::from_static("assets css"));
  let mut second_response_headers = HeaderMap::new();
  second_response_headers.insert("surrogate-key", HeaderValue::from_static("assets js"));

  for (uri, response_headers, body) in [
    (&first_uri, first_response_headers, Bytes::from_static(b"a")),
    (
      &second_uri,
      second_response_headers,
      Bytes::from_static(b"b"),
    ),
  ] {
    assert_eq!(
      cache.insert(
        CacheInsertContext {
          policy_name: Some("default"),
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri,
          request_headers: &headers,
        },
        CacheEntry::memory(StatusCode::OK, response_headers, body),
      ),
      CacheInsertOutcome::Stored
    );
  }

  assert_eq!(cache.purge_tag("default", "css", None, None), 1);
  let first = CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &first_uri,
    request_headers: &headers,
  };
  let second = CacheLookupContext {
    uri: &second_uri,
    ..first.clone()
  };
  assert!(cache.lookup(first).is_none());
  assert!(matches!(cache.lookup(second), Some(CacheLookup::Fresh(_))));
}

#[test]
fn admission_min_hits_rejects_until_threshold() {
  let config = CacheConfig {
    enabled: true,
    admission: CacheAdmissionConfig {
      min_hits: 2,
      ..CacheAdmissionConfig::default()
    },
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let uri = "/asset/app.css".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let ctx = CacheInsertContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri: &uri,
    request_headers: &headers,
  };
  let entry = CacheEntry::memory(
    StatusCode::OK,
    HeaderMap::new(),
    Bytes::from_static(b"body"),
  );
  assert_eq!(
    cache.insert(ctx.clone(), entry.clone()),
    CacheInsertOutcome::AdmissionWarming
  );
  assert!(
    cache
      .lookup(CacheLookupContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &headers,
      })
      .is_none()
  );
  assert_eq!(cache.insert(ctx, entry), CacheInsertOutcome::Stored);
}

#[test]
fn stale_if_error_status_policy_matches_configured_status() {
  let config = CacheConfig {
    stale_if_error: CacheStaleIfErrorConfig {
      statuses: vec![500, 502],
      ..CacheStaleIfErrorConfig::default()
    },
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  assert!(cache.stale_if_error_allows_status(Some("default"), StatusCode::BAD_GATEWAY));
  assert!(!cache.stale_if_error_allows_status(Some("default"), StatusCode::SERVICE_UNAVAILABLE));
}

#[test]
fn background_refresh_permit_respects_disabled_named_policy() {
  let config = cache_config_with_disabled_named_background_refresh();
  let cache = ResponseCache::new(&config, None).unwrap();

  assert!(
    cache
      .try_background_refresh_permit(Some("no-background-refresh"))
      .is_none()
  );
  assert!(
    cache
      .try_background_refresh_permit(Some("default"))
      .is_some()
  );
}

#[test]
fn disk_cache_recovers_entries_and_removes_orphan_bodies() {
  let temp_dir = TestTempDir::new();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(temp_dir.path.clone()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };
  {
    let cache = ResponseCache::new(&config, None).unwrap();
    let uri = "/asset/app.css".parse::<Uri>().unwrap();
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
          HeaderMap::new(),
          Bytes::from_static(b"disk-body")
        ),
      ),
      CacheInsertOutcome::Stored
    );
  }
  std::fs::write(temp_dir.path.join("orphan.body"), b"orphan").unwrap();
  std::fs::write(temp_dir.path.join("stale.body.tmp"), b"tmp").unwrap();

  let cache = ResponseCache::new(&config, None).unwrap();
  let stats = cache.stats();
  assert_eq!(stats.disk_recovered_entries_total, 1);
  assert!(stats.disk_recovery_removed_files_total >= 2);
  assert!(!temp_dir.path.join("orphan.body").exists());
  assert!(!temp_dir.path.join("stale.body.tmp").exists());
}

#[test]
fn disk_cache_recovery_does_not_trust_metadata_body_path() {
  let temp_dir = TestTempDir::new();
  let cache_dir = temp_dir.path.join("cache");
  std::fs::create_dir_all(&cache_dir).unwrap();
  let outside_path = temp_dir.path.join("outside.txt");
  std::fs::write(&outside_path, b"keep").unwrap();

  let variant_key = "https:example.test:/asset/poison.css";
  let meta_path = cache_file_path(&cache_dir, variant_key, CacheFileKind::Meta).unwrap();
  let stored = StoredEntry {
    policy: "default".to_string(),
    partition: String::new(),
    base_key: "https:example.test:/asset/poison.css".to_string(),
    variant_key: variant_key.to_string(),
    scheme: "https".to_string(),
    host: "example.test".to_string(),
    uri: "/asset/poison.css".to_string(),
    status: StatusCode::OK,
    headers: HeaderMap::new(),
    security_headers_neutral: true,
    body: StoredBody::Disk(outside_path.clone()),
    expires_at: UNIX_EPOCH + Duration::from_secs(1),
    stale_if_error_until: None,
    stale_while_revalidate_until: None,
    must_revalidate: false,
    stored_at: UNIX_EPOCH + Duration::from_secs(1),
    vary: Vec::new(),
    tags: Vec::new(),
    size: 4,
  };
  std::fs::write(&meta_path, encode_metadata(&stored).unwrap()).unwrap();

  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(cache_dir),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };
  let cache = ResponseCache::new(&config, None).unwrap();
  let stats = cache.stats();

  assert_eq!(stats.disk_recovered_entries_total, 0);
  assert!(stats.disk_recovery_removed_files_total >= 1);
  assert!(outside_path.exists());
}
