//! Persistence coverage for client-certificate cache identity separation.

use super::*;

const CERTIFICATE_A_FINGERPRINT: &str =
  "a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d";
const CERTIFICATE_B_FINGERPRINT: &str =
  "b3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d";
const CERTIFICATE_CACHE_URI: &str = "/assets/client-certificate.css";

fn certificate_identities() -> (
  CacheCertificateIdentity,
  CacheCertificateIdentity,
  CacheCertificateIdentity,
) {
  (
    CacheCertificateIdentity::new(
      "client-cert",
      "url_encoded_pem",
      Some(CERTIFICATE_A_FINGERPRINT),
    )
    .expect("fixture A fingerprint should be accepted"),
    CacheCertificateIdentity::new(
      "client-cert",
      "url_encoded_pem",
      Some(CERTIFICATE_B_FINGERPRINT),
    )
    .expect("fixture B fingerprint should be accepted"),
    CacheCertificateIdentity::new("client-cert", "url_encoded_pem", None)
      .expect("absent certificate identity should be accepted"),
  )
}

fn lookup_context<'a>(
  uri: &'a Uri,
  request_headers: &'a HeaderMap,
  certificate_identity: Option<&'a CacheCertificateIdentity>,
) -> CacheLookupContext<'a> {
  CacheLookupContext {
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri,
    request_headers,
    certificate_identity,
  }
}

fn insert_certificate_variants(
  cache: &ResponseCache,
  uri: &Uri,
  request_headers: &HeaderMap,
  first: &CacheCertificateIdentity,
  second: &CacheCertificateIdentity,
  absent: &CacheCertificateIdentity,
) {
  for (identity, body) in [
    (Some(first), Bytes::from_static(b"certificate-a")),
    (Some(second), Bytes::from_static(b"certificate-b")),
    (Some(absent), Bytes::from_static(b"certificate-absent")),
    (None, Bytes::from_static(b"certificate-off")),
  ] {
    assert_eq!(
      cache.insert(
        CacheInsertContext {
          policy_name: Some("default"),
          scheme: "https",
          host: "example.test",
          method: &Method::GET,
          uri,
          request_headers,
          certificate_identity: identity,
        },
        CacheEntry::memory(StatusCode::OK, HeaderMap::new(), body),
      ),
      CacheInsertOutcome::Stored
    );
  }
}

fn assert_certificate_variants_are_isolated(
  cache: &ResponseCache,
  uri: &Uri,
  request_headers: &HeaderMap,
  first: &CacheCertificateIdentity,
  second: &CacheCertificateIdentity,
  absent: &CacheCertificateIdentity,
) {
  for (identity, expected) in [
    (Some(first), Bytes::from_static(b"certificate-a")),
    (Some(second), Bytes::from_static(b"certificate-b")),
    (Some(absent), Bytes::from_static(b"certificate-absent")),
    (None, Bytes::from_static(b"certificate-off")),
  ] {
    match cache.lookup(lookup_context(uri, request_headers, identity)) {
      Some(CacheLookup::Fresh(entry)) => {
        let body = match entry.body_file {
          Some(file) => {
            let bytes = std::fs::read(&file.path).unwrap();
            let start = usize::try_from(file.offset).unwrap();
            Bytes::copy_from_slice(&bytes[start..start + file.len])
          }
          None => entry.body,
        };
        assert_eq!(body, expected);
      }
      other => panic!("expected isolated certificate cache hit, got {other:?}"),
    }
  }
}

#[test]
fn disk_cache_recovery_keeps_certificate_identity_variants_separate_and_purgeable() {
  let temp_dir = TestTempDir::new();
  let config = CacheConfig {
    enabled: true,
    store: CacheStore::Disk,
    disk_dir: Some(temp_dir.path.clone()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };
  let uri = CERTIFICATE_CACHE_URI.parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();
  let (first, second, absent) = certificate_identities();

  {
    let cache = ResponseCache::new(&config, None).unwrap();
    insert_certificate_variants(&cache, &uri, &request_headers, &first, &second, &absent);
  }

  let cache = ResponseCache::new(&config, None).unwrap();
  assert_eq!(cache.stats().disk_recovered_entries_total, 4);
  assert_certificate_variants_are_isolated(
    &cache,
    &uri,
    &request_headers,
    &first,
    &second,
    &absent,
  );
  assert_eq!(
    cache.purge_exact("default", "https", "example.test", CERTIFICATE_CACHE_URI),
    4,
    "a logical purge must include each physical certificate namespace"
  );
  for identity in [Some(&first), Some(&second), Some(&absent), None] {
    assert!(
      cache
        .lookup(lookup_context(&uri, &request_headers, identity))
        .is_none()
    );
  }
}

#[tokio::test]
async fn shared_cache_keeps_certificate_identity_variants_separate_and_purgeable() {
  let shared = crate::shared_state::SharedState::test_memory("cache-certificate-storage");
  let config = CacheConfig {
    enabled: true,
    ..CacheConfig::default()
  };
  let writer = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let reader = ResponseCache::new(&config, Some(shared.clone())).unwrap();
  let uri = CERTIFICATE_CACHE_URI.parse::<Uri>().unwrap();
  let request_headers = HeaderMap::new();
  let (first, second, absent) = certificate_identities();

  for (identity, body) in [
    (Some(&first), Bytes::from_static(b"certificate-a")),
    (Some(&second), Bytes::from_static(b"certificate-b")),
    (Some(&absent), Bytes::from_static(b"certificate-absent")),
    (None, Bytes::from_static(b"certificate-off")),
  ] {
    assert_eq!(
      writer
        .insert_async(
          CacheInsertContext {
            policy_name: Some("default"),
            scheme: "https",
            host: "example.test",
            method: &Method::GET,
            uri: &uri,
            request_headers: &request_headers,
            certificate_identity: identity,
          },
          CacheEntry::memory(StatusCode::OK, HeaderMap::new(), body),
        )
        .await,
      CacheInsertOutcome::Stored
    );
  }

  for (identity, expected) in [
    (Some(&first), Bytes::from_static(b"certificate-a")),
    (Some(&second), Bytes::from_static(b"certificate-b")),
    (Some(&absent), Bytes::from_static(b"certificate-absent")),
    (None, Bytes::from_static(b"certificate-off")),
  ] {
    match reader
      .lookup_async(lookup_context(&uri, &request_headers, identity))
      .await
    {
      Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body, expected),
      other => panic!("expected isolated shared certificate cache hit, got {other:?}"),
    }
  }

  assert_eq!(
    reader
      .purge_exact_partition_async(
        "default",
        "https",
        "example.test",
        CERTIFICATE_CACHE_URI,
        None,
      )
      .await
      .expect("shared logical certificate purge should complete"),
    8,
    "reader L1 and shared L2 must each remove all four variants"
  );
  let post_purge_reader = ResponseCache::new(&config, Some(shared)).unwrap();
  for identity in [Some(&first), Some(&second), Some(&absent), None] {
    assert!(
      post_purge_reader
        .lookup_async(lookup_context(&uri, &request_headers, identity))
        .await
        .is_none()
    );
  }
}
