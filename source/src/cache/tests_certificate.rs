use super::*;
use http::header::{HeaderValue, VARY};

#[test]
fn certificate_identity_uses_a_private_base_key_namespace() {
  let plain = certificate_partitioned_base_key("logical-key".to_string(), None);
  let absent = CacheCertificateIdentity::new("client-cert", "url_encoded_pem", None).unwrap();
  let authenticated = CacheCertificateIdentity::new(
    "client-cert",
    "url_encoded_pem",
    Some("a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d"),
  )
  .unwrap();
  let other_header = CacheCertificateIdentity::new(
    "x-client-cert",
    "url_encoded_pem",
    Some("a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d"),
  )
  .unwrap();
  let other_format = CacheCertificateIdentity::new(
    "client-cert",
    "rfc9440",
    Some("a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d"),
  )
  .unwrap();

  assert_eq!(plain, "logical-key");
  assert_ne!(
    certificate_partitioned_base_key("logical-key".to_string(), Some(&absent)),
    plain
  );
  assert_ne!(
    certificate_partitioned_base_key("logical-key".to_string(), Some(&authenticated)),
    certificate_partitioned_base_key("logical-key".to_string(), Some(&absent))
  );
  assert_ne!(
    certificate_partitioned_base_key("logical-key".to_string(), Some(&authenticated)),
    certificate_partitioned_base_key("logical-key".to_string(), Some(&other_header))
  );
  assert_ne!(
    certificate_partitioned_base_key("logical-key".to_string(), Some(&authenticated)),
    certificate_partitioned_base_key("logical-key".to_string(), Some(&other_format))
  );
  let adversarial_query_key = format!("\0oxibelt-cache-certificate-v1\0{}", "query=value");
  let escaped_plain = certificate_partitioned_base_key(adversarial_query_key.clone(), None);
  let certificate_key = certificate_partitioned_base_key(adversarial_query_key, Some(&absent));
  assert!(escaped_plain.starts_with("\0oxibelt-cache-plain-key-v1\0"));
  assert!(certificate_key.starts_with("\0oxibelt-cache-certificate-v1\0"));
  assert_ne!(escaped_plain, certificate_key);
  assert!(CacheCertificateIdentity::new("client-cert\0sentinel", "url_encoded_pem", None).is_err());
  assert!(CacheCertificateIdentity::new("client-cert", "url_encoded_pem\0sentinel", None).is_err());
  assert!(authenticated.is_authenticated());
  assert!(!absent.is_authenticated());
  assert!(
    !format!("{authenticated:?}")
      .contains("a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d")
  );
}

#[test]
fn certificate_identity_segregates_cache_entries_without_changing_partition() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      partition_key: "{header:x-tenant}".to_string(),
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let uri = "/asset.css".parse::<Uri>().unwrap();
  let mut request_headers = HeaderMap::new();
  request_headers.insert("x-tenant", HeaderValue::from_static("tenant-a"));
  let first = CacheCertificateIdentity::new(
    "client-cert",
    "url_encoded_pem",
    Some("a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d"),
  )
  .unwrap();
  let second = CacheCertificateIdentity::new(
    "client-cert",
    "url_encoded_pem",
    Some("b3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d"),
  )
  .unwrap();
  let absent = CacheCertificateIdentity::new("client-cert", "url_encoded_pem", None).unwrap();

  for (identity, body) in [
    (Some(&first), Bytes::from_static(b"first")),
    (Some(&second), Bytes::from_static(b"second")),
    (Some(&absent), Bytes::from_static(b"absent")),
    (None, Bytes::from_static(b"off")),
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
          certificate_identity: identity,
        },
        CacheEntry::memory(StatusCode::OK, HeaderMap::new(), body),
      ),
      CacheInsertOutcome::Stored
    );
  }

  let first_operation = cache
    .operation_context(
      Some("default"),
      "https",
      "example.test",
      &Method::GET,
      &uri,
      &request_headers,
      Some(&first),
    )
    .unwrap();
  let second_operation = cache
    .operation_context(
      Some("default"),
      "https",
      "example.test",
      &Method::GET,
      &uri,
      &request_headers,
      Some(&second),
    )
    .unwrap();
  assert_eq!(first_operation.partition, second_operation.partition);
  assert_ne!(first_operation.base_key, second_operation.base_key);

  for (identity, expected) in [
    (Some(&first), Bytes::from_static(b"first")),
    (Some(&second), Bytes::from_static(b"second")),
    (Some(&absent), Bytes::from_static(b"absent")),
    (None, Bytes::from_static(b"off")),
  ] {
    match cache.lookup(CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &request_headers,
      certificate_identity: identity,
    }) {
      Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body, expected),
      other => panic!("expected isolated cache hit, got {other:?}"),
    }
  }
}

#[test]
fn certificate_vary_uses_identity_not_untrusted_header_values_or_explain_output() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let uri = "/asset.css".parse::<Uri>().unwrap();
  let identity = CacheCertificateIdentity::new(
    "client-cert",
    "rfc9440",
    Some("a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d"),
  )
  .unwrap();
  let mut response_headers = HeaderMap::new();
  response_headers.insert(
    VARY,
    HeaderValue::from_static("Client-Cert, Accept-Language"),
  );
  let mut inserted_headers = HeaderMap::new();
  inserted_headers.insert("client-cert", HeaderValue::from_static("untrusted-a"));
  inserted_headers.insert("accept-language", HeaderValue::from_static("en"));

  assert_eq!(
    cache.insert(
      CacheInsertContext {
        policy_name: Some("default"),
        scheme: "https",
        host: "example.test",
        method: &Method::GET,
        uri: &uri,
        request_headers: &inserted_headers,
        certificate_identity: Some(&identity),
      },
      CacheEntry::memory(
        StatusCode::OK,
        response_headers.clone(),
        Bytes::from_static(b"body")
      ),
    ),
    CacheInsertOutcome::Stored
  );

  let mut lookup_headers = HeaderMap::new();
  lookup_headers.insert("client-cert", HeaderValue::from_static("untrusted-b"));
  lookup_headers.insert("accept-language", HeaderValue::from_static("en"));
  assert!(matches!(
    cache.lookup(CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &lookup_headers,
      certificate_identity: Some(&identity),
    }),
    Some(CacheLookup::Fresh(_))
  ));

  let explain = cache.explain_key(
    CacheLookupContext {
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method: &Method::GET,
      uri: &uri,
      request_headers: &lookup_headers,
      certificate_identity: Some(&identity),
    },
    Some(&response_headers),
  );
  assert_eq!(explain.base_key, "https:example.test:/asset.css");
  assert_eq!(explain.vary_fields, vec!["accept-language"]);
  assert!(
    !format!("{explain:?}")
      .contains("a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d")
  );
}
