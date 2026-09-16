//! Cache-namespace regression coverage for explicit PROXY TLS egress identity.

use super::external_handler::{
  CACHE_KEY_VERSION, ExternalCacheBody, ExternalCacheEntryMetadata, ExternalCacheHeader,
  ExternalCacheLookupHit, PROTOCOL_VERSION,
};
use super::*;

const CERTIFICATE_A_FINGERPRINT: &str =
  "a3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d";
const CERTIFICATE_B_FINGERPRINT: &str =
  "b3dcb4d229de6fde0db5686dee47145dcdc6a1a4ec5a7f5365e5a5df3caa4f4d";

struct Identities {
  local: CacheProxyProtocolIdentity,
  received: CacheProxyProtocolIdentity,
  received_other_metadata: CacheProxyProtocolIdentity,
  received_other_address: CacheProxyProtocolIdentity,
}

fn identities() -> Identities {
  Identities {
    local: CacheProxyProtocolIdentity::new("local_tls", &proxy_header(10, 20, b"client-a")),
    received: CacheProxyProtocolIdentity::new("received_proxy", &proxy_header(10, 20, b"client-a")),
    received_other_metadata: CacheProxyProtocolIdentity::new(
      "received_proxy",
      &proxy_header(10, 20, b"client-b"),
    ),
    received_other_address: CacheProxyProtocolIdentity::new(
      "received_proxy",
      &proxy_header(11, 20, b"client-a"),
    ),
  }
}

fn proxy_header(source_last_octet: u8, destination_last_octet: u8, tls_metadata: &[u8]) -> Vec<u8> {
  let mut header = crate::proxy_protocol_egress::v2_header(
    format!("198.51.100.{source_last_octet}:4242")
      .parse()
      .expect("fixture source address should parse"),
    format!("192.0.2.{destination_last_octet}:443")
      .parse()
      .expect("fixture destination address should parse"),
  );
  let tls_len = u16::try_from(tls_metadata.len()).expect("fixture TLS metadata is bounded");
  header.push(0x20);
  header.extend_from_slice(&tls_len.to_be_bytes());
  header.extend_from_slice(tls_metadata);
  let payload_len = u16::try_from(header.len() - 16).expect("fixture header is bounded");
  header[14..16].copy_from_slice(&payload_len.to_be_bytes());
  header
}

fn certificate_identities() -> (CacheCertificateIdentity, CacheCertificateIdentity) {
  (
    CacheCertificateIdentity::new("client-cert", "rfc9440", Some(CERTIFICATE_A_FINGERPRINT))
      .expect("certificate A should be accepted"),
    CacheCertificateIdentity::new("client-cert", "rfc9440", Some(CERTIFICATE_B_FINGERPRINT))
      .expect("certificate B should be accepted"),
  )
}

fn lookup_context<'a>(
  uri: &'a Uri,
  headers: &'a HeaderMap,
  certificate_identity: Option<&'a CacheCertificateIdentity>,
  proxy_protocol_identity: Option<&'a CacheProxyProtocolIdentity>,
) -> CacheLookupContext<'a> {
  CacheLookupContext {
    group_request: None,
    no_vary_search: None,
    proxy_protocol_identity,
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri,
    request_headers: headers,
    query_identity: None,
    certificate_identity,
  }
}

fn insert_context<'a>(
  uri: &'a Uri,
  headers: &'a HeaderMap,
  certificate_identity: Option<&'a CacheCertificateIdentity>,
  proxy_protocol_identity: Option<&'a CacheProxyProtocolIdentity>,
) -> CacheInsertContext<'a> {
  CacheInsertContext {
    group_request: None,
    no_vary_search: None,
    proxy_protocol_identity,
    policy_name: Some("default"),
    scheme: "https",
    host: "example.test",
    method: &Method::GET,
    uri,
    request_headers: headers,
    query_identity: None,
    certificate_identity,
  }
}

fn assert_memory_hit(
  cache: &ResponseCache,
  uri: &Uri,
  headers: &HeaderMap,
  certificate_identity: Option<&CacheCertificateIdentity>,
  proxy_protocol_identity: Option<&CacheProxyProtocolIdentity>,
  expected: &[u8],
) {
  match cache.lookup(lookup_context(
    uri,
    headers,
    certificate_identity,
    proxy_protocol_identity,
  )) {
    Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body, Bytes::copy_from_slice(expected)),
    other => panic!("expected isolated cache hit, got {other:?}"),
  }
}

fn assert_disk_hit(
  cache: &ResponseCache,
  uri: &Uri,
  headers: &HeaderMap,
  certificate_identity: Option<&CacheCertificateIdentity>,
  proxy_protocol_identity: Option<&CacheProxyProtocolIdentity>,
  expected: &[u8],
) {
  match cache.lookup(lookup_context(
    uri,
    headers,
    certificate_identity,
    proxy_protocol_identity,
  )) {
    Some(CacheLookup::Fresh(entry)) => {
      let body_file = entry
        .body_file
        .expect("disk cache hit should expose a body file");
      let bytes = std::fs::read(&body_file.path).expect("disk cache body should remain readable");
      let offset = usize::try_from(body_file.offset).expect("fixture offset should fit usize");
      assert_eq!(&bytes[offset..offset + body_file.len], expected);
    }
    other => panic!("expected isolated disk-cache hit, got {other:?}"),
  }
}

#[test]
fn proxy_tls_identity_partitions_same_request_by_source_metadata_address_and_absence() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      ..CacheConfig::default()
    },
    None,
  )
  .expect("cache should build");
  let uri = "/assets/proxy-tls.css".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let identity = identities();

  for (proxy_identity, body) in [
    (Some(&identity.local), b"local".as_slice()),
    (Some(&identity.received), b"received".as_slice()),
    (
      Some(&identity.received_other_metadata),
      b"received-other-metadata".as_slice(),
    ),
    (
      Some(&identity.received_other_address),
      b"received-other-address".as_slice(),
    ),
    (None, b"off".as_slice()),
  ] {
    assert_eq!(
      cache.insert(
        insert_context(&uri, &headers, None, proxy_identity),
        CacheEntry::memory(
          StatusCode::OK,
          HeaderMap::new(),
          Bytes::copy_from_slice(body)
        ),
      ),
      CacheInsertOutcome::Stored
    );
  }

  for (proxy_identity, body) in [
    (Some(&identity.local), b"local".as_slice()),
    (Some(&identity.received), b"received".as_slice()),
    (
      Some(&identity.received_other_metadata),
      b"received-other-metadata".as_slice(),
    ),
    (
      Some(&identity.received_other_address),
      b"received-other-address".as_slice(),
    ),
    (None, b"off".as_slice()),
  ] {
    assert_memory_hit(&cache, &uri, &headers, None, proxy_identity, body);
  }

  let unseen =
    CacheProxyProtocolIdentity::new("received_proxy", &proxy_header(10, 21, b"client-a"));
  assert!(
    cache
      .lookup(lookup_context(&uri, &headers, None, Some(&unseen)))
      .is_none(),
    "unseen TLS metadata must not share the no-metadata or any selected-TLS namespace"
  );
}

#[test]
fn proxy_tls_identity_composes_with_client_certificate_identity() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      ..CacheConfig::default()
    },
    None,
  )
  .expect("cache should build");
  let uri = "/assets/proxy-tls-certificate.css".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let identity = identities();
  let (certificate_a, certificate_b) = certificate_identities();

  for (certificate_identity, body) in [
    (Some(&certificate_a), b"certificate-a".as_slice()),
    (Some(&certificate_b), b"certificate-b".as_slice()),
    (None, b"certificate-off".as_slice()),
  ] {
    assert_eq!(
      cache.insert(
        insert_context(
          &uri,
          &headers,
          certificate_identity,
          Some(&identity.received)
        ),
        CacheEntry::memory(
          StatusCode::OK,
          HeaderMap::new(),
          Bytes::copy_from_slice(body)
        ),
      ),
      CacheInsertOutcome::Stored
    );
  }

  for (certificate_identity, body) in [
    (Some(&certificate_a), b"certificate-a".as_slice()),
    (Some(&certificate_b), b"certificate-b".as_slice()),
    (None, b"certificate-off".as_slice()),
  ] {
    assert_memory_hit(
      &cache,
      &uri,
      &headers,
      certificate_identity,
      Some(&identity.received),
      body,
    );
  }
  assert!(
    cache
      .lookup(lookup_context(
        &uri,
        &headers,
        Some(&certificate_a),
        Some(&identity.local),
      ))
      .is_none(),
    "certificate identity must not bridge a distinct selected PROXY TLS namespace"
  );
}

#[test]
fn disk_cache_recovery_preserves_proxy_tls_identity_namespaces() {
  let directory = tempfile::tempdir().expect("temporary disk cache directory should exist");
  let config = CacheConfig {
    enabled: true,
    groups: crate::config::CacheGroupsConfig { enabled: false },
    store: CacheStore::Disk,
    disk_dir: Some(directory.path().to_path_buf()),
    disk_max_size_bytes: Some(1024 * 1024),
    ..CacheConfig::default()
  };
  let uri = "/assets/proxy-tls-disk.css".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let identity = identities();

  {
    let cache = ResponseCache::new(&config, None).expect("disk cache should build");
    for (proxy_identity, body) in [
      (Some(&identity.local), b"local".as_slice()),
      (Some(&identity.received), b"received".as_slice()),
      (None, b"off".as_slice()),
    ] {
      assert_eq!(
        cache.insert(
          insert_context(&uri, &headers, None, proxy_identity),
          CacheEntry::memory(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::copy_from_slice(body)
          ),
        ),
        CacheInsertOutcome::Stored
      );
    }
  }

  let cache = ResponseCache::new(&config, None).expect("disk cache should recover");
  assert_eq!(cache.stats().disk_recovered_entries_total, 3);
  for (proxy_identity, body) in [
    (Some(&identity.local), b"local".as_slice()),
    (Some(&identity.received), b"received".as_slice()),
    (None, b"off".as_slice()),
  ] {
    assert_disk_hit(&cache, &uri, &headers, None, proxy_identity, body);
  }
}

#[tokio::test]
async fn shared_and_external_cache_paths_validate_proxy_tls_identity_namespaces() {
  let shared = crate::shared_state::SharedState::test_memory("proxy-tls-cache-namespaces");
  let config = CacheConfig {
    enabled: true,
    groups: crate::config::CacheGroupsConfig { enabled: false },
    external_handler: Some("proxy-tls-external".to_string()),
    ..CacheConfig::default()
  };
  let writer =
    ResponseCache::new(&config, Some(shared.clone())).expect("writer cache should build");
  let reader = ResponseCache::new(&config, Some(shared)).expect("reader cache should build");
  let uri = "/assets/proxy-tls-shared.css".parse::<Uri>().unwrap();
  let headers = HeaderMap::new();
  let identity = identities();

  for (proxy_identity, body) in [
    (Some(&identity.received), b"received".as_slice()),
    (Some(&identity.received_other_metadata), b"other".as_slice()),
    (None, b"off".as_slice()),
  ] {
    assert_eq!(
      writer
        .insert_async(
          insert_context(&uri, &headers, None, proxy_identity),
          CacheEntry::memory(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::copy_from_slice(body)
          ),
        )
        .await,
      CacheInsertOutcome::Stored
    );
  }
  for (proxy_identity, body) in [
    (Some(&identity.received), b"received".as_slice()),
    (Some(&identity.received_other_metadata), b"other".as_slice()),
    (None, b"off".as_slice()),
  ] {
    match reader
      .lookup_async(lookup_context(&uri, &headers, None, proxy_identity))
      .await
    {
      Some(CacheLookup::Fresh(entry)) => assert_eq!(entry.body, Bytes::copy_from_slice(body)),
      other => panic!("expected isolated shared-cache hit, got {other:?}"),
    }
  }

  let matching_context = lookup_context(&uri, &headers, None, Some(&identity.received));
  let matching_operation = reader
    .operation_context(
      matching_context.policy_name,
      matching_context.scheme,
      matching_context.host,
      matching_context.method,
      matching_context.uri,
      matching_context.request_headers,
      matching_context.query_identity,
      matching_context.certificate_identity,
      matching_context.proxy_protocol_identity,
      None,
    )
    .expect("external operation should build");
  assert!(matches!(
    reader.external_lookup_result(
      matching_operation,
      matching_context.clone(),
      external_hit_for_context(
        &reader,
        matching_context.clone(),
        Bytes::from_static(b"external")
      ),
    ),
    Some(CacheLookup::Fresh(_))
  ));

  let mismatched_context =
    lookup_context(&uri, &headers, None, Some(&identity.received_other_address));
  let mismatched_operation = reader
    .operation_context(
      mismatched_context.policy_name,
      mismatched_context.scheme,
      mismatched_context.host,
      mismatched_context.method,
      mismatched_context.uri,
      mismatched_context.request_headers,
      mismatched_context.query_identity,
      mismatched_context.certificate_identity,
      mismatched_context.proxy_protocol_identity,
      None,
    )
    .expect("mismatched external operation should build");
  assert!(
    reader
      .external_lookup_result(
        mismatched_operation,
        mismatched_context,
        external_hit_for_context(&reader, matching_context, Bytes::from_static(b"external")),
      )
      .is_none(),
    "external metadata for one selected PROXY TLS identity must not validate for another"
  );
}

fn external_hit_for_context(
  cache: &ResponseCache,
  ctx: CacheLookupContext<'_>,
  body: Bytes,
) -> ExternalCacheLookupHit {
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
    .expect("external operation should build");
  external_hit(&operation, body)
}

fn external_hit(operation: &CacheOperationContext, body: Bytes) -> ExternalCacheLookupHit {
  let now = SystemTime::now();
  ExternalCacheLookupHit {
    metadata: ExternalCacheEntryMetadata {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: CACHE_KEY_VERSION.to_string(),
      policy: operation.policy.name.clone(),
      partition: operation.partition.clone(),
      base_key: operation.base_key.clone(),
      variant_key: variant_key(&operation.partition, &operation.base_key, &[]),
      scheme: operation.scheme.clone(),
      host: operation.host.clone(),
      uri: operation.uri.clone(),
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
      vary: Vec::new(),
      tags: Vec::new(),
      query_target_epoch: None,
      no_vary_search: None,
      group_stamp: None,
      capabilities: Vec::new(),
    },
    body: ExternalCacheBody::Memory(body),
  }
}
