use super::*;

#[tokio::test]
async fn query_aliases_require_body_content_headers_trailers_and_both_identities() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      cache_methods: vec!["GET".into(), "HEAD".into(), "QUERY".into()],
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let method = Method::from_bytes(b"QUERY").unwrap();
  let owner_uri: Uri = "/query?ignored=owner".parse().unwrap();
  let owner_identity = query_identity_fixture(&owner_uri, b"body", "application/json", "one");
  let headers = HeaderMap::new();
  seed_with_options(
    &cache,
    &owner_uri,
    "https://origin.test/query?ignored=owner",
    "params=(\"ignored\")",
    b"route-query",
    &method,
    &headers,
    Some(&owner_identity),
    None,
  )
  .await;

  let alias_uri: Uri = "/query?ignored=alias".parse().unwrap();
  let same = query_identity_fixture(&alias_uri, b"body", "application/json", "one");
  assert!(
    alias_with_options(
      &cache,
      &alias_uri,
      "https://origin.test/query?ignored=alias",
      b"route-query",
      &method,
      &headers,
      Some(&same),
      None,
    )
    .await
    .is_some()
  );
  for (body, content_type, trailer) in [
    (b"changed".as_slice(), "application/json", "one"),
    (b"body".as_slice(), "text/plain", "one"),
    (b"body".as_slice(), "application/json", "two"),
  ] {
    let identity = query_identity_fixture(&alias_uri, body, content_type, trailer);
    assert!(
      alias_with_options(
        &cache,
        &alias_uri,
        "https://origin.test/query?ignored=alias",
        b"route-query",
        &method,
        &headers,
        Some(&identity),
        None,
      )
      .await
      .is_none()
    );
  }

  let mut changed_effective =
    query_identity_fixture(&alias_uri, b"body", "application/json", "one");
  let effective_uri: Uri = "https://other.test/query?ignored=alias".parse().unwrap();
  changed_effective.effective.target_uri = effective_uri.to_string();
  assert!(
    alias_with_options(
      &cache,
      &alias_uri,
      "https://origin.test/query?ignored=alias",
      b"route-query",
      &method,
      &headers,
      Some(&changed_effective),
      None,
    )
    .await
    .is_none()
  );
}

#[tokio::test]
async fn key_order_keeps_duplicate_name_order_significant() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let owner: Uri = "/duplicate?b=two&a=one&a=two".parse().unwrap();
  seed(
    &cache,
    &owner,
    "https://origin.test/duplicate?b=two&a=one&a=two",
    "key-order",
  )
  .await;
  assert!(
    alias(
      &cache,
      "/duplicate?a=one&a=two&b=two",
      "https://origin.test/duplicate?a=one&a=two&b=two"
    )
    .await
    .is_some()
  );
  assert!(
    alias(
      &cache,
      "/duplicate?a=two&a=one&b=two",
      "https://origin.test/duplicate?a=two&a=one&b=two"
    )
    .await
    .is_none()
  );
}

#[tokio::test]
async fn nvs_candidate_directory_obeys_bounded_limit() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      max_vary_variants_per_key: 2,
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  for value in ["one", "two", "three"] {
    let uri: Uri = format!("/bounded?ignored={value}").parse().unwrap();
    seed(
      &cache,
      &uri,
      &format!("https://origin.test/bounded?ignored={value}"),
      "params=(\"ignored\")",
    )
    .await;
  }
  let inner = cache.inner_guard();
  assert_eq!(inner.nvs_index.len(), 1);
  assert_eq!(inner.nvs_index.values().next().unwrap().len(), 2);
}

#[tokio::test]
async fn nvs_scope_separates_partition_credentials_certificate_and_route() {
  let cache = ResponseCache::new(
    &CacheConfig {
      enabled: true,
      groups: crate::config::CacheGroupsConfig { enabled: false },
      partition_key: "{header:x-tenant}".into(),
      ..CacheConfig::default()
    },
    None,
  )
  .unwrap();
  let uri: Uri = "/scoped?ignored=one".parse().unwrap();
  let cert_a = CacheCertificateIdentity::new(
    "client-cert",
    "url_encoded_pem",
    Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
  )
  .unwrap();
  let cert_b = CacheCertificateIdentity::new(
    "client-cert",
    "url_encoded_pem",
    Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
  )
  .unwrap();
  let method = Method::GET;
  let mut tenant_a = HeaderMap::new();
  tenant_a.insert("x-tenant", HeaderValue::from_static("a"));
  seed_with_options(
    &cache,
    &uri,
    "https://origin.test/scoped?ignored=one",
    "params=(\"ignored\")",
    b"route-a",
    &method,
    &tenant_a,
    None,
    Some(&cert_a),
  )
  .await;
  let alias_uri: Uri = "/scoped?ignored=two".parse().unwrap();
  assert!(
    alias_with_options(
      &cache,
      &alias_uri,
      "https://origin.test/scoped?ignored=two",
      b"route-a",
      &method,
      &tenant_a,
      None,
      Some(&cert_a)
    )
    .await
    .is_some()
  );

  let mut tenant_b = HeaderMap::new();
  tenant_b.insert("x-tenant", HeaderValue::from_static("b"));
  assert!(
    alias_with_options(
      &cache,
      &alias_uri,
      "https://origin.test/scoped?ignored=two",
      b"route-a",
      &method,
      &tenant_b,
      None,
      Some(&cert_a)
    )
    .await
    .is_none()
  );
  assert!(
    alias_with_options(
      &cache,
      &alias_uri,
      "https://origin.test/scoped?ignored=two",
      b"route-a",
      &method,
      &tenant_a,
      None,
      Some(&cert_b)
    )
    .await
    .is_none()
  );
  assert!(
    alias_with_options(
      &cache,
      &alias_uri,
      "https://origin.test/scoped?ignored=two",
      b"route-b",
      &method,
      &tenant_a,
      None,
      Some(&cert_a)
    )
    .await
    .is_none()
  );

  let mut credentialed = tenant_a.clone();
  credentialed.insert(
    http::header::AUTHORIZATION,
    HeaderValue::from_static("Bearer secret"),
  );
  assert!(
    alias_with_options(
      &cache,
      &alias_uri,
      "https://origin.test/scoped?ignored=two",
      b"route-a",
      &method,
      &credentialed,
      None,
      Some(&cert_a)
    )
    .await
    .is_none()
  );
}
