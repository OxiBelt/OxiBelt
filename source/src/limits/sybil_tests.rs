use super::*;

fn rate_limit_config(name: &str, key: RateLimitKey) -> RateLimitConfig {
  RateLimitConfig {
    name: name.to_string(),
    key,
    ipv4_prefix_bits: default_rate_limit_ipv4_prefix_bits(),
    ipv6_prefix_bits: default_rate_limit_ipv6_prefix_bits(),
    identity_parts: Vec::new(),
    token_bindings: Vec::new(),
    routes: Vec::new(),
    token_header: None,
    access_token_source: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
  }
}

fn rate_limit_check(key: RateLimitKey) -> RateLimitCheck<'static> {
  RateLimitCheck {
    name: "test",
    key,
    token_header: None,
    access_token_source: None,
    ipv4_prefix_bits: default_rate_limit_ipv4_prefix_bits(),
    ipv6_prefix_bits: default_rate_limit_ipv6_prefix_bits(),
    identity_parts: &[],
    token_bindings: &[],
    rate: "1r/h",
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
  }
}

#[test]
fn client_ip_prefix_keys_group_by_prefix_and_preserve_route_path_isolation() {
  let state = LimitState::new(None);
  let first_ip = "203.0.113.10".parse().unwrap();
  let second_ip = "203.0.113.200".parse().unwrap();
  let third_ip = "203.0.114.10".parse().unwrap();
  let headers = HeaderMap::new();
  let route_limit = [RateLimitConfig {
    name: "prefix-route".to_string(),
    key: RateLimitKey::ClientIpPrefixRoute,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("prefix-route", RateLimitKey::ClientIpPrefixRoute)
  }];

  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(first_ip, "app", "/same", &headers),
      &route_limit,
    ),
    None
  );
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(second_ip, "app", "/same", &headers),
      &route_limit,
    ),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(second_ip, "admin", "/same", &headers),
      &route_limit,
    ),
    None
  );
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(third_ip, "app", "/same", &headers),
      &route_limit,
    ),
    None
  );

  let path_state = LimitState::new(None);
  let path_limit = [RateLimitConfig {
    name: "prefix-path".to_string(),
    key: RateLimitKey::ClientIpPrefixPath,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("prefix-path", RateLimitKey::ClientIpPrefixPath)
  }];
  assert_eq!(
    path_state.check_route_rate_limits(
      RateLimitContext::route(first_ip, "app", "/one", &headers),
      &path_limit,
    ),
    None
  );
  assert_eq!(
    path_state.check_route_rate_limits(
      RateLimitContext::route(second_ip, "app", "/one", &headers),
      &path_limit,
    ),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  assert_eq!(
    path_state.check_route_rate_limits(
      RateLimitContext::route(second_ip, "app", "/two", &headers),
      &path_limit,
    ),
    None
  );
}

#[test]
fn tls_fingerprint_keys_hash_values_and_fallback_to_ip() {
  let state = LimitState::new(None);
  let first_ip = "203.0.113.10".parse().unwrap();
  let second_ip = "198.51.100.20".parse().unwrap();
  let headers = HeaderMap::new();
  let limit = [RateLimitConfig {
    name: "tls".to_string(),
    key: RateLimitKey::TlsFingerprintRoute,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("tls", RateLimitKey::TlsFingerprintRoute)
  }];
  let first = RateLimitContext::route(first_ip, "app", "/same", &headers)
    .with_tls_fingerprint(Some("tls-secret"));
  let second = RateLimitContext::route(second_ip, "app", "/same", &headers)
    .with_tls_fingerprint(Some("tls-secret"));
  let other = RateLimitContext::route(second_ip, "app", "/same", &headers)
    .with_tls_fingerprint(Some("tls-other"));

  assert_eq!(state.check_route_rate_limits(first, &limit), None);
  assert_eq!(
    state.check_route_rate_limits(second, &limit),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  assert_eq!(state.check_route_rate_limits(other, &limit), None);

  let key = rate_limit_key(first, &RateLimitCheck::from(&limit[0]));
  assert!(key.starts_with("tls_fingerprint_route:fingerprint:"));
  assert!(!key.contains("tls-secret"));

  let fallback = rate_limit_key(
    RateLimitContext::route(first_ip, "app", "/same", &headers),
    &RateLimitCheck::from(&limit[0]),
  );
  assert_eq!(
    fallback,
    "tls_fingerprint_route:fallback_ip:203.0.113.10:app"
  );
}

#[test]
fn composite_client_keys_hash_canonical_parts_and_missing_parts_fallback_per_ip() {
  let first_ip = "203.0.113.10".parse().unwrap();
  let second_ip = "203.0.113.11".parse().unwrap();
  let mut headers = HeaderMap::new();
  headers.insert(http::header::USER_AGENT, "unit-test-agent".parse().unwrap());
  let parts = [
    RateLimitIdentityPart::ClientIpPrefix,
    RateLimitIdentityPart::UserAgent,
    RateLimitIdentityPart::TlsFingerprint,
    RateLimitIdentityPart::Asn,
  ];
  let check = RateLimitCheck {
    identity_parts: &parts,
    ..rate_limit_check(RateLimitKey::CompositeClientRoute)
  };
  let context = RateLimitContext::route(first_ip, "app", "/same", &headers)
    .with_tls_fingerprint(Some("tls-secret"))
    .with_client_asn(Some(64500));
  let same = rate_limit_key(context, &check);
  let repeat = rate_limit_key(context, &check);
  assert_eq!(same, repeat);
  assert!(same.starts_with("composite_client_route:hash:"));
  assert!(!same.contains("unit-test-agent"));
  assert!(!same.contains("tls-secret"));
  assert!(!same.contains("AS64500"));

  let mut other_headers = HeaderMap::new();
  other_headers.insert(http::header::USER_AGENT, "other-agent".parse().unwrap());
  let changed = rate_limit_key(
    RateLimitContext::route(first_ip, "app", "/same", &other_headers)
      .with_tls_fingerprint(Some("tls-secret"))
      .with_client_asn(Some(64500)),
    &check,
  );
  assert_ne!(same, changed);

  let missing_headers = HeaderMap::new();
  let missing_parts = [RateLimitIdentityPart::UserAgent];
  let missing_check = RateLimitCheck {
    identity_parts: &missing_parts,
    ..rate_limit_check(RateLimitKey::CompositeClient)
  };
  let missing_first = rate_limit_key(
    RateLimitContext::route(first_ip, "app", "/same", &missing_headers),
    &missing_check,
  );
  let missing_second = rate_limit_key(
    RateLimitContext::route(second_ip, "app", "/same", &missing_headers),
    &missing_check,
  );
  assert_ne!(missing_first, missing_second);
}

#[test]
fn token_binding_and_person_proof_keys_use_stable_hashes() {
  let ip = "203.0.113.10".parse().unwrap();
  let mut headers = HeaderMap::new();
  headers.insert(http::header::USER_AGENT, "unit-test-agent".parse().unwrap());
  let bindings = [
    PersonProofTokenBinding::UserAgent,
    PersonProofTokenBinding::TlsFingerprint,
    PersonProofTokenBinding::Route,
    PersonProofTokenBinding::DirectPeerIpNetworkPrefix,
  ];
  let binding_check = RateLimitCheck {
    token_bindings: &bindings,
    ..rate_limit_check(RateLimitKey::TokenBindingHashRoute)
  };
  let context =
    RateLimitContext::route(ip, "app", "/same", &headers).with_tls_fingerprint(Some("tls-secret"));
  let binding_key = rate_limit_key(context, &binding_check);
  assert!(binding_key.starts_with("token_binding_hash_route:binding:"));
  assert!(binding_key.ends_with(":app"));
  assert!(!binding_key.contains("unit-test-agent"));
  assert!(!binding_key.contains("tls-secret"));

  let clearance_key = rate_limit_key(
    context.with_person_proof_clearance_hash(Some("abc123")),
    &rate_limit_check(RateLimitKey::PersonProofClearanceRoute),
  );
  assert_eq!(
    clearance_key,
    "person_proof_clearance_route:clearance:abc123:app"
  );
  let fallback_key = rate_limit_key(
    context,
    &rate_limit_check(RateLimitKey::PersonProofClearance),
  );
  assert_eq!(
    fallback_key,
    "person_proof_clearance:fallback_ip:203.0.113.10"
  );
}

#[test]
fn asn_keys_bucket_by_asn_and_fallback_to_ip() {
  let first_ip = "203.0.113.10".parse().unwrap();
  let second_ip = "198.51.100.20".parse().unwrap();
  let headers = HeaderMap::new();
  let check = rate_limit_check(RateLimitKey::AsnRoute);

  let first = rate_limit_key(
    RateLimitContext::route(first_ip, "app", "/same", &headers).with_client_asn(Some(64500)),
    &check,
  );
  let second = rate_limit_key(
    RateLimitContext::route(second_ip, "app", "/same", &headers).with_client_asn(Some(64500)),
    &check,
  );
  let fallback = rate_limit_key(
    RateLimitContext::route(first_ip, "app", "/same", &headers),
    &check,
  );
  assert_eq!(first, "asn_route:AS64500:app");
  assert_eq!(first, second);
  assert_eq!(fallback, "asn_route:fallback_ip:203.0.113.10:app");
}

#[test]
fn shared_state_keeps_new_bucket_keys_stable_across_instances() {
  let shared = SharedState::test_memory("limit-prefix-test");
  let first = LimitState::new(Some(shared.clone()));
  let second = LimitState::new(Some(shared));
  let first_ip = "203.0.113.10".parse().unwrap();
  let second_ip = "203.0.113.200".parse().unwrap();
  let headers = HeaderMap::new();
  let limit = [RateLimitConfig {
    name: "shared-prefix".to_string(),
    key: RateLimitKey::ClientIpPrefix,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("shared-prefix", RateLimitKey::ClientIpPrefix)
  }];

  assert_eq!(
    first.check_route_rate_limits(
      RateLimitContext::route(first_ip, "app", "/same", &headers),
      &limit,
    ),
    None
  );
  assert_eq!(
    second.check_route_rate_limits(
      RateLimitContext::route(second_ip, "app", "/same", &headers),
      &limit,
    ),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}
