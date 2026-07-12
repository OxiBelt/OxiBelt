use super::*;
use crate::config::{BackendFailureMode, LimitKey, SharedStateFailurePolicies};
use std::time::Duration;

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

fn rate_limit_check<'a>(key: RateLimitKey, token_header: Option<&'a str>) -> RateLimitCheck<'a> {
  RateLimitCheck {
    name: "test",
    key,
    token_header,
    access_token_source: key
      .uses_access_token()
      .then_some(if token_header.is_some() {
        AccessTokenRateLimitSource::TrustedHeader
      } else {
        AccessTokenRateLimitSource::TrustedAuthorizationBearer
      }),
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
fn parses_rates() {
  assert!((parse_rate("10r/s").unwrap().per_second - 10.0).abs() < f64::EPSILON);
  assert!((parse_rate("60r/m").unwrap().per_second - 1.0).abs() < f64::EPSILON);
  assert!(parse_rate("10/s").is_err());
}

#[test]
fn split_connection_permits_release_independent_scopes() {
  let state = LimitState::new(None);
  let ip = "203.0.113.10".parse().unwrap();
  let other_ip = "203.0.113.11".parse().unwrap();
  let limits = LimitsConfig {
    max_connections: 1,
    max_connections_per_ip: 1,
    ..LimitsConfig::default()
  };

  let total = state.acquire_global_connection(&limits).unwrap();
  assert_eq!(
    state.acquire_global_connection(&limits).err(),
    Some(StatusCode::SERVICE_UNAVAILABLE)
  );
  let ip_permit = state.acquire_ip_connection(ip, &limits, &[]).unwrap();
  assert_eq!(
    state.acquire_ip_connection(ip, &limits, &[]).err(),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  let _other_ip_permit = state.acquire_ip_connection(other_ip, &limits, &[]).unwrap();
  drop(ip_permit);
  drop(total);
  assert!(state.acquire_global_connection(&limits).is_ok());
}

#[test]
fn split_connection_permits_enforce_named_limits_per_ip() {
  let state = LimitState::new(None);
  let ip = "203.0.113.10".parse().unwrap();
  let limits = LimitsConfig {
    max_connections: 10,
    max_connections_per_ip: 10,
    ..LimitsConfig::default()
  };
  let named = [ConnectionLimitConfig {
    name: "per-client".to_string(),
    key: LimitKey::ClientIp,
    limit: 1,
    status: 409,
  }];

  let permit = state.acquire_ip_connection(ip, &limits, &named).unwrap();
  assert_eq!(
    state.acquire_ip_connection(ip, &limits, &named).err(),
    Some(StatusCode::CONFLICT)
  );
  drop(permit);
  assert!(state.acquire_ip_connection(ip, &limits, &named).is_ok());
}

#[tokio::test]
async fn shared_state_enforces_rate_and_connection_limits_across_instances() {
  let shared = SharedState::test_memory("limit-test");
  let first = LimitState::new(Some(shared.clone()));
  let second = LimitState::new(Some(shared));
  let ip = "203.0.113.10".parse().unwrap();
  let rate_limits = [RateLimitConfig {
    name: "per-ip".to_string(),
    key: RateLimitKey::ClientIp,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("per-ip", RateLimitKey::ClientIp)
  }];

  assert_eq!(first.check_rate_limits_async(ip, &rate_limits).await, None);
  assert_eq!(
    second.check_rate_limits_async(ip, &rate_limits).await,
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  let limits = LimitsConfig {
    max_connections: 1,
    max_connections_per_ip: 1,
    ..LimitsConfig::default()
  };
  let mut total = first
    .acquire_global_connection_async(&limits)
    .await
    .unwrap();
  assert_eq!(
    second.acquire_global_connection_async(&limits).await.err(),
    Some(StatusCode::SERVICE_UNAVAILABLE)
  );
  let mut second_ip_permit = second
    .acquire_ip_connection_async(ip, &limits, &[])
    .await
    .unwrap();
  second_ip_permit.release().await;
  total.release().await;
  let mut ip_permit = first
    .acquire_ip_connection_async(ip, &limits, &[])
    .await
    .unwrap();
  assert_eq!(
    second
      .acquire_ip_connection_async(ip, &limits, &[])
      .await
      .err(),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  ip_permit.release().await;
  assert!(
    second
      .acquire_global_connection_async(&limits)
      .await
      .is_ok()
  );
}

#[tokio::test]
async fn shared_failure_local_fallback_is_bounded_and_recovers_without_replaying_state() {
  let policies = SharedStateFailurePolicies {
    rate_limits: BackendFailureMode::LocalFallback,
    connection_limits: BackendFailureMode::LocalFallback,
    ..SharedStateFailurePolicies::default()
  };
  let shared = SharedState::test_memory_with_failure_policies("limit-local-fallback", policies);
  let state = LimitState::new(Some(shared.clone()));
  let ip = "203.0.113.10".parse().unwrap();
  let rate_limits = [rate_limit_config("fallback-rate", RateLimitKey::ClientIp)];

  shared.test_fail_next_rate_limit();
  assert_eq!(state.check_rate_limits_async(ip, &rate_limits).await, None);
  assert_eq!(shared.backend_failure_status(), "degraded");

  // The second injected backend failure uses the already-consumed bounded
  // process-local token rather than replaying the failed distributed take.
  shared.test_fail_next_rate_limit();
  assert_eq!(
    state.check_rate_limits_async(ip, &rate_limits).await,
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  // A fresh backend decision recovers the feature independently of the local
  // fallback bucket and clears the degraded status.
  assert_eq!(state.check_rate_limits_async(ip, &rate_limits).await, None);
  assert_eq!(shared.backend_failure_status(), "healthy");

  let limits = LimitsConfig {
    max_connections: 1,
    max_connections_per_ip: 1,
    ..LimitsConfig::default()
  };
  shared.test_fail_next_connection_limit();
  let local_permit = state
    .acquire_global_connection_async(&limits)
    .await
    .expect("local fallback should admit the first bounded connection");
  drop(local_permit);

  // The fallback permit never acquired a shared lease, so a recovered backend
  // can admit exactly one fresh shared lease without a stale double count.
  let mut shared_permit = state
    .acquire_global_connection_async(&limits)
    .await
    .expect("recovered backend should admit a fresh lease");
  shared_permit.release().await;

  // Exercise every remaining policy through a deterministic failed token
  // operation. Stale/reject modes remain conservative because the operation
  // may have consumed a token before its failure was observed.
  for (mode, expected) in [
    (
      BackendFailureMode::FailClosed,
      Some(StatusCode::SERVICE_UNAVAILABLE),
    ),
    (BackendFailureMode::FailOpen, None),
    (
      BackendFailureMode::StaleSnapshot,
      Some(StatusCode::SERVICE_UNAVAILABLE),
    ),
    (
      BackendFailureMode::RejectNewOnly,
      Some(StatusCode::SERVICE_UNAVAILABLE),
    ),
  ] {
    let shared = SharedState::test_memory_with_failure_policies(
      &format!("limit-policy-{}", mode.as_str()),
      SharedStateFailurePolicies {
        rate_limits: mode,
        ..SharedStateFailurePolicies::default()
      },
    );
    let state = LimitState::new(Some(shared.clone()));
    shared.test_fail_next_rate_limit();
    assert_eq!(
      state.check_rate_limits_async(ip, &rate_limits).await,
      expected
    );
    assert_eq!(shared.backend_failure_status(), "degraded");
  }

  // `reject_new_only` never disturbs an acquired lease and recovery creates a
  // single fresh lease after the original holder releases it.
  let shared = SharedState::test_memory("limit-reject-new-only");
  let state = LimitState::new(Some(shared.clone()));
  let mut existing = state
    .acquire_global_connection_async(&limits)
    .await
    .expect("initial shared lease should be acquired");
  shared.test_fail_next_connection_limit();
  assert_eq!(
    state.acquire_global_connection_async(&limits).await.err(),
    Some(StatusCode::SERVICE_UNAVAILABLE)
  );
  existing.release().await;
  let mut recovered = state
    .acquire_global_connection_async(&limits)
    .await
    .expect("recovered backend should create one new lease");
  recovered.release().await;
}

#[tokio::test]
async fn dropped_shared_connection_permit_uses_bounded_deferred_cleanup() {
  let shared = SharedState::test_memory("limit-deferred-release");
  let first = LimitState::new(Some(shared.clone()));
  let second = LimitState::new(Some(shared));
  let limits = LimitsConfig {
    max_connections: 1,
    ..LimitsConfig::default()
  };

  drop(
    first
      .acquire_global_connection_async(&limits)
      .await
      .unwrap(),
  );

  tokio::time::timeout(Duration::from_millis(100), async {
    loop {
      if let Ok(mut permit) = second.acquire_global_connection_async(&limits).await {
        permit.release().await;
        break;
      }
      tokio::task::yield_now().await;
    }
  })
  .await
  .expect("deferred shared connection cleanup should release the lease");
}

#[test]
fn route_and_path_rate_limit_keys_are_isolated() {
  let state = LimitState::new(None);
  let ip = "203.0.113.10".parse().unwrap();
  let headers = HeaderMap::new();
  let route_limit = [RateLimitConfig {
    name: "per-route".to_string(),
    key: RateLimitKey::ClientIpRoute,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("per-route", RateLimitKey::ClientIpRoute)
  }];
  let app = RateLimitContext::route(ip, "app", "/same", &headers);
  let admin = RateLimitContext::route(ip, "admin", "/same", &headers);

  assert_eq!(state.check_route_rate_limits(app, &route_limit), None);
  assert_eq!(
    state.check_route_rate_limits(app, &route_limit),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  assert_eq!(state.check_route_rate_limits(admin, &route_limit), None);

  let path_limit = [RateLimitConfig {
    name: "per-path".to_string(),
    key: RateLimitKey::ClientIpPath,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("per-path", RateLimitKey::ClientIpPath)
  }];
  let first_path = RateLimitContext::route(ip, "app", "/first", &headers);
  let second_path = RateLimitContext::route(ip, "app", "/second", &headers);

  assert_eq!(state.check_route_rate_limits(first_path, &path_limit), None);
  assert_eq!(
    state.check_route_rate_limits(first_path, &path_limit),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  assert_eq!(
    state.check_route_rate_limits(second_path, &path_limit),
    None
  );
}

#[test]
fn global_rate_limit_key_is_shared_across_ips() {
  let state = LimitState::new(None);
  let first_ip = "203.0.113.10".parse().unwrap();
  let second_ip = "203.0.113.11".parse().unwrap();
  let limit = [RateLimitConfig {
    name: "global".to_string(),
    key: RateLimitKey::Global,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("global", RateLimitKey::Global)
  }];

  assert_eq!(state.check_pre_route_rate_limits(first_ip, &limit), None);
  assert_eq!(
    state.check_pre_route_rate_limits(second_ip, &limit),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}

#[test]
fn route_rate_limit_key_is_shared_by_route_not_ip() {
  let state = LimitState::new(None);
  let first_ip = "203.0.113.10".parse().unwrap();
  let second_ip = "203.0.113.11".parse().unwrap();
  let headers = HeaderMap::new();
  let limit = [RateLimitConfig {
    name: "per-route".to_string(),
    key: RateLimitKey::Route,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("per-route", RateLimitKey::Route)
  }];

  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(first_ip, "app", "/first", &headers),
      &limit
    ),
    None
  );
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(second_ip, "app", "/second", &headers),
      &limit
    ),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(second_ip, "admin", "/first", &headers),
      &limit
    ),
    None
  );
}

#[test]
fn route_filtered_global_rate_limit_runs_after_route_match() {
  let state = LimitState::new(None);
  let ip = "203.0.113.10".parse().unwrap();
  let headers = HeaderMap::new();
  let limit = [RateLimitConfig {
    name: "filtered-global".to_string(),
    key: RateLimitKey::Global,
    routes: vec!["app".to_string()],
    token_header: None,
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("filtered-global", RateLimitKey::Global)
  }];

  assert_eq!(state.check_pre_route_rate_limits(ip, &limit), None);
  assert_eq!(state.rates.lock().unwrap().len(), 0);
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(ip, "admin", "/same", &headers),
      &limit
    ),
    None
  );
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(ip, "app", "/same", &headers),
      &limit
    ),
    None
  );
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(ip, "app", "/other", &headers),
      &limit
    ),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}

#[test]
fn access_token_keys_hash_tokens_and_fallback_to_ip() {
  let ip = "203.0.113.10".parse().unwrap();
  let mut headers = HeaderMap::new();
  headers.insert(AUTHORIZATION, "Bearer bearer-secret".parse().unwrap());
  headers.insert("x-api-token", "header-secret".parse().unwrap());
  let context = RateLimitContext::route(ip, "app", "/tokens", &headers);

  let bearer_key = rate_limit_key(context, &rate_limit_check(RateLimitKey::AccessToken, None));
  assert!(bearer_key.starts_with("access_token:token:"));
  assert!(!bearer_key.contains("bearer-secret"));
  assert!(!bearer_key.contains("header-secret"));

  let header_key = rate_limit_key(
    context,
    &rate_limit_check(RateLimitKey::AccessTokenRoute, Some("X-Api-Token")),
  );
  assert!(header_key.starts_with("access_token_route:token:"));
  assert!(header_key.ends_with(":app"));
  assert!(!header_key.contains("bearer-secret"));
  assert!(!header_key.contains("header-secret"));
  assert_ne!(bearer_key, header_key);

  let mut changed_bearer = headers.clone();
  changed_bearer.insert(
    AUTHORIZATION,
    "Bearer random-attacker-token".parse().unwrap(),
  );
  let changed_bearer_context = RateLimitContext::route(ip, "app", "/tokens", &changed_bearer);
  assert_eq!(
    header_key,
    rate_limit_key(
      changed_bearer_context,
      &rate_limit_check(RateLimitKey::AccessTokenRoute, Some("X-Api-Token")),
    )
  );

  let empty_headers = HeaderMap::new();
  let fallback_context = RateLimitContext::route(ip, "app", "/tokens", &empty_headers);
  assert_eq!(
    rate_limit_key(
      fallback_context,
      &rate_limit_check(RateLimitKey::AccessTokenPath, Some("X-Api-Token")),
    ),
    "access_token_path:fallback_ip:203.0.113.10:/tokens"
  );
}

#[test]
fn access_token_rate_limits_are_isolated_by_token_and_fallback_ip() {
  let state = LimitState::new(None);
  let ip = "203.0.113.10".parse().unwrap();
  let limit = [RateLimitConfig {
    name: "per-token".to_string(),
    key: RateLimitKey::AccessToken,
    routes: Vec::new(),
    token_header: None,
    access_token_source: Some(AccessTokenRateLimitSource::TrustedAuthorizationBearer),
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("per-token", RateLimitKey::AccessToken)
  }];
  let mut token_a = HeaderMap::new();
  token_a.insert(AUTHORIZATION, "Bearer token-a".parse().unwrap());
  let mut token_b = HeaderMap::new();
  token_b.insert(AUTHORIZATION, "Bearer token-b".parse().unwrap());
  let token_a_context = RateLimitContext::route(ip, "app", "/tokens", &token_a);
  let token_b_context = RateLimitContext::route(ip, "app", "/tokens", &token_b);

  assert_eq!(state.check_route_rate_limits(token_a_context, &limit), None);
  assert_eq!(
    state.check_route_rate_limits(token_a_context, &limit),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  assert_eq!(state.check_route_rate_limits(token_b_context, &limit), None);

  let fallback_state = LimitState::new(None);
  let empty_headers = HeaderMap::new();
  let fallback_context = RateLimitContext::route(ip, "app", "/tokens", &empty_headers);
  assert_eq!(
    fallback_state.check_route_rate_limits(fallback_context, &limit),
    None
  );
  assert_eq!(
    fallback_state.check_route_rate_limits(fallback_context, &limit),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}

#[test]
fn local_rate_limit_rejects_new_bucket_when_max_buckets_exhausted() {
  let state = LimitState::new(None);
  let ip = "203.0.113.10".parse().unwrap();
  let limit = [RateLimitConfig {
    name: "per-token".to_string(),
    key: RateLimitKey::AccessToken,
    routes: Vec::new(),
    token_header: None,
    access_token_source: Some(AccessTokenRateLimitSource::TrustedAuthorizationBearer),
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: 1,
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("per-token", RateLimitKey::AccessToken)
  }];
  let mut token_a = HeaderMap::new();
  token_a.insert(AUTHORIZATION, "Bearer token-a".parse().unwrap());
  let mut token_b = HeaderMap::new();
  token_b.insert(AUTHORIZATION, "Bearer token-b".parse().unwrap());

  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(ip, "app", "/tokens", &token_a),
      &limit
    ),
    None
  );
  assert_eq!(state.rates.lock().unwrap().len(), 1);
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(ip, "app", "/tokens", &token_b),
      &limit
    ),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  assert_eq!(state.rates.lock().unwrap().len(), 1);
}

#[test]
fn local_rate_limit_monitor_mode_does_not_grow_after_bucket_cap() {
  let state = LimitState::new(None);
  let ip = "203.0.113.10".parse().unwrap();
  let limit = [RateLimitConfig {
    name: "per-token-monitor".to_string(),
    key: RateLimitKey::AccessToken,
    routes: Vec::new(),
    token_header: None,
    access_token_source: Some(AccessTokenRateLimitSource::TrustedAuthorizationBearer),
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: 1,
    mode: LimitMode::Monitor,
    status: 429,
    ..rate_limit_config("per-token-monitor", RateLimitKey::AccessToken)
  }];
  let mut token_a = HeaderMap::new();
  token_a.insert(AUTHORIZATION, "Bearer token-a".parse().unwrap());
  let mut token_b = HeaderMap::new();
  token_b.insert(AUTHORIZATION, "Bearer token-b".parse().unwrap());

  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(ip, "app", "/tokens", &token_a),
      &limit
    ),
    None
  );
  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(ip, "app", "/tokens", &token_b),
      &limit
    ),
    None
  );
  assert_eq!(state.rates.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn shared_rate_limit_rejects_new_bucket_when_max_buckets_exhausted() {
  let shared = SharedState::test_memory("shared-rate-bucket-cap");
  let first = LimitState::new(Some(shared.clone()));
  let second = LimitState::new(Some(shared));
  let ip = "203.0.113.10".parse().unwrap();
  let limit = [RateLimitConfig {
    name: "per-token-shared".to_string(),
    key: RateLimitKey::AccessToken,
    routes: Vec::new(),
    token_header: None,
    access_token_source: Some(AccessTokenRateLimitSource::TrustedAuthorizationBearer),
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: 1,
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("per-token-shared", RateLimitKey::AccessToken)
  }];
  let mut token_a = HeaderMap::new();
  token_a.insert(AUTHORIZATION, "Bearer token-a".parse().unwrap());
  let mut token_b = HeaderMap::new();
  token_b.insert(AUTHORIZATION, "Bearer token-b".parse().unwrap());
  let mut token_c = HeaderMap::new();
  token_c.insert(AUTHORIZATION, "Bearer token-c".parse().unwrap());

  assert_eq!(
    first
      .check_route_rate_limits_async(
        RateLimitContext::route(ip, "app", "/tokens", &token_a),
        &limit
      )
      .await,
    None
  );
  assert_eq!(
    second
      .check_route_rate_limits_async(
        RateLimitContext::route(ip, "app", "/tokens", &token_b),
        &limit
      )
      .await,
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  std::thread::sleep(Duration::from_millis(650));
  assert_eq!(
    second
      .check_route_rate_limits_async(
        RateLimitContext::route(ip, "app", "/tokens", &token_c),
        &limit
      )
      .await,
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}

#[test]
fn local_rate_limit_prunes_refilled_buckets_before_enforcing_cap() {
  let state = LimitState::new(None);
  let ip = "203.0.113.10".parse().unwrap();
  let headers = HeaderMap::new();
  let limit = [RateLimitConfig {
    name: "per-path".to_string(),
    key: RateLimitKey::ClientIpPath,
    routes: Vec::new(),
    token_header: None,
    rate: "1r/s".to_string(),
    burst: 1,
    max_buckets: 1,
    mode: LimitMode::Enforcing,
    status: 429,
    ..rate_limit_config("per-path", RateLimitKey::ClientIpPath)
  }];

  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(ip, "app", "/first", &headers),
      &limit
    ),
    None
  );
  {
    let mut buckets = state.rates.lock().unwrap();
    for bucket in buckets.values_mut() {
      bucket.last = bucket.last.checked_sub(Duration::from_secs(2)).unwrap();
    }
  }

  assert_eq!(
    state.check_route_rate_limits(
      RateLimitContext::route(ip, "app", "/second", &headers),
      &limit
    ),
    None
  );
  let buckets = state.rates.lock().unwrap();
  assert_eq!(buckets.len(), 1);
  assert!(buckets.keys().any(|(_, key)| key.ends_with(":/second")));
}
