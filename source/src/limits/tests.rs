use super::*;
use crate::config::LimitKey;
use std::time::Duration;

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

#[test]
fn shared_state_enforces_rate_and_connection_limits_across_instances() {
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
  }];

  assert_eq!(first.check_rate_limits(ip, &rate_limits), None);
  assert_eq!(
    second.check_rate_limits(ip, &rate_limits),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  let limits = LimitsConfig {
    max_connections: 1,
    max_connections_per_ip: 1,
    ..LimitsConfig::default()
  };
  let total = first.acquire_global_connection(&limits).unwrap();
  assert_eq!(
    second.acquire_global_connection(&limits).err(),
    Some(StatusCode::SERVICE_UNAVAILABLE)
  );
  assert!(second.acquire_ip_connection(ip, &limits, &[]).is_ok());
  drop(total);
  let ip_permit = first.acquire_ip_connection(ip, &limits, &[]).unwrap();
  assert_eq!(
    second.acquire_ip_connection(ip, &limits, &[]).err(),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  drop(ip_permit);
  assert!(second.acquire_global_connection(&limits).is_ok());
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

  let bearer_key = rate_limit_key(context, RateLimitKey::AccessToken, Some("X-Api-Token"));
  assert!(bearer_key.starts_with("access_token:token:"));
  assert!(!bearer_key.contains("bearer-secret"));
  assert!(!bearer_key.contains("header-secret"));

  let mut header_only = HeaderMap::new();
  header_only.insert("x-api-token", "header-secret".parse().unwrap());
  let header_context = RateLimitContext::route(ip, "app", "/tokens", &header_only);
  let header_key = rate_limit_key(
    header_context,
    RateLimitKey::AccessTokenRoute,
    Some("X-Api-Token"),
  );
  assert!(header_key.starts_with("access_token_route:token:"));
  assert!(header_key.ends_with(":app"));
  assert!(!header_key.contains("header-secret"));
  assert_ne!(bearer_key, header_key);

  let empty_headers = HeaderMap::new();
  let fallback_context = RateLimitContext::route(ip, "app", "/tokens", &empty_headers);
  assert_eq!(
    rate_limit_key(
      fallback_context,
      RateLimitKey::AccessTokenPath,
      Some("X-Api-Token"),
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
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: default_rate_limit_max_buckets(),
    mode: LimitMode::Enforcing,
    status: 429,
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
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: 1,
    mode: LimitMode::Enforcing,
    status: 429,
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
    rate: "1r/h".to_string(),
    burst: 1,
    max_buckets: 1,
    mode: LimitMode::Monitor,
    status: 429,
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
