use super::*;

fn test_config() -> DynamicPolicyConfig {
  DynamicPolicyConfig::default()
}

fn route_names() -> HashSet<String> {
  HashSet::from(["app-route".to_string()])
}

fn row(id: i64, action: &str, subject_type: &str, subject: &str) -> PolicyRow {
  (
    id,
    100,
    format!("policy-{id}"),
    "test".to_string(),
    action.to_string(),
    subject_type.to_string(),
    subject.to_string(),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    "0".to_string(),
  )
}

fn policy(
  id: i64,
  action: DynamicPolicyAction,
  subject_type: DynamicPolicySubjectType,
  subject: &str,
) -> DynamicPolicy {
  DynamicPolicy {
    id,
    name: format!("policy-{id}"),
    action,
    subject_type,
    subject: subject.to_string(),
    route_name: None,
    method: None,
    path_prefix: None,
    rate: None,
    burst: None,
    status: StatusCode::TOO_MANY_REQUESTS,
    body: "blocked".to_string(),
    reason: Some("test".to_string()),
  }
}

fn snapshot(policies: Vec<DynamicPolicy>) -> DynamicPolicySnapshot {
  DynamicPolicySnapshot {
    generation: 1,
    fingerprint: 1,
    policies: Arc::from(policies),
  }
}

#[test]
fn client_ip_subject_requires_valid_ip() {
  let error = validate_policy_row(
    row(1, "reject", "client_ip", "not-ip"),
    &test_config(),
    &route_names(),
  )
  .expect_err("invalid IP should fail");
  assert!(error.to_string().contains("valid IP address"));
}

#[test]
fn client_ip_path_requires_matching_composite_path() {
  let mut policy = row(1, "reject", "client_ip_path", "203.0.113.10|/identity");
  policy.9 = Some("/identity".to_string());
  let policy =
    validate_policy_row(policy, &test_config(), &route_names()).expect("policy should validate");
  assert_eq!(policy.path_prefix.as_deref(), Some("/identity"));
}

#[test]
fn rate_limit_requires_rate_and_burst() {
  let error = validate_policy_row(
    row(1, "rate_limit", "client_ip", "203.0.113.10"),
    &test_config(),
    &route_names(),
  )
  .expect_err("missing rate and burst should fail");
  assert!(error.to_string().contains("requires rate"));
}

#[test]
fn unknown_route_name_is_rejected() {
  let mut policy = row(1, "reject", "client_ip_route", "203.0.113.10|missing");
  policy.7 = Some("missing".to_string());
  let error = validate_policy_row(policy, &test_config(), &route_names())
    .expect_err("unknown route should fail");
  assert!(error.to_string().contains("unknown route_name"));
}

#[test]
fn oversized_body_is_rejected() {
  let mut policy = row(1, "reject", "client_ip", "203.0.113.10");
  policy.13 = Some("x".repeat(MAX_DYNAMIC_POLICY_BODY_BYTES + 1));
  let error = validate_policy_row(policy, &test_config(), &route_names())
    .expect_err("oversized body should fail");
  assert!(error.to_string().contains("dynamic policy body"));
}

#[test]
fn noncanonical_ipv6_client_ip_rate_limit_subject_canonicalizes_and_matches() {
  let mut policy = row(
    1,
    "rate_limit",
    "client_ip",
    "2001:0DB8:0000:0000:0000:0000:0000:0001",
  );
  policy.10 = Some("1r/h".to_string());
  policy.11 = Some(1);
  let policy =
    validate_policy_row(policy, &test_config(), &route_names()).expect("policy should validate");
  assert_eq!(policy.subject, "2001:db8::1");

  let limits = LimitState::new(None);
  let snapshot = snapshot(vec![policy]);
  let first = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot,
    DynamicPolicyRequest {
      client_ip: "2001:db8::1".parse().unwrap(),
      route_name: "app-route",
      method: &Method::GET,
      path: "/",
    },
    limits.as_ref(),
  );
  let second = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot,
    DynamicPolicyRequest {
      client_ip: "2001:db8::1".parse().unwrap(),
      route_name: "app-route",
      method: &Method::GET,
      path: "/",
    },
    limits.as_ref(),
  );

  assert!(first.context.matched);
  assert!(first.terminal.is_none());
  assert_eq!(
    second.terminal.as_ref().map(|terminal| terminal.status),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}

#[test]
fn noncanonical_ipv6_composite_subjects_canonicalize_and_reject() {
  let mut route_policy = row(
    1,
    "reject",
    "client_ip_route",
    "2001:0DB8:0000:0000:0000:0000:0000:0002|app-route",
  );
  route_policy.7 = Some("app-route".to_string());
  let route_policy = validate_policy_row(route_policy, &test_config(), &route_names())
    .expect("route policy should validate");
  assert_eq!(route_policy.subject, "2001:db8::2|app-route");

  let mut path_policy = row(
    2,
    "reject",
    "client_ip_path",
    "2001:0DB8:0000:0000:0000:0000:0000:0003|/identity",
  );
  path_policy.9 = Some("/identity".to_string());
  let path_policy = validate_policy_row(path_policy, &test_config(), &route_names())
    .expect("path policy should validate");
  assert_eq!(path_policy.subject, "2001:db8::3|/identity");

  let route_outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![route_policy]),
    DynamicPolicyRequest {
      client_ip: "2001:db8::2".parse().unwrap(),
      route_name: "app-route",
      method: &Method::GET,
      path: "/",
    },
    LimitState::new(None).as_ref(),
  );
  assert!(route_outcome.context.matched);
  assert_eq!(
    route_outcome
      .terminal
      .as_ref()
      .map(|terminal| terminal.status),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  let path_outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![path_policy]),
    DynamicPolicyRequest {
      client_ip: "2001:db8::3".parse().unwrap(),
      route_name: "app-route",
      method: &Method::GET,
      path: "/identity/accounts/prelogin",
    },
    LimitState::new(None).as_ref(),
  );
  assert!(path_outcome.context.matched);
  assert_eq!(
    path_outcome
      .terminal
      .as_ref()
      .map(|terminal| terminal.status),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}

#[test]
fn matching_client_ip_path_rejects_request() {
  let mut policy = policy(
    1,
    DynamicPolicyAction::Reject,
    DynamicPolicySubjectType::IpPath,
    "203.0.113.10|/identity",
  );
  policy.path_prefix = Some("/identity".to_string());
  let request = DynamicPolicyRequest {
    client_ip: "203.0.113.10".parse().unwrap(),
    route_name: "app-route",
    method: &Method::GET,
    path: "/identity/accounts/prelogin",
  };
  let outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy]),
    request,
    LimitState::new(None).as_ref(),
  );

  assert!(outcome.context.matched);
  assert_eq!(outcome.context.action.as_deref(), Some("reject"));
  assert_eq!(
    outcome.terminal.as_ref().map(|terminal| terminal.status),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}

#[test]
fn route_name_mismatch_passes() {
  let mut policy = policy(
    1,
    DynamicPolicyAction::Reject,
    DynamicPolicySubjectType::IpRoute,
    "203.0.113.10|admin-route",
  );
  policy.route_name = Some("admin-route".to_string());
  let request = DynamicPolicyRequest {
    client_ip: "203.0.113.10".parse().unwrap(),
    route_name: "app-route",
    method: &Method::GET,
    path: "/identity",
  };
  let outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy]),
    request,
    LimitState::new(None).as_ref(),
  );

  assert!(!outcome.context.matched);
  assert!(outcome.terminal.is_none());
}

#[test]
fn dynamic_rate_limit_denies_after_burst() {
  let mut policy = policy(
    1,
    DynamicPolicyAction::RateLimit,
    DynamicPolicySubjectType::Ip,
    "203.0.113.10",
  );
  policy.rate = Some("1r/h".to_string());
  policy.burst = Some(1);
  let limits = LimitState::new(None);
  let snapshot = snapshot(vec![policy]);

  let first = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot,
    DynamicPolicyRequest {
      client_ip: "203.0.113.10".parse().unwrap(),
      route_name: "app-route",
      method: &Method::GET,
      path: "/",
    },
    limits.as_ref(),
  );
  let second = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot,
    DynamicPolicyRequest {
      client_ip: "203.0.113.10".parse().unwrap(),
      route_name: "app-route",
      method: &Method::GET,
      path: "/",
    },
    limits.as_ref(),
  );

  assert!(first.context.matched);
  assert!(first.terminal.is_none());
  assert_eq!(
    second.terminal.as_ref().map(|terminal| terminal.status),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}
