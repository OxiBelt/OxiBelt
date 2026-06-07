use super::*;

mod sybil;

fn test_config() -> DynamicPolicyConfig {
  DynamicPolicyConfig::default()
}

fn signed_config() -> DynamicPolicyConfig {
  let mut config = DynamicPolicyConfig::default();
  config.automation_api.enabled = true;
  config.automation_api.require_ttl = true;
  config
}

fn route_names() -> HashSet<String> {
  HashSet::from(["app-route".to_string()])
}

fn row(id: i64, action: &str, subject_type: &str, subject: &str) -> PolicyRow {
  PolicyRow {
    id,
    enabled: true,
    priority: 100,
    name: format!("policy-{id}"),
    source: "test".to_string(),
    action: action.to_string(),
    subject_type: subject_type.to_string(),
    subject: subject.to_string(),
    route_name: None,
    method: None,
    path_prefix: None,
    rate: None,
    burst: None,
    status: None,
    body: None,
    reason: None,
    code: None,
    mode: "enforce".to_string(),
    writer_identity: None,
    signature_version: None,
    row_signature: None,
    expires_at: None,
  }
}

fn policy(
  id: i64,
  action: DynamicPolicyAction,
  subject_type: DynamicPolicySubjectType,
  subject: &str,
) -> DynamicPolicy {
  DynamicPolicy {
    id,
    priority: 100,
    name: format!("policy-{id}"),
    source: "test".to_string(),
    action,
    subject_type,
    subject: subject.to_string(),
    cidr: None,
    route_name: None,
    method: None,
    path_prefix: None,
    rate: None,
    burst: None,
    status: StatusCode::TOO_MANY_REQUESTS,
    body: "blocked".to_string(),
    reason: Some("test".to_string()),
    code: None,
    mode: DynamicPolicyMode::Enforce,
  }
}

fn snapshot(policies: Vec<DynamicPolicy>) -> DynamicPolicySnapshot {
  DynamicPolicySnapshot {
    generation: 1,
    fingerprint: 1,
    policies: Arc::from(policies),
  }
}

fn sign_row(row: &mut PolicyRow, key: &[u8; 32]) {
  row.signature_version = Some(signature::SIGNATURE_VERSION.to_string());
  row.row_signature = Some(signature::sign(
    key,
    &signature::DynamicPolicySignatureFields {
      namespace: "test",
      enabled: row.enabled,
      priority: row.priority,
      name: &row.name,
      source: &row.source,
      action: &row.action,
      subject_type: &row.subject_type,
      subject: &row.subject,
      route_name: row.route_name.as_deref(),
      method: row.method.as_deref(),
      path_prefix: row.path_prefix.as_deref(),
      rate: row.rate.as_deref(),
      burst: row.burst,
      status: row.status,
      body: row.body.as_deref(),
      reason: row.reason.as_deref(),
      code: row.code.as_deref(),
      mode: &row.mode,
      writer_identity: row.writer_identity.as_deref(),
      expires_at: row.expires_at.as_deref(),
    },
  ));
}

fn terminal_status(terminal: &DynamicPolicyTerminal) -> StatusCode {
  match terminal {
    DynamicPolicyTerminal::Text { status, .. } | DynamicPolicyTerminal::Challenge { status } => {
      *status
    }
  }
}

fn request<'a>(client_ip: &str, route_name: &'a str, path: &'a str) -> DynamicPolicyRequest<'a> {
  DynamicPolicyRequest {
    client_ip: client_ip.parse().unwrap(),
    route_name,
    method: &Method::GET,
    path,
    headers: None,
    tls_fingerprint: None,
    client_asn: None,
    tcp_max_hop: None,
    person_proof_clearance_hash: None,
  }
}

fn sybil_request<'a>(headers: &'a HeaderMap, clearance_hash: &'a str) -> DynamicPolicyRequest<'a> {
  DynamicPolicyRequest {
    client_ip: "203.0.113.10".parse().unwrap(),
    route_name: "app-route",
    method: &Method::GET,
    path: "/",
    headers: Some(headers),
    tls_fingerprint: Some("tls-secret"),
    client_asn: Some(64500),
    tcp_max_hop: None,
    person_proof_clearance_hash: Some(clearance_hash),
  }
}

#[test]
fn client_ip_subject_requires_valid_ip() {
  let error = validate_policy_row(
    row(1, "reject", "client_ip", "not-ip"),
    &test_config(),
    "test",
    &route_names(),
    None,
  )
  .expect_err("invalid IP should fail");
  assert!(error.to_string().contains("valid IP address"));
}

#[test]
fn client_ip_path_requires_matching_composite_path() {
  let mut policy = row(1, "reject", "client_ip_path", "203.0.113.10|/identity");
  policy.path_prefix = Some("/identity".to_string());
  let policy = validate_policy_row(policy, &test_config(), "test", &route_names(), None)
    .expect("policy should validate");
  assert_eq!(policy.path_prefix.as_deref(), Some("/identity"));
}

#[test]
fn client_ip_cidr_subject_canonicalizes_and_matches() {
  let policy = validate_policy_row(
    row(1, "reject", "client_ip_cidr", "203.0.113.55/24"),
    &test_config(),
    "test",
    &route_names(),
    None,
  )
  .expect("CIDR policy should validate");
  assert_eq!(policy.subject, "203.0.113.0/24");

  let outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy]),
    request("203.0.113.99", "app-route", "/"),
    LimitState::new(None).as_ref(),
  );

  assert!(outcome.context.matched);
  assert_eq!(
    outcome.terminal.as_ref().map(terminal_status),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}

#[test]
fn rate_limit_requires_rate_and_burst() {
  let error = validate_policy_row(
    row(1, "rate_limit", "client_ip", "203.0.113.10"),
    &test_config(),
    "test",
    &route_names(),
    None,
  )
  .expect_err("missing rate and burst should fail");
  assert!(error.to_string().contains("requires rate"));
}

#[test]
fn challenge_policy_returns_challenge_terminal() {
  let policy = policy(
    1,
    DynamicPolicyAction::Challenge,
    DynamicPolicySubjectType::Ip,
    "203.0.113.10",
  );
  let outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy]),
    request("203.0.113.10", "app-route", "/"),
    LimitState::new(None).as_ref(),
  );

  assert!(outcome.context.matched);
  assert_eq!(outcome.context.action.as_deref(), Some("challenge"));
  assert!(matches!(
    outcome.terminal,
    Some(DynamicPolicyTerminal::Challenge {
      status: StatusCode::TOO_MANY_REQUESTS
    })
  ));
}

#[test]
fn challenge_rows_default_to_forbidden_and_reject_unsupported_fields() {
  let challenge = validate_policy_row(
    row(1, "challenge", "client_ip", "203.0.113.10"),
    &test_config(),
    "test",
    &route_names(),
    None,
  )
  .expect("challenge row should validate");
  assert_eq!(challenge.status, StatusCode::FORBIDDEN);

  let mut with_body = row(2, "challenge", "client_ip", "203.0.113.10");
  with_body.body = Some("not used".to_string());
  let error = validate_policy_row(with_body, &test_config(), "test", &route_names(), None)
    .expect_err("challenge body should fail");
  assert!(error.to_string().contains("does not support body"));

  let mut with_rate = row(3, "challenge", "client_ip", "203.0.113.10");
  with_rate.rate = Some("1r/s".to_string());
  let error = validate_policy_row(with_rate, &test_config(), "test", &route_names(), None)
    .expect_err("challenge rate should fail");
  assert!(error.to_string().contains("does not support rate"));
}

#[test]
fn unknown_route_name_is_rejected() {
  let mut policy = row(1, "reject", "client_ip_route", "203.0.113.10|missing");
  policy.route_name = Some("missing".to_string());
  let error = validate_policy_row(policy, &test_config(), "test", &route_names(), None)
    .expect_err("unknown route should fail");
  assert!(error.to_string().contains("unknown route_name"));
}

#[test]
fn oversized_body_is_rejected() {
  let mut policy = row(1, "reject", "client_ip", "203.0.113.10");
  policy.body = Some("x".repeat(MAX_DYNAMIC_POLICY_BODY_BYTES + 1));
  let error = validate_policy_row(policy, &test_config(), "test", &route_names(), None)
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
  policy.rate = Some("1r/h".to_string());
  policy.burst = Some(1);
  let policy = validate_policy_row(policy, &test_config(), "test", &route_names(), None)
    .expect("policy should validate");
  assert_eq!(policy.subject, "2001:db8::1");

  let limits = LimitState::new(None);
  let snapshot = snapshot(vec![policy]);
  let first = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot,
    request("2001:db8::1", "app-route", "/"),
    limits.as_ref(),
  );
  let second = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot,
    request("2001:db8::1", "app-route", "/"),
    limits.as_ref(),
  );

  assert!(first.context.matched);
  assert!(first.terminal.is_none());
  assert_eq!(
    second.terminal.as_ref().map(terminal_status),
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
  route_policy.route_name = Some("app-route".to_string());
  let route_policy =
    validate_policy_row(route_policy, &test_config(), "test", &route_names(), None)
      .expect("route policy should validate");
  assert_eq!(route_policy.subject, "2001:db8::2|app-route");

  let mut path_policy = row(
    2,
    "reject",
    "client_ip_path",
    "2001:0DB8:0000:0000:0000:0000:0000:0003|/identity",
  );
  path_policy.path_prefix = Some("/identity".to_string());
  let path_policy = validate_policy_row(path_policy, &test_config(), "test", &route_names(), None)
    .expect("path policy should validate");
  assert_eq!(path_policy.subject, "2001:db8::3|/identity");

  let route_outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![route_policy]),
    request("2001:db8::2", "app-route", "/"),
    LimitState::new(None).as_ref(),
  );
  assert!(route_outcome.context.matched);
  assert_eq!(
    route_outcome.terminal.as_ref().map(terminal_status),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  let path_outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![path_policy]),
    request("2001:db8::3", "app-route", "/identity/accounts/prelogin"),
    LimitState::new(None).as_ref(),
  );
  assert!(path_outcome.context.matched);
  assert_eq!(
    path_outcome.terminal.as_ref().map(terminal_status),
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
  let request = request("203.0.113.10", "app-route", "/identity/accounts/prelogin");
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
    outcome.terminal.as_ref().map(terminal_status),
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
  let request = request("203.0.113.10", "app-route", "/identity");
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
    request("203.0.113.10", "app-route", "/"),
    limits.as_ref(),
  );
  let second = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot,
    request("203.0.113.10", "app-route", "/"),
    limits.as_ref(),
  );

  assert!(first.context.matched);
  assert!(first.terminal.is_none());
  assert_eq!(
    second.terminal.as_ref().map(terminal_status),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
}

#[test]
fn route_and_path_specific_allow_precedes_global_reject() {
  let reject = policy(
    1,
    DynamicPolicyAction::Reject,
    DynamicPolicySubjectType::Ip,
    "203.0.113.10",
  );
  let mut allow = policy(
    2,
    DynamicPolicyAction::Allow,
    DynamicPolicySubjectType::Ip,
    "203.0.113.10",
  );
  allow.priority = 500;
  allow.route_name = Some("app-route".to_string());
  allow.path_prefix = Some("/identity".to_string());

  let outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![reject, allow]),
    request("203.0.113.10", "app-route", "/identity/login"),
    LimitState::new(None).as_ref(),
  );

  assert!(outcome.context.matched);
  assert_eq!(outcome.context.action.as_deref(), Some("allow"));
  assert!(outcome.terminal.is_none());
}

#[test]
fn dry_run_reject_records_context_without_terminal_action() {
  let mut policy = policy(
    1,
    DynamicPolicyAction::Reject,
    DynamicPolicySubjectType::Ip,
    "203.0.113.10",
  );
  policy.mode = DynamicPolicyMode::DryRun;
  policy.code = Some("login.block".to_string());

  let outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy]),
    request("203.0.113.10", "app-route", "/"),
    LimitState::new(None).as_ref(),
  );

  assert!(outcome.context.matched);
  assert_eq!(outcome.context.mode.as_deref(), Some("dry_run"));
  assert_eq!(outcome.context.code.as_deref(), Some("login.block"));
  assert!(outcome.terminal.is_none());
}

#[test]
fn automation_api_requires_valid_row_signature() {
  let key = [7_u8; 32];
  let mut row = row(1, "reject", "client_ip", "203.0.113.10");
  row.expires_at = Some("2026-05-10 12:00:00+00".to_string());
  row.writer_identity = Some("security-bot".to_string());
  sign_row(&mut row, &key);

  let policy = validate_policy_row(row, &signed_config(), "test", &route_names(), Some(&key))
    .expect("signed row should validate");
  assert_eq!(policy.source, "test");
}

#[test]
fn automation_api_rejects_tampered_row_signature() {
  let key = [9_u8; 32];
  let mut row = row(1, "reject", "client_ip", "203.0.113.10");
  row.expires_at = Some("2026-05-10 12:00:00+00".to_string());
  row.writer_identity = Some("security-bot".to_string());
  sign_row(&mut row, &key);
  row.subject = "203.0.113.11".to_string();

  let error = validate_policy_row(row, &signed_config(), "test", &route_names(), Some(&key))
    .expect_err("tampered row should fail signature verification");
  assert!(error.to_string().contains("signature verification failed"));
}
