use super::*;
use crate::limits::sybil_identity::{self, SybilIdentityContext};

#[test]
fn client_ip_prefix_route_canonicalizes_and_matches() {
  let mut policy = row(
    1,
    "reject",
    "client_ip_prefix_route",
    "203.0.113.55/24|app-route",
  );
  policy.route_name = Some("app-route".to_string());
  let policy = validate_policy_row(policy, &test_config(), "test", &route_names(), None)
    .expect("prefix route policy should validate");
  assert_eq!(policy.subject, "203.0.113.0/24|app-route");

  let outcome = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy.clone()]),
    request("203.0.113.99", "app-route", "/"),
    LimitState::new(None).as_ref(),
  );
  assert!(outcome.context.matched);

  let route_mismatch = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy]),
    request("203.0.113.99", "other-route", "/"),
    LimitState::new(None).as_ref(),
  );
  assert!(!route_mismatch.context.matched);
}

#[test]
fn hashed_identity_subjects_canonicalize_and_require_identity() {
  let fingerprint_hash = sybil_identity::sha256_hex(b"tls-secret");
  let tls_policy = validate_policy_row(
    row(1, "reject", "tls_fingerprint", &fingerprint_hash),
    &test_config(),
    "test",
    &route_names(),
    None,
  )
  .expect("TLS fingerprint policy should validate");
  assert_eq!(
    tls_policy.subject,
    format!("fingerprint:{fingerprint_hash}")
  );

  let mut matched_request = request("203.0.113.10", "app-route", "/");
  matched_request.tls_fingerprint = Some("tls-secret");
  let matched = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![tls_policy.clone()]),
    matched_request,
    LimitState::new(None).as_ref(),
  );
  assert!(matched.context.matched);

  let missing = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![tls_policy]),
    request("203.0.113.10", "app-route", "/"),
    LimitState::new(None).as_ref(),
  );
  assert!(!missing.context.matched);
}

#[test]
fn asn_route_subject_canonicalizes_and_matches_only_with_asn_lookup() {
  let mut policy = row(1, "reject", "asn_route", "as64500|app-route");
  policy.route_name = Some("app-route".to_string());
  let policy = validate_policy_row(policy, &test_config(), "test", &route_names(), None)
    .expect("ASN route policy should validate");
  assert_eq!(policy.subject, "AS64500|app-route");

  let mut matched_request = request("203.0.113.10", "app-route", "/");
  matched_request.client_asn = Some(64500);
  let matched = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy.clone()]),
    matched_request,
    LimitState::new(None).as_ref(),
  );
  assert!(matched.context.matched);

  let missing_asn = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy]),
    request("203.0.113.10", "app-route", "/"),
    LimitState::new(None).as_ref(),
  );
  assert!(!missing_asn.context.matched);
}

#[test]
fn composite_client_subject_uses_configured_parts() {
  let config = test_config();
  let clearance_hash = sybil_identity::sha256_hex(b"clearance");
  let mut headers = HeaderMap::new();
  headers.insert(http::header::USER_AGENT, "unit-test-agent".parse().unwrap());
  let context = SybilIdentityContext {
    ip: "203.0.113.10".parse().unwrap(),
    route_name: Some("app-route"),
    headers: Some(&headers),
    tls_fingerprint: Some("tls-secret"),
    client_asn: Some(64500),
    tcp_max_hop: None,
    person_proof_clearance_hash: Some(&clearance_hash),
  };
  let subject = sybil_identity::composite_client_identity(context, sybil_spec(&config))
    .expect("composite identity should be available");
  let policy = validate_policy_row(
    row(
      1,
      "reject",
      "composite_client",
      subject.strip_prefix("hash:").unwrap(),
    ),
    &config,
    "test",
    &route_names(),
    None,
  )
  .expect("composite policy should validate");
  assert_eq!(policy.subject, subject);

  let matched = evaluate_snapshot(
    &config,
    Metrics::new().as_ref(),
    &snapshot(vec![policy.clone()]),
    sybil_request(&headers, &clearance_hash),
    LimitState::new(None).as_ref(),
  );
  assert!(matched.context.matched);

  let missing_asn = evaluate_snapshot(
    &config,
    Metrics::new().as_ref(),
    &snapshot(vec![policy]),
    DynamicPolicyRequest {
      client_asn: None,
      ..sybil_request(&headers, &clearance_hash)
    },
    LimitState::new(None).as_ref(),
  );
  assert!(!missing_asn.context.matched);
}

#[test]
fn person_proof_clearance_subject_requires_verified_hash() {
  let clearance_hash = sybil_identity::sha256_hex(b"clearance");
  let policy = validate_policy_row(
    row(1, "reject", "person_proof_clearance", &clearance_hash),
    &test_config(),
    "test",
    &route_names(),
    None,
  )
  .expect("clearance policy should validate");
  assert_eq!(policy.subject, format!("clearance:{clearance_hash}"));

  let mut matched_request = request("203.0.113.10", "app-route", "/");
  matched_request.person_proof_clearance_hash = Some(&clearance_hash);
  let matched = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy.clone()]),
    matched_request,
    LimitState::new(None).as_ref(),
  );
  assert!(matched.context.matched);

  let missing = evaluate_snapshot(
    &test_config(),
    Metrics::new().as_ref(),
    &snapshot(vec![policy]),
    request("203.0.113.10", "app-route", "/"),
    LimitState::new(None).as_ref(),
  );
  assert!(!missing.context.matched);
}

#[test]
fn person_proof_clearance_precheck_uses_request_scope() {
  let clearance_hash = sybil_identity::sha256_hex(b"clearance");
  let mut row = row(1, "reject", "person_proof_clearance", &clearance_hash);
  row.route_name = Some("app-route".to_string());
  row.method = Some("POST".to_string());
  row.path_prefix = Some("/login".to_string());
  let policy = validate_policy_row(row, &test_config(), "test", &route_names(), None)
    .expect("clearance policy should validate");
  let snapshot = snapshot(vec![policy]);
  let config = test_config();
  let post = Method::POST;
  let get = Method::GET;

  fn scoped_request<'a>(
    method: &'a Method,
    route_name: &'a str,
    path: &'a str,
  ) -> DynamicPolicyRequest<'a> {
    DynamicPolicyRequest {
      client_ip: "203.0.113.10".parse().unwrap(),
      route_name,
      method,
      path,
      headers: None,
      tls_fingerprint: None,
      client_asn: None,
      tcp_max_hop: None,
      person_proof_clearance_hash: None,
    }
  }

  assert!(snapshot.needs_person_proof_clearance_for_request(
    &config,
    scoped_request(&post, "app-route", "/login/session")
  ));
  assert!(!snapshot.needs_person_proof_clearance_for_request(
    &config,
    scoped_request(&get, "app-route", "/login/session")
  ));
  assert!(!snapshot.needs_person_proof_clearance_for_request(
    &config,
    scoped_request(&post, "other-route", "/login/session")
  ));
  assert!(!snapshot.needs_person_proof_clearance_for_request(
    &config,
    scoped_request(&post, "app-route", "/public")
  ));
}

#[test]
fn sybil_subject_rate_limits_deny_after_burst() {
  let config = test_config();
  let clearance_hash = sybil_identity::sha256_hex(b"clearance");
  let mut headers = HeaderMap::new();
  headers.insert(http::header::USER_AGENT, "unit-test-agent".parse().unwrap());
  let context = SybilIdentityContext {
    ip: "203.0.113.10".parse().unwrap(),
    route_name: Some("app-route"),
    headers: Some(&headers),
    tls_fingerprint: Some("tls-secret"),
    client_asn: Some(64500),
    tcp_max_hop: None,
    person_proof_clearance_hash: Some(&clearance_hash),
  };
  let tls_identity = sybil_identity::tls_fingerprint_identity(context).unwrap();
  let token_binding = sybil_identity::token_binding_hash_identity(context, sybil_spec(&config))
    .expect("token binding identity should be available");
  let composite_identity = sybil_identity::composite_client_identity(context, sybil_spec(&config))
    .expect("composite identity should be available");
  let cases = [
    ("client_ip_prefix", "203.0.113.55/24".to_string(), None),
    (
      "client_ip_prefix_route",
      "203.0.113.55/24|app-route".to_string(),
      Some("app-route"),
    ),
    ("tls_fingerprint", tls_identity.clone(), None),
    (
      "tls_fingerprint_route",
      format!("{tls_identity}|app-route"),
      Some("app-route"),
    ),
    ("token_binding_hash", token_binding, None),
    (
      "person_proof_clearance",
      format!("clearance:{clearance_hash}"),
      None,
    ),
    ("asn", "64500".to_string(), None),
    (
      "asn_route",
      "AS64500|app-route".to_string(),
      Some("app-route"),
    ),
    ("composite_client", composite_identity, None),
  ];

  for (index, (subject_type, subject, route_name)) in cases.into_iter().enumerate() {
    let mut policy = row(index as i64 + 1, "rate_limit", subject_type, &subject);
    policy.route_name = route_name.map(str::to_string);
    policy.rate = Some("1r/h".to_string());
    policy.burst = Some(1);
    let policy = validate_policy_row(policy, &config, "test", &route_names(), None)
      .expect("rate-limit policy should validate");
    let limits = LimitState::new(None);
    let snapshot = snapshot(vec![policy]);

    let first = evaluate_snapshot(
      &config,
      Metrics::new().as_ref(),
      &snapshot,
      sybil_request(&headers, &clearance_hash),
      limits.as_ref(),
    );
    let second = evaluate_snapshot(
      &config,
      Metrics::new().as_ref(),
      &snapshot,
      sybil_request(&headers, &clearance_hash),
      limits.as_ref(),
    );

    assert!(first.context.matched, "{subject_type} should match");
    assert!(
      first.terminal.is_none(),
      "{subject_type} first request passes"
    );
    assert_eq!(
      second.terminal.as_ref().map(terminal_status),
      Some(StatusCode::TOO_MANY_REQUESTS),
      "{subject_type} second request should be denied"
    );
  }
}
