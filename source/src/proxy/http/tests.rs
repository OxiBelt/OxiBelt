mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use pretty_assertions::assert_eq;

use super::*;
use crate::config::Config;
use crate::waf::HeaderMutation;

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

#[test]
fn uri_wire_len_matches_display_length_without_allocating_in_hot_path() {
  let mut authority_parts = http::uri::Parts::default();
  authority_parts.authority = Some(http::uri::Authority::from_static("example.com:443"));
  let authority_form = http::Uri::from_parts(authority_parts).expect("authority URI should build");
  let uris = [
    http::Uri::from_static("/"),
    http::Uri::from_static("/perf/h3?body=ok"),
    http::Uri::from_static("https://example.com/perf/h3?body=ok"),
    http::Uri::from_static("http://example.com"),
    authority_form,
  ];

  for uri in uris {
    assert_eq!(uri_wire_len(&uri), uri.to_string().len(), "{uri}");
  }
}

#[test]
fn request_limits_reject_ambiguous_body_framing() {
  let limits = crate::config::LimitsConfig::default();
  let mut duplicate_content_length = Request::builder()
    .uri("/")
    .body(())
    .expect("request should build");
  duplicate_content_length
    .headers_mut()
    .append(http::header::CONTENT_LENGTH, "0".parse().unwrap());
  duplicate_content_length
    .headers_mut()
    .append(http::header::CONTENT_LENGTH, "0".parse().unwrap());

  assert_eq!(
    validate_request_limits(&duplicate_content_length, &limits),
    Err((StatusCode::BAD_REQUEST, "ambiguous request body framing"))
  );

  let te_and_cl = Request::builder()
    .uri("/")
    .header(http::header::TRANSFER_ENCODING, "chunked")
    .header(http::header::CONTENT_LENGTH, "7")
    .body(())
    .expect("request should build");

  assert_eq!(
    validate_request_limits(&te_and_cl, &limits),
    Err((StatusCode::BAD_REQUEST, "ambiguous request body framing"))
  );
}

#[test]
fn request_limits_reject_invalid_content_length() {
  let limits = crate::config::LimitsConfig::default();
  let invalid = Request::builder()
    .uri("/")
    .header(http::header::CONTENT_LENGTH, "abc")
    .body(())
    .expect("request should build");

  assert_eq!(
    validate_request_limits(&invalid, &limits),
    Err((StatusCode::BAD_REQUEST, "invalid request body framing"))
  );
}

#[test]
fn request_limits_apply_body_size_to_single_positive_content_length() {
  let limits = crate::config::LimitsConfig {
    max_request_body_bytes: 6,
    ..crate::config::LimitsConfig::default()
  };
  let too_large = Request::builder()
    .uri("/")
    .header(http::header::CONTENT_LENGTH, "7")
    .body(())
    .expect("request should build");

  assert_eq!(
    validate_request_limits(&too_large, &limits),
    Err((StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"))
  );
}

#[test]
fn forwarded_client_addr_source_selects_resolved_or_direct_peer() {
  let peer_addr = "10.0.0.10:443".parse().unwrap();
  let resolved_addr = "203.0.113.7:443".parse().unwrap();

  assert_eq!(
    select_forwarded_client_addr(
      peer_addr,
      resolved_addr,
      crate::config::ForwardedClientIpSource::Resolved
    ),
    resolved_addr
  );
  assert_eq!(
    select_forwarded_client_addr(
      peer_addr,
      resolved_addr,
      crate::config::ForwardedClientIpSource::DirectPeer
    ),
    peer_addr
  );
}

#[tokio::test]
async fn app_snapshot_precomputes_alt_svc_header_value() {
  let temp_dir = common::TempDir::new("alt-svc-precompute");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "alt-svc-precompute");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "http3 = false",
    "http3 = true\n\n[quic.alt_svc]\nenabled = true\nmax_age_seconds = 60\npersist = true\n\n[quic.socket]\nworkers = \"auto\"\nreuse_port = true",
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");

  assert_eq!(
    state.alt_svc_header_value.as_ref().unwrap(),
    "h3=\":8443\"; ma=60; persist=1"
  );
}

#[test]
fn tunnel_connection_limit_hold_keeps_request_permit_until_drop() {
  let limits = crate::config::LimitsConfig {
    max_connections: 10,
    max_connections_per_ip: 1,
    ..crate::config::LimitsConfig::default()
  };
  let limit_state = crate::limits::LimitState::new(None);
  let ip = "203.0.113.10".parse().unwrap();
  let mut request_permit = Some(
    limit_state
      .acquire_ip_connection(ip, &limits, &[])
      .expect("initial request permit should be acquired"),
  );

  let hold = TunnelConnectionLimitHold::capture(&mut request_permit, None);

  assert!(request_permit.is_none());
  assert_eq!(
    limit_state.acquire_ip_connection(ip, &limits, &[]).err(),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  drop(hold);
  assert!(limit_state.acquire_ip_connection(ip, &limits, &[]).is_ok());
}

#[test]
fn tunnel_connection_limit_hold_keeps_first_request_context_until_drop() {
  let limits = crate::config::LimitsConfig {
    max_connections: 10,
    max_connections_per_ip: 1,
    ..crate::config::LimitsConfig::default()
  };
  let limit_state = crate::limits::LimitState::new(None);
  let ip = "203.0.113.11".parse().unwrap();
  let context = ConnectionLimitContext::default();
  context
    .bind_first_request(ip, |ip| limit_state.acquire_ip_connection(ip, &limits, &[]))
    .expect("first request context should bind");
  let mut request_permit = None;

  let hold = TunnelConnectionLimitHold::capture(&mut request_permit, Some(&context));
  drop(context);

  assert_eq!(
    limit_state.acquire_ip_connection(ip, &limits, &[]).err(),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  drop(hold);
  assert!(limit_state.acquire_ip_connection(ip, &limits, &[]).is_ok());
}

#[test]
fn effective_timeouts_prefer_route_overrides() {
  let temp_dir = common::TempDir::new("effective-timeouts");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "effective-timeouts");
  let raw = format!(
    r#"
{}

[limits]
client_body_timeout_ms = 31000
response_send_timeout_ms = 61000
websocket_idle_timeout_ms = 71000
webtransport_idle_timeout_ms = 81000

[[routes]]
name = "timeout-route"
hosts = ["timeouts.example.com"]
path_prefix = "/timeouts"
upstream = "app"

[routes.timeouts]
client_body_timeout_ms = 15000
response_send_timeout_ms = 30000
websocket_idle_timeout_ms = 60000
webtransport_idle_timeout_ms = 65000
upstream_connect_timeout_ms = 1000
upstream_request_timeout_ms = 15000
upstream_first_byte_timeout_ms = 2000
upstream_read_timeout_ms = 10000
upstream_send_timeout_ms = 11000
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config = parse_config(&raw);
  let route = config
    .routes
    .iter()
    .find(|route| route.name == "timeout-route")
    .expect("route should exist");
  let upstream = &config.upstreams[0];

  let timeouts = EffectiveTimeouts::new(&config, route, upstream);

  assert_eq!(timeouts.response_send, Duration::from_millis(30_000));
  assert_eq!(timeouts.websocket_idle, Duration::from_millis(60_000));
  assert_eq!(timeouts.webtransport_idle, Duration::from_millis(65_000));
  assert_eq!(timeouts.upstream_connect, Duration::from_millis(1_000));
  assert_eq!(timeouts.upstream_first_byte, Duration::from_millis(2_000));
  assert_eq!(timeouts.upstream_read, Duration::from_millis(10_000));
  assert_eq!(timeouts.upstream_send, Duration::from_millis(11_000));
}

#[test]
fn effective_first_byte_timeout_is_capped_by_request_timeout() {
  let temp_dir = common::TempDir::new("first-byte-cap");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "first-byte-cap");
  let raw = format!(
    r#"
{}

[routes.timeouts]
upstream_request_timeout_ms = 1000
upstream_first_byte_timeout_ms = 5000
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config = parse_config(&raw);
  let timeouts = EffectiveTimeouts::new(&config, &config.routes[0], &config.upstreams[0]);

  assert_eq!(timeouts.upstream_first_byte, Duration::from_millis(1_000));
}

#[test]
fn client_grpc_deadline_first_byte_timeout_is_not_pool_health_failure() {
  let caps = semantics::GrpcTimeoutCaps {
    upstream_first_byte: true,
  };

  assert!(!should_report_upstream_request_failure(true, caps));
}

#[test]
fn configured_first_byte_timeout_still_reports_pool_health_failure() {
  assert!(should_report_upstream_request_failure(
    true,
    semantics::GrpcTimeoutCaps::default()
  ));
}

#[test]
fn non_timeout_upstream_error_still_reports_pool_health_failure() {
  let caps = semantics::GrpcTimeoutCaps {
    upstream_first_byte: true,
  };

  assert!(should_report_upstream_request_failure(false, caps));
}

#[test]
fn known_small_response_bypasses_downstream_send_timeout_wrapper() {
  let response = text_response(StatusCode::OK, "ok");
  assert!(
    response
      .extensions()
      .get::<body::KnownSmallResponseBody>()
      .is_some()
  );

  let response =
    with_downstream_response_timeout(response, Duration::from_millis(1), WafTransportNetwork::Tcp);

  assert!(
    response
      .extensions()
      .get::<body::KnownSmallResponseBody>()
      .is_some()
  );
}

#[tokio::test]
async fn pending_dynamic_person_proof_rotation_applies_to_early_text_response() {
  let state = single_use_person_proof_state().await;
  let request = PersonProofRequestFixture::new();
  let clearance = issue_single_use_clearance(&state.waf, &request);
  let mut headers = HeaderMap::new();
  headers.insert(
    http::header::COOKIE,
    format!("__test_person_proof={}", clearance_cookie_value(&clearance))
      .parse()
      .unwrap(),
  );
  let evaluated = state
    .waf
    .evaluate_person_proof_request(request.input(&headers));

  let response = with_pending_dynamic_person_proof_response_mutations(
    text_response(StatusCode::TOO_MANY_REQUESTS, "blocked"),
    &state,
    Some(&evaluated),
    false,
    &[],
  );

  assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
  let rotated = response_set_cookie(&response);
  assert!(rotated.contains("__test_person_proof=clearance.v2."));
  assert_ne!(clearance_cookie_value(&clearance), cookie_value(&rotated));
}

#[tokio::test]
async fn pending_dynamic_person_proof_rotation_applies_to_redirect_without_duplicate() {
  let state = single_use_person_proof_state().await;
  let request = PersonProofRequestFixture::new();
  let clearance = issue_single_use_clearance(&state.waf, &request);
  let mut headers = HeaderMap::new();
  headers.insert(
    http::header::COOKIE,
    format!("__test_person_proof={}", clearance_cookie_value(&clearance))
      .parse()
      .unwrap(),
  );
  let evaluated = state
    .waf
    .evaluate_person_proof_request(request.input(&headers));
  let existing = HeaderMutation::Append {
    name: http::header::SET_COOKIE,
    value: "__test_person_proof=already; Path=/".parse().unwrap(),
  };
  let mut redirect = text_response(StatusCode::TEMPORARY_REDIRECT, "");
  redirect
    .headers_mut()
    .insert(http::header::LOCATION, "/next".parse().unwrap());

  let response = with_pending_dynamic_person_proof_response_mutations(
    redirect,
    &state,
    Some(&evaluated),
    true,
    std::slice::from_ref(&existing),
  );

  assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
  assert_eq!(
    response.headers().get(http::header::LOCATION).unwrap(),
    "/next"
  );
  let cookies: Vec<_> = response
    .headers()
    .get_all(http::header::SET_COOKIE)
    .iter()
    .collect();
  assert_eq!(cookies.len(), 1);
  assert_eq!(cookies[0], "__test_person_proof=already; Path=/");
}

#[tokio::test]
async fn alt_svc_applies_only_to_https_h1_h2_non_switching_responses() {
  let temp_dir = common::TempDir::new("alt-svc-helper");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "alt-svc-helper");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "http3 = false",
    "http3 = true\n\n[quic.alt_svc]\nenabled = true\nmax_age_seconds = 120\npersist = false\n\n[quic.socket]\nworkers = \"auto\"\nreuse_port = true",
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");

  assert!(should_add_alt_svc(
    StatusCode::OK,
    &state,
    "https",
    http::Version::HTTP_2
  ));
  assert!(!should_add_alt_svc(
    StatusCode::OK,
    &state,
    "https",
    http::Version::HTTP_3
  ));
  assert!(!should_add_alt_svc(
    StatusCode::OK,
    &state,
    "http",
    http::Version::HTTP_2
  ));
  assert!(!should_add_alt_svc(
    StatusCode::SWITCHING_PROTOCOLS,
    &state,
    "https",
    http::Version::HTTP_11
  ));
}

struct PersonProofRequestFixture {
  method: Method,
  uri: http::Uri,
  peer_addr: std::net::SocketAddr,
  tls: WafTlsMetadata,
  tags: HashMap<String, String>,
  dynamic_policy: crate::dynamic_policy::DynamicPolicyContext,
}

impl PersonProofRequestFixture {
  fn new() -> Self {
    Self {
      method: Method::GET,
      uri: "/protected".parse().unwrap(),
      peer_addr: "203.0.113.10:49152".parse().unwrap(),
      tls: WafTlsMetadata::default(),
      tags: HashMap::new(),
      dynamic_policy: crate::dynamic_policy::DynamicPolicyContext::default(),
    }
  }

  fn input<'a>(&'a self, headers: &'a HeaderMap) -> WafRequestInput<'a> {
    WafRequestInput {
      request_id: "request-id",
      transaction_id: "transaction-id",
      received_at_unix_ms: crate::waf::current_unix_ms(),
      method: &self.method,
      uri: &self.uri,
      version: http::Version::HTTP_11,
      headers,
      body: None,
      peer_addr: self.peer_addr,
      client_asn: None,
      downstream_host: "example.com",
      downstream_scheme: "https",
      route_name: "app",
      tcp_max_hop: None,
      tls: &self.tls,
      protocol: WafProtocol::Http,
      transport_network: WafTransportNetwork::Tcp,
      transport_metadata: WafTransportMetadataInput::default(),
      tags: &self.tags,
      dynamic_policy: &self.dynamic_policy,
    }
  }
}

async fn single_use_person_proof_state() -> AppSnapshot {
  let temp_dir = common::TempDir::new("pending-person-proof-rotation");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "pending-person-proof-rotation");
  let raw = format!(
    "{}{}",
    common::minimal_config_toml(&cert_path, &key_path),
    r#"

[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 10
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
clearance.cookie.key = "__test_person_proof"
single_use = true
"#
  );
  AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize")
}

fn issue_single_use_clearance(
  engine: &crate::waf::WafEngine,
  request: &PersonProofRequestFixture,
) -> crate::waf::PersonProofIssuedClearance {
  let headers = HeaderMap::new();
  let decision = engine.evaluate_request(request.input(&headers));
  let challenge = decision
    .terminal
    .as_ref()
    .expect("request should issue Person proof challenge");
  let session = extract_person_proof_session(&challenge.body);
  let verify_path = extract_person_proof_js_const(&challenge.body, "VerifyPath");
  let verify_method = Method::POST;
  let verify_uri: http::Uri = verify_path.parse().expect("verify path should parse");
  let verify_request = WafRequestInput {
    method: &verify_method,
    uri: &verify_uri,
    ..request.input(&headers)
  };
  let provider_challenge = engine
    .begin_person_proof_provider_challenge(verify_request, &verify_path, &session)
    .expect("PoW session should validate")
    .expect("verify path should map to a PoW challenge");
  engine
    .consume_person_proof_provider_challenge_attempt(&provider_challenge)
    .expect("PoW challenge attempt should be consumed");
  engine
    .complete_person_proof_provider_challenge(verify_request, provider_challenge)
    .expect("PoW challenge should complete")
}

fn extract_person_proof_session(body: &str) -> String {
  let marker = "name=\"oxibelt-person-proof-session\" content=\"";
  let start = body
    .find(marker)
    .map(|index| index + marker.len())
    .expect("challenge session marker should exist");
  let end = body[start..]
    .find('"')
    .map(|index| start + index)
    .expect("challenge session should be quoted");
  body[start..end].to_string()
}

fn extract_person_proof_js_const(body: &str, name: &str) -> String {
  let marker = format!("const {name} = '");
  let start = body
    .find(&marker)
    .map(|index| index + marker.len())
    .unwrap_or_else(|| panic!("challenge JS const {name} should exist"));
  let end = body[start..]
    .find('\'')
    .map(|index| start + index)
    .unwrap_or_else(|| panic!("challenge JS const {name} should be quoted"));
  body[start..end].to_string()
}

fn clearance_cookie_value(clearance: &crate::waf::PersonProofIssuedClearance) -> String {
  clearance
    .response_header
    .as_ref()
    .and_then(|mutation| match mutation {
      HeaderMutation::Append { name, value } | HeaderMutation::Set { name, value }
        if name == http::header::SET_COOKIE =>
      {
        value.to_str().ok().map(cookie_value)
      }
      _ => None,
    })
    .expect("cookie clearance should set a response header")
}

fn response_set_cookie(response: &Response<ProxyBody>) -> String {
  response
    .headers()
    .get(http::header::SET_COOKIE)
    .and_then(|value| value.to_str().ok())
    .map(str::to_string)
    .expect("response should include Set-Cookie")
}

fn cookie_value(set_cookie: &str) -> String {
  set_cookie
    .split_once('=')
    .and_then(|(_, value)| value.split_once(';'))
    .map(|(value, _)| value.to_string())
    .expect("Set-Cookie header should contain a cookie value")
}
