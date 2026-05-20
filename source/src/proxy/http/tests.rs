mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use pretty_assertions::assert_eq;

use super::*;
use crate::config::Config;

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
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
