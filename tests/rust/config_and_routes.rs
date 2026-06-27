#[path = "common/mod.rs"]
mod common;

use std::path::Path;

use base64::Engine;
use oxibelt::config::{
  AccessTokenRateLimitSource, AdminTransportMode, BufferingMode, CacheStore,
  ClientIdentityAsnFailurePolicy, ClientIdentityAsnManagedStorage, ClientIdentityAsnMode,
  CompressionConfig, Config, ConnectionLimitIdentityMode, CrliteCoveragePolicy,
  CrliteFailurePolicy, CrliteManagedStorage, CrliteMode, DatabaseMitigationMode, DatabaseTlsMode,
  DnsDiscoveryRecordType, DynamicPolicyFailPolicy, EarlyHintsMode, ErrorResponseMode,
  ExpectContinueMode, ExternalAuthProvider, ExternalCacheHandlerFailPolicy,
  ExternalCacheHandlerKind, ForwardedClientIpSource, ForwardedHeaderMode, GrpcRetryMode,
  HealthCheckProtocol, HotReloadMode, IpmPolicyEffect, KubernetesDiscoveryResource,
  LbPolicyCompatProfile, LoadBalancingAlgorithm, MetricsDetail, MitigationFailurePolicy, OcspMode,
  OutboundOcspMode, PriorityMode, ProxyProtocolEgressMode, ProxyProtocolVersion, QuicZeroRttMode,
  RateLimitIdentityPart, RateLimitKey, RetryCondition, RuntimeOverrides, SharedStateBackendKind,
  SniForwardClientHelloParseMethod, SniForwardProtocol, StaticFilesSendfileMode,
  StaticPrecompressedEncoding, StreamNetwork, TlsKeyExchangeGroup, TlsServerResumptionMode,
  TlsVersion, TrailerMode, UpstreamDiscoveryProvider, UpstreamEchMode, UpstreamTls12ResumptionMode,
  UpstreamTlsResumptionMode, resolve_auto_worker_count,
};
use oxibelt::quic::load_host_key;
use oxibelt::waf::{
  PersonProofTokenBinding, RouteWafHttpBodyCompressionMode, WafHttpBodyCompressionMode,
  WafHttpBodyEncoding, WafMode,
};

fn test_argon2id_hash(secret: &str, memory_kib: u32) -> String {
  use argon2::password_hash::SaltString;
  use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};

  let params = Params::new(memory_kib, 1, 1, None).expect("test Argon2id params should build");
  let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
  let salt =
    SaltString::encode_b64(b"oxibelt-test-salt").expect("test salt should be valid base64 salt");
  argon2
    .hash_password(secret.as_bytes(), &salt)
    .expect("test Argon2id hash should build")
    .to_string()
}

#[test]
fn config_parses_trusted_upstream_ca_certificates() {
  let temp_dir = common::TempDir::new("config");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "config-test");
  let ca_path = temp_dir.path().join("internal-ca.pem");
  std::fs::copy(&cert_path, &ca_path).expect("failed to copy CA certificate");

  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "trusted_ca_certs = []",
    &format!("trusted_ca_certs = [\"{}\"]", ca_path.display()),
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.proxy.trusted_ca_certs, vec![ca_path]);
}

#[test]
fn protocol_operations_defaults_are_disabled() {
  let temp_dir = common::TempDir::new("protocol-defaults");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "protocol-defaults");
  let raw = common::minimal_config_toml(&cert_path, &key_path);

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(!config.proxy.upgrades.generic_http_upgrade);
  assert!(!config.proxy.upgrades.connect_tunneling);
  assert!(!config.proxy.grpc_web.enabled);
  assert!(!config.routes[0].generic_http_upgrade);
  assert!(!config.routes[0].connect_tunneling);
  assert!(!config.routes[0].grpc_web);
  assert_eq!(
    config.upstreams[0].proxy_protocol_egress,
    ProxyProtocolEgressMode::Off
  );
  assert!(config.stream_listeners.is_empty());
  assert!(!config.sni_forward.enabled);
  assert!(config.sni_forward.rules.is_empty());
  assert_eq!(
    config.sni_forward.client_hello_parse_methods,
    vec![SniForwardClientHelloParseMethod::SingleRecord]
  );
}

#[test]
fn netport_switcher_accepts_privileged_data_plane_ports() {
  let temp_dir = common::TempDir::new("netport-switcher-data-plane");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "netport-switcher-data-plane");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace(
      "unprivileged_mode = true",
      r#"unprivileged_mode = true

[runtime.netport_switcher]
enabled = true"#,
    )
    .replace(
      r#"https_bind = "127.0.0.1:8443""#,
      r#"https_bind = "127.0.0.1:443""#,
    )
    .replace(
      "http3 = false",
      r#"http3 = true
http_bind = "127.0.0.1:80"
http_mode = "proxy""#,
    );
  let raw = format!(
    r#"
{raw}

[quic.socket]
reuse_port = true

[[stream_listeners]]
name = "stream-tcp-low"
bind = "127.0.0.1:22"
target = "127.0.0.1:9000"

[[stream_listeners]]
name = "stream-udp-low"
network = "udp"
bind = "127.0.0.1:53"
target = "127.0.0.1:9001"

[[webrtc_turn_listeners]]
name = "turn-low"
mode = "edge_relay"
bind_udp = "127.0.0.1:347"
bind_tcp = "127.0.0.1:348"
bind_tls = "127.0.0.1:349"
realm = "example.test"
public_ip = "127.0.0.1"
relay_bind_ip = "127.0.0.1"

[webrtc_turn_listeners.relay_port_range]
start = 49152
end = 49160

[webrtc_turn_listeners.auth]
mode = "enforce"
rest_shared_secret = "turn-secret"
"#
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("privileged data-plane ports should validate with netport switcher enabled");
}

#[test]
fn privileged_https_port_requires_netport_switcher_in_unprivileged_mode() {
  let temp_dir = common::TempDir::new("netport-switcher-required");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "netport-switcher-required");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    r#"https_bind = "127.0.0.1:8443""#,
    r#"https_bind = "127.0.0.1:443""#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("direct unprivileged privileged HTTPS bind should fail");

  assert!(
    error.to_string().contains("https_bind")
      && error.to_string().contains("requires a privileged port"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn privileged_stream_port_requires_netport_switcher_in_unprivileged_mode() {
  let temp_dir = common::TempDir::new("netport-switcher-stream-required");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "netport-switcher-stream-required");
  let raw = format!(
    r#"
{}

[[stream_listeners]]
name = "ssh"
bind = "127.0.0.1:22"
target = "127.0.0.1:9000"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("direct unprivileged privileged stream bind should fail");

  assert!(
    error.to_string().contains("stream listener ssh")
      && error.to_string().contains("requires a privileged port"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn netport_switcher_does_not_allow_privileged_control_ports() {
  let temp_dir = common::TempDir::new("netport-switcher-control");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "netport-switcher-control");
  let base = common::minimal_config_toml(&cert_path, &key_path).replace(
    "unprivileged_mode = true",
    r#"unprivileged_mode = true

[runtime.netport_switcher]
enabled = true"#,
  );
  for (label, section, expected) in [
    (
      "admin",
      r#"
[admin]
enabled = true
bind = "127.0.0.1:443"
"#,
      "admin.bind",
    ),
    (
      "metrics",
      r#"
[metrics]
enabled = true
bind = "127.0.0.1:443"
"#,
      "metrics.bind",
    ),
    (
      "health",
      r#"
[health]
enabled = true
bind = "127.0.0.1:443"
"#,
      "health.bind",
    ),
  ] {
    let raw = format!("{base}\n{section}");
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .err()
      .unwrap_or_else(|| panic!("{label} low control port should fail"));
    assert!(
      error.to_string().contains(expected)
        && error
          .to_string()
          .contains("does not broker control listeners"),
      "unexpected {label} error: {error:#}"
    );
  }
}

#[test]
fn upstream_pool_default_algorithm_is_power_of_two_choices() {
  let temp_dir = common::TempDir::new("pool-default-algorithm");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "pool-default-algorithm");
  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "app-pool"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(
    config.upstream_pools[0].algorithm,
    LoadBalancingAlgorithm::PowerOfTwoChoices
  );
}

#[test]
fn lb_policy_compat_profile_normalizes_safe_aliases() {
  let temp_dir = common::TempDir::new("lb-policy-compat");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "lb-policy-compat");
  let raw = format!(
    r#"
{}

[config]
lb_policy_compat_profile = "nginx"

[[upstream_pools]]
name = "app-pool"
algorithm = "least_conn"

[upstream_pools.sticky_cookie]
fallback_algorithm = "ip_hash"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"

[[turn_upstream_pools]]
name = "turn-pool"
algorithm = "ip_hash"

[[turn_upstream_pools.servers]]
id = "turn-a"
origin = "turn://turn-a.example:3478"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("compat aliases should parse");

  assert_eq!(
    config.config.lb_policy_compat_profile,
    LbPolicyCompatProfile::Nginx
  );
  assert_eq!(
    config.upstream_pools[0].algorithm,
    LoadBalancingAlgorithm::WeightedLeastConn
  );
  assert_eq!(
    LoadBalancingAlgorithm::from(config.upstream_pools[0].sticky_cookie.fallback_algorithm),
    LoadBalancingAlgorithm::RendezvousIpHash
  );
  assert_eq!(
    config.turn_upstream_pools[0].algorithm,
    LoadBalancingAlgorithm::RendezvousIpHash
  );
}

#[test]
fn lb_policy_compat_profile_rejects_unsafe_aliases_with_guidance() {
  let temp_dir = common::TempDir::new("lb-policy-compat-unsupported");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "lb-policy-compat-unsupported");
  let raw = format!(
    r#"
{}

[config]
lb_policy_compat_profile = "caddy"

[[upstream_pools]]
name = "app-pool"
algorithm = "random"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let error = toml::from_str::<Config>(&raw)
    .expect_err("unsafe compatibility alias should fail with guidance");
  let rendered = error.to_string();
  assert!(
    rendered.contains("unsupported load-balancing compatibility policy")
      && rendered.contains("choose an OxiBelt canonical policy")
      && rendered.contains("upstream_pools[0].algorithm"),
    "unexpected error: {rendered}"
  );
}

#[test]
fn lb_policy_compat_profile_renders_canonical_effective_toml() {
  let temp_dir = common::TempDir::new("lb-policy-compat-effective");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("config dir should be created");
  std::fs::create_dir_all(&cert_dir).expect("cert dir should be created");
  let (cert_path, key_path) =
    common::create_self_signed_cert(&cert_dir, "lb-policy-compat-effective");
  let config_path = config_dir.join("oxibelt.toml");
  let raw = format!(
    r#"
{}

[config]
lb_policy_compat_profile = "nginx"

[[upstream_pools]]
name = "app-pool"
algorithm = "least_connections"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"
"#,
    common::minimal_config_toml_with_paths(
      cert_path.file_name().unwrap().to_str().unwrap(),
      key_path.file_name().unwrap().to_str().unwrap(),
    )
  );
  std::fs::write(&config_path, raw).expect("config fixture should be written");

  let value = Config::load_effective_toml_redacted(&config_path)
    .expect("effective TOML should load with canonicalized policy");

  assert_eq!(
    value["upstream_pools"][0]["algorithm"].as_str(),
    Some("weighted_least_conn")
  );
}

#[test]
fn upstream_pool_slow_start_outlier_and_nomad_discovery_parse() {
  let temp_dir = common::TempDir::new("pool-lb-polish");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "pool-lb-polish");
  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "nomad-pool"

[upstream_pools.slow_start]
enabled = true
duration_ms = 45000
min_weight_percent = 25

[upstream_pools.outlier_ejection]
enabled = true
consecutive_failures = 3
base_ejection_ms = 10000
max_ejection_ms = 60000

[[upstream_pools.discovery]]
provider = "nomad"
endpoint = "https://nomad.example:4646"
namespace = "payments"
service = "api"
filter = "Tags contains \"blue\""
token_env = "NOMAD_TOKEN"
scheme = "https"
watch = true
watch_timeout_seconds = 45
refresh_interval_ms = 1000
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let pool = &config.upstream_pools[0];
  assert!(pool.slow_start.enabled);
  assert_eq!(pool.slow_start.duration_ms, 45_000);
  assert_eq!(pool.slow_start.min_weight_percent, 25);
  assert!(pool.outlier_ejection.enabled);
  assert_eq!(pool.outlier_ejection.consecutive_failures, 3);
  assert_eq!(pool.outlier_ejection.max_ejection_ms, 60_000);
  let discovery = &pool.discovery[0];
  assert_eq!(discovery.provider, UpstreamDiscoveryProvider::Nomad);
  assert_eq!(discovery.namespace.as_deref(), Some("payments"));
  assert_eq!(discovery.service.as_deref(), Some("api"));
  assert_eq!(discovery.token_env.as_deref(), Some("NOMAD_TOKEN"));
  assert!(discovery.watch);
  assert_eq!(discovery.watch_timeout_seconds, 45);
}

#[test]
fn upstream_pool_health_check_http_options_parse_and_validate() {
  let temp_dir = common::TempDir::new("pool-health-options");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "pool-health-options");
  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "app-pool"

[[upstream_pools.servers]]
id = "app-a"
origin = "https://app-a.example"

[upstream_pools.health_check]
enabled = true
mode = "active"
protocol = "http"
method = "POST"
path = "/health"
health_port = 18081
health_host = "health.internal.example"
body = "{{\"probe\":\"ok\"}}"
expected_status = [204]
expected_body_regex = "ready"
body_match_max_bytes = 65536
jitter_ms = 250
rise = 4
fall = 5

[[upstream_pools.health_check.headers]]
name = "X-OxiBelt-Health"
value = "active"

[[upstream_pools.health_check.expected_status_ranges]]
start = 200
end = 299

[upstream_pools.health_check.tls]
trusted_ca_certs = ["upstream-health-ca.pem"]

[upstream_pools.health_check.tls.upstream_revocation.ocsp]
mode = "live_fetch"
failure_policy = "fail_closed"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let health_check = &config.upstream_pools[0].health_check;
  assert_eq!(health_check.protocol, HealthCheckProtocol::Http);
  assert_eq!(health_check.method, "POST");
  assert_eq!(health_check.health_port, Some(18081));
  assert_eq!(
    health_check.health_host.as_deref(),
    Some("health.internal.example")
  );
  assert_eq!(health_check.headers[0].name, "X-OxiBelt-Health");
  assert_eq!(health_check.expected_status, vec![204]);
  assert_eq!(health_check.expected_status_ranges[0].start, 200);
  assert_eq!(health_check.healthy_threshold, 4);
  assert_eq!(health_check.unhealthy_threshold, 5);
  assert_eq!(
    health_check.tls.trusted_ca_certs[0],
    std::path::PathBuf::from("upstream-health-ca.pem")
  );
  assert!(
    health_check
      .tls
      .upstream_revocation
      .as_ref()
      .expect("revocation policy should parse")
      .enabled()
  );
}

#[test]
fn upstream_pool_health_check_rejects_alias_and_canonical_thresholds_together() {
  let temp_dir = common::TempDir::new("pool-health-alias-conflict");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "pool-health-alias-conflict");
  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "app-pool"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"

[upstream_pools.health_check]
healthy_threshold = 2
rise = 3
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  toml::from_str::<Config>(&raw).expect_err("canonical threshold and alias should not both parse");
}

#[test]
fn upstream_pool_health_check_validation_rejects_invalid_http_options() {
  let temp_dir = common::TempDir::new("pool-health-invalid-options");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "pool-health-invalid-options");
  let base = format!(
    r#"
{}

[[upstream_pools]]
name = "app-pool"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"

[upstream_pools.health_check]
enabled = true
mode = "active"
path = "/health"

"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  for (suffix, expected) in [
    (
      r#"
[[upstream_pools.health_check.expected_status_ranges]]
start = 299
end = 200
"#,
      "expected_status_ranges",
    ),
    (
      r#"
expected_body_regex = "["
"#,
      "expected_body_regex",
    ),
    (
      r#"
body_match_max_bytes = 0
"#,
      "body_match_max_bytes",
    ),
    (
      r#"
[[upstream_pools.health_check.headers]]
name = "Host"
value = "example.com"
"#,
      "reserved",
    ),
  ] {
    let config: Config = toml::from_str(&format!("{base}{suffix}")).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid health option should fail");
    assert!(
      error.to_string().contains(expected),
      "expected {expected:?} in error, got {error:#}"
    );
  }
}

#[test]
fn legacy_upstream_pool_algorithms_are_rejected_without_aliases() {
  let temp_dir = common::TempDir::new("legacy-pool-algorithm");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "legacy-pool-algorithm");

  for algorithm in [
    "round_robin",
    "least_conn",
    "least_connections",
    "random",
    "hash",
    "ip_hash",
  ] {
    let raw = format!(
      r#"
{}

[[upstream_pools]]
name = "app-pool"
algorithm = "{algorithm}"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    toml::from_str::<Config>(&raw).expect_err("legacy upstream pool algorithm should not parse");
  }
}

#[test]
fn legacy_sticky_cookie_fallback_algorithms_are_rejected_without_aliases() {
  let temp_dir = common::TempDir::new("legacy-sticky-fallback");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "legacy-sticky-fallback");

  for fallback_algorithm in [
    "round_robin",
    "least_conn",
    "least_connections",
    "random",
    "hash",
    "ip_hash",
  ] {
    let raw = format!(
      r#"
{}

[[upstream_pools]]
name = "app-pool"
algorithm = "sticky_cookie"

[upstream_pools.sticky_cookie]
fallback_algorithm = "{fallback_algorithm}"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    toml::from_str::<Config>(&raw).expect_err("legacy sticky fallback algorithm should not parse");
  }
}

#[test]
fn turn_pool_default_algorithm_is_power_of_two_choices() {
  let temp_dir = common::TempDir::new("turn-default-algorithm");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-default-algorithm");
  let raw = format!(
    r#"
{}

[[turn_upstream_pools]]
name = "turn-udp"

[[turn_upstream_pools.servers]]
id = "turn-a"
origin = "turn://turn.internal.example:3478"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(
    config.turn_upstream_pools[0].algorithm,
    LoadBalancingAlgorithm::PowerOfTwoChoices
  );
}

#[test]
fn turn_pool_rejects_http_only_algorithms() {
  let temp_dir = common::TempDir::new("turn-http-only-algorithm");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-http-only-algorithm");

  for algorithm in ["ewma", "least_time", "sticky_cookie"] {
    let raw = format!(
      r#"
{}

[[turn_upstream_pools]]
name = "turn-udp"
algorithm = "{algorithm}"

[[turn_upstream_pools.servers]]
id = "turn-a"
origin = "turn://turn.internal.example:3478"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("HTTP-only TURN algorithm should fail validation");
    assert!(
      error
        .to_string()
        .contains("unsupported load-balancing algorithm"),
      "unexpected error for {algorithm}: {error}"
    );
  }
}

#[test]
fn sni_forward_tcp_rule_parses_and_validates() {
  let temp_dir = common::TempDir::new("sni-forward-valid");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "sni-forward-valid");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[sni_forward]
enabled = true
client_hello_max_bytes = 8192
client_hello_parse_methods = ["single_record", "tls_record_reassembly"]
idle_timeout_ms = 60000
quic_max_sessions = 128
quic_local_queue_capacity = 32

[[sni_forward.rules]]
name = "legacy-tls"
server_names = ["legacy.example.com", "*.legacy.example.com"]
target = "127.0.0.1:9443"
protocols = ["tcp_tls"]
connect_timeout_ms = 1000
idle_timeout_ms = 30000
tcp_proxy_protocol_egress = "v1"
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(config.sni_forward.enabled);
  assert_eq!(config.sni_forward.client_hello_max_bytes, 8192);
  assert_eq!(
    config.sni_forward.client_hello_parse_methods,
    vec![
      SniForwardClientHelloParseMethod::SingleRecord,
      SniForwardClientHelloParseMethod::TlsRecordReassembly,
    ]
  );
  assert_eq!(config.sni_forward.quic_max_sessions, 128);
  assert_eq!(config.sni_forward.quic_local_queue_capacity, 32);
  assert_eq!(
    config.sni_forward.rules[0].protocols,
    vec![SniForwardProtocol::TcpTls]
  );
}

#[test]
fn sni_forward_default_target_can_enable_tcp_without_http3() {
  let temp_dir = common::TempDir::new("sni-forward-default-target");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "sni-forward-default-target");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[sni_forward]
enabled = true
default_target = "127.0.0.1:9443"
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert!(config.sni_forward.has_tcp_tls());
  assert_eq!(
    config.sni_forward.client_hello_parse_methods,
    vec![SniForwardClientHelloParseMethod::SingleRecord]
  );
  assert_eq!(config.sni_forward.quic_max_sessions, 8192);
  assert_eq!(config.sni_forward.quic_local_queue_capacity, 1024);
}

#[test]
fn sni_forward_rejects_zero_quic_limits() {
  let temp_dir = common::TempDir::new("sni-forward-zero-limits");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "sni-forward-zero-limits");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (suffix, expected) in [
    (
      r#"
[sni_forward]
enabled = true
quic_max_sessions = 0
"#,
      "sni_forward.quic_max_sessions must be greater than 0",
    ),
    (
      r#"
[sni_forward]
enabled = true
quic_local_queue_capacity = 0
"#,
      "sni_forward.quic_local_queue_capacity must be greater than 0",
    ),
  ] {
    let config: Config = toml::from_str(&(base.clone() + suffix)).expect("config should parse");
    let error = config
      .validate()
      .expect_err("zero SNI forwarding QUIC limits should fail");
    let error_chain = format!("{error:#}");
    assert!(
      error_chain.contains(expected),
      "unexpected error: {error:#}"
    );
  }
}

#[test]
fn sni_forward_rejects_invalid_rules() {
  let temp_dir = common::TempDir::new("sni-forward-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "sni-forward-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (suffix, expected) in [
    (
      r#"
[sni_forward]
enabled = true
client_hello_parse_methods = []
"#,
      "sni_forward.client_hello_parse_methods must include at least one method",
    ),
    (
      r#"
[sni_forward]
enabled = true
client_hello_parse_methods = ["single_record", "single_record"]
"#,
      "duplicate sni_forward.client_hello_parse_methods value: single_record",
    ),
    (
      r#"
[sni_forward]
enabled = true

[[sni_forward.rules]]
name = "a"
server_names = ["dup.example.com"]
target = "127.0.0.1:9443"
protocols = ["tcp_tls"]

[[sni_forward.rules]]
name = "b"
server_names = ["dup.example.com"]
target = "127.0.0.1:9444"
protocols = ["tcp_tls"]
"#,
      "duplicate sni_forward server_name pattern",
    ),
    (
      r#"
[sni_forward]
enabled = true

[[sni_forward.rules]]
name = "bad-wildcard"
server_names = ["api.*.example.com"]
target = "127.0.0.1:9443"
protocols = ["tcp_tls"]
"#,
      "leftmost wildcard",
    ),
    (
      r#"
[sni_forward]
enabled = true

[[sni_forward.rules]]
name = "bad-target"
server_names = ["bad-target.example.com"]
target = "127.0.0.1"
protocols = ["tcp_tls"]
"#,
      "host:port",
    ),
    (
      r#"
[sni_forward]
enabled = true

[[sni_forward.rules]]
name = "quic-needs-http3"
server_names = ["quic.example.com"]
target = "127.0.0.1:9443"
protocols = ["quic"]
"#,
      "requires listeners.http3",
    ),
  ] {
    let config: Config = toml::from_str(&(base.clone() + suffix)).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid SNI forwarding should fail");
    let error_chain = format!("{error:#}");
    assert!(
      error_chain.contains(expected),
      "unexpected error: {error:#}"
    );
  }
}

#[test]
fn sni_forward_unknown_fields_fail_strict_shape_validation() {
  let temp_dir = common::TempDir::new("sni-forward-unknown");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "sni-forward-unknown");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[sni_forward]
enabled = true
unexpected = true
"#;
  let config_path = temp_dir.path().join("oxibelt.toml");
  std::fs::write(&config_path, raw).expect("config should write");

  let error = Config::load(&config_path).expect_err("unknown SNI forwarding field should fail");

  assert!(
    error
      .to_string()
      .contains("configuration contains unknown field(s): sni_forward.unexpected"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn telemetry_tracing_and_detailed_metrics_parse() {
  let temp_dir = common::TempDir::new("telemetry-config");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "telemetry-config");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[metrics]
enabled = true
detail = "detailed"
histogram_buckets_ms = [1, 10, 100]

[telemetry.tracing]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "oxibelt-test"
sample_ratio = 0.5
export_timeout_ms = 250
propagate_trace_context = true
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert_eq!(config.metrics.detail, MetricsDetail::Detailed);
  assert_eq!(config.metrics.histogram_buckets_ms, vec![1, 10, 100]);
  assert!(config.telemetry.tracing.enabled);
  assert_eq!(config.telemetry.tracing.service_name, "oxibelt-test");
  assert_eq!(config.telemetry.tracing.sample_ratio, 0.5);
}

#[test]
fn telemetry_tracing_rejects_invalid_values() {
  let temp_dir = common::TempDir::new("telemetry-invalid");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "telemetry-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  for (suffix, expected) in [
    (
      r#"
[telemetry.tracing]
enabled = true
sample_ratio = 1.5
"#,
      "sample_ratio",
    ),
    (
      r#"
[telemetry.tracing]
enabled = true
export_timeout_ms = 0
"#,
      "export_timeout_ms",
    ),
    (
      r#"
[telemetry.tracing]
enabled = true
endpoint = "https://collector.example/v1/traces"
"#,
      "only http://",
    ),
  ] {
    let config: Config = toml::from_str(&(base.clone() + suffix)).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid telemetry should fail");
    assert!(
      error.to_string().contains(expected),
      "unexpected error: {error:#}"
    );
  }
}

#[test]
fn metrics_histogram_buckets_must_be_strictly_increasing() {
  let temp_dir = common::TempDir::new("metrics-buckets-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "metrics-buckets-invalid");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[metrics]
histogram_buckets_ms = [10, 10]
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("duplicate buckets should fail");

  assert!(
    error
      .to_string()
      .contains("metrics.histogram_buckets_ms values must be strictly increasing"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn telemetry_unknown_fields_fail_strict_shape_validation() {
  let temp_dir = common::TempDir::new("telemetry-unknown");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "telemetry-unknown");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[telemetry.tracing]
enabled = false
unexpected = true
"#;
  let config_path = temp_dir.path().join("oxibelt.toml");
  std::fs::write(&config_path, raw).expect("config should write");

  let error = Config::load(&config_path).expect_err("unknown telemetry field should fail");

  assert!(
    error
      .to_string()
      .contains("configuration contains unknown field(s): telemetry.tracing.unexpected"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn legacy_admin_rbac_tokens_are_rejected_by_ipm_model() {
  let temp_dir = common::TempDir::new("admin-rbac-legacy");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "admin-rbac-legacy");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[admin]
enabled = true
bind = "127.0.0.1:0"
bearer_token_env = "PATH"
transport = "plaintext_allowlist"

[[admin.rbac.tokens]]
name = "config-ci"
bearer_token_env = "PATH"
permissions = ["config.validate", "files.sync.oxirule_group"]
deny_permissions = ["files.delete"]
"#;

  let config: Config = toml::from_str(&raw).expect("legacy shape should parse for migration");
  let error = config
    .validate()
    .expect_err("legacy RBAC tokens should be rejected");
  assert!(
    error
      .to_string()
      .contains("admin.rbac is legacy RBAC syntax"),
    "unexpected error: {error}"
  );
}

fn available_parallelism() -> usize {
  std::thread::available_parallelism()
    .map(std::num::NonZeroUsize::get)
    .unwrap_or(1)
}

#[test]
fn accept_scaling_defaults_are_auto_workers() {
  let temp_dir = common::TempDir::new("accept-defaults");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "accept-defaults");
  let raw = common::minimal_config_toml(&cert_path, &key_path);

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  let expected_runtime = available_parallelism();
  let expected_accept = resolve_auto_worker_count(expected_runtime, 0.5).unwrap();
  assert_eq!(config.runtime.worker_threads, expected_runtime);
  assert_eq!(config.runtime.accept.workers, expected_accept);
  assert!(config.runtime.accept.reuse_port);
  assert_eq!(config.runtime.accept.backlog, 8192);
  assert_eq!(config.runtime.accept.accept_error_backoff_ms, 10);
  assert_eq!(config.quic.socket.workers, expected_runtime);
  assert!(!config.quic.socket.reuse_port);
  assert_eq!(config.runtime.worker_multipliers.runtime, 1.0);
  assert_eq!(config.runtime.worker_multipliers.accept, 0.5);
  assert_eq!(config.runtime.worker_multipliers.quic_socket, 1.0);
}

#[test]
fn accept_scaling_custom_values_parse() {
  let temp_dir = common::TempDir::new("accept-custom");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "accept-custom");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("worker_threads = \"auto\"", "worker_threads = 2")
    .replace(
      "workers = \"auto\"\nreuse_port = true\nbacklog = 8192\naccept_error_backoff_ms = 10",
      "workers = 2\nreuse_port = true\nbacklog = 2048\naccept_error_backoff_ms = 75",
    )
    + r#"

[quic.socket]
receive_buffer_bytes = 1048576
send_buffer_bytes = 1048576
workers = 2
reuse_port = true
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert_eq!(config.runtime.worker_threads, 2);
  assert_eq!(config.runtime.accept.workers, 2);
  assert!(config.runtime.accept.reuse_port);
  assert_eq!(config.runtime.accept.backlog, 2048);
  assert_eq!(config.runtime.accept.accept_error_backoff_ms, 75);
  assert_eq!(config.quic.socket.workers, 2);
  assert!(config.quic.socket.reuse_port);
}

#[test]
fn auto_worker_multipliers_parse_and_round_up() {
  let temp_dir = common::TempDir::new("accept-multipliers");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "accept-multipliers");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[runtime.accept]",
    r#"[runtime.worker_multipliers]
runtime = 1.5
accept = 0.5
quic_socket = 2.0

[runtime.accept]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  let available = available_parallelism();
  assert_eq!(
    config.runtime.worker_threads,
    resolve_auto_worker_count(available, 1.5).unwrap()
  );
  assert_eq!(
    config.runtime.accept.workers,
    resolve_auto_worker_count(available, 0.5).unwrap()
  );
  assert_eq!(
    config.quic.socket.workers,
    resolve_auto_worker_count(available, 2.0).unwrap()
  );
  assert_eq!(resolve_auto_worker_count(3, 1.5).unwrap(), 5);
}

#[test]
fn accept_scaling_rejects_invalid_values() {
  let temp_dir = common::TempDir::new("accept-invalid");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "accept-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let cases = [
    (
      base.replace("worker_threads = \"auto\"", "worker_threads = 0"),
      "runtime.worker_threads must be greater than 0",
    ),
    (
      base.replace("workers = \"auto\"", "workers = 0"),
      "runtime.accept.workers must be greater than 0",
    ),
    (
      base.replace(
        "workers = \"auto\"\nreuse_port = true",
        "workers = 2\nreuse_port = false",
      ),
      "runtime.accept.reuse_port must be true",
    ),
    (
      base.replace("backlog = 8192", "backlog = 0"),
      "runtime.accept.backlog must be greater than 0",
    ),
    (
      base.replace(
        "accept_error_backoff_ms = 10",
        "accept_error_backoff_ms = 0",
      ),
      "runtime.accept.accept_error_backoff_ms must be greater than 0",
    ),
    (
      format!("{base}\n\n[quic.socket]\nworkers = 0\n"),
      "quic.socket.workers must be greater than 0",
    ),
    (
      format!(
        "{}\n\n[quic.socket]\nworkers = 2\nreuse_port = false\n",
        base.replace("http3 = false", "http3 = true")
      ),
      "quic.socket.reuse_port must be true",
    ),
    (
      base.replace(
        "[runtime.accept]",
        "[runtime.worker_multipliers]\nruntime = 0\n\n[runtime.accept]",
      ),
      "runtime.worker_multipliers.runtime must be a finite number greater than 0",
    ),
  ];

  for (raw, expected) in cases {
    let error = match toml::from_str::<Config>(&raw) {
      Ok(config) => config
        .validate()
        .expect_err("validation should fail")
        .to_string(),
      Err(error) => error.to_string(),
    };
    assert!(error.contains(expected), "unexpected error: {error}");
  }
}

#[test]
fn proxy_retry_defaults_and_custom_values_are_parsed() {
  let temp_dir = common::TempDir::new("proxy-retry");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "proxy-retry");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let default_config: Config = toml::from_str(&base).expect("config should parse");
  default_config.validate().expect("config should validate");
  assert!(!default_config.proxy.retry.enabled);
  assert_eq!(default_config.proxy.retry.tries, 2);
  assert_eq!(default_config.proxy.retry.timeout_ms, 5_000);
  assert_eq!(default_config.proxy.retry.total_budget_ms, None);
  assert_eq!(default_config.proxy.retry.per_attempt_timeout_ms, None);
  assert_eq!(
    default_config.proxy.retry.on,
    vec![
      RetryCondition::ConnectError,
      RetryCondition::ReadTimeout,
      RetryCondition::Status502,
      RetryCondition::Status503,
      RetryCondition::Status504,
    ]
  );
  assert!(!default_config.proxy.retry.retry_non_idempotent);
  assert_eq!(default_config.proxy.retry.backoff_base_ms, 0);
  assert_eq!(default_config.proxy.retry.backoff_max_ms, 0);
  assert!(!default_config.proxy.retry.jitter);
  assert!(default_config.proxy.retry.reselect_pool_on_retry);
  assert!(default_config.proxy.retry.exclude_failed_pool_upstreams);
  assert!(default_config.proxy.retry.report_passive_health);

  let raw = format!(
    r#"
{base}

[proxy.retry]
enabled = true
tries = 4
timeout_ms = 750
total_budget_ms = 1250
per_attempt_timeout_ms = 300
on = ["connect_error", "read_timeout", "502", "503", "504"]
retry_non_idempotent = true
backoff_base_ms = 25
backoff_max_ms = 100
jitter = true
reselect_pool_on_retry = false
exclude_failed_pool_upstreams = false
report_passive_health = false
"#
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert!(config.proxy.retry.enabled);
  assert_eq!(config.proxy.retry.tries, 4);
  assert_eq!(config.proxy.retry.timeout_ms, 750);
  assert_eq!(config.proxy.retry.total_budget_ms, Some(1250));
  assert_eq!(config.proxy.retry.per_attempt_timeout_ms, Some(300));
  assert_eq!(
    config.proxy.retry.on,
    vec![
      RetryCondition::ConnectError,
      RetryCondition::ReadTimeout,
      RetryCondition::Status502,
      RetryCondition::Status503,
      RetryCondition::Status504,
    ]
  );
  assert!(config.proxy.retry.retry_non_idempotent);
  assert_eq!(config.proxy.retry.backoff_base_ms, 25);
  assert_eq!(config.proxy.retry.backoff_max_ms, 100);
  assert!(config.proxy.retry.jitter);
  assert!(!config.proxy.retry.reselect_pool_on_retry);
  assert!(!config.proxy.retry.exclude_failed_pool_upstreams);
  assert!(!config.proxy.retry.report_passive_health);
}

#[test]
fn route_retry_overrides_are_parsed() {
  let temp_dir = common::TempDir::new("route-retry");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "route-retry");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  let raw = format!(
    r#"
{base}

[proxy.retry]
enabled = false
tries = 2
total_budget_ms = 1000

[routes.retry]
enabled = true
tries = 3
total_budget_ms = 900
per_attempt_timeout_ms = 250
on = ["503"]
retry_non_idempotent = true
backoff_base_ms = 10
backoff_max_ms = 50
jitter = true
reselect_pool_on_retry = true
exclude_failed_pool_upstreams = true
report_passive_health = false
"#
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let retry = config.routes[0]
    .retry
    .as_ref()
    .expect("route retry should parse");
  assert_eq!(retry.enabled, Some(true));
  assert_eq!(retry.tries, Some(3));
  assert_eq!(retry.total_budget_ms, Some(900));
  assert_eq!(retry.per_attempt_timeout_ms, Some(250));
  assert_eq!(retry.on, Some(vec![RetryCondition::Status503]));
  assert_eq!(retry.retry_non_idempotent, Some(true));
  assert_eq!(retry.backoff_base_ms, Some(10));
  assert_eq!(retry.backoff_max_ms, Some(50));
  assert_eq!(retry.jitter, Some(true));
  assert_eq!(retry.reselect_pool_on_retry, Some(true));
  assert_eq!(retry.exclude_failed_pool_upstreams, Some(true));
  assert_eq!(retry.report_passive_health, Some(false));
}

#[test]
fn proxy_retry_rejects_zero_numeric_values() {
  let temp_dir = common::TempDir::new("proxy-retry-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-retry-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (setting, expected) in [
    ("tries = 0", "proxy.retry.tries must be greater than 0"),
    (
      "timeout_ms = 0",
      "proxy.retry.timeout_ms must be greater than 0",
    ),
    (
      "total_budget_ms = 0",
      "proxy.retry.total_budget_ms must be greater than 0",
    ),
    (
      "per_attempt_timeout_ms = 0",
      "proxy.retry.per_attempt_timeout_ms must be greater than 0",
    ),
    (
      "backoff_base_ms = 200\nbackoff_max_ms = 100",
      "proxy.retry.backoff_max_ms",
    ),
  ] {
    let raw = format!(
      r#"
{base}

[proxy.retry]
{setting}
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
      error.to_string().contains(expected),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn route_retry_rejects_invalid_numeric_values() {
  let temp_dir = common::TempDir::new("route-retry-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-retry-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (setting, expected) in [
    (
      "tries = 0",
      "route app-root retry.tries must be greater than 0",
    ),
    (
      "total_budget_ms = 0",
      "route app-root retry.total_budget_ms must be greater than 0",
    ),
    (
      "per_attempt_timeout_ms = 0",
      "route app-root retry.per_attempt_timeout_ms must be greater than 0",
    ),
    (
      "backoff_base_ms = 200\nbackoff_max_ms = 100",
      "route app-root retry.backoff_max_ms",
    ),
  ] {
    let raw = format!(
      r#"
{base}

[routes.retry]
{setting}
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
      error.to_string().contains(expected),
      "expected {expected:?}, got {error}"
    );
  }
}

#[test]
fn proxy_http_semantics_modes_parse() {
  let temp_dir = common::TempDir::new("proxy-http");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "proxy-http");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let raw = format!(
    r#"
{base}

[proxy.http]
trailers = "drop"
early_hints = "pass"
expect_continue = "reject"
priority = "ignore"
sse_auto_streaming = false

[proxy.http.grpc]
enabled = true
respect_grpc_timeout = false
retry = "safe_unary"

[proxy.http.errors]
mode = "json"
"#
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.proxy.http.early_hints, EarlyHintsMode::Pass);
  assert_eq!(config.proxy.http.trailers, TrailerMode::Drop);
  assert_eq!(
    config.proxy.http.expect_continue,
    ExpectContinueMode::Reject
  );
  assert_eq!(config.proxy.http.priority, PriorityMode::Ignore);
  assert!(!config.proxy.http.sse_auto_streaming);
  assert!(config.proxy.http.grpc.enabled);
  assert!(!config.proxy.http.grpc.respect_grpc_timeout);
  assert_eq!(config.proxy.http.grpc.retry, GrpcRetryMode::SafeUnary);
  assert_eq!(config.proxy.http.errors.mode, ErrorResponseMode::Json);
}

#[test]
fn proxy_http2_tuning_defaults_and_custom_values_parse() {
  let temp_dir = common::TempDir::new("proxy-http2");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "proxy-http2");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let default_config: Config = toml::from_str(&base).expect("config should parse");
  default_config.validate().expect("config should validate");
  assert!(default_config.proxy.http2.adaptive_window);
  assert_eq!(default_config.proxy.http2.max_concurrent_streams, 1024);
  assert_eq!(default_config.proxy.http2.max_send_buf_size, 1024 * 1024);
  assert_eq!(default_config.proxy.http2.initial_stream_window_bytes, None);
  assert_eq!(
    default_config.proxy.http2.initial_connection_window_bytes,
    None
  );
  assert_eq!(default_config.proxy.http2.max_frame_size_bytes, None);
  assert_eq!(default_config.proxy.http2.keep_alive_interval_ms, 0);
  assert_eq!(default_config.proxy.http2.keep_alive_timeout_ms, 20_000);
  assert!(!default_config.proxy.http2.keep_alive_while_idle);
  assert_eq!(default_config.upstreams[0].pool_max_idle_per_host, 128);

  let raw = format!(
    r#"
{}

[proxy.http2]
adaptive_window = false
initial_stream_window_bytes = 1048576
initial_connection_window_bytes = 16777216
max_frame_size_bytes = 65535
max_concurrent_streams = 64
max_send_buf_size = 262144
keep_alive_interval_ms = 10000
keep_alive_timeout_ms = 3000
keep_alive_while_idle = true
"#,
    base.replace(
      "request_timeout_ms = 30000",
      "request_timeout_ms = 30000\npool_max_idle_per_host = 7",
    )
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert!(!config.proxy.http2.adaptive_window);
  assert_eq!(
    config.proxy.http2.initial_stream_window_bytes,
    Some(1_048_576)
  );
  assert_eq!(
    config.proxy.http2.initial_connection_window_bytes,
    Some(16_777_216)
  );
  assert_eq!(config.proxy.http2.max_frame_size_bytes, Some(65_535));
  assert_eq!(config.proxy.http2.max_concurrent_streams, 64);
  assert_eq!(config.proxy.http2.max_send_buf_size, 262_144);
  assert_eq!(config.proxy.http2.keep_alive_interval_ms, 10_000);
  assert_eq!(config.proxy.http2.keep_alive_timeout_ms, 3_000);
  assert!(config.proxy.http2.keep_alive_while_idle);
  assert_eq!(config.upstreams[0].pool_max_idle_per_host, 7);
}

#[test]
fn proxy_http2_rejects_invalid_numeric_values() {
  let temp_dir = common::TempDir::new("proxy-http2-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-http2-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for setting in [
    "max_concurrent_streams = 0",
    "max_send_buf_size = 0",
    "keep_alive_timeout_ms = 0",
    "initial_stream_window_bytes = 0",
    "initial_connection_window_bytes = 0",
    "max_frame_size_bytes = 0",
  ] {
    let raw = format!(
      r#"
{base}

[proxy.http2]
{setting}
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
      error.to_string().contains("proxy.http2 numeric values"),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn proxy_http2_rejects_out_of_range_manual_window_values() {
  let temp_dir = common::TempDir::new("proxy-http2-invalid-ranges");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-http2-invalid-ranges");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (setting, expected) in [
    (
      "initial_stream_window_bytes = 2147483648",
      "initial window values must be at most 2147483647 bytes",
    ),
    (
      "initial_connection_window_bytes = 2147483648",
      "initial window values must be at most 2147483647 bytes",
    ),
    (
      "max_frame_size_bytes = 16383",
      "max_frame_size_bytes must be between 16384 and 16777215 bytes",
    ),
    (
      "max_frame_size_bytes = 16777216",
      "max_frame_size_bytes must be between 16384 and 16777215 bytes",
    ),
  ] {
    let raw = format!(
      r#"
{base}

[proxy.http2]
adaptive_window = false
{setting}
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("out-of-range H2 setting should fail");
    assert!(
      error.to_string().contains(expected),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn proxy_http2_rejects_manual_windows_when_adaptive_window_is_enabled() {
  let temp_dir = common::TempDir::new("proxy-http2-adaptive-manual");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-http2-adaptive-manual");
  let raw = format!(
    r#"
{}

[proxy.http2]
adaptive_window = true
initial_stream_window_bytes = 1048576
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("manual H2 window should require disabled adaptive window");
  assert!(
    error
      .to_string()
      .contains("manual window and frame-size values require adaptive_window = false"),
    "unexpected error: {error}"
  );
}

#[test]
fn proxy_static_files_defaults_and_custom_values_parse() {
  let temp_dir = common::TempDir::new("proxy-static-files");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-static-files");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let default_config: Config = toml::from_str(&base).expect("config should parse");
  default_config.validate().expect("config should validate");
  assert_eq!(
    default_config.proxy.static_files.sendfile,
    StaticFilesSendfileMode::Off
  );
  assert_eq!(
    default_config.proxy.static_files.inline_max_bytes,
    16 * 1024
  );
  assert_eq!(
    default_config
      .proxy
      .static_files
      .open_file_cache_max_entries,
    0
  );
  assert_eq!(default_config.proxy.static_files.open_file_cache_ttl_ms, 0);
  assert_eq!(
    default_config.proxy.static_files.hot_object_cache_max_bytes,
    0
  );
  assert_eq!(
    default_config
      .proxy
      .static_files
      .hot_object_cache_max_file_bytes,
    64 * 1024
  );

  let raw = format!(
    r#"
{base}

[proxy.static_files]
sendfile = "auto"
inline_max_bytes = 0
open_file_cache_max_entries = 128
open_file_cache_ttl_ms = 250
hot_object_cache_max_bytes = 1048576
hot_object_cache_max_file_bytes = 32768
"#
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(
    config.proxy.static_files.sendfile,
    StaticFilesSendfileMode::Auto
  );
  assert_eq!(config.proxy.static_files.inline_max_bytes, 0);
  assert_eq!(config.proxy.static_files.open_file_cache_max_entries, 128);
  assert_eq!(config.proxy.static_files.open_file_cache_ttl_ms, 250);
  assert_eq!(
    config.proxy.static_files.hot_object_cache_max_bytes,
    1_048_576
  );
  assert_eq!(
    config.proxy.static_files.hot_object_cache_max_file_bytes,
    32_768
  );
}

#[test]
fn proxy_static_files_rejects_incomplete_cache_settings() {
  let temp_dir = common::TempDir::new("proxy-static-cache-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-static-cache-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (setting, expected) in [
    (
      "open_file_cache_max_entries = 16",
      "open_file_cache_ttl_ms must be greater than 0",
    ),
    (
      "hot_object_cache_max_bytes = 1024",
      "hot_object_cache_max_bytes requires open_file_cache_max_entries",
    ),
    (
      "open_file_cache_max_entries = 16\nopen_file_cache_ttl_ms = 100\nhot_object_cache_max_bytes = 1024\nhot_object_cache_max_file_bytes = 0",
      "hot_object_cache_max_file_bytes must be greater than 0",
    ),
  ] {
    let raw = format!(
      r#"
{base}

[proxy.static_files]
{setting}
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid static cache settings should fail");
    assert!(
      error.to_string().contains(expected),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn proxy_static_files_rejects_invalid_sendfile_mode() {
  let temp_dir = common::TempDir::new("proxy-static-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-static-invalid");
  let raw = format!(
    r#"
{}

[proxy.static_files]
sendfile = "always"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let error = toml::from_str::<Config>(&raw).expect_err("invalid sendfile mode should fail");

  assert!(
    error.to_string().contains("unknown variant") && error.to_string().contains("always"),
    "unexpected error: {error}"
  );
}

#[test]
fn proxy_buffering_parses_spool_and_route_overrides() {
  let temp_dir = common::TempDir::new("proxy-buffering");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "proxy-buffering");
  let buffering_dir = temp_dir.path().join("buffering");
  std::fs::create_dir_all(&buffering_dir).expect("failed to create buffering temp dir");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  let raw = format!(
    r#"
{base}

[proxy.buffering]
request = "spool"
response = "memory"
max_memory_body_bytes = 4
max_temp_file_bytes = 16
temp_dir = "{}"

[routes.buffering]
request = "streaming"
response = "spool"
max_memory_body_bytes = 2
max_temp_file_bytes = 8
"#,
    buffering_dir.display()
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.proxy.buffering.request, BufferingMode::Spool);
  assert_eq!(config.proxy.buffering.response, BufferingMode::Memory);
  assert_eq!(
    config.proxy.buffering.temp_dir.as_deref(),
    Some(buffering_dir.as_path())
  );
  let route = &config.routes[0].buffering;
  assert_eq!(route.request, Some(BufferingMode::Streaming));
  assert_eq!(route.response, Some(BufferingMode::Spool));
  assert_eq!(route.max_memory_body_bytes, Some(2));
  assert_eq!(route.max_temp_file_bytes, Some(8));
}

#[test]
fn proxy_buffering_rejects_spool_without_temp_dir() {
  let temp_dir = common::TempDir::new("proxy-buffering-no-temp");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-buffering-no-temp");
  let raw = format!(
    r#"
{}

[proxy.buffering]
request = "spool"
max_temp_file_bytes = 16
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("spool without temp_dir should fail");
  assert!(
    error
      .to_string()
      .contains("proxy.buffering.temp_dir is required"),
    "unexpected error: {error}"
  );
}

#[test]
fn proxy_buffering_rejects_spool_with_zero_temp_quota() {
  let temp_dir = common::TempDir::new("proxy-buffering-zero-temp");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-buffering-zero-temp");
  let buffering_dir = temp_dir.path().join("buffering");
  std::fs::create_dir_all(&buffering_dir).expect("failed to create buffering temp dir");
  let raw = format!(
    r#"
{}

[proxy.buffering]
request = "spool"
max_temp_file_bytes = 0
temp_dir = "{}"
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    buffering_dir.display()
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("spool with zero temp quota should fail");
  assert!(
    error
      .to_string()
      .contains("max_temp_file_bytes must be greater than 0"),
    "unexpected error: {error}"
  );
}

#[test]
fn security_headers_parse_hsts_and_optional_headers() {
  let temp_dir = common::TempDir::new("security-headers");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "security-headers");
  let raw = format!(
    r#"
{}

[security.headers]
hsts = true
hsts_max_age_seconds = 31536000
hsts_include_subdomains = false
hsts_preload = true
x_content_type_options = "nosniff"
referrer_policy = "strict-origin-when-cross-origin"
permissions_policy = "geolocation=()"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert!(config.security.headers.hsts);
  assert_eq!(config.security.headers.hsts_max_age_seconds, 31_536_000);
  assert!(!config.security.headers.hsts_include_subdomains);
  assert!(config.security.headers.hsts_preload);
  assert_eq!(
    config.security.headers.x_content_type_options.as_deref(),
    Some("nosniff")
  );
  assert_eq!(
    config.security.headers.referrer_policy.as_deref(),
    Some("strict-origin-when-cross-origin")
  );
  assert_eq!(
    config.security.headers.permissions_policy.as_deref(),
    Some("geolocation=()")
  );
}

#[test]
fn security_headers_reject_invalid_header_values() {
  let temp_dir = common::TempDir::new("security-headers-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "security-headers-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (setting, expected_field) in [
    (
      r#"x_content_type_options = "nosniff\nbad""#,
      "security.headers.x_content_type_options",
    ),
    (
      r#"referrer_policy = "strict-origin\rbad""#,
      "security.headers.referrer_policy",
    ),
    (
      r#"permissions_policy = "geolocation=()\nbad""#,
      "security.headers.permissions_policy",
    ),
  ] {
    let raw = format!(
      r#"
{base}

[security.headers]
{setting}
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid header value should fail");
    let error = error.to_string();
    assert!(
      error.contains(expected_field) && error.contains("not a valid header value"),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn tls_versions_and_session_ticket_rotation_are_validated() {
  let temp_dir = common::TempDir::new("tls-validation");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "tls-validation");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let raw = base.replace(
    "[tls.ocsp]",
    r#"min_version = "tls1.2"
max_version = "tls1.3"
session_tickets = false
session_ticket_rotation_seconds = 120

[tls.ocsp]"#,
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.tls.min_version, TlsVersion::Tls12);
  assert_eq!(config.tls.max_version, TlsVersion::Tls13);
  assert!(!config.tls.session_tickets);
  assert_eq!(config.tls.session_ticket_rotation_seconds, 120);

  let raw = base.replace(
    "[tls.ocsp]",
    r#"min_version = "tls1.3"
max_version = "tls1.2"

[tls.ocsp]"#,
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("invalid TLS version range should fail");
  assert!(
    error
      .to_string()
      .contains("tls.min_version must be less than or equal to tls.max_version"),
    "unexpected error: {error}"
  );

  let raw = base.replace(
    "[tls.ocsp]",
    r#"session_ticket_rotation_seconds = 0

[tls.ocsp]"#,
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("zero ticket rotation should fail");
  assert!(
    error
      .to_string()
      .contains("tls.session_ticket_rotation_seconds must be greater than 0"),
    "unexpected error: {error}"
  );
}

#[test]
fn tls_resumption_nested_config_parses_and_legacy_conflicts_are_rejected() {
  let temp_dir = common::TempDir::new("tls-resumption-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "tls-resumption-config");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let raw = base.replace(
    "[tls.ocsp]",
    r#"[tls.resumption]
mode = "stateless"
session_cache_size = 8192
tls13_ticket_count = 4
rotation_seconds = 600

[tls.ocsp]"#,
  );
  let raw = raw.replace(
    "webtransport = true",
    r#"webtransport = true

[upstreams.tls.resumption]
mode = "disabled"
session_cache_size = 2048
tls12 = "session_id_only""#,
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(
    config.tls.resumption.mode,
    TlsServerResumptionMode::Stateless
  );
  assert_eq!(config.tls.resumption.session_cache_size, 8192);
  assert_eq!(config.tls.resumption.tls13_ticket_count, 4);
  assert_eq!(config.tls.resumption.rotation_seconds, 600);
  assert!(config.tls.session_tickets);
  assert_eq!(
    config.upstreams[0].tls.resumption.mode,
    UpstreamTlsResumptionMode::Disabled
  );
  assert_eq!(
    config.upstreams[0].tls.resumption.tls12,
    UpstreamTls12ResumptionMode::SessionIdOnly
  );

  let raw = base.replace(
    "[tls.ocsp]",
    r#"session_tickets = false

[tls.resumption]
mode = "stateful"

[tls.ocsp]"#,
  );
  let error = toml::from_str::<Config>(&raw).expect_err("conflicting legacy alias should fail");
  assert!(
    error
      .to_string()
      .contains("session_tickets = false conflicts"),
    "unexpected error: {error}"
  );
}

#[test]
fn tls_key_exchange_groups_parse_and_validate() {
  let temp_dir = common::TempDir::new("tls-key-exchange-groups");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "tls-key-exchange-groups");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let raw = base.replace(
    "private_key =",
    "key_exchange_groups = [\"x25519\", \"secp256r1\", \"secp384r1\"]\nprivate_key =",
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(
    config.tls.key_exchange_groups,
    vec![
      TlsKeyExchangeGroup::X25519,
      TlsKeyExchangeGroup::Secp256r1,
      TlsKeyExchangeGroup::Secp384r1,
    ]
  );

  let raw = base.replace("private_key =", "key_exchange_groups = []\nprivate_key =");
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("empty key exchange group list should fail");
  assert!(
    error
      .to_string()
      .contains("tls.key_exchange_groups must include at least one group"),
    "unexpected error: {error}"
  );

  let raw = base.replace(
    "private_key =",
    "key_exchange_groups = [\"x25519\", \"x25519\"]\nprivate_key =",
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("duplicate key exchange group should fail");
  assert!(
    error
      .to_string()
      .contains("tls.key_exchange_groups contains duplicate x25519"),
    "unexpected error: {error}"
  );
}

#[test]
fn tls_resumption_validation_rejects_invalid_values_and_zero_rtt_conflict() {
  let temp_dir = common::TempDir::new("tls-resumption-validation");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "tls-resumption-validation");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (setting, expected) in [
    (
      "session_cache_size = 0",
      "tls.resumption.session_cache_size must be greater than 0",
    ),
    (
      "tls13_ticket_count = 0",
      "tls.resumption.tls13_ticket_count must be greater than 0",
    ),
    (
      "rotation_seconds = 0",
      "tls.resumption.rotation_seconds must be greater than 0",
    ),
  ] {
    let raw = base.replace(
      "[tls.ocsp]",
      &format!(
        r#"[tls.resumption]
{setting}

[tls.ocsp]"#
      ),
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid resumption value should fail");
    assert!(
      error.to_string().contains(expected),
      "unexpected error: {error}"
    );
  }

  let raw = base
    .replace("http3 = false", "http3 = true")
    .replace(
      "[tls.ocsp]",
      r#"[tls.resumption]
mode = "stateless"

[tls.ocsp]"#,
    )
    .replace(
      "[proxy]",
      r#"[quic]
zero_rtt = "safe_methods"

[proxy]"#,
    );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("stateless tickets must reject QUIC 0-RTT");
  assert!(
    error
      .to_string()
      .contains("tls.resumption.mode = \"stateless\" cannot be used"),
    "unexpected error: {error}"
  );
}

#[test]
fn remote_tls_signer_config_accepts_no_private_key_and_rejects_unsafe_combinations() {
  let token_env = "OXIBELT_KEYSIGNER_TOKEN_CONFIG_TEST";
  unsafe {
    std::env::set_var(
      token_env,
      base64::engine::general_purpose::STANDARD.encode([11u8; 32]),
    );
  }
  let temp_dir = common::TempDir::new("remote-tls-signer-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "remote-tls-signer-config");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  let remote_block = format!(
    r#"[tls.remote_signer]
enabled = true
socket_path = "/run/oxibelt-keysigner/sign.sock"
key_id = "edge-default"
token_env = "{token_env}"
"#
  );

  let remote_only = base
    .replace(&format!("private_key = \"{}\"\n", key_path.display()), "")
    .replace("[tls.ocsp]", &format!("{remote_block}\n[tls.ocsp]"));
  let config: Config = toml::from_str(&remote_only).expect("config should parse");
  config
    .validate()
    .expect("remote signer should replace local private key");
  assert_eq!(config.tls.remote_signer.pool_max_idle_connections, 64);

  let no_pool = remote_only.replace(
    &format!("token_env = \"{token_env}\"\n"),
    &format!("token_env = \"{token_env}\"\npool_max_idle_connections = 0\n"),
  );
  let config: Config = toml::from_str(&no_pool).expect("config should parse");
  config
    .validate()
    .expect("pool_max_idle_connections = 0 should disable reuse without disabling signing");
  assert_eq!(config.tls.remote_signer.pool_max_idle_connections, 0);

  let both = base.replace("[tls.ocsp]", &format!("{remote_block}\n[tls.ocsp]"));
  let config: Config = toml::from_str(&both).expect("config should parse");
  let error = config
    .validate()
    .expect_err("private_key and remote signer must be mutually exclusive");
  assert!(
    error
      .to_string()
      .contains("tls.private_key must not be set"),
    "unexpected error: {error}"
  );

  let tls12_without_opt_in = remote_only.replace(
    &format!("cert_chain = \"{}\"\n", cert_path.display()),
    &format!(
      "cert_chain = \"{}\"\nmin_version = \"tls1.2\"\n",
      cert_path.display()
    ),
  );
  let config: Config = toml::from_str(&tls12_without_opt_in).expect("config should parse");
  let error = config
    .validate()
    .expect_err("TLS 1.2 remote signing requires explicit opt-in");
  assert!(
    error
      .to_string()
      .contains("allow_tls12_unstructured_signing"),
    "unexpected error: {error}"
  );
}

#[test]
fn remote_tls_signer_token_file_resolves_and_replaces_env_token() {
  let temp_dir = common::TempDir::new("remote-tls-signer-token-file");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("config dir should create");
  std::fs::create_dir_all(&cert_dir).expect("cert dir should create");
  let (cert_path, _key_path) =
    common::create_self_signed_cert(&cert_dir, "remote-tls-signer-token-file");
  let token_file = cert_dir.join("keysigner-token.b64");
  std::fs::write(
    &token_file,
    base64::engine::general_purpose::STANDARD.encode([17u8; 32]),
  )
  .expect("token file should write");
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    format!(
      r#"
{}

[tls.remote_signer]
enabled = true
socket_path = "/run/oxibelt-keysigner/sign.sock"
key_id = "edge-default"
token_file = "keysigner-token.b64"
token_reload_interval_ms = 250
"#,
      common::minimal_config_toml_with_paths(
        cert_path.file_name().unwrap().to_str().unwrap(),
        "unused-local-key.pem",
      )
      .replace("private_key = \"unused-local-key.pem\"\n", "")
    ),
  )
  .expect("config file should write");

  let config = Config::load(&config_path).expect("config should load with token_file");
  assert_eq!(
    config.tls.remote_signer.token_file,
    Some(token_file.clone())
  );
  assert_eq!(config.tls.remote_signer.token_reload_interval_ms, 250);
  assert!(
    config
      .source_paths
      .downstream_tls_reload_files()
      .contains(&token_file)
  );
  config
    .validate()
    .expect("token_file should replace token_env validation");
}

#[test]
fn remote_tls_signer_token_file_retains_logical_symlink_reload_path() {
  let temp_dir = common::TempDir::new("remote-tls-signer-token-file-symlink");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("config dir should create");
  std::fs::create_dir_all(&cert_dir).expect("cert dir should create");
  let (cert_path, _key_path) =
    common::create_self_signed_cert(&cert_dir, "remote-tls-signer-token-file-symlink");
  let first_target = cert_dir.join("keysigner-token-a.b64");
  let token_file = cert_dir.join("keysigner-token.b64");
  std::fs::write(
    &first_target,
    base64::engine::general_purpose::STANDARD.encode([17u8; 32]),
  )
  .expect("token file should write");
  std::os::unix::fs::symlink("keysigner-token-a.b64", &token_file)
    .expect("token symlink should create");
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    format!(
      r#"
{}

[tls.remote_signer]
enabled = true
socket_path = "/run/oxibelt-keysigner/sign.sock"
key_id = "edge-default"
token_file = "keysigner-token.b64"
"#,
      common::minimal_config_toml_with_paths(
        cert_path.file_name().unwrap().to_str().unwrap(),
        "unused-local-key.pem",
      )
      .replace("private_key = \"unused-local-key.pem\"\n", "")
    ),
  )
  .expect("config file should write");

  let config = Config::load(&config_path).expect("config should load with symlinked token_file");
  assert_eq!(
    config.tls.remote_signer.token_file,
    Some(first_target.clone())
  );
  assert_eq!(
    config.tls.remote_signer.token_file_reload_path,
    Some(token_file.clone())
  );
  assert_eq!(
    config.tls.remote_signer.token_file_reload_base_dir,
    Some(cert_dir.clone())
  );
  assert!(
    config
      .source_paths
      .downstream_tls_reload_files()
      .contains(&token_file)
  );
  config
    .validate()
    .expect("symlinked token_file target should validate");
}

#[test]
fn remote_tls_signer_token_file_rejects_missing_and_invalid_files() {
  let token_env = "OXIBELT_KEYSIGNER_TOKEN_FILE_REJECTS_ENV";
  let temp_dir = common::TempDir::new("remote-tls-signer-token-file-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "remote-token-file-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  let missing = temp_dir.path().join("missing-token.b64");
  let remote_block = format!(
    r#"[tls.remote_signer]
enabled = true
socket_path = "/run/oxibelt-keysigner/sign.sock"
key_id = "edge-default"
token_env = "{token_env}"
token_file = "{}"
"#,
    missing.display()
  );
  let raw = base
    .replace(&format!("private_key = \"{}\"\n", key_path.display()), "")
    .replace("[tls.ocsp]", &format!("{remote_block}\n[tls.ocsp]"));
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("missing token file should reject remote signer");
  assert!(
    error.to_string().contains("failed to read"),
    "unexpected error: {error}"
  );

  let invalid = temp_dir.path().join("keysigner-token.b64");
  std::fs::write(&invalid, "short").expect("invalid token should write");
  let raw = raw.replace(
    &missing.display().to_string(),
    &invalid.display().to_string(),
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("invalid token file should reject remote signer");
  assert!(
    error.to_string().contains("exactly 32 bytes") || error.to_string().contains("base64"),
    "unexpected error: {error}"
  );
}

#[test]
fn turn_tls_remote_signer_override_requires_global_remote_signer() {
  let temp_dir = common::TempDir::new("turn-remote-signer-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-remote-signer-config");
  let raw = format!(
    r#"
{}

[[turn_upstream_pools]]
name = "turn-tls"

[[turn_upstream_pools.servers]]
origin = "turns://turn.example.test:5349"

[[webrtc_turn_listeners]]
name = "turn"
mode = "proxy_pool"
bind_tls = "127.0.0.1:5349"
tls_pool = "turn-tls"

[webrtc_turn_listeners.tls]
cert_chain = "{}"
remote_signer_key_id = "turn-key"
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    cert_path.display()
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("TURN remote signer override requires global remote signer config");
  assert!(
    error
      .to_string()
      .contains("tls.remote_signer.enabled = true"),
    "unexpected error: {error}"
  );
}

#[test]
fn admin_tls_validation_rejects_invalid_versions_and_missing_client_auth_roots() {
  unsafe {
    std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("admin-tls-validation");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-tls-validation");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let raw = format!(
    r#"
{base}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[admin.tls]
min_version = "tls1.3"
max_version = "tls1.2"
"#
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("invalid admin TLS version range should fail");
  assert!(
    error
      .to_string()
      .contains("admin.tls.min_version must be less than or equal to admin.tls.max_version"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{base}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[admin.tls.client_auth]
mode = "require"
"#
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("admin TLS client auth without roots should fail");
  assert!(
    error
      .to_string()
      .contains("admin.tls.client_auth.ca_certs is required"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{base}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[admin.tls.client_auth]
mode = "require"
ca_certs = ["client-ca.pem"]
verify_depth = 0
"#
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("admin TLS client auth verify_depth zero should fail");
  assert!(
    error
      .to_string()
      .contains("admin.tls.client_auth.verify_depth must be greater than 0"),
    "unexpected error: {error}"
  );
}

#[test]
fn tls_client_auth_validation_rejects_zero_verify_depth() {
  let temp_dir = common::TempDir::new("tls-client-auth-depth-validation");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "tls-client-auth-depth-validation");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  let raw = format!(
    r#"
{base}

[tls.client_auth]
mode = "require"
ca_certs = ["client-ca.pem"]
verify_depth = 0
"#
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("TLS client auth verify_depth zero should fail");
  assert!(
    error
      .to_string()
      .contains("tls.client_auth.verify_depth must be greater than 0"),
    "unexpected error: {error}"
  );
}

#[test]
fn proxy_protocol_listener_versions_parse() {
  let temp_dir = common::TempDir::new("proxy-protocol-versions");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "proxy-protocol-versions");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (raw_version, expected) in [
    ("v1", ProxyProtocolVersion::V1),
    ("v2", ProxyProtocolVersion::V2),
    ("any", ProxyProtocolVersion::Any),
  ] {
    let raw = format!(
      r#"
{base}

[listeners.proxy_protocol]
enabled = true
version = "{raw_version}"
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    assert_eq!(config.listeners.proxy_protocol.version, expected);
  }
}

#[test]
fn connection_limit_identity_modes_parse() {
  let temp_dir = common::TempDir::new("connection-limit-identity");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "connection-limit-identity");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  let cases = [
    ("proxy_protocol", ConnectionLimitIdentityMode::ProxyProtocol),
    (
      "first_request_real_ip",
      ConnectionLimitIdentityMode::FirstRequestRealIp,
    ),
    (
      "per_request_real_ip",
      ConnectionLimitIdentityMode::PerRequestRealIp,
    ),
  ];

  let default_config: Config = toml::from_str(&base).expect("config should parse");
  assert_eq!(
    default_config.limits.connection_limit_identity,
    ConnectionLimitIdentityMode::ProxyProtocol
  );

  for (raw_mode, expected) in cases {
    let raw = format!(
      r#"
{}

[limits]
connection_limit_identity = "{raw_mode}"
"#,
      base
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    assert_eq!(config.limits.connection_limit_identity, expected);
  }
}

#[test]
fn timeout_defaults_and_route_overrides_are_parsed() {
  let temp_dir = common::TempDir::new("timeout-overrides");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "timeout-overrides");
  let raw = format!(
    r#"
{}

[limits]
client_body_timeout_ms = 30000
response_send_timeout_ms = 60000
websocket_idle_timeout_ms = 75000
webtransport_idle_timeout_ms = 75000

[[routes]]
name = "timeout-route"
hosts = ["timeouts.example.com"]
path_prefix = "/timeouts"
upstream = "app"

[routes.timeouts]
client_body_timeout_ms = 15000
response_send_timeout_ms = 30000
websocket_idle_timeout_ms = 60000
webtransport_idle_timeout_ms = 60000
upstream_connect_timeout_ms = 1000
upstream_request_timeout_ms = 15000
upstream_first_byte_timeout_ms = 2000
upstream_read_timeout_ms = 10000
upstream_send_timeout_ms = 10000
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert_eq!(config.limits.websocket_idle_timeout_ms, 75_000);
  assert_eq!(config.limits.webtransport_idle_timeout_ms, 75_000);
  assert_eq!(config.upstreams[0].first_byte_timeout_ms, 30_000);
  let route = config
    .routes
    .iter()
    .find(|route| route.name == "timeout-route")
    .expect("route should exist");
  assert_eq!(route.timeouts.client_body_timeout_ms, Some(15_000));
  assert_eq!(route.timeouts.upstream_first_byte_timeout_ms, Some(2_000));
}

#[test]
fn webtransport_session_limits_default_to_connection_limits_and_parse_overrides() {
  let temp_dir = common::TempDir::new("webtransport-session-limit-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "webtransport-session-limit-config");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  let default_config: Config = toml::from_str(&base).expect("config should parse");
  default_config.validate().expect("config should validate");

  assert_eq!(
    default_config.limits.effective_max_webtransport_sessions(),
    default_config.limits.max_connections
  );
  assert_eq!(
    default_config
      .limits
      .effective_max_webtransport_sessions_per_ip(),
    default_config.limits.max_connections_per_ip
  );
  assert_eq!(
    default_config
      .limits
      .max_webtransport_sessions_per_connection,
    256
  );

  let raw = format!(
    r#"
{}

[limits]
max_webtransport_sessions = 32
max_webtransport_sessions_per_ip = 4
max_webtransport_sessions_per_connection = 2
"#,
    base
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert_eq!(config.limits.effective_max_webtransport_sessions(), 32);
  assert_eq!(
    config.limits.effective_max_webtransport_sessions_per_ip(),
    4
  );
  assert_eq!(config.limits.max_webtransport_sessions_per_connection, 2);
}

#[test]
fn route_timeout_values_must_be_positive_when_configured() {
  let temp_dir = common::TempDir::new("timeout-invalid");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "timeout-invalid");
  let raw = format!(
    r#"
{}

[routes.timeouts]
upstream_read_timeout_ms = 0
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("zero route timeout should be rejected");
  assert!(
    error
      .to_string()
      .contains("timeouts.upstream_read_timeout_ms must be greater than 0"),
    "unexpected error: {error}"
  );
}

#[test]
fn cache_policy_disk_and_memory_then_disk_config_parse() {
  let temp_dir = common::TempDir::new("cache-policy");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "cache-policy");
  let disk_dir = temp_dir.path().join("cache");
  std::fs::create_dir_all(&disk_dir).expect("failed to create cache dir");
  let raw = format!(
    r#"
{}

[cache]
enabled = true
store = "memory_then_disk"
disk_dir = "{}"
max_size_bytes = 10485760
memory_max_size_bytes = 1024
disk_max_size_bytes = 1048576
memory_auto_fraction = 0.5
default_ttl_seconds = 60
cache_methods = ["GET"]
cache_key = "{{scheme}}:{{host}}:{{path}}:{{query:v}}:{{header:Accept-Language}}"
negative_statuses = [404]
negative_ttl_seconds = 10

[[cache.policies]]
name = "assets"
store = "disk"
disk_max_size_bytes = 1048576

[[cache.policies.rules]]
mime_types = ["text/css", "image/*"]
store = "disk"

[[routes]]
name = "cached-assets"
hosts = ["assets.example.com"]
path_prefix = "/assets"
upstream = "app"
cache = "assets"
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    disk_dir.display()
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.cache.store, CacheStore::MemoryThenDisk);
  assert_eq!(config.cache.policies[0].name, "assets");
  assert_eq!(config.routes[1].cache.as_deref(), Some("assets"));
}

#[test]
fn cache_advanced_policy_config_parse() {
  let temp_dir = common::TempDir::new("cache-advanced-policy");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-advanced-policy");
  let raw = format!(
    r#"
{}

[cache]
enabled = true
partition_key = "{{header:X-Tenant-ID}}"
tag_headers = ["Surrogate-Key", "Cache-Tag"]
max_tags_per_entry = 16
max_tag_bytes = 64
max_vary_fields = 4
max_vary_variants_per_key = 8
bypass_request_headers = ["Authorization", "Cookie"]
stream_large_objects = true
stream_chunk_bytes = 262144
background_refresh = true
background_refresh_max_concurrent = 4
lock_wait_timeout_ms = 250
stale_if_error_seconds = 30
stale_while_revalidate_seconds = 30

[cache.surrogate]
enabled = true
strip_response_header = true

[cache.admission]
statuses = [200, 203, 204]
content_types = ["text/*", "application/json"]
max_body_bytes = 4096
min_hits = 2
max_tracked_keys = 128

[cache.stale_if_error]
connect_error = true
read_timeout = false
statuses = [500, 502]
max_upstream_stale_seconds = 120

[[cache.policies]]
name = "assets"
cache_key = "{{scheme}}:{{host}}:{{path}}"
partition_key = "{{header:X-Tenant-ID}}"
negative_statuses = [404]
negative_ttl_seconds = 15
tag_headers = ["Surrogate-Key"]
max_vary_fields = 2
max_vary_variants_per_key = 4
background_refresh = false
lock_wait_timeout_ms = 100

[cache.policies.admission]
statuses = [200]
content_types = ["text/css"]
min_hits = 1
max_tracked_keys = 64

[cache.policies.stale_if_error]
connect_error = false
read_timeout = true
statuses = [503]
max_upstream_stale_seconds = 30

[[routes]]
name = "cached-assets"
hosts = ["assets.example.com"]
path_prefix = "/assets"
upstream = "app"
cache = "assets"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.cache.max_tags_per_entry, 16);
  assert_eq!(config.cache.partition_key, "{header:X-Tenant-ID}");
  assert_eq!(config.cache.max_vary_fields, 4);
  assert_eq!(config.cache.max_vary_variants_per_key, 8);
  assert_eq!(
    config.cache.bypass_request_headers,
    ["Authorization", "Cookie"]
  );
  assert_eq!(config.cache.stream_chunk_bytes, 262144);
  assert_eq!(config.cache.admission.min_hits, 2);
  assert_eq!(config.cache.stale_if_error.statuses, vec![500, 502]);
  assert_eq!(config.cache.stale_if_error.max_upstream_stale_seconds, 120);
  assert_eq!(
    config.cache.policies[0].tag_headers.as_deref().unwrap(),
    ["Surrogate-Key"]
  );
  assert_eq!(
    config.cache.policies[0].partition_key.as_deref(),
    Some("{header:X-Tenant-ID}")
  );
  assert_eq!(
    config.cache.policies[0].negative_statuses.as_deref(),
    Some(&[404][..])
  );
  assert_eq!(config.cache.policies[0].negative_ttl_seconds, Some(15));
  assert_eq!(config.cache.policies[0].max_vary_fields, Some(2));
  assert_eq!(config.cache.policies[0].lock_wait_timeout_ms, Some(100));
  assert_eq!(config.routes[1].cache.as_deref(), Some("assets"));
}

#[test]
fn cache_external_handler_config_parse_and_policy_override() {
  let temp_dir = common::TempDir::new("cache-external-handler");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-external-handler");
  let raw = format!(
    r#"
{}

[cache]
enabled = true
external_handler = "massive"

[[cache.external_handlers]]
name = "massive"
kind = "http"
endpoint = "http://127.0.0.1:19090/internal/v1/cache/"
token_env = "OXIBELT_EXTERNAL_CACHE_TOKEN"
connect_timeout_ms = 125
request_timeout_ms = 5000
max_metadata_bytes = 4096
max_body_bytes = 8192
max_inflight_requests = 8
fail_policy = "local_only"

[[cache.policies]]
name = "assets"
external_handler = "off"

[[cache.policies]]
name = "api"
external_handler = "massive"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert_eq!(config.cache.external_handler.as_deref(), Some("massive"));
  let handler = &config.cache.external_handlers[0];
  assert_eq!(handler.name, "massive");
  assert_eq!(handler.kind, ExternalCacheHandlerKind::Http);
  assert_eq!(
    handler.token_env.as_deref(),
    Some("OXIBELT_EXTERNAL_CACHE_TOKEN")
  );
  assert_eq!(handler.connect_timeout_ms, 125);
  assert_eq!(handler.request_timeout_ms, 5000);
  assert_eq!(handler.max_metadata_bytes, 4096);
  assert_eq!(handler.max_body_bytes, Some(8192));
  assert_eq!(handler.max_inflight_requests, 8);
  assert_eq!(
    handler.fail_policy,
    ExternalCacheHandlerFailPolicy::LocalOnly
  );
  assert_eq!(
    config.cache.policies[0].external_handler.as_deref(),
    Some("off")
  );
  assert_eq!(
    config.cache.policies[1].external_handler.as_deref(),
    Some("massive")
  );
}

#[test]
fn cache_external_handler_rejects_invalid_values() {
  let temp_dir = common::TempDir::new("cache-external-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-external-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (label, suffix, expected) in [
    (
      "duplicate",
      r#"
[cache]
enabled = true

[[cache.external_handlers]]
name = "massive"
endpoint = "http://127.0.0.1:19090/cache/"

[[cache.external_handlers]]
name = "massive"
endpoint = "http://127.0.0.1:19091/cache/"
"#,
      "duplicate cache external handler name massive",
    ),
    (
      "invalid-scheme",
      r#"
[cache]
enabled = true

[[cache.external_handlers]]
name = "massive"
endpoint = "unix://cache.sock"
"#,
      "endpoint must use http:// or https://",
    ),
    (
      "zero-timeout",
      r#"
[cache]
enabled = true

[[cache.external_handlers]]
name = "massive"
endpoint = "http://127.0.0.1:19090/cache/"
connect_timeout_ms = 0
"#,
      "connect_timeout_ms must be greater than 0",
    ),
    (
      "zero-body-limit",
      r#"
[cache]
enabled = true

[[cache.external_handlers]]
name = "massive"
endpoint = "http://127.0.0.1:19090/cache/"
max_body_bytes = 0
"#,
      "max_body_bytes must be greater than 0",
    ),
    (
      "zero-inflight",
      r#"
[cache]
enabled = true

[[cache.external_handlers]]
name = "massive"
endpoint = "http://127.0.0.1:19090/cache/"
max_inflight_requests = 0
"#,
      "max_inflight_requests must be greater than 0",
    ),
    (
      "unknown-top-level-reference",
      r#"
[cache]
enabled = true
external_handler = "missing"
"#,
      "cache.external_handler references unknown cache external handler missing",
    ),
    (
      "top-level-off",
      r#"
[cache]
enabled = true
external_handler = "off"
"#,
      "cache.external_handler must reference a cache external handler name",
    ),
    (
      "unknown-policy-reference",
      r#"
[cache]
enabled = true

[[cache.external_handlers]]
name = "massive"
endpoint = "http://127.0.0.1:19090/cache/"

[[cache.policies]]
name = "assets"
external_handler = "missing"
"#,
      "cache policy assets external_handler references unknown cache external handler missing",
    ),
  ] {
    let config: Config = toml::from_str(&(base.clone() + suffix)).expect("config should parse");
    let error = config
      .validate()
      .err()
      .unwrap_or_else(|| panic!("{label} should fail validation"));
    assert!(
      error.to_string().contains(expected),
      "unexpected {label} error: {error:#}"
    );
  }
}

#[test]
fn cache_external_handler_unknown_fields_fail_strict_shape_validation() {
  let temp_dir = common::TempDir::new("cache-external-unknown");
  let config_path = write_loadable_config(&temp_dir, "cache-external-unknown", |raw| {
    raw
      + r#"

[cache]
enabled = true
external_handler = "massive"

[[cache.external_handlers]]
name = "massive"
endpoint = "http://127.0.0.1:19090/cache/"
unexpected = true
"#
  });

  let error = Config::load(&config_path).expect_err("unknown external handler field should fail");
  assert!(
    error
      .to_string()
      .contains("configuration contains unknown field(s): cache.external_handlers.unexpected"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn cache_advanced_policy_rejects_invalid_values() {
  let temp_dir = common::TempDir::new("cache-advanced-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-advanced-invalid");
  let raw = format!(
    r#"
{}

[cache]
enabled = true
max_tags_per_entry = 0
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("config should reject invalid cache tag limit");
  assert!(
    error
      .to_string()
      .contains("cache.max_tags_per_entry must be greater than 0")
  );
}

#[test]
fn cache_disk_store_requires_explicit_disk_dir() {
  let temp_dir = common::TempDir::new("cache-disk-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "cache-disk-invalid");
  let raw = format!(
    r#"
{}

[cache]
enabled = true
store = "disk"
disk_max_size_bytes = 1048576
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("disk cache without disk_dir should fail");
  assert!(
    error.to_string().contains("cache.disk_dir is required"),
    "unexpected error: {error}"
  );
}

#[test]
fn shared_state_config_parses_feature_mapped_redis_and_postgres_backends() {
  let temp_dir = common::TempDir::new("shared-state-config");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "shared-state");
  let raw = format!(
    r#"
{}

[shared_state]
enabled = true
namespace = "matrix"
default_backend = "redis-main"
rate_limits_backend = "redis-main"
connection_limits_backend = "redis-main"
person_proof_backend = "postgres-main"
upstream_health_backend = "redis-main"
cache_backend = "postgres-main"
reload_backend = "postgres-main"
dynamic_policy_backend = "postgres-main"
operation_timeout_ms = 250
connection_lease_ms = 30000
cache_lock_ms = 5000

[[shared_state.backends]]
name = "redis-main"
kind = "redis"
connection_url = "redis://mock-redis:6379/0"

[[shared_state.backends]]
name = "postgres-main"
kind = "postgres"
connection_url = "postgres://oxibelt:oxibelt@mock-postgres:5432/oxibelt"
max_connections = 2
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config.validate().expect("config should validate");
  assert!(config.shared_state.enabled);
  assert_eq!(
    config.shared_state.backends[0].kind,
    SharedStateBackendKind::Redis
  );
  assert_eq!(
    config.shared_state.backends[1].kind,
    SharedStateBackendKind::Postgres
  );
  assert_eq!(
    config.shared_state.person_proof_backend.as_deref(),
    Some("postgres-main")
  );
  assert_eq!(
    config.shared_state.dynamic_policy_backend.as_deref(),
    Some("postgres-main")
  );
}

#[test]
fn dynamic_policy_config_parses_postgres_backend_mapping() {
  let temp_dir = common::TempDir::new("dynamic-policy-config");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "dynamic-policy");
  let raw = format!(
    r#"
{}

[dynamic_policy]
enabled = true
backend = "postgres-main"
refresh_interval_ms = 250
max_policies = 256
fail_policy = "disabled_on_error"
default_status = 403
default_body = "blocked"

[dynamic_policy.matching]
trust_route_name = true
normalize_path = true

[shared_state]
enabled = true
namespace = "matrix"
dynamic_policy_backend = "postgres-main"

[[shared_state.backends]]
name = "postgres-main"
kind = "postgres"
connection_url = "postgres://oxibelt:oxibelt@mock-postgres:5432/oxibelt"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(config.dynamic_policy.enabled);
  assert_eq!(
    config.dynamic_policy.backend.as_deref(),
    Some("postgres-main")
  );
  assert_eq!(
    config.dynamic_policy.fail_policy,
    DynamicPolicyFailPolicy::DisabledOnError
  );
  assert_eq!(config.dynamic_policy.default_status, 403);
  assert_eq!(config.dynamic_policy.matching.ipv4_prefix_bits, 24);
  assert_eq!(config.dynamic_policy.matching.ipv6_prefix_bits, 56);
  assert_eq!(
    config.dynamic_policy.matching.token_bindings,
    vec![
      PersonProofTokenBinding::UserAgent,
      PersonProofTokenBinding::TlsFingerprint,
      PersonProofTokenBinding::Route,
      PersonProofTokenBinding::DirectPeerIpNetworkPrefix,
    ]
  );
  assert_eq!(
    config.dynamic_policy.matching.composite_identity_parts,
    vec![
      RateLimitIdentityPart::ClientIpPrefix,
      RateLimitIdentityPart::UserAgent,
      RateLimitIdentityPart::TlsFingerprint,
      RateLimitIdentityPart::Asn,
    ]
  );
}

#[test]
fn ipm_config_parses_postgres_backend_mapping_without_bootstrap_env_token() {
  unsafe {
    std::env::set_var("OXIBELT_IPM_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("ipm-store-config");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ipm-store-config");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bind = "127.0.0.1:0"
transport = "plaintext_allowlist"

[ipm]
enabled = true
backend = "postgres-main"

[[ipm.principals]]
id = "deployer"
subject = "oidc:ci/deployer"
groups = ["operators"]

[[ipm.credentials]]
name = "deployer-token"
principal = "deployer"
bearer_token_env = "OXIBELT_IPM_TOKEN_TEST"

[[ipm.policies]]
name = "config-read"

[[ipm.policies.statements]]
effect = "allow"
actions = ["config:GetStatus"]
resources = ["oxibelt:oxibelt:config:*"]

[[ipm.bindings]]
group = "operators"
policy = "config-read"

[shared_state]
enabled = true
namespace = "matrix"

[[shared_state.backends]]
name = "postgres-main"
kind = "postgres"
connection_url = "postgres://oxibelt:oxibelt@mock-postgres:5432/oxibelt"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(config.ipm.enabled);
  assert_eq!(config.ipm.backend.as_deref(), Some("postgres-main"));
}

#[test]
fn admin_audit_requires_postgres_shared_state_backend() {
  unsafe {
    std::env::set_var("OXIBELT_ADMIN_TOKEN", "secret");
  }
  let temp_dir = common::TempDir::new("admin-audit-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-audit-config");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bind = "127.0.0.1:0"
transport = "plaintext_allowlist"

[admin.audit]
enabled = true
backend = "postgres-main"

[shared_state]
enabled = true
namespace = "matrix"

[[shared_state.backends]]
name = "postgres-main"
kind = "postgres"
connection_url = "postgres://oxibelt:oxibelt@mock-postgres:5432/oxibelt"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert!(config.admin.audit.enabled);
  assert_eq!(config.admin.audit.backend.as_deref(), Some("postgres-main"));

  let invalid = raw.replace("kind = \"postgres\"", "kind = \"redis\"");
  let config: Config = toml::from_str(&invalid).expect("invalid config should parse");
  let error = config
    .validate()
    .expect_err("Redis admin audit backend should fail validation");
  assert!(
    error
      .to_string()
      .contains("admin.audit.backend postgres-main must use kind = \"postgres\""),
    "{error}"
  );
}

#[test]
fn ipm_store_rejects_non_postgres_backend() {
  let temp_dir = common::TempDir::new("ipm-store-redis");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ipm-store-redis");
  let raw = format!(
    r#"
{}

[admin]
enabled = true

[ipm]
enabled = true
backend = "redis-main"

[shared_state]
enabled = true

[[shared_state.backends]]
name = "redis-main"
kind = "redis"
connection_url = "redis://mock-redis:6379/0"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("IPM store should require postgres");

  assert!(
    error
      .to_string()
      .contains("ipm backend redis-main must use kind = \"postgres\""),
    "unexpected error: {error}"
  );
}

#[test]
fn ipm_store_rejects_invalid_backend_and_legacy_shared_state_mapping() {
  let temp_dir = common::TempDir::new("ipm-store-invalid");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ipm-store-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (setting, expected) in [
    (
      r#"
[ipm]
backend = ""
"#,
      "ipm.backend must not be empty",
    ),
    (
      r#"
[shared_state]
enabled = true
admin_tokens_backend = "postgres-main"

[[shared_state.backends]]
name = "postgres-main"
kind = "postgres"
connection_url = "postgres://oxibelt:oxibelt@mock-postgres:5432/oxibelt"
"#,
      "shared_state.admin_tokens_backend is legacy Admin token syntax",
    ),
  ] {
    let raw = format!(
      r#"
{base}
{setting}
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid IPM store config should fail");
    assert!(
      error.to_string().contains(expected),
      "expected {expected}, got {error:#}"
    );
  }
}

#[test]
fn dynamic_policy_automation_api_config_validates_signature_key_and_quotas() {
  unsafe {
    std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
    std::env::set_var(
      "OXIBELT_DYNAMIC_POLICY_HMAC_KEY_TEST",
      base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
    );
  }
  let temp_dir = common::TempDir::new("dynamic-policy-automation");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "dynamic-policy-automation");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[dynamic_policy]
enabled = true
backend = "postgres-main"
max_policies = 256

[dynamic_policy.automation_api]
enabled = true
require_ttl = true
signature_key_env = "OXIBELT_DYNAMIC_POLICY_HMAC_KEY_TEST"
default_source_quota = 16

[[dynamic_policy.automation_api.source_quotas]]
source = "vaultwarden"
max_active_policies = 8

[shared_state]
enabled = true
namespace = "matrix"
dynamic_policy_backend = "postgres-main"

[[shared_state.backends]]
name = "postgres-main"
kind = "postgres"
connection_url = "postgres://oxibelt:oxibelt@mock-postgres:5432/oxibelt"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(config.dynamic_policy.automation_api.enabled);
  assert_eq!(
    config
      .dynamic_policy
      .automation_api
      .quota_for_source("vaultwarden", config.dynamic_policy.max_policies),
    8
  );
  assert_eq!(
    config
      .dynamic_policy
      .automation_api
      .quota_for_source("other", config.dynamic_policy.max_policies),
    16
  );
}

#[test]
fn dynamic_policy_automation_api_rejects_default_quota_above_global_cap() {
  unsafe {
    std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
    std::env::set_var(
      "OXIBELT_DYNAMIC_POLICY_HMAC_KEY_TEST",
      base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
    );
  }
  let temp_dir = common::TempDir::new("dynamic-policy-default-quota");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "dynamic-policy-default-quota");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[dynamic_policy]
enabled = true
backend = "postgres-main"
max_policies = 8

[dynamic_policy.automation_api]
enabled = true
signature_key_env = "OXIBELT_DYNAMIC_POLICY_HMAC_KEY_TEST"
default_source_quota = 9

[shared_state]
enabled = true
namespace = "matrix"
dynamic_policy_backend = "postgres-main"

[[shared_state.backends]]
name = "postgres-main"
kind = "postgres"
connection_url = "postgres://oxibelt:oxibelt@mock-postgres:5432/oxibelt"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("default quota above max_policies should fail");
  assert!(
    error
      .to_string()
      .contains("default_source_quota must be less than or equal")
  );
}

#[test]
fn dynamic_policy_rejects_non_postgres_backend() {
  let temp_dir = common::TempDir::new("dynamic-policy-redis");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "dynamic-policy-redis");
  let raw = format!(
    r#"
{}

[dynamic_policy]
enabled = true
backend = "redis-main"

[shared_state]
enabled = true

[[shared_state.backends]]
name = "redis-main"
kind = "redis"
connection_url = "redis://mock-redis:6379/0"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("dynamic policy should require postgres");

  assert!(
    error
      .to_string()
      .contains("dynamic_policy backend redis-main must use kind = \"postgres\""),
    "unexpected error: {error}"
  );
}

#[test]
fn dynamic_policy_rejects_invalid_values() {
  let temp_dir = common::TempDir::new("dynamic-policy-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "dynamic-policy-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (setting, expected) in [
    (
      "refresh_interval_ms = 0",
      "dynamic_policy.refresh_interval_ms must be greater than 0",
    ),
    (
      "max_policies = 0",
      "dynamic_policy.max_policies must be greater than 0",
    ),
    (
      "default_status = 99",
      "dynamic_policy.default_status is not a valid HTTP status",
    ),
    (
      "\n[dynamic_policy.matching]\nipv4_prefix_bits = 33",
      "dynamic_policy.matching.ipv4_prefix_bits must be between 0 and 32",
    ),
    (
      "\n[dynamic_policy.matching]\nipv6_prefix_bits = 129",
      "dynamic_policy.matching.ipv6_prefix_bits must be between 0 and 128",
    ),
    (
      "\n[dynamic_policy.matching]\ntoken_bindings = [\"user_agent\", \"user_agent\"]",
      "dynamic_policy.matching.token_bindings contains duplicate user_agent",
    ),
    (
      "\n[dynamic_policy.matching]\ncomposite_identity_parts = [\"client_ip_prefix\", \"client_ip_prefix\"]",
      "dynamic_policy.matching.composite_identity_parts contains duplicate ClientIpPrefix",
    ),
  ] {
    let raw = format!(
      r#"
{base}

[dynamic_policy]
{setting}
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
      error.to_string().contains(expected),
      "unexpected error for {setting}: {error}"
    );
  }
}

#[test]
fn dynamic_policy_matching_unknown_fields_fail_strict_shape_validation() {
  let temp_dir = common::TempDir::new("dynamic-policy-matching-unknown");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "dynamic-policy-matching-unknown");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[dynamic_policy.matching]
ipv4_prefix_bits = 24
ipv6_prefix_bits = 56
token_bindings = ["user_agent", "tls_fingerprint", "route", "direct_peer_ip_network_prefix"]
composite_identity_parts = ["client_ip_prefix", "user_agent", "tls_fingerprint", "asn"]
unexpected = true
"#;
  let config_path = temp_dir.path().join("oxibelt.toml");
  std::fs::write(&config_path, raw).expect("config should write");

  let error =
    Config::load(&config_path).expect_err("unknown dynamic_policy.matching field should fail");
  assert!(
    error
      .to_string()
      .contains("configuration contains unknown field(s): dynamic_policy.matching.unexpected"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn rate_limit_config_parses_route_and_token_keys() {
  let temp_dir = common::TempDir::new("rate-limit-config");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "rate-limit-config");
  let raw = format!(
    r#"
{}

[[rate_limits]]
name = "route-token"
key = "access-token-route"
routes = ["app-root"]
access_token_source = "trusted_header"
token_header = "X-Api-Token"
rate = "10r/m"
burst = 10
max_buckets = 256
status = 429

[[rate_limits]]
name = "route-bearer"
key = "access_token_route"
routes = ["app-root"]
access_token_source = "trusted_authorization_bearer"
rate = "10r/m"
burst = 10
status = 429
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.rate_limits[0].key, RateLimitKey::AccessTokenRoute);
  assert_eq!(config.rate_limits[0].routes, ["app-root"]);
  assert_eq!(
    config.rate_limits[0].token_header.as_deref(),
    Some("X-Api-Token")
  );
  assert_eq!(
    config.rate_limits[0].access_token_source,
    Some(AccessTokenRateLimitSource::TrustedHeader)
  );
  assert_eq!(config.rate_limits[0].max_buckets, 256);
  assert_eq!(config.rate_limits[1].key, RateLimitKey::AccessTokenRoute);
  assert_eq!(
    config.rate_limits[1].access_token_source,
    Some(AccessTokenRateLimitSource::TrustedAuthorizationBearer)
  );
  assert_eq!(config.rate_limits[1].token_header.as_deref(), None);
}

#[test]
fn rate_limit_config_parses_global_and_route_keys() {
  let temp_dir = common::TempDir::new("rate-limit-global-route-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "rate-limit-global-route-config");
  let raw = format!(
    r#"
{}

[[rate_limits]]
name = "global-flood"
key = "global"
rate = "100r/s"
burst = 200

[[rate_limits]]
name = "route-flood"
key = "route"
routes = ["app-root"]
rate = "20r/s"
burst = 40
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.rate_limits[0].key, RateLimitKey::Global);
  assert_eq!(config.rate_limits[1].key, RateLimitKey::Route);
  assert_eq!(config.rate_limits[1].routes, ["app-root"]);
}

#[test]
fn rate_limit_config_parses_sybil_oriented_top_level_keys() {
  let temp_dir = common::TempDir::new("rate-limit-sybil-keys");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "rate-limit-sybil-keys");
  let raw = format!(
    r#"
{}

[[rate_limits]]
name = "prefix-route"
key = "client_ip_prefix_route"
routes = ["app-root"]
ipv4_prefix_bits = 20
ipv6_prefix_bits = 60
rate = "10r/m"

[[rate_limits]]
name = "tls-route"
key = "tls_fingerprint_route"
routes = ["app-root"]
rate = "10r/m"

[[rate_limits]]
name = "composite-route"
key = "composite_client_route"
routes = ["app-root"]
identity_parts = ["client_ip_prefix", "user_agent", "tls_fingerprint", "asn"]
rate = "10r/m"

[[rate_limits]]
name = "asn-route"
key = "asn_route"
routes = ["app-root"]
rate = "10r/m"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.rate_limits[0].key, RateLimitKey::ClientIpPrefixRoute);
  assert_eq!(config.rate_limits[0].ipv4_prefix_bits, 20);
  assert_eq!(config.rate_limits[0].ipv6_prefix_bits, 60);
  assert_eq!(config.rate_limits[1].key, RateLimitKey::TlsFingerprintRoute);
  assert_eq!(
    config.rate_limits[2].key,
    RateLimitKey::CompositeClientRoute
  );
  assert_eq!(
    config.rate_limits[2].identity_parts,
    [
      RateLimitIdentityPart::ClientIpPrefix,
      RateLimitIdentityPart::UserAgent,
      RateLimitIdentityPart::TlsFingerprint,
      RateLimitIdentityPart::Asn,
    ]
  );
  assert_eq!(config.rate_limits[3].key, RateLimitKey::AsnRoute);
}

#[test]
fn rate_limit_config_rejects_waf_only_keys_at_top_level() {
  for key in ["token_binding_hash", "person_proof_clearance_route"] {
    let key_label = key.replace('_', "-");
    let temp_dir = common::TempDir::new(&format!("rate-limit-waf-only-{key_label}"));
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), &format!("rate-limit-{key_label}"));
    let raw = format!(
      r#"
{}

[[rate_limits]]
name = "{key}-top-level"
key = "{key}"
rate = "10r/m"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("WAF-only rate-limit key should fail at top level");
    assert!(
      error
        .to_string()
        .contains("only valid in WAF rate_limit actions"),
      "unexpected error for {key}: {error}"
    );
  }
}

#[test]
fn rate_limit_config_validates_prefix_bits_and_identity_parts() {
  let temp_dir = common::TempDir::new("rate-limit-prefix-bits");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "rate-limit-prefix-bits");
  let raw = format!(
    r#"
{}

[[rate_limits]]
name = "bad-prefix"
key = "client_ip_prefix"
ipv4_prefix_bits = 33
rate = "10r/m"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("invalid prefix bits should fail");
  assert!(
    error
      .to_string()
      .contains("ipv4_prefix_bits must be between 0 and 32"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{}

[[rate_limits]]
name = "bad-composite"
key = "composite_client"
rate = "10r/m"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("composite without identity_parts should fail");
  assert!(
    error
      .to_string()
      .contains("identity_parts must not be empty for composite_client keys"),
    "unexpected error: {error}"
  );
}

#[test]
fn rate_limit_config_rejects_token_header_for_global_and_route_keys() {
  for key in ["global", "route"] {
    let temp_dir = common::TempDir::new(&format!("rate-limit-token-header-{key}"));
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), &format!("rate-limit-{key}"));
    let raw = format!(
      r#"
{}

[[rate_limits]]
name = "{key}-with-token-header"
key = "{key}"
token_header = "X-Api-Token"
rate = "10r/m"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("token_header should require access_token key");
    assert!(
      error
        .to_string()
        .contains("token_header requires an access_token key"),
      "unexpected error for {key}: {error}"
    );
  }
}

#[test]
fn rate_limit_config_validates_access_token_source_trust_boundary() {
  let cases = [
    (
      "missing-source",
      r#"
[[rate_limits]]
name = "missing-source"
key = "access_token_route"
routes = ["app-root"]
rate = "10r/m"
"#,
      "access_token keys require access_token_source",
    ),
    (
      "header-without-token-header",
      r#"
[[rate_limits]]
name = "header-without-token-header"
key = "access_token_route"
routes = ["app-root"]
access_token_source = "trusted_header"
rate = "10r/m"
"#,
      "trusted_header access_token_source requires token_header",
    ),
    (
      "bearer-with-token-header",
      r#"
[[rate_limits]]
name = "bearer-with-token-header"
key = "access_token_route"
routes = ["app-root"]
access_token_source = "trusted_authorization_bearer"
token_header = "X-Api-Token"
rate = "10r/m"
"#,
      "trusted_authorization_bearer access_token_source must not set token_header",
    ),
    (
      "source-on-client-ip",
      r#"
[[rate_limits]]
name = "source-on-client-ip"
key = "client_ip"
access_token_source = "trusted_authorization_bearer"
rate = "10r/m"
"#,
      "access_token_source requires an access_token key",
    ),
  ];

  for (name, rate_limit, expected) in cases {
    let temp_dir = common::TempDir::new(&format!("rate-limit-{name}"));
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), &format!("rate-limit-{name}"));
    let raw = format!(
      "{}\n{}",
      common::minimal_config_toml(&cert_path, &key_path),
      rate_limit
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid access token source should fail validation");
    assert!(
      error.to_string().contains(expected),
      "unexpected error for {name}: {error}"
    );
  }
}

#[test]
fn rate_limit_config_rejects_unknown_route_filter() {
  let temp_dir = common::TempDir::new("rate-limit-unknown-route");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "rate-limit-unknown-route");
  let raw = format!(
    r#"
{}

[[rate_limits]]
name = "unknown-route"
key = "client_ip_route"
routes = ["missing-route"]
rate = "10r/m"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("unknown route filter should fail");
  assert!(
    error
      .to_string()
      .contains("rate limit unknown-route references unknown route missing-route"),
    "unexpected error: {error}"
  );
}

#[test]
fn client_identity_asn_config_validates_local_and_managed_modes() {
  let temp_dir = common::TempDir::new("client-identity-asn-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "client-identity-asn-config");
  let database_path = temp_dir.path().join("asn-prefixes.csv");
  std::fs::write(&database_path, "prefix,asn\n203.0.113.0/24,AS64500\n")
    .expect("ASN database fixture should write");
  let raw = format!(
    r#"
{}

[client_identity.asn]
mode = "local"
database_file = "{}"
format = "prefix_asn_csv"
max_database_bytes = 4096
max_entries = 16
max_database_age_seconds = 3600
failure_policy = "degraded_null"

[client_identity.asn.iana_registry]
enabled = true
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    database_path.display()
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(
    config.client_identity.asn.mode,
    ClientIdentityAsnMode::Local
  );
  assert_eq!(
    config.client_identity.asn.failure_policy,
    ClientIdentityAsnFailurePolicy::DegradedNull
  );
  assert!(config.client_identity.asn.iana_registry.enabled);

  let raw = format!(
    r#"
{}

[client_identity.asn]
mode = "managed"
failure_policy = "degraded_null"

[client_identity.asn.managed]
source_url = "https://operator.example/asn-prefixes.csv"
storage = "memory"
refresh_interval_seconds = 3600
request_timeout_ms = 500
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(
    config.client_identity.asn.mode,
    ClientIdentityAsnMode::Managed
  );
  assert_eq!(
    config.client_identity.asn.managed.storage,
    ClientIdentityAsnManagedStorage::Memory
  );
}

#[test]
fn client_identity_asn_config_rejects_invalid_sources() {
  let temp_dir = common::TempDir::new("client-identity-asn-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "client-identity-asn-invalid");
  let raw = format!(
    r#"
{}

[client_identity.asn]
mode = "managed"

[client_identity.asn.managed]
source_url = "http://operator.example/asn-prefixes.csv"
storage = "memory"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("managed ASN source must be HTTPS");
  assert!(
    error.to_string().contains("must use https://"),
    "unexpected error: {error}"
  );
}

#[test]
fn rate_limit_config_rejects_zero_max_buckets() {
  let temp_dir = common::TempDir::new("rate-limit-zero-buckets");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "rate-limit-zero-buckets");
  let raw = format!(
    r#"
{}

[[rate_limits]]
name = "zero-buckets"
key = "access_token"
access_token_source = "trusted_authorization_bearer"
rate = "10r/m"
max_buckets = 0
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("zero max_buckets should fail");
  assert!(
    error
      .to_string()
      .contains("rate limit zero-buckets max_buckets must be greater than 0"),
    "unexpected error: {error}"
  );
}

#[test]
fn shared_state_rejects_unknown_feature_backend() {
  let temp_dir = common::TempDir::new("shared-state-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "shared-state-invalid");
  let raw = format!(
    r#"
{}

[shared_state]
enabled = true
default_backend = "redis-main"
cache_backend = "missing"

[[shared_state.backends]]
name = "redis-main"
kind = "redis"
connection_url = "redis://mock-redis:6379/0"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("unknown backend should fail");

  assert!(
    error
      .to_string()
      .contains("shared_state.cache_backend references unknown"),
    "unexpected error: {error}"
  );
}

#[test]
fn effective_config_dump_redacts_shared_state_connection_urls() {
  let temp_dir = common::TempDir::new("shared-redacted");
  let config_path = write_loadable_config(&temp_dir, "shared-redacted", |raw| {
    raw.replace(
      "[[upstreams]]",
      r#"[shared_state]
enabled = true
default_backend = "redis-main"

[[shared_state.backends]]
name = "redis-main"
kind = "redis"
connection_url = "redis://:secret@redis.example:6379/0"

[[upstreams]]"#,
    )
  });

  let redacted =
    toml::to_string_pretty(&Config::load_effective_toml_redacted(&config_path).unwrap())
      .expect("redacted TOML should serialize");

  assert!(redacted.contains("connection_url = \"<redacted>\""));
  assert!(!redacted.contains("secret@redis.example"));
}

#[test]
fn effective_config_dump_redacts_upstream_origin_sensitive_url_parts() {
  let temp_dir = common::TempDir::new("upstream-origin-redacted");
  let config_path = write_loadable_config(&temp_dir, "upstream-origin-redacted", |raw| {
    raw
      .replace(
        "origin = \"https://app.internal.example\"",
        "origin = \"https://user:secret@app.internal.example/private?token=secret#frag\"",
      )
      .replace(
        "[[routes]]",
        r#"[[upstream_pools]]
name = "app-pool"

[[upstream_pools.servers]]
id = "app-a"
origin = "https://pooluser:poolsecret@pool.internal.example/base?pool_token=secret#poolfrag"

[[routes]]"#,
      )
  });

  let value = Config::load_effective_toml_redacted(&config_path).unwrap();
  let upstreams = value
    .get("upstreams")
    .and_then(toml::Value::as_array)
    .expect("effective TOML should contain upstreams");
  assert_eq!(
    upstreams[0].get("origin").and_then(toml::Value::as_str),
    Some("https://app.internal.example/private")
  );
  let pools = value
    .get("upstream_pools")
    .and_then(toml::Value::as_array)
    .expect("effective TOML should contain upstream pools");
  let servers = pools[0]
    .get("servers")
    .and_then(toml::Value::as_array)
    .expect("effective TOML should contain upstream pool servers");
  assert_eq!(
    servers[0].get("origin").and_then(toml::Value::as_str),
    Some("https://pool.internal.example/base")
  );

  let redacted = toml::to_string_pretty(&value).expect("redacted TOML should serialize");
  assert!(!redacted.contains("user:secret"));
  assert!(!redacted.contains("token=secret"));
  assert!(!redacted.contains("pooluser:poolsecret"));
  assert!(!redacted.contains("pool_token=secret"));
}

#[test]
fn effective_config_dump_redacts_ocsp_responder_url_sensitive_url_parts() {
  let temp_dir = common::TempDir::new("ocsp-responder-url-redacted");
  let config_path = write_loadable_config(&temp_dir, "ocsp-responder-url-redacted", |raw| {
    raw.replace(
            "mode = \"disabled\"",
            "mode = \"live_fetch\"\nresponder_url = \"https://ocsp.internal.example/status?tenant=prod&token=SECRET_QUERY_TOKEN\"",
        )
  });

  let value = Config::load_effective_toml_redacted(&config_path).unwrap();
  let ocsp = value
    .get("tls")
    .and_then(|tls| tls.get("ocsp"))
    .expect("effective TOML should contain tls.ocsp");
  assert_eq!(
    ocsp.get("responder_url").and_then(toml::Value::as_str),
    Some("https://ocsp.internal.example/status")
  );

  let redacted = toml::to_string_pretty(&value).expect("redacted TOML should serialize");
  assert!(!redacted.contains("tenant=prod"));
  assert!(!redacted.contains("SECRET_QUERY_TOKEN"));
}

#[test]
fn effective_config_dump_redacts_break_glass_access_hashes() {
  let temp_dir = common::TempDir::new("ipm-break-glass-redacted");
  let hash = test_argon2id_hash("break-glass-secret", 8);
  let config_path = write_loadable_config(&temp_dir, "ipm-break-glass-redacted", |raw| {
    raw.replace(
      "[[upstreams]]",
      &format!(
        r#"[ipm]
enabled = true

[ipm.break_glass]
argon2id_memory_mib = 1

[[ipm.principals]]
id = "break-glass-admin"
subject = "break-glass"
groups = ["ipm-admin"]

[[ipm.credentials]]
name = "break-glass-token"
principal = "break-glass-admin"
break_glass_access_token_hash = "{hash}"

[[upstreams]]"#
      ),
    )
  });

  let redacted =
    toml::to_string_pretty(&Config::load_effective_toml_redacted(&config_path).unwrap())
      .expect("redacted TOML should serialize");

  assert!(redacted.contains("break_glass_access_token_hash = \"<redacted>\""));
  assert!(!redacted.contains(&hash));
}

#[test]
fn effective_config_dump_redacts_webrtc_turn_auth_secrets() {
  let temp_dir = common::TempDir::new("turn-redacted");
  let config_path = write_loadable_config(&temp_dir, "turn-redacted", |raw| {
    raw.replace(
      "[[upstreams]]",
      r#"[[webrtc_turn_listeners]]
name = "turn-edge"
mode = "edge_relay"
bind_udp = "127.0.0.1:0"
realm = "example.test"
public_ip = "127.0.0.1"
relay_bind_ip = "127.0.0.1"

[webrtc_turn_listeners.relay_port_range]
start = 49152
end = 49160

[webrtc_turn_listeners.auth]
mode = "enforce"
rest_shared_secret = "REST-SHARED-SECRET-LEAK"

[[webrtc_turn_listeners.auth.static_credentials]]
username = "media-user"
password = "STATIC-PASSWORD-LEAK"

[[upstreams]]"#,
    )
  });

  let value = Config::load_effective_toml_redacted(&config_path).unwrap();
  let listeners = value
    .get("webrtc_turn_listeners")
    .and_then(toml::Value::as_array)
    .expect("effective TOML should contain TURN listeners");
  let auth = listeners[0]
    .get("auth")
    .and_then(toml::Value::as_table)
    .expect("effective TOML should contain TURN auth");
  assert_eq!(
    auth.get("rest_shared_secret").and_then(toml::Value::as_str),
    Some("<redacted>")
  );
  let static_credentials = auth
    .get("static_credentials")
    .and_then(toml::Value::as_array)
    .expect("effective TOML should contain TURN static credentials");
  assert_eq!(
    static_credentials[0]
      .get("password")
      .and_then(toml::Value::as_str),
    Some("<redacted>")
  );
  assert_eq!(
    static_credentials[0]
      .get("username")
      .and_then(toml::Value::as_str),
    Some("media-user")
  );

  let redacted = toml::to_string_pretty(&value).expect("redacted TOML should serialize");
  assert!(!redacted.contains("REST-SHARED-SECRET-LEAK"));
  assert!(!redacted.contains("STATIC-PASSWORD-LEAK"));
}

#[test]
fn effective_config_dump_resolves_auto_worker_counts() {
  let temp_dir = common::TempDir::new("effective-workers");
  let config_path = write_loadable_config(&temp_dir, "effective-workers", |raw| raw);

  let rendered =
    toml::to_string_pretty(&Config::load_effective_toml_redacted(&config_path).unwrap())
      .expect("effective TOML should serialize");
  let expected_runtime = available_parallelism();
  let expected_accept = resolve_auto_worker_count(expected_runtime, 0.5).unwrap();
  let rendered_value: toml::Value = toml::from_str(&rendered).expect("effective TOML should parse");
  let runtime = rendered_value
    .get("runtime")
    .and_then(toml::Value::as_table)
    .expect("effective TOML should contain runtime table");
  let worker_multipliers = runtime
    .get("worker_multipliers")
    .and_then(toml::Value::as_table)
    .expect("effective TOML should contain runtime.worker_multipliers table");
  let accept = runtime
    .get("accept")
    .and_then(toml::Value::as_table)
    .expect("effective TOML should contain runtime.accept table");

  assert_eq!(
    runtime
      .get("worker_threads")
      .and_then(toml::Value::as_integer),
    Some(i64::try_from(expected_runtime).unwrap())
  );
  assert_eq!(
    worker_multipliers
      .get("accept")
      .and_then(toml::Value::as_float),
    Some(0.5)
  );
  assert_eq!(
    accept.get("workers").and_then(toml::Value::as_integer),
    Some(i64::try_from(expected_accept).unwrap())
  );
  assert!(
    !rendered.contains("\"auto\""),
    "effective config should not keep auto worker strings: {rendered}"
  );
}

#[test]
fn admin_transport_plaintext_requires_explicit_insecure_opt_in() {
  unsafe {
    std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("admin-plaintext");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "admin-plaintext");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"
transport = "plaintext"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("plain admin transport should require opt-in");
  assert!(
    error
      .to_string()
      .contains("admin.allow_insecure_plaintext must be true"),
    "unexpected error: {error}"
  );
}

#[test]
fn admin_non_loopback_auto_requires_tls() {
  unsafe {
    std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("admin-auto");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "admin-auto");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bind = "0.0.0.0:9092"
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"
transport = "auto"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("non-loopback auto admin transport should require TLS");
  assert!(
    error.to_string().contains("admin.tls.enabled must be true"),
    "unexpected error: {error}"
  );
}

#[test]
fn admin_tls_sni_certificate_config_validates() {
  unsafe {
    std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("admin-tls");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "admin-tls");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bind = "0.0.0.0:9092"
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"
transport = "auto"

[admin.tls]
enabled = true
require_sni = true
reject_unknown_sni = true

[[admin.tls.certificates]]
server_names = ["admin.example.com", "*.ops.example.com"]
cert_chain = "{}"
private_key = "{}"
default = true
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    cert_path.display(),
    key_path.display()
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert!(config.admin.tls.enabled);
  assert_eq!(config.admin.transport, AdminTransportMode::Auto);
}

#[test]
fn admin_http3_and_operation_webtransport_config_validates() {
  unsafe {
    std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("admin-http3");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "admin-http3");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bind = "127.0.0.1:9092"
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"
transport = "tls"

[admin.http3]
enabled = true
bind = "127.0.0.1:9443"

[admin.operations]
webtransport = false
webtransport_max_sessions = 12

[admin.tls]
enabled = true
min_version = "tls1.3"
max_version = "tls1.3"

[[admin.tls.certificates]]
server_names = ["admin.example.com"]
cert_chain = "{}"
private_key = "{}"
default = true
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    cert_path.display(),
    key_path.display()
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert!(config.admin.http3.enabled);
  assert_eq!(
    config.admin.http3.bind,
    Some("127.0.0.1:9443".parse().expect("bind should parse"))
  );
  assert!(!config.admin.operations.webtransport);
  assert_eq!(config.admin.operations.webtransport_max_sessions, 12);
}

#[test]
fn admin_http3_requires_admin_and_tls13() {
  let temp_dir = common::TempDir::new("admin-http3-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-http3-invalid");
  let raw = format!(
    r#"
{}

[admin.http3]
enabled = true
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("admin HTTP/3 should require admin.enabled");
  assert!(
    error
      .to_string()
      .contains("admin.http3.enabled requires admin.enabled = true"),
    "unexpected error: {error}"
  );

  unsafe {
    std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
  }
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bind = "127.0.0.1:9092"
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"
transport = "auto"

[admin.http3]
enabled = true
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("admin HTTP/3 should require admin TLS");
  assert!(
    error
      .to_string()
      .contains("admin.http3.enabled requires admin.tls.enabled = true"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{}

[admin]
enabled = true
bind = "127.0.0.1:9092"
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"
transport = "auto"

[admin.http3]
enabled = true

[admin.tls]
enabled = true
min_version = "tls1.2"
max_version = "tls1.2"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("admin HTTP/3 should require TLS 1.3 support");
  assert!(
    error
      .to_string()
      .contains("admin.http3.enabled requires admin.tls.max_version to allow tls1.3"),
    "unexpected error: {error}"
  );
}

#[test]
fn ipm_config_parses_principals_credentials_policies_and_bindings() {
  unsafe {
    std::env::set_var("OXIBELT_IPM_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("ipm-config");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ipm-config");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[ipm]
enabled = true
namespace = "default"

[[ipm.principals]]
id = "deployer"
subject = "oidc:ci/deployer"
groups = ["operators"]

[[ipm.credentials]]
name = "deployer-token"
principal = "deployer"
bearer_token_env = "OXIBELT_IPM_TOKEN_TEST"

[[ipm.policies]]
name = "config-read"

[[ipm.policies.statements]]
effect = "allow"
actions = ["config:GetStatus", "config:GetEffective"]
resources = ["oxibelt:default:config:*"]

[[ipm.bindings]]
group = "operators"
policy = "config-read"
    "#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert!(config.ipm.enabled);
  assert_eq!(config.ipm.namespace, "default");
  assert_eq!(config.ipm.principals[0].id, "deployer");
  assert_eq!(config.ipm.credentials[0].principal, "deployer");
  assert!(matches!(
    config.ipm.policies[0].statements[0].effect,
    IpmPolicyEffect::Allow
  ));
  assert_eq!(config.ipm.bindings[0].group.as_deref(), Some("operators"));
}

#[test]
fn ipm_break_glass_access_credential_uses_argon2id_hash() {
  let temp_dir = common::TempDir::new("ipm-break-glass");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ipm-break-glass");
  let hash = test_argon2id_hash("break-glass-secret", 8);
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[ipm]
enabled = true
namespace = "default"

[ipm.break_glass]
argon2id_memory_mib = 1

[[ipm.principals]]
id = "break-glass-admin"
subject = "break-glass"
groups = ["ipm-admin"]

[[ipm.credentials]]
name = "break-glass-token"
principal = "break-glass-admin"
break_glass_access_token_hash = "{hash}"
    "#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.ipm.break_glass.argon2id_memory_mib, 1);
  assert_eq!(config.ipm.credentials[0].bearer_token_env, "");
  assert!(
    config.ipm.credentials[0]
      .break_glass_access_token_hash
      .is_some()
  );
}

#[test]
fn ipm_break_glass_access_hash_cannot_exceed_configured_memory() {
  let temp_dir = common::TempDir::new("ipm-break-glass-memory");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "ipm-break-glass-memory");
  let hash = test_argon2id_hash("break-glass-secret", 2048);
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[ipm]
enabled = true
namespace = "default"

[ipm.break_glass]
argon2id_memory_mib = 1

[[ipm.principals]]
id = "break-glass-admin"
subject = "break-glass"
groups = ["ipm-admin"]

[[ipm.credentials]]
name = "break-glass-token"
principal = "break-glass-admin"
break_glass_access_token_hash = "{hash}"
    "#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("hash memory above configured limit should fail");
  assert!(
    error
      .to_string()
      .contains("above ipm.break_glass.argon2id_memory_mib"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn ipm_config_accepts_oxirule_management_actions() {
  unsafe {
    std::env::set_var("OXIBELT_IPM_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("ipm-oxirule-actions");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "ipm-oxirule-actions");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[ipm]
enabled = true
namespace = "default"

[[ipm.principals]]
id = "waf-deployer"
subject = "oidc:ci/waf-deployer"
groups = ["waf-operators"]

[[ipm.credentials]]
name = "waf-deployer-token"
principal = "waf-deployer"
bearer_token_env = "OXIBELT_IPM_TOKEN_TEST"

[[ipm.policies]]
name = "oxirule-management"

[[ipm.policies.statements]]
effect = "allow"
actions = [
    "waf:PutOxiRule",
    "waf:DeleteOxiRule",
    "waf:PutOxiRuleGroup",
    "waf:DeleteOxiRuleGroup",
    "waf:CheckOxiRule",
    "waf:CheckOxiRuleGroup",
    "waf:TestOxiRule",
    "waf:ExplainOxiRule",
    "waf:EstimateOxiRuleCost",
    "waf:ReplayOxiRule",
    "waf:AnalyzeOxiRuleRisk",
    "waf:PlanOxiRuleHardening",
    "waf:PlanOxiRulePack",
    "config:ReadRouteInventory",
]
resources = [
    "oxibelt:default:waf:oxirule/*",
    "oxibelt:default:waf:oxirule-group/*",
    "oxibelt:default:waf:oxirule-rulepack/*",
    "oxibelt:default:config:route-inventory/current",
    "oxibelt:default:waf:replay/*",
    "oxibelt:default:waf:analyze/*",
    "oxibelt:default:waf:hardening-plan/*",
]

[[ipm.policies.statements]]
effect = "allow"
actions = [
    "waf:ReloadOxiRule",
    "waf:ListOxiRuleTemplates",
    "waf:RenderOxiRuleTemplate",
    "waf:PlanOxiRuleFalsePositive",
]
resources = [
    "*",
    "oxibelt:default:waf:template/*",
    "oxibelt:default:waf:false-positive/*",
]

[[ipm.bindings]]
group = "waf-operators"
policy = "oxirule-management"
    "#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
}

#[test]
fn ipm_config_accepts_diagnostics_actions() {
  unsafe {
    std::env::set_var("OXIBELT_IPM_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("ipm-diagnostics-actions");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "ipm-diagnostics-actions");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[ipm]
enabled = true
namespace = "default"

[[ipm.principals]]
id = "diagnostics"
subject = "oidc:ci/diagnostics"
groups = ["diagnostics-readers"]

[[ipm.credentials]]
name = "diagnostics-token"
principal = "diagnostics"
bearer_token_env = "OXIBELT_IPM_TOKEN_TEST"

[[ipm.policies]]
name = "diagnostics-preflight"

[[ipm.policies.statements]]
effect = "allow"
actions = ["diagnostics:ReadPreflight", "diagnostics:RunPreflight", "diagnostics:RunProbe"]
resources = [
    "oxibelt:default:diagnostics:preflight/current",
    "oxibelt:default:diagnostics:preflight/candidate",
    "oxibelt:default:diagnostics:probe/shared_state",
    "oxibelt:default:diagnostics:probe/shared_state/tcp/redis.example.test:6379",
    "oxibelt:default:diagnostics:probe/upstream/tcp/example.test:443",
    "oxibelt:default:diagnostics:probe/upstream/tcp/*",
    "oxibelt:default:diagnostics:probe/remote_signer/unix/*",
]

[[ipm.bindings]]
group = "diagnostics-readers"
policy = "diagnostics-preflight"
    "#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
}

#[test]
fn ipm_config_accepts_control_plane_config_update_actions() {
  unsafe {
    std::env::set_var("OXIBELT_IPM_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("ipm-control-plane-actions");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "ipm-control-plane-actions");
  let raw = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[ipm]
enabled = true
namespace = "default"

[[ipm.principals]]
id = "deployer"
subject = "oidc:ci/deployer"
groups = ["operators"]

[[ipm.credentials]]
name = "deployer-token"
principal = "deployer"
bearer_token_env = "OXIBELT_IPM_TOKEN_TEST"

[[ipm.policies]]
name = "control-plane-config"

[[ipm.policies.statements]]
effect = "allow"
actions = ["admin:ReadMetadata", "admin:UpdateConfig", "admin:*", "ipm:UpdateConfig", "ipm:*"]
resources = [
    "oxibelt:default:admin:metadata/openapi",
    "oxibelt:default:admin:config",
    "oxibelt:default:admin:*",
    "oxibelt:default:ipm:config",
    "oxibelt:default:ipm:*",
]

[[ipm.bindings]]
group = "operators"
policy = "control-plane-config"
    "#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
}

#[test]
fn ipm_config_rejects_unknown_action_resource_condition_and_legacy_token_store() {
  unsafe {
    std::env::set_var("OXIBELT_IPM_TOKEN_TEST", "secret");
  }
  let temp_dir = common::TempDir::new("ipm-invalid");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ipm-invalid");
  let base = format!(
    r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[ipm]
enabled = true
namespace = "default"

[[ipm.principals]]
id = "deployer"
subject = "oidc:ci/deployer"
groups = ["operators"]

[[ipm.credentials]]
name = "deployer-token"
principal = "deployer"
bearer_token_env = "OXIBELT_IPM_TOKEN_TEST"

[[ipm.policies]]
name = "policy"

[[ipm.policies.statements]]
effect = "allow"
actions = ["{{action}}"]
resources = ["{{resource}}"]
{{condition}}

[[ipm.bindings]]
group = "operators"
policy = "policy"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let unknown_action = base
    .replace("{action}", "config:Teleport")
    .replace("{resource}", "oxibelt:default:config:*")
    .replace("{condition}", "");
  let config: Config = toml::from_str(&unknown_action).expect("config should parse");
  let error = config.validate().expect_err("unknown action should fail");
  assert!(
    error
      .to_string()
      .contains("unsupported action config:Teleport"),
    "unexpected error: {error}"
  );

  let unknown_waf_action = base
    .replace("{action}", "waf:Teleport")
    .replace("{resource}", "oxibelt:default:waf:*")
    .replace("{condition}", "");
  let config: Config = toml::from_str(&unknown_waf_action).expect("config should parse");
  let error = config
    .validate()
    .expect_err("unknown WAF action should fail");
  assert!(
    error
      .to_string()
      .contains("unsupported action waf:Teleport"),
    "unexpected error: {error}"
  );

  let unknown_admin_action = base
    .replace("{action}", "admin:Teleport")
    .replace("{resource}", "oxibelt:default:admin:*")
    .replace("{condition}", "");
  let config: Config = toml::from_str(&unknown_admin_action).expect("config should parse");
  let error = config
    .validate()
    .expect_err("unknown Admin action should fail");
  assert!(
    error
      .to_string()
      .contains("unsupported action admin:Teleport"),
    "unexpected error: {error}"
  );

  let legacy_simulate_action = base
    .replace("{action}", "ipm:Simulate")
    .replace("{resource}", "oxibelt:default:ipm:simulation/current")
    .replace("{condition}", "");
  let config: Config = toml::from_str(&legacy_simulate_action).expect("config should parse");
  let error = config
    .validate()
    .expect_err("legacy IPM simulate action should fail");
  assert!(
    error
      .to_string()
      .contains("unsupported action ipm:Simulate"),
    "unexpected error: {error}"
  );

  let unknown_resource_service = base
    .replace("{action}", "config:GetStatus")
    .replace("{resource}", "oxibelt:default:unknown:*")
    .replace("{condition}", "");
  let config: Config = toml::from_str(&unknown_resource_service).expect("config should parse");
  let error = config
    .validate()
    .expect_err("unknown resource service should fail");
  assert!(
    error
      .to_string()
      .contains("unsupported IPM service unknown"),
    "unexpected error: {error}"
  );

  let unknown_condition = base
    .replace("{action}", "config:GetStatus")
    .replace("{resource}", "oxibelt:default:config:*")
    .replace(
      "{condition}",
      r#"conditions = [{ operator = "StringEquals", key = "request.cookie", values = ["x"] }]"#,
    );
  let config: Config = toml::from_str(&unknown_condition).expect("config should parse");
  let error = config
    .validate()
    .expect_err("unknown condition key should fail");
  let error_chain = format!("{error:#}");
  assert!(
    error_chain.contains("unsupported IPM condition key request.cookie"),
    "unexpected error: {error:#}"
  );

  let legacy_token_store = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[admin.token_store]
enabled = false
"#;
  let config: Config = toml::from_str(&legacy_token_store).expect("legacy shape should parse");
  let error = config
    .validate()
    .expect_err("legacy token store should be rejected");
  assert!(
    error
      .to_string()
      .contains("admin.token_store is legacy Admin token syntax"),
    "unexpected error: {error}"
  );
}

#[test]
fn upstream_pool_discovery_config_parses_dns_and_file_providers() {
  let temp_dir = common::TempDir::new("pool-discovery");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "pool-discovery");
  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "dynamic-pool"
algorithm = "power_of_two_choices"

[[upstream_pools.servers]]
id = "static-a"
origin = "http://static-a.example"
weight = 2
state = "maintenance"

[[upstream_pools.discovery]]
provider = "file"
file = "discovery/app.json"
refresh_interval_ms = 1000

[[upstream_pools.discovery]]
provider = "dns"
name = "app.internal.example"
record_type = "a_aaaa"
scheme = "http"
port = 8080
refresh_interval_ms = 5000
min_ttl_ms = 1000
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let pool = &config.upstream_pools[0];
  assert_eq!(pool.discovery[0].provider, UpstreamDiscoveryProvider::File);
  assert_eq!(pool.discovery[1].provider, UpstreamDiscoveryProvider::Dns);
  assert_eq!(
    pool.discovery[1].record_type,
    DnsDiscoveryRecordType::AAndAaaa
  );
}

#[test]
fn enterprise_reverse_proxy_config_parses_external_auth_sticky_cookie_and_discovery() {
  let temp_dir = common::TempDir::new("enterprise-reverse-proxy");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "enterprise-reverse-proxy");
  let raw = format!(
    r#"
{}

[[external_auth]]
name = "edge-auth"
provider = "oidc"
endpoint = "https://idp.example/userinfo"
required_scopes = ["openid"]

[[external_auth.required_claims]]
name = "aud"
value = "oxibelt"

[[external_auth.claim_headers]]
claim = "sub"
header = "remote-user"

[[routes]]
name = "auth-route"
hosts = ["secure.example"]
path_prefix = "/"
upstream = "app"
external_auth = "edge-auth"

[[upstream_pools]]
name = "sticky-pool"
algorithm = "sticky_cookie"

[upstream_pools.sticky_cookie]
cookie_name = "oxibelt_affinity"
ttl_seconds = 60
fallback_algorithm = "power_of_two_choices"
same_site = "strict"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"

[[upstream_pools.discovery]]
provider = "kubernetes"
endpoint = "https://kubernetes.default.svc"
namespace = "default"
service = "api"
port_name = "http"

[[upstream_pools]]
name = "consul-pool"

[[upstream_pools.discovery]]
provider = "consul"
endpoint = "http://consul.service.consul:8500"
service = "api"
datacenter = "dc1"

[[upstream_pools]]
name = "etcd-pool"

[[upstream_pools.discovery]]
provider = "etcd"
endpoint = "https://etcd.example:2379"
key_prefix = "/oxibelt/upstreams/api/"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.external_auth[0].provider, ExternalAuthProvider::Oidc);
  assert_eq!(config.routes[1].external_auth.as_deref(), Some("edge-auth"));
  assert_eq!(
    config.upstream_pools[0].discovery[0].provider,
    UpstreamDiscoveryProvider::Kubernetes
  );
  assert_eq!(
    config.upstream_pools[0].discovery[0].kubernetes_resource,
    KubernetesDiscoveryResource::Endpoints
  );
  assert!(!config.upstream_pools[0].discovery[0].watch);
  assert_eq!(
    config.upstream_pools[1].discovery[0].provider,
    UpstreamDiscoveryProvider::Consul
  );
  assert_eq!(
    config.upstream_pools[2].discovery[0].provider,
    UpstreamDiscoveryProvider::Etcd
  );
}

#[test]
fn kubernetes_endpoint_slice_watch_discovery_config_parses() {
  let temp_dir = common::TempDir::new("kubernetes-endpoint-slice-watch");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "kubernetes-endpoint-slice-watch");
  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "kubernetes-pool"

[[upstream_pools.discovery]]
provider = "kubernetes"
endpoint = "https://kubernetes.default.svc"
namespace = "default"
service = "api"
port = 8080
kubernetes_resource = "endpoint_slice"
watch = true
watch_timeout_seconds = 120
update_debounce_ms = 50
token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let discovery = &config.upstream_pools[0].discovery[0];
  assert_eq!(
    discovery.kubernetes_resource,
    KubernetesDiscoveryResource::EndpointSlice
  );
  assert!(discovery.watch);
  assert_eq!(discovery.watch_timeout_seconds, 120);
  assert_eq!(discovery.update_debounce_ms, 50);
  assert_eq!(
    discovery.token_file.as_deref(),
    Some(std::path::Path::new(
      "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ))
  );
}

#[test]
fn upstream_pool_discovery_rejects_bad_values() {
  let temp_dir = common::TempDir::new("pool-discovery-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "pool-discovery-invalid");
  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "dynamic-pool"
algorithm = "power_of_two_choices"

[[upstream_pools.discovery]]
provider = "consul"
service = "app"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("missing Consul endpoint should be rejected");
  assert!(
    error.to_string().contains("consul discovery endpoint"),
    "unexpected error: {error}"
  );

  let raw = raw
    .replace("provider = \"consul\"", "provider = \"dns\"")
    .replace(
      "service = \"app\"",
      "name = \"app\"\nrefresh_interval_ms = 0",
    );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("zero discovery interval should be rejected");
  assert!(
    error.to_string().contains("must be greater than 0"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "dynamic-pool"

[[upstream_pools.discovery]]
provider = "kubernetes"
endpoint = "https://kubernetes.default.svc"
namespace = "default"
service = "api"
port = 8080
watch = true
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("watching Endpoints should be rejected");
  assert!(
    error
      .to_string()
      .contains("watch requires kubernetes_resource"),
    "unexpected error: {error}"
  );

  let raw = raw
    .replace("provider = \"kubernetes\"", "provider = \"dns\"")
    .replace(
      "endpoint = \"https://kubernetes.default.svc\"",
      "name = \"app\"",
    )
    .replace("namespace = \"default\"\nservice = \"api\"\n", "")
    .replace("watch = true", "kubernetes_resource = \"endpoint_slice\"");
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("EndpointSlice resource on DNS discovery should be rejected");
  assert!(
    error
      .to_string()
      .contains("kubernetes_resource is only supported"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "dynamic-pool"

[[upstream_pools.discovery]]
provider = "kubernetes"
endpoint = "https://kubernetes.default.svc"
namespace = "default"
service = "api"
port = 8080
kubernetes_resource = "endpoint_slice"
watch = true
update_debounce_ms = 0
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("zero discovery debounce should be rejected");
  assert!(
    error.to_string().contains("update_debounce_ms"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "dynamic-pool"

[[upstream_pools.discovery]]
provider = "kubernetes"
endpoint = "https://kubernetes.default.svc"
namespace = "default"
service = "api"
port = 8080
token_env = "KUBERNETES_TOKEN"
token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("ambiguous Kubernetes token sources should be rejected");
  assert!(
    error
      .to_string()
      .contains("only one of token_env or token_file"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "slow-start-pool"

[upstream_pools.slow_start]
enabled = true
duration_ms = 0

[[upstream_pools.servers]]
id = "app"
origin = "http://app.example"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("zero slow_start duration should be rejected");
  assert!(
    error.to_string().contains("slow_start"),
    "unexpected error: {error}"
  );

  let raw = raw.replace(
    r#"[upstream_pools.slow_start]
enabled = true
duration_ms = 0"#,
    r#"[upstream_pools.outlier_ejection]
enabled = true
base_ejection_ms = 60000
max_ejection_ms = 10000"#,
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("outlier max below base should be rejected");
  assert!(
    error.to_string().contains("max_ejection_ms"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "nomad-pool"

[[upstream_pools.discovery]]
provider = "nomad"
service = "api"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("Nomad endpoint should be required");
  assert!(
    error.to_string().contains("nomad discovery endpoint"),
    "unexpected error: {error}"
  );

  let raw = raw
    .replace(
      "service = \"api\"",
      "endpoint = \"http://nomad.example:4646\"",
    )
    .replace(
      "provider = \"nomad\"",
      "provider = \"nomad\"\ndatacenter = \"dc1\"",
    );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("Nomad service and unsupported fields should be rejected");
  assert!(
    error.to_string().contains("nomad discovery service")
      || error.to_string().contains("only supports"),
    "unexpected error: {error}"
  );
}

#[test]
fn file_discovery_path_must_stay_under_config_directory() {
  let temp_dir = common::TempDir::new("pool-discovery-path");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("failed to create config dir");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert dir");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "pool-discovery-path");
  std::fs::copy(cert_path, cert_dir.join("fullchain.pem")).expect("failed to copy cert");
  std::fs::copy(key_path, cert_dir.join("privkey.pem")).expect("failed to copy key");
  let config_path = config_dir.join("oxibelt.toml");
  let raw = format!(
    r#"
{}

[[upstream_pools]]
name = "dynamic-pool"

[[upstream_pools.discovery]]
provider = "file"
file = "../outside.json"
"#,
    common::minimal_config_toml_with_paths("fullchain.pem", "privkey.pem")
  );
  std::fs::write(&config_path, raw).expect("failed to write config");

  let error = Config::load(&config_path)
    .expect_err("file discovery path outside config dir should be rejected");
  assert!(
    error.to_string().contains("parent-directory"),
    "unexpected error: {error}"
  );
}

#[test]
fn system_access_log_defaults_to_disabled_stdout() {
  let temp_dir = common::TempDir::new("system-access-log-default");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "system-access-log-default");
  let raw = common::minimal_config_toml(&cert_path, &key_path);

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(!config.logging.access_log.enabled);
  assert!(config.logging.access_log.stdout);
  assert!(!config.logging.access_log.fields.is_empty());
  assert_eq!(
    config
      .logging
      .access_log
      .fields
      .iter()
      .find(|field| field.name == "user_agent")
      .map(|field| field.value.as_str()),
    Some("Request.Headers.getAll('User-Agent')")
  );
  assert!(!config.logging.access_log.database.enabled);
}

#[test]
fn system_access_log_accepts_stdout_only_custom_fields() {
  let temp_dir = common::TempDir::new("system-access-log-stdout");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "system-access-log-stdout");
  let raw = format!(
    r#"
{}

[logging.access_log]
enabled = true
stdout = true

[[logging.access_log.fields]]
name = "method"
value = "Request.Http.Method"

[[logging.access_log.fields]]
name = "status"
expression = "Response.Http.Status"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(config.logging.access_log.enabled);
  assert_eq!(config.logging.access_log.fields.len(), 2);
}

#[test]
fn system_access_log_has_separate_database_config() {
  let temp_dir = common::TempDir::new("system-access-log-db");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "system-access-log-db");
  let raw = format!(
    r#"
{}

[logging.access_log]
enabled = true
stdout = false

[logging.access_log.database]
enabled = true
connection_url = "postgres://oxibelt:oxibelt@example.invalid:5432/oxibelt"
table = "system_access_log"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(config.logging.access_log.database.enabled);
  assert_eq!(
    config.logging.access_log.database.table.as_deref(),
    Some("system_access_log")
  );
  assert!(!config.database.access_log.enabled);
}

#[test]
fn system_access_log_rejects_duplicate_and_reserved_fields() {
  let temp_dir = common::TempDir::new("system-access-log-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "system-access-log-invalid");
  let raw = format!(
    r#"
{}

[logging.access_log]
enabled = true

[[logging.access_log.fields]]
name = "event"
value = "Request.Http.Method"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("reserved field should fail");
  assert!(
    error.to_string().contains("uses a reserved field name"),
    "unexpected error: {error}"
  );

  let raw = format!(
    r#"
{}

[logging.access_log]
enabled = true

[[logging.access_log.fields]]
name = "method"
value = "Request.Http.Method"

[[logging.access_log.fields]]
name = "method"
value = "Response.Http.Status"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("duplicate field should fail");
  assert!(
    error
      .to_string()
      .contains("contains duplicate field method"),
    "unexpected error: {error}"
  );
}

#[test]
fn quic_defaults_are_parsed() {
  let temp_dir = common::TempDir::new("quic-defaults");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "quic-defaults");
  let raw = common::minimal_config_toml(&cert_path, &key_path);

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(!config.quic.retry);
  assert_eq!(config.quic.zero_rtt, QuicZeroRttMode::Off);
  assert!(config.quic.alt_svc.enabled);
  assert_eq!(config.quic.alt_svc.max_age_seconds, 86_400);
  assert_eq!(config.quic.transport.max_concurrent_bidi_streams, 100);
  assert_eq!(config.quic.transport.keep_alive_interval_ms, 0);
  assert_eq!(config.quic.transport.stream_receive_window_bytes, 1_250_000);
  assert_eq!(config.quic.transport.receive_window_bytes, 8_388_608);
  assert_eq!(config.quic.transport.send_window_bytes, 10_000_000);
  assert!(config.quic.transport.send_fairness);
  assert_eq!(
    config.quic.transport.datagram_receive_buffer_bytes,
    1024 * 1024
  );
  assert_eq!(config.quic.transport.max_udp_payload_size, 1472);
  assert_eq!(config.quic.transport.initial_mtu, 1200);
  assert_eq!(config.quic.transport.min_mtu, 1200);
  assert!(config.quic.transport.mtu_discovery.enabled);
  assert_eq!(config.quic.transport.mtu_discovery.upper_bound, 1452);
  assert_eq!(config.quic.transport.mtu_discovery.interval_ms, 600_000);
  assert_eq!(
    config.quic.transport.mtu_discovery.black_hole_cooldown_ms,
    60_000
  );
  assert_eq!(config.quic.transport.mtu_discovery.minimum_change, 20);
  assert_eq!(config.quic.downstream.transport, config.quic.transport);
  assert_eq!(config.quic.upstream.transport, config.quic.transport);
  assert_eq!(config.quic.socket.receive_buffer_bytes, 0);
  assert!(config.quic.upstream_pool.enabled);
}

#[test]
fn quic_custom_values_are_parsed() {
  let temp_dir = common::TempDir::new("quic-custom");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "quic-custom");
  let raw = format!(
    r#"
{}

[quic]
retry = true
zero_rtt = "safe_methods"

[quic.alt_svc]
enabled = false
max_age_seconds = 42
persist = true

[quic.transport]
max_concurrent_bidi_streams = 8
max_concurrent_uni_streams = 9
idle_timeout_ms = 1234
keep_alive_interval_ms = 123
stream_receive_window_bytes = 8192
receive_window_bytes = 16384
send_window_bytes = 32768
send_fairness = false
datagram_receive_buffer_bytes = 2048
datagram_send_buffer_bytes = 4096
max_udp_payload_size = 1300
gso = false
initial_mtu = 1200
min_mtu = 1200

[quic.transport.mtu_discovery]
enabled = false
upper_bound = 1500
interval_ms = 111000
black_hole_cooldown_ms = 222000
minimum_change = 30

[quic.socket]
receive_buffer_bytes = 8192
send_buffer_bytes = 16384

[quic.upstream_pool]
enabled = false
max_connections_per_upstream = 2
max_lifetime_ms = 7777
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(config.quic.retry);
  assert_eq!(config.quic.zero_rtt, QuicZeroRttMode::SafeMethods);
  assert!(!config.quic.alt_svc.enabled);
  assert_eq!(config.quic.alt_svc.max_age_seconds, 42);
  assert!(config.quic.alt_svc.persist);
  assert_eq!(config.quic.transport.max_concurrent_bidi_streams, 8);
  assert_eq!(config.quic.transport.max_concurrent_uni_streams, 9);
  assert_eq!(config.quic.transport.idle_timeout_ms, 1234);
  assert_eq!(config.quic.transport.keep_alive_interval_ms, 123);
  assert_eq!(config.quic.transport.stream_receive_window_bytes, 8192);
  assert_eq!(config.quic.transport.receive_window_bytes, 16384);
  assert_eq!(config.quic.transport.send_window_bytes, 32768);
  assert!(!config.quic.transport.send_fairness);
  assert!(!config.quic.transport.mtu_discovery.enabled);
  assert_eq!(config.quic.transport.mtu_discovery.upper_bound, 1500);
  assert_eq!(config.quic.transport.mtu_discovery.interval_ms, 111_000);
  assert_eq!(
    config.quic.transport.mtu_discovery.black_hole_cooldown_ms,
    222_000
  );
  assert_eq!(config.quic.transport.mtu_discovery.minimum_change, 30);
  assert_eq!(config.quic.downstream.transport, config.quic.transport);
  assert_eq!(config.quic.upstream.transport, config.quic.transport);
  assert_eq!(config.quic.socket.receive_buffer_bytes, 8192);
  assert!(!config.quic.upstream_pool.enabled);
}

#[test]
fn quic_endpoint_transport_overrides_inherit_base_transport() {
  let temp_dir = common::TempDir::new("quic-endpoint-overrides");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "quic-endpoint-overrides");
  let raw = format!(
    r#"
{}

[quic.transport]
max_concurrent_bidi_streams = 300
idle_timeout_ms = 45000
keep_alive_interval_ms = 0
stream_receive_window_bytes = 2000000
send_window_bytes = 12000000

[quic.transport.mtu_discovery]
enabled = true
upper_bound = 1500
interval_ms = 700000

[quic.downstream.transport]
keep_alive_interval_ms = 5000
max_udp_payload_size = 1400
send_fairness = false

[quic.downstream.transport.mtu_discovery]
enabled = false

[quic.upstream.transport]
stream_receive_window_bytes = 3000000
receive_window_bytes = 4000000

[quic.upstream.transport.mtu_discovery]
upper_bound = 1600
black_hole_cooldown_ms = 90000
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert_eq!(config.quic.transport.max_concurrent_bidi_streams, 300);
  assert_eq!(config.quic.transport.keep_alive_interval_ms, 0);
  assert_eq!(config.quic.transport.mtu_discovery.upper_bound, 1500);
  assert_eq!(config.quic.transport.mtu_discovery.interval_ms, 700_000);

  assert_eq!(
    config.quic.downstream.transport.max_concurrent_bidi_streams,
    300
  );
  assert_eq!(
    config.quic.downstream.transport.keep_alive_interval_ms,
    5000
  );
  assert_eq!(config.quic.downstream.transport.max_udp_payload_size, 1400);
  assert!(!config.quic.downstream.transport.send_fairness);
  assert!(!config.quic.downstream.transport.mtu_discovery.enabled);
  assert_eq!(
    config.quic.downstream.transport.mtu_discovery.upper_bound,
    1500
  );

  assert_eq!(
    config.quic.upstream.transport.max_concurrent_bidi_streams,
    300
  );
  assert_eq!(config.quic.upstream.transport.keep_alive_interval_ms, 0);
  assert_eq!(
    config.quic.upstream.transport.stream_receive_window_bytes,
    3_000_000
  );
  assert_eq!(
    config.quic.upstream.transport.receive_window_bytes,
    4_000_000
  );
  assert_eq!(
    config.quic.upstream.transport.mtu_discovery.upper_bound,
    1600
  );
  assert_eq!(
    config
      .quic
      .upstream
      .transport
      .mtu_discovery
      .black_hole_cooldown_ms,
    90_000
  );
}

#[test]
fn quic_invalid_numeric_values_are_rejected() {
  let temp_dir = common::TempDir::new("quic-invalid-numeric");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "quic-invalid-numeric");
  let raw = format!(
    r#"
{}

[quic.transport]
idle_timeout_ms = 0
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("invalid QUIC numeric value should fail");

  assert!(
    error
      .to_string()
      .contains("quic.transport numeric values must be greater than 0"),
    "unexpected error: {error}"
  );
}

#[test]
fn quic_invalid_endpoint_transport_values_are_rejected() {
  let temp_dir = common::TempDir::new("quic-invalid-endpoint-transport");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "quic-invalid-endpoint-transport");
  let cases = [
    (
      "keepalive",
      r#"
[quic.downstream.transport]
keep_alive_interval_ms = 30000
"#,
      "quic.downstream.transport.keep_alive_interval_ms must be 0 or less than quic.downstream.transport.idle_timeout_ms",
    ),
    (
      "window",
      r#"
[quic.upstream.transport]
receive_window_bytes = 4611686018427387904
"#,
      "quic.upstream.transport.receive_window_bytes must be at most 4611686018427387903",
    ),
    (
      "window_dynamic_cap",
      r#"
[quic.downstream.transport]
max_concurrent_bidi_streams = 2
max_concurrent_uni_streams = 3
stream_receive_window_bytes = 1024
receive_window_bytes = 4096
"#,
      "quic.downstream.transport.receive_window_bytes must be at most 3072 based on quic.downstream.transport.stream_receive_window_bytes and the larger concurrent stream limit",
    ),
    (
      "mtu",
      r#"
[quic.downstream.transport]
initial_mtu = 1400
min_mtu = 1450
"#,
      "quic.downstream.transport.min_mtu must be less than or equal to quic.downstream.transport.initial_mtu",
    ),
    (
      "mtu_discovery",
      r#"
[quic.upstream.transport]
initial_mtu = 1500

[quic.upstream.transport.mtu_discovery]
upper_bound = 1400
"#,
      "quic.upstream.transport.mtu_discovery.upper_bound must be greater than or equal to the transport initial_mtu",
    ),
  ];

  for (name, quic_toml, expected) in cases {
    let raw = format!(
      "{}\n{}",
      common::minimal_config_toml(&cert_path, &key_path),
      quic_toml
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = match config.validate() {
      Ok(()) => panic!("{name} should fail validation"),
      Err(error) => error,
    };
    assert!(
      error.to_string().contains(expected),
      "{name} produced unexpected error: {error}"
    );
  }
}

#[test]
fn config_load_resolves_quic_host_key_under_cert_directory() {
  let temp_dir = common::TempDir::new("quic-host-key");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "quic-host-key");
  let host_key_path = cert_dir.join("quic-host-key.b64");
  std::fs::write(
    &host_key_path,
    base64::engine::general_purpose::STANDARD.encode([9u8; 64]),
  )
  .expect("failed to write host key");
  let cert_file = cert_path.file_name().unwrap().to_string_lossy();
  let key_file = key_path.file_name().unwrap().to_string_lossy();
  let config_path = config_dir.join("oxibelt.toml");
  let raw = format!(
    r#"
{}

[quic]
host_key_file = "quic-host-key.b64"
"#,
    common::minimal_config_toml_with_paths(&cert_file, &key_file)
  );
  std::fs::write(&config_path, raw).expect("failed to write config");

  let config = Config::load(&config_path).expect("config should load");
  let expected_host_key_path = host_key_path.canonicalize().unwrap();

  assert_eq!(
    config.quic.host_key_file.as_deref(),
    Some(expected_host_key_path.as_path())
  );
  assert!(
    config
      .source_paths
      .downstream_tls_reload_files()
      .contains(&host_key_path)
  );
}

#[test]
fn quic_host_key_loader_accepts_key_under_base_directory() {
  let temp_dir = common::TempDir::new("quic-host-key-load");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
  let host_key_path = cert_dir.join("quic-host-key.b64");
  let bytes = [7u8; 64];
  std::fs::write(
    &host_key_path,
    base64::engine::general_purpose::STANDARD.encode(bytes),
  )
  .expect("failed to write host key");

  assert_eq!(
    load_host_key(&cert_dir, &host_key_path).expect("host key should load"),
    bytes
  );
}

#[test]
fn quic_host_key_loader_accepts_wrapped_base64() {
  let temp_dir = common::TempDir::new("quic-host-key-wrapped");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
  let host_key_path = cert_dir.join("quic-host-key.b64");
  let bytes = [11u8; 64];
  let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
  let wrapped = format!("{}\n{}\n", &encoded[..64], &encoded[64..]);
  std::fs::write(&host_key_path, wrapped).expect("failed to write wrapped host key");

  assert_eq!(
    load_host_key(&cert_dir, &host_key_path).expect("host key should load"),
    bytes
  );
}

#[test]
fn quic_host_key_loader_rejects_wrong_length() {
  let temp_dir = common::TempDir::new("quic-host-key-short");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
  let host_key_path = cert_dir.join("quic-host-key.b64");
  std::fs::write(
    &host_key_path,
    base64::engine::general_purpose::STANDARD.encode([1u8; 63]),
  )
  .expect("failed to write host key");

  let error = load_host_key(&cert_dir, &host_key_path).expect_err("short key should fail");

  assert!(
    error.to_string().contains("exactly 64"),
    "unexpected error: {error}"
  );
}

#[test]
fn quic_host_key_loader_rejects_path_outside_base_directory() {
  let temp_dir = common::TempDir::new("quic-host-key-outside");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
  let outside_path = temp_dir.path().join("outside.b64");
  std::fs::write(
    &outside_path,
    base64::engine::general_purpose::STANDARD.encode([3u8; 64]),
  )
  .expect("failed to write outside host key");

  let error = load_host_key(&cert_dir, &outside_path).expect_err("outside key should fail");

  assert!(
    error
      .to_string()
      .contains("configured certificate directory"),
    "unexpected error: {error}"
  );
}

#[test]
fn route_protocol_operations_require_global_enablement() {
  let temp_dir = common::TempDir::new("protocol-enable");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "protocol-enable");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    "upstream = \"app\"\nconnect_tunneling = true",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("route-only CONNECT should fail");
  assert!(
    error
      .to_string()
      .contains("connect_tunneling but proxy.upgrades.connect_tunneling is false"),
    "unexpected error: {error}"
  );
}

#[test]
fn proxy_protocol_egress_rejects_http3_upstream() {
  let temp_dir = common::TempDir::new("proxy-egress-h3");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "proxy-egress-h3");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("max_http_version = \"h2\"", "max_http_version = \"h3\"")
    .replace(
      "webtransport = true",
      "webtransport = true\nproxy_protocol_egress = \"v1\"",
    );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("HTTP/3 PROXY egress should fail");
  assert!(
    error
      .to_string()
      .contains("cannot enable proxy_protocol_egress with max_http_version"),
    "unexpected error: {error}"
  );
}

#[test]
fn stream_listener_validates_target_shape() {
  let temp_dir = common::TempDir::new("stream-target");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "stream-target");
  let raw = format!(
    r#"
{}

[[stream_listeners]]
name = "db"
bind = "127.0.0.1:15432"
target = "db.internal.example:5432"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("stream listener should validate");
}

#[test]
fn invalid_stream_listener_target_is_rejected() {
  let temp_dir = common::TempDir::new("stream-target-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "stream-target-invalid");
  let raw = format!(
    r#"
{}

[[stream_listeners]]
name = "db"
bind = "127.0.0.1:15432"
target = "db.internal.example"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("stream target should fail");
  assert!(
    error
      .to_string()
      .contains("target must be in host:port form"),
    "unexpected error: {error}"
  );
}

#[test]
fn stream_pools_udp_and_sni_rules_validate() {
  let temp_dir = common::TempDir::new("stream-pool-valid");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "stream-pool-valid");
  let raw = format!(
    r#"
{}

[[stream_upstream_pools]]
name = "tcp-pool"
algorithm = "rendezvous_hash"

[[stream_upstream_pools.servers]]
id = "tcp-primary"
origin = "tcp://tcp.internal.example:9443"
weight = 2

[[stream_upstream_pools]]
name = "udp-pool"
algorithm = "rendezvous_ip_hash"

[[stream_upstream_pools.servers]]
id = "udp-primary"
origin = "udp://udp.internal.example:443"

[[stream_listeners]]
name = "tls-stream"
bind = "127.0.0.1:15443"
upstream_pool = "tcp-pool"

[[stream_listeners.sni_rules]]
name = "tenant-a"
server_names = ["tenant-a.example.com", "*.tenant-a.example.com"]
target = "tenant-a.internal.example:9443"

[[stream_listeners]]
name = "quic-stream"
network = "udp"
bind = "127.0.0.1:15444"
upstream_pool = "udp-pool"
max_udp_flows = 256
udp_datagram_rate = "100r/s"
udp_datagram_burst = 20
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("stream pools should validate");
  assert_eq!(config.stream_upstream_pools.len(), 2);
  assert_eq!(config.stream_listeners[1].network, StreamNetwork::Udp);
  assert_eq!(
    config.stream_listeners[0].sni_rules[0]
      .upstream_pool
      .as_deref(),
    None
  );
}

#[test]
fn stream_pool_rejects_invalid_origin_scheme() {
  let temp_dir = common::TempDir::new("stream-pool-invalid-scheme");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "stream-pool-invalid-scheme");
  let raw = format!(
    r#"
{}

[[stream_upstream_pools]]
name = "bad-pool"

[[stream_upstream_pools.servers]]
origin = "http://app.internal.example:80"

[[stream_listeners]]
name = "stream"
bind = "127.0.0.1:15443"
upstream_pool = "bad-pool"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("invalid stream pool origin should fail");
  assert!(
    error
      .to_string()
      .contains("origin must use tcp:// or udp://"),
    "unexpected error: {error}"
  );
}

#[test]
fn stream_listener_allows_sni_only_fail_closed_default() {
  let temp_dir = common::TempDir::new("stream-sni-only");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "stream-sni-only");
  let raw = format!(
    r#"
{}

[[stream_listeners]]
name = "sni-only"
bind = "127.0.0.1:15443"

[[stream_listeners.sni_rules]]
name = "tenant"
server_names = ["tenant.example.com"]
target = "tenant.internal.example:9443"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("SNI-only listener without a default should validate");
}

#[test]
fn stream_listener_without_default_or_sni_rule_is_rejected() {
  let temp_dir = common::TempDir::new("stream-missing-default");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "stream-missing-default");
  let raw = format!(
    r#"
{}

[[stream_listeners]]
name = "empty"
bind = "127.0.0.1:15443"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("listener without any route target should fail");
  assert!(
    error
      .to_string()
      .contains("stream listener empty must set target or upstream_pool"),
    "unexpected error: {error}"
  );
}

#[test]
fn udp_stream_listener_rejects_proxy_protocol_egress() {
  let temp_dir = common::TempDir::new("stream-udp-proxy-protocol");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "stream-udp-proxy-protocol");
  let raw = format!(
    r#"
{}

[[stream_listeners]]
name = "udp"
network = "udp"
bind = "127.0.0.1:15443"
target = "udp.internal.example:443"
proxy_protocol_egress = "v1"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("UDP stream listener PROXY egress should fail");
  assert!(
    error
      .to_string()
      .contains("cannot enable proxy_protocol_egress for UDP"),
    "unexpected error: {error}"
  );
}

#[test]
fn webrtc_turn_proxy_pool_listener_validates() {
  let temp_dir = common::TempDir::new("turn-proxy-valid");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "turn-proxy-valid");
  let raw = format!(
    r#"
{}

[[turn_upstream_pools]]
name = "turn-udp"
algorithm = "power_of_two_choices"

[[turn_upstream_pools.servers]]
id = "turn-a"
origin = "turn://turn.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tcp"
algorithm = "power_of_two_choices"

[[turn_upstream_pools.servers]]
id = "turn-tcp-a"
origin = "turn+tcp://turn.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tls"
algorithm = "power_of_two_choices"

[[turn_upstream_pools.servers]]
id = "turn-tls-a"
origin = "turns://turn.internal.example:5349"
weight = 1

[[webrtc_turn_listeners]]
name = "turn-edge"
mode = "proxy_pool"
bind_udp = "127.0.0.1:0"
bind_tcp = "127.0.0.1:0"
bind_tls = "127.0.0.1:0"
realm = "example.test"
udp_pool = "turn-udp"
tcp_pool = "turn-tcp"
tls_pool = "turn-tls"

[webrtc_turn_listeners.auth]
mode = "validate"
rest_shared_secret = "turn-secret"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("TURN proxy listener should validate");
}

#[test]
fn webrtc_turn_proxy_pool_requires_configured_pool() {
  let temp_dir = common::TempDir::new("turn-missing-pool");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "turn-missing-pool");
  let raw = format!(
    r#"
{}

[[webrtc_turn_listeners]]
name = "turn-edge"
mode = "proxy_pool"
bind_udp = "127.0.0.1:0"
realm = "example.test"
udp_pool = "missing-pool"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("missing TURN pool should fail");
  assert!(
    error.to_string().contains("unknown TURN upstream pool"),
    "unexpected error: {error}"
  );
}

#[test]
fn webrtc_turn_proxy_pool_rejects_transport_incompatible_pool() {
  let temp_dir = common::TempDir::new("turn-incompatible-pool");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-incompatible-pool");
  let raw = format!(
    r#"
{}

[[turn_upstream_pools]]
name = "plain-turn"

[[turn_upstream_pools.servers]]
origin = "turn://turn.internal.example:3478"

[[webrtc_turn_listeners]]
name = "turn-edge"
mode = "proxy_pool"
bind_tls = "127.0.0.1:0"
tls_pool = "plain-turn"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("transport-incompatible TURN pool should fail");
  assert!(
    error
      .to_string()
      .contains("requires TURN upstream pool plain-turn to use turns:// servers only"),
    "unexpected error: {error}"
  );
}

#[test]
fn webrtc_turn_edge_relay_requires_enforced_auth() {
  let temp_dir = common::TempDir::new("turn-edge-auth");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "turn-edge-auth");
  let raw = format!(
    r#"
{}

[[webrtc_turn_listeners]]
name = "edge-relay"
mode = "edge_relay"
bind_udp = "127.0.0.1:0"
realm = "example.test"
public_ip = "127.0.0.1"
relay_bind_ip = "127.0.0.1"

[webrtc_turn_listeners.relay_port_range]
start = 49152
end = 49160

[webrtc_turn_listeners.auth]
mode = "pass_through"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("open edge relay should fail");
  assert!(
    error
      .to_string()
      .contains("edge_relay requires auth.mode = \"enforce\""),
    "unexpected error: {error}"
  );
}

#[test]
fn webrtc_turn_edge_relay_stream_queue_defaults_to_32() {
  let temp_dir = common::TempDir::new("turn-edge-stream-queue-default");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-edge-stream-queue-default");
  let raw = edge_relay_turn_config_toml(&cert_path, &key_path, "");

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("TURN edge relay listener should validate");
  assert_eq!(
    config.webrtc_turn_listeners[0].stream_outbound_queue_capacity,
    32
  );
}

#[test]
fn webrtc_turn_edge_relay_stream_queue_accepts_fixed_capacity() {
  let temp_dir = common::TempDir::new("turn-edge-stream-queue-fixed");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-edge-stream-queue-fixed");
  let raw =
    edge_relay_turn_config_toml(&cert_path, &key_path, "stream_outbound_queue_capacity = 64");

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("TURN edge relay listener should validate");
  assert_eq!(
    config.webrtc_turn_listeners[0].stream_outbound_queue_capacity,
    64
  );
}

#[test]
fn webrtc_turn_edge_relay_stream_queue_auto_is_conservative() {
  let temp_dir = common::TempDir::new("turn-edge-stream-queue-auto");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-edge-stream-queue-auto");
  let raw = edge_relay_turn_config_toml(
    &cert_path,
    &key_path,
    r#"stream_outbound_queue_capacity = "auto""#,
  );
  let expected = std::thread::available_parallelism()
    .map(|parallelism| parallelism.get())
    .unwrap_or(1)
    .saturating_mul(8)
    .clamp(32, 64);

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("TURN edge relay listener should validate");
  assert_eq!(
    config.webrtc_turn_listeners[0].stream_outbound_queue_capacity,
    expected
  );
}

#[test]
fn webrtc_turn_edge_relay_stream_queue_rejects_unsafe_values() {
  let temp_dir = common::TempDir::new("turn-edge-stream-queue-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-edge-stream-queue-invalid");

  for (setting, expected) in [
    (
      "stream_outbound_queue_capacity = 0",
      "stream outbound queue capacity must be greater than 0",
    ),
    (
      "stream_outbound_queue_capacity = 257",
      "stream_outbound_queue_capacity must be at most 256",
    ),
    (
      r#"stream_outbound_queue_capacity = "large""#,
      "stream outbound queue capacity string must be \"auto\"",
    ),
  ] {
    let raw = edge_relay_turn_config_toml(&cert_path, &key_path, setting);
    let error =
      toml::from_str::<Config>(&raw).expect_err("unsafe TURN stream queue capacity should fail");
    assert!(
      error.to_string().contains(expected),
      "expected {expected:?}, got {error}"
    );
  }
}

#[test]
fn webrtc_turn_edge_relay_accepts_dual_stack_relay_families() {
  let temp_dir = common::TempDir::new("turn-edge-dual-stack");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-edge-dual-stack");
  let raw = format!(
    r#"
{}

[[webrtc_turn_listeners]]
name = "edge-relay"
mode = "edge_relay"
bind_udp = "127.0.0.1:0"
realm = "example.test"

[[webrtc_turn_listeners.relay_families]]
family = "ipv4"
public_ip = "203.0.113.10"
relay_bind_ip = "0.0.0.0"

[webrtc_turn_listeners.relay_families.relay_port_range]
start = 49152
end = 49160

[[webrtc_turn_listeners.relay_families]]
family = "ipv6"
public_ip = "2001:db8::10"
relay_bind_ip = "::"

[webrtc_turn_listeners.relay_families.relay_port_range]
start = 49152
end = 49160

[webrtc_turn_listeners.auth]
mode = "enforce"
rest_shared_secret = "turn-secret"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("dual-stack TURN edge relay should validate");
  assert_eq!(config.webrtc_turn_listeners[0].relay_families.len(), 2);
}

#[test]
fn webrtc_turn_edge_relay_rejects_mixed_legacy_and_relay_families() {
  let temp_dir = common::TempDir::new("turn-edge-mixed-family-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-edge-mixed-family-config");
  let raw = format!(
    r#"
{}

[[webrtc_turn_listeners]]
name = "edge-relay"
mode = "edge_relay"
bind_udp = "127.0.0.1:0"
realm = "example.test"
public_ip = "127.0.0.1"
relay_bind_ip = "127.0.0.1"

[webrtc_turn_listeners.relay_port_range]
start = 49152
end = 49160

[[webrtc_turn_listeners.relay_families]]
family = "ipv4"
public_ip = "203.0.113.10"
relay_bind_ip = "0.0.0.0"

[webrtc_turn_listeners.relay_families.relay_port_range]
start = 49152
end = 49160

[webrtc_turn_listeners.auth]
mode = "enforce"
rest_shared_secret = "turn-secret"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let error = toml::from_str::<Config>(&raw).expect_err("mixed relay fields should fail");
  assert!(
    error
      .to_string()
      .contains("must not mix relay_families with legacy"),
    "unexpected error: {error}"
  );
}

#[test]
fn webrtc_turn_edge_relay_rejects_relay_family_ip_mismatch() {
  let temp_dir = common::TempDir::new("turn-edge-family-mismatch");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-edge-family-mismatch");
  let raw = format!(
    r#"
{}

[[webrtc_turn_listeners]]
name = "edge-relay"
mode = "edge_relay"
bind_udp = "127.0.0.1:0"
realm = "example.test"

[[webrtc_turn_listeners.relay_families]]
family = "ipv6"
public_ip = "203.0.113.10"
relay_bind_ip = "::"

[webrtc_turn_listeners.relay_families.relay_port_range]
start = 49152
end = 49160

[webrtc_turn_listeners.auth]
mode = "enforce"
rest_shared_secret = "turn-secret"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("relay family IP mismatch should fail");
  assert!(
    error
      .to_string()
      .contains("public_ip must use the same address family"),
    "unexpected error: {error}"
  );
}

#[test]
fn webrtc_turn_proxy_pool_rejects_stream_queue_capacity() {
  let temp_dir = common::TempDir::new("turn-proxy-stream-queue");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-proxy-stream-queue");
  let raw = format!(
    r#"
{}

[[webrtc_turn_listeners]]
name = "turn-edge"
mode = "proxy_pool"
bind_udp = "127.0.0.1:0"
stream_outbound_queue_capacity = 64
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let error =
    toml::from_str::<Config>(&raw).expect_err("proxy_pool stream queue capacity should fail");
  assert!(
    error
      .to_string()
      .contains("stream_outbound_queue_capacity is only valid when mode = \"edge_relay\""),
    "unexpected error: {error}"
  );
}

#[test]
fn turn_upstream_pool_rejects_invalid_scheme() {
  let temp_dir = common::TempDir::new("turn-invalid-scheme");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "turn-invalid-scheme");
  let raw = format!(
    r#"
{}

[[turn_upstream_pools]]
name = "turn-pool"

[[turn_upstream_pools.servers]]
origin = "http://turn.internal.example:3478"

[[webrtc_turn_listeners]]
name = "turn-edge"
mode = "proxy_pool"
bind_udp = "127.0.0.1:0"
udp_pool = "turn-pool"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("invalid TURN upstream scheme should fail");
  assert!(
    error.to_string().contains("must use turn://"),
    "unexpected error: {error}"
  );
}

fn edge_relay_turn_config_toml(cert_path: &Path, key_path: &Path, listener_extra: &str) -> String {
  format!(
    r#"
{}

[[webrtc_turn_listeners]]
name = "edge-relay"
mode = "edge_relay"
bind_tcp = "127.0.0.1:0"
realm = "example.test"
public_ip = "127.0.0.1"
relay_bind_ip = "127.0.0.1"
{}

[webrtc_turn_listeners.relay_port_range]
start = 49152
end = 49160

[webrtc_turn_listeners.auth]
mode = "enforce"
rest_shared_secret = "turn-secret"
"#,
    common::minimal_config_toml(cert_path, key_path),
    listener_extra
  )
}

#[test]
fn config_load_resolves_relative_paths_against_config_directory() {
  let temp_dir = common::TempDir::new("relative-config");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");

  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "relative-config");
  let ocsp_path = cert_dir.join("response.der");
  std::fs::write(&ocsp_path, b"ocsp").expect("failed to write OCSP response");
  let ca_path = cert_dir.join("upstream-ca.pem");
  std::fs::copy(&cert_path, &ca_path).expect("failed to copy CA certificate");
  let ech_config_list_path = cert_dir.join("upstream.echconfiglist");
  std::fs::write(&ech_config_list_path, b"ech").expect("failed to write ECH config list");

  let config_path = config_dir.join("oxibelt.toml");
  let cert_file = cert_path.file_name().unwrap().to_string_lossy();
  let key_file = key_path.file_name().unwrap().to_string_lossy();
  std::fs::write(
    &config_path,
    format!(
      r#"
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "{cert_file}"
private_key = "{key_file}"

[tls.ocsp]
mode = "static_file"
response_file = "response.der"

[proxy]
trusted_ca_certs = ["upstream-ca.pem"]

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[compression]
enabled = true
gzip = true
deflate = true
zstd = true

[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[upstreams.tls.ech]
mode = "config_list"
config_list_file = "upstream.echconfiglist"

[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
"#
    ),
  )
  .expect("failed to write config");

  let config = Config::load(&config_path).expect("config should load");
  let expected_ocsp_path = ocsp_path.canonicalize().unwrap();
  let expected_ca_path = ca_path.canonicalize().unwrap();
  let expected_ech_config_list_path = ech_config_list_path.canonicalize().unwrap();

  assert_eq!(config.tls.cert_chain, cert_path);
  assert_eq!(config.tls.private_key.as_deref(), Some(key_path.as_path()));
  assert_eq!(
    config.tls.ocsp.response_file.as_deref(),
    Some(expected_ocsp_path.as_path())
  );
  assert_eq!(config.proxy.trusted_ca_certs, vec![expected_ca_path]);
  assert_eq!(
    config.upstreams[0].tls.ech.config_list_file.as_deref(),
    Some(expected_ech_config_list_path.as_path())
  );
}

#[test]
fn config_load_resolves_upstream_pool_health_check_tls_paths_against_cert_directory() {
  let temp_dir = common::TempDir::new("relative-health-check-tls");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");

  let (cert_path, key_path) =
    common::create_self_signed_cert(&cert_dir, "relative-health-check-tls");
  let ca_path = cert_dir.join("health-ca.pem");
  std::fs::copy(&cert_path, &ca_path).expect("failed to copy health CA certificate");
  let filter_path = cert_dir.join("health-crlite.filter");
  std::fs::write(&filter_path, b"filter").expect("failed to write CRLite filter");

  let config_path = config_dir.join("oxibelt.toml");
  let cert_file = cert_path.file_name().unwrap().to_string_lossy();
  let key_file = key_path.file_name().unwrap().to_string_lossy();
  std::fs::write(
    &config_path,
    format!(
      r#"
{}

[[upstream_pools]]
name = "app-pool"

[[upstream_pools.servers]]
id = "app-a"
origin = "https://app-a.example"

[upstream_pools.health_check]
enabled = true
mode = "active"
path = "/health"

[upstream_pools.health_check.tls]
trusted_ca_certs = ["health-ca.pem"]

[upstream_pools.health_check.tls.upstream_revocation.crlite]
mode = "enforce"
filter_file = "health-crlite.filter"
"#,
      common::minimal_config_toml_with_paths(&cert_file, &key_file)
    ),
  )
  .expect("failed to write config");

  let config = Config::load(&config_path).expect("config should load");
  let expected_ca_path = ca_path.canonicalize().unwrap();
  let expected_filter_path = filter_path.canonicalize().unwrap();
  let health_check = &config.upstream_pools[0].health_check;

  assert_eq!(
    health_check.tls.trusted_ca_certs,
    vec![expected_ca_path.clone()]
  );
  assert_eq!(
    health_check
      .tls
      .upstream_revocation
      .as_ref()
      .and_then(|policy| policy.crlite.filter_file.as_deref()),
    Some(expected_filter_path.as_path())
  );
  assert!(
    config
      .source_paths
      .runtime_files
      .contains(&expected_ca_path)
  );
  assert!(
    config
      .source_paths
      .runtime_files
      .contains(&expected_filter_path)
  );
  assert!(
    !config
      .source_paths
      .downstream_tls_files
      .contains(&expected_ca_path)
  );
}

#[test]
fn config_load_rejects_unknown_fields_by_default() {
  let temp_dir = common::TempDir::new("strict-unknown");
  let config_path = write_loadable_config(&temp_dir, "strict-unknown", |raw| {
    raw.replace(
      "[proxy]\ntrusted_ca_certs = []",
      "[proxy]\ntrusted_ca_certs = []\nunknown_proxy_key = true",
    )
  });

  let error = Config::load(&config_path).expect_err("unknown field should be rejected");

  assert!(
    error.to_string().contains("proxy.unknown_proxy_key"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn config_load_rejects_unknown_route_action_fields_by_default() {
  let temp_dir = common::TempDir::new("strict-route-action-unknown");
  let config_path = write_loadable_config(&temp_dir, "strict-route-action-unknown", |raw| {
    raw.replace(
      "upstream = \"app\"",
      r#"upstream = "app"

[routes.actions.rewrite]
path = "/edge{path_suffix}"
unexpected = true"#,
    )
  });

  let error = Config::load(&config_path).expect_err("unknown route action field should fail");

  assert!(
    error
      .to_string()
      .contains("routes.actions.rewrite.unexpected"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn config_load_rejects_unknown_upstream_pool_health_check_fields_by_default() {
  let temp_dir = common::TempDir::new("strict-health-check-unknown");
  let config_path = write_loadable_config(&temp_dir, "strict-health-check-unknown", |mut raw| {
    raw.push_str(
      r#"

[[upstream_pools]]
name = "app-pool"

[[upstream_pools.servers]]
id = "app-a"
origin = "http://app-a.example"

[upstream_pools.health_check]
enabled = true
mode = "active"
path = "/health"

[[upstream_pools.health_check.headers]]
name = "X-OxiBelt-Health"
value = "active"
unexpected = true
"#,
    );
    raw
  });

  let error =
    Config::load(&config_path).expect_err("unknown health-check header field should fail");

  assert!(
    error
      .to_string()
      .contains("upstream_pools.health_check.headers.unexpected"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn config_load_accepts_quic_endpoint_transport_sections() {
  let temp_dir = common::TempDir::new("strict-quic-endpoint-transport");
  let config_path = write_loadable_config(&temp_dir, "strict-quic-endpoint-transport", |raw| {
    format!(
      r#"{}

[quic.downstream.transport]
keep_alive_interval_ms = 5000
send_fairness = false

[quic.downstream.transport.mtu_discovery]
enabled = false

[quic.upstream.transport]
stream_receive_window_bytes = 3000000

[quic.upstream.transport.mtu_discovery]
upper_bound = 1500
"#,
      raw
    )
  });

  Config::load(&config_path).expect("new QUIC endpoint transport sections should load");
}

#[test]
fn config_load_rejects_unknown_quic_endpoint_transport_fields() {
  let temp_dir = common::TempDir::new("strict-quic-endpoint-unknown");
  let config_path = write_loadable_config(&temp_dir, "strict-quic-endpoint-unknown", |raw| {
    format!(
      r#"{}

[quic.downstream.transport]
recieve_window_bytes = 3000000
"#,
      raw
    )
  });

  let error = Config::load(&config_path).expect_err("misspelled QUIC field should be rejected");

  assert!(
    error
      .to_string()
      .contains("quic.downstream.transport.recieve_window_bytes"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn config_load_allows_unknown_fields_when_strict_mode_is_disabled() {
  let temp_dir = common::TempDir::new("strict-disabled");
  let config_path = write_loadable_config(&temp_dir, "strict-disabled", |raw| {
    format!(
      "[config]\nstrict_unknown_fields = false\n\n{}",
      raw.replace(
        "[proxy]\ntrusted_ca_certs = []",
        "[proxy]\ntrusted_ca_certs = []\nunknown_proxy_key = true",
      )
    )
  });

  Config::load(&config_path).expect("unknown field should be ignored when strict mode is off");
}

#[test]
fn effective_config_dump_redacts_database_connection_url() {
  let temp_dir = common::TempDir::new("effective-redacted");
  let config_path = write_loadable_config(&temp_dir, "effective-redacted", |raw| {
    raw.replace(
      "[[upstreams]]",
      r#"[database.access_log]
enabled = true
connection_url = "postgres://user:secret@postgres.example:5432/oxibelt"
table = "access_log"

[[upstreams]]"#,
    )
  });

  let redacted =
    toml::to_string_pretty(&Config::load_effective_toml_redacted(&config_path).unwrap())
      .expect("redacted TOML should serialize");

  assert!(redacted.contains("connection_url = \"<redacted>\""));
  assert!(!redacted.contains("secret@postgres.example"));
}

#[test]
fn database_mitigation_parses_dedicated_postgres_sink() {
  let temp_dir = common::TempDir::new("database-mitigation");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "mitigation");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.mitigation]
enabled = true
mode = "existing"
connection_url_env = "OXIBELT_TEST_MITIGATION_DATABASE_URL"
table = "audit.mitigation_events"
namespace = "edge"
queue_capacity = 8192
dedupe_window_ms = 30000
ttl_seconds = 600
failure_policy = "closed"

[[upstreams]]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert!(config.database.mitigation.enabled);
  assert_eq!(
    config.database.mitigation.mode,
    DatabaseMitigationMode::Existing
  );
  assert_eq!(
    config.database.mitigation.connection_url_env.as_deref(),
    Some("OXIBELT_TEST_MITIGATION_DATABASE_URL")
  );
  assert_eq!(config.database.mitigation.table, "audit.mitigation_events");
  assert_eq!(config.database.mitigation.namespace, "edge");
  assert_eq!(
    config.database.mitigation.failure_policy,
    MitigationFailurePolicy::Closed
  );
}

#[test]
fn database_mitigation_accepts_postgres_shared_state_backend() {
  let temp_dir = common::TempDir::new("database-mitigation-backend");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "mitigation-backend");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.mitigation]
enabled = true
backend = "cluster"

[shared_state]
enabled = true
namespace = "oxibelt"

[[shared_state.backends]]
name = "cluster"
kind = "postgres"
connection_url_env = "OXIBELT_SHARED_STATE_URL"

[[upstreams]]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert_eq!(
    config.database.mitigation.backend.as_deref(),
    Some("cluster")
  );
}

#[test]
fn database_mitigation_rejects_redis_shared_state_backend() {
  let temp_dir = common::TempDir::new("database-mitigation-redis");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "mitigation-redis");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.mitigation]
enabled = true
backend = "cluster"

[shared_state]
enabled = true
namespace = "oxibelt"

[[shared_state.backends]]
name = "cluster"
kind = "redis"
connection_url = "redis://127.0.0.1:6379"

[[upstreams]]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("Redis backend should be rejected");

  assert!(
    error
      .to_string()
      .contains("database.mitigation.backend cluster must use kind = \"postgres\""),
    "unexpected error: {error}"
  );
}

#[test]
fn effective_config_dump_redacts_database_mitigation_connection_url() {
  let temp_dir = common::TempDir::new("effective-mitigation-redacted");
  let config_path = write_loadable_config(&temp_dir, "effective-mitigation-redacted", |raw| {
    raw.replace(
      "[[upstreams]]",
      r#"[database.mitigation]
enabled = true
connection_url = "postgres://user:secret@postgres.example:5432/mitigation"
table = "mitigation_events"

[[upstreams]]"#,
    )
  });

  let redacted =
    toml::to_string_pretty(&Config::load_effective_toml_redacted(&config_path).unwrap())
      .expect("redacted TOML should serialize");

  assert!(redacted.contains("connection_url = \"<redacted>\""));
  assert!(!redacted.contains("secret@postgres.example"));
}

#[test]
fn database_mitigation_rejects_unsafe_table_name() {
  let temp_dir = common::TempDir::new("database-mitigation-table");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "mitigation-table");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.mitigation]
enabled = true
connection_url_env = "OXIBELT_TEST_MITIGATION_DATABASE_URL"
table = "audit.mitigation;drop"

[[upstreams]]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("unsafe mitigation table should fail");

  assert!(
    error
      .to_string()
      .contains("database.mitigation.table identifier segments must contain only ASCII letters"),
    "unexpected error: {error}"
  );
}

#[test]
fn config_load_resolves_database_access_log_tls_ca_under_cert_directory() {
  let temp_dir = common::TempDir::new("database-access-log-ca");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");

  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "database-access-log-ca");
  let ca_path = cert_dir.join("postgres-ca.pem");
  std::fs::copy(&cert_path, &ca_path).expect("failed to copy CA certificate");
  let cert_file = cert_path.file_name().unwrap().to_string_lossy();
  let key_file = key_path.file_name().unwrap().to_string_lossy();
  let config_path = config_dir.join("oxibelt.toml");
  let raw = common::minimal_config_toml_with_paths(&cert_file, &key_file).replace(
    "[[upstreams]]",
    r#"[database.access_log]
enabled = true
connection_url_env = "OXIBELT_TEST_ACCESS_LOG_DATABASE_URL"
table = "audit.access_log"

[database.access_log.tls]
mode = "verify_full"
ca_cert = "postgres-ca.pem"

[[upstreams]]"#,
  );
  std::fs::write(&config_path, raw).expect("failed to write config");

  let config = Config::load(&config_path).expect("config should load");

  config.validate().expect("config should validate");
  let expected_ca_path = ca_path.canonicalize().unwrap();
  assert_eq!(
    config.database.access_log.tls.ca_cert.as_deref(),
    Some(expected_ca_path.as_path())
  );
  assert_eq!(
    config.database.access_log.tls.mode,
    DatabaseTlsMode::VerifyFull
  );
}

#[test]
fn database_access_log_tls_mode_defaults_to_off() {
  let temp_dir = common::TempDir::new("database-access-log-tls-default");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "database-access-log-tls-default");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.access_log]
enabled = true
connection_url = "postgres://log-user:log-pass@postgres.example:5432/oxibelt"
table = "access_log"

[[upstreams]]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config.validate().expect("config should validate");
  assert_eq!(config.database.access_log.tls.mode, DatabaseTlsMode::Off);
}

#[test]
fn database_access_log_custom_ca_requires_verifying_tls_mode() {
  let temp_dir = common::TempDir::new("database-access-log-ca-mode");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "database-access-log-ca-mode");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.access_log]
enabled = true
connection_url = "postgres://log-user:log-pass@postgres.example:5432/oxibelt"
table = "access_log"

[database.access_log.tls]
mode = "off"
ca_cert = "postgres-ca.pem"

[[upstreams]]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("validation should fail");

  assert!(
    error
      .to_string()
      .contains("ca_cert is only valid when database.access_log.tls.mode is \"verify_full\""),
    "unexpected error: {error}"
  );
}

#[test]
fn database_access_log_rejects_unsupported_tls_mode() {
  let temp_dir = common::TempDir::new("database-access-log-tls-mode");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "database-access-log-tls-mode");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.access_log]
enabled = true
connection_url = "postgres://log-user:log-pass@postgres.example:5432/oxibelt"
table = "access_log"

[database.access_log.tls]
mode = "prefer"

[[upstreams]]"#,
  );

  let error = toml::from_str::<Config>(&raw).expect_err("unsupported TLS mode should fail");

  assert!(
    error.to_string().contains("unknown variant") && error.to_string().contains("verify_full"),
    "unexpected error: {error}"
  );
}

#[test]
fn database_access_log_mtls_resolves_client_certificate_and_key() {
  let temp_dir = common::TempDir::new("database-access-log-mtls");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");

  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "database-access-log");
  let ca_path = cert_dir.join("postgres-ca.pem");
  let client_cert_path = cert_dir.join("postgres-client.pem");
  let client_key_path = cert_dir.join("postgres-client.key");
  std::fs::copy(&cert_path, &ca_path).expect("failed to copy CA certificate");
  std::fs::copy(&cert_path, &client_cert_path).expect("failed to copy client certificate");
  std::fs::copy(&key_path, &client_key_path).expect("failed to copy client key");
  let cert_file = cert_path.file_name().unwrap().to_string_lossy();
  let key_file = key_path.file_name().unwrap().to_string_lossy();
  let config_path = config_dir.join("oxibelt.toml");
  let raw = common::minimal_config_toml_with_paths(&cert_file, &key_file).replace(
    "[[upstreams]]",
    r#"[database.access_log]
enabled = true
connection_url_env = "OXIBELT_TEST_ACCESS_LOG_DATABASE_URL"
table = "audit.access_log"

[database.access_log.tls]
mode = "verify_full"
ca_cert = "postgres-ca.pem"
client_cert = "postgres-client.pem"
client_key = "postgres-client.key"

[[upstreams]]"#,
  );
  std::fs::write(&config_path, raw).expect("failed to write config");

  let config = Config::load(&config_path).expect("config should load");

  config.validate().expect("config should validate");
  let expected_client_cert_path = client_cert_path.canonicalize().unwrap();
  let expected_client_key_path = client_key_path.canonicalize().unwrap();
  assert_eq!(
    config.database.access_log.tls.client_cert.as_deref(),
    Some(expected_client_cert_path.as_path())
  );
  assert_eq!(
    config.database.access_log.tls.client_key.as_deref(),
    Some(expected_client_key_path.as_path())
  );
}

#[test]
fn database_access_log_mtls_requires_client_certificate_and_key_pair() {
  let temp_dir = common::TempDir::new("database-access-log-mtls-pair");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "database-access-log-mtls-pair");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.access_log]
enabled = true
connection_url = "postgres://log-user:log-pass@postgres.example:5432/oxibelt"
table = "access_log"

[database.access_log.tls]
mode = "verify_full"
client_cert = "postgres-client.pem"

[[upstreams]]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("validation should fail");

  assert!(
    error
      .to_string()
      .contains("client_key is required when client_cert is configured"),
    "unexpected error: {error}"
  );
}

#[test]
fn database_access_log_requires_connection_source_when_enabled() {
  let temp_dir = common::TempDir::new("database-access-log-source");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "database-access-log-source");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.access_log]
enabled = true
table = "access_log"

[[upstreams]]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("validation should fail");

  assert!(
    error
      .to_string()
      .contains("requires connection_url or connection_url_env"),
    "unexpected error: {error}"
  );
}

#[test]
fn database_access_log_rejects_unsafe_table_name() {
  let temp_dir = common::TempDir::new("database-access-log-table");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "database-access-log-table");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[database.access_log]
enabled = true
connection_url = "postgres://log-user:log-pass@postgres.example:5432/oxibelt"
table = "audit.access_log;drop"

[[upstreams]]"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("validation should fail");

  assert!(
    error
      .to_string()
      .contains("identifier segments must contain only ASCII letters"),
    "unexpected error: {error}"
  );
}

#[test]
fn config_load_rejects_absolute_runtime_file_paths() {
  let temp_dir = common::TempDir::new("absolute-runtime-path");
  let config_dir = temp_dir.path().join("config");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  let (cert_path, key_path) = common::create_self_signed_cert(&config_dir, "absolute-runtime-path");

  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    common::minimal_config_toml(&cert_path, &key_path),
  )
  .expect("failed to write config");

  let error = Config::load(&config_path).expect_err("absolute runtime path should be rejected");

  assert!(
    error
      .to_string()
      .contains("tls.cert_chain must be a relative path"),
    "unexpected error: {error}"
  );
}

#[test]
fn config_load_rejects_runtime_directories() {
  let temp_dir = common::TempDir::new("runtime-directory");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  let cert_subdir = cert_dir.join("not-a-file");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  std::fs::create_dir_all(&cert_subdir).expect("failed to create cert subdirectory");

  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    common::minimal_config_toml_with_paths("not-a-file", "not-a-file"),
  )
  .expect("failed to write config");

  let error = Config::load(&config_path).expect_err("directory path should be rejected");

  assert!(
    error
      .to_string()
      .contains("tls.cert_chain must point to a regular file"),
    "unexpected error: {error}"
  );
}

#[test]
fn config_load_merges_modular_include_files() {
  let temp_dir = common::TempDir::new("modular-config");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  let modules_dir = config_dir.join("conf.d");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
  std::fs::create_dir_all(&modules_dir).expect("failed to create module directory");

  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "modular-config");
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    main_entry_config_toml(&cert_path, &key_path, r#"["conf.d/*.toml"]"#),
  )
  .expect("failed to write config");
  std::fs::write(
    modules_dir.join("10-upstreams.toml"),
    r#"
[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true
"#,
  )
  .expect("failed to write upstream module");
  std::fs::write(
    modules_dir.join("20-routes.toml"),
    r#"
[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
"#,
  )
  .expect("failed to write routes module");

  let config = Config::load(&config_path).expect("config should load modular includes");

  config.validate().expect("config should validate");
  assert_eq!(config.tls.cert_chain, cert_path);
  assert_eq!(config.tls.private_key.as_deref(), Some(key_path.as_path()));
  assert_eq!(config.upstreams.len(), 1);
  assert_eq!(config.upstreams[0].name, "app");
  assert_eq!(config.routes.len(), 1);
  assert_eq!(config.routes[0].name, "app-root");
}

#[test]
fn nested_config_includes_are_relative_to_declaring_file() {
  let temp_dir = common::TempDir::new("nested-config");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  let site_dir = config_dir.join("sites");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
  std::fs::create_dir_all(&site_dir).expect("failed to create site directory");

  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "nested-config");
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    main_entry_config_toml(&cert_path, &key_path, r#""sites/site.toml""#),
  )
  .expect("failed to write config");
  std::fs::write(
    site_dir.join("site.toml"),
    r#"
include = "upstreams.toml"

[[routes]]
name = "site-root"
hosts = ["site.example.com"]
path_prefix = "/"
upstream = "site"
"#,
  )
  .expect("failed to write site config");
  std::fs::write(
    site_dir.join("upstreams.toml"),
    r#"
[[upstreams]]
name = "site"
origin = "https://site.internal.example"
"#,
  )
  .expect("failed to write upstream config");

  let config = Config::load(&config_path).expect("config should load nested includes");

  config.validate().expect("config should validate");
  assert_eq!(config.upstreams[0].name, "site");
  assert_eq!(config.routes[0].upstream.as_deref(), Some("site"));
}

#[test]
fn config_include_cycles_are_rejected() {
  let temp_dir = common::TempDir::new("config-cycle");
  let config_dir = temp_dir.path().join("config");
  let modules_dir = config_dir.join("conf.d");
  std::fs::create_dir_all(&modules_dir).expect("failed to create module directory");

  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(&config_path, r#"include = "conf.d/loop-a.toml""#)
    .expect("failed to write config");
  std::fs::write(
    modules_dir.join("loop-a.toml"),
    r#"include = "loop-b.toml""#,
  )
  .expect("failed to write loop-a module");
  std::fs::write(
    modules_dir.join("loop-b.toml"),
    r#"include = "loop-a.toml""#,
  )
  .expect("failed to write loop-b module");

  let error = Config::load(&config_path).expect_err("cycle should be rejected");

  assert!(
    error.to_string().contains("configuration include cycle"),
    "unexpected error: {error}"
  );
}

#[test]
fn config_include_rejects_parent_directory_escape() {
  let temp_dir = common::TempDir::new("include-parent");
  let config_dir = temp_dir.path().join("config");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  std::fs::write(
    temp_dir.path().join("outside.toml"),
    "[logging]\nlevel = \"debug\"\n",
  )
  .expect("failed to write outside config");

  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(&config_path, r#"include = "../outside.toml""#).expect("failed to write config");

  let error = Config::load(&config_path).expect_err("parent traversal should be rejected");

  assert!(
    error
      .to_string()
      .contains("configuration include must not contain"),
    "unexpected error: {error}"
  );
}

#[test]
fn config_include_rejects_absolute_paths() {
  let temp_dir = common::TempDir::new("include-absolute");
  let config_dir = temp_dir.path().join("config");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  let outside_path = temp_dir.path().join("outside.toml");
  std::fs::write(&outside_path, "[logging]\nlevel = \"debug\"\n")
    .expect("failed to write outside config");

  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    format!("include = \"{}\"", outside_path.display()),
  )
  .expect("failed to write config");

  let error = Config::load(&config_path).expect_err("absolute include should be rejected");

  assert!(
    error
      .to_string()
      .contains("configuration include must be a relative path"),
    "unexpected error: {error}"
  );
}

#[test]
fn config_include_rejects_duplicate_scalar_values() {
  let temp_dir = common::TempDir::new("duplicate-include");
  let config_dir = temp_dir.path().join("config");
  let modules_dir = config_dir.join("conf.d");
  std::fs::create_dir_all(&modules_dir).expect("failed to create module directory");

  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    r#"
include = "conf.d/logging.toml"

[logging]
level = "info"
"#,
  )
  .expect("failed to write config");
  std::fs::write(
    modules_dir.join("logging.toml"),
    r#"
[logging]
level = "debug"
"#,
  )
  .expect("failed to write logging module");

  let error = Config::load(&config_path).expect_err("duplicate scalar should be rejected");

  assert!(
    error
      .to_string()
      .contains("configuration key logging.level"),
    "unexpected error: {error}"
  );
}

#[test]
fn static_ocsp_requires_a_response_file() {
  let temp_dir = common::TempDir::new("ocsp");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ocsp-test");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("mode = \"disabled\"", "mode = \"static_file\"");

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("validation should fail");
  assert!(
    error
      .to_string()
      .contains("tls.ocsp.response_file is required"),
    "unexpected error: {error}"
  );
}

#[test]
fn live_ocsp_accepts_operator_responder_url_and_defaults() {
  let temp_dir = common::TempDir::new("ocsp-live");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ocsp-live");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "mode = \"disabled\"",
    "mode = \"live_fetch\"\nresponder_url = \"https://ocsp.example.test/status\"",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config.validate().expect("live OCSP config should validate");
  assert_eq!(config.tls.ocsp.mode, OcspMode::LiveFetch);
  assert_eq!(config.tls.ocsp.request_timeout_ms, 3_000);
  assert_eq!(config.tls.ocsp.max_response_bytes, 16_384);
  assert_eq!(config.tls.ocsp.refresh_jitter_pct, 10);
  assert_eq!(config.tls.ocsp.clock_skew_seconds, 300);
}

#[test]
fn live_ocsp_rejects_static_response_file() {
  let temp_dir = common::TempDir::new("ocsp-live-response-file");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "ocsp-live-response-file");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "mode = \"disabled\"",
    "mode = \"live_fetch\"\nresponse_file = \"ocsp.der\"",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("live OCSP must reject response_file");

  assert!(
    error
      .to_string()
      .contains("tls.ocsp.response_file cannot be used"),
    "unexpected error: {error}"
  );
}

#[test]
fn live_ocsp_rejects_unsafe_responder_urls_and_zero_limits() {
  let cases = [
    (
      "responder_url = \"ftp://ocsp.example.test/status\"",
      "scheme must be http or https",
    ),
    (
      "responder_url = \"https://user:pass@ocsp.example.test/status\"",
      "must not include credentials",
    ),
    (
      "responder_url = \"https://ocsp.example.test/status#frag\"",
      "must not include a fragment",
    ),
    (
      "request_timeout_ms = 0",
      "request_timeout_ms must be greater than 0",
    ),
    (
      "max_response_bytes = 0",
      "max_response_bytes must be greater than 0",
    ),
    (
      "refresh_jitter_pct = 101",
      "refresh_jitter_pct must be between 0 and 100",
    ),
  ];

  for (setting, expected) in cases {
    let temp_dir = common::TempDir::new("ocsp-live-invalid");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "ocsp-live-invalid");
    let ocsp_settings = if setting.starts_with("responder_url") {
      format!("mode = \"live_fetch\"\n{setting}")
    } else {
      format!(
        "mode = \"live_fetch\"\nresponder_url = \"https://ocsp.example.test/status\"\n{setting}"
      )
    };
    let raw = common::minimal_config_toml(&cert_path, &key_path)
      .replace("mode = \"disabled\"", &ocsp_settings);
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("config should be rejected");

    assert!(
      error.to_string().contains(expected),
      "setting {setting} produced unexpected error: {error}"
    );
  }
}

#[test]
fn crlite_defaults_to_disabled_policy() {
  let temp_dir = common::TempDir::new("crlite-defaults");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "crlite-defaults");
  let raw = common::minimal_config_toml(&cert_path, &key_path);

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config
    .validate()
    .expect("default CRLite config should validate");
  assert_eq!(config.tls.crlite.mode, CrliteMode::Disabled);
  assert_eq!(config.tls.crlite.filter_file, None);
  assert_eq!(config.tls.crlite.filter_sha256, None);
  assert_eq!(config.tls.crlite.max_filter_bytes, 33_554_432);
  assert_eq!(config.tls.crlite.max_filter_age_seconds, 86_400);
  assert_eq!(
    config.tls.crlite.failure_policy,
    CrliteFailurePolicy::FailClosed
  );
  assert_eq!(
    config.tls.crlite.coverage_policy,
    CrliteCoveragePolicy::AllowUnknown
  );
  assert_eq!(
    config.tls.crlite.managed.storage,
    CrliteManagedStorage::Disk
  );
  assert_eq!(config.tls.crlite.managed.max_cache_bytes, 67_108_864);
  assert_eq!(config.tls.crlite.managed.refresh_interval_seconds, 21_600);
  assert_eq!(config.tls.crlite.managed.request_timeout_ms, 3_000);
}

#[test]
fn crlite_enforce_requires_a_filter_file() {
  let temp_dir = common::TempDir::new("crlite-requires-filter");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "crlite-requires-filter");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[tls.crlite]
mode = "enforce"
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("enforced CRLite without a filter should fail");

  assert!(
    error
      .to_string()
      .contains("tls.crlite.filter_file is required"),
    "unexpected error: {error}"
  );
}

#[test]
fn crlite_enforce_config_coexists_with_live_ocsp() {
  let temp_dir = common::TempDir::new("crlite-live-ocsp");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "crlite-live-ocsp");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "mode = \"disabled\"",
    "mode = \"live_fetch\"\nresponder_url = \"https://ocsp.example.test/status\"",
  ) + r#"

[tls.crlite]
mode = "enforce"
filter_file = "crlite.filter"
filter_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
max_filter_bytes = 65536
max_filter_age_seconds = 3600
failure_policy = "degraded_allow"
coverage_policy = "require_good"
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config
    .validate()
    .expect("CRLite and live OCSP config should validate together");
  assert_eq!(config.tls.ocsp.mode, OcspMode::LiveFetch);
  assert_eq!(config.tls.crlite.mode, CrliteMode::Enforce);
  assert_eq!(
    config.tls.crlite.filter_file.as_deref(),
    Some(Path::new("crlite.filter"))
  );
  assert_eq!(
    config.tls.crlite.failure_policy,
    CrliteFailurePolicy::DegradedAllow
  );
  assert_eq!(
    config.tls.crlite.coverage_policy,
    CrliteCoveragePolicy::RequireGood
  );
}

#[test]
fn crlite_managed_disk_config_validates_and_coexists_with_live_ocsp() {
  let temp_dir = common::TempDir::new("crlite-managed-disk");
  let cache_dir = temp_dir.path().join("crlite-cache");
  std::fs::create_dir(&cache_dir).expect("cache dir");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "crlite-managed-disk");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "mode = \"disabled\"",
    "mode = \"live_fetch\"\nresponder_url = \"https://ocsp.example.test/status\"",
  ) + &format!(
    r#"

[tls.crlite]
mode = "managed"
max_filter_bytes = 65536
max_filter_age_seconds = 3600
failure_policy = "degraded_allow"
coverage_policy = "require_good"

[tls.crlite.managed]
storage = "disk"
cache_dir = "{}"
max_cache_bytes = 131072
refresh_interval_seconds = 120
request_timeout_ms = 500
"#,
    cache_dir.display()
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config
    .validate()
    .expect("managed CRLite disk config should validate");
  assert_eq!(config.tls.ocsp.mode, OcspMode::LiveFetch);
  assert_eq!(config.tls.crlite.mode, CrliteMode::Managed);
  assert_eq!(
    config.tls.crlite.managed.storage,
    CrliteManagedStorage::Disk
  );
  assert_eq!(config.tls.crlite.managed.cache_dir, cache_dir);
}

#[test]
fn crlite_managed_memory_config_validates_without_persistent_storage() {
  let temp_dir = common::TempDir::new("crlite-managed-memory");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "crlite-managed-memory");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[tls.crlite]
mode = "managed"
failure_policy = "degraded_allow"

[tls.crlite.managed]
storage = "memory"
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config
    .validate()
    .expect("managed CRLite memory config should validate");
  assert_eq!(
    config.tls.crlite.managed.storage,
    CrliteManagedStorage::Memory
  );
}

#[test]
fn crlite_managed_tmpfs_config_validates_when_tmpfs_dir_is_writable() {
  let tmpfs_root = Path::new("/dev/shm");
  if !tmpfs_root.is_dir() {
    return;
  }
  let tmpfs_dir = tmpfs_root.join(format!("oxibelt-crlite-test-{}", std::process::id()));
  if std::fs::create_dir_all(&tmpfs_dir).is_err() {
    return;
  }
  struct RemoveDir(std::path::PathBuf);
  impl Drop for RemoveDir {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.0);
    }
  }
  let _cleanup = RemoveDir(tmpfs_dir.clone());
  let temp_dir = common::TempDir::new("crlite-managed-tmpfs");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "crlite-managed-tmpfs");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + &format!(
      r#"

[tls.crlite]
mode = "managed"
failure_policy = "degraded_allow"

[tls.crlite.managed]
storage = "tmpfs"
tmpfs_dir = "{}"
"#,
      tmpfs_dir.display()
    );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config
    .validate()
    .expect("managed CRLite tmpfs config should validate");
  assert_eq!(
    config.tls.crlite.managed.storage,
    CrliteManagedStorage::Tmpfs
  );
}

#[test]
fn crlite_managed_rejects_manual_filter_source() {
  let cases = [
    (
      "filter_file = \"crlite.filter\"",
      "filter_file cannot be used when tls.crlite.mode = \"managed\"",
    ),
    (
      "filter_sha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"",
      "filter_sha256 cannot be used when tls.crlite.mode = \"managed\"",
    ),
  ];

  for (setting, expected) in cases {
    let temp_dir = common::TempDir::new("crlite-managed-manual-source");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "crlite-managed-manual-source");
    let raw = common::minimal_config_toml(&cert_path, &key_path)
      + &format!(
        r#"

[tls.crlite]
mode = "managed"
{setting}

[tls.crlite.managed]
storage = "memory"
"#
      );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("managed CRLite manual source should fail");

    assert!(
      error.to_string().contains(expected),
      "setting {setting} produced unexpected error: {error}"
    );
  }
}

#[test]
fn crlite_managed_rejects_invalid_limits() {
  let cases = [
    (
      "max_cache_bytes = 0",
      "managed.max_cache_bytes must be greater than 0",
    ),
    (
      "refresh_interval_seconds = 0",
      "managed.refresh_interval_seconds must be greater than 0",
    ),
    (
      "request_timeout_ms = 0",
      "managed.request_timeout_ms must be greater than 0",
    ),
  ];

  for (setting, expected) in cases {
    let temp_dir = common::TempDir::new("crlite-managed-invalid");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "crlite-managed-invalid");
    let raw = common::minimal_config_toml(&cert_path, &key_path)
      + &format!(
        r#"

[tls.crlite]
mode = "managed"

[tls.crlite.managed]
storage = "memory"
{setting}
"#
      );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("managed CRLite invalid limit should fail");

    assert!(
      error.to_string().contains(expected),
      "setting {setting} produced unexpected error: {error}"
    );
  }
}

#[test]
fn crlite_rejects_invalid_limits_and_filter_digest() {
  let cases = [
    (
      "filter_sha256 = \"abc\"",
      "filter_sha256 must be a 64-character hex",
    ),
    (
      "filter_sha256 = \"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"",
      "filter_sha256 must be a 64-character hex",
    ),
    (
      "max_filter_bytes = 0",
      "max_filter_bytes must be greater than 0",
    ),
    (
      "max_filter_age_seconds = 0",
      "max_filter_age_seconds must be greater than 0",
    ),
  ];

  for (setting, expected) in cases {
    let temp_dir = common::TempDir::new("crlite-invalid-config");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "crlite-invalid-config");
    let raw = common::minimal_config_toml(&cert_path, &key_path)
      + &format!(
        r#"

[tls.crlite]
mode = "enforce"
filter_file = "crlite.filter"
{setting}
"#
      );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("CRLite setting should fail");

    assert!(
      error.to_string().contains(expected),
      "setting {setting} produced unexpected error: {error}"
    );
  }
}

#[test]
fn crlite_filter_file_is_tracked_for_downstream_tls_reload() {
  let temp_dir = common::TempDir::new("crlite-reload-path");
  let config_path = write_loadable_config(&temp_dir, "crlite-reload-path", |raw| {
    raw
      + r#"

[tls.crlite]
mode = "enforce"
filter_file = "crlite.filter"
failure_policy = "degraded_allow"
"#
  });
  let filter_path = temp_dir.path().join("cert").join("crlite.filter");
  std::fs::write(&filter_path, b"test filter bytes").expect("failed to write CRLite filter");

  let config = Config::load(&config_path).expect("config should load");

  assert_eq!(
    config
      .source_paths
      .downstream_tls_crlite_filter_file
      .as_deref(),
    Some(filter_path.as_path())
  );
  assert!(
    config
      .source_paths
      .downstream_tls_reload_files()
      .contains(&filter_path)
  );
  assert!(config.source_paths.runtime_files.contains(&filter_path));
}

#[test]
fn upstream_revocation_defaults_are_disabled() {
  let temp_dir = common::TempDir::new("upstream-revocation-defaults");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "upstream-revocation-defaults");
  let raw = common::minimal_config_toml(&cert_path, &key_path);

  let config: Config = toml::from_str(&raw).expect("config should parse");

  assert_eq!(
    config.proxy.upstream_revocation.ocsp.mode,
    OutboundOcspMode::Disabled
  );
  assert_eq!(
    config.proxy.upstream_revocation.crlite.mode,
    CrliteMode::Disabled
  );
  assert!(config.upstreams[0].tls.upstream_revocation.is_none());
  config.validate().expect("config should validate");
}

#[test]
fn upstream_revocation_parses_global_policy_and_upstream_override() {
  let temp_dir = common::TempDir::new("upstream-revocation-parse");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "upstream-revocation-parse");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[proxy.upstream_revocation.ocsp]
mode = "live_fetch"
failure_policy = "degraded_allow"
request_timeout_ms = 2500

[upstreams.tls.upstream_revocation.ocsp]
mode = "disabled"
failure_policy = "fail_closed"
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");

  assert_eq!(
    config.proxy.upstream_revocation.ocsp.mode,
    OutboundOcspMode::LiveFetch
  );
  assert_eq!(
    config.proxy.upstream_revocation.ocsp.failure_policy,
    CrliteFailurePolicy::DegradedAllow
  );
  assert_eq!(
    config.proxy.upstream_revocation.ocsp.request_timeout_ms,
    2500
  );
  let override_policy = config.upstreams[0]
    .tls
    .upstream_revocation
    .as_ref()
    .expect("upstream override should parse");
  assert_eq!(override_policy.ocsp.mode, OutboundOcspMode::Disabled);
  assert_eq!(
    override_policy.ocsp.failure_policy,
    CrliteFailurePolicy::FailClosed
  );
  config.validate().expect("config should validate");
}

#[test]
fn upstream_revocation_rejects_invalid_ocsp_limits() {
  let cases = [
    (
      "request_timeout_ms = 0",
      "proxy.upstream_revocation.ocsp.request_timeout_ms must be greater than 0",
    ),
    (
      "max_response_bytes = 0",
      "proxy.upstream_revocation.ocsp.max_response_bytes must be greater than 0",
    ),
    (
      "refresh_jitter_pct = 101",
      "proxy.upstream_revocation.ocsp.refresh_jitter_pct must be between 0 and 100",
    ),
  ];

  for (setting, expected) in cases {
    let temp_dir = common::TempDir::new("upstream-revocation-invalid");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "upstream-revocation-invalid");
    let raw = common::minimal_config_toml(&cert_path, &key_path)
      + &format!(
        r#"

[proxy.upstream_revocation.ocsp]
mode = "live_fetch"
{setting}
"#
      );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid upstream OCSP limit should fail");

    assert!(
      error.to_string().contains(expected),
      "setting {setting} produced unexpected error: {error}"
    );
  }
}

#[test]
fn upstream_crlite_filter_file_is_tracked_for_runtime_reload_only() {
  let temp_dir = common::TempDir::new("upstream-crlite-reload-path");
  let config_path = write_loadable_config(&temp_dir, "upstream-crlite-reload-path", |raw| {
    raw
      + r#"

[proxy.upstream_revocation.crlite]
mode = "enforce"
filter_file = "upstream-crlite.filter"
failure_policy = "degraded_allow"
"#
  });
  let filter_path = temp_dir.path().join("cert").join("upstream-crlite.filter");
  std::fs::write(&filter_path, b"test upstream filter bytes")
    .expect("failed to write upstream CRLite filter");

  let config = Config::load(&config_path).expect("config should load");

  assert!(config.source_paths.runtime_files.contains(&filter_path));
  assert!(
    !config
      .source_paths
      .downstream_tls_reload_files()
      .contains(&filter_path)
  );
}

#[test]
fn compression_header_order_remains_stable() {
  let config = CompressionConfig {
    enabled: true,
    gzip: true,
    deflate: true,
    zstd: true,
    br: true,
    ..CompressionConfig::default()
  };

  assert_eq!(
    config.accept_encoding_value().as_deref(),
    Some("br, zstd, gzip, deflate")
  );
}

#[test]
fn compression_defaults_enable_downstream_algorithms_and_policy_fields() {
  let temp_dir = common::TempDir::new("compression-defaults");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "compression-defaults");
  let raw = common::minimal_config_toml(&cert_path, &key_path);

  let config: Config = toml::from_str(&raw).expect("config should parse");

  assert!(config.compression.gzip);
  assert!(config.compression.deflate);
  assert!(config.compression.zstd);
  assert!(config.compression.br);
  assert_eq!(config.compression.min_size_bytes, 1024);
  assert_eq!(config.compression.statuses, vec![200]);
  config.validate().expect("config should validate");
}

#[test]
fn waf_http_body_compression_defaults_and_route_override_parse() {
  let temp_dir = common::TempDir::new("waf-body-compression-defaults");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "waf-body-compression-defaults");
  let raw = common::minimal_config_toml(&cert_path, &key_path);

  let config: Config = toml::from_str(&raw).expect("config should parse");

  assert_eq!(
    config.waf.http_body_compression.mode,
    WafHttpBodyCompressionMode::Off
  );
  assert_eq!(
    config.waf.http_body_compression.encodings,
    vec![
      WafHttpBodyEncoding::Gzip,
      WafHttpBodyEncoding::Deflate,
      WafHttpBodyEncoding::Br,
      WafHttpBodyEncoding::Zstd
    ]
  );
  assert_eq!(
    config.waf.http_body_compression.max_decoded_body_bytes,
    10 * 1024 * 1024
  );
  assert_eq!(config.waf.http_body_compression.max_expansion_ratio, 20);
  assert_eq!(config.waf.http_body_compression.decode_timeout_ms, 1000);
  assert_eq!(config.waf.http_body_compression.max_concurrent_bodies, 0);
  assert_eq!(
    config.routes[0].waf.http_body_compression.mode,
    RouteWafHttpBodyCompressionMode::Inherit
  );
  config.validate().expect("default config should validate");

  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    r#"upstream = "app"

[routes.waf.http_body_compression]
mode = "transform""#,
  ) + r#"

[waf.http_body_compression]
mode = "off"
"#;
  let config: Config = toml::from_str(&raw).expect("route override should parse");
  assert_eq!(
    config.routes[0].waf.http_body_compression.mode,
    RouteWafHttpBodyCompressionMode::Transform
  );
  config.validate().expect("route override should validate");
}

#[test]
fn waf_http_body_compression_rejects_invalid_limits_and_encodings() {
  let temp_dir = common::TempDir::new("waf-body-compression-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "waf-body-compression-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (toml, expected) in [
    (
      "[waf.http_body_compression]\nencodings = []\n",
      "encodings must not be empty",
    ),
    (
      "[waf.http_body_compression]\nencodings = [\"gzip\", \"gzip\"]\n",
      "duplicate encoding gzip",
    ),
    (
      "[waf.http_body_compression]\nmax_decoded_body_bytes = 0\n",
      "must be greater than 0",
    ),
    (
      "[waf.http_body_compression]\nmax_expansion_ratio = 0\n",
      "must be greater than 0",
    ),
    (
      "[waf.http_body_compression]\ndecode_timeout_ms = 0\n",
      "must be greater than 0",
    ),
  ] {
    let config: Config = toml::from_str(&(base.clone() + toml)).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid WAF body compression config should fail");
    assert!(
      error.to_string().contains(expected),
      "expected {expected:?} in {error}"
    );
  }
}

#[test]
fn waf_http_body_compression_rejects_content_encoding_route_mutation() {
  let temp_dir = common::TempDir::new("waf-body-compression-content-encoding");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "waf-body-compression-content-encoding");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    r#"upstream = "app"

[[routes.actions.response_headers.set]]
name = "Content-Encoding"
value = "gzip""#,
  ) + r#"

[waf.http_body_compression]
mode = "transform"
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("Content-Encoding mutation should fail on transform route");
  assert!(
    error.to_string().contains(
      "cannot mutate Content-Encoding when WAF HTTP body compression transform is enabled"
    ),
    "{error}"
  );
}

#[test]
fn routes_validate_named_compression_policies() {
  let temp_dir = common::TempDir::new("compression-policy");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "compression-policy");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    "upstream = \"app\"\ncompression = \"json-only\"",
  ) + r#"

[[compression.policies]]
name = "json-only"
gzip = true
deflate = false
zstd = true
br = true
mime_types = ["application/json", "application/*+json"]
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config.validate().expect("config should validate");
}

#[test]
fn compression_policy_names_reject_reserved_route_keywords() {
  for reserved_name in ["default", "off"] {
    let test_name = format!("compression-policy-reserved-{reserved_name}");
    let temp_dir = common::TempDir::new(&test_name);
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), &test_name);
    let raw = common::minimal_config_toml(&cert_path, &key_path)
      + &format!(
        r#"

[[compression.policies]]
name = "{reserved_name}"
"#
      );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("reserved compression policy name should fail");
    let expected = format!("compression policy name {reserved_name} is reserved");

    assert!(
      error.to_string().contains(&expected),
      "unexpected error for {reserved_name}: {error}"
    );
  }
}

#[test]
fn routes_accept_reserved_compression_route_keywords() {
  for route_compression in ["default", "off"] {
    let test_name = format!("compression-route-keyword-{route_compression}");
    let temp_dir = common::TempDir::new(&test_name);
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), &test_name);
    let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
      "upstream = \"app\"",
      &format!("upstream = \"app\"\ncompression = \"{route_compression}\""),
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");

    config.validate().expect("config should validate");
  }
}

#[test]
fn routes_reject_unknown_compression_policies() {
  let temp_dir = common::TempDir::new("compression-policy-unknown");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "compression-policy-unknown");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    "upstream = \"app\"\ncompression = \"missing\"",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("validation should fail");

  assert!(
    error
      .to_string()
      .contains("route app-root references unknown compression policy missing"),
    "unexpected error: {error}"
  );
}

#[test]
fn forwarded_headers_mode_defaults_to_overwrite() {
  let temp_dir = common::TempDir::new("forwarded-headers-default");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "forwarded-headers-default");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "\n[proxy.forwarded_headers]\nmode = \"overwrite\"\nclient_ip_source = \"resolved\"\n",
    "\n",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  assert_eq!(
    config.proxy.forwarded_headers.mode,
    ForwardedHeaderMode::Overwrite
  );
  assert_eq!(
    config.proxy.forwarded_headers.client_ip_source,
    ForwardedClientIpSource::Resolved
  );
  config.validate().expect("config should validate");
}

#[test]
fn forwarded_headers_mode_parses_append() {
  let temp_dir = common::TempDir::new("forwarded-headers-append");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "forwarded-headers-append");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("mode = \"overwrite\"", "mode = \"append\"");

  let config: Config = toml::from_str(&raw).expect("config should parse");

  assert_eq!(
    config.proxy.forwarded_headers.mode,
    ForwardedHeaderMode::Append
  );
  config.validate().expect("config should validate");
}

#[test]
fn forwarded_headers_client_ip_source_parses_direct_peer() {
  let temp_dir = common::TempDir::new("forwarded-headers-direct-peer");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "forwarded-headers-direct-peer");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "client_ip_source = \"resolved\"",
    "client_ip_source = \"direct_peer\"",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  assert_eq!(
    config.proxy.forwarded_headers.client_ip_source,
    ForwardedClientIpSource::DirectPeer
  );
  config.validate().expect("config should validate");
}

#[test]
fn forwarded_headers_client_ip_source_rejects_unknown_values() {
  let temp_dir = common::TempDir::new("forwarded-headers-bad-source");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "forwarded-headers-bad-source");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "client_ip_source = \"resolved\"",
    "client_ip_source = \"spoofed\"",
  );

  let error = toml::from_str::<Config>(&raw).expect_err("config should reject unknown source");

  assert!(
    error.to_string().contains("unknown variant"),
    "unexpected error: {error}"
  );
}

#[test]
fn ocsp_mode_defaults_to_disabled() {
  assert_eq!(OcspMode::default(), OcspMode::Disabled);
}

#[test]
fn upstream_ech_mode_defaults_to_disabled() {
  assert_eq!(UpstreamEchMode::default(), UpstreamEchMode::Disabled);
}

#[test]
fn hot_reload_config_defaults_to_off() {
  let temp_dir = common::TempDir::new("hot-reload-default");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "hot-reload");
  let config: Config = toml::from_str(&common::minimal_config_toml(&cert_path, &key_path))
    .expect("config should parse");

  assert_eq!(config.runtime.hot_reload.mode, HotReloadMode::Off);
  assert_eq!(config.runtime.hot_reload.poll_interval_ms, 2_000);
  config.validate().expect("config should validate");
}

#[test]
fn runtime_drain_config_defaults_are_safe_for_graceful_reload() {
  let temp_dir = common::TempDir::new("drain-default");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "drain-default");
  let config: Config = toml::from_str(&common::minimal_config_toml(&cert_path, &key_path))
    .expect("config should parse");

  assert_eq!(config.runtime.drain.graceful_timeout_ms, 30_000);
  assert_eq!(config.runtime.drain.long_connection_close_delay_ms, 300_000);
  assert_eq!(config.runtime.drain.shutdown_delay_ms, 0);
  config.validate().expect("config should validate");
}

#[test]
fn runtime_drain_config_parses_custom_values() {
  let temp_dir = common::TempDir::new("drain-custom");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "drain-custom");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "unprivileged_mode = true",
    r#"unprivileged_mode = true

[runtime.drain]
graceful_timeout_ms = 750
long_connection_close_delay_ms = 1250
shutdown_delay_ms = 250"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  assert_eq!(config.runtime.drain.graceful_timeout_ms, 750);
  assert_eq!(config.runtime.drain.long_connection_close_delay_ms, 1250);
  assert_eq!(config.runtime.drain.shutdown_delay_ms, 250);
  config.validate().expect("config should validate");
}

#[test]
fn runtime_drain_config_rejects_zero_enforcement_timeouts() {
  let temp_dir = common::TempDir::new("drain-invalid");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "drain-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);
  let cases = [
    (
      base.replace(
        "unprivileged_mode = true",
        "unprivileged_mode = true\n\n[runtime.drain]\ngraceful_timeout_ms = 0",
      ),
      "runtime.drain.graceful_timeout_ms must be greater than 0",
    ),
    (
      base.replace(
        "unprivileged_mode = true",
        "unprivileged_mode = true\n\n[runtime.drain]\nlong_connection_close_delay_ms = 0",
      ),
      "runtime.drain.long_connection_close_delay_ms must be greater than 0",
    ),
  ];

  for (raw, expected) in cases {
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config.validate().expect_err("validation should fail");
    assert!(
      error.to_string().contains(expected),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn hot_reload_config_parses_modes_and_poll_interval() {
  let temp_dir = common::TempDir::new("hot-reload-parse");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "hot-reload");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "unprivileged_mode = true",
    "unprivileged_mode = true\n\n[runtime.hot_reload]\nmode = \"full\"\npoll_interval_ms = 500",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  assert_eq!(config.runtime.hot_reload.mode, HotReloadMode::Full);
  assert_eq!(config.runtime.hot_reload.poll_interval_ms, 500);
  config.validate().expect("config should validate");
}

#[test]
fn hot_reload_config_rejects_zero_poll_interval() {
  let temp_dir = common::TempDir::new("hot-reload-zero");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "hot-reload");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "unprivileged_mode = true",
    "unprivileged_mode = true\n\n[runtime.hot_reload]\nmode = \"oxirule\"\npoll_interval_ms = 0",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("validation should fail");

  assert!(
    error
      .to_string()
      .contains("runtime.hot_reload.poll_interval_ms must be greater than 0"),
    "unexpected error: {error}"
  );
}

#[test]
fn hot_reload_cli_overrides_config_and_reports_conflicts() {
  let temp_dir = common::TempDir::new("hot-reload-override");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "hot-reload");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "unprivileged_mode = true",
    "unprivileged_mode = true\n\n[runtime.hot_reload]\nmode = \"oxirule\"\npoll_interval_ms = 2000",
  );
  let mut config: Config = toml::from_str(&raw).expect("config should parse");

  let warnings = config.apply_runtime_overrides(&RuntimeOverrides {
    hot_reload_mode: Some(HotReloadMode::Full),
    hot_reload_poll_interval_ms: Some(1_000),
  });

  assert_eq!(config.runtime.hot_reload.mode, HotReloadMode::Full);
  assert_eq!(config.runtime.hot_reload.poll_interval_ms, 1_000);
  assert_eq!(warnings.len(), 2);
  assert!(warnings[0].contains("--hot-reload-mode=full"));
  assert!(warnings[1].contains("--hot-reload-poll-interval-ms=1000"));
}

#[test]
fn oxirule_reload_equivalence_accepts_waf_only_changes() {
  let temp_dir = common::TempDir::new("hot-reload-waf-only");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "hot-reload");
  let base_raw = common::minimal_config_toml(&cert_path, &key_path);
  let changed_raw = base_raw.replace(
    "[[upstreams]]",
    r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.pattern_sets]]
name = "blocked-paths"
kind = "contains"
patterns = ["/blocked"]

[[waf.rules]]
name = "block-matrix"
phase = "request"
priority = 10
when = "Request.Http.Path.containsAny('blocked-paths')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "blocked"

[[upstreams]]"#,
  );

  let base: Config = toml::from_str(&base_raw).expect("base config should parse");
  let changed: Config = toml::from_str(&changed_raw).expect("changed config should parse");

  assert!(base.non_waf_equivalent(&changed));
  assert!(!base.waf_equivalent(&changed));
}

#[test]
fn oxirule_reload_equivalence_accepts_udf_only_changes() {
  let temp_dir = common::TempDir::new("hot-reload-waf-udf-only");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "hot-reload-udf");
  let base_raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[waf]
enabled = true
mode = "enforcing"

[[upstreams]]"#,
  );
  let changed_raw = base_raw.replace(
    "[[upstreams]]",
    r#"[[waf.functions]]
name = "is_admin_path"
params = ["path"]
expression = "path.startsWith('/admin')"

[[upstreams]]"#,
  );

  let base: Config = toml::from_str(&base_raw).expect("base config should parse");
  let changed: Config = toml::from_str(&changed_raw).expect("changed config should parse");

  base.validate().expect("base config should validate");
  changed.validate().expect("changed config should validate");
  assert!(base.non_waf_equivalent(&changed));
  assert!(!base.waf_equivalent(&changed));
}

#[test]
fn waf_rule_mode_parses_for_global_and_route_rules() {
  let temp_dir = common::TempDir::new("waf-rule-mode-parse");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "waf-rule-mode");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "[[upstreams]]",
    r#"[waf]
enabled = true
mode = "enforcing"

[[waf.rules]]
name = "shadow-global"
mode = "monitor"
phase = "request"
priority = 10
when = "true"

[[waf.rules.actions]]
type = "reject"
status = 403

[[upstreams]]"#,
  ) + r#"
[[routes.waf.rules]]
name = "enforced-route"
mode = "enforcing"
phase = "request"
priority = 10
when = "true"

[[routes.waf.rules.actions]]
type = "reject"
status = 403
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");

  assert_eq!(config.waf.rules[0].mode, Some(WafMode::Monitor));
  assert_eq!(config.routes[0].waf.rules[0].mode, Some(WafMode::Enforcing));
}

#[test]
fn oxirule_reload_equivalence_accepts_inline_route_pattern_set_and_external_changes() {
  let temp_dir = common::TempDir::new("hot-reload-waf-loaded");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  let rules_dir = temp_dir.path().join("oxirule").join("rules");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
  std::fs::create_dir_all(&rules_dir).expect("failed to create rules directory");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "hot-reload-waf");
  let cert_file = cert_path
    .file_name()
    .and_then(|value| value.to_str())
    .expect("certificate filename should be UTF-8");
  let key_file = key_path
    .file_name()
    .and_then(|value| value.to_str())
    .expect("key filename should be UTF-8");

  let base_config = format!(
    r#"
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "{cert_file}"
private_key = "{key_file}"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[compression]
enabled = true
gzip = true
deflate = true
zstd = true

[[upstreams]]
name = "app"
origin = "https://app.internal.example"
max_http_version = "h2"
connect_timeout_ms = 3000
request_timeout_ms = 30000
preserve_host = false
websocket = true
webrtc = true
webtransport = true

[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
"#
  );
  let changed_config = base_config.replace(
    "[[upstreams]]",
    r#"[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.pattern_sets]]
name = "blocked-keywords"
kind = "contains"
patterns = ["blocked"]

[[waf.rules]]
name = "inline-global"
phase = "request"
priority = 10
when = "Request.Http.Path.containsAny('blocked-keywords')"

[[waf.rules.actions]]
type = "reject"
status = 403
body = "inline blocked"

[[waf.rules]]
name = "external-global"
phase = "request"
priority = 20
path = "rules/external.oxirule.toml"

[[upstreams]]"#,
  ) + r#"

[[routes.waf.rules]]
name = "route-level"
phase = "request"
priority = 30
when = "Request.Http.Path.endsWith('/route-blocked')"

[[routes.waf.rules.actions]]
type = "reject"
status = 409
body = "route blocked"
"#;

  std::fs::write(
    rules_dir.join("external.oxirule.toml"),
    r#"
when = "Request.Headers.anyValueContains('external-block')"

[[actions]]
type = "reject"
status = 451
body = "external blocked"
"#,
  )
  .expect("failed to write external rule");
  let base_path = config_dir.join("base.toml");
  let changed_path = config_dir.join("changed.toml");
  std::fs::write(&base_path, base_config).expect("failed to write base config");
  std::fs::write(&changed_path, changed_config).expect("failed to write changed config");

  let base = Config::load(&base_path).expect("base config should load");
  base.validate().expect("base config should validate");
  let changed = Config::load(&changed_path).expect("changed config should load");
  changed.validate().expect("changed config should validate");

  assert!(base.non_waf_equivalent(&changed));
  assert!(!base.waf_equivalent(&changed));
  assert_eq!(changed.waf.pattern_sets.len(), 1);
  assert_eq!(changed.waf.rules.len(), 2);
  assert_eq!(changed.routes[0].waf.rules.len(), 1);
  assert!(
    changed
      .source_paths
      .oxirule_reload_files()
      .iter()
      .any(|path| {
        path
          .file_name()
          .and_then(|value| value.to_str())
          .is_some_and(|name| name == "external.oxirule.toml")
      })
  );
}

#[test]
fn oxirule_reload_equivalence_rejects_non_waf_changes() {
  let temp_dir = common::TempDir::new("hot-reload-non-waf");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "hot-reload");
  let base_raw = common::minimal_config_toml(&cert_path, &key_path);
  let changed_raw = base_raw.replace(
    "origin = \"https://app.internal.example\"",
    "origin = \"https://other.internal.example\"",
  );

  let base: Config = toml::from_str(&base_raw).expect("base config should parse");
  let changed: Config = toml::from_str(&changed_raw).expect("changed config should parse");

  assert!(!base.non_waf_equivalent(&changed));
}

#[test]
fn downstream_http3_listener_validates() {
  let temp_dir = common::TempDir::new("downstream-http3");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "downstream-h3");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("http3 = false", "http3 = true")
    + r#"

[quic.socket]
workers = "auto"
reuse_port = true
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("HTTP/3 listener should validate");
}

#[test]
fn upstream_http3_https_origin_validates() {
  let temp_dir = common::TempDir::new("upstream-http3-https");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "upstream-h3-https");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("max_http_version = \"h2\"", "max_http_version = \"h3\"");

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("HTTPS HTTP/3 upstream should validate");
}

#[test]
fn upstream_http3_requires_https_origin() {
  let temp_dir = common::TempDir::new("upstream-http3-http");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "upstream-h3-http");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace(
      "origin = \"https://app.internal.example\"",
      "origin = \"http://app.internal.example\"",
    )
    .replace("max_http_version = \"h2\"", "max_http_version = \"h3\"");

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("HTTP/3 upstream over HTTP should fail");
  assert!(
    error
      .to_string()
      .contains("must use https:// origin when max_http_version = \"h3\""),
    "unexpected error: {error}"
  );
}

#[test]
fn auto_upgrade_to_http3_validates_when_upstream_supports_https_h3() {
  let temp_dir = common::TempDir::new("auto-upgrade-http3");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "auto-upgrade-h3");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("max_http_version = \"h2\"", "max_http_version = \"h3\"");

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("auto-upgrade to HTTP/3 should validate");
}

#[test]
fn upstream_ech_config_list_mode_requires_a_file() {
  let temp_dir = common::TempDir::new("ech-required");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ech-required");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "webtransport = true",
    "webtransport = true\n\n[upstreams.tls.ech]\nmode = \"config_list\"",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("validation should fail");
  assert!(
    error.to_string().contains("tls.ech.config_list_file"),
    "unexpected error: {error}"
  );
}

#[test]
fn upstream_ech_config_list_file_is_only_valid_in_config_list_mode() {
  let temp_dir = common::TempDir::new("ech-unused-file");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "ech-unused-file");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
        "webtransport = true",
        "webtransport = true\n\n[upstreams.tls.ech]\nmode = \"grease\"\nconfig_list_file = \"unused.bin\"",
    );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config.validate().expect_err("validation should fail");
  assert!(
    error.to_string().contains("only valid when tls.ech.mode"),
    "unexpected error: {error}"
  );
}

#[test]
fn route_path_prefix_rejects_dot_segments() {
  let temp_dir = common::TempDir::new("route-dot-segment");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "route-dot-segment");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("path_prefix = \"/\"", "path_prefix = \"/../admin\"");

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("route path should be rejected");

  assert!(
    error.to_string().contains("must not contain dot segments"),
    "unexpected error: {error}"
  );
}

#[test]
fn route_replacement_rejects_query_fragments() {
  let temp_dir = common::TempDir::new("route-query");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "route-query");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "path_prefix = \"/\"",
    "path_prefix = \"/\"\nreplace_prefix_with = \"/edge?debug=true\"",
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("route replacement should be rejected");

  assert!(
    error
      .to_string()
      .contains("must not contain control characters"),
    "unexpected error: {error}"
  );
}

#[test]
fn route_path_values_reject_encoded_dot_and_slash_separators() {
  let temp_dir = common::TempDir::new("route-encoded-separators");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-encoded-separators");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for raw in [
    base.replace("path_prefix = \"/\"", "path_prefix = \"/%2e/admin\""),
    base.replace(
      "path_prefix = \"/\"",
      "path_prefix = \"/\"\nreplace_prefix_with = \"/edge%2fadmin\"",
    ),
    base.replace(
      "path_prefix = \"/\"",
      "path_prefix = \"/\"\nreplace_prefix_with = \"/edge%5Cadmin\"",
    ),
  ] {
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("encoded separators should be rejected");
    assert!(
      error
        .to_string()
        .contains("must not contain encoded dot or slash separators"),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn route_actions_parse_valid_rewrite_and_redirect_blocks() {
  let temp_dir = common::TempDir::new("route-actions-valid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-actions-valid");

  let rewrite_raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    r#"upstream = "app"

[routes.match.path]
regex = "^/items/([0-9]+)$"

[routes.actions.rewrite]
path = "/edge{path_suffix}"
query = "id={capture:1}&debug={query:debug}""#,
  );
  let rewrite_config: Config = toml::from_str(&rewrite_raw).expect("config should parse");
  rewrite_config
    .validate()
    .expect("rewrite action should validate");
  let rewrite = rewrite_config.routes[0]
    .actions
    .rewrite
    .as_ref()
    .expect("rewrite action should parse");
  assert_eq!(rewrite.path.as_deref(), Some("/edge{path_suffix}"));
  assert_eq!(
    rewrite.query.as_deref(),
    Some("id={capture:1}&debug={query:debug}")
  );

  let redirect_raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    r#"[routes.actions.redirect]
status = 308
location_template = "/new{path_suffix}?{query}""#,
  );
  let redirect_config: Config = toml::from_str(&redirect_raw).expect("config should parse");
  redirect_config
    .validate()
    .expect("redirect action should validate");
  let redirect = redirect_config.routes[0]
    .actions
    .redirect
    .as_ref()
    .expect("redirect action should parse");
  assert_eq!(redirect.status, Some(308));
  assert_eq!(
    redirect.location_template.as_deref(),
    Some("/new{path_suffix}?{query}")
  );
}

#[test]
fn route_actions_parse_header_cors_mirror_and_gateway_auth_blocks() {
  let temp_dir = common::TempDir::new("route-actions-parity-valid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-actions-parity-valid");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    r#"upstream_pool = "edge-pool"
external_auth = "gw-auth"

[[upstream_pools]]
name = "edge-pool"
[[upstream_pools.servers]]
id = "app"
origin = "http://127.0.0.1:18080"

[[external_auth]]
name = "gw-auth"
provider = "gateway_ext_auth_http"
endpoint = "http://127.0.0.1:19090"
forward_headers = ["authorization"]
identity_headers = ["x-auth-user"]
terminal_response_headers = ["www-authenticate"]

[[routes.actions.request_headers.set]]
name = "x-route"
value = "edge"

[[routes.actions.request_headers.add]]
name = "x-added"
value = "yes"

[routes.actions.response_headers]
remove = ["server"]

[[routes.actions.response_headers.set]]
name = "x-response"
value = "ok"

[routes.actions.cors]
allow_origins = ["https://app.example.com"]
allow_methods = ["GET", "POST"]
allow_headers = ["authorization"]
expose_headers = ["x-response"]
allow_credentials = true
max_age_seconds = 600

[[routes.actions.request_mirrors]]
upstream_pool = "edge-pool"
sample_percent = 50
max_body_bytes = 0"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("route actions should validate");
  let route = &config.routes[0];
  assert_eq!(route.external_auth.as_deref(), Some("gw-auth"));
  assert_eq!(route.actions.request_headers.set[0].name, "x-route");
  assert_eq!(route.actions.response_headers.remove, vec!["server"]);
  assert_eq!(
    route
      .actions
      .cors
      .as_ref()
      .expect("CORS action should parse")
      .allow_methods,
    vec!["GET", "POST"]
  );
  assert_eq!(route.actions.request_mirrors[0].upstream_pool, "edge-pool");
}

#[test]
fn route_actions_reject_invalid_shapes_and_combinations() {
  let temp_dir = common::TempDir::new("route-actions-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-actions-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (raw, expected) in [
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[[routes.actions.request_headers.set]]
name = "content-length"
value = "10""#,
      ),
      "cannot mutate header content-length",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[routes.actions.cors]
allow_origins = ["*"]
allow_methods = ["GET"]
allow_credentials = true"#,
      ),
      "allow_credentials cannot be true when allow_origins contains '*'",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[[routes.actions.request_mirrors]]
upstream_pool = "missing"
sample_percent = 10"#,
      ),
      "actions.request_mirrors references unknown upstream_pool missing",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[routes.actions.rewrite]"#,
      ),
      "actions.rewrite must set path or query",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"
replace_prefix_with = "/edge"

[routes.actions.rewrite]
path = "/edge{path_suffix}""#,
      ),
      "cannot set replace_prefix_with when actions.rewrite is configured",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"[routes.actions.redirect]
status = 308
location_template = "/new{path_suffix}"

[routes.actions.rewrite]
path = "/edge{path_suffix}""#,
      ),
      "cannot configure both actions.rewrite and actions.redirect",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[routes.actions.redirect]
status = 302
location_template = "/new{path_suffix}""#,
      ),
      "must set exactly one of upstream, upstream_pool, static_root, or actions.redirect",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"[routes.actions.redirect]
status = 305
location_template = "/new{path_suffix}""#,
      ),
      "must be one of 301, 302, 303, 307, or 308",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"[routes.actions.redirect]
status = 308
location_template = "/new\rbad""#,
      ),
      "must not contain unsafe characters",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"[routes.actions.redirect]
status = 308
location_template = "https://example.com/new""#,
      ),
      "must render to an origin-relative location",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[routes.actions.rewrite]
path = "//edge""#,
      ),
      "must start with one '/'",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[routes.actions.rewrite]
path = "/edge%2fadmin""#,
      ),
      "must not contain encoded dot or slash separators",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[routes.actions.rewrite]
path = "/edge{capture:1}""#,
      ),
      "cannot reference captures without match.path.regex",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[routes.match.path]
regex = "^/items/([0-9]+)$"

[routes.actions.rewrite]
path = "/edge{capture:2}""#,
      ),
      "references capture 2",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[routes.actions.rewrite]
path = "/edge{unknown}""#,
      ),
      "unsupported template token",
    ),
  ] {
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("route action config should be rejected");
    assert!(
      error.to_string().contains(expected),
      "expected {expected:?}, got {error}"
    );
  }
}

#[test]
fn route_actions_reject_reserved_request_identity_headers() {
  let temp_dir = common::TempDir::new("route-actions-reserved-headers");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-actions-reserved-headers");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (raw, expected) in [
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[[routes.actions.request_headers.set]]
name = "Host"
value = "attacker.example.com""#,
      ),
      "cannot mutate header host",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[[routes.actions.request_headers.add]]
name = "X-Forwarded-For"
value = "127.0.0.1""#,
      ),
      "cannot mutate header x-forwarded-for",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        r#"upstream = "app"

[routes.actions.request_headers]
remove = ["Forwarded"]"#,
      ),
      "cannot mutate header forwarded",
    ),
  ] {
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("reserved request header mutation should be rejected");
    assert!(
      error.to_string().contains(expected),
      "expected {expected:?}, got {error}"
    );
  }

  let response_header = base.replace(
    "upstream = \"app\"",
    r#"upstream = "app"

[[routes.actions.response_headers.set]]
name = "Host"
value = "backend.example.com""#,
  );
  let config: Config = toml::from_str(&response_header).expect("config should parse");
  config
    .validate()
    .expect("response header actions should keep existing header policy");
}

#[test]
fn route_actions_reject_external_auth_identity_header_mutations() {
  let temp_dir = common::TempDir::new("route-actions-auth-identity");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-actions-auth-identity");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for raw in [
    base.replace(
      "upstream = \"app\"",
      r#"upstream = "app"
external_auth = "edge-auth"

[[routes.actions.request_headers.set]]
name = "x-auth-user"
value = "admin@example.com"

[[external_auth]]
name = "edge-auth"
endpoint = "http://127.0.0.1:19090"
identity_headers = ["X-Auth-User"]"#,
    ),
    base.replace(
      "upstream = \"app\"",
      r#"upstream = "app"
external_auth = "edge-auth"

[[routes.actions.request_headers.add]]
name = "X-Auth-User"
value = "admin@example.com"

[[external_auth]]
name = "edge-auth"
endpoint = "http://127.0.0.1:19090"
identity_headers = ["x-auth-user"]"#,
    ),
    base.replace(
      "upstream = \"app\"",
      r#"upstream = "app"
external_auth = "edge-auth"

[routes.actions.request_headers]
remove = ["x-auth-user"]

[[external_auth]]
name = "edge-auth"
endpoint = "http://127.0.0.1:19090"
identity_headers = ["x-auth-user"]"#,
    ),
  ] {
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("external auth identity header mutation should be rejected");
    assert!(
      error
        .to_string()
        .contains("cannot mutate external_auth identity header x-auth-user"),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn route_match_config_parses_and_validates() {
  let temp_dir = common::TempDir::new("route-match-parse");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "route-match");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    r#"upstream = "app"

[routes.match]
methods = ["GET", "HEAD"]
source_cidrs = ["203.0.113.0/24"]
protocols = ["http", "http2"]
priority = 10
terminal = true

[routes.match.path]
prefix = "/"
regex = "^/assets(/[a-z0-9._-]+)?$"

[[routes.match.headers]]
name = "X-Route"
exact = "assets"

[[routes.match.queries]]
name = "v"
present = true

[routes.match.tls.client_cert]
present = true

[routes.match.tls.client_cert.fingerprint_sha256]
prefix = "abc"
"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  assert_eq!(config.routes[0].r#match.priority, 10);
  assert!(config.routes[0].r#match.terminal);
  assert_eq!(config.routes[0].r#match.headers[0].name, "X-Route");
}

#[test]
fn route_match_config_rejects_invalid_regex_and_cidr() {
  let temp_dir = common::TempDir::new("route-match-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-match-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let invalid_regex = base.replace(
    "upstream = \"app\"",
    "upstream = \"app\"\n\n[routes.match.path]\nregex = \"[\"",
  );
  let config: Config = toml::from_str(&invalid_regex).expect("config should parse");
  let error = config
    .validate()
    .expect_err("invalid route regex should be rejected");
  assert!(
    error.to_string().contains("match.path.regex"),
    "unexpected error: {error}"
  );

  let invalid_cidr = base.replace(
    "upstream = \"app\"",
    "upstream = \"app\"\n\n[routes.match]\nsource_cidrs = [\"203.0.113.0/99\"]",
  );
  let config: Config = toml::from_str(&invalid_cidr).expect("config should parse");
  let error = config
    .validate()
    .expect_err("invalid source CIDR should be rejected");
  assert!(
    error.to_string().contains("match.source_cidrs"),
    "unexpected error: {error}"
  );
}

#[test]
fn route_match_path_prefix_must_not_conflict_with_legacy_prefix() {
  let temp_dir = common::TempDir::new("route-match-prefix-conflict");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-match-prefix-conflict");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("path_prefix = \"/\"", "path_prefix = \"/api\"")
    .replace(
      "upstream = \"app\"",
      "upstream = \"app\"\n\n[routes.match.path]\nprefix = \"/v2\"",
    );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("conflicting path prefixes should be rejected");
  assert!(
    error
      .to_string()
      .contains("match.path.prefix must match path_prefix"),
    "unexpected error: {error}"
  );
}

#[test]
fn routes_reject_indistinguishable_non_terminal_matchers() {
  let temp_dir = common::TempDir::new("route-match-conflict");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-match-conflict");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[[upstreams]]
name = "other"
origin = "https://other.internal"

[[routes]]
name = "other-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "other"
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("ambiguous non-terminal routes should be rejected");
  assert!(
    error
      .to_string()
      .contains("indistinguishable non-terminal route matchers"),
    "unexpected error: {error}"
  );
}

#[test]
fn routes_allow_distinguishable_equal_specificity_ties() {
  let temp_dir = common::TempDir::new("route-match-distinguishable-tie");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-match-distinguishable-tie");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    + r#"

[[upstreams]]
name = "other"
origin = "https://other.internal"

[[routes]]
name = "header-tie"
hosts = ["example.com"]
path_prefix = "/same"
upstream = "app"

[routes.match]

[[routes.match.headers]]
name = "X-Tie"
exact = "yes"

[[routes]]
name = "query-tie"
hosts = ["example.com"]
path_prefix = "/same"
upstream = "other"

[routes.match]

[[routes.match.queries]]
name = "tie"
exact = "yes"
"#;

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("distinguishable equal-specificity routes should validate");
}

#[test]
fn routes_reject_empty_host_lists_and_duplicate_names() {
  let temp_dir = common::TempDir::new("route-identity-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-identity-invalid");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  let empty_hosts = base.replace("hosts = [\"example.com\"]", "hosts = []");
  let config: Config = toml::from_str(&empty_hosts).expect("config should parse");
  let error = config
    .validate()
    .expect_err("route with no hosts should be rejected");
  assert!(
    error
      .to_string()
      .contains("route app-root must have at least one host match"),
    "unexpected error: {error}"
  );

  let duplicate_name = base
    + r#"

[[routes]]
name = "app-root"
hosts = ["duplicate.example.com"]
path_prefix = "/duplicate"
upstream = "app"
"#;
  let config: Config = toml::from_str(&duplicate_name).expect("config should parse");
  let error = config
    .validate()
    .expect_err("duplicate route names should be rejected");
  assert!(
    error.to_string().contains("duplicate route name: app-root"),
    "unexpected error: {error}"
  );
}

#[test]
fn routes_reject_unknown_option_references() {
  let temp_dir = common::TempDir::new("route-unknown-references");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "route-unknown-references");
  let base = common::minimal_config_toml(&cert_path, &key_path);

  for (raw, expected) in [
    (
      base.replace(
        "upstream = \"app\"",
        "upstream = \"app\"\ncache = \"missing\"",
      ),
      "route app-root references unknown cache missing",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        "upstream = \"app\"\ncompression = \"missing\"",
      ),
      "route app-root references unknown compression policy missing",
    ),
    (
      base.replace(
        "upstream = \"app\"",
        "upstream = \"app\"\nexternal_auth = \"missing\"",
      ),
      "route app-root references unknown external_auth missing",
    ),
  ] {
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("unknown route reference should be rejected");
    assert!(
      error.to_string().contains(expected),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn route_can_reference_pool_without_direct_upstreams() {
  let temp_dir = common::TempDir::new("pool-only-route");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "pool-only-route");
  let raw = format!(
    r#"
[runtime]
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[[upstream_pools]]
name = "app-pool"
algorithm = "power_of_two_choices"

[[upstream_pools.servers]]
origin = "http://app-a.example/origin"

[[routes]]
name = "pool-route"
hosts = ["example.com"]
path_prefix = "/"
upstream_pool = "app-pool"
"#,
    cert = cert_path.display(),
    key = key_path.display(),
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config.validate().expect("pool-only route should validate");
  assert!(config.upstreams.is_empty());
  assert_eq!(config.routes[0].upstream_pool.as_deref(), Some("app-pool"));
}

#[test]
fn static_route_can_validate_without_upstreams() {
  let temp_dir = common::TempDir::new("static-route-config");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "static-route");
  let static_root = temp_dir.path().join("public");
  std::fs::create_dir_all(&static_root).expect("static root should be created");
  let raw = format!(
    r#"
[runtime]
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[[routes]]
name = "assets"
hosts = ["static.example.com"]
path_prefix = "/assets"
static_root = "{static_root}"
"#,
    cert = cert_path.display(),
    key = key_path.display(),
    static_root = static_root.display(),
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");

  config
    .validate()
    .expect("static-only route should validate");
  assert!(config.upstreams.is_empty());
  assert_eq!(
    config.routes[0].static_root.as_deref(),
    Some(static_root.as_path())
  );
}

#[test]
fn static_route_static_files_options_parse_and_validate() {
  let temp_dir = common::TempDir::new("static-route-options");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "static-options");
  let static_root = temp_dir.path().join("public");
  std::fs::create_dir_all(&static_root).expect("static root should be created");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    &format!(
      r#"static_root = "{static_root}"

[routes.static_files]
directory_index = ["index.html"]
try_files = ["{{path}}.html", "/index.html"]
spa_fallback = "/index.html"
precompressed = ["br", "zstd", "gzip"]
cache_control = "public, max-age=60"

[routes.static_files.cache_control_by_extension]
js = "public, max-age=31536000"

[routes.static_files.mime_overrides]
wasm = "application/wasm"

[routes.static_files.error_pages]
not_found = "/404.html"
server_error = "/50x.html""#,
      static_root = static_root.display()
    ),
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("static route options should validate");
  let static_files = &config.routes[0].static_files;
  assert_eq!(static_files.directory_index, ["index.html"]);
  assert_eq!(static_files.try_files, ["{path}.html", "/index.html"]);
  assert_eq!(static_files.spa_fallback.as_deref(), Some("/index.html"));
  assert_eq!(
    static_files.precompressed,
    [
      StaticPrecompressedEncoding::Br,
      StaticPrecompressedEncoding::Zstd,
      StaticPrecompressedEncoding::Gzip
    ]
  );
  assert_eq!(
    static_files.cache_control_by_extension["js"],
    "public, max-age=31536000"
  );
  assert_eq!(static_files.mime_overrides["wasm"], "application/wasm");
  assert_eq!(
    static_files.error_pages.not_found.as_deref(),
    Some("/404.html")
  );
  assert_eq!(
    static_files.error_pages.server_error.as_deref(),
    Some("/50x.html")
  );
}

#[test]
fn static_route_static_files_reject_invalid_options() {
  let temp_dir = common::TempDir::new("static-route-options-invalid");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "static-options-invalid");
  let static_root = temp_dir.path().join("public");
  std::fs::create_dir_all(&static_root).expect("static root should be created");
  let base = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    &format!(
      r#"static_root = "{static_root}"

[routes.static_files]
"#,
      static_root = static_root.display()
    ),
  );

  for (settings, expected) in [
    (
      r#"directory_index = ["../index.html"]"#,
      "must be a simple filename",
    ),
    (
      r#"try_files = ["{host}.html"]"#,
      "may only use the {path} placeholder",
    ),
    (r#"cache_control = "public\nbad""#, "invalid header value"),
    (
      r#"spa_fallback = "../index.html""#,
      "must be an absolute path under static_root",
    ),
    (
      r#"[routes.static_files.mime_overrides]
".wasm" = "application/wasm""#,
      "lowercase extension without a leading dot",
    ),
    (
      r#"[routes.static_files.error_pages]
server_error = "/../50x.html""#,
      "contains an invalid path segment",
    ),
    (
      r#"precompressed = ["gzip", "gzip"]"#,
      "duplicate encoding gzip",
    ),
  ] {
    let raw = format!("{base}{settings}");
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("invalid static route option should fail");
    assert!(
      error.to_string().contains(expected),
      "expected {expected:?}, got {error:#}"
    );
  }
}

#[test]
fn static_route_static_files_rejects_unknown_fields_and_non_static_routes() {
  let temp_dir = common::TempDir::new("static-route-options-strict");
  let config_path = write_loadable_config(&temp_dir, "static-route-options-strict", |raw| {
    raw.replace(
      "upstream = \"app\"",
      r#"upstream = "app"

[routes.static_files]
directory_index = ["index.html"]
unexpected = true"#,
    )
  });
  let error = Config::load(&config_path).expect_err("unknown static file field should fail");
  assert!(
    error.to_string().contains("routes.static_files.unexpected"),
    "unexpected error: {error:#}"
  );

  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "static-options-non-static");
  let raw = format!(
    r#"{}

[routes.static_files]
directory_index = ["index.html"]
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("static_files options without static_root should fail");
  assert!(
    error
      .to_string()
      .contains("cannot set static_files options without static_root"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn static_route_static_files_rejects_unknown_precompressed_encoding() {
  let temp_dir = common::TempDir::new("static-route-options-precompressed");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "static-options-precompressed");
  let static_root = temp_dir.path().join("public");
  std::fs::create_dir_all(&static_root).expect("static root should be created");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    &format!(
      r#"static_root = "{static_root}"

[routes.static_files]
precompressed = ["brotli"]"#,
      static_root = static_root.display()
    ),
  );

  let error = toml::from_str::<Config>(&raw).expect_err("unknown encoding should fail parse");
  assert!(
    error.to_string().contains("unknown variant") && error.to_string().contains("brotli"),
    "unexpected error: {error}"
  );
}

#[test]
fn static_route_rejects_multiple_targets() {
  let temp_dir = common::TempDir::new("static-route-targets");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "static-targets");
  let static_root = temp_dir.path().join("public");
  std::fs::create_dir_all(&static_root).expect("static root should be created");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    &format!(
      "upstream = \"app\"\nstatic_root = \"{}\"",
      static_root.display()
    ),
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("route with multiple targets should fail");

  assert!(
    error
      .to_string()
      .contains("exactly one of upstream, upstream_pool, static_root, or actions.redirect"),
    "unexpected error: {error}"
  );
}

#[test]
fn static_route_rejects_missing_root() {
  let temp_dir = common::TempDir::new("static-route-missing");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "static-missing");
  let missing_root = temp_dir.path().join("missing");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    &format!("static_root = \"{}\"", missing_root.display()),
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("missing static root should fail");

  assert!(
    error.to_string().contains("static_root is invalid"),
    "unexpected error: {error}"
  );
}

#[test]
fn static_routes_reject_upstream_only_options() {
  let temp_dir = common::TempDir::new("static-route-upstream-options");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "static-upstream-options");
  let static_root = temp_dir.path().join("public");
  std::fs::create_dir_all(&static_root).expect("static root should be created");
  let base = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    &format!("static_root = \"{}\"", static_root.display()),
  );

  for (raw, expected) in [
    (
      base.replace(
        &format!("static_root = \"{}\"", static_root.display()),
        &format!(
          "static_root = \"{}\"\nreplace_prefix_with = \"/edge\"",
          static_root.display()
        ),
      ),
      "cannot set replace_prefix_with when static_root is configured",
    ),
    (
      base.replace(
        &format!("static_root = \"{}\"", static_root.display()),
        &format!(
          "static_root = \"{}\"\ncache = \"default\"",
          static_root.display()
        ),
      ),
      "cannot set cache when static_root is configured",
    ),
    (
      base.replace(
        &format!("static_root = \"{}\"", static_root.display()),
        &format!(
          "static_root = \"{}\"\nupstream_http_version = \"h2\"",
          static_root.display()
        ),
      ),
      "cannot set upstream_http_version when static_root is configured",
    ),
    (
      base.replace(
        &format!("static_root = \"{}\"", static_root.display()),
        &format!(
          "static_root = \"{}\"\ngeneric_http_upgrade = true",
          static_root.display()
        ),
      ),
      "cannot enable upstream-only route features when static_root is configured",
    ),
    (
      base.replace(
        &format!("static_root = \"{}\"", static_root.display()),
        &format!(
          "static_root = \"{}\"\nconnect_tunneling = true",
          static_root.display()
        ),
      ),
      "cannot enable upstream-only route features when static_root is configured",
    ),
    (
      base.replace(
        &format!("static_root = \"{}\"", static_root.display()),
        &format!(
          "static_root = \"{}\"\ngrpc_web = true",
          static_root.display()
        ),
      ),
      "cannot enable upstream-only route features when static_root is configured",
    ),
  ] {
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
      .validate()
      .expect_err("static route upstream-only option should fail");
    assert!(
      error.to_string().contains(expected),
      "unexpected error: {error}"
    );
  }
}

#[test]
fn upstream_pool_routes_reject_http3_route_override() {
  let temp_dir = common::TempDir::new("pool-route-h3-override");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "pool-route-h3-override");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    r#"upstream_pool = "app-pool"
upstream_http_version = "h3"

[[upstream_pools]]
name = "app-pool"

[[upstream_pools.servers]]
origin = "https://app.internal.example"
"#,
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  let error = config
    .validate()
    .expect_err("HTTP/3 route override should fail for pool routes");
  assert!(
    error
      .to_string()
      .contains("cannot set upstream_http_version = \"h3\" for upstream_pool routes"),
    "unexpected error: {error}"
  );
}

fn write_loadable_config(
  temp_dir: &common::TempDir,
  common_name: &str,
  edit: impl FnOnce(String) -> String,
) -> std::path::PathBuf {
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
  std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, common_name);
  let cert_file = cert_path.file_name().unwrap().to_string_lossy();
  let key_file = key_path.file_name().unwrap().to_string_lossy();
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    edit(common::minimal_config_toml_with_paths(
      &cert_file, &key_file,
    )),
  )
  .expect("failed to write config");
  config_path
}

fn main_entry_config_toml(cert_path: &Path, key_path: &Path, include: &str) -> String {
  let cert_file = cert_path.file_name().unwrap().to_string_lossy();
  let key_file = key_path.file_name().unwrap().to_string_lossy();
  format!(
    r#"
include = {include}

[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = "auto"

[runtime.accept]
workers = "auto"
reuse_port = true
backlog = 8192
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[proxy.auto_upgrade]
enabled = true
max_http_version = "h2"

[compression]
enabled = true
gzip = true
deflate = true
zstd = true
"#,
    cert = cert_file,
    key = key_file,
  )
}
