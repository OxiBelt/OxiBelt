#[path = "common/mod.rs"]
mod common;

use std::path::Path;

use base64::Engine;
use oxibelt::config::{
    AdminRole, AdminTransportMode, BufferingMode, CacheStore, CompressionConfig, Config,
    ConnectionLimitIdentityMode, DatabaseTlsMode, DnsDiscoveryRecordType, DynamicPolicyFailPolicy,
    EarlyHintsMode, ErrorResponseMode, ExpectContinueMode, ForwardedHeaderMode, GrpcRetryMode,
    HotReloadMode, OcspMode, PriorityMode, ProxyProtocolEgressMode, ProxyProtocolVersion,
    QuicZeroRttMode, RateLimitKey, RetryCondition, RuntimeOverrides, SharedStateBackendKind,
    StaticFilesSendfileMode, TlsServerResumptionMode, TlsVersion, TrailerMode,
    UpstreamDiscoveryProvider, UpstreamEchMode, UpstreamTls12ResumptionMode,
    UpstreamTlsResumptionMode, resolve_auto_worker_count,
};
use oxibelt::quic::load_host_key;
use oxibelt::waf::WafMode;

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
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "protocol-defaults");
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

    let expected = available_parallelism();
    assert_eq!(config.runtime.worker_threads, expected);
    assert_eq!(config.runtime.accept.workers, expected);
    assert!(config.runtime.accept.reuse_port);
    assert_eq!(config.runtime.accept.backlog, 8192);
    assert_eq!(config.runtime.accept.accept_error_backoff_ms, 10);
    assert_eq!(config.quic.socket.workers, expected);
    assert!(!config.quic.socket.reuse_port);
    assert_eq!(config.runtime.worker_multipliers.runtime, 1.0);
    assert_eq!(config.runtime.worker_multipliers.accept, 1.0);
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

    let raw = format!(
        r#"
{base}

[proxy.retry]
enabled = true
tries = 4
timeout_ms = 750
on = ["connect_error", "read_timeout", "502", "503", "504"]
retry_non_idempotent = true
"#
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    assert!(config.proxy.retry.enabled);
    assert_eq!(config.proxy.retry.tries, 4);
    assert_eq!(config.proxy.retry.timeout_ms, 750);
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

    let raw = format!(
        r#"
{base}

[proxy.static_files]
sendfile = "auto"
inline_max_bytes = 0
"#
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    assert_eq!(
        config.proxy.static_files.sendfile,
        StaticFilesSendfileMode::Auto
    );
    assert_eq!(config.proxy.static_files.inline_max_bytes, 0);
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
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "security-headers");
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
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "timeout-overrides");
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
fn rate_limit_config_parses_route_and_token_keys() {
    let temp_dir = common::TempDir::new("rate-limit-config");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "rate-limit-config");
    let raw = format!(
        r#"
{}

[[rate_limits]]
name = "route-token"
key = "access-token-route"
routes = ["app-root"]
token_header = "X-Api-Token"
rate = "10r/m"
burst = 10
max_buckets = 256
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
    assert_eq!(config.rate_limits[0].max_buckets, 256);
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
fn effective_config_dump_resolves_auto_worker_counts() {
    let temp_dir = common::TempDir::new("effective-workers");
    let config_path = write_loadable_config(&temp_dir, "effective-workers", |raw| raw);

    let rendered =
        toml::to_string_pretty(&Config::load_effective_toml_redacted(&config_path).unwrap())
            .expect("effective TOML should serialize");
    let expected = available_parallelism();

    assert!(
        rendered.contains(&format!("worker_threads = {expected}")),
        "effective config should contain resolved runtime worker count: {rendered}"
    );
    assert!(
        rendered.contains(&format!("workers = {expected}")),
        "effective config should contain resolved accept worker count: {rendered}"
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
fn admin_rbac_tokens_parse_and_validate_roles() {
    unsafe {
        std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
        std::env::set_var("OXIBELT_VIEWER_TOKEN_TEST", "viewer-secret");
        std::env::set_var("OXIBELT_UPSTREAM_TOKEN_TEST", "upstream-secret");
        std::env::set_var("OXIBELT_SECURITY_TOKEN_TEST", "security-secret");
    }
    let temp_dir = common::TempDir::new("admin-rbac");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "admin-rbac");
    let raw = format!(
        r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[[admin.rbac.tokens]]
name = "viewer"
bearer_token_env = "OXIBELT_VIEWER_TOKEN_TEST"
roles = ["viewer"]

[[admin.rbac.tokens]]
	name = "upstream-ops"
	bearer_token_env = "OXIBELT_UPSTREAM_TOKEN_TEST"
	roles = ["upstream_operator", "cache_operator"]

[[admin.rbac.tokens]]
name = "security-ops"
bearer_token_env = "OXIBELT_SECURITY_TOKEN_TEST"
roles = ["security_operator"]
	"#,
        common::minimal_config_toml(&cert_path, &key_path)
    );

    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    assert_eq!(config.admin.rbac.tokens[0].roles, vec![AdminRole::Viewer]);
    assert_eq!(
        config.admin.rbac.tokens[1].roles,
        vec![AdminRole::UpstreamOperator, AdminRole::CacheOperator]
    );
    assert_eq!(
        config.admin.rbac.tokens[2].roles,
        vec![AdminRole::SecurityOperator]
    );
}

#[test]
fn admin_rbac_rejects_duplicate_names_empty_roles_and_unknown_roles() {
    unsafe {
        std::env::set_var("OXIBELT_ADMIN_TOKEN_TEST", "secret");
        std::env::set_var("OXIBELT_VIEWER_TOKEN_TEST", "viewer-secret");
    }
    let temp_dir = common::TempDir::new("admin-rbac-invalid");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "admin-rbac-invalid");
    let duplicate_raw = format!(
        r#"
{}

[admin]
enabled = true
bearer_token_env = "OXIBELT_ADMIN_TOKEN_TEST"

[[admin.rbac.tokens]]
name = "viewer"
bearer_token_env = "OXIBELT_VIEWER_TOKEN_TEST"
roles = ["viewer"]

[[admin.rbac.tokens]]
name = "viewer"
bearer_token_env = "OXIBELT_VIEWER_TOKEN_TEST"
roles = ["viewer"]
"#,
        common::minimal_config_toml(&cert_path, &key_path)
    );
    let config: Config = toml::from_str(&duplicate_raw).expect("config should parse");
    let error = config
        .validate()
        .expect_err("duplicate RBAC token names should be rejected");
    assert!(
        error
            .to_string()
            .contains("duplicate admin.rbac.tokens name"),
        "unexpected error: {error}"
    );

    let empty_roles_raw = duplicate_raw.replace("roles = [\"viewer\"]", "roles = []");
    let config: Config = toml::from_str(&empty_roles_raw).expect("config should parse");
    let error = config
        .validate()
        .expect_err("empty RBAC token roles should be rejected");
    assert!(
        error.to_string().contains("roles must not be empty"),
        "unexpected error: {error}"
    );

    let unknown_role_raw = duplicate_raw.replace("roles = [\"viewer\"]", "roles = [\"root\"]");
    toml::from_str::<Config>(&unknown_role_raw).expect_err("unknown RBAC role should not parse");
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
algorithm = "round_robin"

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
fn upstream_pool_discovery_rejects_reserved_providers_and_bad_values() {
    let temp_dir = common::TempDir::new("pool-discovery-invalid");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "pool-discovery-invalid");
    let raw = format!(
        r#"
{}

[[upstream_pools]]
name = "dynamic-pool"
algorithm = "round_robin"

[[upstream_pools.discovery]]
provider = "consul"
name = "app"
"#,
        common::minimal_config_toml(&cert_path, &key_path)
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
        .validate()
        .expect_err("reserved discovery provider should be rejected");
    assert!(
        error.to_string().contains("reserved and not implemented"),
        "unexpected error: {error}"
    );

    let raw = raw
        .replace("provider = \"consul\"", "provider = \"dns\"")
        .replace("name = \"app\"", "name = \"app\"\nrefresh_interval_ms = 0");
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let error = config
        .validate()
        .expect_err("zero discovery interval should be rejected");
    assert!(
        error.to_string().contains("must be greater than 0"),
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
    assert_eq!(
        config.quic.transport.datagram_receive_buffer_bytes,
        1024 * 1024
    );
    assert_eq!(config.quic.transport.max_udp_payload_size, 1472);
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
datagram_receive_buffer_bytes = 2048
datagram_send_buffer_bytes = 4096
max_udp_payload_size = 1300
gso = false

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
    assert_eq!(config.quic.socket.receive_buffer_bytes, 8192);
    assert!(!config.quic.upstream_pool.enabled);
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
fn webrtc_turn_proxy_pool_listener_validates() {
    let temp_dir = common::TempDir::new("turn-proxy-valid");
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "turn-proxy-valid");
    let raw = format!(
        r#"
{}

[[turn_upstream_pools]]
name = "turn-udp"
algorithm = "round_robin"

[[turn_upstream_pools.servers]]
id = "turn-a"
origin = "turn://turn.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tcp"
algorithm = "round_robin"

[[turn_upstream_pools.servers]]
id = "turn-tcp-a"
origin = "turn+tcp://turn.internal.example:3478"
weight = 1

[[turn_upstream_pools]]
name = "turn-tls"
algorithm = "round_robin"

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
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "turn-missing-pool");
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
fn config_load_resolves_database_access_log_tls_ca_under_cert_directory() {
    let temp_dir = common::TempDir::new("database-access-log-ca");
    let config_dir = temp_dir.path().join("config");
    let cert_dir = temp_dir.path().join("cert");
    std::fs::create_dir_all(&config_dir).expect("failed to create config directory");
    std::fs::create_dir_all(&cert_dir).expect("failed to create cert directory");

    let (cert_path, key_path) =
        common::create_self_signed_cert(&cert_dir, "database-access-log-ca");
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
    let (cert_path, key_path) =
        common::create_self_signed_cert(&config_dir, "absolute-runtime-path");

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
    let raw = common::minimal_config_toml(&cert_path, &key_path)
        .replace("\n[proxy.forwarded_headers]\nmode = \"overwrite\"\n", "\n");

    let config: Config = toml::from_str(&raw).expect("config should parse");

    assert_eq!(
        config.proxy.forwarded_headers.mode,
        ForwardedHeaderMode::Overwrite
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
when = "PatternSets.contains('blocked-paths', Request.Http.Path)"

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
when = "PatternSets.contains('blocked-keywords', Request.Http.Path)"

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
                path.file_name()
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
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "upstream-h3-https");
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
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "upstream-h3-http");
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
    let (cert_path, key_path) =
        common::create_self_signed_cert(temp_dir.path(), "route-dot-segment");
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
algorithm = "round_robin"

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
            .contains("exactly one of upstream, upstream_pool, or static_root"),
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
