#[path = "common/mod.rs"]
mod common;

use oxibelt::config::{CompressionConfig, Config, OcspMode};

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
fn config_load_resolves_relative_paths_against_config_directory() {
    let temp_dir = common::TempDir::new("relative-config");
    let config_dir = temp_dir.path().join("config");
    let tls_dir = config_dir.join("tls");
    std::fs::create_dir_all(&tls_dir).expect("failed to create TLS directory");

    let (cert_path, key_path) = common::create_self_signed_cert(&tls_dir, "relative-config");
    let ocsp_path = tls_dir.join("response.der");
    std::fs::write(&ocsp_path, b"ocsp").expect("failed to write OCSP response");
    let ca_path = tls_dir.join("upstream-ca.pem");
    std::fs::copy(&cert_path, &ca_path).expect("failed to copy CA certificate");

    let config_path = config_dir.join("oxibelt.toml");
    common::write_file(
        &config_path,
        r#"
[logging]
level = "info"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "tls/relative-config.pem"
private_key = "tls/relative-config.key"

[tls.ocsp]
mode = "static_file"
response_file = "tls/response.der"

[proxy]
trusted_ca_certs = ["tls/upstream-ca.pem"]

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
"#,
    );

    let config = Config::load(&config_path).expect("config should load");

    assert_eq!(config.tls.cert_chain, cert_path);
    assert_eq!(config.tls.private_key, key_path);
    assert_eq!(
        config.tls.ocsp.response_file.as_deref(),
        Some(ocsp_path.as_path())
    );
    assert_eq!(config.proxy.trusted_ca_certs, vec![ca_path]);
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
    };

    assert_eq!(
        config.accept_encoding_value().as_deref(),
        Some("zstd, gzip, deflate")
    );
}

#[test]
fn ocsp_mode_defaults_to_disabled() {
    assert_eq!(OcspMode::default(), OcspMode::Disabled);
}
