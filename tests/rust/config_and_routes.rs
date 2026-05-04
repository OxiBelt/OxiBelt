#[path = "common/mod.rs"]
mod common;

use std::path::Path;

use oxibelt::config::{CompressionConfig, Config, OcspMode, UpstreamEchMode};

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
    let ech_config_list_path = tls_dir.join("upstream.echconfiglist");
    std::fs::write(&ech_config_list_path, b"ech").expect("failed to write ECH config list");

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

[upstreams.tls.ech]
mode = "config_list"
config_list_file = "tls/upstream.echconfiglist"

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
    assert_eq!(
        config.upstreams[0].tls.ech.config_list_file.as_deref(),
        Some(ech_config_list_path.as_path())
    );
}

#[test]
fn config_load_merges_modular_include_files() {
    let temp_dir = common::TempDir::new("modular-config");
    let config_dir = temp_dir.path().join("config");
    let tls_dir = config_dir.join("tls");
    let modules_dir = config_dir.join("conf.d");
    std::fs::create_dir_all(&tls_dir).expect("failed to create TLS directory");
    std::fs::create_dir_all(&modules_dir).expect("failed to create module directory");

    let (cert_path, key_path) = common::create_self_signed_cert(&tls_dir, "modular-config");
    let config_path = config_dir.join("oxibelt.toml");
    common::write_file(
        &config_path,
        &main_entry_config_toml(&cert_path, &key_path, r#"["conf.d/*.toml"]"#),
    );
    common::write_file(
        &modules_dir.join("10-upstreams.toml"),
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
    );
    common::write_file(
        &modules_dir.join("20-routes.toml"),
        r#"
[[routes]]
name = "app-root"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
"#,
    );

    let config = Config::load(&config_path).expect("config should load modular includes");

    config.validate().expect("config should validate");
    assert_eq!(config.tls.cert_chain, cert_path);
    assert_eq!(config.tls.private_key, key_path);
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.upstreams[0].name, "app");
    assert_eq!(config.routes.len(), 1);
    assert_eq!(config.routes[0].name, "app-root");
}

#[test]
fn nested_config_includes_are_relative_to_declaring_file() {
    let temp_dir = common::TempDir::new("nested-config");
    let config_dir = temp_dir.path().join("config");
    let tls_dir = config_dir.join("tls");
    let site_dir = config_dir.join("sites");
    std::fs::create_dir_all(&tls_dir).expect("failed to create TLS directory");
    std::fs::create_dir_all(&site_dir).expect("failed to create site directory");

    let (cert_path, key_path) = common::create_self_signed_cert(&tls_dir, "nested-config");
    let config_path = config_dir.join("oxibelt.toml");
    common::write_file(
        &config_path,
        &main_entry_config_toml(&cert_path, &key_path, r#""sites/site.toml""#),
    );
    common::write_file(
        &site_dir.join("site.toml"),
        r#"
include = "upstreams.toml"

[[routes]]
name = "site-root"
hosts = ["site.example.com"]
path_prefix = "/"
upstream = "site"
"#,
    );
    common::write_file(
        &site_dir.join("upstreams.toml"),
        r#"
[[upstreams]]
name = "site"
origin = "https://site.internal.example"
"#,
    );

    let config = Config::load(&config_path).expect("config should load nested includes");

    config.validate().expect("config should validate");
    assert_eq!(config.upstreams[0].name, "site");
    assert_eq!(config.routes[0].upstream, "site");
}

#[test]
fn config_include_cycles_are_rejected() {
    let temp_dir = common::TempDir::new("config-cycle");
    let config_dir = temp_dir.path().join("config");
    let modules_dir = config_dir.join("conf.d");
    std::fs::create_dir_all(&modules_dir).expect("failed to create module directory");

    let config_path = config_dir.join("oxibelt.toml");
    common::write_file(&config_path, r#"include = "conf.d/loop.toml""#);
    common::write_file(
        &modules_dir.join("loop.toml"),
        r#"include = "../oxibelt.toml""#,
    );

    let error = Config::load(&config_path).expect_err("cycle should be rejected");

    assert!(
        error.to_string().contains("configuration include cycle"),
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
    common::write_file(
        &config_path,
        r#"
include = "conf.d/logging.toml"

[logging]
level = "info"
"#,
    );
    common::write_file(
        &modules_dir.join("logging.toml"),
        r#"
[logging]
level = "debug"
"#,
    );

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

#[test]
fn upstream_ech_mode_defaults_to_disabled() {
    assert_eq!(UpstreamEchMode::default(), UpstreamEchMode::Disabled);
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

fn main_entry_config_toml(cert_path: &Path, key_path: &Path, include: &str) -> String {
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
        cert = cert_path.display(),
        key = key_path.display(),
    )
}
