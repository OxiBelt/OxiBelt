#[path = "common/mod.rs"]
mod common;

use std::path::Path;

use oxibelt::config::{CompressionConfig, Config, DatabaseTlsMode, OcspMode, UpstreamEchMode};

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
    assert_eq!(config.tls.private_key, key_path);
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
    assert_eq!(config.routes[0].upstream, "site");
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
fn downstream_http3_listener_validates() {
    let temp_dir = common::TempDir::new("downstream-http3");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "downstream-h3");
    let raw =
        common::minimal_config_toml(&cert_path, &key_path).replace("http3 = false", "http3 = true");

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
