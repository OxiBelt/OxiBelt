#[path = "common/mod.rs"]
mod common;

use std::path::Path;

use oxibelt::config::{
    CompressionConfig, Config, DatabaseTlsMode, ForwardedHeaderMode, HotReloadMode, OcspMode,
    RuntimeOverrides, UpstreamEchMode,
};

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

#[test]
fn route_can_reference_pool_without_direct_upstreams() {
    let temp_dir = common::TempDir::new("pool-only-route");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "pool-only-route");
    let raw = format!(
        r#"
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
