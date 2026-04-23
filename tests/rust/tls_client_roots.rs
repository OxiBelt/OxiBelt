#[path = "common/mod.rs"]
mod common;

use oxibelt::config::{ListenerConfig, OcspConfig, TlsConfig};
use oxibelt::tls;

#[test]
fn upstream_tls_client_accepts_extra_root_certificates() {
    let temp_dir = common::TempDir::new("roots");
    let (cert_path, _key_path) = common::create_self_signed_cert(temp_dir.path(), "unit-root");

    tls::build_upstream_client_config(&[cert_path]).expect("root store should build");
}

#[test]
fn upstream_tls_client_rejects_invalid_root_pem() {
    let temp_dir = common::TempDir::new("invalid-root");
    let invalid_cert = temp_dir.path().join("invalid.pem");
    common::write_file(&invalid_cert, "not a certificate");

    let error =
        tls::build_upstream_client_config(&[invalid_cert]).expect_err("must reject invalid PEM");
    assert!(
        error
            .to_string()
            .contains("no parsable upstream root certificates found"),
        "unexpected error: {error}"
    );
}

#[test]
fn server_config_sets_alpn_from_listener_flags() {
    let temp_dir = common::TempDir::new("server-config");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "downstream");
    let tls_config = TlsConfig {
        cert_chain: cert_path,
        private_key: key_path,
        ocsp: OcspConfig::default(),
    };
    let listeners = ListenerConfig {
        https_bind: "127.0.0.1:8443".parse().unwrap(),
        http1: true,
        http2: false,
        http3: false,
    };

    let server_config =
        tls::build_server_config(&tls_config, &listeners).expect("server config should build");
    assert_eq!(server_config.alpn_protocols, vec![b"http/1.1".to_vec()]);
}
