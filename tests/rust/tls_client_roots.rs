#[path = "common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use h3_quinn::quinn::Endpoint;
use oxibelt::config::{
    ListenerConfig, OcspConfig, ProxyProtocolConfig, QuicConfig, TlsClientAuthConfig,
    TlsClientAuthMode, TlsConfig, TlsVersion, UpstreamEchConfig, UpstreamEchMode,
};
use oxibelt::tls;

#[test]
fn upstream_tls_client_accepts_extra_root_certificates() {
    let temp_dir = common::TempDir::new("roots");
    let (cert_path, _key_path) = common::create_self_signed_cert(temp_dir.path(), "unit-root");

    tls::build_upstream_client_config(&[cert_path], &UpstreamEchConfig::default())
        .expect("root store should build");
}

#[test]
fn upstream_tls_client_rejects_invalid_root_pem() {
    let temp_dir = common::TempDir::new("invalid-root");
    let invalid_cert = temp_dir.path().join("invalid.pem");
    std::fs::write(&invalid_cert, "not a certificate").expect("failed to write invalid cert");

    let error = tls::build_upstream_client_config(&[invalid_cert], &UpstreamEchConfig::default())
        .expect_err("must reject invalid PEM");
    assert!(
        error
            .to_string()
            .contains("no parsable upstream root certificates found"),
        "unexpected error: {error}"
    );
}

#[test]
fn upstream_tls_client_builds_with_ech_grease() {
    tls::build_upstream_client_config(
        &[],
        &UpstreamEchConfig {
            mode: UpstreamEchMode::Grease,
            config_list_file: None,
        },
    )
    .expect("ECH GREASE upstream TLS client should build");
}

#[test]
fn upstream_tls_client_rejects_invalid_ech_config_list() {
    let temp_dir = common::TempDir::new("invalid-ech");
    let config_list = temp_dir.path().join("echconfiglist.bin");
    std::fs::write(&config_list, "not an ECHConfigList")
        .expect("failed to write invalid ECH config list");

    let error = tls::build_upstream_client_config(
        &[],
        &UpstreamEchConfig {
            mode: UpstreamEchMode::ConfigList,
            config_list_file: Some(config_list),
        },
    )
    .expect_err("invalid ECHConfigList should be rejected");
    assert!(
        error.to_string().contains("failed to parse upstream ECH"),
        "unexpected error: {error}"
    );
}

#[test]
fn server_config_sets_alpn_from_listener_flags() {
    let temp_dir = common::TempDir::new("server-config");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "downstream");
    let tls_config = downstream_tls_config(cert_path, key_path, TlsClientAuthConfig::default());
    let listeners = ListenerConfig {
        https_bind: "127.0.0.1:8443".parse().unwrap(),
        http_bind: None,
        http_mode: Default::default(),
        http1: true,
        http2: false,
        http3: false,
        proxy_protocol: ProxyProtocolConfig::default(),
    };

    let server_config =
        tls::build_server_config(&tls_config, &listeners).expect("server config should build");
    assert_eq!(server_config.alpn_protocols, vec![b"http/1.1".to_vec()]);
}

#[test]
fn quic_server_config_rejects_invalid_client_auth_roots() {
    let temp_dir = common::TempDir::new("quic-invalid-client-auth");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "downstream");
    let invalid_ca = temp_dir.path().join("invalid-client-ca.pem");
    std::fs::write(&invalid_ca, "not a certificate").expect("failed to write invalid CA file");
    let tls_config = downstream_tls_config(
        cert_path,
        key_path,
        TlsClientAuthConfig {
            mode: TlsClientAuthMode::Require,
            ca_certs: vec![invalid_ca],
            verify_depth: 4,
        },
    );

    let error = tls::build_quic_server_config(&tls_config, &QuicConfig::default(), None)
        .expect_err("QUIC client auth must validate configured CA roots");
    assert!(
        error
            .to_string()
            .contains("no parsable downstream client auth root certificates"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn quic_required_client_auth_rejects_client_without_certificate() {
    let temp_dir = common::TempDir::new("quic-client-auth-required");
    let (ca_cert_path, ca_key_path) = common::create_self_signed_cert(temp_dir.path(), "test-ca");
    let (cert_path, key_path) = common::create_ca_signed_server_cert(
        temp_dir.path(),
        "downstream",
        &ca_cert_path,
        &ca_key_path,
    );

    let tls_without_client_auth = downstream_tls_config(
        cert_path.clone(),
        key_path.clone(),
        TlsClientAuthConfig::default(),
    );
    quic_connect_without_client_certificate(&tls_without_client_auth, &ca_cert_path)
        .await
        .expect("control QUIC connection without client auth should succeed");

    let tls_with_required_client_auth = downstream_tls_config(
        cert_path.clone(),
        key_path,
        TlsClientAuthConfig {
            mode: TlsClientAuthMode::Require,
            ca_certs: vec![ca_cert_path.clone()],
            verify_depth: 4,
        },
    );
    let error =
        quic_connect_without_client_certificate(&tls_with_required_client_auth, &ca_cert_path)
            .await
            .expect_err("client without a certificate must not complete QUIC TLS");
    assert!(
        error.contains("client") || error.contains("server"),
        "unexpected QUIC client-auth error: {error}"
    );
}

fn downstream_tls_config(
    cert_path: PathBuf,
    key_path: PathBuf,
    client_auth: TlsClientAuthConfig,
) -> TlsConfig {
    TlsConfig {
        cert_chain: cert_path,
        private_key: key_path,
        min_version: TlsVersion::Tls13,
        max_version: TlsVersion::Tls13,
        session_tickets: true,
        session_ticket_rotation_seconds: 86_400,
        client_auth,
        ocsp: OcspConfig::default(),
    }
}

async fn quic_connect_without_client_certificate(
    tls_config: &TlsConfig,
    trusted_server_root: &Path,
) -> Result<(), String> {
    let server_config = tls::build_quic_server_config(tls_config, &QuicConfig::default(), None)
        .map_err(|error| format!("failed to build QUIC server config: {error}"))?;
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
        .map_err(|error| format!("failed to start QUIC server endpoint: {error}"))?;
    let server_addr = server_endpoint
        .local_addr()
        .map_err(|error| format!("failed to read QUIC server address: {error}"))?;

    let client_config = tls::build_upstream_quic_client_config(
        &[trusted_server_root.to_path_buf()],
        &UpstreamEchConfig::default(),
        &QuicConfig::default(),
    )
    .map_err(|error| format!("failed to build QUIC client config: {error}"))?;
    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap())
        .map_err(|error| format!("failed to start QUIC client endpoint: {error}"))?;
    client_endpoint.set_default_client_config(client_config);

    let client_connect = async {
        let connecting = client_endpoint
            .connect(server_addr, "downstream")
            .map_err(|error| format!("failed to start QUIC connection: {error}"))?;
        tokio::time::timeout(Duration::from_secs(3), connecting)
            .await
            .map_err(|_| "client timed out waiting for QUIC handshake".to_string())?
            .map(|_| ())
            .map_err(|error| format!("client rejected QUIC handshake: {error}"))
    };

    let server_accept = async {
        let incoming = tokio::time::timeout(Duration::from_secs(3), server_endpoint.accept())
            .await
            .map_err(|_| "server timed out waiting for QUIC handshake".to_string())?
            .ok_or_else(|| "server endpoint closed before QUIC handshake".to_string())?;
        incoming
            .await
            .map(|_| ())
            .map_err(|error| format!("server rejected QUIC handshake: {error}"))
    };

    let (client_result, server_result) = tokio::join!(client_connect, server_accept);
    client_endpoint.close(0u32.into(), b"test complete");
    client_result?;
    server_result?;
    Ok(())
}
