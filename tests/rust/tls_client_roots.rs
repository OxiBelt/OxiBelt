#[path = "common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use h3_quinn::quinn::Endpoint;
use oxibelt::config::{
    ListenerConfig, OcspConfig, ProxyProtocolConfig, QuicConfig, TlsClientAuthConfig,
    TlsClientAuthMode, TlsConfig, TlsKeyExchangeGroup, TlsRemoteSignerConfig,
    TlsServerResumptionMode, TlsVersion, TurnListenerTlsConfig, UpstreamEchConfig, UpstreamEchMode,
};
use oxibelt::remote_signer::{
    self, DEFAULT_REMOTE_SIGNER_IO_TIMEOUT_MS, DEFAULT_REMOTE_SIGNER_MAX_CONNECTIONS,
    SignerServerConfig,
};
use oxibelt::tls;
use rustls::NamedGroup;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

static NEXT_REMOTE_SIGNER_ID: AtomicU64 = AtomicU64::new(0);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_config_uses_configured_key_exchange_groups() {
    let temp_dir = common::TempDir::new("server-config-key-exchange-groups");
    let (ca_cert_path, ca_key_path) =
        common::create_self_signed_cert(temp_dir.path(), "key-exchange-ca");
    let (cert_path, key_path) = common::create_ca_signed_server_cert(
        temp_dir.path(),
        "classical-downstream",
        &ca_cert_path,
        &ca_key_path,
    );
    let mut tls_config = downstream_tls_config(cert_path, key_path, TlsClientAuthConfig::default());
    tls_config.key_exchange_groups = vec![
        TlsKeyExchangeGroup::X25519,
        TlsKeyExchangeGroup::Secp256r1,
        TlsKeyExchangeGroup::Secp384r1,
    ];
    let listeners = ListenerConfig {
        https_bind: "127.0.0.1:8443".parse().unwrap(),
        http_bind: None,
        http_mode: Default::default(),
        http1: true,
        http2: true,
        http3: false,
        proxy_protocol: ProxyProtocolConfig::default(),
    };
    let server_config =
        tls::build_server_config(&tls_config, &listeners).expect("server config should build");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("server listener should bind");
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("server should accept");
        let tls_stream = TlsAcceptor::from(server_config)
            .accept(stream)
            .await
            .expect("server TLS handshake should complete");
        tls_stream
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .expect("TLS handshake should negotiate a key exchange group")
            .name()
    });

    let client_config =
        tls::build_upstream_client_config(&[ca_cert_path], &UpstreamEchConfig::default())
            .expect("client config should build");
    let stream = TcpStream::connect(addr)
        .await
        .expect("client should connect to server");
    TlsConnector::from(Arc::new(client_config))
        .connect("classical-downstream".try_into().unwrap(), stream)
        .await
        .expect("client TLS handshake should complete");

    let group = server.await.expect("server task should finish");
    assert_eq!(group, NamedGroup::X25519);
}

#[test]
fn server_config_applies_resumption_modes() {
    let temp_dir = common::TempDir::new("server-resumption-modes");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "downstream");
    let listeners = ListenerConfig {
        https_bind: "127.0.0.1:8443".parse().unwrap(),
        http_bind: None,
        http_mode: Default::default(),
        http1: true,
        http2: true,
        http3: false,
        proxy_protocol: ProxyProtocolConfig::default(),
    };

    let mut stateful = downstream_tls_config(
        cert_path.clone(),
        key_path.clone(),
        TlsClientAuthConfig::default(),
    );
    stateful.resumption.mode = TlsServerResumptionMode::Stateful;
    stateful.resumption.session_cache_size = 16;
    stateful.resumption.tls13_ticket_count = 3;
    let stateful_config =
        tls::build_server_config(&stateful, &listeners).expect("stateful config should build");
    assert_eq!(stateful_config.send_tls13_tickets, 3);
    assert!(stateful_config.session_storage.can_cache());
    assert!(!stateful_config.ticketer.enabled());

    let mut stateless = downstream_tls_config(
        cert_path.clone(),
        key_path.clone(),
        TlsClientAuthConfig::default(),
    );
    stateless.resumption.mode = TlsServerResumptionMode::Stateless;
    stateless.resumption.tls13_ticket_count = 4;
    let stateless_config =
        tls::build_server_config(&stateless, &listeners).expect("stateless config should build");
    assert_eq!(stateless_config.send_tls13_tickets, 4);
    assert!(!stateless_config.session_storage.can_cache());
    assert!(stateless_config.ticketer.enabled());

    let mut off = downstream_tls_config(cert_path, key_path, TlsClientAuthConfig::default());
    off.resumption.mode = TlsServerResumptionMode::Off;
    let off_config = tls::build_server_config(&off, &listeners).expect("off config should build");
    assert_eq!(off_config.send_tls13_tickets, 0);
    assert!(!off_config.session_storage.can_cache());
    assert!(!off_config.ticketer.enabled());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_server_config_accepts_handshake_with_remote_signer() {
    let temp_dir = common::TempDir::new("remote-signer-tcp");
    let (ca_cert_path, ca_key_path) = common::create_self_signed_cert(temp_dir.path(), "remote-ca");
    let (cert_path, key_path) = common::create_ca_signed_server_cert(
        temp_dir.path(),
        "remote-tcp",
        &ca_cert_path,
        &ca_key_path,
    );
    let token_env = remote_signer_token_env("TCP");
    let signer = start_remote_signer(&temp_dir, "edge-default", &key_path, &token_env, false).await;
    let tls_config = remote_tls_config(
        cert_path.clone(),
        signer.socket_path.clone(),
        "edge-default",
        &token_env,
        false,
    );
    let listeners = ListenerConfig {
        https_bind: "127.0.0.1:8443".parse().unwrap(),
        http_bind: None,
        http_mode: Default::default(),
        http1: true,
        http2: true,
        http3: false,
        proxy_protocol: ProxyProtocolConfig::default(),
    };
    let server_config =
        tls::build_server_config(&tls_config, &listeners).expect("server config should build");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("server listener should bind");
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("server should accept");
        TlsAcceptor::from(server_config)
            .accept(stream)
            .await
            .expect("server TLS handshake should complete");
    });

    let client_config =
        tls::build_upstream_client_config(&[ca_cert_path], &UpstreamEchConfig::default())
            .expect("client config should build");
    let stream = TcpStream::connect(addr)
        .await
        .expect("client should connect to server");
    TlsConnector::from(Arc::new(client_config))
        .connect("remote-tcp".try_into().unwrap(), stream)
        .await
        .expect("client TLS handshake should complete");
    server.await.expect("server task should finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_server_config_accepts_handshake_with_remote_signer() {
    let temp_dir = common::TempDir::new("remote-signer-quic");
    let (ca_cert_path, ca_key_path) = common::create_self_signed_cert(temp_dir.path(), "quic-ca");
    let (cert_path, key_path) = common::create_ca_signed_server_cert(
        temp_dir.path(),
        "downstream",
        &ca_cert_path,
        &ca_key_path,
    );
    let token_env = remote_signer_token_env("QUIC");
    let signer = start_remote_signer(&temp_dir, "edge-default", &key_path, &token_env, false).await;
    let tls_config = remote_tls_config(
        cert_path.clone(),
        signer.socket_path.clone(),
        "edge-default",
        &token_env,
        false,
    );

    quic_connect_without_client_certificate(&tls_config, &ca_cert_path)
        .await
        .expect("QUIC handshake should complete with remote signer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_signer_rejects_spki_mismatch() {
    let temp_dir = common::TempDir::new("remote-signer-spki");
    let (cert_path, _key_path) = common::create_self_signed_cert(temp_dir.path(), "remote-spki");
    let (_other_cert, other_key) =
        common::create_self_signed_cert(temp_dir.path(), "remote-spki-other");
    let token_env = remote_signer_token_env("SPKI");
    let signer =
        start_remote_signer(&temp_dir, "edge-default", &other_key, &token_env, false).await;
    let tls_config = remote_tls_config(
        cert_path,
        signer.socket_path.clone(),
        "edge-default",
        &token_env,
        false,
    );
    let listeners = ListenerConfig {
        https_bind: "127.0.0.1:8443".parse().unwrap(),
        http_bind: None,
        http_mode: Default::default(),
        http1: true,
        http2: true,
        http3: false,
        proxy_protocol: ProxyProtocolConfig::default(),
    };
    let error = tls::build_server_config(&tls_config, &listeners)
        .expect_err("SPKI mismatch must reject remote signer");
    let error = format!("{error:#}");
    assert!(
        error.contains("does not match"),
        "unexpected error: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_signer_protocol_rejects_bad_token_unknown_key_and_invalid_contexts() {
    let temp_dir = common::TempDir::new("remote-signer-protocol");
    let (_cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "remote-proto");
    let token_env = remote_signer_token_env("PROTO");
    let signer = start_remote_signer(&temp_dir, "edge-default", &key_path, &token_env, false).await;
    let good_token = remote_signer_token();
    let bad_token = base64::engine::general_purpose::STANDARD.encode([99u8; 32]);

    let response = signer
        .request(json!({
            "type": "describe_key",
            "token": bad_token,
            "key_id": "edge-default"
        }))
        .await;
    assert_eq!(response["type"], "error");
    assert_eq!(response["code"], "unauthorized");

    let response = signer
        .request(json!({
            "type": "describe_key",
            "token": good_token,
            "key_id": "missing"
        }))
        .await;
    assert_eq!(response["type"], "error");
    assert_eq!(response["code"], "unknown_key");

    let response = signer
        .request(json!({
            "type": "sign",
            "token": good_token,
            "key_id": "edge-default",
            "scheme": u16::from(rustls::SignatureScheme::RSA_PSS_SHA256),
            "context": "tls13_server_certificate_verify",
            "message": base64::engine::general_purpose::STANDARD.encode(b"not tls13")
        }))
        .await;
    assert_eq!(response["type"], "error");
    assert_eq!(response["code"], "invalid_tls13_message");

    let response = signer
        .request(json!({
            "type": "sign",
            "token": good_token,
            "key_id": "edge-default",
            "scheme": u16::from(rustls::SignatureScheme::RSA_PSS_SHA256),
            "context": "tls12_unstructured",
            "message": base64::engine::general_purpose::STANDARD.encode(b"tls12 input")
        }))
        .await;
    assert_eq!(response["type"], "error");
    assert_eq!(response["code"], "tls12_disabled");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_signer_closes_idle_connections_and_recovers() {
    let temp_dir = common::TempDir::new("remote-signer-idle-timeout");
    let (_cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "remote-idle");
    let token_env = remote_signer_token_env("IDLE");
    let signer = start_remote_signer_with_limits(
        &temp_dir,
        "edge-default",
        &key_path,
        &token_env,
        false,
        2,
        Duration::from_millis(100),
    )
    .await;

    let mut idle_connections = Vec::new();
    for _ in 0..2 {
        idle_connections.push(
            UnixStream::connect(&signer.socket_path)
                .await
                .expect("idle attacker connection should connect"),
        );
    }

    tokio::time::sleep(Duration::from_millis(250)).await;
    for stream in &mut idle_connections {
        let mut byte = [0u8; 1];
        let closed =
            match tokio::time::timeout(Duration::from_millis(100), stream.read(&mut byte)).await {
                Ok(Ok(0)) | Ok(Err(_)) => true,
                Ok(Ok(_)) | Err(_) => false,
            };
        assert!(
            closed,
            "idle connection should be closed by signer read timeout"
        );
    }

    let response = signer
        .request(json!({
            "type": "describe_key",
            "token": remote_signer_token(),
            "key_id": "edge-default"
        }))
        .await;
    assert_eq!(response["type"], "describe_key");
    assert!(
        !response["schemes"].as_array().unwrap().is_empty(),
        "legitimate request should still be served after idle peers time out"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_signer_protocol_allows_tls12_when_sidecar_opts_in() {
    let temp_dir = common::TempDir::new("remote-signer-tls12");
    let (_cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "remote-tls12");
    let token_env = remote_signer_token_env("TLS12");
    let signer = start_remote_signer(&temp_dir, "edge-default", &key_path, &token_env, true).await;
    let response = signer
        .request(json!({
            "type": "sign",
            "token": remote_signer_token(),
            "key_id": "edge-default",
            "scheme": u16::from(rustls::SignatureScheme::RSA_PSS_SHA256),
            "context": "tls12_unstructured",
            "message": base64::engine::general_purpose::STANDARD.encode(b"tls12 input")
        }))
        .await;
    assert_eq!(response["type"], "sign");
    assert!(response["signature"].as_str().unwrap().len() > 64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turn_server_config_builds_with_remote_signer_override() {
    let temp_dir = common::TempDir::new("remote-signer-turn");
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "remote-turn");
    let token_env = remote_signer_token_env("TURN");
    let signer = start_remote_signer(&temp_dir, "turn-key", &key_path, &token_env, false).await;
    let default_tls = remote_tls_config(
        cert_path.clone(),
        signer.socket_path.clone(),
        "turn-key",
        &token_env,
        false,
    );
    let listener_tls = TurnListenerTlsConfig {
        cert_chain: Some(cert_path),
        private_key: None,
        remote_signer_key_id: Some("turn-key".to_string()),
        resumption: None,
    };
    tls::build_turn_server_config(&listener_tls, &default_tls)
        .expect("TURN TLS config should build with remote signer override");
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
        private_key: Some(key_path),
        remote_signer: TlsRemoteSignerConfig::default(),
        min_version: TlsVersion::Tls13,
        max_version: TlsVersion::Tls13,
        key_exchange_groups: default_tls_key_exchange_groups(),
        session_tickets: true,
        session_ticket_rotation_seconds: 86_400,
        resumption: Default::default(),
        client_auth,
        ocsp: OcspConfig::default(),
    }
}

fn remote_tls_config(
    cert_path: PathBuf,
    socket_path: PathBuf,
    key_id: &str,
    token_env: &str,
    allow_tls12_unstructured_signing: bool,
) -> TlsConfig {
    TlsConfig {
        cert_chain: cert_path,
        private_key: None,
        remote_signer: TlsRemoteSignerConfig {
            enabled: true,
            socket_path,
            key_id: key_id.to_string(),
            token_env: token_env.to_string(),
            connect_timeout_ms: 5000,
            sign_timeout_ms: 5000,
            allow_tls12_unstructured_signing,
        },
        min_version: TlsVersion::Tls13,
        max_version: TlsVersion::Tls13,
        key_exchange_groups: default_tls_key_exchange_groups(),
        session_tickets: true,
        session_ticket_rotation_seconds: 86_400,
        resumption: Default::default(),
        client_auth: TlsClientAuthConfig::default(),
        ocsp: OcspConfig::default(),
    }
}

fn default_tls_key_exchange_groups() -> Vec<TlsKeyExchangeGroup> {
    vec![
        TlsKeyExchangeGroup::X25519MlKem768,
        TlsKeyExchangeGroup::X25519,
        TlsKeyExchangeGroup::Secp256r1,
        TlsKeyExchangeGroup::Secp384r1,
    ]
}

struct RemoteSignerTestServer {
    socket_path: PathBuf,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RemoteSignerTestServer {
    async fn request(&self, value: serde_json::Value) -> serde_json::Value {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .expect("test client should connect to signer");
        let bytes = serde_json::to_vec(&value).expect("request should serialize");
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .expect("request length should write");
        stream
            .write_all(&bytes)
            .await
            .expect("request body should write");
        let mut len = [0u8; 4];
        stream
            .read_exact(&mut len)
            .await
            .expect("response length should read");
        let mut bytes = vec![0u8; u32::from_be_bytes(len) as usize];
        stream
            .read_exact(&mut bytes)
            .await
            .expect("response body should read");
        serde_json::from_slice(&bytes).expect("response should parse")
    }
}

impl Drop for RemoteSignerTestServer {
    fn drop(&mut self) {
        let _ = self.thread.take();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn start_remote_signer(
    _temp_dir: &common::TempDir,
    key_id: &str,
    key_path: &Path,
    token_env: &str,
    allow_tls12_unstructured_signing: bool,
) -> RemoteSignerTestServer {
    start_remote_signer_with_limits(
        _temp_dir,
        key_id,
        key_path,
        token_env,
        allow_tls12_unstructured_signing,
        DEFAULT_REMOTE_SIGNER_MAX_CONNECTIONS,
        Duration::from_millis(DEFAULT_REMOTE_SIGNER_IO_TIMEOUT_MS),
    )
    .await
}

async fn start_remote_signer_with_limits(
    _temp_dir: &common::TempDir,
    key_id: &str,
    key_path: &Path,
    token_env: &str,
    allow_tls12_unstructured_signing: bool,
    max_connections: usize,
    io_timeout: Duration,
) -> RemoteSignerTestServer {
    unsafe {
        std::env::set_var(token_env, remote_signer_token());
    }
    let id = NEXT_REMOTE_SIGNER_ID.fetch_add(1, Ordering::Relaxed);
    let socket_path = std::env::temp_dir().join(format!("obks-{}-{id}.sock", std::process::id()));
    let config = SignerServerConfig {
        socket_path: socket_path.clone(),
        socket_mode: 0o600,
        keys: vec![(key_id.to_string(), key_path.to_path_buf())],
        token_env: token_env.to_string(),
        max_connections,
        io_timeout,
        allow_peer_uids: Vec::new(),
        allow_peer_gids: Vec::new(),
        allow_tls12_unstructured_signing,
    };
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("remote signer test runtime should build");
        runtime.block_on(async move {
            remote_signer::serve(config)
                .await
                .expect("remote signer should serve");
        });
    });
    for _ in 0..100 {
        if socket_path.exists() {
            return RemoteSignerTestServer {
                socket_path,
                thread: Some(thread),
            };
        }
        assert!(
            !thread.is_finished(),
            "remote signer thread exited before binding"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("remote signer socket was not created");
}

fn remote_signer_token_env(prefix: &str) -> String {
    let id = NEXT_REMOTE_SIGNER_ID.fetch_add(1, Ordering::Relaxed);
    format!("OXIBELT_KEYSIGNER_{prefix}_{id}")
}

fn remote_signer_token() -> String {
    base64::engine::general_purpose::STANDARD.encode([23u8; 32])
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
