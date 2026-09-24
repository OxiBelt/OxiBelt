use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use rustls::{ClientConfig, ClientConnection, ProtocolVersion, RootCertStore, ServerConnection};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};

use super::*;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[test]
fn sni_version_policy_lookup_tracks_route_policy() {
  let temp_dir = common::TempDir::new("sni-version-policy-lookup");
  let (config, _) = sni_version_policy_config(&temp_dir);
  let server_config = downstream_tls_server_config(&config);
  assert_sni_policy_lookup(&server_config);
}

#[test]
fn partitioned_tcp_resumption_keys_include_certificate_identity() {
  let temp_dir = common::TempDir::new("tcp-cert-partition-keys");
  let config = partitioned_certificate_config(&temp_dir);
  let server_config = downstream_tls_server_config(&config);
  let identities = server_config
    .configs
    .keys()
    .filter_map(|key| key.certificate_identity.as_deref())
    .collect::<std::collections::HashSet<_>>();

  assert_eq!(identities.len(), 2);
}

#[test]
fn partitioned_quic_policy_index_includes_certificate_identity() {
  let temp_dir = common::TempDir::new("quic-cert-partition-index");
  let config = partitioned_certificate_config(&temp_dir);
  let quic_config = build_downstream_quic_server_config_with_resumption_and_ocsp(
    &config.crypto,
    &config.tls,
    &config.quic,
    None,
    &config.routes,
    None,
    None,
    None,
    None,
  )
  .expect("QUIC server config should build");

  assert!(quic_config.requires_sni_policy_demux());
  assert_ne!(
    quic_config.policy_index_for_sni(Some("example.com")),
    quic_config.policy_index_for_sni(Some("alt.example.com"))
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sni_version_policy_selects_tcp_tls_versions() {
  let temp_dir = common::TempDir::new("sni-version-policy");
  let (config, ca_cert_path) = sni_version_policy_config(&temp_dir);
  let server_config = downstream_tls_server_config(&config);

  let legacy_version = selected_tcp_tls_version(
    server_config.clone(),
    &ca_cert_path,
    "legacy.example.com",
    &[&rustls::version::TLS12],
  )
  .await;
  let default_version = selected_tcp_tls_version(
    server_config,
    &ca_cert_path,
    "example.com",
    &[&rustls::version::TLS13],
  )
  .await;

  assert_eq!(legacy_version, ProtocolVersion::TLSv1_2);
  assert_eq!(default_version, ProtocolVersion::TLSv1_3);
}

#[test]
fn dual_version_tls12_server_hello_contains_downgrade_protection() {
  let temp_dir = common::TempDir::new("tls12-downgrade-sentinel");
  let (cert, key) = common::create_self_signed_cert(temp_dir.path(), "example.com");
  let raw = common::minimal_config_toml(&cert, &key).replace(
    "[tls]\n",
    "[tls]\nmin_version = \"tls1.2\"\nmax_version = \"tls1.3\"\n",
  );
  let config: crate::config::Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let server_config = downstream_tls_server_config(&config);
  let config_set = server_config
    .configs
    .get(&server_config.default_key)
    .expect("default TLS policy should exist");
  assert!(
    config_set.tls13.is_some(),
    "listener should also support TLS 1.3"
  );
  let tls12 = config_set
    .tls12
    .as_ref()
    .expect("TLS 1.2 should be enabled");

  let random = tls12_server_hello_random(tls12.config.clone(), &cert);
  assert_eq!(
    &random[24..],
    b"DOWNGRD\x01",
    "TLS 1.3-capable listener must mark a TLS 1.2 ServerHello"
  );
}

#[test]
fn dual_version_turn_tls12_server_hello_contains_downgrade_protection() {
  let temp_dir = common::TempDir::new("turn-tls12-downgrade-sentinel");
  let (cert, key) = common::create_self_signed_cert(temp_dir.path(), "example.com");
  let raw = common::minimal_config_toml(&cert, &key).replace(
    "[tls]\n",
    "[tls]\nmin_version = \"tls1.2\"\nmax_version = \"tls1.3\"\n",
  );
  let config: crate::config::Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let turn = build_turn_tls_server_config_with_resumption(
    &config.crypto,
    &crate::config::TurnListenerTlsConfig::default(),
    &config.tls,
    None,
  )
  .expect("TURN TLS config should build");
  assert!(turn.config_set.tls13.is_some());
  let tls12 = turn
    .config_set
    .tls12
    .as_ref()
    .expect("TLS 1.2 should be enabled");

  let random = tls12_server_hello_random(tls12.config.clone(), &cert);
  assert_eq!(&random[24..], b"DOWNGRD\x01");
}

fn tls12_server_hello_random(server_config: Arc<rustls::ServerConfig>, cert: &Path) -> [u8; 32] {
  let client_config = Arc::new(tcp_client_config(cert, &[&rustls::version::TLS12]));
  let mut client = ClientConnection::new(
    client_config,
    ServerName::try_from("example.com").expect("server name should be valid"),
  )
  .expect("TLS 1.2 client should build");
  let mut server = ServerConnection::new(server_config).expect("server should build");
  let mut client_hello = Vec::new();
  client
    .write_tls(&mut client_hello)
    .expect("ClientHello should serialize");
  server
    .read_tls(&mut client_hello.as_slice())
    .expect("server should read ClientHello");
  server
    .process_new_packets()
    .expect("server should accept ClientHello");
  let mut server_flight = Vec::new();
  server
    .write_tls(&mut server_flight)
    .expect("ServerHello should serialize");
  assert!(
    server_flight.len() >= 43,
    "ServerHello should contain a random"
  );
  assert_eq!(
    server_flight[0], 22,
    "first record must contain a handshake"
  );
  assert_eq!(server_flight[5], 2, "first handshake must be ServerHello");
  server_flight[11..43]
    .try_into()
    .expect("ServerHello.random should contain 32 bytes")
}

fn sni_version_policy_config(temp_dir: &common::TempDir) -> (crate::config::Config, PathBuf) {
  let (ca_cert_path, ca_key_path) =
    common::create_self_signed_cert(temp_dir.path(), "sni-version-policy-ca");
  let (default_cert, default_key) = common::create_ca_signed_server_cert(
    temp_dir.path(),
    "example.com",
    &ca_cert_path,
    &ca_key_path,
  );
  let (legacy_cert, legacy_key) = common::create_ca_signed_server_cert(
    temp_dir.path(),
    "legacy.example.com",
    &ca_cert_path,
    &ca_key_path,
  );
  let raw = common::minimal_config_toml(&default_cert, &default_key).replace(
    "[tls.ocsp]",
    &format!(
      r#"server_names = ["example.com"]

[tls.resumption]
mode = "off"

[[tls.certificates]]
server_names = ["legacy.example.com"]
cert_chain = "{}"
private_key = "{}"

[tls.ocsp]"#,
      legacy_cert.display(),
      legacy_key.display()
    ),
  ) + r#"

[[routes]]
name = "legacy-root"
hosts = ["legacy.example.com"]
path_prefix = "/"
upstream = "app"

[routes.tls]
min_version = "tls1.2"
max_version = "tls1.2"
"#;
  let config: crate::config::Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  (config, ca_cert_path)
}

fn partitioned_certificate_config(temp_dir: &common::TempDir) -> crate::config::Config {
  let (default_cert, default_key) = common::create_self_signed_cert(temp_dir.path(), "example.com");
  let (alt_cert, alt_key) = common::create_self_signed_cert(temp_dir.path(), "alt.example.com");
  let raw = common::minimal_config_toml(&default_cert, &default_key)
    .replace(
      "[tls]\n",
      r#"[tls]
server_names = ["example.com"]
require_sni = true
reject_unknown_sni = true
"#,
    )
    .replace(
      "[tls.ocsp]",
      &format!(
        r#"[tls.resumption]
mode = "stateful"
multi_certificate = "partition_by_sni"

[[tls.certificates]]
server_names = ["alt.example.com"]
cert_chain = "{}"
private_key = "{}"

[tls.ocsp]"#,
        alt_cert.display(),
        alt_key.display()
      ),
    );
  let config: crate::config::Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

fn downstream_tls_server_config(config: &crate::config::Config) -> DownstreamTlsServerConfig {
  build_downstream_tls_server_config_with_resumption_and_ocsp(
    &config.crypto,
    &config.tls,
    &config.listeners,
    &config.routes,
    0,
    None,
    None,
    None,
    None,
  )
  .expect("server config should build")
}

fn assert_sni_policy_lookup(server_config: &DownstreamTlsServerConfig) {
  let legacy_policy = server_config.selected_negotiation_policy(Some("legacy.example.com"));
  assert_eq!(legacy_policy.min_version, TlsVersion::Tls12);
  assert_eq!(legacy_policy.max_version, TlsVersion::Tls12);
  let default_policy = server_config.selected_negotiation_policy(Some("example.com"));
  assert_eq!(default_policy.min_version, TlsVersion::Tls13);
  assert_eq!(default_policy.max_version, TlsVersion::Tls13);
  assert_eq!(
    server_config.selected_negotiation_policy(Some("unknown.example.com")),
    default_policy
  );
  assert_eq!(
    server_config.selected_negotiation_policy(None),
    default_policy
  );
}

async fn selected_tcp_tls_version(
  server_config: DownstreamTlsServerConfig,
  ca_cert_path: &Path,
  server_name: &str,
  versions: &[&'static rustls::SupportedProtocolVersion],
) -> ProtocolVersion {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("server listener should bind");
  let addr = listener.local_addr().expect("listener addr should resolve");
  let server = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("server should accept");
    let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
      .await
      .expect("server should read ClientHello");
    let selected_config = server_config.select(&start.client_hello());
    let tls_stream = start
      .into_stream(selected_config)
      .await
      .expect("server TLS handshake should complete");
    tls_stream
      .get_ref()
      .1
      .protocol_version()
      .expect("TLS version should be selected")
  });

  let client_config = tcp_client_config(ca_cert_path, versions);
  let stream = TcpStream::connect(addr)
    .await
    .expect("client should connect to server");
  TlsConnector::from(Arc::new(client_config))
    .connect(
      ServerName::try_from(server_name.to_string()).expect("server name should be valid"),
      stream,
    )
    .await
    .expect("client TLS handshake should complete");

  server.await.expect("server task should finish")
}

fn tcp_client_config(
  ca_cert_path: &Path,
  versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
  let mut roots = RootCertStore::empty();
  let certs = CertificateDer::pem_file_iter(ca_cert_path)
    .expect("CA cert file should open")
    .collect::<Result<Vec<_>, _>>()
    .expect("CA cert should parse");
  let (added, _) = roots.add_parsable_certificates(certs);
  assert!(added > 0, "CA root should be added");
  ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
    .with_protocol_versions(versions)
    .expect("client TLS versions should configure")
    .with_root_certificates(roots)
    .with_no_client_auth()
}
