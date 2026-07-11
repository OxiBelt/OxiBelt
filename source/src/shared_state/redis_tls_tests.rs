use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::redis_pool::RedisPool;
use crate::config::{
  CryptoConfig, RedisAuthConfig, RedisPlaintextPolicy, RedisTlsConfig, RedisTrustStore,
  SharedStateBackendConfig, SharedStateBackendKind,
};
use crate::metrics::Metrics;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn load_certificates(path: &Path) -> Vec<CertificateDer<'static>> {
  let bytes = std::fs::read(path).expect("test certificate should be readable");
  CertificateDer::pem_slice_iter(&bytes)
    .collect::<Result<Vec<_>, _>>()
    .expect("test certificate should parse")
}

fn load_private_key(path: &Path) -> PrivateKeyDer<'static> {
  let bytes = std::fs::read(path).expect("test private key should be readable");
  PrivateKeyDer::from_pem_slice(&bytes).expect("test private key should parse")
}

fn redis_server_config(
  certificate: &Path,
  private_key: &Path,
  client_ca: Option<&Path>,
) -> Arc<ServerConfig> {
  let provider = Arc::new(crate::tls::default_crypto_provider());
  let builder = ServerConfig::builder_with_provider(provider.clone())
    .with_safe_default_protocol_versions()
    .expect("test TLS versions should configure");
  let builder = match client_ca {
    Some(client_ca) => {
      let mut roots = RootCertStore::empty();
      let (added, _) = roots.add_parsable_certificates(load_certificates(client_ca));
      assert!(added > 0, "client CA should contain a trust anchor");
      let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
          .build()
          .expect("client certificate verifier should build");
      builder.with_client_cert_verifier(verifier)
    }
    None => builder.with_no_client_auth(),
  };
  Arc::new(
    builder
      .with_single_cert(
        load_certificates(certificate),
        load_private_key(private_key),
      )
      .expect("test Redis TLS server should build"),
  )
}

fn redis_backend(
  port: u16,
  tls: RedisTlsConfig,
  auth: RedisAuthConfig,
) -> SharedStateBackendConfig {
  SharedStateBackendConfig {
    name: "redis-tls-test".to_string(),
    kind: SharedStateBackendKind::Redis,
    connection_url: Some(format!("rediss://127.0.0.1:{port}/2")),
    connection_url_env: None,
    max_connections: 1,
    connect_timeout_ms: 1_000,
    redis_pool: None,
    redis_tls: tls,
    redis_auth: auth,
    tls: Default::default(),
  }
}

fn redis_pool(config: &SharedStateBackendConfig) -> RedisPool {
  RedisPool::new(
    config,
    Duration::from_millis(1_000),
    &CryptoConfig::default(),
    RedisPlaintextPolicy::Deny,
    Metrics::new(),
  )
  .expect("Redis TLS pool should build")
}

fn spki_pin(certificate: &Path) -> String {
  let certificate = load_certificates(certificate)
    .into_iter()
    .next()
    .expect("server certificate should contain a leaf");
  let certificate = webpki::EndEntityCert::try_from(&certificate)
    .expect("server certificate should parse as an end-entity certificate");
  format!(
    "sha256/{}",
    base64::engine::general_purpose::STANDARD.encode(crate::crypto::sha256(
      certificate.subject_public_key_info().as_ref()
    ))
  )
}

fn create_expired_server_certificate(
  directory: &Path,
  common_name: &str,
  ca_certificate: &Path,
  ca_private_key: &Path,
) -> (PathBuf, PathBuf) {
  let key = directory.join("expired-server.key");
  let csr = directory.join("expired-server.csr");
  let certificate = directory.join("expired-server.pem");
  let request_config = directory.join("expired-server-request.cnf");
  let authority_config = directory.join("expired-server-authority.cnf");
  let index = directory.join("expired-server-index.txt");
  let serial = directory.join("expired-server-serial.txt");
  let issued = directory.join("expired-server-issued");
  std::fs::create_dir_all(&issued).expect("expired certificate directory should create");
  std::fs::write(
    &request_config,
    format!(
      "[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = req_ext\nprompt = no\n\n[req_distinguished_name]\nCN = {common_name}\n\n[req_ext]\nsubjectAltName = @alt_names\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\n\n[alt_names]\nDNS.1 = {common_name}\n"
    ),
  )
  .expect("expired certificate request config should write");
  std::fs::write(&index, "").expect("expired certificate index should write");
  std::fs::write(&serial, "1000\n").expect("expired certificate serial should write");
  std::fs::write(
    &authority_config,
    format!(
      "[ca]\ndefault_ca = CA_default\n\n[CA_default]\ndatabase = {}\nserial = {}\nnew_certs_dir = {}\ncertificate = {}\nprivate_key = {}\ndefault_md = sha256\ndefault_days = 1\npolicy = policy_any\ncopy_extensions = copy\n\n[policy_any]\ncommonName = supplied\n",
      index.display(),
      serial.display(),
      issued.display(),
      ca_certificate.display(),
      ca_private_key.display(),
    ),
  )
  .expect("expired certificate authority config should write");

  let status = Command::new("openssl")
    .args(["req", "-newkey", "rsa:2048", "-sha256", "-nodes", "-config"])
    .arg(&request_config)
    .arg("-keyout")
    .arg(&key)
    .arg("-out")
    .arg(&csr)
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .expect("openssl should create the expired certificate request");
  assert!(status.success(), "openssl request creation should succeed");
  let status = Command::new("openssl")
    .args(["ca", "-batch", "-config"])
    .arg(&authority_config)
    .arg("-in")
    .arg(&csr)
    .args([
      "-startdate",
      "20200101000000Z",
      "-enddate",
      "20200102000000Z",
    ])
    .arg("-out")
    .arg(&certificate)
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .expect("openssl should sign the expired server certificate");
  assert!(
    status.success(),
    "openssl expired certificate signing should succeed"
  );
  (certificate, key)
}

async fn read_command<R>(reader: &mut R) -> std::io::Result<Vec<Vec<u8>>>
where
  R: AsyncBufRead + Unpin,
{
  let mut header = String::new();
  reader.read_line(&mut header).await?;
  let count = header
    .strip_prefix('*')
    .and_then(|line| line.trim_end().parse::<usize>().ok())
    .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid RESP array header"))?;
  let mut command = Vec::with_capacity(count);
  for _ in 0..count {
    let mut length = String::new();
    reader.read_line(&mut length).await?;
    let length = length
      .strip_prefix('$')
      .and_then(|line| line.trim_end().parse::<usize>().ok())
      .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid RESP bulk header"))?;
    let mut value = vec![0; length + 2];
    reader.read_exact(&mut value).await?;
    if value[length..] != *b"\r\n" {
      return Err(Error::new(
        ErrorKind::InvalidData,
        "invalid RESP bulk terminator",
      ));
    }
    value.truncate(length);
    command.push(value);
  }
  Ok(command)
}

async fn assert_pre_activation_rejected(server_config: Arc<ServerConfig>, tls: RedisTlsConfig) {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("test listener should bind");
  let port = listener
    .local_addr()
    .expect("test listener should have an address")
    .port();
  let server = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("client should connect");
    let _ = TlsAcceptor::from(server_config).accept(stream).await;
  });

  let error = redis_pool(&redis_backend(port, tls, RedisAuthConfig::default()))
    .prewarm()
    .await
    .expect_err("untrusted Redis TLS endpoint must not activate");
  assert!(
    error
      .to_string()
      .contains("shared state Redis backend redis-tls-test"),
    "unexpected pre-activation error: {error}"
  );
  tokio::time::timeout(Duration::from_secs(2), server)
    .await
    .expect("TLS server should observe the failed handshake")
    .expect("TLS server task should not panic");
}

#[tokio::test]
async fn rediss_validates_custom_ca_spki_mtls_and_acl_files_before_activation() {
  let temp_dir = common::TempDir::new("redis-tls-acl");
  let (ca_cert, ca_key) = common::create_self_signed_cert(temp_dir.path(), "redis-test-ca");
  let (server_cert, server_key) =
    common::create_ca_signed_server_cert(temp_dir.path(), "redis.edge.test", &ca_cert, &ca_key);
  let (client_cert, client_key) =
    common::create_ca_signed_client_cert(temp_dir.path(), "oxibelt-client.test", &ca_cert, &ca_key);
  let username_file = temp_dir.path().join("redis-username");
  let password_file = temp_dir.path().join("redis-password");
  std::fs::write(&username_file, "edge-user\n").expect("username secret should write");
  std::fs::write(&password_file, "edge-password\r\n").expect("password secret should write");

  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("test listener should bind");
  let port = listener
    .local_addr()
    .expect("test listener should have an address")
    .port();
  let server_config = redis_server_config(&server_cert, &server_key, Some(&ca_cert));
  let server = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("client should connect");
    let tls = TlsAcceptor::from(server_config)
      .accept(stream)
      .await
      .expect("mTLS handshake should complete");
    let client_certificate_present = tls
      .get_ref()
      .1
      .peer_certificates()
      .is_some_and(|certificates| !certificates.is_empty());
    let (reader, mut writer) = tokio::io::split(tls);
    let mut reader = BufReader::new(reader);
    let auth = read_command(&mut reader)
      .await
      .expect("Redis ACL AUTH should use RESP framing");
    writer
      .write_all(b"+OK\r\n")
      .await
      .expect("Redis server should accept ACL authentication");
    let select = read_command(&mut reader)
      .await
      .expect("Redis SELECT should use RESP framing");
    writer
      .write_all(b"+OK\r\n")
      .await
      .expect("Redis server should accept database selection");
    (client_certificate_present, auth, select)
  });

  let tls = RedisTlsConfig {
    trust_store: RedisTrustStore::Custom,
    server_name: Some("redis.edge.test".to_string()),
    ca_cert: Some(ca_cert),
    client_cert: Some(client_cert),
    client_key: Some(client_key),
    server_spki_sha256: vec![spki_pin(&server_cert)],
  };
  let auth = RedisAuthConfig {
    username_file: Some(username_file),
    password_file: Some(password_file),
  };
  redis_pool(&redis_backend(port, tls, auth))
    .prewarm()
    .await
    .expect("verified Redis TLS and ACL credentials must activate");

  let (client_certificate_present, auth, select) =
    server.await.expect("Redis TLS server should not panic");
  assert!(
    client_certificate_present,
    "client certificate must be presented"
  );
  assert_eq!(
    auth,
    vec![
      b"AUTH".to_vec(),
      b"edge-user".to_vec(),
      b"edge-password".to_vec(),
    ]
  );
  assert_eq!(select, vec![b"SELECT".to_vec(), b"2".to_vec()]);
}

#[tokio::test]
async fn rediss_rejects_invalid_ca_hostname_and_spki_before_activation() {
  let temp_dir = common::TempDir::new("redis-tls-rejections");
  let (ca_cert, ca_key) = common::create_self_signed_cert(temp_dir.path(), "redis-test-ca");
  let (other_ca, _other_ca_key) =
    common::create_self_signed_cert(temp_dir.path(), "redis-other-ca");
  let (server_cert, server_key) =
    common::create_ca_signed_server_cert(temp_dir.path(), "redis.edge.test", &ca_cert, &ca_key);
  let server_config = redis_server_config(&server_cert, &server_key, None);

  assert_pre_activation_rejected(
    server_config.clone(),
    RedisTlsConfig {
      trust_store: RedisTrustStore::Custom,
      server_name: Some("redis.edge.test".to_string()),
      ca_cert: Some(other_ca),
      ..Default::default()
    },
  )
  .await;
  assert_pre_activation_rejected(
    server_config.clone(),
    RedisTlsConfig {
      trust_store: RedisTrustStore::Custom,
      server_name: Some("other.edge.test".to_string()),
      ca_cert: Some(ca_cert.clone()),
      ..Default::default()
    },
  )
  .await;
  assert_pre_activation_rejected(
    server_config,
    RedisTlsConfig {
      trust_store: RedisTrustStore::Custom,
      server_name: Some("redis.edge.test".to_string()),
      ca_cert: Some(ca_cert.clone()),
      server_spki_sha256: vec![format!(
        "sha256/{}",
        base64::engine::general_purpose::STANDARD.encode([0_u8; 32])
      )],
      ..Default::default()
    },
  )
  .await;

  let (expired_server_cert, expired_server_key) =
    create_expired_server_certificate(temp_dir.path(), "redis.edge.test", &ca_cert, &ca_key);
  assert_pre_activation_rejected(
    redis_server_config(&expired_server_cert, &expired_server_key, None),
    RedisTlsConfig {
      trust_store: RedisTrustStore::Custom,
      server_name: Some("redis.edge.test".to_string()),
      ca_cert: Some(ca_cert),
      ..Default::default()
    },
  )
  .await;
}
