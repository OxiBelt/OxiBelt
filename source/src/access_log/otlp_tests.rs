mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::json;

use super::*;
use crate::access_log::projection::{project_ecs, project_ocsf};
use crate::config::CryptoConfig;

#[test]
fn endpoint_parser_accepts_https_with_default_port() {
  let endpoint =
    OtlpHttpEndpoint::parse("https://collector.example/v1/logs").expect("endpoint should parse");

  assert_eq!(endpoint.scheme, OtlpEndpointScheme::Https);
  assert_eq!(endpoint.host, "collector.example");
  assert_eq!(endpoint.port, 443);
  assert_eq!(endpoint.authority, "collector.example");
  assert_eq!(endpoint.path_and_query, "/v1/logs");
}

#[test]
fn endpoint_parser_allows_plaintext_only_for_loopback_collectors() {
  let loopback = OtlpHttpEndpoint::parse("http://127.42.0.9:4318/v1/logs")
    .expect("loopback HTTP endpoint should parse");
  assert_eq!(loopback.scheme, OtlpEndpointScheme::Http);

  let localhost = OtlpHttpEndpoint::parse("http://localhost:4318/v1/logs")
    .expect("localhost HTTP endpoint should parse");
  assert_eq!(localhost.scheme, OtlpEndpointScheme::Http);

  let error = OtlpHttpEndpoint::parse("http://collector.example:4318/v1/logs")
    .expect_err("remote HTTP endpoint should fail");
  assert!(
    error
      .to_string()
      .contains("http:// is only supported for loopback"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn post_otlp_http_keeps_local_plaintext_collector_compatibility() {
  let (endpoint, server) = spawn_plain_otlp_server();
  let endpoint = OtlpHttpEndpoint::parse(&endpoint).expect("endpoint should parse");

  post_otlp_http(&endpoint, Duration::from_secs(3), b"local-payload", None)
    .expect("local plaintext OTLP post should succeed");
  let captured = server.join().expect("plain server should join");

  assert_payload_contains(&captured, b"POST /v1/logs HTTP/1.1");
  assert_payload_contains(&captured, b"Host: 127.0.0.1:");
  assert_payload_contains(&captured, b"local-payload");
}

#[test]
fn post_otlp_http_uses_https_with_configured_ca() {
  let temp_dir = common::TempDir::new("access-log-otlp-https");
  let (ca_cert_path, ca_key_path) =
    common::create_self_signed_cert(temp_dir.path(), "access-log-otlp-ca");
  let (server_cert_path, server_key_path) =
    common::create_ca_signed_server_cert(temp_dir.path(), "localhost", &ca_cert_path, &ca_key_path);
  let (endpoint, server) = spawn_tls_otlp_server(&server_cert_path, &server_key_path);
  let endpoint = OtlpHttpEndpoint::parse(&endpoint).expect("endpoint should parse");
  let tls_config = test_client_tls_config(std::slice::from_ref(&ca_cert_path));

  post_otlp_http(
    &endpoint,
    Duration::from_secs(3),
    b"secure-payload",
    Some(&tls_config),
  )
  .expect("HTTPS OTLP post should succeed with configured CA");
  let captured = server
    .join()
    .expect("TLS server should join")
    .expect("TLS server should capture request");

  assert_payload_contains(&captured, b"POST /v1/logs HTTP/1.1");
  assert_payload_contains(&captured, b"Host: localhost:");
  assert_payload_contains(&captured, b"secure-payload");
}

#[test]
fn post_otlp_http_rejects_untrusted_https_collector_certificate() {
  let temp_dir = common::TempDir::new("access-log-otlp-https-untrusted");
  let (ca_cert_path, ca_key_path) =
    common::create_self_signed_cert(temp_dir.path(), "access-log-otlp-untrusted-ca");
  let (server_cert_path, server_key_path) =
    common::create_ca_signed_server_cert(temp_dir.path(), "localhost", &ca_cert_path, &ca_key_path);
  let (endpoint, server) = spawn_tls_otlp_server(&server_cert_path, &server_key_path);
  let endpoint = OtlpHttpEndpoint::parse(&endpoint).expect("endpoint should parse");
  let tls_config = test_client_tls_config(&[]);

  let error = post_otlp_http(
    &endpoint,
    Duration::from_secs(3),
    b"secure-payload",
    Some(&tls_config),
  )
  .expect_err("untrusted collector certificate should fail");
  let _ = server.join().expect("TLS server should join");
  let error_chain = format!("{error:#}");

  assert!(
    error_chain.contains("certificate")
      || error_chain.contains("invalid peer certificate")
      || error_chain.contains("UnknownIssuer"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn otlp_logs_export_request_contains_ecs_payload_and_attributes() {
  let original = json!({
    "event": "oxibelt.access",
    "scope": "system",
    "method": "GET",
    "status": 200,
    "user_agent": {
      "values": ["first-agent", "second-agent"],
      "is_truncated": false
    }
  });
  let record = OtlpLogRecord::from_projected(
    AccessLogSource::System,
    42,
    AccessLogSchema::Ecs,
    &original,
    project_ecs(AccessLogSource::System, 42, &original),
  );

  let bytes = encode_logs_export_request("oxibelt", &[record]);

  assert_payload_contains(&bytes, b"service.name");
  assert_payload_contains(&bytes, b"ecs.version");
  assert_payload_contains(&bytes, b"oxibelt.access_log.schema");
  assert_payload_contains(&bytes, b"oxibelt.access.system");
  assert_payload_contains(&bytes, b"\"oxibelt\"");
  assert_payload_contains(&bytes, b"\"original\"");
  assert_payload_contains(&bytes, b"first-agent");
  assert_payload_contains(&bytes, b"second-agent");
}

#[test]
fn otlp_logs_export_request_contains_ocsf_payload_and_attributes() {
  let original = json!({
    "event": "oxibelt.admin.access",
    "scope": "admin",
    "request_id": "req-1",
    "actor": "alice",
    "principal": "admin",
    "subject": "sub-1",
    "groups": ["ops"],
    "tls": true,
    "method": "POST",
    "path": "/admin/v1/tokens",
    "service": "tokens",
    "operation": "post.tokens.create",
    "action": "admin:CreateToken",
    "resource": "token/*",
    "target_kind": "token",
    "target_id": "tok-1",
    "status": 201,
    "outcome": "applied"
  });
  let record = OtlpLogRecord::from_projected(
    AccessLogSource::Admin,
    42,
    AccessLogSchema::Ocsf,
    &original,
    project_ocsf(AccessLogSource::Admin, 42, &original),
  );

  let bytes = encode_logs_export_request("oxibelt", &[record]);

  assert_payload_contains(&bytes, b"ocsf.version");
  assert_payload_contains(&bytes, b"API Activity");
  assert_payload_contains(&bytes, b"oxibelt.admin.access");
  assert_payload_contains(&bytes, b"admin:CreateToken");
  assert_payload_contains(&bytes, b"tok-1");
}

#[test]
fn failed_status_uses_error_severity() {
  let original = json!({
    "event": "oxibelt.access",
    "scope": "waf",
    "method": "POST",
    "status": 403
  });
  let record = OtlpLogRecord::from_projected(
    AccessLogSource::Waf,
    42,
    AccessLogSchema::Ecs,
    &original,
    project_ecs(AccessLogSource::Waf, 42, &original),
  );

  assert_eq!(record.severity_number, 17);
  assert_eq!(record.severity_text, "ERROR");
}

fn assert_payload_contains(payload: &[u8], needle: &[u8]) {
  assert!(
    payload.windows(needle.len()).any(|window| window == needle),
    "payload did not contain {:?}",
    String::from_utf8_lossy(needle)
  );
}

fn spawn_plain_otlp_server() -> (String, thread::JoinHandle<Vec<u8>>) {
  let listener =
    std::net::TcpListener::bind("127.0.0.1:0").expect("plain OTLP listener should bind");
  let endpoint = format!(
    "http://127.0.0.1:{}/v1/logs",
    listener
      .local_addr()
      .expect("listener should expose address")
      .port()
  );
  let server = thread::spawn(move || {
    let (mut stream, _) = listener.accept().expect("plain server should accept");
    stream
      .set_read_timeout(Some(Duration::from_secs(3)))
      .expect("plain server should set read timeout");
    let captured = read_http_request(&mut stream).expect("plain server should read request");
    stream
      .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
      .expect("plain server should write response");
    captured
  });
  (endpoint, server)
}

fn spawn_tls_otlp_server(
  cert_path: &Path,
  key_path: &Path,
) -> (String, thread::JoinHandle<anyhow::Result<Vec<u8>>>) {
  let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("TLS OTLP listener should bind");
  let endpoint = format!(
    "https://localhost:{}/v1/logs",
    listener
      .local_addr()
      .expect("listener should expose address")
      .port()
  );
  let server_config = test_server_tls_config(cert_path, key_path);
  let server = thread::spawn(move || -> anyhow::Result<Vec<u8>> {
    let (stream, _) = listener.accept().context("TLS server should accept")?;
    stream
      .set_read_timeout(Some(Duration::from_secs(3)))
      .context("TLS server should set read timeout")?;
    stream
      .set_write_timeout(Some(Duration::from_secs(3)))
      .context("TLS server should set write timeout")?;
    let connection =
      rustls::ServerConnection::new(server_config).context("TLS server connection should build")?;
    let mut tls = rustls::StreamOwned::new(connection, stream);
    let captured = read_http_request(&mut tls).context("TLS server should read request")?;
    tls
      .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
      .context("TLS server should write response")?;
    Ok(captured)
  });
  (endpoint, server)
}

fn read_http_request(stream: &mut (impl Read + Write)) -> anyhow::Result<Vec<u8>> {
  let mut captured = Vec::new();
  let mut chunk = [0u8; 512];
  loop {
    let read = stream.read(&mut chunk)?;
    if read == 0 {
      break;
    }
    captured.extend_from_slice(&chunk[..read]);
    if http_request_complete(&captured) {
      break;
    }
  }
  Ok(captured)
}

fn http_request_complete(bytes: &[u8]) -> bool {
  let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
    return false;
  };
  let headers = String::from_utf8_lossy(&bytes[..header_end]);
  let content_length = headers
    .lines()
    .find_map(|line| {
      let (name, value) = line.split_once(':')?;
      if name.eq_ignore_ascii_case("content-length") {
        value.trim().parse::<usize>().ok()
      } else {
        None
      }
    })
    .unwrap_or(0);
  bytes.len().saturating_sub(header_end + 4) >= content_length
}

fn test_client_tls_config(ca_certs: &[PathBuf]) -> Arc<rustls::ClientConfig> {
  let config = AccessLogOtlpConfig {
    trusted_ca_certs: ca_certs.to_vec(),
    ..AccessLogOtlpConfig::default()
  };
  build_otlp_tls_config(&config, &CryptoConfig::default())
    .expect("test OTLP TLS client should build")
}

fn test_server_tls_config(cert_path: &Path, key_path: &Path) -> Arc<rustls::ServerConfig> {
  let provider = Arc::new(crate::tls::default_crypto_provider());
  let mut config = rustls::ServerConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()
    .expect("test TLS versions should configure")
    .with_no_client_auth()
    .with_single_cert(load_test_certs(cert_path), load_test_private_key(key_path))
    .expect("test server TLS config should build");
  config.alpn_protocols = vec![b"http/1.1".to_vec()];
  Arc::new(config)
}

fn load_test_certs(path: &Path) -> Vec<CertificateDer<'static>> {
  let bytes = fs::read(path).expect("test certificate should be readable");
  CertificateDer::pem_slice_iter(&bytes)
    .collect::<Result<Vec<_>, _>>()
    .expect("test certificate should parse")
}

fn load_test_private_key(path: &Path) -> PrivateKeyDer<'static> {
  let bytes = fs::read(path).expect("test private key should be readable");
  PrivateKeyDer::from_pem_slice(&bytes).expect("test private key should parse")
}
