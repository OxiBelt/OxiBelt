use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::Empty;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use super::*;
use crate::config::{Config, RuntimeOverrides, UpstreamEchConfig};
use crate::server;
use crate::state::{AppHandle, AppSnapshot};
use crate::tls;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

async fn unused_loopback_port() -> u16 {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("ephemeral listener should bind");
  listener
    .local_addr()
    .expect("ephemeral listener address should be available")
    .port()
}

async fn connect_with_retry(addr: SocketAddr) -> TcpStream {
  let deadline = Instant::now() + Duration::from_secs(2);
  loop {
    match TcpStream::connect(addr).await {
      Ok(stream) => return stream,
      Err(_) if Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(10)).await;
      }
      Err(error) => panic!("proxy listener did not become ready: {error}"),
    }
  }
}

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("test config should parse");
  config.validate().expect("test config should validate");
  config
}

fn scoped_connection_config(
  cert_path: &std::path::Path,
  key_path: &std::path::Path,
  port: u16,
) -> String {
  format!(
    r#"{}

[[routes]]
name = "first"
hosts = ["first.example.test"]
path_prefix = "/"
upstream = "app"

[[routes]]
name = "second"
hosts = ["second.example.test"]
path_prefix = "/"
upstream = "app"

[[proxy.real_ip.rules]]
name = "first-authority"
hosts = ["first.example.test"]
server_names = ["edge.example.test"]
enabled = true
trusted_proxies = ["127.0.0.0/8"]
header = "x-forwarded-for"

[[proxy.real_ip.rules]]
name = "second-authority"
hosts = ["second.example.test"]
server_names = ["edge.example.test"]
enabled = true
trusted_proxies = ["127.0.0.0/8"]
header = "x-real-ip"

[waf]
enabled = true

[[waf.rules]]
name = "first-identity"
phase = "request"
priority = 10
when = "Request.Client.Ip.inCidr('203.0.113.0/24')"

[[waf.rules.actions]]
type = "reject"
status = 451

[[waf.rules]]
name = "second-identity"
phase = "request"
priority = 20
when = "Request.Client.Ip.inCidr('198.51.100.0/24')"

[[waf.rules.actions]]
type = "reject"
status = 452
"#,
    common::minimal_config_toml(cert_path, key_path).replace(
      "https_bind = \"127.0.0.1:8443\"",
      &format!("https_bind = \"127.0.0.1:{port}\"")
    )
  )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_connection_reselects_scoped_real_ip_for_each_authority() {
  let temp_dir = common::TempDir::new("h2-scoped-real-ip");
  let (ca_cert_path, ca_key_path) =
    common::create_self_signed_cert(temp_dir.path(), "h2-scoped-real-ip-ca");
  let (cert_path, key_path) = common::create_ca_signed_server_cert(
    temp_dir.path(),
    "edge.example.test",
    &ca_cert_path,
    &ca_key_path,
  );
  let port = unused_loopback_port().await;
  let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
  let snapshot = AppSnapshot::new(parse_config(&scoped_connection_config(
    &cert_path, &key_path, port,
  )))
  .await
  .expect("snapshot should initialize");
  let state = AppHandle::new(snapshot);
  let server_task = tokio::spawn(server::serve(state, None, RuntimeOverrides::default()));

  let mut client_config =
    tls::build_upstream_client_config(&[ca_cert_path], &UpstreamEchConfig::default())
      .expect("client trust should initialize");
  client_config.alpn_protocols = vec![b"h2".to_vec()];
  let stream = connect_with_retry(addr).await;
  let tls_stream = TlsConnector::from(Arc::new(client_config))
    .connect(
      "edge.example.test".try_into().expect("SNI should parse"),
      stream,
    )
    .await
    .expect("TLS handshake should complete");
  assert_eq!(
    tls_stream.get_ref().1.alpn_protocol(),
    Some(b"h2".as_slice())
  );

  let (mut sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
    .await
    .expect("HTTP/2 handshake should complete");
  let connection_task = tokio::spawn(connection);

  let first = Request::builder()
    .method(Method::GET)
    .uri("https://first.example.test/")
    .header("x-forwarded-for", "203.0.113.9")
    .body(Empty::<bytes::Bytes>::new())
    .expect("first request should build");
  let first_response = sender
    .send_request(first)
    .await
    .expect("first response should arrive");
  assert_eq!(
    first_response.status(),
    StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
  );

  let second = Request::builder()
    .method(Method::GET)
    .uri("https://second.example.test/")
    .header("x-real-ip", "198.51.100.8")
    .body(Empty::<bytes::Bytes>::new())
    .expect("second request should build");
  let second_response = sender
    .send_request(second)
    .await
    .expect("second response should arrive");
  assert_eq!(second_response.status(), StatusCode::from_u16(452).unwrap());

  drop(sender);
  connection_task.abort();
  server_task.abort();
}

#[tokio::test]
async fn full_reload_keeps_captured_selector_and_rejects_invalid_replacement() {
  let temp_dir = common::TempDir::new("reload-scoped-real-ip");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "reload-scoped-real-ip");
  let raw = format!(
    r#"{}

[[proxy.real_ip.rules]]
name = "reload-policy"
hosts = ["reload.example.test"]
enabled = true
trusted_proxies = ["10.0.0.0/8"]
header = "x-forwarded-for"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let initial_config = parse_config(&raw);
  let initial = AppSnapshot::new(initial_config)
    .await
    .expect("initial snapshot should initialize");
  let handle = AppHandle::new(initial);
  let captured = handle.snapshot();
  let mut headers = HeaderMap::new();
  headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
  headers.insert("x-real-ip", "198.51.100.7".parse().unwrap());
  let peer = "10.0.0.7:443".parse().unwrap();
  assert_eq!(
    captured
      .resolve_client_addr(&headers, peer, "reload.example.test", None)
      .expect("captured selector should resolve")
      .ip()
      .to_string(),
    "203.0.113.7"
  );

  let changed_raw = raw.replace("header = \"x-forwarded-for\"", "header = \"x-real-ip\"");
  let replacement =
    AppSnapshot::new_with_previous(parse_config(&changed_raw), Some(captured.as_ref()))
      .await
      .expect("valid replacement snapshot should initialize");
  handle.replace(replacement);
  assert_eq!(
    captured
      .resolve_client_addr(&headers, peer, "reload.example.test", None)
      .expect("captured selector must remain usable")
      .ip()
      .to_string(),
    "203.0.113.7"
  );
  let current = handle.snapshot();
  assert_eq!(
    current
      .resolve_client_addr(&headers, peer, "reload.example.test", None)
      .expect("replacement selector should resolve")
      .ip()
      .to_string(),
    "198.51.100.7"
  );

  let invalid_raw = changed_raw.replace("reload.example.test", "bad*selector");
  let invalid = toml::from_str::<Config>(&invalid_raw).expect("invalid selector TOML should parse");
  assert!(
    AppSnapshot::new_with_previous(invalid, Some(current.as_ref()))
      .await
      .is_err(),
    "invalid selector compilation must reject a replacement snapshot"
  );
  assert!(
    Arc::ptr_eq(&current, &handle.snapshot()),
    "a failed candidate must not replace the published snapshot"
  );
}
