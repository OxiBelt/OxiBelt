//! Listener lifecycle and TLS fingerprint characterization.

use super::*;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use std::path::Path;
use std::time::Instant;

use crate::config::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADMIN_TOKEN_ENV: &str = "PATH";

#[tokio::test]
async fn admin_listener_disabled_config_does_not_serve_stale_requests() {
  let temp_dir = common::TempDir::new("admin-listener-disabled");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-listener-disabled");
  let config = admin_listener_config(&cert_path, &key_path, false, None);
  let state = AppHandle::new(
    AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize"),
  );
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let (shutdown, shutdown_rx) = watch::channel(false);
  let task = tokio::spawn(serve_admin_listener(
    listener,
    addr,
    state,
    test_admin_control(),
    test_admin_operations(),
    shutdown_rx,
  ));

  match admin_purge_response(addr).await {
    Ok(response) => assert!(
      !response.contains("purged="),
      "disabled admin listener must not serve purge requests: {}",
      log_safe_test_text(&response)
    ),
    Err(error)
      if matches!(
        error.kind(),
        std::io::ErrorKind::BrokenPipe
          | std::io::ErrorKind::ConnectionReset
          | std::io::ErrorKind::UnexpectedEof
      ) => {}
    Err(error) => panic!(
      "unexpected stale admin connection error kind: {:?}",
      error.kind()
    ),
  }
  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn admin_listener_supervisor_rebinds_admin_port_on_reload() {
  let temp_dir = common::TempDir::new("admin-listener-rebind");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-listener-rebind");
  let (old_admin, new_admin) = unused_loopback_ports().await;
  let initial_config = admin_listener_config(&cert_path, &key_path, true, Some(old_admin));
  let state = AppHandle::new(
    AppSnapshot::new(initial_config)
      .await
      .expect("initial snapshot should initialize"),
  );
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut supervisor = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    test_admin_control(),
    test_admin_operations(),
  )
  .await
  .expect("listener supervisor should start");

  let response = admin_purge_response_with_retry(old_admin).await;
  assert!(
    response.starts_with("HTTP/1.1 200 OK"),
    "old admin listener should serve before reload: {}",
    log_safe_test_text(&response)
  );
  let mut stale_connection = TcpStream::connect(old_admin)
    .await
    .expect("stale admin connection should open before reload");
  write_admin_purge_request_headers(&mut stale_connection)
    .await
    .expect("stale admin request headers should write before reload");
  tokio::time::sleep(Duration::from_millis(50)).await;

  let active = state.snapshot();
  let reloaded_config = admin_listener_config(&cert_path, &key_path, true, Some(new_admin));
  let reloaded = AppSnapshot::new_with_previous(reloaded_config, Some(active.as_ref()))
    .await
    .expect("reloaded snapshot should initialize");
  let pending = supervisor
    .prepare(&reloaded)
    .await
    .expect("admin rebind should prepare");
  state.replace(reloaded);
  let active = state.snapshot();
  supervisor.commit(pending, active.as_ref(), state.clone());

  let response = admin_purge_response_with_retry(new_admin).await;
  assert!(
    response.starts_with("HTTP/1.1 200 OK"),
    "new admin listener should serve after reload: {}",
    log_safe_test_text(&response)
  );
  let stale_response = finish_admin_purge_response_on_stream(stale_connection)
    .await
    .expect("stale admin connection should receive a response after rebind");
  assert!(
    stale_response.starts_with("HTTP/1.1 404 Not Found"),
    "stale admin connection should stop serving after rebind: {}",
    log_safe_test_text(&stale_response)
  );
  assert_tcp_connect_fails(old_admin).await;
}

#[tokio::test]
async fn admin_listener_supervisor_stops_admin_port_when_disabled() {
  let temp_dir = common::TempDir::new("admin-listener-disable-reload");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-listener-disable-reload");
  let admin_addr = unused_loopback_port().await;
  let initial_config = admin_listener_config(&cert_path, &key_path, true, Some(admin_addr));
  let state = AppHandle::new(
    AppSnapshot::new(initial_config)
      .await
      .expect("initial snapshot should initialize"),
  );
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut supervisor = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    test_admin_control(),
    test_admin_operations(),
  )
  .await
  .expect("listener supervisor should start");

  let response = admin_purge_response_with_retry(admin_addr).await;
  assert!(
    response.starts_with("HTTP/1.1 200 OK"),
    "admin listener should serve before disable reload: {}",
    log_safe_test_text(&response)
  );

  let active = state.snapshot();
  let disabled_config = admin_listener_config(&cert_path, &key_path, false, Some(admin_addr));
  let reloaded = AppSnapshot::new_with_previous(disabled_config, Some(active.as_ref()))
    .await
    .expect("disabled snapshot should initialize");
  let pending = supervisor
    .prepare(&reloaded)
    .await
    .expect("admin disable should prepare");
  state.replace(reloaded);
  let active = state.snapshot();
  supervisor.commit(pending, active.as_ref(), state.clone());

  assert_tcp_connect_fails(admin_addr).await;
}

#[tokio::test]
async fn listener_supervisor_rebind_drains_delayed_plain_http_request() {
  let temp_dir = common::TempDir::new("plain-http-drain-rebind");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-http-drain-rebind");
  let (old_http, new_http) = unused_loopback_ports().await;
  let https_bind = unused_loopback_port().await;
  let (upstream_addr, upstream_task, first_upstream_request) =
    start_delayed_http_upstream(Duration::from_millis(200), 2).await;
  let initial_config =
    plain_http_listener_config(&cert_path, &key_path, https_bind, old_http, upstream_addr);
  let state = AppHandle::new(
    AppSnapshot::new(initial_config)
      .await
      .expect("initial snapshot should initialize"),
  );
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut supervisor = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    test_admin_control(),
    test_admin_operations(),
  )
  .await
  .expect("listener supervisor should start");

  let held_request = tokio::spawn(raw_http_response(old_http, "/slow"));
  tokio::time::timeout(Duration::from_secs(2), first_upstream_request)
    .await
    .expect("upstream should receive held request before reload")
    .expect("upstream signal should be sent");

  let active = state.snapshot();
  let reloaded_config =
    plain_http_listener_config(&cert_path, &key_path, https_bind, new_http, upstream_addr);
  let reloaded = AppSnapshot::new_with_previous(reloaded_config, Some(active.as_ref()))
    .await
    .expect("reloaded snapshot should initialize");
  let pending = supervisor
    .prepare(&reloaded)
    .await
    .expect("plain HTTP rebind should prepare");
  state.replace(reloaded);
  let active = state.snapshot();
  supervisor.commit(pending, active.as_ref(), state.clone());

  let held_response = held_request
    .await
    .expect("held request task should not panic")
    .expect("held request should finish across listener drain");
  assert!(
    held_response.starts_with("HTTP/1.1 200 OK") && held_response.contains("delayed-0"),
    "held request should complete on old listener generation: {}",
    log_safe_test_text(&held_response)
  );
  assert_tcp_connect_fails(old_http).await;

  let new_response = raw_http_response(new_http, "/after")
    .await
    .expect("new listener should serve after reload");
  assert!(
    new_response.starts_with("HTTP/1.1 200 OK") && new_response.contains("delayed-1"),
    "new listener generation should serve after reload: {}",
    log_safe_test_text(&new_response)
  );

  supervisor.shutdown(state.snapshot().as_ref()).await;
  upstream_task
    .await
    .expect("delayed upstream task should not panic");
}

fn admin_listener_config(
  cert_path: &Path,
  key_path: &Path,
  enabled: bool,
  admin_bind: Option<SocketAddr>,
) -> Config {
  let mut raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      "https_bind = \"127.0.0.1:0\"",
    );
  raw.push_str(&format!(
    r#"

[admin]
enabled = {enabled}
bearer_token_env = "{ADMIN_TOKEN_ENV}"
transport = "plaintext_allowlist"
"#
  ));
  if let Some(admin_bind) = admin_bind {
    raw.push_str(&format!("bind = \"{admin_bind}\"\n"));
  }
  parse_test_config(&raw)
}

fn plain_http_listener_config(
  cert_path: &Path,
  key_path: &Path,
  https_bind: SocketAddr,
  http_bind: SocketAddr,
  upstream_addr: SocketAddr,
) -> Config {
  let mut raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      &format!("https_bind = \"{https_bind}\"\nhttp_bind = \"{http_bind}\"\nhttp_mode = \"proxy\""),
    )
    .replace(
      "origin = \"https://app.internal.example\"",
      &format!("origin = \"http://{upstream_addr}/origin\""),
    )
    .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"");
  raw.push_str(
    r#"

[runtime.drain]
graceful_timeout_ms = 1000
long_connection_close_delay_ms = 1000
shutdown_delay_ms = 0
"#,
  );
  parse_test_config(&raw)
}

async fn start_delayed_http_upstream(
  response_delay: Duration,
  request_count: usize,
) -> (
  SocketAddr,
  JoinHandle<()>,
  tokio::sync::oneshot::Receiver<()>,
) {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("delayed upstream should bind");
  let addr = listener
    .local_addr()
    .expect("delayed upstream address should be available");
  let (first_request_tx, first_request_rx) = tokio::sync::oneshot::channel();
  let task = tokio::spawn(async move {
    let mut first_request_tx = Some(first_request_tx);
    for index in 0..request_count {
      let (mut stream, _) = listener
        .accept()
        .await
        .expect("delayed upstream should accept connection");
      read_http_request_headers(&mut stream)
        .await
        .expect("delayed upstream should read request headers");
      if let Some(tx) = first_request_tx.take() {
        let _ = tx.send(());
      }
      tokio::time::sleep(response_delay).await;
      let body = format!("delayed-{index}");
      let response = format!(
        "HTTP/1.1 200 OK\r\n\
           Content-Type: text/plain\r\n\
           Content-Length: {}\r\n\
           Connection: close\r\n\
           \r\n\
           {body}",
        body.len()
      );
      stream
        .write_all(response.as_bytes())
        .await
        .expect("delayed upstream should write response");
    }
  });
  (addr, task, first_request_rx)
}

async fn read_http_request_headers(stream: &mut TcpStream) -> std::io::Result<()> {
  let mut buffer = Vec::new();
  let mut chunk = [0u8; 256];
  loop {
    let read = stream.read(&mut chunk).await?;
    if read == 0 {
      return Err(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "connection closed before request headers completed",
      ));
    }
    buffer.extend_from_slice(&chunk[..read]);
    if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
      return Ok(());
    }
  }
}

async fn raw_http_response(addr: SocketAddr, path: &str) -> std::io::Result<String> {
  let mut stream = TcpStream::connect(addr).await?;
  let request = format!(
    "GET {path} HTTP/1.1\r\n\
       Host: example.com\r\n\
       Content-Length: 0\r\n\
       Connection: close\r\n\
       \r\n"
  );
  stream.write_all(request.as_bytes()).await?;
  let mut response = Vec::new();
  tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP response timed out"))??;
  Ok(String::from_utf8_lossy(&response).into_owned())
}

fn parse_test_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

async fn unused_loopback_ports() -> (SocketAddr, SocketAddr) {
  let first = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("first ephemeral port should bind");
  let second = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("second ephemeral port should bind");
  let first_addr = first
    .local_addr()
    .expect("first ephemeral address should be available");
  let second_addr = second
    .local_addr()
    .expect("second ephemeral address should be available");
  (first_addr, second_addr)
}

async fn unused_loopback_port() -> SocketAddr {
  unused_loopback_ports().await.0
}

async fn admin_purge_response_with_retry(addr: SocketAddr) -> String {
  let deadline = Instant::now() + Duration::from_secs(2);
  loop {
    match admin_purge_response(addr).await {
      Ok(response) if response.starts_with("HTTP/1.1 200 OK") => return response,
      Ok(response) if Instant::now() >= deadline => {
        panic!(
          "admin listener did not return 200 before deadline: {}",
          log_safe_test_text(&response)
        )
      }
      Err(error) if Instant::now() >= deadline => {
        panic!(
          "admin listener did not become ready before deadline with error kind: {:?}",
          error.kind()
        )
      }
      Ok(_) | Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
    }
  }
}

async fn admin_purge_response(addr: SocketAddr) -> std::io::Result<String> {
  let stream = TcpStream::connect(addr).await?;
  admin_purge_response_on_stream(stream).await
}

async fn admin_purge_response_on_stream(mut stream: TcpStream) -> std::io::Result<String> {
  write_admin_purge_request_headers(&mut stream).await?;
  finish_admin_purge_response_on_stream(stream).await
}

async fn write_admin_purge_request_headers(stream: &mut TcpStream) -> std::io::Result<()> {
  let token = admin_test_token()?;
  let request_headers = format!(
    "POST /cache/purge?policy=default&scheme=http&host=example.com&uri=/ HTTP/1.1\r\n\
       Host: admin\r\n\
       Authorization: Bearer {token}\r\n\
       Content-Length: 0\r\n\
       Connection: close\r\n"
  );
  stream.write_all(request_headers.as_bytes()).await
}

async fn finish_admin_purge_response_on_stream(mut stream: TcpStream) -> std::io::Result<String> {
  stream.write_all(b"\r\n").await?;
  let mut response = Vec::new();
  let read = tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "admin response timed out"))??;
  let _ = read;
  Ok(String::from_utf8_lossy(&response).into_owned())
}

fn log_safe_test_text(input: &str) -> String {
  input.replace('\n', "\\n").replace('\r', "\\r")
}

#[test]
fn log_safe_test_text_escapes_line_breaks() {
  assert_eq!(
    log_safe_test_text("HTTP/1.1 500\r\nforged: true\nbody"),
    "HTTP/1.1 500\\r\\nforged: true\\nbody"
  );
}

fn admin_test_token() -> std::io::Result<String> {
  std::env::var(ADMIN_TOKEN_ENV).map_err(|error| {
    std::io::Error::new(
      std::io::ErrorKind::NotFound,
      format!("{ADMIN_TOKEN_ENV} is required for admin listener tests: {error}"),
    )
  })
}

async fn assert_tcp_connect_fails(addr: SocketAddr) {
  let deadline = Instant::now() + Duration::from_secs(2);
  loop {
    match tokio::time::timeout(Duration::from_millis(100), TcpStream::connect(addr)).await {
      Ok(Ok(stream)) => {
        drop(stream);
        if Instant::now() >= deadline {
          panic!("TCP listener at {addr} stayed reachable");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
      }
      Ok(Err(_)) | Err(_) => return,
    }
  }
}

#[test]
fn tls_fingerprint_payload_includes_client_hello_and_selected_tls_metadata() {
  let client_hello = ClientHelloFingerprintMetadata {
    cipher_suites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384".to_string(),
    key_exchange_groups: "X25519,X25519MLKEM768".to_string(),
    signature_schemes: "ECDSA_NISTP256_SHA256,RSA_PSS_SHA256".to_string(),
    data_integrity_groups: "SHA256,SHA384".to_string(),
  };

  let payload = tls_fingerprint_payload(
    &client_hello,
    Some("TLSv1_3"),
    Some("TLS_AES_128_GCM_SHA256"),
    Some("X25519MLKEM768"),
    Some("SHA256"),
    Some("example.com"),
    Some("h2"),
  );

  assert!(payload.starts_with("rustls-tcp-negotiated-v2\n"));
  assert!(
    payload.contains("client_hello_cipher_suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384")
  );
  assert!(payload.contains("client_hello_key_exchange_groups=X25519,X25519MLKEM768"));
  assert!(payload.contains("client_hello_signature_schemes=ECDSA_NISTP256_SHA256,RSA_PSS_SHA256"));
  assert!(payload.contains("client_hello_data_integrity_groups=SHA256,SHA384"));
  assert!(payload.contains("selected_cipher_suite=TLS_AES_128_GCM_SHA256"));
  assert!(payload.contains("selected_key_exchange_group=X25519MLKEM768"));
  assert!(payload.contains("selected_data_integrity_group=SHA256"));
}

#[test]
fn tls_fingerprint_changes_when_client_hello_or_selection_changes() {
  let client_hello = ClientHelloFingerprintMetadata {
    cipher_suites: "TLS_AES_128_GCM_SHA256".to_string(),
    key_exchange_groups: "X25519".to_string(),
    signature_schemes: "ECDSA_NISTP256_SHA256".to_string(),
    data_integrity_groups: "SHA256".to_string(),
  };
  let different_client_hello = ClientHelloFingerprintMetadata {
    cipher_suites: "TLS_AES_256_GCM_SHA384".to_string(),
    key_exchange_groups: "X25519".to_string(),
    signature_schemes: "ECDSA_NISTP256_SHA256".to_string(),
    data_integrity_groups: "SHA384".to_string(),
  };

  let base = tls_fingerprint(
    &client_hello,
    Some("TLSv1_3"),
    Some("TLS_AES_128_GCM_SHA256"),
    Some("X25519"),
    Some("SHA256"),
    Some("example.com"),
    Some("h2"),
  );
  let changed_client_hello = tls_fingerprint(
    &different_client_hello,
    Some("TLSv1_3"),
    Some("TLS_AES_128_GCM_SHA256"),
    Some("X25519"),
    Some("SHA256"),
    Some("example.com"),
    Some("h2"),
  );
  let changed_selection = tls_fingerprint(
    &client_hello,
    Some("TLSv1_3"),
    Some("TLS_AES_256_GCM_SHA384"),
    Some("X25519"),
    Some("SHA384"),
    Some("example.com"),
    Some("h2"),
  );

  assert_eq!(base.len(), 64);
  assert_ne!(base, changed_client_hello);
  assert_ne!(base, changed_selection);
}

#[test]
fn quic_tls_fingerprint_payload_uses_exposed_quic_scheme() {
  let payload = quic_tls_fingerprint_payload(QuicTlsFingerprintInput {
    version: Some("TLSv1_3"),
    cipher_suite: None,
    key_exchange_group: None,
    data_integrity_group: None,
    sni: Some("example.com"),
    alpn: Some("h3"),
  });

  assert!(payload.starts_with("quinn-rustls-quic-v2\n"));
  assert!(payload.contains("selected_version=TLSv1_3"));
  assert!(payload.contains("selected_cipher_suite="));
  assert!(payload.contains("selected_key_exchange_group="));
  assert!(payload.contains("selected_data_integrity_group="));
  assert!(payload.contains("sni=example.com"));
  assert!(payload.contains("alpn=h3"));
  assert!(payload.contains("metadata_source=quinn-rustls-handshake-data"));
}

#[test]
fn quic_tls_fingerprint_changes_when_exposed_handshake_metadata_changes() {
  let base = quic_tls_fingerprint(QuicTlsFingerprintInput {
    version: Some("TLSv1_3"),
    cipher_suite: None,
    key_exchange_group: None,
    data_integrity_group: None,
    sni: Some("example.com"),
    alpn: Some("h3"),
  });
  let changed_sni = quic_tls_fingerprint(QuicTlsFingerprintInput {
    version: Some("TLSv1_3"),
    cipher_suite: None,
    key_exchange_group: None,
    data_integrity_group: None,
    sni: Some("alt.example.com"),
    alpn: Some("h3"),
  });
  let changed_alpn = quic_tls_fingerprint(QuicTlsFingerprintInput {
    version: Some("TLSv1_3"),
    cipher_suite: None,
    key_exchange_group: None,
    data_integrity_group: None,
    sni: Some("example.com"),
    alpn: Some("h3-29"),
  });

  assert_eq!(base.len(), 64);
  assert_ne!(base, changed_sni);
  assert_ne!(base, changed_alpn);
}

#[test]
fn cipher_suite_data_integrity_groups_are_deduplicated_in_order() {
  let groups = unique_nonempty(
    [
      "TLS_AES_128_GCM_SHA256",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_AES_256_GCM_SHA384",
    ]
    .iter()
    .filter_map(|suite| cipher_suite_data_integrity_group(suite))
    .map(str::to_string),
  );

  assert_eq!(groups, vec!["SHA256".to_string(), "SHA384".to_string()]);
}
