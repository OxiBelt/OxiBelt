use std::net::SocketAddr;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::config::Config;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

const ADMIN_TOKEN_ENV: &str = "PATH";

#[tokio::test]
async fn cache_warm_prefer_async_returns_operation_and_poll_succeeds() {
  let (addr, shutdown, task) = start_admin().await;
  let response = create_cache_warm_operation(addr, true).await;
  let lower = response.to_ascii_lowercase();
  assert!(
    response.starts_with("HTTP/1.1 202 Accepted")
      && lower.contains("preference-applied: respond-async")
      && lower.contains("operation-location: /admin/v1/operations/op_"),
    "async cache warm should be accepted: {}",
    log_safe_text(&response)
  );
  let id = operation_id_from_response(&response);
  assert!(id.starts_with("op_"));
  assert_eq!(id.len(), 39);

  let polled = poll_operation(addr, &id).await;
  assert!(
    polled.contains(r#""state":"succeeded""#) && polled.contains(r#""result""#),
    "operation should finish successfully: {}",
    log_safe_text(&polled)
  );
  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn operation_events_stream_sse_and_ndjson_history() {
  let (addr, shutdown, task) = start_admin().await;
  let id = operation_id_from_response(&create_cache_warm_operation(addr, true).await);
  let _ = poll_operation(addr, &id).await;

  let sse = admin_request(
    addr,
    "GET",
    &format!("/admin/v1/operations/{id}/events"),
    "",
    &[],
  )
  .await;
  assert!(
    sse.starts_with("HTTP/1.1 200 OK")
      && sse.contains("content-type: text/event-stream")
      && sse.contains("event: operation.result"),
    "SSE event history should replay terminal event: {}",
    log_safe_text(&sse)
  );

  let ndjson = admin_request(
    addr,
    "GET",
    &format!("/admin/v1/operations/{id}/events?format=ndjson"),
    "",
    &[],
  )
  .await;
  assert!(
    ndjson.starts_with("HTTP/1.1 200 OK")
      && ndjson.contains("content-type: application/x-ndjson")
      && ndjson.contains(r#""event":"operation.result""#),
    "NDJSON event history should replay terminal event: {}",
    log_safe_text(&ndjson)
  );

  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn operation_events_websocket_replays_json_frames() {
  let (addr, shutdown, task) = start_admin().await;
  let id = operation_id_from_response(&create_cache_warm_operation(addr, true).await);
  let _ = poll_operation(addr, &id).await;

  let response = websocket_operation_events(addr, &id).await;
  assert!(
    response.starts_with("HTTP/1.1 101 Switching Protocols")
      && response.contains(r#""event":"operation.result""#),
    "WebSocket event stream should replay terminal event: {}",
    log_safe_text(&response)
  );

  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn operation_events_websocket_rejects_malformed_handshakes() {
  let (addr, shutdown, task) = start_admin().await;
  let id = operation_id_from_response(&create_cache_warm_operation(addr, true).await);
  let _ = poll_operation(addr, &id).await;

  for (name, headers) in [
    (
      "missing Upgrade",
      vec![
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
      ],
    ),
    (
      "missing Connection upgrade",
      vec![
        "Upgrade: websocket\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
      ],
    ),
    (
      "invalid key",
      vec![
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Key: not-base64\r\n",
      ],
    ),
    (
      "short key",
      vec![
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Key: c2hvcnQ=\r\n",
      ],
    ),
  ] {
    let response = admin_request(
      addr,
      "GET",
      &format!("/admin/v1/operations/{id}/events/ws"),
      "",
      &headers,
    )
    .await;
    assert!(
      response.starts_with("HTTP/1.1 400 Bad Request"),
      "{name} should be rejected: {}",
      log_safe_text(&response)
    );
  }

  let _ = shutdown.send(true);
  task.abort();
}

async fn start_admin() -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
  let temp_dir = common::TempDir::new("admin-operations");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "admin-operations");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = admin_listener_config(&cert_path, &key_path, addr);
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let state = AppHandle::new(snapshot);
  let (shutdown, shutdown_rx) = watch::channel(false);
  let task = tokio::spawn(async move {
    let _ = serve_admin_listener(
      listener,
      addr,
      state,
      test_admin_control(),
      test_admin_operations(),
      shutdown_rx,
    )
    .await;
  });
  (addr, shutdown, task)
}

fn admin_listener_config(cert_path: &Path, key_path: &Path, admin_bind: SocketAddr) -> Config {
  let mut raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      "https_bind = \"127.0.0.1:0\"",
    );
  raw.push_str(&format!(
    r#"

[cache]
enabled = true
store = "memory"
cache_methods = ["GET"]

[admin]
enabled = true
bind = "{admin_bind}"
bearer_token_env = "{ADMIN_TOKEN_ENV}"
transport = "plaintext_allowlist"
"#
  ));
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

async fn create_cache_warm_operation(addr: SocketAddr, prefer_async: bool) -> String {
  let prefer = if prefer_async {
    "Prefer: respond-async\r\n"
  } else {
    ""
  };
  admin_request(
    addr,
    "POST",
    "/admin/v1/cache/warm",
    r#"{"items":[{"scheme":"http","host":"example.com","uri":"relative"}]}"#,
    &[prefer],
  )
  .await
}

async fn poll_operation(addr: SocketAddr, id: &str) -> String {
  for _ in 0..50 {
    let response = admin_request(addr, "GET", &format!("/admin/v1/operations/{id}"), "", &[]).await;
    if response.contains(r#""state":"succeeded""#)
      || response.contains(r#""state":"failed""#)
      || response.contains(r#""state":"cancelled""#)
    {
      return response;
    }
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
  }
  admin_request(addr, "GET", &format!("/admin/v1/operations/{id}"), "", &[]).await
}

async fn admin_request(
  addr: SocketAddr,
  method: &str,
  path: &str,
  body: &str,
  extra_headers: &[&str],
) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let extra = extra_headers.join("");
  let request = format!(
    "{method} {path} HTTP/1.1\r\n\
     Host: admin\r\n\
     Authorization: Bearer {token}\r\n\
     {extra}\
     Content-Type: application/json\r\n\
     Content-Length: {}\r\n\
     Connection: close\r\n\
     \r\n\
     {body}",
    body.len()
  );
  stream
    .write_all(request.as_bytes())
    .await
    .expect("admin request should write");
  read_response(stream).await
}

async fn websocket_operation_events(addr: SocketAddr, id: &str) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin WebSocket connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let request = format!(
    "GET /admin/v1/operations/{id}/events/ws HTTP/1.1\r\n\
     Host: admin\r\n\
     Authorization: Bearer {token}\r\n\
     Upgrade: websocket\r\n\
     Connection: Upgrade\r\n\
     Sec-WebSocket-Version: 13\r\n\
     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
     \r\n"
  );
  stream
    .write_all(request.as_bytes())
    .await
    .expect("admin WebSocket request should write");
  read_response(stream).await
}

async fn read_response(mut stream: TcpStream) -> String {
  let mut response = Vec::new();
  tokio::time::timeout(
    std::time::Duration::from_secs(2),
    stream.read_to_end(&mut response),
  )
  .await
  .expect("admin response should not time out")
  .expect("admin response should read");
  String::from_utf8_lossy(&response).into_owned()
}

fn operation_id_from_response(response: &str) -> String {
  let body = response.split("\r\n\r\n").nth(1).unwrap_or("");
  serde_json::from_str::<serde_json::Value>(body)
    .expect("operation response body should be JSON")
    .get("id")
    .and_then(|value| value.as_str())
    .expect("operation response should include id")
    .to_string()
}

fn log_safe_text(input: &str) -> String {
  input.replace('\n', "\\n").replace('\r', "\\r")
}
