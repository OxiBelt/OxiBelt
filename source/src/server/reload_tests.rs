use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::*;
use crate::config::Config;
use crate::state::{AppHandle, AppSnapshot};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[tokio::test]
async fn same_listener_reload_drains_keepalive_and_new_connections_use_new_snapshot() {
  let temp_dir = common::TempDir::new("plain-http-same-listener-drain");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-http-same-listener-drain");
  let http_bind = unused_loopback_port().await;
  let https_bind = unused_loopback_port().await;
  let (old_upstream_addr, old_upstream_task) = start_path_echo_http_upstream(1).await;
  let (new_upstream_addr, new_upstream_task) = start_path_echo_http_upstream(1).await;
  let initial_config = plain_http_listener_config(
    &cert_path,
    &key_path,
    https_bind,
    http_bind,
    old_upstream_addr,
  );
  let state = AppHandle::new(
    AppSnapshot::new(initial_config)
      .await
      .expect("initial snapshot should initialize"),
  );
  let (error_tx, _error_rx) = mpsc::unbounded_channel();
  let mut supervisor = ListenerSupervisor::start(state.clone(), error_tx, test_admin_control())
    .await
    .expect("listener supervisor should start");

  let mut keepalive = TcpStream::connect(http_bind)
    .await
    .expect("keep-alive client should connect");
  write_raw_http_request(&mut keepalive, "/before", "keep-alive")
    .await
    .expect("keep-alive request should write");
  let old_response = read_http_until_contains(&mut keepalive, "path=/origin/before")
    .await
    .expect("old generation response should read");
  assert!(
    old_response.starts_with("HTTP/1.1 200 OK"),
    "old generation should serve first keep-alive request: {}",
    log_safe_test_text(&old_response)
  );

  let active = state.snapshot();
  let mut reloaded_config = plain_http_listener_config(
    &cert_path,
    &key_path,
    https_bind,
    http_bind,
    new_upstream_addr,
  );
  reloaded_config.upstreams[0].origin =
    url::Url::parse(&format!("http://{new_upstream_addr}/reloaded"))
      .expect("test upstream URL should parse");
  let reloaded = AppSnapshot::new_with_previous(reloaded_config, Some(active.as_ref()))
    .await
    .expect("same-listener reloaded snapshot should initialize");
  let pending = supervisor
    .prepare(&reloaded)
    .await
    .expect("same listener reload should prepare");
  state.replace(reloaded);
  let active = state.snapshot();
  supervisor.commit(pending, active.as_ref(), state.clone());

  assert_stream_closes(keepalive).await;

  let new_response = raw_http_response(http_bind, "/after")
    .await
    .expect("same listener should serve new connection after reload");
  assert!(
    new_response.starts_with("HTTP/1.1 200 OK") && new_response.contains("path=/reloaded/after"),
    "new connection should use reloaded snapshot: {}",
    log_safe_test_text(&new_response)
  );

  supervisor.shutdown(state.snapshot().as_ref()).await;
  old_upstream_task
    .await
    .expect("old path echo upstream task should not panic");
  new_upstream_task
    .await
    .expect("new path echo upstream task should not panic");
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

async fn start_path_echo_http_upstream(request_count: usize) -> (SocketAddr, JoinHandle<()>) {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("path echo upstream should bind");
  let addr = listener
    .local_addr()
    .expect("path echo upstream address should be available");
  let task = tokio::spawn(async move {
    for _ in 0..request_count {
      let (mut stream, _) = listener
        .accept()
        .await
        .expect("path echo upstream should accept connection");
      let request_head = read_http_request_head(&mut stream)
        .await
        .expect("path echo upstream should read request headers");
      let path = request_head.split_whitespace().nth(1).unwrap_or("/");
      let body = format!("path={path}");
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
        .expect("path echo upstream should write response");
    }
  });
  (addr, task)
}

async fn read_http_request_head(stream: &mut TcpStream) -> std::io::Result<String> {
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
      return Ok(String::from_utf8_lossy(&buffer).into_owned());
    }
  }
}

async fn raw_http_response(addr: SocketAddr, path: &str) -> std::io::Result<String> {
  let mut stream = TcpStream::connect(addr).await?;
  write_raw_http_request(&mut stream, path, "close").await?;
  let mut response = Vec::new();
  tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP response timed out"))??;
  Ok(String::from_utf8_lossy(&response).into_owned())
}

async fn write_raw_http_request(
  stream: &mut TcpStream,
  path: &str,
  connection: &str,
) -> std::io::Result<()> {
  let request = format!(
    "GET {path} HTTP/1.1\r\n\
     Host: example.com\r\n\
     Content-Length: 0\r\n\
     Connection: {connection}\r\n\
     \r\n"
  );
  stream.write_all(request.as_bytes()).await
}

async fn read_http_until_contains(stream: &mut TcpStream, needle: &str) -> std::io::Result<String> {
  tokio::time::timeout(Duration::from_secs(3), async {
    let mut response = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
      let read = stream.read(&mut chunk).await?;
      if read == 0 {
        break;
      }
      response.extend_from_slice(&chunk[..read]);
      if String::from_utf8_lossy(&response).contains(needle) {
        break;
      }
    }
    Ok::<_, std::io::Error>(String::from_utf8_lossy(&response).into_owned())
  })
  .await
  .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP response timed out"))?
}

async fn assert_stream_closes(mut stream: TcpStream) {
  let mut byte = [0u8; 1];
  match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await {
    Ok(Ok(0)) => {}
    Ok(Ok(read)) => panic!("expected old keep-alive stream to close, read {read} bytes"),
    Ok(Err(error)) => panic!("failed to read old keep-alive stream close: {error}"),
    Err(_) => panic!("old keep-alive stream stayed open after reload drain"),
  }
}

fn parse_test_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

async fn unused_loopback_port() -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("ephemeral port should bind");
  listener
    .local_addr()
    .expect("ephemeral address should be available")
}

fn log_safe_test_text(input: &str) -> String {
  input.replace('\n', "\\n").replace('\r', "\\r")
}
