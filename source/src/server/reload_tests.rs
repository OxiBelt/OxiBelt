use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::*;
use crate::config::{
  Config, RuntimeOverrides, SharedStateConfig, StreamListenerConfig, StreamNetwork, UdpFlowState,
};
use crate::listener_socket::TcpListenOptions;
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::shared_state::SharedState;
use crate::state::{AppHandle, AppSnapshot};
use crate::stream::StreamListenerGeneration;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[test]
fn shared_required_udp_listener_generation_tracks_runtime_identity() {
  let config = test_stream_listener(StreamNetwork::Udp, UdpFlowState::SharedRequired);
  let options = test_stream_listener_options();
  let shared_config = SharedStateConfig::default();
  let initial_runtime = SharedState::test_memory("listener-generation");
  let replacement_runtime = SharedState::test_memory("listener-generation");
  let initial = StreamListenerGeneration::new(
    config.clone(),
    options,
    shared_config.clone(),
    Some(initial_runtime.clone()),
  )
  .expect("initial shared-required generation should build");
  let unchanged = StreamListenerGeneration::new(
    config.clone(),
    options,
    shared_config.clone(),
    Some(initial_runtime),
  )
  .expect("unchanged shared-required generation should build");
  let replacement = StreamListenerGeneration::new(
    config.clone(),
    options,
    shared_config.clone(),
    Some(replacement_runtime),
  )
  .expect("replacement shared-required generation should build");

  assert!(
    initial == unchanged,
    "the same shared-state runtime must retain the listener generation"
  );
  assert!(
    initial != replacement,
    "a replacement shared-state runtime must replace the listener generation"
  );
  assert!(
    StreamListenerGeneration::new(config, options, shared_config, None).is_err(),
    "shared-required UDP must fail closed without an active shared-state runtime"
  );
}

#[test]
fn local_udp_and_tcp_listener_generations_ignore_runtime_identity() {
  let options = test_stream_listener_options();
  let shared_config = SharedStateConfig::default();
  let initial_runtime = SharedState::test_memory("listener-generation");
  let replacement_runtime = SharedState::test_memory("listener-generation");
  for config in [
    test_stream_listener(StreamNetwork::Udp, UdpFlowState::Local),
    test_stream_listener(StreamNetwork::Tcp, UdpFlowState::Local),
  ] {
    let initial = StreamListenerGeneration::new(
      config.clone(),
      options,
      shared_config.clone(),
      Some(initial_runtime.clone()),
    )
    .expect("non-durable listener generation should build");
    let replacement = StreamListenerGeneration::new(
      config,
      options,
      shared_config.clone(),
      Some(replacement_runtime.clone()),
    )
    .expect("non-durable listener replacement generation should build");
    assert!(
      initial == replacement,
      "non-durable listener keys must ignore shared runtime identity changes"
    );
  }
}

#[test]
fn stream_listener_generation_preserves_serialized_config_matching() {
  let config = test_stream_listener(StreamNetwork::Udp, UdpFlowState::Local);
  let options = test_stream_listener_options();
  let initial =
    StreamListenerGeneration::new(config.clone(), options, SharedStateConfig::default(), None)
      .expect("initial local generation should build");
  let mut changed_shared_config = SharedStateConfig::default();
  changed_shared_config.enabled = true;
  let changed = StreamListenerGeneration::new(config, options, changed_shared_config, None)
    .expect("changed local generation should build");
  assert!(
    initial != changed,
    "serialized shared-state config changes must preserve existing listener replacement behavior"
  );
}

#[tokio::test]
async fn torn_full_reload_keeps_active_generation_then_complete_candidate_recovers() {
  let temp_dir = common::TempDir::new("torn-full-reload");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("reload config directory should be created");
  std::fs::create_dir_all(&cert_dir).expect("reload certificate directory should be created");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "torn-full-reload");
  let config_path = config_dir.join("oxibelt.toml");
  let http_bind = unused_loopback_port().await;
  let https_bind = unused_loopback_port().await;
  let (old_upstream_addr, old_request_seen, release_old_request, old_upstream_task) =
    start_gated_path_echo_http_upstream().await;
  let (new_upstream_addr, new_upstream_task) = start_path_echo_http_upstream(1).await;
  let initial_raw = full_reload_config(
    &cert_path,
    &key_path,
    https_bind,
    http_bind,
    old_upstream_addr,
  );
  std::fs::write(&config_path, &initial_raw).expect("initial reload config should write");
  let initial_config = Config::load(&config_path).expect("initial reload config should load");
  initial_config
    .validate()
    .expect("initial reload config should validate");
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
  let mut reload = ReloadManager::new(
    config_path.clone(),
    RuntimeOverrides::default(),
    state.snapshot().as_ref(),
  )
  .expect("reload manager should initialize");

  let held_client = tokio::spawn(raw_http_response(http_bind, "/held"));
  tokio::time::timeout(Duration::from_secs(3), old_request_seen)
    .await
    .expect("old upstream request observation should not time out")
    .expect("old upstream should observe the held request");

  let original = state.snapshot();
  std::fs::write(&config_path, "[runtime\nhot_reload = ")
    .expect("torn reload candidate should write");
  reload
    .reload_if_changed(ReloadTrigger::Signal, &state, &mut supervisor)
    .await;
  let after_torn = state.snapshot();
  assert!(
    Arc::ptr_eq(&original, &after_torn),
    "an invalid candidate must not publish a new generation"
  );

  let replacement_raw = full_reload_config(
    &cert_path,
    &key_path,
    https_bind,
    http_bind,
    new_upstream_addr,
  );
  std::fs::write(&config_path, replacement_raw).expect("complete reload candidate should write");
  reload
    .reload_if_changed(ReloadTrigger::Signal, &state, &mut supervisor)
    .await;
  let replacement = state.snapshot();
  assert!(
    !Arc::ptr_eq(&original, &replacement),
    "a complete candidate should publish a new generation"
  );
  assert_eq!(
    replacement.config.upstreams[0].origin.host_str(),
    Some("127.0.0.1")
  );
  assert_eq!(
    replacement.config.upstreams[0].origin.port(),
    Some(new_upstream_addr.port())
  );

  release_old_request
    .send(())
    .expect("held old-generation request should still be waiting");
  let old_response = held_client
    .await
    .expect("held client task should not panic")
    .expect("held old-generation response should complete");
  assert!(
    old_response.contains("path=/origin/held"),
    "held request should finish on the captured old generation: {}",
    log_safe_test_text(&old_response)
  );
  let new_response = raw_http_response(http_bind, "/fresh")
    .await
    .expect("fresh request should use the recovered generation");
  assert!(
    new_response.contains("path=/origin/fresh"),
    "fresh request should finish on the recovered generation: {}",
    log_safe_test_text(&new_response)
  );

  supervisor.shutdown(state.snapshot().as_ref()).await;
  old_upstream_task
    .await
    .expect("old gated upstream task should not panic");
  new_upstream_task
    .await
    .expect("new path echo upstream task should not panic");
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
  let mut supervisor = ListenerSupervisor::start(
    state.clone(),
    error_tx,
    test_admin_control(),
    test_admin_operations(),
  )
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

#[tokio::test]
async fn listener_reload_adds_plain_http_bind_without_rebinding_existing_listener() {
  let temp_dir = common::TempDir::new("plain-http-add-bind");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-http-add-bind");
  let https_bind = unused_loopback_port().await;
  let first_http = unused_loopback_port().await;
  let second_http = unused_loopback_port().await;
  let (upstream_addr, upstream_task) = start_path_echo_http_upstream(3).await;
  let initial_config = plain_http_listener_config_with_http_binds(
    &cert_path,
    &key_path,
    https_bind,
    &[first_http],
    upstream_addr,
  );
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

  let initial_response = raw_http_response(first_http, "/before")
    .await
    .expect("first plain HTTP bind should serve before reload");
  assert!(
    initial_response.starts_with("HTTP/1.1 200 OK")
      && initial_response.contains("path=/origin/before"),
    "first bind should serve before reload: {}",
    log_safe_test_text(&initial_response)
  );

  let active = state.snapshot();
  let reloaded_config = plain_http_listener_config_with_http_binds(
    &cert_path,
    &key_path,
    https_bind,
    &[first_http, second_http],
    upstream_addr,
  );
  let reloaded = AppSnapshot::new_with_previous(reloaded_config, Some(active.as_ref()))
    .await
    .expect("additional-bind snapshot should initialize");
  let pending = supervisor
    .prepare(&reloaded)
    .await
    .expect("adding a listener bind should not rebind the existing address");
  state.replace(reloaded);
  let active = state.snapshot();
  supervisor.commit(pending, active.as_ref(), state.clone());

  let retained_response = raw_http_response(first_http, "/after-retained")
    .await
    .expect("retained plain HTTP bind should serve after reload");
  assert!(
    retained_response.starts_with("HTTP/1.1 200 OK")
      && retained_response.contains("path=/origin/after-retained"),
    "retained bind should serve after reload: {}",
    log_safe_test_text(&retained_response)
  );
  let added_response = raw_http_response(second_http, "/after-added")
    .await
    .expect("added plain HTTP bind should serve after reload");
  assert!(
    added_response.starts_with("HTTP/1.1 200 OK")
      && added_response.contains("path=/origin/after-added"),
    "added bind should serve after reload: {}",
    log_safe_test_text(&added_response)
  );

  supervisor.shutdown(state.snapshot().as_ref()).await;
  upstream_task
    .await
    .expect("path echo upstream task should not panic");
}

fn test_stream_listener(
  network: StreamNetwork,
  udp_flow_state: UdpFlowState,
) -> StreamListenerConfig {
  let network = match network {
    StreamNetwork::Tcp => "tcp",
    StreamNetwork::Udp => "udp",
  };
  let udp_flow_state = match udp_flow_state {
    UdpFlowState::Local => "local",
    UdpFlowState::SharedRequired => "shared_required",
  };
  toml::from_str(&format!(
    "name = \"generation-test\"\nnetwork = \"{network}\"\nbind = \"127.0.0.1:0\"\nudp_flow_state = \"{udp_flow_state}\"\n"
  ))
  .expect("test stream listener should parse")
}

fn test_stream_listener_options() -> TcpListenOptions {
  TcpListenOptions {
    workers: 1,
    reuse_port: false,
    backlog: 16,
  }
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

fn plain_http_listener_config_with_http_binds(
  cert_path: &Path,
  key_path: &Path,
  https_bind: SocketAddr,
  http_binds: &[SocketAddr],
  upstream_addr: SocketAddr,
) -> Config {
  let http_binds = http_binds
    .iter()
    .map(|bind| format!("\"{bind}\""))
    .collect::<Vec<_>>()
    .join(", ");
  let mut raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      &format!("https_bind = \"{https_bind}\"\nhttp_binds = [{http_binds}]\nhttp_mode = \"proxy\""),
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

fn full_reload_config(
  cert_path: &Path,
  key_path: &Path,
  https_bind: SocketAddr,
  http_bind: SocketAddr,
  upstream_addr: SocketAddr,
) -> String {
  let cert_name = cert_path
    .file_name()
    .and_then(|name| name.to_str())
    .expect("test certificate filename should be UTF-8");
  let key_name = key_path
    .file_name()
    .and_then(|name| name.to_str())
    .expect("test private-key filename should be UTF-8");
  let mut raw = common::minimal_config_toml_with_paths(cert_name, key_name)
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

[runtime.hot_reload]
mode = "full"
poll_interval_ms = 60000

[runtime.drain]
graceful_timeout_ms = 1000
long_connection_close_delay_ms = 1000
shutdown_delay_ms = 0
"#,
  );
  raw
}

async fn start_gated_path_echo_http_upstream() -> (
  SocketAddr,
  oneshot::Receiver<()>,
  oneshot::Sender<()>,
  JoinHandle<()>,
) {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("gated path echo upstream should bind");
  let addr = listener
    .local_addr()
    .expect("gated path echo upstream address should be available");
  let (seen_tx, seen_rx) = oneshot::channel();
  let (release_tx, release_rx) = oneshot::channel();
  let task = tokio::spawn(async move {
    let (mut stream, _) = listener
      .accept()
      .await
      .expect("gated path echo upstream should accept connection");
    let request_head = read_http_request_head(&mut stream)
      .await
      .expect("gated path echo upstream should read request headers");
    let path = request_head.split_whitespace().nth(1).unwrap_or("/");
    seen_tx
      .send(())
      .expect("reload test should wait for upstream observation");
    release_rx
      .await
      .expect("reload test should release gated upstream response");
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
      .expect("gated path echo upstream should write response");
  });
  (addr, seen_rx, release_tx, task)
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
