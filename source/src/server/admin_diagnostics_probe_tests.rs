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
async fn diagnostics_preflight_get_external_probe_uses_query_options() {
  let temp_dir = common::TempDir::new("admin-diagnostics-read-probe");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-diagnostics-read-probe");
  let admin_listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let admin_addr = admin_listener
    .local_addr()
    .expect("admin listener address should be available");
  let probe_listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("probe listener should bind");
  let probe_addr = probe_listener
    .local_addr()
    .expect("probe listener address should be available");
  let config = admin_preflight_probe_config(&cert_path, &key_path, admin_addr, probe_addr);
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let state = AppHandle::new(snapshot);
  let (shutdown, shutdown_rx) = watch::channel(false);
  let task = tokio::spawn(serve_admin_listener(
    admin_listener,
    admin_addr,
    state,
    test_admin_control(),
    shutdown_rx,
  ));
  let probe_task = spawn_health_probe_responder(probe_listener);

  let response = admin_get_response(
    admin_addr,
    "/admin/v1/diagnostics/preflight?external_probe=upstream",
  )
  .await;
  assert!(
    response.starts_with("HTTP/1.1 200 OK")
      && response.contains(r#""kind":"upstream""#)
      && response.contains(r#""status":"ok""#),
    "remote preflight GET should run query-string probes: {}",
    log_safe_text(&response)
  );
  tokio::time::timeout(std::time::Duration::from_secs(1), probe_task)
    .await
    .expect("target health responder should not time out")
    .expect("target health responder should complete");

  let _ = shutdown.send(true);
  task.abort();
}

fn admin_preflight_probe_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
  probe_addr: SocketAddr,
) -> Config {
  let target_resource = format!(
    "oxibelt:oxibelt:diagnostics:probe/upstream/tcp/127.0.0.1:{}",
    probe_addr.port()
  );
  let mut raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      "https_bind = \"127.0.0.1:0\"",
    )
    .replace(
      "origin = \"https://app.internal.example\"",
      &format!("origin = \"http://127.0.0.1:{}\"", probe_addr.port()),
    );
  raw.push_str(&format!(
    r#"

[admin]
enabled = true
bind = "{admin_bind}"
bearer_token_env = "{ADMIN_TOKEN_ENV}"
transport = "plaintext_allowlist"

[ipm]
enabled = true

[[ipm.principals]]
id = "diagnostics"
subject = "diagnostics@example.com"

[[ipm.credentials]]
name = "diagnostics-token"
principal = "diagnostics"
bearer_token_env = "{ADMIN_TOKEN_ENV}"

[[ipm.policies]]
name = "diagnostics"

[[ipm.policies.statements]]
effect = "allow"
actions = ["diagnostics:ReadPreflight", "diagnostics:RunProbe"]
resources = [
  "oxibelt:oxibelt:diagnostics:preflight/current",
  "oxibelt:oxibelt:diagnostics:probe/upstream",
  "{target_resource}",
]

[[ipm.bindings]]
principal = "diagnostics"
policy = "diagnostics"
"#
  ));
  parse_config(&raw)
}

fn parse_config(raw: &str) -> Config {
  let mut config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  let root = std::env::current_dir().expect("test current directory should be available");
  let cert_dir = config
    .tls
    .cert_chain
    .parent()
    .map(Path::to_path_buf)
    .unwrap_or_else(|| root.clone());
  config.source_paths.config_dir = Some(root.clone());
  config.source_paths.cert_dir = Some(cert_dir);
  config.source_paths.oxirule_dir = Some(root);
  config
}

async fn admin_get_response(addr: SocketAddr, path: &str) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let request = format!(
    "GET {path} HTTP/1.1\r\n\
     Host: admin\r\n\
     Authorization: Bearer {token}\r\n\
     Connection: close\r\n\
     \r\n"
  );
  stream
    .write_all(request.as_bytes())
    .await
    .expect("admin GET request should write");
  read_admin_response(stream).await
}

async fn read_admin_response(mut stream: TcpStream) -> String {
  let mut response = Vec::new();
  tokio::time::timeout(
    std::time::Duration::from_secs(1),
    stream.read_to_end(&mut response),
  )
  .await
  .expect("admin response should not time out")
  .expect("admin response should read");
  String::from_utf8_lossy(&response).into_owned()
}

fn spawn_health_probe_responder(listener: TcpListener) -> tokio::task::JoinHandle<()> {
  tokio::spawn(async move {
    let (mut stream, _) = listener
      .accept()
      .await
      .expect("target listener should receive an authorized probe connection");
    let mut request = [0_u8; 512];
    let _ = stream
      .read(&mut request)
      .await
      .expect("target listener should read health probe request");
    stream
      .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
      .await
      .expect("target listener should write health probe response");
  })
}

fn log_safe_text(input: &str) -> String {
  input.replace('\n', "\\n").replace('\r', "\\r")
}
