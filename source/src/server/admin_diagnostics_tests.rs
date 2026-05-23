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
async fn diagnostics_preflight_get_allows_read_only_actor() {
  let temp_dir = common::TempDir::new("admin-diagnostics-read");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-diagnostics-read");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = admin_listener_diagnostics_config(&cert_path, &key_path, addr, false, &[]);
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let state = AppHandle::new(snapshot);
  let (shutdown, shutdown_rx) = watch::channel(false);
  let task = tokio::spawn(serve_admin_listener(
    listener,
    addr,
    state,
    test_admin_control(),
    shutdown_rx,
  ));

  let response = admin_get_response(addr, "/admin/v1/diagnostics/preflight").await;
  assert!(
    response.starts_with("HTTP/1.1 200 OK")
      && response.contains(r#""profile":"production""#)
      && response.contains(r#""ok":"#),
    "diagnostics GET should return a report: {}",
    log_safe_text(&response)
  );

  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn diagnostics_candidate_requires_probe_permission_and_reports_invalid_config() {
  let temp_dir = common::TempDir::new("admin-diagnostics-candidate");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-diagnostics-candidate");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = admin_listener_diagnostics_config(&cert_path, &key_path, addr, true, &[]);
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let state = AppHandle::new(snapshot);
  let (shutdown, shutdown_rx) = watch::channel(false);
  let task = tokio::spawn(serve_admin_listener(
    listener,
    addr,
    state,
    test_admin_control(),
    shutdown_rx,
  ));

  let invalid_candidate =
    r#"{"format":"toml","config":"[listeners\nhttps_bind = \"127.0.0.1:8443\""}"#;
  let response =
    admin_post_json_response(addr, "/admin/v1/diagnostics/preflight", invalid_candidate).await;
  assert!(
    response.starts_with("HTTP/1.1 200 OK")
      && response.contains(r#""ok":false"#)
      && response.contains("config.invalid"),
    "invalid candidate should be returned as a diagnostics report: {}",
    log_safe_text(&response)
  );

  let probe_candidate =
    r#"{"format":"toml","config":"[broken","external_probes":["shared_state"]}"#;
  let response =
    admin_post_json_response(addr, "/admin/v1/diagnostics/preflight", probe_candidate).await;
  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden"),
    "external probe should require diagnostics:RunProbe: {}",
    log_safe_text(&response)
  );

  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn diagnostics_candidate_upstream_probe_requires_target_permission() {
  let temp_dir = common::TempDir::new("admin-diagnostics-target-deny");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-diagnostics-target-deny");
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
  let config = admin_listener_diagnostics_config(
    &cert_path,
    &key_path,
    admin_addr,
    true,
    &["oxibelt:oxibelt:diagnostics:probe/upstream".to_string()],
  );
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

  let body = candidate_upstream_probe_body(&cert_path, &key_path, probe_addr);
  let response =
    admin_post_json_response(admin_addr, "/admin/v1/diagnostics/preflight", &body).await;
  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden"),
    "candidate upstream probe should require a target permission: {}",
    log_safe_text(&response)
  );
  assert!(
    tokio::time::timeout(
      std::time::Duration::from_millis(150),
      probe_listener.accept()
    )
    .await
    .is_err(),
    "target listener should not receive a connection when target permission is missing"
  );

  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn diagnostics_candidate_upstream_probe_allows_authorized_target() {
  let temp_dir = common::TempDir::new("admin-diagnostics-target-allow");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-diagnostics-target-allow");
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
  let target_resource = format!(
    "oxibelt:oxibelt:diagnostics:probe/upstream/tcp/127.0.0.1:{}",
    probe_addr.port()
  );
  let config = admin_listener_diagnostics_config(
    &cert_path,
    &key_path,
    admin_addr,
    true,
    &[
      "oxibelt:oxibelt:diagnostics:probe/upstream".to_string(),
      target_resource,
    ],
  );
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

  let body = candidate_upstream_probe_body(&cert_path, &key_path, probe_addr);
  let response =
    admin_post_json_response(admin_addr, "/admin/v1/diagnostics/preflight", &body).await;
  assert!(
    response.starts_with("HTTP/1.1 200 OK")
      && response.contains(r#""kind":"upstream""#)
      && response.contains(r#""status":"ok""#),
    "authorized candidate upstream probe should run: {}",
    log_safe_text(&response)
  );
  tokio::time::timeout(std::time::Duration::from_secs(1), probe_listener.accept())
    .await
    .expect("target listener should receive an authorized probe connection")
    .expect("target listener accept should succeed");

  let _ = shutdown.send(true);
  task.abort();
}

fn admin_listener_diagnostics_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
  allow_candidate: bool,
  probe_resources: &[String],
) -> Config {
  let mut raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      "https_bind = \"127.0.0.1:0\"",
    );
  let mut actions = vec!["diagnostics:ReadPreflight".to_string()];
  if allow_candidate {
    actions.push("diagnostics:RunPreflight".to_string());
  }
  if !probe_resources.is_empty() {
    actions.push("diagnostics:RunProbe".to_string());
  }
  let mut resources = vec!["oxibelt:oxibelt:diagnostics:preflight/current".to_string()];
  if allow_candidate {
    resources.push("oxibelt:oxibelt:diagnostics:preflight/candidate".to_string());
  }
  resources.extend(probe_resources.iter().cloned());
  let actions = toml_string_array(&actions);
  let resources = toml_string_array(&resources);
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
actions = {actions}
resources = {resources}

[[ipm.bindings]]
principal = "diagnostics"
policy = "diagnostics"
"#
  ));
  parse_config(&raw)
}

fn candidate_upstream_probe_body(
  cert_path: &Path,
  key_path: &Path,
  probe_addr: SocketAddr,
) -> String {
  let cert_name = cert_path
    .file_name()
    .and_then(|name| name.to_str())
    .expect("test certificate path should have a UTF-8 file name");
  let key_name = key_path
    .file_name()
    .and_then(|name| name.to_str())
    .expect("test key path should have a UTF-8 file name");
  let raw = common::minimal_config_toml_with_paths(cert_name, key_name)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      "https_bind = \"127.0.0.1:0\"",
    )
    .replace(
      "origin = \"https://app.internal.example\"",
      &format!("origin = \"http://127.0.0.1:{}\"", probe_addr.port()),
    );
  serde_json::json!({
    "format": "toml",
    "config": raw,
    "external_probes": ["upstream"],
  })
  .to_string()
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

fn toml_string_array(values: &[String]) -> String {
  format!(
    "[{}]",
    values
      .iter()
      .map(|value| format!("{value:?}"))
      .collect::<Vec<_>>()
      .join(", ")
  )
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

async fn admin_post_json_response(addr: SocketAddr, path: &str, body: &str) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let request = format!(
    "POST {path} HTTP/1.1\r\n\
     Host: admin\r\n\
     Authorization: Bearer {token}\r\n\
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
    .expect("admin POST request should write");
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

fn log_safe_text(input: &str) -> String {
  input.replace('\n', "\\n").replace('\r', "\\r")
}
