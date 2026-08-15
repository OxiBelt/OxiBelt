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
async fn runtime_introspection_requires_redact_and_dedicated_permission() {
  let temp_dir = common::TempDir::new("admin-runtime-introspection");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-runtime-introspection");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = admin_listener_policy_config(
    &cert_path,
    &key_path,
    addr,
    &["runtime:ReadIntrospection".to_string()],
    &["oxibelt:oxibelt:runtime:introspection/current".to_string()],
  );
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
    test_admin_operations(),
    shutdown_rx,
  ));

  let missing_redact = admin_get_response(addr, "/admin/v1/runtime/introspection").await;
  assert!(
    missing_redact.starts_with("HTTP/1.1 400 Bad Request"),
    "runtime introspection should require redact=true: {}",
    log_safe_text(&missing_redact)
  );
  let response = admin_get_response(addr, "/admin/v1/runtime/introspection?redact=true").await;
  assert!(
    response.starts_with("HTTP/1.1 200 OK")
      && response.contains(r#""metadata""#)
      && response.contains(r#""runtime""#)
      && response.contains(r#""connections""#)
      && response.contains(r#""format_version":3"#)
      && response.contains(r#""udp_clients_active":0"#)
      && response.contains(r#""allocations_active":0"#)
      && response.contains(r#""redacted":true"#),
    "runtime introspection should return redacted JSON: {}",
    log_safe_text(&response)
  );

  let _ = shutdown.send(true);
  task.abort();

  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = admin_listener_policy_config(
    &cert_path,
    &key_path,
    addr,
    &["runtime:ReadSnapshot".to_string()],
    &["oxibelt:oxibelt:runtime:snapshot/current".to_string()],
  );
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
    test_admin_operations(),
    shutdown_rx,
  ));

  let denied = admin_get_response(addr, "/admin/v1/runtime/introspection?redact=true").await;
  assert!(
    denied.starts_with("HTTP/1.1 403 Forbidden"),
    "runtime introspection should require runtime:ReadIntrospection: {}",
    log_safe_text(&denied)
  );
  let snapshot_response = admin_get_response(addr, "/admin/v1/runtime/snapshot?redact=true").await;
  assert!(
    snapshot_response.starts_with("HTTP/1.1 200 OK"),
    "runtime snapshot should still allow runtime:ReadSnapshot: {}",
    log_safe_text(&snapshot_response)
  );

  let _ = shutdown.send(true);
  task.abort();
}

fn admin_listener_policy_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
  actions: &[String],
  resources: &[String],
) -> Config {
  let mut raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      "https_bind = \"127.0.0.1:0\"",
    );
  let actions = toml_string_array(actions);
  let resources = toml_string_array(resources);
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
