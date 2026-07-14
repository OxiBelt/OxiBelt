use std::net::SocketAddr;
use std::path::Path;

use ::http::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::admin_audit::AdminAuditHandle;
use crate::config::Config;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

const ADMIN_TOKEN_ENV: &str = "PATH";

#[tokio::test]
async fn full_durable_audit_spool_rejects_config_load_before_handler() {
  let temp_dir = common::TempDir::new("admin-audit-queue-full");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-audit-queue-full");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let spool_path = temp_dir.path().join("audit-spool");
  let config = admin_listener_config(&cert_path, &key_path, &spool_path, addr);
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let filler = AdminAuditHandle::new(
    "127.0.0.1:1234".parse().unwrap(),
    "http",
    &Method::POST,
    "/admin/v1/config/load",
    None,
  );
  assert!(
    snapshot
      .admin_audit
      .begin_required_mutation(&filler, "config.load", "config")
      .await
      .expect("first durable intent should reserve the remaining terminal slot")
  );
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

  let response = admin_config_load_response(addr).await;
  assert!(
    response.starts_with("HTTP/1.1 503 Service Unavailable")
      && response.contains(r#""code":"control_plane_unavailable""#)
      && response.contains(r#""request_id":""#),
    "full audit spool should reject before config load runs: {}",
    log_safe_text(&response)
  );

  let _ = shutdown.send(true);
  task.abort();
}

fn admin_listener_config(
  cert_path: &Path,
  key_path: &Path,
  spool_path: &Path,
  admin_bind: SocketAddr,
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
enabled = true
bind = "{admin_bind}"
bearer_token_env = "{ADMIN_TOKEN_ENV}"
transport = "plaintext_allowlist"

[admin.audit]
enabled = true
mode = "durable_required"
acknowledgement = "fsynced_spool"

[admin.audit.spool]
enabled = true
directory = "{}"
max_events = 2
max_bytes = 65536
max_event_bytes = 32768
"#,
    spool_path.display()
  ));
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

async fn admin_config_load_response(addr: SocketAddr) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin config load connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let body = serde_json::json!({
    "format": "toml",
    "config": "[admin]\nenabled = true\n",
  })
  .to_string();
  let request = format!(
    "POST /admin/v1/config/load HTTP/1.1\r\n\
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
    .expect("admin config load request should write");
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
