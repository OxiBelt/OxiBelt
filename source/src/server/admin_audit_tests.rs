use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use ::http::{Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::admin_audit::{AdminAuditHandle, AdminAuditRuntime};
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

#[tokio::test]
async fn selective_best_effort_events_do_not_exhaust_required_spool_capacity() {
  let temp_dir = common::TempDir::new("admin-audit-selective-capacity");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-audit-selective-capacity");
  let spool_path = temp_dir.path().join("audit-spool");
  let config = admin_listener_config_with_policy(
    &cert_path,
    &key_path,
    &spool_path,
    "127.0.0.1:9092".parse().unwrap(),
    "durable_required_for_actions",
    r#"["config.load"]"#,
  );
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let runtime = snapshot.admin_audit.clone();

  for status in [StatusCode::UNAUTHORIZED, StatusCode::OK] {
    commit_non_required_event(&runtime, status).await;
  }
  assert!(
    spool_records(&spool_path).is_empty(),
    "non-required events must not consume selective required-audit capacity"
  );

  let audit = AdminAuditHandle::new(
    "127.0.0.1:1234".parse().unwrap(),
    "http",
    &Method::POST,
    "/admin/v1/config/load",
    None,
  );
  let reservation = runtime.reserve().expect("audit reservation should succeed");
  assert!(
    runtime
      .begin_required_mutation(&audit, "config.load", "config")
      .await
      .expect("required intent should retain terminal capacity")
  );
  let event = audit.finish(StatusCode::FORBIDDEN);
  reservation
    .commit(&audit, event)
    .await
    .expect("required terminal should consume its reservation");

  let records = spool_records(&spool_path);
  assert_eq!(records.len(), 2);
  assert_eq!(records[0]["phase"], "intent");
  assert_eq!(records[1]["phase"], "terminal");
  assert!(
    records
      .iter()
      .all(|record| record["durability_action"] == "config.load")
  );
}

#[tokio::test]
async fn global_best_effort_mode_still_spools_non_required_events() {
  let temp_dir = common::TempDir::new("admin-audit-global-best-effort");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-audit-global-best-effort");
  let spool_path = temp_dir.path().join("audit-spool");
  let config = admin_listener_config_with_policy(
    &cert_path,
    &key_path,
    &spool_path,
    "127.0.0.1:9092".parse().unwrap(),
    "best_effort",
    "[]",
  );
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");

  commit_non_required_event(&snapshot.admin_audit, StatusCode::UNAUTHORIZED).await;

  let records = spool_records(&spool_path);
  assert_eq!(records.len(), 1);
  assert_eq!(records[0]["phase"], "terminal");
  assert_eq!(records[0]["error_code"], "unauthorized");
  assert!(records[0]["durability_action"].is_null());
}

#[tokio::test]
async fn unauthenticated_requests_do_not_exhaust_selective_required_spool() {
  let temp_dir = common::TempDir::new("admin-audit-selective-listener");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-audit-selective-listener");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let spool_path = temp_dir.path().join("audit-spool");
  let config = admin_listener_config_with_policy(
    &cert_path,
    &key_path,
    &spool_path,
    addr,
    "durable_required_for_actions",
    r#"["config.load"]"#,
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

  for _ in 0..2 {
    let response = unauthenticated_admin_status_response(addr).await;
    assert!(
      response.starts_with("HTTP/1.1 401 Unauthorized"),
      "invalid authentication should remain rejected: {}",
      log_safe_text(&response)
    );
  }
  assert!(
    spool_records(&spool_path).is_empty(),
    "unauthenticated best-effort events must not consume the required spool"
  );

  let response = admin_config_load_response(addr).await;
  assert!(
    !response.contains("required Admin audit persistence failed"),
    "best-effort traffic must not cause an audit-generated 503: {}",
    log_safe_text(&response)
  );
  let records = spool_records(&spool_path);
  assert_eq!(records.len(), 2);
  assert_eq!(records[0]["phase"], "intent");
  assert_eq!(records[1]["phase"], "terminal");
  assert!(
    records
      .iter()
      .all(|record| record["durability_action"] == "config.load")
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
  admin_listener_config_with_policy(
    cert_path,
    key_path,
    spool_path,
    admin_bind,
    "durable_required",
    "[]",
  )
}

fn admin_listener_config_with_policy(
  cert_path: &Path,
  key_path: &Path,
  spool_path: &Path,
  admin_bind: SocketAddr,
  audit_mode: &str,
  required_actions: &str,
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
mode = "{audit_mode}"
acknowledgement = "fsynced_spool"
required_actions = {required_actions}

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

async fn commit_non_required_event(runtime: &AdminAuditRuntime, status: StatusCode) {
  let audit = AdminAuditHandle::new(
    "127.0.0.1:1234".parse().unwrap(),
    "http",
    &Method::GET,
    "/admin/v1/config/status",
    None,
  );
  let reservation = runtime.reserve().expect("audit reservation should succeed");
  let event = audit.finish(status);
  reservation
    .commit(&audit, event)
    .await
    .expect("non-required event commit should remain best effort");
}

fn spool_records(spool_path: &Path) -> Vec<serde_json::Value> {
  let mut paths = fs::read_dir(spool_path)
    .expect("spool directory should be readable")
    .map(|entry| entry.expect("spool entry should be readable").path())
    .filter(|path| {
      path
        .extension()
        .is_some_and(|extension| extension == "audit")
    })
    .collect::<Vec<_>>();
  paths.sort();
  paths
    .into_iter()
    .map(|path| {
      serde_json::from_slice(&fs::read(path).expect("spool record should be readable"))
        .expect("spool record should contain JSON")
    })
    .collect()
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

async fn unauthenticated_admin_status_response(addr: SocketAddr) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin status connection should open");
  stream
    .write_all(
      b"GET /admin/v1/config/status HTTP/1.1\r\n\
        Host: admin\r\n\
        Connection: close\r\n\
        \r\n",
    )
    .await
    .expect("admin status request should write");
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
