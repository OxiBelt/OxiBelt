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
async fn async_support_bundle_get_uses_authorized_snapshot_after_config_replace() {
  assert_async_support_bundle_uses_authorized_snapshot_after_config_replace(
    SupportBundleAsyncRequest::GetPreferAsync,
  )
  .await;
}

#[tokio::test]
async fn support_bundle_operation_uses_authorized_snapshot_after_config_replace() {
  assert_async_support_bundle_uses_authorized_snapshot_after_config_replace(
    SupportBundleAsyncRequest::PostOperation,
  )
  .await;
}

#[derive(Clone, Copy)]
enum SupportBundleAsyncRequest {
  GetPreferAsync,
  PostOperation,
}

async fn assert_async_support_bundle_uses_authorized_snapshot_after_config_replace(
  request_kind: SupportBundleAsyncRequest,
) {
  let temp_dir = common::TempDir::new("admin-support-bundle-authorized-snapshot");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-support-bundle-authorized-snapshot");
  let admin_listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let admin_addr = admin_listener
    .local_addr()
    .expect("admin listener address should be available");
  let old_probe_listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("old probe listener should bind");
  let old_probe_addr = old_probe_listener
    .local_addr()
    .expect("old probe listener address should be available");
  let new_probe_listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("new probe listener should bind");
  let new_probe_addr = new_probe_listener
    .local_addr()
    .expect("new probe listener address should be available");
  let old_target_resource = format!(
    "oxibelt:oxibelt:diagnostics:probe/upstream/tcp/127.0.0.1:{}",
    old_probe_addr.port()
  );
  let policy_resources = vec![
    "oxibelt:oxibelt:diagnostics:support-bundle/current".to_string(),
    "oxibelt:oxibelt:diagnostics:probe/upstream".to_string(),
    old_target_resource,
  ];
  let old_config = admin_listener_policy_config(
    &cert_path,
    &key_path,
    admin_addr,
    &[
      "diagnostics:ReadSupportBundle".to_string(),
      "diagnostics:RunProbe".to_string(),
    ],
    &policy_resources,
    Some(format!("http://127.0.0.1:{}", old_probe_addr.port())),
  );
  let new_config = admin_listener_policy_config(
    &cert_path,
    &key_path,
    admin_addr,
    &[
      "diagnostics:ReadSupportBundle".to_string(),
      "diagnostics:RunProbe".to_string(),
    ],
    &policy_resources,
    Some(format!("http://127.0.0.1:{}", new_probe_addr.port())),
  );
  let snapshot = AppSnapshot::new(old_config)
    .await
    .expect("old snapshot should initialize");
  let replacement = AppSnapshot::new(new_config)
    .await
    .expect("new snapshot should initialize");
  let state = AppHandle::new(snapshot);
  let operations = single_runner_admin_operations();
  let (blocker_release, blocker_released) = tokio::sync::oneshot::channel();
  let (blocker_started, blocker_started_rx) = tokio::sync::oneshot::channel();
  let blocker_actor = test_operation_actor("blocker");
  operations
    .enqueue(
      admin_operations::AdminOperationKind::CacheWarm,
      &blocker_actor,
      "block-support-bundle".to_string(),
      move |_| async move {
        let _ = blocker_started.send(());
        let _ = blocker_released.await;
        admin_operations::value_result(serde_json::json!({"released": true}))
      },
    )
    .await
    .expect("blocker operation should enqueue");
  blocker_started_rx
    .await
    .expect("blocker operation should start");
  let (shutdown, shutdown_rx) = watch::channel(false);
  let task = tokio::spawn(serve_admin_listener(
    admin_listener,
    admin_addr,
    state.clone(),
    test_admin_control(),
    operations.clone(),
    shutdown_rx,
  ));
  let old_probe_task = spawn_health_probe_responder(old_probe_listener);
  let mut new_probe_task = spawn_health_probe_responder(new_probe_listener);

  let response = match request_kind {
    SupportBundleAsyncRequest::GetPreferAsync => {
      admin_get_response_with_headers(
        admin_addr,
        "/admin/v1/diagnostics/support-bundle?redact=true&external_probe=upstream",
        &["Prefer: respond-async\r\n"],
      )
      .await
    }
    SupportBundleAsyncRequest::PostOperation => {
      admin_post_json_response(
        admin_addr,
        "/admin/v1/operations",
        r#"{"kind":"support_bundle","request":{"redact":true,"external_probes":["upstream"]}}"#,
      )
      .await
    }
  };
  assert!(
    response.starts_with("HTTP/1.1 202 Accepted"),
    "async support bundle should be accepted: {}",
    log_safe_text(&response)
  );
  let id = operation_id_from_response(&response);

  state.replace(replacement);
  blocker_release
    .send(())
    .expect("blocker release should be delivered");
  let result = poll_admin_operation(admin_addr, &id).await;
  assert!(
    result.contains(r#""state":"succeeded""#)
      && result.contains(r#""kind":"upstream""#)
      && result.contains(r#""status":"ok""#),
    "support bundle operation should succeed with the authorized probe target: {}",
    log_safe_text(&result)
  );
  tokio::time::timeout(std::time::Duration::from_secs(1), old_probe_task)
    .await
    .expect("old authorized target should receive a probe")
    .expect("old authorized target responder should complete");
  assert!(
    tokio::time::timeout(std::time::Duration::from_millis(150), &mut new_probe_task)
      .await
      .is_err(),
    "new unauthorized target should not receive the queued support-bundle probe"
  );
  new_probe_task.abort();

  let _ = shutdown.send(true);
  task.abort();
}

fn admin_listener_policy_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
  actions: &[String],
  resources: &[String],
  upstream_origin: Option<String>,
) -> Config {
  let mut raw = common::minimal_config_toml(cert_path, key_path)
    .replace("unprivileged_mode = true", "unprivileged_mode = false")
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      "https_bind = \"127.0.0.1:0\"",
    );
  if let Some(origin) = upstream_origin {
    raw = raw.replace(
      "origin = \"https://app.internal.example\"",
      &format!("origin = \"{origin}\""),
    );
  }
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

fn single_runner_admin_operations() -> admin_operations::AdminOperationRuntime {
  let config = crate::config::AdminOperationsConfig {
    max_running: 1,
    max_queued: 4,
    max_stored: 8,
    ..crate::config::AdminOperationsConfig::default()
  };
  admin_operations::AdminOperationRuntime::new(config)
}

fn test_operation_actor(name: &str) -> AdminActor {
  AdminActor {
    name: name.to_string(),
    principal: name.to_string(),
    subject: format!("{name}@example.test"),
    groups: Vec::new(),
  }
}

async fn admin_get_response_with_headers(
  addr: SocketAddr,
  path: &str,
  extra_headers: &[&str],
) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let extra = extra_headers.join("");
  let request = format!(
    "GET {path} HTTP/1.1\r\n\
     Host: admin\r\n\
     Authorization: Bearer {token}\r\n\
     {extra}\
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

async fn poll_admin_operation(addr: SocketAddr, id: &str) -> String {
  for _ in 0..100 {
    let response =
      admin_get_response_with_headers(addr, &format!("/admin/v1/operations/{id}"), &[]).await;
    if response.contains(r#""state":"succeeded""#)
      || response.contains(r#""state":"failed""#)
      || response.contains(r#""state":"cancelled""#)
    {
      return response;
    }
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
  }
  admin_get_response_with_headers(addr, &format!("/admin/v1/operations/{id}"), &[]).await
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
