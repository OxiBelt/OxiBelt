use std::net::SocketAddr;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

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
async fn cache_purge_requires_policy_and_host_resources() {
  let response = scoped_admin_response(
    "resource-cache-host-deny",
    cache_scope_config,
    "POST",
    "/admin/v1/cache/purge",
    r#"{"type":"exact","policy":"default","scheme":"http","host":"example.com","uri":"/item"}"#,
  )
  .await;

  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden")
      && response.contains(r#""action":"cache:PurgeObject""#)
      && response.contains(r#""resource":"oxibelt:oxibelt:cache:host/example.com""#),
    "cache purge should require host resource: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn cache_warm_denies_batch_before_any_warm_item_runs() {
  let response = scoped_admin_response(
    "resource-cache-warm-deny",
    cache_warm_scope_config,
    "POST",
    "/admin/v1/cache/warm",
    r#"{"items":[{"scheme":"https","host":"example.com","uri":"/ok"},{"scheme":"https","host":"denied.example.com","uri":"/blocked"}]}"#,
  )
  .await;

  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden")
      && response.contains(r#""action":"cache:Warm""#)
      && response.contains(r#""resource":"oxibelt:oxibelt:cache:host/denied.example.com""#),
    "cache warm should reject unauthorized batch targets: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn dynamic_policy_create_requires_source_name_and_route_resources() {
  let response = scoped_admin_response(
    "resource-dynamic-route-deny",
    dynamic_policy_scope_config,
    "POST",
    "/admin/v1/dynamic-policies",
    r#"{"source":"vault","name":"block","route_name":"app-root","action":"reject","subject_type":"client_ip","subject":"203.0.113.9","status":429,"body":"blocked","ttl_seconds":60}"#,
  )
  .await;

  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden")
      && response.contains(r#""action":"dynamic-policy:Create""#)
      && response.contains(r#""resource":"oxibelt:oxibelt:dynamic-policy:route/app-root""#),
    "dynamic policy create should require route resource: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn upstream_pool_server_mutation_requires_server_resource() {
  let response = scoped_admin_response(
    "resource-upstream-server-deny",
    upstream_pool_scope_config,
    "PATCH",
    "/admin/v1/upstream-pools/app-pool/servers/primary",
    r#"{"state":"down"}"#,
  )
  .await;

  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden")
      && response.contains(r#""action":"upstream-pool:UpdateServer""#)
      && response.contains(r#""resource":"oxibelt:oxibelt:upstream-pool:app-pool/server/primary""#),
    "upstream server mutation should require server resource: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn dynamic_policy_status_requires_status_resource() {
  let Some(denied) = try_scoped_admin_response(
    "resource-dynamic-status-deny",
    dynamic_policy_scope_config,
    "GET",
    "/admin/v1/dynamic-policies/status",
    "",
  )
  .await
  else {
    return;
  };

  assert!(
    denied.starts_with("HTTP/1.1 403 Forbidden")
      && denied.contains(r#""action":"dynamic-policy:GetStatus""#)
      && denied.contains(r#""resource":"oxibelt:oxibelt:dynamic-policy:status/current""#),
    "dynamic policy status should require status/current: {}",
    log_safe_text(&denied)
  );

  let Some(allowed) = try_scoped_admin_response(
    "resource-dynamic-status-allow",
    dynamic_policy_status_scope_config,
    "GET",
    "/admin/v1/dynamic-policies/status",
    "",
  )
  .await
  else {
    return;
  };

  assert!(
    allowed.starts_with("HTTP/1.1 400 Bad Request")
      && allowed.contains("dynamic policy is disabled"),
    "dynamic policy status permission should reach the handler: {}",
    log_safe_text(&allowed)
  );
}

#[tokio::test]
async fn upstream_pool_status_requires_status_resource() {
  let Some(denied) = try_scoped_admin_response(
    "resource-upstream-status-deny",
    upstream_pool_scope_config,
    "GET",
    "/admin/v1/upstream-pools/status",
    "",
  )
  .await
  else {
    return;
  };

  assert!(
    denied.starts_with("HTTP/1.1 403 Forbidden")
      && denied.contains(r#""action":"upstream-pool:GetStatus""#)
      && denied.contains(r#""resource":"oxibelt:oxibelt:upstream-pool:status/current""#),
    "upstream pool status should require status/current: {}",
    log_safe_text(&denied)
  );

  let Some(allowed) = try_scoped_admin_response(
    "resource-upstream-status-allow",
    upstream_pool_status_scope_config,
    "GET",
    "/admin/v1/upstream-pools/status",
    "",
  )
  .await
  else {
    return;
  };

  assert!(
    allowed.starts_with("HTTP/1.1 200 OK")
      && allowed.contains(r#""generation":0"#)
      && allowed.contains(r#""etag":"\"oxibelt-upstream-pools-0\"""#),
    "upstream pool status permission should return the status ETag: {}",
    log_safe_text(&allowed)
  );
}

#[tokio::test]
async fn ipm_credential_create_requires_target_principal_resource() {
  let response = scoped_admin_response(
    "resource-ipm-principal-deny",
    ipm_credential_scope_config,
    "POST",
    "/admin/v1/ipm/credentials",
    r#"{"id":"new-token","principal":"deployer","ttl_seconds":60}"#,
  )
  .await;

  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden")
      && response.contains(r#""action":"ipm:CreateCredential""#)
      && response.contains(r#""resource":"oxibelt:oxibelt:ipm:principal/deployer""#),
    "IPM credential create should require target principal resource: {}",
    log_safe_text(&response)
  );
}

async fn scoped_admin_response(
  name: &str,
  config: fn(&Path, &Path, SocketAddr) -> Config,
  method: &str,
  path: &str,
  body: &str,
) -> String {
  try_scoped_admin_response(name, config, method, path, body)
    .await
    .expect("admin listener should bind")
}

async fn try_scoped_admin_response(
  name: &str,
  config: fn(&Path, &Path, SocketAddr) -> Config,
  method: &str,
  path: &str,
  body: &str,
) -> Option<String> {
  let temp_dir = common::TempDir::new(name);
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), name);
  let listener = match TcpListener::bind("127.0.0.1:0").await {
    Ok(listener) => listener,
    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
    Err(error) => panic!("admin listener should bind: {error}"),
  };
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = config(&cert_path, &key_path, addr);
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

  let response = admin_json_response(addr, method, path, body).await;
  let _ = shutdown.send(true);
  task.abort();
  Some(response)
}

async fn admin_json_response(addr: SocketAddr, method: &str, path: &str, body: &str) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let request = format!(
    "{method} {path} HTTP/1.1\r\n\
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
    .expect("admin request should write");
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

fn cache_scope_config(cert_path: &Path, key_path: &Path, admin_bind: SocketAddr) -> Config {
  parse_scoped_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[cache]
enabled = true
store = "memory"
cache_methods = ["GET"]

[[ipm.policies.statements]]
effect = "allow"
actions = ["cache:PurgeObject"]
resources = ["oxibelt:oxibelt:cache:policy/default"]
"#,
  )
}

fn cache_warm_scope_config(cert_path: &Path, key_path: &Path, admin_bind: SocketAddr) -> Config {
  parse_scoped_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[cache]
enabled = true
store = "memory"
cache_methods = ["GET"]

[[ipm.policies.statements]]
effect = "allow"
actions = ["cache:Warm"]
resources = [
  "oxibelt:oxibelt:cache:policy/default",
  "oxibelt:oxibelt:cache:host/example.com",
]
"#,
  )
}

fn dynamic_policy_scope_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_scoped_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["dynamic-policy:Create"]
resources = ["oxibelt:oxibelt:dynamic-policy:source/vault/name/block"]
"#,
  )
}

fn dynamic_policy_status_scope_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_scoped_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["dynamic-policy:GetStatus"]
resources = ["oxibelt:oxibelt:dynamic-policy:status/current"]
"#,
  )
}

fn upstream_pool_scope_config(cert_path: &Path, key_path: &Path, admin_bind: SocketAddr) -> Config {
  parse_scoped_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[upstream_pools]]
name = "app-pool"

[[upstream_pools.servers]]
id = "primary"
origin = "https://primary.internal.example"

[[ipm.policies.statements]]
effect = "allow"
actions = ["upstream-pool:UpdateServer"]
resources = ["oxibelt:oxibelt:upstream-pool:app-pool"]
"#,
  )
}

fn upstream_pool_status_scope_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_scoped_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["upstream-pool:GetStatus"]
resources = ["oxibelt:oxibelt:upstream-pool:status/current"]
"#,
  )
}

fn ipm_credential_scope_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_scoped_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["ipm:CreateCredential"]
resources = ["oxibelt:oxibelt:ipm:credential/new-token"]
"#,
  )
}

fn parse_scoped_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
  extra: &str,
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

[ipm]
enabled = true

[[ipm.principals]]
id = "operator"
subject = "operator@example.com"

[[ipm.credentials]]
name = "operator-token"
principal = "operator"
bearer_token_env = "{ADMIN_TOKEN_ENV}"

[[ipm.policies]]
name = "scoped"
{extra}

[[ipm.bindings]]
principal = "operator"
policy = "scoped"
"#
  ));
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

fn log_safe_text(input: &str) -> String {
  input.replace('\n', "\\n").replace('\r', "\\r")
}
