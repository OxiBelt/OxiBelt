use std::net::SocketAddr;
use std::path::Path;

use ::http::{HeaderMap, HeaderValue, StatusCode};
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
async fn admin_v1_json_purge_removes_exact_prefix_and_tag_entries() {
  let temp_dir = common::TempDir::new("admin-json-cache-purge");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-json-cache-purge");
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
  for (uri, tag) in [
    ("/json/exact", None),
    ("/json/prefix/a", None),
    ("/json/prefix/b", None),
    ("/json/tag", Some("release-1")),
  ] {
    seed_cache_entry(&snapshot, uri, tag);
  }
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

  for (body, expected) in [
    (
      r#"{"type":"exact","policy":"default","scheme":"http","host":"example.com","uri":"/json/exact"}"#,
      r#"{"purged":1}"#,
    ),
    (
      r#"{"type":"prefix","policy":"default","scheme":"http","host":"example.com","path_prefix":"/json/prefix/"}"#,
      r#"{"purged":2}"#,
    ),
    (
      r#"{"type":"tag","policy":"default","tag":"release-1"}"#,
      r#"{"purged":1}"#,
    ),
  ] {
    let response = admin_json_purge_response(addr, body).await;
    assert!(
      response.starts_with("HTTP/1.1 200 OK") && response.contains(expected),
      "JSON purge response should succeed: {}",
      log_safe_text(&response)
    );
  }
  let response = admin_json_purge_response(addr, r#"{"type":"exact","host":"example.com"}"#).await;
  assert!(
    response.starts_with("HTTP/1.1 400 Bad Request")
      && response.contains(r#""code":"invalid_request""#),
    "invalid JSON purge should be rejected: {}",
    log_safe_text(&response)
  );

  let large_body = "x".repeat(64 * 1024 + 1);
  let response = admin_json_purge_response(addr, &large_body).await;
  assert!(
    response.starts_with("HTTP/1.1 413 Payload Too Large")
      && response.contains(r#""code":"payload_too_large""#),
    "oversized JSON purge should be rejected before parsing: {}",
    log_safe_text(&response)
  );

  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn query_cache_purge_authorizes_specific_type_and_policy() {
  let temp_dir = common::TempDir::new("admin-query-cache-purge-ipm");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-query-cache-purge-ipm");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = admin_listener_exact_purge_ipm_config(&cert_path, &key_path, addr);
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  seed_cache_entry(&snapshot, "/query/exact", Some("release-1"));
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

  let response = admin_query_purge_response(
    addr,
    "/cache/purge?policy=default&scheme=http&host=example.com&uri=/query/exact",
  )
  .await;
  assert!(
    response.starts_with("HTTP/1.1 200 OK") && response.contains("purged=1"),
    "exact purge should succeed with matching action and policy: {}",
    log_safe_text(&response)
  );

  for path in [
    "/cache/purge-prefix?policy=default&scheme=http&host=example.com&path_prefix=/query/",
    "/cache/purge-tag?policy=default&tag=release-1",
    "/cache/purge?policy=other&scheme=http&host=example.com&uri=/query/exact",
  ] {
    let response = admin_query_purge_response(addr, path).await;
    assert!(
      response.starts_with("HTTP/1.1 403 Forbidden")
        && response.contains(r#""code":"permission_denied""#),
      "query purge should reject unauthorized type or policy: {}",
      log_safe_text(&response)
    );
  }

  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn admin_ipm_request_context_applies_source_ip_deny() {
  let temp_dir = common::TempDir::new("admin-ipm-request-context");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-ipm-request-context");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = admin_listener_source_ip_deny_config(&cert_path, &key_path, addr);
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

  let response = admin_config_status_response(addr).await;
  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden"),
    "request.source_ip deny should reject local admin request: {}",
    log_safe_text(&response)
  );

  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn admin_metadata_endpoints_require_auth_and_ipm_permission() {
  let temp_dir = common::TempDir::new("admin-metadata-denied");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-metadata-denied");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = admin_listener_metadata_denied_config(&cert_path, &key_path, addr);
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

  let unauthenticated = admin_get_response(addr, "/admin/v1/openapi.json", false).await;
  assert!(
    unauthenticated.starts_with("HTTP/1.1 401 Unauthorized")
      && unauthenticated.contains(r#""code":"unauthorized""#)
      && unauthenticated.contains(r#""request_id":""#),
    "metadata without auth should be rejected: {}",
    log_safe_text(&unauthenticated)
  );

  let forbidden = admin_get_response(addr, "/admin/v1/openapi.json", true).await;
  assert!(
    forbidden.starts_with("HTTP/1.1 403 Forbidden")
      && forbidden.contains(r#""code":"permission_denied""#)
      && forbidden.contains(r#""action":"admin:ReadMetadata""#)
      && forbidden.contains(r#""resource":"oxibelt:oxibelt:admin:metadata/openapi""#),
    "metadata without admin:ReadMetadata should be forbidden: {}",
    log_safe_text(&forbidden)
  );

  let _ = shutdown.send(true);
  task.abort();
}

#[tokio::test]
async fn admin_metadata_endpoints_return_openapi_capabilities_and_version() {
  let temp_dir = common::TempDir::new("admin-metadata-reader");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-metadata-reader");
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("admin listener should bind");
  let addr = listener
    .local_addr()
    .expect("admin listener address should be available");
  let config = admin_listener_metadata_reader_config(&cert_path, &key_path, addr);
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

  let openapi = admin_get_response(addr, "/admin/v1/openapi.json", true).await;
  assert!(
    openapi.starts_with("HTTP/1.1 200 OK")
      && openapi
        .to_ascii_lowercase()
        .contains("content-type: application/json"),
    "OpenAPI response should be JSON: {}",
    log_safe_text(&openapi)
  );
  let openapi_body: serde_json::Value =
    serde_json::from_str(response_body(&openapi)).expect("OpenAPI response should parse as JSON");
  assert_eq!(openapi_body["openapi"], "3.1.0");

  let capabilities = admin_get_response(addr, "/admin/v1/capabilities", true).await;
  assert!(
    capabilities.starts_with("HTTP/1.1 200 OK"),
    "capabilities should succeed: {}",
    log_safe_text(&capabilities)
  );
  let capabilities_body: serde_json::Value = serde_json::from_str(response_body(&capabilities))
    .expect("capabilities response should parse as JSON");
  assert_eq!(capabilities_body["api_version"], "v1");
  assert_eq!(
    capabilities_body["package_version"],
    oxibelt_build_identity::SHORT_VERSION
  );
  assert_eq!(
    capabilities_body["limits"]["admin_json_body_bytes"],
    64 * 1024
  );
  assert!(capabilities_body["features"]["waf_devtools"].as_bool() == Some(true));

  let version = admin_get_response(addr, "/admin/v1/version", true).await;
  assert!(
    version.starts_with("HTTP/1.1 200 OK"),
    "version should succeed: {}",
    log_safe_text(&version)
  );
  let version_body: serde_json::Value =
    serde_json::from_str(response_body(&version)).expect("version response should parse as JSON");
  assert_eq!(version_body["api_version"], "v1");
  assert_eq!(version_body["package_name"], env!("CARGO_PKG_NAME"));
  assert_eq!(
    version_body["package_version"],
    oxibelt_build_identity::SHORT_VERSION
  );
  super::admin_metadata_assertions::assert_embedded_build_metadata(&version_body);

  let _ = shutdown.send(true);
  task.abort();
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
  parse_config(&raw)
}

fn admin_listener_metadata_denied_config(
  cert_path: &Path,
  key_path: &Path,
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

[ipm]
enabled = true

[[ipm.principals]]
id = "metadata-reader"
subject = "metadata-reader@example.com"

[[ipm.credentials]]
name = "metadata-token"
principal = "metadata-reader"
bearer_token_env = "{ADMIN_TOKEN_ENV}"

[[ipm.policies]]
name = "config-status-only"

[[ipm.policies.statements]]
effect = "allow"
actions = ["config:GetStatus"]
resources = ["*"]

[[ipm.bindings]]
principal = "metadata-reader"
policy = "config-status-only"
"#
  ));
  parse_config(&raw)
}

fn admin_listener_metadata_reader_config(
  cert_path: &Path,
  key_path: &Path,
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

[ipm]
enabled = true

[[ipm.principals]]
id = "metadata-reader"
subject = "metadata-reader@example.com"

[[ipm.credentials]]
name = "metadata-token"
principal = "metadata-reader"
bearer_token_env = "{ADMIN_TOKEN_ENV}"

[[ipm.policies]]
name = "metadata-read"

[[ipm.policies.statements]]
effect = "allow"
actions = ["admin:ReadMetadata"]
resources = ["oxibelt:oxibelt:admin:metadata/*"]

[[ipm.bindings]]
principal = "metadata-reader"
policy = "metadata-read"
"#
  ));
  parse_config(&raw)
}

fn admin_listener_exact_purge_ipm_config(
  cert_path: &Path,
  key_path: &Path,
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

[cache]
enabled = true
store = "memory"
cache_methods = ["GET"]

[admin]
enabled = true
bind = "{admin_bind}"
bearer_token_env = "{ADMIN_TOKEN_ENV}"
transport = "plaintext_allowlist"

[ipm]
enabled = true

[[ipm.principals]]
id = "purger"
subject = "purger@example.com"

[[ipm.credentials]]
name = "purge-token"
principal = "purger"
bearer_token_env = "{ADMIN_TOKEN_ENV}"

[[ipm.policies]]
name = "exact-default"

[[ipm.policies.statements]]
effect = "allow"
actions = ["cache:PurgeObject"]
resources = [
  "oxibelt:oxibelt:cache:policy/default",
  "oxibelt:oxibelt:cache:host/example.com",
]

[[ipm.bindings]]
principal = "purger"
policy = "exact-default"
"#
  ));
  parse_config(&raw)
}

fn admin_listener_source_ip_deny_config(
  cert_path: &Path,
  key_path: &Path,
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

[ipm]
enabled = true

[[ipm.principals]]
id = "deployer"
subject = "deployer@example.com"

[[ipm.credentials]]
name = "deployer-token"
principal = "deployer"
bearer_token_env = "{ADMIN_TOKEN_ENV}"

[[ipm.policies]]
name = "config-local-network"

[[ipm.policies.statements]]
effect = "allow"
actions = ["config:*"]
resources = ["*"]

[[ipm.policies.statements]]
effect = "deny"
actions = ["config:*"]
resources = ["*"]
conditions = [
  {{ operator = "NotIpAddress", key = "request.source_ip", values = ["10.0.0.0/8"] }}
]

[[ipm.bindings]]
principal = "deployer"
policy = "config-local-network"
"#
  ));
  parse_config(&raw)
}

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

fn seed_cache_entry(snapshot: &AppSnapshot, uri: &str, tag: Option<&str>) {
  let uri = uri.parse::<::http::Uri>().expect("cache URI should parse");
  let mut headers = HeaderMap::new();
  headers.insert(
    ::http::header::CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  if let Some(tag) = tag {
    headers.insert("surrogate-key", HeaderValue::from_str(tag).unwrap());
  }
  assert_eq!(
    snapshot.cache.insert(
      crate::cache::CacheInsertContext {
        policy_name: Some("default"),
        scheme: "http",
        host: "example.com",
        method: &::http::Method::GET,
        uri: &uri,
        request_headers: &HeaderMap::new(),
      },
      crate::cache::CacheEntry::memory(
        StatusCode::OK,
        headers,
        bytes::Bytes::from_static(b"cached")
      ),
    ),
    crate::cache::CacheInsertOutcome::Stored
  );
}

async fn admin_json_purge_response(addr: SocketAddr, body: &str) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin JSON purge connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let request = format!(
    "POST /admin/v1/cache/purge HTTP/1.1\r\n\
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
    .expect("admin JSON purge request should write");
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

async fn admin_query_purge_response(addr: SocketAddr, path: &str) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin query purge connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let request = format!(
    "POST {path} HTTP/1.1\r\n\
     Host: admin\r\n\
     Authorization: Bearer {token}\r\n\
     Content-Length: 0\r\n\
     Connection: close\r\n\
     \r\n"
  );
  stream
    .write_all(request.as_bytes())
    .await
    .expect("admin query purge request should write");
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

async fn admin_get_response(addr: SocketAddr, path: &str, include_auth: bool) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin GET connection should open");
  let auth = if include_auth {
    let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
    format!("Authorization: Bearer {token}\r\n")
  } else {
    String::new()
  };
  let request = format!(
    "GET {path} HTTP/1.1\r\n\
     Host: admin\r\n\
     {auth}\
     Connection: close\r\n\
     \r\n"
  );
  stream
    .write_all(request.as_bytes())
    .await
    .expect("admin GET request should write");
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

async fn admin_config_status_response(addr: SocketAddr) -> String {
  let mut stream = TcpStream::connect(addr)
    .await
    .expect("admin config status connection should open");
  let token = std::env::var(ADMIN_TOKEN_ENV).expect("admin token should be available");
  let request = format!(
    "GET /admin/v1/config/status HTTP/1.1\r\n\
     Host: Admin.Example.COM:9443\r\n\
     Authorization: Bearer {token}\r\n\
     Connection: close\r\n\
     \r\n"
  );
  stream
    .write_all(request.as_bytes())
    .await
    .expect("admin config status request should write");
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

fn response_body(response: &str) -> &str {
  response.split("\r\n\r\n").nth(1).unwrap_or("")
}

fn log_safe_text(input: &str) -> String {
  input.replace('\n', "\\n").replace('\r', "\\r")
}
