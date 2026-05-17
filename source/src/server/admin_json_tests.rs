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
  let task = tokio::spawn(serve_admin_listener(listener, addr, state, shutdown_rx));

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
    response.starts_with("HTTP/1.1 400 Bad Request"),
    "invalid JSON purge should be rejected: {}",
    log_safe_text(&response)
  );

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
      crate::cache::CacheEntry {
        status: StatusCode::OK,
        headers,
        body: bytes::Bytes::from_static(b"cached"),
      },
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

fn log_safe_text(input: &str) -> String {
  input.replace('\n', "\\n").replace('\r', "\\r")
}
