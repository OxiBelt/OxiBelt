use std::sync::Arc;
use std::time::Duration;

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn parsed(raw: &[u8]) -> ParsedPlainRequest {
  match parse_buffered_request(raw, 16) {
    ParseResult::Complete {
      header_len,
      request,
    } => ParsedPlainRequest {
      method: request.method,
      target: request.target,
      version: request.version,
      headers: request.headers,
      raw: raw[..header_len].to_vec(),
      remaining: raw[header_len..].to_vec(),
    },
    _ => panic!("request should parse"),
  }
}

fn static_sendfile_config_toml(
  cert_path: &std::path::Path,
  key_path: &std::path::Path,
  root: &std::path::Path,
  extra: &str,
) -> String {
  format!(
    "{}{}{}",
    common::minimal_config_toml(cert_path, key_path)
      .replace(
        "[listeners]\n",
        "[listeners]\nhttp_bind = \"127.0.0.1:8080\"\nhttp_mode = \"proxy\"\n",
      )
      .replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      )
      .replace(
        "path_prefix = \"/\"\nupstream = \"app\"",
        &format!(
          "path_prefix = \"/static\"\nstatic_root = \"{}\"",
          root.display()
        ),
      ),
    r#"

[proxy.static_files]
sendfile = "auto"
"#,
    extra
  )
}

#[test]
fn parser_preserves_pipelined_bytes_for_fallback() {
  let request =
    parsed(b"GET /static/app.txt HTTP/1.1\r\nHost: example.test\r\n\r\nGET /next HTTP/1.1\r\n");

  assert_eq!(request.target, "/static/app.txt");
  assert_eq!(request.remaining, b"GET /next HTTP/1.1\r\n");
}

#[test]
fn header_token_matching_is_case_insensitive() {
  let request = parsed(
    b"GET /static/app.txt HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive, Upgrade\r\n\r\n",
  );

  assert!(header_has_token(&request.headers, CONNECTION, "upgrade"));
}

#[tokio::test]
async fn eligible_plain_static_get_uses_pre_hyper_sendfile_path() {
  let temp_dir = common::TempDir::new("plain-sendfile");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "plain-sendfile");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "hello sendfile")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(&cert_path, &key_path, &root, "");
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let snapshot = Arc::new(
    AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize"),
  );
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let server = tokio::spawn(async move {
    let (stream, peer_addr) = listener.accept().await.unwrap();
    let (_shutdown_tx, mut shutdown) = watch::channel(false);
    let (_drain_tx, mut drain) = watch::channel(false);
    let result = try_sendfile_fast_path(stream, peer_addr, &snapshot, &mut shutdown, &mut drain)
      .await
      .unwrap();
    assert!(matches!(result, SendfilePreflight::Done));
  });

  let mut client = TcpStream::connect(addr).await.unwrap();
  client
    .write_all(b"GET /static/app.txt HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    .await
    .unwrap();
  let mut response = Vec::new();
  client.read_to_end(&mut response).await.unwrap();
  server.await.unwrap();
  let response = String::from_utf8(response).unwrap();

  assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
  assert!(response.ends_with("hello sendfile"));
}

#[tokio::test]
async fn sendfile_fast_path_times_out_stalled_downstream_response() {
  const LARGE_FILE_BYTES: u64 = 1024 * 1024 * 1024;

  let temp_dir = common::TempDir::new("plain-sendfile-timeout");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-timeout");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  let large_file_path = root.join("large.bin");
  let large_file = tokio::fs::File::create(&large_file_path).await.unwrap();
  large_file.set_len(LARGE_FILE_BYTES).await.unwrap();
  drop(large_file);

  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[limits]
response_send_timeout_ms = 100
"#,
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let snapshot = Arc::new(
    AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize"),
  );
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let addr = listener.local_addr().unwrap();
  let server = tokio::spawn(async move {
    let (stream, peer_addr) = listener.accept().await.unwrap();
    socket2::SockRef::from(&stream)
      .set_send_buffer_size(4096)
      .unwrap();
    let (_shutdown_tx, mut shutdown) = watch::channel(false);
    let (_drain_tx, mut drain) = watch::channel(false);
    try_sendfile_fast_path(stream, peer_addr, &snapshot, &mut shutdown, &mut drain)
      .await
      .unwrap()
  });

  let mut client = TcpStream::connect(addr).await.unwrap();
  socket2::SockRef::from(&client)
    .set_recv_buffer_size(4096)
    .unwrap();
  client
    .write_all(b"GET /static/large.bin HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    .await
    .unwrap();

  let result = tokio::time::timeout(Duration::from_secs(5), server)
    .await
    .expect("stalled sendfile response should time out")
    .expect("server task should not panic");
  assert!(matches!(result, SendfilePreflight::Done));
}
