use std::sync::Arc;
use std::time::Duration;

use super::parse::{
  ParseResult, ParsedPlainRequest, header_has_token, parse_buffered_request,
  parse_buffered_request_with_static_target_filter,
};
use super::*;
use crate::config::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

mod sendfile_waf;

fn kernel_sendfile_available_or_skip() -> bool {
  let available = sendfile::kernel_sendfile_available();
  if !available {
    eprintln!("skipping plain HTTP sendfile fast-path test because kernel sendfile is unavailable");
  }
  available
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

fn static_sendfile_with_proxy_config_toml(
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
          "path_prefix = \"/static\"\nstatic_root = \"{}\"\n\n[[routes]]\nname = \"main-route\"\nhosts = [\"example.com\"]\npath_prefix = \"/\"\nupstream = \"app\"",
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

async fn run_static_sendfile_request(raw_config: &str, request: &[u8]) -> String {
  let config: Config = toml::from_str(raw_config).expect("config should parse");
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
    let result = try_sendfile_fast_path(
      stream,
      peer_addr,
      &snapshot,
      WafTransportMetadataInput::default(),
      &mut shutdown,
      &mut drain,
    )
    .await
    .unwrap();
    assert!(matches!(result, SendfilePreflight::Done));
  });

  let mut client = TcpStream::connect(addr).await.unwrap();
  client.write_all(request).await.unwrap();
  let mut response = Vec::new();
  client.read_to_end(&mut response).await.unwrap();
  server.await.unwrap();
  String::from_utf8(response).unwrap()
}

#[test]
fn parser_preserves_pipelined_bytes_for_fallback() {
  let request =
    parsed(b"GET /static/app.txt HTTP/1.1\r\nHost: example.test\r\n\r\nGET /next HTTP/1.1\r\n");

  assert_eq!(request.target, "/static/app.txt");
  assert_eq!(request.remaining, b"GET /next HTTP/1.1\r\n");
}

#[test]
fn parser_accepts_stack_sized_header_blocks() {
  let mut raw = b"GET /static/app.txt HTTP/1.1\r\n".to_vec();
  for index in 0..128 {
    raw.extend_from_slice(format!("X-Test-{index}: value\r\n").as_bytes());
  }
  raw.extend_from_slice(b"\r\n");

  match parse_buffered_request(&raw, 128) {
    ParseResult::Complete {
      header_len,
      request,
    } => {
      assert_eq!(request.target, "/static/app.txt");
      assert_eq!(header_len, raw.len());
      assert_eq!(request.headers.len(), 128);
    }
    _ => panic!("stack-sized header block should parse"),
  }
}

#[test]
fn parser_falls_back_before_headers_for_unmatched_static_target() {
  let raw = b"GET /perf/h1?body=ok HTTP/1.1\r\nHost: example.test\r\n\r\n";

  match parse_buffered_request_with_static_target_filter(raw, 16, &|target| {
    target.starts_with("/static")
  }) {
    ParseResult::Fallback(reason) => {
      assert_eq!(reason, "request target cannot match static sendfile route");
    }
    _ => panic!("non-static origin-form target should fall back before header conversion"),
  }
}

#[test]
fn parser_keeps_ambiguous_targets_on_static_preflight_path() {
  let raw = b"GET https://example.test/perf/h1 HTTP/1.1\r\nHost: example.test\r\n\r\n";

  match parse_buffered_request_with_static_target_filter(raw, 16, &|_| false) {
    ParseResult::Complete { request, .. } => {
      assert_eq!(request.target, "https://example.test/perf/h1");
    }
    _ => panic!("ambiguous target should keep the existing static preflight path"),
  }
}

#[test]
fn vectored_write_advance_tracks_head_and_body_progress() {
  let mut head = &b"head"[..];
  let mut body = &b"body"[..];

  advance_vectored_write(&mut head, &mut body, 2);
  assert_eq!(head, b"ad");
  assert_eq!(body, b"body");

  advance_vectored_write(&mut head, &mut body, 3);
  assert!(head.is_empty());
  assert_eq!(body, b"ody");

  advance_vectored_write(&mut head, &mut body, 99);
  assert!(head.is_empty());
  assert!(body.is_empty());
}

#[tokio::test]
async fn non_static_origin_form_request_falls_back_without_route_resolution() {
  let temp_dir = common::TempDir::new("plain-sendfile-non-static-bypass");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-non-static-bypass");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "hello sendfile")
    .await
    .unwrap();
  let raw = static_sendfile_with_proxy_config_toml(&cert_path, &key_path, &root, "");
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
    match try_sendfile_fast_path_inner(
      stream,
      peer_addr,
      &snapshot,
      WafTransportMetadataInput::default(),
      &mut shutdown,
      &mut drain,
      true,
    )
    .await
    .unwrap()
    {
      SendfilePreflight::Continue {
        io,
        served_requests,
      } => {
        assert_eq!(served_requests, 0);
        assert_eq!(
          io.prefix_for_tests(),
          b"GET /perf/h1?body=ok HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );
      }
      SendfilePreflight::Done => panic!("non-static request should fall back to Hyper"),
    }
  });

  let mut client = TcpStream::connect(addr).await.unwrap();
  client
    .write_all(b"GET /perf/h1?body=ok HTTP/1.1\r\nHost: example.com\r\n\r\n")
    .await
    .unwrap();
  server.await.unwrap();
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
  if !kernel_sendfile_available_or_skip() {
    return;
  }

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
    let result = try_sendfile_fast_path(
      stream,
      peer_addr,
      &snapshot,
      WafTransportMetadataInput::default(),
      &mut shutdown,
      &mut drain,
    )
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
async fn eligible_plain_static_get_uses_hot_object_cache_when_enabled() {
  let temp_dir = common::TempDir::new("plain-sendfile-hot-cache");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-hot-cache");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "cached sendfile")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"
open_file_cache_max_entries = 8
open_file_cache_ttl_ms = 10000
hot_object_cache_max_bytes = 65536
hot_object_cache_max_file_bytes = 65536
"#,
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let request = parsed(b"GET /static/app.txt HTTP/1.1\r\nHost: example.com\r\n\r\n");

  let plan = eligible_static_plan(
    &request,
    &snapshot,
    "127.0.0.1:12345".parse().unwrap(),
    WafTransportMetadataInput::default(),
  )
  .await
  .expect("plain static request should be eligible");

  match plan.response.body {
    StaticBodyPlan::Bytes(bytes) => assert_eq!(bytes.as_ref(), b"cached sendfile"),
    other => panic!("expected cached bytes body, got {other:?}"),
  }
}

#[tokio::test]
async fn security_headers_are_preserved_on_plain_static_sendfile_path() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-security-headers");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-security-headers");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "secure sendfile")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[security.headers]
hsts = true
hsts_max_age_seconds = 63072000
hsts_include_subdomains = true
hsts_preload = true
x_content_type_options = "nosniff"
referrer_policy = "no-referrer"
permissions_policy = "geolocation=(), camera=()"
"#,
  );

  let response = run_static_sendfile_request(
    &raw,
    b"GET /static/app.txt HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
  )
  .await;

  assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
  assert!(
    response
      .contains("strict-transport-security: max-age=63072000; includeSubDomains; preload\r\n")
  );
  assert!(response.contains("x-content-type-options: nosniff\r\n"));
  assert!(response.contains("referrer-policy: no-referrer\r\n"));
  assert!(response.contains("permissions-policy: geolocation=(), camera=()\r\n"));
  assert!(response.ends_with("secure sendfile"));
}

#[tokio::test]
async fn route_static_options_apply_on_plain_static_sendfile_path() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-route-static-options");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-route-static-options");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.css"), "body { color: black; }")
    .await
    .unwrap();
  tokio::fs::write(root.join("app.css.br"), "compressed css")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[routes.static_files]
precompressed = ["br", "gzip"]
cache_control = "public, max-age=60"

[routes.static_files.mime_overrides]
css = "text/custom-css"
"#,
  );

  let response = run_static_sendfile_request(
    &raw,
    b"GET /static/app.css HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip;q=1, br;q=1\r\nConnection: close\r\n\r\n",
  )
  .await;

  assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
  assert!(response.contains("content-type: text/custom-css\r\n"));
  assert!(response.contains("content-encoding: br\r\n"));
  assert!(response.contains("cache-control: public, max-age=60\r\n"));
  assert!(response.contains("vary: Accept-Encoding\r\n"));
  assert!(response.ends_with("compressed css"));
}

#[tokio::test]
async fn system_access_log_keeps_plain_static_sendfile_path() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-system-access-log");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-system-access-log");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "logged sendfile")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[logging.access_log]
enabled = true
stdout = false
"#,
  );

  let response = run_static_sendfile_request(
    &raw,
    b"GET /static/app.txt HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
  )
  .await;

  assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
  assert!(response.ends_with("logged sendfile"));
}

#[tokio::test]
async fn kernel_sendfile_unavailable_skips_pre_hyper_path_before_request_read() {
  let temp_dir = common::TempDir::new("plain-sendfile-unavailable");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-unavailable");
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
    match try_sendfile_fast_path_inner(
      stream,
      peer_addr,
      &snapshot,
      WafTransportMetadataInput::default(),
      &mut shutdown,
      &mut drain,
      false,
    )
    .await
    .unwrap()
    {
      SendfilePreflight::Continue {
        served_requests, ..
      } => assert_eq!(served_requests, 0),
      SendfilePreflight::Done => panic!("unavailable kernel sendfile should fall back to Hyper"),
    }
  });

  let _client = TcpStream::connect(addr).await.unwrap();
  server.await.unwrap();
}

#[tokio::test]
async fn sendfile_fast_path_times_out_stalled_downstream_response() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

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
    try_sendfile_fast_path(
      stream,
      peer_addr,
      &snapshot,
      WafTransportMetadataInput::default(),
      &mut shutdown,
      &mut drain,
    )
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
