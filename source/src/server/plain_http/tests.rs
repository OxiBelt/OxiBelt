use std::sync::Arc;
use std::time::Duration;

use super::parse::{ParseResult, ParsedPlainRequest, header_has_token, parse_buffered_request};
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

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
async fn header_only_waf_keeps_plain_static_sendfile_path() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-waf-header");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-waf-header");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "hello waf sendfile")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[waf]
enabled = true

[[waf.rules]]
name = "block-other"
phase = "request"
priority = 10
when = "Request.Http.Path == '/static/blocked.txt'"

[[waf.rules.actions]]
type = "reject"
status = 451
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
  assert!(response.ends_with("hello waf sendfile"));
}

#[tokio::test]
async fn request_waf_can_reject_plain_static_sendfile_request() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-waf-request-reject");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-waf-request-reject");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("blocked.txt"), "should not be sent")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[waf]
enabled = true

[[waf.rules]]
name = "block-static"
phase = "request"
priority = 10
when = "Request.Http.Path == '/static/blocked.txt'"

[[waf.rules.actions]]
type = "reject"
status = 451
body = "blocked by waf"
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
    .write_all(
      b"GET /static/blocked.txt HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
  let mut response = Vec::new();
  client.read_to_end(&mut response).await.unwrap();
  server.await.unwrap();
  let response = String::from_utf8(response).unwrap();

  assert!(response.starts_with("HTTP/1.1 451 "));
  assert!(response.ends_with("blocked by waf"));
  assert!(!response.contains("should not be sent"));
}

#[tokio::test]
async fn request_waf_uses_resolved_real_ip_on_plain_static_sendfile() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-real-ip-request-waf");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-real-ip-request-waf");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "should not be sent")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[proxy.real_ip]
enabled = true
trusted_proxies = ["127.0.0.1/32"]
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = true

[waf]
enabled = true

[[waf.rules]]
name = "block-real-ip"
phase = "request"
priority = 10
when = "Request.Client.Ip.inCidr('203.0.113.0/24')"

[[waf.rules.actions]]
type = "reject"
status = 451
body = "real ip blocked"
"#,
  );

  let response = run_static_sendfile_request(
    &raw,
    b"GET /static/app.txt HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.10\r\nConnection: close\r\n\r\n",
  )
  .await;

  assert!(response.starts_with("HTTP/1.1 451 "));
  assert!(response.ends_with("real ip blocked"));
  assert!(!response.contains("should not be sent"));
}

#[tokio::test]
async fn response_waf_can_reject_plain_static_sendfile_before_file_body() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-waf-response-reject");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-waf-response-reject");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "large enough static body")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[waf]
enabled = true

[[waf.rules]]
name = "large-response"
phase = "response"
priority = 10
when = "Response.Body.Size > 8"

[[waf.rules.actions]]
type = "reject_response"
status = 502
body = "response blocked"
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

  assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
  assert!(response.ends_with("response blocked"));
  assert!(!response.contains("large enough static body"));
}

#[tokio::test]
async fn response_waf_uses_resolved_real_ip_on_plain_static_sendfile() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-real-ip-response-waf");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-real-ip-response-waf");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "should not be sent")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[proxy.real_ip]
enabled = true
trusted_proxies = ["127.0.0.1/32"]
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = true

[waf]
enabled = true

[[waf.rules]]
name = "block-real-ip-response"
phase = "response"
priority = 10
when = "Request.Client.Ip.inCidr('203.0.113.0/24')"

[[waf.rules.actions]]
type = "reject_response"
status = 502
body = "response real ip blocked"
"#,
  );

  let response = run_static_sendfile_request(
    &raw,
    b"GET /static/app.txt HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.10\r\nConnection: close\r\n\r\n",
  )
  .await;

  assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
  assert!(response.ends_with("response real ip blocked"));
  assert!(!response.contains("should not be sent"));
}

#[tokio::test]
async fn untrusted_real_ip_metadata_rejected_on_plain_static_sendfile() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-real-ip-untrusted");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-real-ip-untrusted");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "should not be sent")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[proxy.real_ip]
enabled = true
trusted_proxies = ["10.0.0.0/8"]
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = true
"#,
  );

  let response = run_static_sendfile_request(
    &raw,
    b"GET /static/app.txt HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.10\r\nConnection: close\r\n\r\n",
  )
  .await;

  assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
  assert!(response.ends_with("untrusted forwarded client IP metadata"));
  assert!(!response.contains("should not be sent"));
}

#[tokio::test]
async fn response_waf_header_mutation_applies_to_plain_static_sendfile() {
  if !kernel_sendfile_available_or_skip() {
    return;
  }

  let temp_dir = common::TempDir::new("plain-sendfile-waf-response-header");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-waf-response-header");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "header mutation body")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[waf]
enabled = true

[[waf.rules]]
name = "mark-response"
phase = "response"
priority = 10
when = "Response.Http.Status == 200"

[[waf.rules.actions]]
type = "set_response_header"
name = "x-static-waf"
value = "yes"
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
  assert!(response.contains("x-static-waf: yes\r\n"));
  assert!(response.ends_with("header mutation body"));
}

#[tokio::test]
async fn prefix_body_waf_static_route_falls_back_to_hyper_path() {
  let temp_dir = common::TempDir::new("plain-sendfile-waf-prefix-fallback");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-sendfile-waf-prefix-fallback");
  let root = temp_dir.path().join("public");
  tokio::fs::create_dir_all(&root).await.unwrap();
  tokio::fs::write(root.join("app.txt"), "fallback body")
    .await
    .unwrap();
  let raw = static_sendfile_config_toml(
    &cert_path,
    &key_path,
    &root,
    r#"

[waf]
enabled = true

[[waf.rules]]
name = "prefix"
phase = "request"
priority = 10
when = "Request.Body.contains('secret')"

[[waf.rules.actions]]
type = "reject"
status = 403
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
    let (_shutdown_tx, mut shutdown) = watch::channel(false);
    let (_drain_tx, mut drain) = watch::channel(false);
    match try_sendfile_fast_path(
      stream,
      peer_addr,
      &snapshot,
      WafTransportMetadataInput::default(),
      &mut shutdown,
      &mut drain,
    )
    .await
    .unwrap()
    {
      SendfilePreflight::Continue {
        served_requests, ..
      } => assert_eq!(served_requests, 0),
      SendfilePreflight::Done => panic!("prefix-body WAF should fall back to Hyper"),
    }
  });

  let mut client = TcpStream::connect(addr).await.unwrap();
  client
    .write_all(b"GET /static/app.txt HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    .await
    .unwrap();
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
