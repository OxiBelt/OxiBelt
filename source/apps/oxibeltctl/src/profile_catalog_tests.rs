use std::time::Duration;

use clap::Parser;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, DEFAULT_ADMIN_URL};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

use super::*;
use crate::test_support;

#[test]
fn mitigate_profile_url_renders_apply_policy_and_uses_profile_token_env() {
  const TOKEN_ENV: &str = "OXIBELT_TEST_PROFILE_TOKEN";
  if test_support::run_test_in_subprocess_with_env(
    "plan::profile_catalog_tests::mitigate_profile_url_renders_apply_policy_and_uses_profile_token_env",
    &[(TOKEN_ENV, "profile-token")],
  ) {
    return;
  }
  let catalog = r#"{
    "profiles": {
      "login-bruteforce": {
        "action": "reject",
        "path_prefix": "/identity",
        "status": 429,
        "code": "login.bruteforce",
        "ttl_seconds": 900,
        "reason": "login brute-force mitigation"
      }
    }
  }"#;
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let (profile_url, request_rx) = runtime.block_on(spawn_profile_server(catalog.to_string()));
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--profile-url",
    &profile_url,
    "--allow-insecure-profile-url",
    "--profile-token-env",
    TOKEN_ENV,
    "--profile-sha256",
    &sha256_hex(catalog.as_bytes()),
    "--source",
    "203.0.113.13",
  ])
  .expect("mitigate profile URL should parse");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");
  let request = runtime
    .block_on(request_rx)
    .expect("profile server should receive request");

  assert_request_header(&request, "authorization", "Bearer profile-token");
  assert!(
    !request.contains("test-token"),
    "profile request must not reuse the Admin API token"
  );
  assert_eq!(plan.endpoint, "/admin/v1/dynamic-policies/apply");
  assert_eq!(
    plan.body,
    Some(json!({
      "enabled": true,
      "priority": 100,
      "source": "oxibeltctl-profile",
      "name": "mitigate-login-bruteforce-client_ip_path-203-0-113-13--identity",
      "action": "reject",
      "subject_type": "client_ip_path",
      "subject": "203.0.113.13|/identity",
      "route_name": null,
      "path_prefix": "/identity",
      "method": null,
      "rate": null,
      "burst": null,
      "status": 429,
      "body": null,
      "reason": "login brute-force mitigation",
      "code": "login.bruteforce",
      "ttl_seconds": 900,
      "mode": "enforce",
    }))
  );
}

#[test]
fn mitigate_profile_url_requires_https_without_opt_in() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--profile-url",
    "http://127.0.0.1:1/profiles.json",
    "--source",
    "203.0.113.13",
  ])
  .expect("mitigate profile URL should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let error = match runtime.block_on(plan_command(&client, &parsed.command)) {
    Ok(_) => panic!("insecure profile URL should fail without opt-in"),
    Err(error) => error,
  };

  assert!(
    error.to_string().contains("--allow-insecure-profile-url"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn mitigate_profile_url_rejects_userinfo() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--profile-url",
    "https://user:secret@profiles.example.test/catalog.json",
    "--source",
    "203.0.113.13",
  ])
  .expect("mitigate profile URL should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let error = match runtime.block_on(plan_command(&client, &parsed.command)) {
    Ok(_) => panic!("profile URL userinfo should fail"),
    Err(error) => error,
  };

  assert!(
    error.to_string().contains("must not include username"),
    "unexpected error: {error:#}"
  );
}

#[test]
fn mitigate_profile_url_error_redacts_query_and_fragment() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--profile-url",
    "http://127.0.0.1:1/profiles.json?token=secret#fragment",
    "--allow-insecure-profile-url",
    "--source",
    "203.0.113.13",
  ])
  .expect("mitigate profile URL should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let error = match runtime.block_on(plan_command(&client, &parsed.command)) {
    Ok(_) => panic!("profile URL connection should fail"),
    Err(error) => error,
  };
  let rendered = format!("{error:#}");

  assert!(
    rendered.contains("http://127.0.0.1:1/profiles.json"),
    "unexpected error: {rendered}"
  );
  assert!(
    !rendered.contains("secret") && !rendered.contains("fragment"),
    "profile URL diagnostics should redact query and fragment: {rendered}"
  );
}

#[test]
fn mitigate_profile_url_rejects_sha256_mismatch() {
  let catalog = r#"{"profiles":{"login-bruteforce":{"action":"reject","ttl_seconds":60}}}"#;
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let (profile_url, _request_rx) = runtime.block_on(spawn_profile_server(catalog.to_string()));
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--profile-url",
    &profile_url,
    "--allow-insecure-profile-url",
    "--profile-sha256",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "--source",
    "203.0.113.13",
  ])
  .expect("mitigate profile URL should parse");
  let client = dummy_client();
  let error = match runtime.block_on(plan_command(&client, &parsed.command)) {
    Ok(_) => panic!("profile SHA-256 mismatch should fail"),
    Err(error) => error,
  };

  assert!(
    error.to_string().contains("SHA-256 mismatch"),
    "unexpected error: {error:#}"
  );
}

async fn spawn_profile_server(body: String) -> (String, oneshot::Receiver<String>) {
  let listener = TcpListener::bind(("127.0.0.1", 0))
    .await
    .expect("profile test server should bind");
  let address = listener.local_addr().expect("profile server address");
  let (request_tx, request_rx) = oneshot::channel();
  tokio::spawn(async move {
    let (mut stream, _) = listener
      .accept()
      .await
      .expect("profile test server should accept");
    let request = read_http_request(&mut stream).await;
    let _ = request_tx.send(request);
    let response = format!(
      "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
      body.len(),
      body
    );
    stream
      .write_all(response.as_bytes())
      .await
      .expect("profile test server should write response");
  });
  (format!("http://{address}/profiles.json"), request_rx)
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
  let mut buffer = [0_u8; 1024];
  let mut received = Vec::new();
  loop {
    let read = stream
      .read(&mut buffer)
      .await
      .expect("profile test server should read request");
    if read == 0 {
      break;
    }
    received.extend_from_slice(&buffer[..read]);
    if received.windows(4).any(|window| window == b"\r\n\r\n") {
      break;
    }
    assert!(received.len() <= 8192, "profile request headers too large");
  }
  String::from_utf8(received).expect("profile request should be UTF-8")
}

fn assert_request_header(request: &str, name: &str, expected_value: &str) {
  let found = request.lines().any(|line| {
    line.split_once(':').is_some_and(|(header, value)| {
      header.eq_ignore_ascii_case(name) && value.trim() == expected_value
    })
  });
  assert!(
    found,
    "expected request header {name}: {expected_value}, got:\n{request}"
  );
}

fn sha256_hex(bytes: &[u8]) -> String {
  let digest = Sha256::digest(bytes);
  let mut out = String::with_capacity(digest.len() * 2);
  for byte in digest {
    use std::fmt::Write;
    write!(&mut out, "{byte:02x}").expect("hex write should succeed");
  }
  out
}

fn dummy_client() -> AdminClient {
  oxibelt::tls::install_default_provider().expect("provider");
  let options = AdminClientOptions::new(
    Url::parse(DEFAULT_ADMIN_URL).expect("url"),
    "test-token".to_string(),
    Duration::from_secs(1),
  );
  AdminClient::new(options).expect("client")
}
