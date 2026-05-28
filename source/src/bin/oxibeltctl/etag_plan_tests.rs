use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use oxibelt::admin_client::{AdminClient, AdminClientOptions};
use url::Url;

use super::*;

#[test]
fn pool_mutation_fetches_current_etag_when_omitted() {
  let Some((client, request_thread)) =
    status_client(r#"{"generation":7,"etag":"\"oxibelt-upstream-pools-7\""}"#)
  else {
    return;
  };
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "pool",
    "update-server",
    "app-pool",
    "primary",
    "--state",
    "down",
  ])
  .expect("pool update should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");
  let request = request_thread.join().expect("status server should finish");

  assert_eq!(
    plan.if_match.as_deref(),
    Some("\"oxibelt-upstream-pools-7\"")
  );
  assert!(request.starts_with("GET /admin/v1/upstream-pools/status "));
}

#[test]
fn dynamic_policy_create_fetches_current_etag_when_omitted() {
  let json_file = write_temp_file(
    "dynamic-policy-create",
    r#"{
      "source": "oxibeltctl",
      "name": "block login",
      "action": "reject",
      "subject_type": "client_ip",
      "subject": "203.0.113.22"
    }"#,
  );
  let Some((client, request_thread)) = status_client(
    r#"{"namespace":"oxibelt","generation":3,"etag":"\"oxibelt-dynamic-policy-3\""}"#,
  ) else {
    let _ = std::fs::remove_file(&json_file);
    return;
  };
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "dynamic-policy",
    "create",
    "--json",
    json_file.to_str().expect("json path should be UTF-8"),
  ])
  .expect("dynamic-policy create should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");
  let request = request_thread.join().expect("status server should finish");
  let _ = std::fs::remove_file(&json_file);

  assert_eq!(
    plan.if_match.as_deref(),
    Some("\"oxibelt-dynamic-policy-3\"")
  );
  assert!(request.starts_with("GET /admin/v1/dynamic-policies/status "));
}

fn write_temp_file(label: &str, content: &str) -> std::path::PathBuf {
  let nanos = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("clock should be after Unix epoch")
    .as_nanos();
  let path = std::env::temp_dir().join(format!(
    "oxibeltctl-{label}-{}-{nanos}.json",
    std::process::id()
  ));
  std::fs::write(&path, content).expect("temp policy should be written");
  path
}

fn status_client(body: &'static str) -> Option<(AdminClient, thread::JoinHandle<String>)> {
  oxibelt::tls::install_default_provider().expect("provider");
  let listener = match TcpListener::bind("127.0.0.1:0") {
    Ok(listener) => listener,
    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
    Err(error) => panic!("status listener: {error}"),
  };
  let addr = listener.local_addr().expect("status listener address");
  let handle = thread::spawn(move || {
    let (mut stream, _) = listener.accept().expect("status request");
    stream
      .set_read_timeout(Some(Duration::from_secs(2)))
      .expect("read timeout");
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
      match stream.read(&mut buffer) {
        Ok(0) => break,
        Ok(n) => {
          request.extend_from_slice(&buffer[..n]);
          if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
          }
        }
        Err(error)
          if error.kind() == std::io::ErrorKind::WouldBlock
            || error.kind() == std::io::ErrorKind::TimedOut =>
        {
          break;
        }
        Err(error) => panic!("failed to read status request: {error}"),
      }
    }
    let response = format!(
      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
      body.len(),
      body
    );
    stream
      .write_all(response.as_bytes())
      .expect("status response");
    String::from_utf8_lossy(&request).into_owned()
  });
  let options = AdminClientOptions::new(
    Url::parse(&format!("http://{addr}")).expect("url"),
    "test-token".to_string(),
    Duration::from_secs(2),
  );
  Some((AdminClient::new(options).expect("client"), handle))
}
