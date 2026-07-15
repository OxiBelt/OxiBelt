use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use clap::Parser;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, DEFAULT_ADMIN_URL};
use url::Url;

use super::*;
use crate::cli::{Cli, Command, OutputFormat};

#[test]
fn rulepack_apply_dry_run_is_not_mutating_admin_plan() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--file",
    "vaultwarden.oxirule-rulepack.toml",
    "--dry-run",
  ])
  .expect("rulepack dry-run command should parse");
  let Command::Rulepack(command) = parsed.command else {
    panic!("expected rulepack command");
  };
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let error = match runtime.block_on(plan_rulepack(&dummy_client(), &command)) {
    Ok(_) => panic!("dry-run should not build a file-sync request"),
    Err(error) => error,
  };

  assert!(error.to_string().contains("--dry-run"));
}

#[test]
fn rulepack_apply_dry_run_does_not_file_sync_or_verify_active() {
  let source = TempTree::new().expect("source temp");
  let path = source.path().join("dry-run.oxirule-rulepack.toml");
  std::fs::write(
    &path,
    r#"[rulepack]
schema_version = 2
name = "dry-run-demo"
version = "0.1.0"

[[rules]]
name = "dry-run-rule"
phase = "request"
priority = 100
content = '''
when = "true"

[[actions]]
type = "log"
'''
"#,
  )
  .expect("write dry-run rulepack");

  let Some((client, handle)) = dry_run_admin_server(1, "200 OK") else {
    return;
  };
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--file",
    path.to_str().expect("UTF-8 path"),
    "--dry-run",
  ])
  .expect("rulepack dry-run command should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");

  assert!(
    runtime
      .block_on(run_remote_if_requested(
        &client,
        &parsed.command,
        OutputFormat::Json,
      ))
      .expect("dry-run should finish"),
    "dry-run should be handled"
  );
  let requests = handle.join().expect("dry-run server thread");
  assert!(
    requests
      .iter()
      .any(|request| request.starts_with("POST /admin/v1/waf/rulepacks/plan ")),
    "dry-run should use the Admin rulepack plan endpoint, got {requests:?}"
  );
  assert!(
    requests
      .iter()
      .all(|request| !request.starts_with("POST /admin/v1/files/sync ")),
    "dry-run must not call file sync, got {requests:?}"
  );
}

#[test]
fn rulepack_apply_dry_run_falls_back_when_admin_plan_is_unavailable() {
  let source = TempTree::new().expect("source temp");
  let path = source.path().join("dry-run-fallback.oxirule-rulepack.toml");
  std::fs::write(
    &path,
    r#"[rulepack]
schema_version = 2
name = "dry-run-fallback"
version = "0.1.0"

[[rules]]
name = "dry-run-rule"
phase = "request"
priority = 100
content = '''
when = "true"

[[actions]]
type = "log"
'''
"#,
  )
  .expect("write dry-run rulepack");

  let Some((client, handle)) = dry_run_admin_server(4, "404 Not Found") else {
    return;
  };
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rulepack",
    "apply",
    "--file",
    path.to_str().expect("UTF-8 path"),
    "--dry-run",
  ])
  .expect("rulepack dry-run command should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");

  assert!(
    runtime
      .block_on(run_remote_if_requested(
        &client,
        &parsed.command,
        OutputFormat::Json,
      ))
      .expect("dry-run should finish"),
    "dry-run should be handled"
  );
  let requests = handle.join().expect("dry-run fallback server thread");
  assert!(
    requests
      .iter()
      .any(|request| request.starts_with("POST /admin/v1/waf/rulepacks/plan ")),
    "dry-run should try the Admin rulepack plan endpoint first, got {requests:?}"
  );
  assert!(
    requests
      .iter()
      .any(|request| request.starts_with("GET /admin/v1/config/effective ")),
    "fallback should read effective config, got {requests:?}"
  );
  assert!(
    requests
      .iter()
      .any(|request| request.starts_with("GET /admin/v1/waf/rulepacks ")),
    "fallback should fetch active summaries for diff, got {requests:?}"
  );
  assert!(
    requests
      .iter()
      .any(|request| request.starts_with("POST /admin/v1/waf/oxirule/cost ")),
    "fallback should run the non-mutating cost probe, got {requests:?}"
  );
  assert!(
    requests
      .iter()
      .all(|request| !request.starts_with("POST /admin/v1/files/sync ")),
    "dry-run must not call file sync, got {requests:?}"
  );
}

fn dummy_client() -> AdminClient {
  oxibelt::tls::install_default_provider().expect("provider");
  let options = AdminClientOptions::new(
    Url::parse(DEFAULT_ADMIN_URL).expect("default URL"),
    "dummy-token".to_string(),
    Duration::from_millis(10),
  );
  AdminClient::new(options).expect("dummy client")
}

fn dry_run_admin_server(
  expected_requests: usize,
  plan_status: &'static str,
) -> Option<(AdminClient, thread::JoinHandle<Vec<String>>)> {
  oxibelt::tls::install_default_provider().expect("provider");
  let listener = match TcpListener::bind("127.0.0.1:0") {
    Ok(listener) => listener,
    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
    Err(error) => panic!("dry-run listener: {error}"),
  };
  let addr = listener.local_addr().expect("dry-run listener address");
  let handle = thread::spawn(move || {
    let mut requests = Vec::new();
    for _ in 0..expected_requests {
      let (mut stream, _) = listener.accept().expect("dry-run request");
      stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("dry-run read timeout");
      let request = read_http_request(&mut stream);
      let (status, body) = dry_run_response(&request, plan_status);
      let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
      );
      stream
        .write_all(response.as_bytes())
        .expect("dry-run response");
      requests.push(request);
    }
    requests
  });
  let options = AdminClientOptions::new(
    Url::parse(&format!("http://{addr}")).expect("dry-run URL"),
    "test-token".to_string(),
    Duration::from_secs(2),
  );
  Some((AdminClient::new(options).expect("dry-run client"), handle))
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
  let mut request = Vec::new();
  let mut buffer = [0_u8; 1024];
  loop {
    match stream.read(&mut buffer) {
      Ok(0) => break,
      Ok(n) => {
        request.extend_from_slice(&buffer[..n]);
        if complete_http_request(&request) {
          break;
        }
      }
      Err(error)
        if error.kind() == std::io::ErrorKind::WouldBlock
          || error.kind() == std::io::ErrorKind::TimedOut =>
      {
        break;
      }
      Err(error) => panic!("failed to read dry-run request: {error}"),
    }
  }
  String::from_utf8_lossy(&request).into_owned()
}

fn complete_http_request(request: &[u8]) -> bool {
  let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
    return false;
  };
  let headers = String::from_utf8_lossy(&request[..header_end]);
  let content_length = headers
    .lines()
    .find_map(|line| line.split_once(':'))
    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
    .unwrap_or(0);
  request.len() >= header_end + 4 + content_length
}

fn dry_run_response(request: &str, plan_status: &'static str) -> (&'static str, &'static str) {
  if request.starts_with("POST /admin/v1/waf/rulepacks/plan ") {
    (
      plan_status,
      r#"{"ok":true,"rulepack":"dry-run-demo","required_inputs":[],"route_candidates":[],"rendered_manifest":"","install_plan":{"ready":true,"will_put":["rulepacks/dry-run-demo.oxirule-rulepack.toml"],"will_reload":"oxirule","mode":"monitor","bindings":{},"values_count":0,"endpoint":"/admin/v1/files/sync"},"diff":{"added_rules":1,"changed_rules":0,"deleted_rules":0,"basis":"new_install","planned_version":"0.1.0"},"risk":{"terminal_actions":[],"body_inspection":false,"response_inspection":false,"estimated_cost":"low"},"cost_warnings":[],"warnings":[],"permission_hints":["waf:PutOxiRulePack","waf:ReloadOxiRule"]}"#,
    )
  } else if request.starts_with("GET /admin/v1/config/effective ") {
    ("200 OK", r#"{"config":""}"#)
  } else if request.starts_with("GET /admin/v1/waf/rulepacks ") {
    ("200 OK", r#"{"rulepacks":[]}"#)
  } else if request.starts_with("POST /admin/v1/waf/oxirule/cost ") {
    (
      "200 OK",
      r#"{"ok":true,"body_need":{"request_body":"none","response_body":"none"},"cost_warnings":[]}"#,
    )
  } else {
    ("200 OK", r#"{"error":"unexpected dry-run request"}"#)
  }
}
