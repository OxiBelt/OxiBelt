use std::time::Duration;

use clap::Parser;
use http::Method;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, DEFAULT_ADMIN_URL};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

use super::*;

#[test]
fn ipm_status_uses_status_endpoint_and_permission() {
  let command = Command::Ipm(IpmCommand {
    command: IpmSubcommand::Status,
  });
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &command))
    .expect("plan");

  assert_eq!(plan.method, Method::GET);
  assert_eq!(plan.endpoint, "/admin/v1/ipm/status");
  assert_eq!(plan.permission.action, "ipm:GetStatus");
  assert_eq!(plan.permission.resources, vec!["status/current"]);
}

#[test]
fn ipm_principal_list_builds_pagination_query_endpoint() {
  let command = Command::Ipm(IpmCommand {
    command: IpmSubcommand::Principal(IpmPrincipalCommand {
      command: IpmPrincipalSubcommand::List(ListQueryArgs {
        limit: Some(25),
        cursor: None,
        sort: Some("subject".to_string()),
        order: Some("desc".to_string()),
        filters: vec!["group=deployers".to_string(), "enabled=true".to_string()],
      }),
    }),
  });
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &command))
    .expect("plan");

  assert_eq!(plan.method, Method::GET);
  assert_eq!(
    plan.endpoint,
    "/admin/v1/ipm/principals?limit=25&sort=subject&order=desc&filter%5Bgroup%5D=deployers&filter%5Benabled%5D=true"
  );
  assert_eq!(plan.permission.action, "ipm:ListPrincipals");
}

#[test]
fn ipm_simulate_target_and_context_build_extended_body() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "ipm",
    "simulate",
    "--action",
    "config:Load",
    "--resource",
    "oxibelt:oxibelt:config:*",
    "--principal",
    "deployer",
    "--group",
    "deployers",
    "--source-ip",
    "10.0.0.5",
    "--method",
    "POST",
    "--claim",
    "env=prod",
  ])
  .expect("ipm simulate should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.method, Method::POST);
  assert_eq!(plan.endpoint, "/admin/v1/ipm/simulate");
  assert_eq!(plan.permission.action, "ipm:SimulatePrincipal");
  assert_eq!(
    plan.permission.resources,
    vec![
      "simulation/current",
      "principal/deployer",
      "group/deployers"
    ]
  );
  assert_eq!(
    plan.body,
    Some(json!({
      "action": "config:Load",
      "resource": "oxibelt:oxibelt:config:*",
      "target": {
        "principal": "deployer",
        "groups": ["deployers"],
      },
      "context": {
        "source_ip": "10.0.0.5",
        "method": "POST",
        "claims": { "env": "prod" },
      }
    }))
  );
}

#[test]
fn ipm_simulate_overlay_file_hints_policy_resources() {
  let overlay = tempfile::Builder::new()
    .prefix("oxibeltctl-ipm-overlay-")
    .suffix(".json")
    .tempfile()
    .expect("overlay fixture file should be created");
  std::fs::write(
    overlay.path(),
    r#"{"policies":[{"name":"deny-load","statements":[{"effect":"deny","actions":["config:Load"],"resources":["*"]}]}],"bindings":[{"group":"deployers","policy":"deny-load"}]}"#,
  )
  .expect("overlay fixture should be writable");
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "ipm",
    "simulate",
    "--action",
    "config:Load",
    "--resource",
    "oxibelt:oxibelt:config:*",
    "--overlay",
    overlay.path().to_str().expect("path should be utf-8"),
  ])
  .expect("ipm simulate overlay should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.permission.action, "ipm:SimulatePolicy");
  assert_eq!(
    plan.permission.resources,
    vec![
      "simulation/current",
      "policy/deny-load",
      "binding/group.deployers.deny-load",
      "group/deployers"
    ]
  );
  assert_eq!(
    plan.body,
    Some(json!({
      "action": "config:Load",
      "resource": "oxibelt:oxibelt:config:*",
      "overlay": {
        "policies": [{
          "name": "deny-load",
          "statements": [{
            "effect": "deny",
            "actions": ["config:Load"],
            "resources": ["*"],
          }],
        }],
        "bindings": [{
          "group": "deployers",
          "policy": "deny-load",
        }],
      }
    }))
  );
}

#[test]
fn ipm_credential_rotate_uses_default_overlap_and_explicit_etag() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "ipm",
    "credential",
    "rotate",
    "admin-token",
    "--expires",
    "7d",
    "--etag",
    "ipm-etag-1",
  ])
  .expect("credential rotate should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.method, Method::POST);
  assert_eq!(
    plan.endpoint,
    "/admin/v1/ipm/credentials/admin-token/rotate"
  );
  assert_eq!(plan.if_match, Some("ipm-etag-1".to_string()));
  assert_eq!(plan.permission.action, "ipm:RotateCredential");
  assert_eq!(plan.permission.resources, vec!["credential/admin-token"]);
  assert_eq!(
    plan.body,
    Some(json!({
      "overlap_seconds": 86_400,
      "ttl_seconds": 604_800,
      "no_expiry": false,
    }))
  );
}

#[test]
fn ipm_credential_create_hints_credential_and_principal_resources() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "ipm",
    "credential",
    "create",
    "deploy-token",
    "--principal",
    "deployer",
    "--expires",
    "1h",
    "--etag",
    "ipm-etag-1",
  ])
  .expect("credential create should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.permission.action, "ipm:CreateCredential");
  assert_eq!(
    plan.permission.resources,
    vec!["credential/deploy-token", "principal/deployer"]
  );
}

#[test]
fn ipm_credential_patch_hints_target_principal_when_moving() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "ipm",
    "credential",
    "patch",
    "deploy-token",
    "--principal",
    "release-admin",
    "--etag",
    "ipm-etag-1",
  ])
  .expect("credential patch should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.permission.action, "ipm:UpdateCredential");
  assert_eq!(
    plan.permission.resources,
    vec!["credential/deploy-token", "principal/release-admin"]
  );
}

#[test]
fn ipm_binding_create_hints_binding_subject_and_policy_resources() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "ipm",
    "binding",
    "create",
    "--group",
    "platform-admins",
    "--policy",
    "admin-full-access",
    "--etag",
    "ipm-etag-1",
  ])
  .expect("binding create should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.permission.action, "ipm:CreateBinding");
  assert_eq!(
    plan.permission.resources,
    vec![
      "binding/group.platform-admins.admin-full-access",
      "group/platform-admins",
      "policy/admin-full-access"
    ]
  );
}

#[test]
fn ipm_credential_create_requires_expiry_or_no_expiry() {
  let missing = Cli::try_parse_from([
    "oxibeltctl",
    "ipm",
    "credential",
    "create",
    "admin-token",
    "--principal",
    "admin",
  ]);
  assert!(missing.is_err(), "credential create should require expiry");

  let no_expiry = Cli::try_parse_from([
    "oxibeltctl",
    "ipm",
    "credential",
    "create",
    "admin-token",
    "--principal",
    "admin",
    "--no-expiry",
  ]);
  assert!(
    no_expiry.is_ok(),
    "credential create should accept --no-expiry"
  );
}

#[test]
fn ipm_mutations_fetch_etag_when_omitted() {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  runtime.block_on(async {
    let Ok((url, request_rx)) = spawn_ipm_status_server("ipm-etag-auto").await else {
      return;
    };
    let options = AdminClientOptions::new(
      Url::parse(&url).expect("url"),
      "test-token".to_string(),
      Duration::from_secs(1),
    );
    let client = AdminClient::new(options).expect("client");
    let parsed = Cli::try_parse_from(["oxibeltctl", "ipm", "principal", "delete", "stale-admin"])
      .expect("principal delete should parse");
    let plan = plan_command(&client, &parsed.command).await.expect("plan");
    let request = request_rx.await.expect("status request should be captured");

    assert_eq!(plan.method, Method::DELETE);
    assert_eq!(plan.endpoint, "/admin/v1/ipm/principals/stale-admin");
    assert_eq!(plan.if_match, Some("ipm-etag-auto".to_string()));
    assert!(
      request.starts_with("GET /admin/v1/ipm/status HTTP/1.1"),
      "unexpected request:\n{request}"
    );
  });
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

async fn spawn_ipm_status_server(
  etag: &str,
) -> std::io::Result<(String, oneshot::Receiver<String>)> {
  let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
  let address = listener.local_addr().expect("IPM status server address");
  let (request_tx, request_rx) = oneshot::channel();
  let etag = etag.to_string();
  tokio::spawn(async move {
    let (mut stream, _) = listener
      .accept()
      .await
      .expect("IPM status test server should accept");
    let request = read_http_request(&mut stream).await;
    let _ = request_tx.send(request);
    let body = json!({ "etag": etag }).to_string();
    let response = format!(
      "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
      body.len(),
      body
    );
    stream
      .write_all(response.as_bytes())
      .await
      .expect("IPM status test server should write response");
  });
  Ok((format!("http://{address}"), request_rx))
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
  let mut buffer = [0_u8; 1024];
  let mut received = Vec::new();
  loop {
    let read = stream
      .read(&mut buffer)
      .await
      .expect("IPM status test server should read request");
    if read == 0 {
      break;
    }
    received.extend_from_slice(&buffer[..read]);
    if received.windows(4).any(|window| window == b"\r\n\r\n") {
      break;
    }
    assert!(
      received.len() <= 8192,
      "IPM status request headers too large"
    );
  }
  String::from_utf8(received).expect("IPM status request should be UTF-8")
}
