use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use http::Method;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, DEFAULT_ADMIN_URL};
use oxibelt::diagnostics::{DoctorFailOn, DoctorOutputFormat, ExternalProbeKind};
use serde_json::json;
use url::Url;

use super::*;

#[test]
fn auth_check_uses_ipm_simulate_shape() {
  let command = Command::Auth(AuthCommand {
    command: AuthSubcommand::Check(AuthCheckArgs {
      action: "config:GetStatus".to_string(),
      resource: "*".to_string(),
      source_ip: None,
      method: None,
      host: None,
      path: None,
      route: None,
      protocol: None,
      claims: Vec::new(),
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
  assert_eq!(plan.method, Method::POST);
  assert_eq!(plan.endpoint, "/admin/v1/ipm/simulate");
  assert_eq!(
    plan.body,
    Some(json!({ "action": "config:GetStatus", "resource": "*" }))
  );
  assert_eq!(plan.permission.action, "ipm:SimulateSelf");
  assert_eq!(plan.permission.resources, vec!["simulation/current"]);
}

#[test]
fn auth_check_accepts_context_flags() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "auth",
    "check",
    "--action",
    "config:Load",
    "--resource",
    "oxibelt:oxibelt:config:*",
    "--source-ip",
    "10.0.0.5",
    "--method",
    "POST",
    "--claim",
    "env=prod",
  ])
  .expect("auth check should parse context flags");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(
    plan.body,
    Some(json!({
      "action": "config:Load",
      "resource": "oxibelt:oxibelt:config:*",
      "context": {
        "source_ip": "10.0.0.5",
        "method": "POST",
        "claims": { "env": "prod" },
      },
    }))
  );
}

#[test]
fn current_doctor_includes_external_probe_query() {
  let command = Command::Doctor(DoctorArgs {
    config: None,
    candidate: None,
    format: DoctorOutputFormat::Text,
    fail_on: DoctorFailOn::Error,
    external_probes: vec![ExternalProbeKind::SharedState, ExternalProbeKind::Upstream],
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
    "/admin/v1/diagnostics/preflight?external_probe=shared_state&external_probe=upstream"
  );
  assert_eq!(plan.permission.action, "diagnostics:ReadPreflight");
  assert_eq!(plan.permission.resources, vec!["preflight/current"]);
}

#[test]
fn candidate_doctor_posts_toml() {
  let temp_dir = std::env::temp_dir();
  let path = temp_dir.join(format!("oxibeltctl-doctor-{}.toml", std::process::id()));
  std::fs::write(&path, "[listeners]\nhttps_bind = \"127.0.0.1:8443\"\n")
    .expect("candidate should be written");
  let command = Command::Doctor(DoctorArgs {
    config: None,
    candidate: Some(path.clone()),
    format: DoctorOutputFormat::Json,
    fail_on: DoctorFailOn::Warning,
    external_probes: vec![ExternalProbeKind::RemoteSigner],
  });
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &command))
    .expect("plan");
  let _ = std::fs::remove_file(&path);

  assert_eq!(plan.method, Method::POST);
  assert_eq!(plan.endpoint, "/admin/v1/diagnostics/preflight");
  assert_eq!(
    plan.body,
    Some(json!({
      "format": "toml",
      "config": "[listeners]\nhttps_bind = \"127.0.0.1:8443\"\n",
      "external_probes": ["remote_signer"],
    }))
  );
}

#[test]
fn local_doctor_cli_conflicts_with_candidate_and_parses_options() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "doctor",
    "--config",
    "source/config/oxibelt.toml",
    "--format",
    "json",
    "--fail-on",
    "warning",
    "--external-probe",
    "all",
  ])
  .expect("local doctor should parse");
  let Command::Doctor(args) = parsed.command else {
    panic!("expected doctor command");
  };
  assert!(args.config.is_some());
  assert_eq!(args.format, DoctorOutputFormat::Json);
  assert_eq!(args.fail_on, DoctorFailOn::Warning);
  assert_eq!(args.external_probes, vec![ExternalProbeKind::All]);

  let conflict = Cli::try_parse_from([
    "oxibeltctl",
    "doctor",
    "--config",
    "active.toml",
    "--candidate",
    "candidate.toml",
  ]);
  assert!(conflict.is_err(), "doctor config and candidate conflict");
}

#[test]
fn support_bundle_uses_redacted_endpoint() {
  let command = Command::SupportBundle(SupportBundleArgs {
    redact: true,
    external_probes: vec!["shared_state".to_string(), "upstream".to_string()],
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
    "/admin/v1/diagnostics/support-bundle?redact=true&external_probe=shared_state&external_probe=upstream"
  );
  assert_eq!(plan.permission.action, "diagnostics:ReadSupportBundle");
  assert_eq!(plan.permission.resources, vec!["support-bundle/current"]);
}

#[test]
fn support_bundle_cli_requires_redact() {
  let parsed = Cli::try_parse_from(["oxibeltctl", "support-bundle", "--redact"])
    .expect("support-bundle --redact should parse");
  assert!(matches!(parsed.command, Command::SupportBundle(_)));

  let missing = Cli::try_parse_from(["oxibeltctl", "support-bundle"]);
  assert!(missing.is_err(), "support-bundle should require --redact");
}

#[test]
fn runtime_introspection_uses_redacted_endpoint_and_permission() {
  let command = Command::Runtime(RuntimeCommand {
    command: RuntimeSubcommand::Introspection(RuntimeIntrospectionArgs { redact: true }),
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
  assert_eq!(plan.endpoint, "/admin/v1/runtime/introspection?redact=true");
  assert_eq!(plan.permission.action, "runtime:ReadIntrospection");
  assert_eq!(plan.permission.resources, vec!["introspection/current"]);
}

#[test]
fn runtime_introspection_cli_requires_redact() {
  let parsed = Cli::try_parse_from(["oxibeltctl", "runtime", "introspection", "--redact"])
    .expect("runtime introspection --redact should parse");
  assert!(matches!(parsed.command, Command::Runtime(_)));

  let missing = Cli::try_parse_from(["oxibeltctl", "runtime", "introspection"]);
  assert!(
    missing.is_err(),
    "runtime introspection should require --redact"
  );
}

#[test]
fn block_ip_uses_apply_with_duration_route_and_dry_run() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "block",
    "ip",
    "203.0.113.10",
    "--ttl",
    "1h",
    "--route",
    "admin",
    "--reason",
    "incident response",
    "--dry-run",
  ])
  .expect("block command should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.method, Method::POST);
  assert_eq!(plan.endpoint, "/admin/v1/dynamic-policies/apply");
  assert_eq!(plan.permission.action, "dynamic-policy:Apply");
  assert_eq!(
    plan.permission.resources,
    vec![
      "source/oxibeltctl/name/reject-client_ip_route-203-0-113-10-admin",
      "route/admin"
    ]
  );
  assert_eq!(
    plan.body,
    Some(json!({
      "enabled": true,
      "priority": 100,
      "source": "oxibeltctl",
      "name": "reject-client_ip_route-203-0-113-10-admin",
      "action": "reject",
      "subject_type": "client_ip_route",
      "subject": "203.0.113.10|admin",
      "route_name": "admin",
      "path_prefix": null,
      "method": null,
      "reason": "incident response",
      "ttl_seconds": 3600,
      "mode": "dry_run",
    }))
  );
}

#[test]
fn challenge_person_proof_uses_dynamic_challenge_action() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "challenge",
    "--person-proof",
    "ip",
    "203.0.113.11",
    "--ttl",
    "2h",
  ])
  .expect("challenge command should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.endpoint, "/admin/v1/dynamic-policies/apply");
  assert_eq!(
    plan.body,
    Some(json!({
      "enabled": true,
      "priority": 100,
      "source": "oxibeltctl",
      "name": "challenge-client_ip-203-0-113-11",
      "action": "challenge",
      "subject_type": "client_ip",
      "subject": "203.0.113.11",
      "route_name": null,
      "path_prefix": null,
      "method": null,
      "reason": "oxibeltctl challenge 203.0.113.11",
      "ttl_seconds": 7200,
      "mode": "enforce",
    }))
  );
}

#[test]
fn rate_limit_source_accepts_rps_and_default_burst() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "rate-limit",
    "source",
    "203.0.113.12",
    "--rps",
    "1",
    "--ttl",
    "10m",
  ])
  .expect("rate-limit source command should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.endpoint, "/admin/v1/dynamic-policies/apply");
  assert_eq!(
    plan.body,
    Some(json!({
      "enabled": true,
      "priority": 100,
      "source": "oxibeltctl",
      "name": "rate-limit-client_ip-203-0-113-12",
      "action": "rate_limit",
      "subject_type": "client_ip",
      "subject": "203.0.113.12",
      "route_name": null,
      "path_prefix": null,
      "method": null,
      "rate": "1r/s",
      "burst": 1,
      "reason": "oxibeltctl rate-limit 203.0.113.12",
      "ttl_seconds": 600,
      "mode": "enforce",
    }))
  );
}

#[test]
fn mitigate_profile_file_renders_apply_policy() {
  let profile_file = write_temp_file(
    "mitigation-profile",
    r#"{
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
    }"#,
  );
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--profile-file",
    profile_file.to_str().expect("profile path should be UTF-8"),
    "--source",
    "203.0.113.13",
  ])
  .expect("mitigate profile should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");
  let _ = std::fs::remove_file(&profile_file);

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
fn mitigate_profile_cli_options_override_profile_shape() {
  let profile_file = write_temp_file(
    "mitigation-profile-overrides",
    r#"{
      "profiles": {
        "login-bruteforce": {
          "action": "reject",
          "source": "operator-profiles",
          "priority": 50,
          "path_prefix": "/identity",
          "method": "get",
          "status": 429,
          "reason": "profile reason",
          "ttl_seconds": 900,
          "mode": "enforce"
        }
      }
    }"#,
  );
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--profile-file",
    profile_file.to_str().expect("profile path should be UTF-8"),
    "--source",
    "203.0.113.14",
    "--path-prefix",
    "/login",
    "--route",
    "app",
    "--method",
    "post",
    "--priority",
    "7",
    "--ttl",
    "30m",
    "--reason",
    "operator override",
    "--name",
    "custom-profile-name",
    "--dry-run",
  ])
  .expect("mitigate profile should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");
  let _ = std::fs::remove_file(&profile_file);

  assert_eq!(plan.endpoint, "/admin/v1/dynamic-policies/apply");
  assert_eq!(
    plan.body,
    Some(json!({
      "enabled": true,
      "priority": 7,
      "source": "operator-profiles",
      "name": "custom-profile-name",
      "action": "reject",
      "subject_type": "client_ip_path",
      "subject": "203.0.113.14|/login",
      "route_name": "app",
      "path_prefix": "/login",
      "method": "POST",
      "rate": null,
      "burst": null,
      "status": 429,
      "body": null,
      "reason": "operator override",
      "code": null,
      "ttl_seconds": 1800,
      "mode": "dry_run",
    }))
  );
}

#[test]
fn mitigate_unknown_profile_fails() {
  let profile_file = write_temp_file(
    "mitigation-profile-missing",
    r#"{"profiles":{"known":{"action":"reject","ttl_seconds":60}}}"#,
  );
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "missing",
    "--profile-file",
    profile_file.to_str().expect("profile path should be UTF-8"),
    "--source",
    "203.0.113.15",
  ])
  .expect("mitigate profile should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let error = match runtime.block_on(plan_command(&client, &parsed.command)) {
    Ok(_) => panic!("unknown profile should fail"),
    Err(error) => error,
  };
  let _ = std::fs::remove_file(&profile_file);

  assert!(error.to_string().contains("mitigation profile missing"));
}

#[test]
fn mitigate_requires_profile_catalog_source() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--source",
    "203.0.113.16",
  ]);
  assert!(
    parsed.is_err(),
    "mitigate should require a profile catalog source"
  );
}

#[test]
fn mitigate_accepts_exactly_one_profile_catalog_source() {
  let both = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--profile-file",
    "profiles.json",
    "--profile-url",
    "https://profiles.example.test/catalog.json",
    "--source",
    "203.0.113.16",
  ]);
  assert!(
    both.is_err(),
    "mitigate should reject both --profile-file and --profile-url"
  );

  let url = Cli::try_parse_from([
    "oxibeltctl",
    "mitigate",
    "login-bruteforce",
    "--profile-url",
    "https://profiles.example.test/catalog.json",
    "--source",
    "203.0.113.16",
  ]);
  assert!(url.is_ok(), "mitigate should accept --profile-url");
}

#[test]
fn dynamic_policy_audit_builds_query_endpoint() {
  let command = Command::DynamicPolicy(DynamicPolicyCommand {
    command: DynamicPolicySubcommand::Audit(DynamicPolicyAuditArgs {
      policy_id: Some(42),
      limit: 25,
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
    "/admin/v1/dynamic-policies/audit?limit=25&policy_id=42"
  );
  assert_eq!(plan.permission.action, "dynamic-policy:ReadAudit");
}

#[test]
fn admin_audit_builds_query_endpoint() {
  let command = Command::Audit(AdminAuditArgs {
    outcome: Some("rejected".to_string()),
    actor: Some("ops-token".to_string()),
    principal: Some("ops".to_string()),
    service: Some("config".to_string()),
    operation: Some("post.config.load".to_string()),
    request_id: Some("req-123".to_string()),
    path_prefix: Some("/admin/v1/config".to_string()),
    before_id: Some(50),
    limit: 25,
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
    "/admin/v1/audit?limit=25&outcome=rejected&actor=ops-token&principal=ops&service=config&operation=post.config.load&request_id=req-123&path_prefix=%2Fadmin%2Fv1%2Fconfig&before_id=50"
  );
  assert_eq!(plan.permission.action, "admin:ReadAudit");
  assert_eq!(plan.permission.resources, vec!["audit/admin"]);
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
  std::fs::write(&path, content).expect("temp profile should be written");
  path
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
