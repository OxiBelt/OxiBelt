use std::time::Duration;

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
  assert_eq!(plan.permission.resource, "preflight/current");
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
  assert_eq!(plan.permission.resource, "support-bundle/current");
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
  assert_eq!(plan.permission.resource, "introspection/current");
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

fn dummy_client() -> AdminClient {
  oxibelt::tls::install_default_provider().expect("provider");
  let options = AdminClientOptions::new(
    Url::parse(DEFAULT_ADMIN_URL).expect("url"),
    "test-token".to_string(),
    Duration::from_secs(1),
  );
  AdminClient::new(options).expect("client")
}
