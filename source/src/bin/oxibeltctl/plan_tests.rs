use std::time::Duration;

use clap::Parser;
use http::Method;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, DEFAULT_ADMIN_URL};
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
