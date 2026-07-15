use std::time::Duration;

use clap::Parser;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, DEFAULT_ADMIN_URL};
use url::Url;

use super::*;

#[test]
fn pool_server_mutations_hint_server_resource() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "pool",
    "update-server",
    "app-pool",
    "primary",
    "--state",
    "down",
    "--etag",
    "\"oxibelt-upstream-pools-0\"",
  ])
  .expect("pool update should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.permission.action, "upstream-pool:UpdateServer");
  assert_eq!(plan.permission.resources, vec!["app-pool/server/primary"]);
}

#[test]
fn cache_purge_hints_policy_and_normalized_host_resources() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "cache",
    "purge",
    "exact",
    "--policy",
    "default",
    "--host",
    "Example.COM:443",
    "--uri",
    "/asset.css",
  ])
  .expect("cache purge should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.permission.action, "cache:PurgeObject");
  assert_eq!(
    plan.permission.resources,
    vec!["policy/default", "host/example.com"]
  );
}

#[test]
fn cache_key_explain_hints_policy_and_host_from_json() {
  let json_file = write_temp_file(
    "cache-key-explain",
    r#"{
      "policy": "assets",
      "method": "GET",
      "scheme": "https",
      "host": "Assets.Example.COM:443",
      "uri": "/main.css"
    }"#,
  );
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "cache",
    "key-explain",
    "--json",
    json_file
      .path()
      .to_str()
      .expect("json path should be UTF-8"),
  ])
  .expect("cache key-explain should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.permission.action, "cache:ExplainKey");
  assert_eq!(
    plan.permission.resources,
    vec!["policy/assets", "host/assets.example.com"]
  );
}

#[test]
fn dynamic_policy_apply_hints_source_name_and_route_from_json() {
  let json_file = write_temp_file(
    "dynamic-policy-apply",
    r#"{
      "source": "incident/team",
      "name": "block login",
      "action": "reject",
      "subject_type": "client_ip",
      "subject": "203.0.113.22",
      "route_name": "app-root"
    }"#,
  );
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "dynamic-policy",
    "apply",
    "--json",
    json_file
      .path()
      .to_str()
      .expect("json path should be UTF-8"),
  ])
  .expect("dynamic-policy apply should parse");
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &parsed.command))
    .expect("plan");

  assert_eq!(plan.permission.action, "dynamic-policy:Apply");
  assert_eq!(
    plan.permission.resources,
    vec![
      "source/incident%2Fteam/name/block%20login",
      "route/app-root"
    ]
  );
}

#[test]
fn dynamic_policy_by_id_uses_collection_fallback_hint() {
  let command = Command::DynamicPolicy(DynamicPolicyCommand {
    command: DynamicPolicySubcommand::Get(IdArg { id: 42 }),
  });
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &command))
    .expect("plan");

  assert_eq!(plan.permission.action, "dynamic-policy:Get");
  assert_eq!(plan.permission.resources, vec!["*"]);
}

fn write_temp_file(label: &str, content: &str) -> tempfile::NamedTempFile {
  let file = tempfile::Builder::new()
    .prefix(&format!("oxibeltctl-{label}-"))
    .suffix(".json")
    .tempfile()
    .expect("temp profile file should be created");
  std::fs::write(file.path(), content).expect("temp profile should be written");
  file
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
