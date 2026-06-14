use super::*;
use crate::ipm::{IpmActor, IpmRequestContext, IpmRuntime};
use crate::{
  config::{IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig},
  server::admin_auth::AdminAuthorization,
};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn actor_and_ipm(actions: &[&str]) -> (IpmActor, IpmRuntime) {
  let actor = IpmActor {
    name: "planner-token".to_string(),
    principal: "planner".to_string(),
    subject: "planner@example.com".to_string(),
    groups: vec!["ops".to_string()],
  };
  let policy = IpmPolicyConfig {
    name: "test".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![IpmPolicyStatementConfig {
      effect: IpmPolicyEffect::Allow,
      actions: actions.iter().map(|action| (*action).to_string()).collect(),
      resources: vec!["*".to_string()],
      conditions: Vec::new(),
    }],
  };
  let ipm = IpmRuntime::test_with_actor_policy("oxibelt", actor.clone(), policy);
  (actor, ipm)
}

fn config() -> Config {
  let temp_dir = common::TempDir::new("admin-rulepack-plan");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "rulepack-plan");
  let mut config: Config = toml::from_str(&common::minimal_config_toml(&cert_path, &key_path))
    .expect("config should parse");
  config.upstreams[0].name = "vaultwarden-upstream".to_string();
  config.upstreams[0].origin =
    url::Url::parse("https://user:secret@vaultwarden.internal").expect("origin");
  config.routes[0].name = "mmsecretvault".to_string();
  config.routes[0].hosts = vec!["vault.example.com".to_string()];
  config.routes[0].upstream = Some("vaultwarden-upstream".to_string());
  config
}

fn rulepack_manifest(schema_version: u32) -> String {
  format!(
    r#"[rulepack]
schema_version = {schema_version}
name = "vaultwarden-hardening"
version = "0.1.0"
targets = ["vaultwarden"]

[[variables]]
name = "admin_cidr"
type = "cidr"
required = true
prompt = "Trusted CIDR allowed to access /admin."

[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"
required = true
prompt = "Select the route that points to Vaultwarden."

[bindings.discovery]
name_any = ["vault", "secret"]
host_contains_any = ["vault"]
upstream_contains_any = ["vaultwarden"]
path_prefix_any = ["/"]

[[rules]]
name = "admin"
phase = "request"
priority = 100
content = '''
when = "Context.RouteName == '{{route_name}}' && !Request.Client.Ip.inCidr('{{admin_cidr}}')"

[[actions]]
type = "reject"
status = 403
'''
"#
  )
}

fn plan_request() -> AdminRulepackPlanRequest {
  AdminRulepackPlanRequest {
    manifest: rulepack_manifest(2),
    source: None,
    values: BTreeMap::new(),
    bindings: BTreeMap::new(),
    rule_overrides: Vec::new(),
    exceptions: Vec::new(),
    profile: None,
    mode: None,
    force_mode: false,
    include_route_candidates: true,
    include_diff: true,
    include_cost: false,
  }
}

#[test]
fn plan_reports_missing_inputs_and_redacted_route_candidates() {
  let report = plan_rulepack(&config(), plan_request()).expect("plan should build");

  assert!(!report.ok);
  assert!(
    report
      .required_inputs
      .iter()
      .any(|input| input.name == "app_route" && input.input_type == "route")
  );
  assert!(
    report
      .required_inputs
      .iter()
      .any(|input| input.name == "admin_cidr" && input.input_type == "cidr")
  );
  let candidates = &report.route_candidates[0].candidates;
  assert_eq!(candidates[0].name, "mmsecretvault");
  assert_eq!(
    candidates[0].upstream.as_deref(),
    Some("vaultwarden-upstream")
  );
  let serialized = serde_json::to_string(&report).expect("report should serialize");
  assert!(!serialized.contains("user:secret"));
  assert!(!serialized.contains("vaultwarden.internal"));
}

#[test]
fn plan_rejects_schema_v1_manifests() {
  let mut request = plan_request();
  request.manifest = rulepack_manifest(1);
  let error = plan_rulepack(&config(), request).expect_err("schema v1 should fail");

  assert!(
    error
      .to_string()
      .contains("unsupported rulepack schema_version 1")
  );
}

#[test]
fn plan_permission_flags_are_enforced_independently() {
  let context = IpmRequestContext::default();
  let mut request = plan_request();
  request.include_cost = true;

  let (actor, ipm) = actor_and_ipm(&[
    "config:ReadRouteInventory",
    "waf:ListOxiRulePacks",
    "waf:EstimateOxiRuleCost",
  ]);
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let response =
    plan_permission_denial(&request, &authorization).expect("missing plan permission should fail");
  assert_eq!(response.status(), StatusCode::FORBIDDEN);

  let (actor, ipm) = actor_and_ipm(&["waf:PlanOxiRulePack"]);
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let response = plan_permission_denial(&request, &authorization)
    .expect("missing route inventory permission should fail");
  assert_eq!(response.status(), StatusCode::FORBIDDEN);

  let (actor, ipm) = actor_and_ipm(&["waf:PlanOxiRulePack", "config:ReadRouteInventory"]);
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let response =
    plan_permission_denial(&request, &authorization).expect("missing diff permission should fail");
  assert_eq!(response.status(), StatusCode::FORBIDDEN);

  let (actor, ipm) = actor_and_ipm(&[
    "waf:PlanOxiRulePack",
    "config:ReadRouteInventory",
    "waf:ListOxiRulePacks",
  ]);
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let response =
    plan_permission_denial(&request, &authorization).expect("missing cost permission should fail");
  assert_eq!(response.status(), StatusCode::FORBIDDEN);

  let (actor, ipm) = actor_and_ipm(&[
    "waf:PlanOxiRulePack",
    "config:ReadRouteInventory",
    "waf:ListOxiRulePacks",
    "waf:EstimateOxiRuleCost",
  ]);
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  assert!(plan_permission_denial(&request, &authorization).is_none());
}
