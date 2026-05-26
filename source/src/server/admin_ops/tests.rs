use super::*;
use crate::config::{Config, IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig};
use crate::ipm::{IpmActor, IpmRequestContext, IpmRuntime};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn actor_and_ipm(actions: &[&str], resources: &[&str]) -> (AdminActor, IpmRuntime) {
  let actor = IpmActor {
    name: "deployer-token".to_string(),
    principal: "deployer".to_string(),
    subject: "deployer@example.com".to_string(),
    groups: vec!["ops".to_string()],
  };
  let policy = IpmPolicyConfig {
    name: "test".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![IpmPolicyStatementConfig {
      effect: IpmPolicyEffect::Allow,
      actions: actions.iter().map(|action| (*action).to_string()).collect(),
      resources: resources
        .iter()
        .map(|resource| (*resource).to_string())
        .collect(),
      conditions: Vec::new(),
    }],
  };
  let ipm = IpmRuntime::test_with_actor_policy("oxibelt", actor.clone(), policy);
  (actor, ipm)
}

fn admin_actor(name: &str, groups: Vec<String>) -> AdminActor {
  AdminActor {
    name: name.to_string(),
    principal: name.to_string(),
    subject: name.to_string(),
    groups,
  }
}

fn sync_request(
  apply: admin_control::AdminApplyMode,
  operations: Vec<admin_control::AdminFileOperation>,
) -> admin_control::AdminFilesSyncRequest {
  admin_control::AdminFilesSyncRequest { apply, operations }
}

fn put(root: admin_control::AdminFileRoot, path: &str) -> admin_control::AdminFileOperation {
  admin_control::AdminFileOperation {
    op: admin_control::AdminFileOperationKind::Put,
    root,
    path: path.to_string(),
    expected_sha256: None,
    content: Some("content".to_string()),
  }
}

fn delete(root: admin_control::AdminFileRoot, path: &str) -> admin_control::AdminFileOperation {
  admin_control::AdminFileOperation {
    op: admin_control::AdminFileOperationKind::Delete,
    root,
    path: path.to_string(),
    expected_sha256: None,
    content: None,
  }
}

#[tokio::test]
async fn admin_lifecycle_endpoints_enforce_ipm_and_toggle_drain() {
  let temp_dir = common::TempDir::new("admin-lifecycle");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "admin-lifecycle");
  let config: Config = toml::from_str(&common::minimal_config_toml(&cert_path, &key_path))
    .expect("config should parse");
  config.validate().expect("config should validate");
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let viewer = admin_actor("viewer", Vec::new());
  let admin = admin_actor("admin", vec!["ipm-admin".to_string()]);
  let context = IpmRequestContext::default();
  let viewer_auth = AdminAuthorization::new(&viewer, &snapshot.ipm, &context);
  let admin_auth = AdminAuthorization::new(&admin, &snapshot.ipm, &context);

  let response = admin_lifecycle_response(
    &snapshot,
    &viewer_auth,
    &::http::Method::GET,
    "/admin/v1/lifecycle",
  )
  .expect("lifecycle GET should be handled");
  assert_eq!(response.status(), StatusCode::FORBIDDEN);
  assert!(!snapshot.lifecycle.is_draining());

  let response = admin_lifecycle_response(
    &snapshot,
    &viewer_auth,
    &::http::Method::POST,
    "/admin/v1/lifecycle/drain",
  )
  .expect("lifecycle drain should be handled");
  assert_eq!(response.status(), StatusCode::FORBIDDEN);
  assert!(!snapshot.lifecycle.is_draining());

  let response = admin_lifecycle_response(
    &snapshot,
    &admin_auth,
    &::http::Method::POST,
    "/admin/v1/lifecycle/drain",
  )
  .expect("lifecycle drain should be handled");
  assert_eq!(response.status(), StatusCode::OK);
  assert!(snapshot.lifecycle.is_draining());
  assert_eq!(snapshot.lifecycle.reason(), "admin");

  let response = admin_lifecycle_response(
    &snapshot,
    &admin_auth,
    &::http::Method::POST,
    "/admin/v1/lifecycle/undrain",
  )
  .expect("lifecycle undrain should be handled");
  assert_eq!(response.status(), StatusCode::OK);
  assert!(!snapshot.lifecycle.is_draining());
}

#[test]
fn config_sync_files_does_not_authorize_oxirule_files() {
  let (actor, ipm) = actor_and_ipm(&["config:SyncFiles"], &["*"]);
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);

  let oxirule_put = sync_request(
    admin_control::AdminApplyMode::None,
    vec![put(
      admin_control::AdminFileRoot::OxiRule,
      "rules/block.oxirule.toml",
    )],
  );
  assert_eq!(
    check_file_sync_permissions(&authorization, &oxirule_put),
    Err(FileSyncPermissionError::Denied("waf:PutOxiRule"))
  );

  let group_delete = sync_request(
    admin_control::AdminApplyMode::None,
    vec![delete(
      admin_control::AdminFileRoot::OxiRuleGroup,
      "groups/bot.oxirule-group.toml",
    )],
  );
  assert_eq!(
    check_file_sync_permissions(&authorization, &group_delete),
    Err(FileSyncPermissionError::Denied("waf:DeleteOxiRuleGroup"))
  );

  let rulepack_put = sync_request(
    admin_control::AdminApplyMode::None,
    vec![put(
      admin_control::AdminFileRoot::OxiRuleRulepack,
      "rulepacks/main.oxirule-rulepack.toml",
    )],
  );
  assert_eq!(
    check_file_sync_permissions(&authorization, &rulepack_put),
    Err(FileSyncPermissionError::Denied("waf:PutOxiRulePack"))
  );

  let reload = sync_request(
    admin_control::AdminApplyMode::OxiRule,
    vec![put(admin_control::AdminFileRoot::Config, "runtime.toml")],
  );
  assert_eq!(
    check_file_sync_permissions(&authorization, &reload),
    Err(FileSyncPermissionError::Denied("waf:ReloadOxiRule"))
  );
}

#[tokio::test]
async fn waf_rulepack_list_endpoint_requires_list_permission() {
  let temp_dir = common::TempDir::new("admin-waf-rulepacks");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  let rulepack_dir = temp_dir.path().join("oxirule").join("rulepacks");
  std::fs::create_dir_all(&config_dir).expect("config dir should be created");
  std::fs::create_dir_all(&cert_dir).expect("cert dir should be created");
  std::fs::create_dir_all(&rulepack_dir).expect("rulepack dir should be created");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, "admin-waf-rulepacks");
  std::fs::write(
    rulepack_dir.join("main.oxirule-rulepack.toml"),
    r#"
[rulepack]
schema_version = 1
name = "main"
version = "0.1.0"

[[group_files]]
content = '''
[[rule_groups]]
name = "main-group"
when = "true"
'''
"#,
  )
  .expect("rulepack should be written");
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    format!(
      "{}\n{}",
      common::minimal_config_toml_with_paths(
        cert_path.file_name().unwrap().to_str().unwrap(),
        key_path.file_name().unwrap().to_str().unwrap(),
      ),
      r#"
[waf]
enabled = true
rulepack_files = ["rulepacks/main.oxirule-rulepack.toml"]
"#
    ),
  )
  .expect("config should be written");
  let config = Config::load(&config_path).expect("config should load");
  config.validate().expect("config should validate");
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let (actor, ipm) = actor_and_ipm(&["waf:ListOxiRulePacks"], &["*"]);
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);

  let response = admin_waf_response(
    &snapshot,
    &authorization,
    &::http::Method::GET,
    "/admin/v1/waf/rulepacks",
  )
  .expect("rulepack list should be handled");
  assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn waf_file_permissions_authorize_matching_operations() {
  let (actor, ipm) = actor_and_ipm(
    &[
      "waf:PutOxiRule",
      "waf:DeleteOxiRule",
      "waf:PutOxiRuleGroup",
      "waf:DeleteOxiRuleGroup",
      "waf:PutOxiRulePack",
      "waf:DeleteOxiRulePack",
    ],
    &[
      "oxibelt:oxibelt:waf:oxirule/*",
      "oxibelt:oxibelt:waf:oxirule-group/*",
      "oxibelt:oxibelt:waf:oxirule-rulepack/*",
    ],
  );
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let payload = sync_request(
    admin_control::AdminApplyMode::None,
    vec![
      put(
        admin_control::AdminFileRoot::OxiRule,
        "rules/a.oxirule.toml",
      ),
      delete(
        admin_control::AdminFileRoot::OxiRule,
        "rules/b.oxirule.toml",
      ),
      put(
        admin_control::AdminFileRoot::OxiRuleGroup,
        "groups/a.oxirule-group.toml",
      ),
      delete(
        admin_control::AdminFileRoot::OxiRuleGroup,
        "groups/b.oxirule-group.toml",
      ),
      put(
        admin_control::AdminFileRoot::OxiRuleRulepack,
        "rulepacks/a.oxirule-rulepack.toml",
      ),
      delete(
        admin_control::AdminFileRoot::OxiRuleRulepack,
        "rulepacks/b.oxirule-rulepack.toml",
      ),
    ],
  );

  assert!(check_file_sync_permissions(&authorization, &payload).is_ok());
}

#[test]
fn waf_file_permissions_reject_cross_type_paths() {
  let (actor, ipm) = actor_and_ipm(&["waf:PutOxiRule"], &["oxibelt:oxibelt:waf:oxirule/*"]);
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let group_path_as_rule = sync_request(
    admin_control::AdminApplyMode::None,
    vec![put(
      admin_control::AdminFileRoot::OxiRule,
      "groups/main.oxirule-group.toml",
    )],
  );
  let error = check_file_sync_permissions(&authorization, &group_path_as_rule)
    .expect_err("group file path should not authorize as an OxiRule file");
  assert!(matches!(
    error,
    FileSyncPermissionError::InvalidPath(message)
      if message.contains("root oxirule can only manage .oxirule.toml files")
  ));

  let (actor, ipm) = actor_and_ipm(
    &["waf:PutOxiRuleGroup"],
    &["oxibelt:oxibelt:waf:oxirule-group/*"],
  );
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let rule_path_as_group = sync_request(
    admin_control::AdminApplyMode::None,
    vec![put(
      admin_control::AdminFileRoot::OxiRuleGroup,
      "rules/main.oxirule.toml",
    )],
  );
  let error = check_file_sync_permissions(&authorization, &rule_path_as_group)
    .expect_err("rule file path should not authorize as an OxiRule group file");
  assert!(matches!(
    error,
    FileSyncPermissionError::InvalidPath(message)
      if message.contains("root oxirule_group can only manage .oxirule-group.toml files")
  ));
}

#[test]
fn mixed_file_sync_requires_every_operation_permission() {
  let (actor, ipm) = actor_and_ipm(&["waf:PutOxiRule"], &["oxibelt:oxibelt:waf:oxirule/*"]);
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let payload = sync_request(
    admin_control::AdminApplyMode::None,
    vec![
      put(
        admin_control::AdminFileRoot::OxiRule,
        "rules/a.oxirule.toml",
      ),
      put(
        admin_control::AdminFileRoot::OxiRuleGroup,
        "groups/a.oxirule-group.toml",
      ),
    ],
  );

  assert_eq!(
    check_file_sync_permissions(&authorization, &payload),
    Err(FileSyncPermissionError::Denied("waf:PutOxiRuleGroup"))
  );
}

#[test]
fn oxirule_reload_requires_waf_reload_permission() {
  let (actor, ipm) = actor_and_ipm(&["config:SyncFiles", "waf:ReloadOxiRule"], &["*"]);
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let payload = sync_request(
    admin_control::AdminApplyMode::OxiRule,
    vec![put(admin_control::AdminFileRoot::Config, "runtime.toml")],
  );

  assert!(check_file_sync_permissions(&authorization, &payload).is_ok());
}

#[test]
fn oxirule_devtools_check_requires_rule_and_group_permissions() {
  let (actor, ipm) = actor_and_ipm(&["waf:CheckOxiRule"], &["oxibelt:oxibelt:waf:oxirule/*"]);
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let payload = crate::waf::OxiRuleDevtoolsCheckRequest {
    rule: Some(crate::waf::OxiRuleCandidate {
      content: "when = \"true\"\n".to_string(),
      name: Some("candidate".to_string()),
      id: None,
      tags: Vec::new(),
      mode: None,
      phase: Some(crate::waf::WafPhase::Request),
      priority: Some(100),
      route: None,
    }),
    groups: vec![crate::waf::OxiRuleGroupCandidate {
      content: "[[rule_groups]]\nname = \"group\"\nwhen = \"true\"\n".to_string(),
      route: None,
      name: Some("group".to_string()),
    }],
    include_active_rules: false,
  };

  let response = authorize_oxirule_check(&authorization, &payload)
    .expect("missing group permission should reject");
  assert_eq!(response.status(), StatusCode::FORBIDDEN);

  let (actor, ipm) = actor_and_ipm(
    &["waf:CheckOxiRule", "waf:CheckOxiRuleGroup"],
    &[
      "oxibelt:oxibelt:waf:oxirule/*",
      "oxibelt:oxibelt:waf:oxirule-group/*",
    ],
  );
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  assert!(authorize_oxirule_check(&authorization, &payload).is_none());
}

#[test]
fn oxirule_devtools_active_context_requires_wildcard_permission() {
  let context = IpmRequestContext::default();
  let active_context_cases = [
    (
      "check",
      "waf:CheckOxiRule",
      "oxibelt:oxibelt:waf:oxirule/candidate",
      "oxibelt:oxibelt:waf:oxirule/*",
      "oxirule/*",
    ),
    (
      "cost",
      "waf:EstimateOxiRuleCost",
      "oxibelt:oxibelt:waf:oxirule/candidate",
      "oxibelt:oxibelt:waf:oxirule/*",
      "oxirule/*",
    ),
    (
      "test",
      "waf:TestOxiRule",
      "oxibelt:oxibelt:waf:oxirule/candidate",
      "oxibelt:oxibelt:waf:oxirule/*",
      "oxirule/*",
    ),
    (
      "explain",
      "waf:ExplainOxiRule",
      "oxibelt:oxibelt:waf:oxirule/candidate",
      "oxibelt:oxibelt:waf:oxirule/*",
      "oxirule/*",
    ),
    (
      "replay",
      "waf:ReplayOxiRule",
      "oxibelt:oxibelt:waf:replay/candidate",
      "oxibelt:oxibelt:waf:replay/*",
      "replay/*",
    ),
  ];

  for (name, action, scoped_resource, wildcard_resource, active_resource) in active_context_cases {
    let (actor, ipm) = actor_and_ipm(&[action], &[scoped_resource]);
    let authorization = AdminAuthorization::new(&actor, &ipm, &context);
    if name == "check" {
      let inactive_payload = oxirule_check_payload(false);
      assert!(
        authorize_oxirule_check(&authorization, &inactive_payload).is_none(),
        "{name} should allow inactive candidate-only checks"
      );
      let active_payload = oxirule_check_payload(true);
      let response = authorize_oxirule_check(&authorization, &active_payload)
        .expect("active check should require wildcard permission");
      assert_eq!(response.status(), StatusCode::FORBIDDEN);
    } else {
      assert!(
        authorize_oxirule_active_context(&authorization, false, action, active_resource).is_none(),
        "{name} should not require wildcard permission without active rules"
      );
      let response =
        authorize_oxirule_active_context(&authorization, true, action, active_resource)
          .expect("active context should require wildcard permission");
      assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    let (actor, ipm) = actor_and_ipm(&[action], &[wildcard_resource]);
    let authorization = AdminAuthorization::new(&actor, &ipm, &context);
    if name == "check" {
      let active_payload = oxirule_check_payload(true);
      assert!(
        authorize_oxirule_check(&authorization, &active_payload).is_none(),
        "{name} should allow active checks with wildcard permission"
      );
    } else {
      assert!(
        authorize_oxirule_active_context(&authorization, true, action, active_resource).is_none(),
        "{name} should allow active context with wildcard permission"
      );
    }
  }
}

fn oxirule_check_payload(include_active_rules: bool) -> crate::waf::OxiRuleDevtoolsCheckRequest {
  crate::waf::OxiRuleDevtoolsCheckRequest {
    rule: Some(crate::waf::OxiRuleCandidate {
      content: "when = \"true\"\n".to_string(),
      name: Some("candidate".to_string()),
      id: None,
      tags: Vec::new(),
      mode: None,
      phase: Some(crate::waf::WafPhase::Request),
      priority: Some(100),
      route: None,
    }),
    groups: Vec::new(),
    include_active_rules,
  }
}

#[test]
fn oxirule_devtools_actions_require_matching_ipm_permission() {
  let context = IpmRequestContext::default();
  let cases = [
    (
      "waf:CheckOxiRule",
      "oxibelt:oxibelt:waf:oxirule/candidate",
      "oxirule/candidate",
      "waf:TestOxiRule",
    ),
    (
      "waf:CheckOxiRuleGroup",
      "oxibelt:oxibelt:waf:oxirule-group/group",
      "oxirule-group/group",
      "waf:CheckOxiRule",
    ),
    (
      "waf:TestOxiRule",
      "oxibelt:oxibelt:waf:oxirule/candidate",
      "oxirule/candidate",
      "waf:ExplainOxiRule",
    ),
    (
      "waf:ExplainOxiRule",
      "oxibelt:oxibelt:waf:oxirule/candidate",
      "oxirule/candidate",
      "waf:EstimateOxiRuleCost",
    ),
    (
      "waf:EstimateOxiRuleCost",
      "oxibelt:oxibelt:waf:oxirule/candidate",
      "oxirule/candidate",
      "waf:ReplayOxiRule",
    ),
    (
      "waf:ReplayOxiRule",
      "oxibelt:oxibelt:waf:replay/candidate",
      "replay/candidate",
      "waf:TestOxiRule",
    ),
    (
      "waf:ListOxiRuleTemplates",
      "oxibelt:oxibelt:waf:template/*",
      "template/*",
      "waf:RenderOxiRuleTemplate",
    ),
    (
      "waf:RenderOxiRuleTemplate",
      "oxibelt:oxibelt:waf:template/admin-path",
      "template/admin-path",
      "waf:ListOxiRuleTemplates",
    ),
    (
      "waf:PlanOxiRuleFalsePositive",
      "oxibelt:oxibelt:waf:false-positive/inline",
      "false-positive/inline",
      "waf:CheckOxiRule",
    ),
  ];

  for (action, policy_resource, resource_name, denied_action) in cases {
    let (actor, ipm) = actor_and_ipm(&[action], &[policy_resource]);
    let authorization = AdminAuthorization::new(&actor, &ipm, &context);
    assert!(
      authorization.is_allowed(action, resource_name),
      "{action} should allow {resource_name}"
    );
    assert!(
      !authorization.is_allowed(denied_action, resource_name),
      "{denied_action} should not be allowed by {action}"
    );

    let (actor, ipm) = actor_and_ipm(&[action], &["oxibelt:oxibelt:waf:other/*"]);
    let authorization = AdminAuthorization::new(&actor, &ipm, &context);
    assert!(
      !authorization.is_allowed(action, resource_name),
      "{action} should still require a matching resource"
    );
  }
}
