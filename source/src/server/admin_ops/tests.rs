use super::*;
use crate::config::{IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig};
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

  let reload = sync_request(
    admin_control::AdminApplyMode::OxiRule,
    vec![put(admin_control::AdminFileRoot::Config, "runtime.toml")],
  );
  assert_eq!(
    check_file_sync_permissions(&authorization, &reload),
    Err(FileSyncPermissionError::Denied("waf:ReloadOxiRule"))
  );
}

#[test]
fn waf_file_permissions_authorize_matching_operations() {
  let (actor, ipm) = actor_and_ipm(
    &[
      "waf:PutOxiRule",
      "waf:DeleteOxiRule",
      "waf:PutOxiRuleGroup",
      "waf:DeleteOxiRuleGroup",
    ],
    &[
      "oxibelt:oxibelt:waf:oxirule/*",
      "oxibelt:oxibelt:waf:oxirule-group/*",
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
