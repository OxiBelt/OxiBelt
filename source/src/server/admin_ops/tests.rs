use super::*;
use crate::config::{IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig};
use crate::ipm::IpmActor;

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

#[test]
fn config_sync_files_does_not_authorize_oxirule_files() {
  let (actor, ipm) = actor_and_ipm(&["config:SyncFiles"], &["*"]);

  let oxirule_put = sync_request(
    admin_control::AdminApplyMode::None,
    vec![put(
      admin_control::AdminFileRoot::OxiRule,
      "rules/block.oxirule.toml",
    )],
  );
  assert_eq!(
    check_file_sync_permissions(&actor, &ipm, &oxirule_put),
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
    check_file_sync_permissions(&actor, &ipm, &group_delete),
    Err(FileSyncPermissionError::Denied("waf:DeleteOxiRuleGroup"))
  );

  let reload = sync_request(
    admin_control::AdminApplyMode::OxiRule,
    vec![put(admin_control::AdminFileRoot::Config, "runtime.toml")],
  );
  assert_eq!(
    check_file_sync_permissions(&actor, &ipm, &reload),
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

  assert!(check_file_sync_permissions(&actor, &ipm, &payload).is_ok());
}

#[test]
fn mixed_file_sync_requires_every_operation_permission() {
  let (actor, ipm) = actor_and_ipm(&["waf:PutOxiRule"], &["oxibelt:oxibelt:waf:oxirule/*"]);
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
    check_file_sync_permissions(&actor, &ipm, &payload),
    Err(FileSyncPermissionError::Denied("waf:PutOxiRuleGroup"))
  );
}

#[test]
fn oxirule_reload_requires_waf_reload_permission() {
  let (actor, ipm) = actor_and_ipm(&["config:SyncFiles", "waf:ReloadOxiRule"], &["*"]);
  let payload = sync_request(
    admin_control::AdminApplyMode::OxiRule,
    vec![put(admin_control::AdminFileRoot::Config, "runtime.toml")],
  );

  assert!(check_file_sync_permissions(&actor, &ipm, &payload).is_ok());
}
