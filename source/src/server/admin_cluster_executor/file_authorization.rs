//! Exact authorization resources for clustered file synchronization.

use crate::admin_mutation::ClusterAuthorizationCheck;
use crate::server::admin_control::{
  AdminApplyMode, AdminFileOperationKind, AdminFileRoot, AdminFilesSyncRequest,
};
use crate::server::file_sync_path;

pub(super) fn derive_file_checks(
  request: &AdminFilesSyncRequest,
  checks: &mut Vec<ClusterAuthorizationCheck>,
) -> anyhow::Result<()> {
  for operation in &request.operations {
    let path =
      file_sync_path::normalized_relative_path(&operation.path).map_err(anyhow::Error::msg)?;
    file_sync_path::validate_root_path(operation.root, &path).map_err(anyhow::Error::msg)?;
    let (action, resource) = match (operation.root, operation.op) {
      (AdminFileRoot::Config, AdminFileOperationKind::Put) => ("config:SyncFiles", "*".into()),
      (AdminFileRoot::Config, AdminFileOperationKind::Delete) => {
        push_check(checks, "config:SyncFiles", "*");
        ("config:SyncFiles", "delete".into())
      }
      (AdminFileRoot::OxiRule, AdminFileOperationKind::Put) => {
        ("waf:PutOxiRule", format!("oxirule/{path}"))
      }
      (AdminFileRoot::OxiRule, AdminFileOperationKind::Delete) => {
        ("waf:DeleteOxiRule", format!("oxirule/{path}"))
      }
      (AdminFileRoot::OxiRuleGroup, AdminFileOperationKind::Put) => {
        ("waf:PutOxiRuleGroup", format!("oxirule-group/{path}"))
      }
      (AdminFileRoot::OxiRuleGroup, AdminFileOperationKind::Delete) => {
        ("waf:DeleteOxiRuleGroup", format!("oxirule-group/{path}"))
      }
      (AdminFileRoot::OxiRuleRulepack | AdminFileRoot::OxiRuleRulepackInstall, kind) => {
        let action = if kind == AdminFileOperationKind::Put {
          "waf:PutOxiRulePack"
        } else {
          "waf:DeleteOxiRulePack"
        };
        let prefix = if operation.root == AdminFileRoot::OxiRuleRulepack {
          "oxirule-rulepack"
        } else {
          "oxirule-rulepack-install"
        };
        (action, format!("{prefix}/{path}"))
      }
    };
    push_check(checks, action, &resource);
  }
  match request.apply {
    AdminApplyMode::None => {}
    AdminApplyMode::Full => push_check(checks, "config:Load", "*"),
    AdminApplyMode::DownstreamTls => push_check(checks, "config:ReloadDownstreamTls", "*"),
    AdminApplyMode::OxiRule => push_check(checks, "waf:ReloadOxiRule", "*"),
  }
  Ok(())
}

fn push_check(checks: &mut Vec<ClusterAuthorizationCheck>, action: &str, resource: &str) {
  checks.push(ClusterAuthorizationCheck {
    action: action.to_string(),
    resource: resource.to_string(),
  });
}
