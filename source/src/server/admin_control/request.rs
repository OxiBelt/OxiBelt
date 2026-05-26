use serde::Deserialize;
use tokio::sync::oneshot;

use super::{AdminControlResponse, ControlPlaneConfigPermissions};

pub(in crate::server) enum AdminControlCommand {
  LoadConfig {
    actor: String,
    control_plane_permissions: ControlPlaneConfigPermissions,
    if_match: Option<String>,
    raw: String,
    respond: oneshot::Sender<AdminControlResponse>,
  },
  RollbackConfig {
    actor: String,
    control_plane_permissions: ControlPlaneConfigPermissions,
    if_match: Option<String>,
    respond: oneshot::Sender<AdminControlResponse>,
  },
  ReloadDownstreamTls {
    actor: String,
    if_match: Option<String>,
    respond: oneshot::Sender<AdminControlResponse>,
  },
  SyncFiles {
    actor: String,
    control_plane_permissions: ControlPlaneConfigPermissions,
    if_match: Option<String>,
    request: AdminFilesSyncRequest,
    respond: oneshot::Sender<AdminControlResponse>,
  },
}

#[derive(Debug, Deserialize)]
pub(in crate::server) struct AdminConfigPayload {
  #[serde(default = "default_config_format")]
  pub(in crate::server) format: String,
  pub(in crate::server) config: String,
}

#[derive(Debug, Deserialize)]
pub(in crate::server) struct AdminFilesSyncRequest {
  #[serde(default)]
  pub(in crate::server) apply: AdminApplyMode,
  #[serde(default)]
  pub(in crate::server) operations: Vec<AdminFileOperation>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminApplyMode {
  #[default]
  None,
  #[serde(rename = "oxirule", alias = "oxi_rule")]
  OxiRule,
  Full,
  DownstreamTls,
}

#[derive(Debug, Deserialize)]
pub(in crate::server) struct AdminFileOperation {
  #[serde(rename = "op", alias = "type")]
  pub(in crate::server) op: AdminFileOperationKind,
  pub(in crate::server) root: AdminFileRoot,
  pub(in crate::server) path: String,
  #[serde(default)]
  pub(in crate::server) expected_sha256: Option<String>,
  #[serde(default)]
  pub(in crate::server) content: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminFileOperationKind {
  Put,
  Delete,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminFileRoot {
  Config,
  #[serde(rename = "oxirule", alias = "oxi_rule")]
  OxiRule,
  #[serde(rename = "oxirule_group", alias = "oxi_rule_group")]
  OxiRuleGroup,
  #[serde(rename = "oxirule_rulepack", alias = "oxi_rulepack")]
  OxiRuleRulepack,
}

fn default_config_format() -> String {
  "toml".to_string()
}
