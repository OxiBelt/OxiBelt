//! Admin control request payload types.
//! Payload parsing is kept separate from authorization and mutation execution.

use serde::Deserialize;
use tokio::sync::oneshot;

use crate::secret_activation::SecretReferenceUpdateRequest;

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
  ActivateSecretReference {
    actor: String,
    if_match: Option<String>,
    mutation_request_id: String,
    logical_revision: Option<String>,
    expected_reference_set_digest: Option<String>,
    request: SecretReferenceUpdateRequest,
    respond: oneshot::Sender<AdminControlResponse>,
  },
  ExpireSecretRollback {
    runtime_snapshot_revision: String,
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
  #[serde(rename = "oxirule_rulepack_install", alias = "oxi_rulepack_install")]
  OxiRuleRulepackInstall,
}

fn default_config_format() -> String {
  "toml".to_string()
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_decode_mutation_body(selector: u8, data: &[u8]) {
  match selector % 2 {
    0 => {
      let _ = serde_json::from_slice::<AdminConfigPayload>(data);
    }
    _ => {
      let _ = serde_json::from_slice::<AdminFilesSyncRequest>(data);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{AdminApplyMode, AdminFileRoot, AdminFilesSyncRequest};

  #[test]
  fn file_sync_payload_accepts_public_oxirule_names() {
    let payload: AdminFilesSyncRequest = serde_json::from_str(
      r#"{
        "apply": "oxirule",
        "operations": [
          {
            "op": "put",
            "root": "oxirule_group",
            "path": "groups/main.oxirule-group.toml",
            "content": "[[rule_groups]]\nname = \"main\"\n"
          },
          {
            "op": "put",
            "root": "oxirule_rulepack",
            "path": "rulepacks/main.oxirule-rulepack.toml",
            "content": "[rulepack]\nschema_version = 2\nname = \"main\"\nversion = \"0.1.0\"\n\n[[group_files]]\ncontent = '''\n[[rule_groups]]\nname = \"main\"\nwhen = \"true\"\n'''\n"
          },
          {
            "op": "put",
            "root": "oxirule_rulepack_install",
            "path": "rulepacks/main.install.toml",
            "content": "[install]\nname = \"main\"\nversion = \"0.1.0\"\nsource = \"test\"\neffective_mode = \"monitor\"\nforce_mode = false\ninstalled_at = \"2026-06-12T00:00:00Z\"\n"
          }
        ]
      }"#,
    )
    .expect("public file sync payload names should deserialize");

    assert_eq!(payload.apply, AdminApplyMode::OxiRule);
    assert_eq!(payload.operations.len(), 3);
    assert_eq!(payload.operations[0].root, AdminFileRoot::OxiRuleGroup);
    assert_eq!(payload.operations[1].root, AdminFileRoot::OxiRuleRulepack);
    assert_eq!(
      payload.operations[2].root,
      AdminFileRoot::OxiRuleRulepackInstall
    );
  }
}
