use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminOperationKind {
  CacheWarm,
  OxiRuleReplay,
  DiagnosticsPreflight,
  SupportBundle,
  DynamicPolicyImport,
}

impl AdminOperationKind {
  pub(in crate::server) fn as_str(self) -> &'static str {
    match self {
      Self::CacheWarm => "cache_warm",
      Self::OxiRuleReplay => "oxirule_replay",
      Self::DiagnosticsPreflight => "diagnostics_preflight",
      Self::SupportBundle => "support_bundle",
      Self::DynamicPolicyImport => "dynamic_policy_import",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminOperationState {
  Queued,
  Running,
  Succeeded,
  Failed,
  Cancelled,
  Expired,
}

impl AdminOperationState {
  pub(in crate::server) fn is_terminal(self) -> bool {
    matches!(
      self,
      Self::Succeeded | Self::Failed | Self::Cancelled | Self::Expired
    )
  }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(in crate::server) struct AdminOperationProgress {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub phase: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub processed: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub total: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::server) struct AdminOperationSnapshot {
  pub id: String,
  pub kind: AdminOperationKind,
  pub state: AdminOperationState,
  pub created_at_unix_ms: u64,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub started_at_unix_ms: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub finished_at_unix_ms: Option<u64>,
  pub actor: String,
  pub principal: String,
  pub request_id: String,
  pub cancel_requested: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub progress: Option<AdminOperationProgress>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub result: Option<Value>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::server) struct AdminOperationEvent {
  pub sequence: u64,
  pub event: String,
  pub created_at_unix_ms: u64,
  pub operation: AdminOperationSnapshot,
}
