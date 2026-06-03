//! Wire types for admin operation status and events.
//! Types are shared by polling, streaming, WebSocket, and WebTransport responses.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminOperationKind {
  CacheWarm,
  #[serde(rename = "oxirule_replay")]
  OxiRuleReplay,
  DiagnosticsPreflight,
  SupportBundle,
  DynamicPolicyImport,
  #[serde(rename = "webtransport_snapshot")]
  WebTransportSnapshot,
  #[serde(rename = "webtransport_drain")]
  WebTransportDrain,
}

impl AdminOperationKind {
  pub(in crate::server) fn as_str(self) -> &'static str {
    match self {
      Self::CacheWarm => "cache_warm",
      Self::OxiRuleReplay => "oxirule_replay",
      Self::DiagnosticsPreflight => "diagnostics_preflight",
      Self::SupportBundle => "support_bundle",
      Self::DynamicPolicyImport => "dynamic_policy_import",
      Self::WebTransportSnapshot => "webtransport_snapshot",
      Self::WebTransportDrain => "webtransport_drain",
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

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;

  #[test]
  fn operation_kind_wire_names_match_contract() {
    let cases = [
      (AdminOperationKind::CacheWarm, "cache_warm"),
      (AdminOperationKind::OxiRuleReplay, "oxirule_replay"),
      (
        AdminOperationKind::DiagnosticsPreflight,
        "diagnostics_preflight",
      ),
      (AdminOperationKind::SupportBundle, "support_bundle"),
      (
        AdminOperationKind::DynamicPolicyImport,
        "dynamic_policy_import",
      ),
      (
        AdminOperationKind::WebTransportSnapshot,
        "webtransport_snapshot",
      ),
      (AdminOperationKind::WebTransportDrain, "webtransport_drain"),
    ];

    for (kind, wire_name) in cases {
      assert_eq!(kind.as_str(), wire_name);
      assert_eq!(serde_json::to_value(kind).unwrap(), json!(wire_name));
      assert_eq!(
        serde_json::from_value::<AdminOperationKind>(json!(wire_name)).unwrap(),
        kind
      );
    }
  }
}
