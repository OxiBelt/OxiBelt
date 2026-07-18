//! Wire types for admin operation status and events.
//! Types are shared by polling, streaming, WebSocket, and WebTransport responses.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(in crate::server) const ADMIN_OPERATION_SCHEMA_VERSION: u16 = 1;
pub(in crate::server) const ADMIN_OPERATION_RECEIPT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminOperationKind {
  #[default]
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
  pub(in crate::server) const fn as_str(self) -> &'static str {
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

impl FromStr for AdminOperationKind {
  type Err = &'static str;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "cache_warm" => Ok(Self::CacheWarm),
      "oxirule_replay" => Ok(Self::OxiRuleReplay),
      "diagnostics_preflight" => Ok(Self::DiagnosticsPreflight),
      "support_bundle" => Ok(Self::SupportBundle),
      "dynamic_policy_import" => Ok(Self::DynamicPolicyImport),
      "webtransport_snapshot" => Ok(Self::WebTransportSnapshot),
      "webtransport_drain" => Ok(Self::WebTransportDrain),
      _ => Err("unknown admin operation kind"),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminOperationState {
  #[default]
  Accepted,
  Queued,
  Claimed,
  Running,
  CancellationRequested,
  Compensating,
  Succeeded,
  Failed,
  Cancelled,
  Indeterminate,
  /// Legacy wire value retained so old retained responses can still be decoded.
  Expired,
}

impl AdminOperationState {
  pub(in crate::server) const fn as_str(self) -> &'static str {
    match self {
      Self::Accepted => "accepted",
      Self::Queued => "queued",
      Self::Claimed => "claimed",
      Self::Running => "running",
      Self::CancellationRequested => "cancellation_requested",
      Self::Compensating => "compensating",
      Self::Succeeded => "succeeded",
      Self::Failed => "failed",
      Self::Cancelled => "cancelled",
      Self::Indeterminate => "indeterminate",
      Self::Expired => "expired",
    }
  }

  pub(in crate::server) const fn is_terminal(self) -> bool {
    matches!(
      self,
      Self::Succeeded | Self::Failed | Self::Cancelled | Self::Indeterminate | Self::Expired
    )
  }

  pub(in crate::server) const fn is_receiptable_terminal(self) -> bool {
    matches!(
      self,
      Self::Succeeded | Self::Failed | Self::Cancelled | Self::Indeterminate
    )
  }

  pub(in crate::server) const fn owns_execution_lease(self) -> bool {
    matches!(
      self,
      Self::Claimed | Self::Running | Self::CancellationRequested | Self::Compensating
    )
  }
}

impl FromStr for AdminOperationState {
  type Err = &'static str;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "accepted" => Ok(Self::Accepted),
      "queued" => Ok(Self::Queued),
      "claimed" => Ok(Self::Claimed),
      "running" => Ok(Self::Running),
      "cancellation_requested" => Ok(Self::CancellationRequested),
      "compensating" => Ok(Self::Compensating),
      "succeeded" => Ok(Self::Succeeded),
      "failed" => Ok(Self::Failed),
      "cancelled" => Ok(Self::Cancelled),
      "indeterminate" => Ok(Self::Indeterminate),
      "expired" => Ok(Self::Expired),
      _ => Err("unknown admin operation state"),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminOperationDurability {
  #[default]
  Ephemeral,
  Durable,
}

impl AdminOperationDurability {
  pub(in crate::server) const fn as_str(self) -> &'static str {
    match self {
      Self::Ephemeral => "ephemeral",
      Self::Durable => "durable",
    }
  }
}

impl FromStr for AdminOperationDurability {
  type Err = &'static str;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "ephemeral" => Ok(Self::Ephemeral),
      "durable" => Ok(Self::Durable),
      _ => Err("unknown admin operation durability"),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminOperationRecoveryClass {
  Resumable,
  Restartable,
  Compensatable,
  #[default]
  NonResumable,
}

impl AdminOperationRecoveryClass {
  pub(in crate::server) const fn as_str(self) -> &'static str {
    match self {
      Self::Resumable => "resumable",
      Self::Restartable => "restartable",
      Self::Compensatable => "compensatable",
      Self::NonResumable => "non_resumable",
    }
  }
}

impl FromStr for AdminOperationRecoveryClass {
  type Err = &'static str;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "resumable" => Ok(Self::Resumable),
      "restartable" => Ok(Self::Restartable),
      "compensatable" => Ok(Self::Compensatable),
      "non_resumable" => Ok(Self::NonResumable),
      _ => Err("unknown admin operation recovery class"),
    }
  }
}

/// Coarse, fixed-vocabulary error data safe to persist and return to an Admin client.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::server) enum AdminOperationSafeErrorClass {
  InvalidRequest,
  AuthorizationDenied,
  Conflict,
  Capacity,
  DependencyUnavailable,
  Integrity,
  Timeout,
  Cancelled,
  Internal,
  Indeterminate,
}

impl AdminOperationSafeErrorClass {
  pub(in crate::server) const fn as_str(self) -> &'static str {
    match self {
      Self::InvalidRequest => "invalid_request",
      Self::AuthorizationDenied => "authorization_denied",
      Self::Conflict => "conflict",
      Self::Capacity => "capacity",
      Self::DependencyUnavailable => "dependency_unavailable",
      Self::Integrity => "integrity",
      Self::Timeout => "timeout",
      Self::Cancelled => "cancelled",
      Self::Internal => "internal",
      Self::Indeterminate => "indeterminate",
    }
  }
}

impl FromStr for AdminOperationSafeErrorClass {
  type Err = &'static str;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "invalid_request" => Ok(Self::InvalidRequest),
      "authorization_denied" => Ok(Self::AuthorizationDenied),
      "conflict" => Ok(Self::Conflict),
      "capacity" => Ok(Self::Capacity),
      "dependency_unavailable" => Ok(Self::DependencyUnavailable),
      "integrity" => Ok(Self::Integrity),
      "timeout" => Ok(Self::Timeout),
      "cancelled" => Ok(Self::Cancelled),
      "internal" => Ok(Self::Internal),
      "indeterminate" => Ok(Self::Indeterminate),
      _ => Err("unknown admin operation safe error class"),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(in crate::server) struct AdminOperationProgress {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub phase: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub processed: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub total: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub(in crate::server) struct AdminOperationTerminalReceiptV1 {
  #[serde(default = "default_receipt_schema_version")]
  pub schema_version: u16,
  pub operation_id: String,
  pub kind: AdminOperationKind,
  pub state: AdminOperationState,
  pub revision: u64,
  pub completed_at_unix_ms: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub result_digest: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error_class: Option<AdminOperationSafeErrorClass>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error_code: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub audit_record_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(in crate::server) struct AdminOperationSnapshot {
  pub id: String,
  pub kind: AdminOperationKind,
  pub state: AdminOperationState,
  #[serde(default = "default_operation_schema_version")]
  pub schema_version: u16,
  #[serde(default)]
  pub revision: u64,
  #[serde(default)]
  pub durability: AdminOperationDurability,
  #[serde(default)]
  pub recovery_class: AdminOperationRecoveryClass,
  pub created_at_unix_ms: u64,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub updated_at_unix_ms: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub started_at_unix_ms: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub finished_at_unix_ms: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expires_at_unix_ms: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub retention_until_unix_ms: Option<u64>,
  pub actor: String,
  pub principal: String,
  pub request_id: String,
  #[serde(default)]
  pub cancel_requested: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub progress: Option<AdminOperationProgress>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub result: Option<Value>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error_class: Option<AdminOperationSafeErrorClass>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error_code: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub terminal_receipt: Option<AdminOperationTerminalReceiptV1>,
}

impl Default for AdminOperationSnapshot {
  fn default() -> Self {
    Self {
      id: String::new(),
      kind: AdminOperationKind::default(),
      state: AdminOperationState::default(),
      schema_version: ADMIN_OPERATION_SCHEMA_VERSION,
      revision: 0,
      durability: AdminOperationDurability::default(),
      recovery_class: AdminOperationRecoveryClass::default(),
      created_at_unix_ms: 0,
      updated_at_unix_ms: None,
      started_at_unix_ms: None,
      finished_at_unix_ms: None,
      expires_at_unix_ms: None,
      retention_until_unix_ms: None,
      actor: String::new(),
      principal: String::new(),
      request_id: String::new(),
      cancel_requested: false,
      progress: None,
      result: None,
      error: None,
      error_class: None,
      error_code: None,
      terminal_receipt: None,
    }
  }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(in crate::server) struct AdminOperationEvent {
  pub sequence: u64,
  pub event: String,
  pub created_at_unix_ms: u64,
  pub operation: AdminOperationSnapshot,
}

const fn default_operation_schema_version() -> u16 {
  ADMIN_OPERATION_SCHEMA_VERSION
}

const fn default_receipt_schema_version() -> u16 {
  ADMIN_OPERATION_RECEIPT_SCHEMA_VERSION
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

    assert_eq!(
      cases
        .iter()
        .map(|(_, wire_name)| *wire_name)
        .collect::<Vec<_>>(),
      crate::server::ADMIN_OPERATION_KIND_WIRE_VALUES
    );

    for (kind, wire_name) in cases {
      assert_eq!(kind.as_str(), wire_name);
      assert_eq!(serde_json::to_value(kind).unwrap(), json!(wire_name));
      assert_eq!(wire_name.parse::<AdminOperationKind>().unwrap(), kind);
      assert_eq!(
        serde_json::from_value::<AdminOperationKind>(json!(wire_name)).unwrap(),
        kind
      );
    }
  }

  #[test]
  fn operation_state_wire_names_match_contract() {
    let cases = [
      (AdminOperationState::Accepted, "accepted"),
      (AdminOperationState::Queued, "queued"),
      (AdminOperationState::Claimed, "claimed"),
      (AdminOperationState::Running, "running"),
      (
        AdminOperationState::CancellationRequested,
        "cancellation_requested",
      ),
      (AdminOperationState::Compensating, "compensating"),
      (AdminOperationState::Succeeded, "succeeded"),
      (AdminOperationState::Failed, "failed"),
      (AdminOperationState::Cancelled, "cancelled"),
      (AdminOperationState::Indeterminate, "indeterminate"),
      (AdminOperationState::Expired, "expired"),
    ];

    assert_eq!(
      cases
        .iter()
        .map(|(_, wire_name)| *wire_name)
        .collect::<Vec<_>>(),
      crate::server::ADMIN_OPERATION_STATE_WIRE_VALUES
    );

    for (state, wire_name) in cases {
      assert_eq!(state.as_str(), wire_name);
      assert_eq!(serde_json::to_value(state).unwrap(), json!(wire_name));
      assert_eq!(wire_name.parse::<AdminOperationState>().unwrap(), state);
    }
  }

  #[test]
  fn legacy_snapshot_json_deserializes_with_safe_defaults() {
    let snapshot: AdminOperationSnapshot = serde_json::from_value(json!({
      "id": "op_550e8400-e29b-41d4-a716-446655440000",
      "kind": "support_bundle",
      "state": "running",
      "created_at_unix_ms": 1,
      "actor": "operator",
      "principal": "spiffe://example.test/operator",
      "request_id": "req-1"
    }))
    .unwrap();

    assert_eq!(snapshot.schema_version, ADMIN_OPERATION_SCHEMA_VERSION);
    assert_eq!(snapshot.revision, 0);
    assert_eq!(snapshot.durability, AdminOperationDurability::Ephemeral);
    assert_eq!(
      snapshot.recovery_class,
      AdminOperationRecoveryClass::NonResumable
    );
    assert!(!snapshot.cancel_requested);
    assert!(snapshot.terminal_receipt.is_none());
  }

  #[test]
  fn terminal_receipt_requires_a_terminal_state() {
    let mut receipt = AdminOperationTerminalReceiptV1 {
      schema_version: ADMIN_OPERATION_RECEIPT_SCHEMA_VERSION,
      operation_id: "op_550e8400-e29b-41d4-a716-446655440000".to_string(),
      kind: AdminOperationKind::SupportBundle,
      state: AdminOperationState::Succeeded,
      revision: 7,
      completed_at_unix_ms: 42,
      result_digest: Some("sha256:test".to_string()),
      error_class: None,
      error_code: None,
      audit_record_id: Some(1),
    };

    assert!(receipt.state.is_receiptable_terminal());
    receipt.state = AdminOperationState::Running;
    assert!(!receipt.state.is_receiptable_terminal());
    receipt.state = AdminOperationState::Expired;
    assert!(!receipt.state.is_receiptable_terminal());
  }
}
