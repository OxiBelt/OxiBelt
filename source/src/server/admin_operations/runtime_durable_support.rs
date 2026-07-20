//! Bounded wire conversion and terminal material for durable Admin operations.

use std::str::FromStr as _;

use anyhow::Context as _;
use serde_json::Value;
use tracing::warn;

use super::artifact::sha256_digest;
use super::runtime::{
  AdminOperationError, AdminOperationSubmission, AdminOperationWorkResult, now_unix_ms,
};
use super::types::{
  ADMIN_OPERATION_RECEIPT_SCHEMA_VERSION, AdminOperationDurability, AdminOperationEvent,
  AdminOperationSafeErrorClass, AdminOperationSnapshot, AdminOperationState,
  AdminOperationTerminalReceiptV1,
};
use super::{JournalEvent, JournalOperation};

pub(super) fn encode_hex(bytes: &[u8]) -> String {
  let mut encoded = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    use std::fmt::Write as _;
    let _ = write!(encoded, "{byte:02x}");
  }
  encoded
}

pub(super) fn snapshot_from_journal(operation: &JournalOperation) -> AdminOperationSnapshot {
  let terminal_visible = !operation.state.is_terminal() || operation.terminal_audit_confirmed;
  let visible_state = if terminal_visible {
    operation.state
  } else {
    // The durable execution result is internal until its exact audit event is
    // externally anchored. Keep public snapshots nonterminal in the interim.
    AdminOperationState::Running
  };
  let terminal_receipt = terminal_visible
    .then(|| {
      operation
        .terminal_receipt
        .as_deref()
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
    })
    .flatten();
  let error_class = terminal_visible
    .then(|| {
      operation
        .safe_error_class
        .as_deref()
        .and_then(|value| AdminOperationSafeErrorClass::from_str(value).ok())
    })
    .flatten();
  AdminOperationSnapshot {
    id: operation.operation_id.clone(),
    kind: operation.kind,
    state: visible_state,
    schema_version: operation.schema_version,
    revision: operation.revision,
    durability: AdminOperationDurability::Durable,
    recovery_class: operation.recovery_class,
    created_at_unix_ms: operation.created_at_unix_ms,
    updated_at_unix_ms: Some(operation.updated_at_unix_ms),
    started_at_unix_ms: visible_state
      .owns_execution_lease()
      .then_some(operation.updated_at_unix_ms),
    finished_at_unix_ms: visible_state
      .is_receiptable_terminal()
      .then_some(operation.updated_at_unix_ms),
    expires_at_unix_ms: Some(operation.expires_at_unix_ms),
    retention_until_unix_ms: Some(operation.retention_until_unix_ms),
    actor: operation.actor.clone(),
    principal: operation.principal.clone(),
    request_id: operation.request_id.clone(),
    cancel_requested: matches!(
      operation.state,
      AdminOperationState::CancellationRequested
        | AdminOperationState::Compensating
        | AdminOperationState::Cancelled
    ),
    progress: operation
      .progress
      .clone()
      .and_then(|value| serde_json::from_value(value).ok()),
    result: terminal_visible
      .then(|| operation.terminal_result.clone())
      .flatten(),
    error: terminal_visible
      .then(|| operation.error_code.clone())
      .flatten(),
    error_class,
    error_code: terminal_visible
      .then(|| operation.error_code.clone())
      .flatten(),
    terminal_receipt,
  }
}

pub(super) fn event_from_journal(
  event: &JournalEvent,
  current: &AdminOperationSnapshot,
) -> AdminOperationEvent {
  let mut operation = current.clone();
  operation.state = event.state;
  operation.revision = event.revision;
  operation.updated_at_unix_ms = Some(event.created_at_unix_ms);
  operation.progress = event
    .progress
    .clone()
    .and_then(|value| serde_json::from_value(value).ok());
  AdminOperationEvent {
    sequence: event.revision,
    event: event.event.clone(),
    created_at_unix_ms: event.created_at_unix_ms,
    operation,
  }
}

pub(super) fn request_fingerprint(
  submission: &AdminOperationSubmission,
  resource_digest: &str,
  command: &[u8],
) -> String {
  let mut bytes = b"OXIBELT-ADMIN-OPERATION-REQUEST-V1\0".to_vec();
  for value in [
    submission.kind.as_str().as_bytes(),
    submission.permission_action.as_bytes(),
    resource_digest.as_bytes(),
    submission.recovery_class.as_str().as_bytes(),
    command,
  ] {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
  }
  sha256_digest(&bytes)
}

pub(super) fn terminal_outcome(
  work: AdminOperationWorkResult,
  _cancellation_requested: bool,
  result_max_bytes: usize,
) -> (
  AdminOperationState,
  Option<Value>,
  Option<AdminOperationSafeErrorClass>,
  Option<&'static str>,
) {
  if matches!(&work, Err(error) if error == "operation cancelled") {
    return (
      AdminOperationState::Cancelled,
      None,
      Some(AdminOperationSafeErrorClass::Cancelled),
      Some("operation_cancelled"),
    );
  }
  match work {
    Ok(result)
      if serde_json::to_vec(&result).is_ok_and(|bytes| bytes.len() <= result_max_bytes) =>
    {
      (AdminOperationState::Succeeded, Some(result), None, None)
    }
    Ok(_) => (
      AdminOperationState::Failed,
      None,
      Some(AdminOperationSafeErrorClass::Capacity),
      Some("result_too_large"),
    ),
    Err(_) => (
      AdminOperationState::Failed,
      None,
      Some(AdminOperationSafeErrorClass::Internal),
      Some("operation_failed"),
    ),
  }
}

pub(super) fn receipt_bytes(
  operation: &JournalOperation,
  state: AdminOperationState,
  revision: u64,
  result: Option<&Value>,
  error_class: Option<AdminOperationSafeErrorClass>,
  error_code: Option<&str>,
  audit_record_id: i64,
) -> anyhow::Result<Vec<u8>> {
  let result_digest = result
    .map(serde_json::to_vec)
    .transpose()?
    .map(|bytes| sha256_digest(&bytes));
  serde_json::to_vec(&AdminOperationTerminalReceiptV1 {
    schema_version: ADMIN_OPERATION_RECEIPT_SCHEMA_VERSION,
    operation_id: operation.operation_id.clone(),
    kind: operation.kind,
    state,
    revision,
    completed_at_unix_ms: now_unix_ms(),
    result_digest,
    error_class,
    error_code: error_code.map(str::to_string),
    audit_record_id: Some(audit_record_id),
  })
  .context("failed to encode durable Admin operation receipt")
}

pub(super) fn terminal_event(state: AdminOperationState) -> &'static str {
  match state {
    AdminOperationState::Succeeded => "operation.succeeded",
    AdminOperationState::Failed => "operation.failed",
    AdminOperationState::Cancelled => "operation.cancelled",
    AdminOperationState::Indeterminate => "operation.indeterminate",
    _ => "operation.finished",
  }
}

pub(super) fn terminal_or_cancel_event(state: AdminOperationState) -> &'static str {
  if state == AdminOperationState::Cancelled {
    "operation.cancelled"
  } else {
    "operation.cancellation_requested"
  }
}

pub(super) fn unavailable(error: anyhow::Error) -> AdminOperationError {
  warn!(error = %error, "durable Admin operation journal is unavailable");
  AdminOperationError::Unavailable
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn raw_work_errors_are_mapped_to_fixed_safe_codes() {
    let outcome = terminal_outcome(
      Err("postgres://secret@example.test".to_string()),
      false,
      1024,
    );
    assert_eq!(outcome.0, AdminOperationState::Failed);
    assert_eq!(outcome.3, Some("operation_failed"));
  }

  #[test]
  fn completed_work_wins_a_late_cancellation_request() {
    let outcome = terminal_outcome(Ok(serde_json::json!({"applied": true})), true, 1024);
    assert_eq!(outcome.0, AdminOperationState::Succeeded);
    assert_eq!(outcome.1, Some(serde_json::json!({"applied": true})));

    let cancelled = terminal_outcome(Err("operation cancelled".to_string()), false, 1024);
    assert_eq!(cancelled.0, AdminOperationState::Cancelled);
  }
}
