//! Durable terminal mutation outcomes after the protected side effect returns.

use anyhow::Context;
use http::StatusCode;
use serde_json::Value;

use crate::admin_audit::{AdminAuditHandle, AdminAuditRuntime};

use super::{AdminMutationRuntime, MutationExecution};
use crate::admin_mutation::ledger::{MutationRecord, MutationState, TerminalMutation};

impl AdminMutationRuntime {
  pub(crate) async fn finish(
    &self,
    execution: &MutationExecution,
    status: StatusCode,
    safe_response: Option<Value>,
    audit: &AdminAuditHandle,
    audit_runtime: &AdminAuditRuntime,
  ) -> anyhow::Result<MutationRecord> {
    let state = terminal_state_for_status(status);
    let error_code = match state {
      MutationState::Indeterminate => Some("mutation_indeterminate".to_string()),
      MutationState::Failed => Some("mutation_failed".to_string()),
      _ => None,
    };
    self
      .finish_terminal(
        execution,
        state,
        status,
        safe_response,
        error_code,
        audit,
        audit_runtime,
      )
      .await
  }

  #[allow(clippy::too_many_arguments)]
  async fn finish_terminal(
    &self,
    execution: &MutationExecution,
    state: MutationState,
    status: StatusCode,
    safe_response: Option<Value>,
    error_code: Option<String>,
    audit: &AdminAuditHandle,
    audit_runtime: &AdminAuditRuntime,
  ) -> anyhow::Result<MutationRecord> {
    let outcome = match state {
      MutationState::Committed => "applied",
      MutationState::Indeterminate => "indeterminate",
      _ => "rejected",
    };
    let error = (!matches!(state, MutationState::Committed))
      .then(|| status.canonical_reason().unwrap_or("mutation failed"));
    let event = audit.critical_mutation_event(&execution.request_id, status, outcome, error);
    let terminal_audit_record_id = audit_runtime
      .persist_critical_mutation(event)
      .await
      .context("failed to persist critical mutation terminal audit")?;
    self
      .store()?
      .finish(
        &execution.request_id,
        &TerminalMutation {
          state,
          http_status: status.as_u16(),
          safe_response,
          error_code,
          terminal_audit_record_id,
        },
      )
      .await
      .context("failed to commit Admin mutation receipt")
  }
}

fn terminal_state_for_status(status: StatusCode) -> MutationState {
  if status.is_success() {
    MutationState::Committed
  } else if status.is_server_error() {
    // A server error can mean the protected handler cannot prove whether all
    // side effects completed. Keep the logical revision reservation so no
    // later mutation can build on an uncertain result.
    MutationState::Indeterminate
  } else {
    MutationState::Failed
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn server_errors_block_the_resource_as_indeterminate() {
    assert_eq!(
      terminal_state_for_status(StatusCode::SERVICE_UNAVAILABLE),
      MutationState::Indeterminate
    );
    assert_eq!(
      terminal_state_for_status(StatusCode::BAD_REQUEST),
      MutationState::Failed
    );
    assert_eq!(
      terminal_state_for_status(StatusCode::OK),
      MutationState::Committed
    );
  }
}
