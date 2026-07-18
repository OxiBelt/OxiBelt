//! Durable terminal mutation outcomes after the protected side effect returns.

use anyhow::Context;
use http::{Method, StatusCode};
use serde_json::Value;
use serde_json::json;

use crate::admin_audit::{AdminAuditHandle, AdminAuditRuntime};

use super::{AdminMutationRuntime, MutationExecution};
use crate::admin_mutation::ClusterExecutionModel;
use crate::admin_mutation::ledger::{MutationRecord, MutationState, TerminalMutation};
use crate::admin_mutation::rollout_store::{
  CoordinatorFence, guarded_cluster_finish_tx, load_applied_shared_publication_tx,
};
use crate::admin_mutation::store::finish_tx;

impl AdminMutationRuntime {
  pub(crate) async fn finish_cluster_rollout(
    &self,
    fence: &CoordinatorFence,
    state: MutationState,
    error_code: Option<String>,
    audit_runtime: &AdminAuditRuntime,
  ) -> anyhow::Result<MutationRecord> {
    let record = self
      .load_mutation(&fence.request_id)
      .await?
      .context("cluster mutation disappeared before terminal audit")?;
    let command = self.fetch_cluster_command(&record).await?;
    let (status, outcome) = match state {
      MutationState::Committed => (
        terminal_success_status(
          command.execution_model,
          &command.method,
          &command.path_and_query,
        ),
        "applied",
      ),
      MutationState::Failed | MutationState::RolledBack => (StatusCode::CONFLICT, "rejected"),
      MutationState::RollbackFailed | MutationState::Indeterminate => {
        (StatusCode::SERVICE_UNAVAILABLE, "indeterminate")
      }
      _ => anyhow::bail!("cluster rollout terminal state is invalid"),
    };
    let audit = AdminAuditHandle::new(
      "0.0.0.0:0".parse()?,
      "admin-cluster",
      &command.method,
      command.path_and_query.split('?').next().unwrap_or_default(),
      None,
    );
    audit.set_actor(
      &command.actor.name,
      &command.actor.principal,
      &command.actor.subject,
      &command.actor.groups,
    );
    audit.set_authentication(
      "cluster_recovery",
      None,
      None,
      None,
      None,
      Some(&command.actor.credential_kind),
      None,
      Some(&command.actor.principal),
    );
    audit.record_mutation_context(
      &record.signer_id,
      &record.action,
      &record.resource,
      &record.expected_previous_revision,
      &record.new_revision,
      &record.content_digest,
      record.cluster_id.as_deref().unwrap_or_default(),
      record.membership_revision.as_deref().unwrap_or_default(),
    );
    let event =
      audit.critical_mutation_event(&record.request_id, status, outcome, error_code.as_deref());
    let staged = audit_runtime.stage_critical_mutation(event).await?;
    let store = self.store()?;
    let mut tx = store.pool().begin().await?;
    let terminal_audit_record_id = staged.insert(&mut tx).await?;
    let safe_response = if state == MutationState::Committed
      && command.execution_model == ClusterExecutionModel::SharedStaged
    {
      load_applied_shared_publication_tx(&mut tx, store, fence)
        .await?
        .context("committed shared rollout is missing its exact applied publication")?
        .safe_response
        .context("committed shared rollout is missing its safe response")?
    } else {
      json!({
        "ok": state == MutationState::Committed,
        "request_id": record.request_id,
        "revision": record.new_revision,
        "state": state,
        "token_recoverable": false,
      })
    };
    let terminal = TerminalMutation {
      state,
      http_status: status.as_u16(),
      safe_response: Some(safe_response),
      error_code,
      terminal_audit_record_id,
    };
    let finished = guarded_cluster_finish_tx(&mut tx, store, fence, &terminal).await?;
    tx.commit().await?;
    staged.publish();
    Ok(finished)
  }

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
    let staged_audit = audit_runtime
      .stage_critical_mutation(event)
      .await
      .context("failed to stage critical mutation terminal audit")?;
    let store = self.store()?;
    let mut tx = store.pool().begin().await?;
    let terminal_audit_record_id = staged_audit
      .insert(&mut tx)
      .await
      .context("failed to persist critical mutation terminal audit")?;
    let record = match finish_tx(
      &mut tx,
      store.namespace(),
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
    {
      Ok(record) => record,
      Err(error) => {
        audit_runtime.record_required_persistence_failure("postgres_unavailable");
        return Err(error).context("failed to stage Admin mutation receipt");
      }
    };
    if let Err(error) = tx.commit().await {
      audit_runtime.record_required_persistence_failure("postgres_unavailable");
      return Err(error).context("failed to commit Admin mutation receipt and terminal audit");
    }
    staged_audit.publish();
    Ok(record)
  }
}

fn terminal_success_status(
  execution_model: ClusterExecutionModel,
  method: &Method,
  path_and_query: &str,
) -> StatusCode {
  let path = path_and_query.split('?').next().unwrap_or_default();
  if execution_model == ClusterExecutionModel::SharedStaged
    && *method == Method::POST
    && matches!(
      path,
      "/admin/v1/ipm/principals"
        | "/admin/v1/ipm/credentials"
        | "/admin/v1/ipm/policies"
        | "/admin/v1/ipm/bindings"
        | "/admin/v1/break-glass/activations"
    )
  {
    StatusCode::CREATED
  } else {
    StatusCode::OK
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

  #[test]
  fn shared_create_preserves_created_while_updates_and_deletes_use_ok() {
    assert_eq!(
      terminal_success_status(
        ClusterExecutionModel::SharedStaged,
        &Method::POST,
        "/admin/v1/ipm/credentials",
      ),
      StatusCode::CREATED
    );
    assert_eq!(
      terminal_success_status(
        ClusterExecutionModel::SharedStaged,
        &Method::PATCH,
        "/admin/v1/ipm/credentials/api",
      ),
      StatusCode::OK
    );
    assert_eq!(
      terminal_success_status(
        ClusterExecutionModel::SharedStaged,
        &Method::DELETE,
        "/admin/v1/ipm/credentials/api",
      ),
      StatusCode::OK
    );
  }
}
