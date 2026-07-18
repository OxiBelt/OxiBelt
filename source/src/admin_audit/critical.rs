//! Synchronous durable audit writes for replay-protected mutations.

use anyhow::Context;
use http::StatusCode;
use serde_json::json;
use sqlx::{Pool, Postgres, Transaction};
use tokio::sync::MutexGuard;

use super::integrity::IntegrityChain;
use super::{AdminAuditEvent, AdminAuditHandle, AdminAuditRuntime, store};

pub(crate) struct StagedCriticalAudit<'a> {
  runtime: &'a AdminAuditRuntime,
  event: AdminAuditEvent,
  staged_chain: IntegrityChain,
  live_chain: MutexGuard<'a, IntegrityChain>,
}

impl StagedCriticalAudit<'_> {
  pub(crate) async fn insert(&self, tx: &mut Transaction<'_, Postgres>) -> anyhow::Result<i64> {
    let durable = self
      .runtime
      .store
      .as_ref()
      .context("critical Admin mutation audit store is unavailable")?;
    let result = store::insert_record_returning_id_tx(tx, &durable.namespace, &self.event).await;
    if result.is_err() {
      self
        .runtime
        .record_required_persistence_failure("postgres_unavailable");
    }
    result
  }

  pub(crate) fn publish(mut self) {
    *self.live_chain = self.staged_chain;
    self.runtime.publish_postgres_event(&self.event);
  }
}

impl AdminAuditRuntime {
  #[cfg(test)]
  pub(crate) async fn test_with_postgres(
    pool: Pool<Postgres>,
    namespace: String,
  ) -> anyhow::Result<Self> {
    Box::pin(store::init_postgres(&pool)).await?;
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    let metrics = std::thread::Builder::new()
      .name("admin-audit-postgres-test-metrics".to_string())
      .stack_size(64 * 1024 * 1024)
      .spawn(|| std::sync::Arc::new(crate::metrics::Metrics::default()))
      .context("failed to spawn Admin audit test metrics constructor")?
      .join()
      .map_err(|_| anyhow::anyhow!("Admin audit test metrics constructor panicked"))?;
    Ok(Self {
      store: Some(super::PostgresAdminAuditStore {
        namespace,
        pool,
        sender,
      }),
      spool: None,
      export: super::AdminAuditExportRuntime::default(),
      mode: crate::config::AdminAuditMode::DurableRequired,
      acknowledgement: crate::config::AdminAuditAcknowledgement::Postgres,
      required_actions: std::sync::Arc::new(Default::default()),
      instance_id: std::sync::Arc::from("postgres-test-instance"),
      direct_integrity: std::sync::Arc::new(tokio::sync::Mutex::new(
        super::fallback_integrity_chain(),
      )),
      max_event_bytes: 64 * 1024,
      metrics,
    })
  }

  pub(crate) fn critical_postgres_pool(&self) -> Option<Pool<Postgres>> {
    self.store.as_ref().map(|store| store.pool.clone())
  }

  pub(crate) async fn stage_critical_mutation(
    &self,
    event: AdminAuditEvent,
  ) -> anyhow::Result<StagedCriticalAudit<'_>> {
    let event = self.prepare_unsealed_event(event)?;
    let live_chain = self.direct_integrity.lock().await;
    let mut staged_chain = live_chain.clone();
    let event = match self.seal_with_chain(event, &mut staged_chain) {
      Ok(event) => event,
      Err(error) => {
        let reason = if error.to_string().contains("exceeds") {
          "event_oversize"
        } else {
          "integrity_failure"
        };
        self.record_required_persistence_failure(reason);
        return Err(error);
      }
    };
    Ok(StagedCriticalAudit {
      runtime: self,
      event,
      staged_chain,
      live_chain,
    })
  }

  fn publish_postgres_event(&self, event: &AdminAuditEvent) {
    self
      .metrics
      .record_admin_audit_event(&event.outcome, "postgres");
    super::emit_tracing(event);
    self.export.emit_admin_event(event, self.metrics.as_ref());
  }

  pub(crate) fn record_required_persistence_failure(&self, reason: &str) {
    self.metrics.record_admin_audit_required_rejection(reason);
  }

  /// Builds a bounded lifecycle event for a durable Admin operation.
  ///
  /// Operation execution is detached from the originating HTTP request, so
  /// this event intentionally carries only the authenticated actor/principal,
  /// immutable operation identity, fixed kind/state values, and revision. Raw
  /// work payloads, checkpoints, progress details, and error strings never
  /// enter enforcing audit storage through this path.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn operation_lifecycle_event(
    &self,
    operation_id: &str,
    kind: &str,
    actor: &str,
    principal: &str,
    request_id: &str,
    state: &str,
    revision: u64,
    error_code: Option<&str>,
  ) -> AdminAuditEvent {
    let occurrence = super::event::occurrence_timestamp().ok();
    let terminal = matches!(
      state,
      "succeeded" | "failed" | "cancelled" | "indeterminate"
    );
    let result = match state {
      "succeeded" | "cancelled" => super::event::AuditResult::Applied,
      "indeterminate" => super::event::AuditResult::Indeterminate,
      "failed" => super::event::AuditResult::Rejected,
      _ => super::event::AuditResult::Accepted,
    };
    let status = match state {
      "succeeded" | "cancelled" => StatusCode::OK,
      "failed" | "indeterminate" => StatusCode::INTERNAL_SERVER_ERROR,
      _ => StatusCode::ACCEPTED,
    };
    let resource = format!("operation/{kind}/{operation_id}");
    AdminAuditEvent {
      schema_version: super::event::ADMIN_AUDIT_SCHEMA_VERSION.to_string(),
      event_id: super::event::generate_event_id().unwrap_or_default(),
      timestamp: occurrence
        .as_ref()
        .map(|timestamp| timestamp.rfc3339.clone())
        .unwrap_or_default(),
      timestamp_unix_ms: occurrence.map_or(0, |timestamp| timestamp.unix_ms),
      instance_id: self.instance_id.to_string(),
      phase: if terminal {
        super::event::AuditPhase::Terminal
      } else {
        super::event::AuditPhase::Intent
      },
      request_id: request_id.to_string(),
      mutation_request_id: Some(operation_id.to_string()),
      actor: Some(actor.to_string()),
      principal: Some(principal.to_string()),
      subject: None,
      groups: Vec::new(),
      workload_identity_kind: None,
      workload_identity: None,
      workload_principal: None,
      certificate_fingerprint_sha256: None,
      credential_kind: None,
      credential_identity: None,
      credential_principal: None,
      credential_id: None,
      authentication_reason: Some("previously_authorized_operation".to_string()),
      peer: "internal".to_string(),
      source_ip: None,
      source_address: None,
      scheme: "internal".to_string(),
      method: "WORKER".to_string(),
      path: format!("/admin/v1/operations/{operation_id}"),
      service: Some("admin-operation".to_string()),
      operation: "operations.lifecycle".to_string(),
      durability_action: Some("operations.lifecycle".to_string()),
      action: Some("operations.lifecycle".to_string()),
      resource: Some(resource),
      target_kind: Some("operation".to_string()),
      target_id: Some(operation_id.to_string()),
      previous_revision: revision.checked_sub(1).map(|value| value.to_string()),
      desired_revision: Some(revision.to_string()),
      content_digest: None,
      status: status.as_u16(),
      result,
      outcome: state.to_string(),
      error_code: error_code.map(str::to_string),
      error: None,
      request_summary: json!({
        "operation": {
          "id": operation_id,
          "kind": kind,
          "state": state,
          "revision": revision,
        }
      }),
      integrity: None,
      durable_required: true,
      lifecycle_managed: true,
    }
  }

  /// Persists a critical mutation event before returning to the caller.
  ///
  /// Unlike the normal bounded audit queue, this path proves the row exists
  /// before a protected side effect can begin. P1-13 configuration validation
  /// keeps this path on the mutation ledger's PostgreSQL authority even when
  /// general P1-14 acknowledgement uses the local spool.
  pub(crate) async fn persist_critical_mutation(
    &self,
    event: AdminAuditEvent,
  ) -> anyhow::Result<i64> {
    let durable = self
      .store
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("critical Admin mutation audit store is unavailable"))?;
    let staged = self.stage_critical_mutation(event).await?;
    let mut tx = durable.pool.begin().await?;
    let record_id = staged.insert(&mut tx).await?;
    if let Err(error) = tx.commit().await {
      self.record_required_persistence_failure("postgres_unavailable");
      return Err(error.into());
    }
    staged.publish();
    Ok(record_id)
  }
}

impl AdminAuditHandle {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn record_mutation_context(
    &self,
    signer_id: &str,
    action: &str,
    resource: &str,
    expected_previous_revision: &str,
    new_revision: &str,
    content_digest: &str,
    cluster_id: &str,
    membership_revision: &str,
  ) {
    let mut event = self.event_guard();
    event.service = Some("admin-mutation".to_string());
    event.operation = action.to_string();
    event.durability_action = Some(action.to_string());
    event.action = Some(action.to_string());
    event.resource = Some(resource.to_string());
    event.previous_revision = Some(expected_previous_revision.to_string());
    event.desired_revision = Some(new_revision.to_string());
    event.content_digest = Some(content_digest.to_string());
    event.durable_required = true;
    if !event.request_summary.is_object() {
      event.request_summary = json!({});
    }
    event.request_summary["mutation"] = json!({
      "signer_id": signer_id,
      "expected_previous_revision": expected_previous_revision,
      "new_revision": new_revision,
      "content_digest": content_digest,
      "target": {
        "cluster_id": cluster_id,
        "membership_revision": membership_revision,
      },
    });
  }

  pub(crate) fn mark_critical_mutation_lifecycle_managed(&self) {
    self.event_guard().lifecycle_managed = true;
  }

  pub(crate) fn critical_mutation_event(
    &self,
    mutation_request_id: &str,
    status: StatusCode,
    outcome: &str,
    error: Option<&str>,
  ) -> AdminAuditEvent {
    let mut event = self.event_guard().clone();
    event.event_id = super::event::generate_event_id().unwrap_or_default();
    if let Ok(occurrence) = super::event::occurrence_timestamp() {
      event.timestamp = occurrence.rfc3339;
      event.timestamp_unix_ms = occurrence.unix_ms;
    }
    event.mutation_request_id = Some(mutation_request_id.to_string());
    event.status = status.as_u16();
    event.phase = if outcome == "attempted" {
      super::event::AuditPhase::Intent
    } else {
      super::event::AuditPhase::Terminal
    };
    event.result = match outcome {
      "attempted" | "accepted" => super::event::AuditResult::Accepted,
      "applied" => super::event::AuditResult::Applied,
      "indeterminate" => super::event::AuditResult::Indeterminate,
      _ => super::event::AuditResult::Rejected,
    };
    event.outcome = outcome.to_string();
    event.error_code = error.map(|_| {
      if outcome == "indeterminate" {
        "mutation_indeterminate"
      } else {
        "mutation_failed"
      }
      .to_string()
    });
    event.error = error.map(str::to_string);
    event
  }
}

#[cfg(test)]
mod tests {
  use http::Method;

  use super::*;

  #[test]
  fn critical_mutation_context_is_redacted_and_revision_attributable() {
    let audit = AdminAuditHandle::new(
      "127.0.0.1:1234".parse().expect("socket address"),
      "https",
      &Method::POST,
      "/admin/v1/config/load",
      None,
    );
    audit.record_mutation_context(
      "controller-1",
      "config.load",
      "config",
      "r-1",
      "r-2",
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "single",
      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let event = audit.critical_mutation_event("request-1", StatusCode::ACCEPTED, "attempted", None);

    assert_eq!(event.operation, "config.load");
    assert_eq!(event.outcome, "attempted");
    assert_eq!(event.action.as_deref(), Some("config.load"));
    assert_eq!(event.request_summary["mutation"]["new_revision"], "r-2");
    assert!(event.request_summary.get("signature").is_none());
    assert!(
      !event.lifecycle_managed,
      "replay and conflict responses still need an outer terminal audit"
    );
    audit.mark_critical_mutation_lifecycle_managed();
    assert!(
      audit
        .critical_mutation_event("request-1", StatusCode::OK, "applied", None)
        .lifecycle_managed,
      "only a claimed mutation transfers terminal auditing to the mutation lifecycle"
    );
  }

  #[test]
  fn operation_lifecycle_event_contains_only_bounded_safe_context() {
    let runtime = AdminAuditRuntime::test_export_only();
    let event = runtime.operation_lifecycle_event(
      "op_550e8400-e29b-41d4-a716-446655440000",
      "dynamic_policy_import",
      "controller",
      "platform-admin",
      "request-1",
      "indeterminate",
      9,
      Some("commit_outcome_unknown"),
    );

    assert_eq!(event.operation, "operations.lifecycle");
    assert_eq!(event.outcome, "indeterminate");
    assert_eq!(
      event.result,
      super::super::event::AuditResult::Indeterminate
    );
    assert_eq!(event.previous_revision.as_deref(), Some("8"));
    assert_eq!(event.desired_revision.as_deref(), Some("9"));
    assert_eq!(event.error_code.as_deref(), Some("commit_outcome_unknown"));
    assert!(event.error.is_none());
    let encoded = serde_json::to_string(&event).expect("operation event should encode");
    assert!(!encoded.contains("Authorization"));
    assert!(!encoded.contains("checkpoint"));
  }

  #[tokio::test]
  async fn dropping_a_staged_audit_does_not_advance_the_chain() {
    let runtime = AdminAuditRuntime::test_export_only();
    let first = runtime
      .stage_critical_mutation(event_for_chain_test())
      .await
      .unwrap();
    let first_sequence = first.event.integrity.as_ref().unwrap().sequence;
    drop(first);
    let second = runtime
      .stage_critical_mutation(event_for_chain_test())
      .await
      .unwrap();
    assert_eq!(
      second.event.integrity.as_ref().unwrap().sequence,
      first_sequence
    );
  }

  fn event_for_chain_test() -> AdminAuditEvent {
    AdminAuditHandle::new(
      "127.0.0.1:1234".parse().unwrap(),
      "https",
      &Method::POST,
      "/admin/v1/config/load",
      None,
    )
    .finish(StatusCode::OK)
  }
}
