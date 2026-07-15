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
