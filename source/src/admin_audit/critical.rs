//! Synchronous durable audit writes for replay-protected mutations.

use http::StatusCode;
use serde_json::json;
use sqlx::{Pool, Postgres};

use super::{AdminAuditEvent, AdminAuditHandle, AdminAuditRuntime, emit_tracing, store};

impl AdminAuditRuntime {
  pub(crate) fn critical_postgres_pool(&self) -> Option<Pool<Postgres>> {
    self.store.as_ref().map(|store| store.pool.clone())
  }

  /// Persists a critical mutation event before returning to the caller.
  ///
  /// Unlike the normal bounded audit queue, this path proves the row exists
  /// before a protected side effect can begin. Configuration validation limits
  /// it to enforcing PostgreSQL audit deployments.
  pub(crate) async fn persist_critical_mutation(
    &self,
    event: AdminAuditEvent,
  ) -> anyhow::Result<i64> {
    let durable = self
      .store
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("critical Admin mutation audit store is unavailable"))?;
    let id = store::insert_record_returning_id(&durable.pool, &durable.namespace, &event).await?;
    emit_tracing(&event);
    self.export.emit_admin_event(&event, self.metrics.as_ref());
    self
      .metrics
      .record_admin_audit_event(&event.outcome, "postgres_sync");
    Ok(id)
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
    let mut event = self.inner.lock().expect("admin audit lock poisoned");
    event.service = Some("admin-mutation".to_string());
    event.operation = action.to_string();
    event.action = Some(action.to_string());
    event.resource = Some(resource.to_string());
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

  pub(crate) fn critical_mutation_event(
    &self,
    mutation_request_id: &str,
    status: StatusCode,
    outcome: &str,
    error: Option<&str>,
  ) -> AdminAuditEvent {
    let mut event = self
      .inner
      .lock()
      .expect("admin audit lock poisoned")
      .clone();
    event.request_id = mutation_request_id.to_string();
    event.status = status.as_u16();
    event.outcome = outcome.to_string();
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
  }
}
