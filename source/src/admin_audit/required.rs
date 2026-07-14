//! Fail-closed persistence for Admin audit intent and terminal events.

use anyhow::Context;

use crate::config::{AdminAuditAcknowledgement, AdminAuditMode};

use super::{AdminAuditEvent, AdminAuditHandle, AdminAuditRuntime, emit_tracing, spool};

impl AdminAuditRuntime {
  pub(crate) async fn begin_required_mutation(
    &self,
    audit: &AdminAuditHandle,
    durability_action: &str,
    resource: &str,
  ) -> anyhow::Result<bool> {
    if !self.requires_durability(Some(durability_action)) {
      return Ok(false);
    }
    let event = audit.begin_required_mutation(durability_action, resource);
    if self.acknowledgement == AdminAuditAcknowledgement::FsyncedSpool {
      let event = self.prepare_unsealed_event(event)?;
      let spool = self
        .spool
        .as_ref()
        .context("required Admin audit spool is unavailable")?;
      let (event, reservation) = match spool.append_with_terminal_reservation(event).await {
        Ok(value) => value,
        Err(error) => {
          self.record_spool_persistence_failure(&error);
          return Err(error);
        }
      };
      audit.install_spool_reservation(reservation)?;
      self
        .metrics
        .record_admin_audit_event(&event.outcome, "spool");
      emit_tracing(&event);
      self.export.emit_admin_event(&event, self.metrics.as_ref());
    } else {
      self.persist_required_event(event).await?;
    }
    Ok(true)
  }

  pub(super) fn requires_durability(&self, durability_action: Option<&str>) -> bool {
    match self.mode {
      AdminAuditMode::BestEffort => false,
      AdminAuditMode::DurableRequired => true,
      AdminAuditMode::DurableRequiredForActions => {
        durability_action.is_some_and(|action| self.required_actions.contains(action))
      }
    }
  }

  pub(super) async fn persist_required_event(
    &self,
    event: AdminAuditEvent,
  ) -> anyhow::Result<AdminAuditEvent> {
    let event = self.prepare_unsealed_event(event)?;
    let event = match self.acknowledgement {
      AdminAuditAcknowledgement::FsyncedSpool => {
        let spool = self
          .spool
          .as_ref()
          .context("required Admin audit spool is unavailable")?;
        match spool.append(event).await {
          Ok(event) => {
            self
              .metrics
              .record_admin_audit_event(&event.outcome, "spool");
            event
          }
          Err(error) => {
            self.record_spool_persistence_failure(&error);
            return Err(error);
          }
        }
      }
      AdminAuditAcknowledgement::Postgres => {
        let event = match self.persist_direct_postgres_event(event).await {
          Ok(event) => event,
          Err(error) => {
            let reason = if error.to_string().contains("exceeds") {
              "event_oversize"
            } else if error.to_string().contains("integrity") {
              "integrity_failure"
            } else {
              "postgres_unavailable"
            };
            self.metrics.record_admin_audit_required_rejection(reason);
            return Err(error).context("failed to persist required Admin audit event");
          }
        };
        self
          .metrics
          .record_admin_audit_event(&event.outcome, "postgres");
        event
      }
    };
    emit_tracing(&event);
    self.export.emit_admin_event(&event, self.metrics.as_ref());
    Ok(event)
  }

  pub(super) async fn persist_reserved_spool_event(
    &self,
    reservation: spool::AdminAuditSpoolReservation,
    event: AdminAuditEvent,
  ) -> anyhow::Result<AdminAuditEvent> {
    let event = self.prepare_unsealed_event(event)?;
    let event = match reservation.commit(event).await {
      Ok(event) => event,
      Err(error) => {
        self.record_spool_persistence_failure(&error);
        return Err(error);
      }
    };
    self
      .metrics
      .record_admin_audit_event(&event.outcome, "spool");
    emit_tracing(&event);
    self.export.emit_admin_event(&event, self.metrics.as_ref());
    Ok(event)
  }

  fn record_spool_persistence_failure(&self, error: &anyhow::Error) {
    let reason = if error.to_string().contains("full") {
      "spool_full"
    } else if error.to_string().contains("exceeds") {
      "event_oversize"
    } else if error.to_string().contains("integrity") {
      "integrity_failure"
    } else {
      "spool_io"
    };
    self.metrics.record_admin_audit_required_rejection(reason);
  }
}
