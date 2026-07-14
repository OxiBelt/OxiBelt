//! Admin audit request lifecycle and query parsing.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http::{Method, StatusCode};
use serde_json::{Value, json};

use super::event::{
  ADMIN_AUDIT_SCHEMA_VERSION, AdminAuditEvent, AdminAuditQuery, AuditPhase, AuditResult,
};
use super::{AdminAuditHandle, AdminAuditReservation, request};

impl AdminAuditReservation {
  pub(crate) async fn commit(
    self,
    audit: &AdminAuditHandle,
    event: AdminAuditEvent,
  ) -> anyhow::Result<()> {
    if event.lifecycle_managed {
      return Ok(());
    }
    let required = event.durable_required
      || self
        .runtime
        .requires_durability(event.durability_action.as_deref());
    if required {
      if let Some(reservation) = audit.take_spool_reservation() {
        self
          .runtime
          .persist_reserved_spool_event(reservation, event)
          .await?;
      } else {
        self.runtime.persist_required_event(event).await?;
      }
    } else {
      self
        .runtime
        .persist_best_effort_event(event, self.permit)
        .await;
    }
    Ok(())
  }
}

impl AdminAuditHandle {
  pub fn new(
    peer_addr: SocketAddr,
    scheme: &'static str,
    method: &Method,
    path: &str,
    query: Option<&str>,
  ) -> Self {
    let descriptor = request::describe_request(method, path);
    let event_id = super::event::generate_event_id().unwrap_or_default();
    let occurrence = super::event::occurrence_timestamp().ok();
    let event = AdminAuditEvent {
      schema_version: ADMIN_AUDIT_SCHEMA_VERSION.to_string(),
      event_id,
      timestamp: occurrence
        .as_ref()
        .map(|timestamp| timestamp.rfc3339.clone())
        .unwrap_or_default(),
      timestamp_unix_ms: occurrence.map_or(0, |timestamp| timestamp.unix_ms),
      instance_id: String::new(),
      phase: AuditPhase::Terminal,
      request_id: request::random_request_id(),
      mutation_request_id: None,
      actor: None,
      principal: None,
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
      authentication_reason: None,
      peer: peer_addr.to_string(),
      source_ip: Some(peer_addr.ip().to_string()),
      source_address: Some(peer_addr.ip().to_string()),
      scheme: scheme.to_string(),
      method: method.as_str().to_string(),
      path: path.to_string(),
      service: descriptor.service,
      operation: descriptor.operation,
      durability_action: None,
      action: None,
      resource: None,
      target_kind: descriptor.target_kind,
      target_id: descriptor.target_id,
      previous_revision: None,
      desired_revision: None,
      content_digest: None,
      status: 0,
      result: AuditResult::Rejected,
      outcome: "unknown".to_string(),
      error_code: None,
      error: None,
      request_summary: request::request_summary_from_query(query),
      integrity: None,
      durable_required: false,
      lifecycle_managed: false,
    };
    Self {
      inner: Arc::new(Mutex::new(event)),
      spool_reservation: Arc::new(Mutex::new(None)),
    }
  }

  pub fn from_request<B>(request: &http::Request<B>) -> Option<Self> {
    request.extensions().get::<Self>().cloned()
  }

  pub fn set_actor(&self, name: &str, principal: &str, subject: &str, groups: &[String]) {
    let mut event = self.inner.lock().expect("admin audit lock poisoned");
    event.actor = Some(name.to_string());
    event.principal = Some(principal.to_string());
    event.subject = Some(subject.to_string());
    event.groups = groups.to_vec();
  }

  #[allow(clippy::too_many_arguments)]
  pub fn set_authentication(
    &self,
    reason: &str,
    workload_identity_kind: Option<&str>,
    workload_identity: Option<&str>,
    workload_principal: Option<&str>,
    certificate_fingerprint_sha256: Option<&str>,
    credential_kind: Option<&str>,
    credential_identity: Option<&str>,
    credential_principal: Option<&str>,
  ) {
    let mut event = self.inner.lock().expect("admin audit lock poisoned");
    event.authentication_reason = Some(reason.to_string());
    event.workload_identity_kind = workload_identity_kind.map(str::to_string);
    event.workload_identity = workload_identity.map(str::to_string);
    event.workload_principal = workload_principal.map(str::to_string);
    event.certificate_fingerprint_sha256 = certificate_fingerprint_sha256.map(str::to_string);
    event.credential_kind = credential_kind.map(str::to_string);
    event.credential_identity = credential_identity.map(str::to_string);
    event.credential_principal = credential_principal.map(str::to_string);
    event.credential_id = certificate_fingerprint_sha256
      .map(|fingerprint| format!("cert-sha256:{fingerprint}"))
      .or_else(|| {
        credential_identity
          .map(|identity| format!("{}:{identity}", credential_kind.unwrap_or("credential")))
      });
  }

  pub(crate) fn request_id(&self) -> String {
    self
      .inner
      .lock()
      .expect("admin audit lock poisoned")
      .request_id
      .clone()
  }

  pub(super) fn install_spool_reservation(
    &self,
    reservation: super::spool::AdminAuditSpoolReservation,
  ) -> anyhow::Result<()> {
    let mut current = self
      .spool_reservation
      .lock()
      .expect("admin audit spool reservation lock poisoned");
    if current.is_some() {
      anyhow::bail!("Admin audit request already owns a terminal spool reservation");
    }
    *current = Some(reservation);
    Ok(())
  }

  fn take_spool_reservation(&self) -> Option<super::spool::AdminAuditSpoolReservation> {
    self
      .spool_reservation
      .lock()
      .expect("admin audit spool reservation lock poisoned")
      .take()
  }

  pub(crate) fn error_details(&self, status: StatusCode) -> Option<Value> {
    if status != StatusCode::FORBIDDEN {
      return None;
    }
    let event = self.inner.lock().expect("admin audit lock poisoned");
    match (&event.action, &event.resource) {
      (Some(action), Some(resource)) => Some(json!({
        "action": action,
        "resource": resource,
      })),
      _ => None,
    }
  }

  pub fn record_authorization(&self, action: &str, resource: &str, allowed: bool) {
    let mut event = self.inner.lock().expect("admin audit lock poisoned");
    if event.action.is_none() || !allowed {
      event.action = Some(action.to_string());
      event.resource = Some(resource.to_string());
    }
    if event.service.is_none()
      && let Some((service, _)) = action.split_once(':')
    {
      event.service = Some(service.to_string());
    }
    request::push_authorization_check(&mut event.request_summary, action, resource, allowed);
  }

  pub fn record_json_body(&self, bytes: &[u8]) {
    let mut event = self.inner.lock().expect("admin audit lock poisoned");
    request::merge_json_body_summary(
      &mut event.request_summary,
      request::json_body_summary(bytes),
    );
  }

  pub(super) fn begin_required_mutation(
    &self,
    durability_action: &str,
    resource: &str,
  ) -> AdminAuditEvent {
    let mut event = self.inner.lock().expect("admin audit lock poisoned");
    event.durability_action = Some(durability_action.to_string());
    event.durable_required = true;
    let mut intent = event.clone();
    if intent.action.is_none() {
      intent.action = Some(durability_action.to_string());
      intent.resource = Some(resource.to_string());
    }
    intent.event_id = super::event::generate_event_id().unwrap_or_default();
    if let Ok(occurrence) = super::event::occurrence_timestamp() {
      intent.timestamp = occurrence.rfc3339;
      intent.timestamp_unix_ms = occurrence.unix_ms;
    }
    intent.phase = AuditPhase::Intent;
    intent.status = StatusCode::ACCEPTED.as_u16();
    intent.result = AuditResult::Accepted;
    intent.outcome = "accepted".to_string();
    intent.error_code = None;
    intent.error = None;
    intent
  }

  pub fn finish(&self, status: StatusCode) -> AdminAuditEvent {
    self.finish_with_error(status, request::status_reason(status))
  }

  pub fn finish_with_error(&self, status: StatusCode, error: &str) -> AdminAuditEvent {
    let mut event = self.inner.lock().expect("admin audit lock poisoned");
    if let Ok(event_id) = super::event::generate_event_id() {
      event.event_id = event_id;
    }
    if let Ok(occurrence) = super::event::occurrence_timestamp() {
      event.timestamp = occurrence.rfc3339;
      event.timestamp_unix_ms = occurrence.unix_ms;
    }
    event.status = status.as_u16();
    if status == StatusCode::SWITCHING_PROTOCOLS || status.is_success() || status.is_redirection() {
      event.result = AuditResult::Applied;
      event.outcome = "applied".to_string();
      event.error_code = None;
      event.error = None;
    } else {
      event.result = if status.is_server_error() && event.durable_required {
        AuditResult::Indeterminate
      } else {
        AuditResult::Rejected
      };
      event.outcome = match event.result {
        AuditResult::Indeterminate => "indeterminate",
        _ => "rejected",
      }
      .to_string();
      event.error_code = Some(error_code_for_status(status).to_string());
      if event.error.is_none() {
        event.error = Some(error.to_string());
      }
    }
    event.clone()
  }
}

fn error_code_for_status(status: StatusCode) -> &'static str {
  match status {
    StatusCode::BAD_REQUEST => "invalid_request",
    StatusCode::UNAUTHORIZED => "unauthorized",
    StatusCode::FORBIDDEN => "permission_denied",
    StatusCode::NOT_FOUND => "not_found",
    StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
    StatusCode::CONFLICT => "conflict",
    StatusCode::PRECONDITION_FAILED => "etag_mismatch",
    StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
    StatusCode::PRECONDITION_REQUIRED => "precondition_required",
    StatusCode::SERVICE_UNAVAILABLE => "control_plane_unavailable",
    _ if status.is_server_error() => "internal_error",
    _ => "request_rejected",
  }
}

impl AdminAuditQuery {
  pub fn from_query(query: Option<&str>) -> anyhow::Result<Self> {
    let mut parsed = Self {
      limit: 100,
      outcome: None,
      actor: None,
      principal: None,
      service: None,
      operation: None,
      request_id: None,
      path_prefix: None,
      before_id: None,
    };
    if let Some(query) = query {
      for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
          "limit" => {
            parsed.limit = value
              .parse::<i64>()
              .map_err(|_| anyhow::anyhow!("limit must be an integer"))?;
          }
          "outcome" => parsed.outcome = Some(value.into_owned()),
          "actor" => parsed.actor = Some(value.into_owned()),
          "principal" => parsed.principal = Some(value.into_owned()),
          "service" => parsed.service = Some(value.into_owned()),
          "operation" => parsed.operation = Some(value.into_owned()),
          "request_id" => parsed.request_id = Some(value.into_owned()),
          "path_prefix" => parsed.path_prefix = Some(value.into_owned()),
          "before_id" => {
            parsed.before_id = Some(
              value
                .parse::<i64>()
                .map_err(|_| anyhow::anyhow!("before_id must be an integer"))?,
            );
          }
          _ => {}
        }
      }
    }
    Ok(parsed)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn durability_selection_does_not_replace_semantic_authorization() {
    let audit = AdminAuditHandle::new(
      "127.0.0.1:12345".parse().unwrap(),
      "https",
      &Method::POST,
      "/admin/v1/config/load",
      None,
    );
    let intent = audit.begin_required_mutation("config.load", "config");
    assert_eq!(intent.durability_action.as_deref(), Some("config.load"));
    assert_eq!(intent.action.as_deref(), Some("config.load"));

    audit.record_authorization("config:Load", "oxibelt:default:config:*", true);
    let terminal = audit.finish(StatusCode::OK);
    assert_ne!(terminal.event_id, intent.event_id);
    assert!(terminal.timestamp_unix_ms >= intent.timestamp_unix_ms);
    assert_eq!(terminal.durability_action.as_deref(), Some("config.load"));
    assert_eq!(terminal.action.as_deref(), Some("config:Load"));
    assert_eq!(
      terminal.resource.as_deref(),
      Some("oxibelt:default:config:*")
    );
  }
}
