//! Admin audit buffering and delivery.
//! Authorization and mutation records stay structured so sensitive decisions remain reviewable.

use std::net::SocketAddr;
#[cfg(test)]
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use http::{Method, StatusCode};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{Pool, Postgres};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::Config;

mod request;
mod store;

#[derive(Clone)]
pub struct AdminAuditRuntime {
  inner: Option<AdminAuditSink>,
}

#[derive(Clone)]
struct AdminAuditSink {
  namespace: String,
  pool: Pool<Postgres>,
  sender: mpsc::Sender<AdminAuditEvent>,
}

#[derive(Debug, Clone)]
pub struct AdminAuditEvent {
  pub request_id: String,
  pub actor: Option<String>,
  pub principal: Option<String>,
  pub subject: Option<String>,
  pub groups: Vec<String>,
  pub peer: String,
  pub source_ip: Option<String>,
  pub scheme: &'static str,
  pub method: String,
  pub path: String,
  pub service: Option<String>,
  pub operation: String,
  pub action: Option<String>,
  pub resource: Option<String>,
  pub target_kind: Option<String>,
  pub target_id: Option<String>,
  pub status: u16,
  pub outcome: String,
  pub error: Option<String>,
  pub request_summary: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminAuditRecord {
  pub id: i64,
  pub namespace: String,
  pub request_id: String,
  pub actor: Option<String>,
  pub principal: Option<String>,
  pub subject: Option<String>,
  pub groups: Vec<String>,
  pub peer: String,
  pub source_ip: Option<String>,
  pub scheme: String,
  pub method: String,
  pub path: String,
  pub service: Option<String>,
  pub operation: String,
  pub action: Option<String>,
  pub resource: Option<String>,
  pub target_kind: Option<String>,
  pub target_id: Option<String>,
  pub status: i32,
  pub outcome: String,
  pub error: Option<String>,
  pub request_summary: Value,
  pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct AdminAuditQuery {
  pub limit: i64,
  pub outcome: Option<String>,
  pub actor: Option<String>,
  pub principal: Option<String>,
  pub service: Option<String>,
  pub operation: Option<String>,
  pub request_id: Option<String>,
  pub path_prefix: Option<String>,
  pub before_id: Option<i64>,
}

#[derive(Clone)]
pub struct AdminAuditHandle {
  inner: Arc<Mutex<AdminAuditEvent>>,
}

pub(crate) struct AdminAuditReservation {
  permit: Option<mpsc::OwnedPermit<AdminAuditEvent>>,
}

impl AdminAuditRuntime {
  pub fn disabled() -> Self {
    Self { inner: None }
  }

  #[cfg(test)]
  pub(crate) fn test_with_sender(sender: mpsc::Sender<AdminAuditEvent>) -> Self {
    let options =
      sqlx::postgres::PgConnectOptions::from_str("postgres://oxibelt@localhost/oxibelt")
        .expect("lazy PostgreSQL options should parse");
    let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy_with(options);
    Self {
      inner: Some(AdminAuditSink {
        namespace: "oxibelt".to_string(),
        pool,
        sender,
      }),
    }
  }

  pub async fn new(config: &Config) -> anyhow::Result<Self> {
    if !config.admin.enabled || !config.admin.audit.enabled {
      return Ok(Self::disabled());
    }
    let backend_name = config
      .admin
      .audit
      .backend
      .as_deref()
      .context("admin.audit.enabled requires admin.audit.backend")?;
    let backend = config
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
      .ok_or_else(|| anyhow::anyhow!("admin.audit.backend {backend_name} was not found"))?;
    let pool = store::connect_pool(backend).await.with_context(|| {
      format!("failed to connect admin audit PostgreSQL backend {backend_name}")
    })?;
    store::init_postgres(&pool)
      .await
      .context("failed to initialize admin audit PostgreSQL tables")?;
    let (sender, receiver) = mpsc::channel(config.admin.audit.queue_capacity);
    let namespace = config.shared_state.namespace.clone();
    tokio::spawn(store::run_database_writer(
      pool.clone(),
      namespace.clone(),
      receiver,
    ));
    info!(backend = backend_name, "admin audit sink initialized");
    Ok(Self {
      inner: Some(AdminAuditSink {
        namespace,
        pool,
        sender,
      }),
    })
  }

  pub(crate) fn reserve(&self) -> anyhow::Result<AdminAuditReservation> {
    let Some(inner) = &self.inner else {
      return Ok(AdminAuditReservation { permit: None });
    };
    match inner.sender.clone().try_reserve_owned() {
      Ok(permit) => Ok(AdminAuditReservation {
        permit: Some(permit),
      }),
      Err(mpsc::error::TrySendError::Full(_)) => {
        bail!("admin audit queue is full");
      }
      Err(mpsc::error::TrySendError::Closed(_)) => {
        bail!("admin audit writer is closed");
      }
    }
  }

  pub(crate) fn emit_unstored(&self, event: AdminAuditEvent, error: &anyhow::Error) {
    emit_tracing(&event);
    warn!(error = %error, "admin audit unavailable; rejected admin request without durable audit row");
  }

  pub async fn query(&self, query: AdminAuditQuery) -> anyhow::Result<Vec<AdminAuditRecord>> {
    let Some(inner) = &self.inner else {
      bail!("admin audit store is not configured");
    };
    store::select_records(&inner.pool, &inner.namespace, query).await
  }
}

impl AdminAuditReservation {
  pub(crate) fn commit(self, event: AdminAuditEvent) {
    emit_tracing(&event);
    if let Some(permit) = self.permit {
      drop(permit.send(event));
    }
  }
}

impl Default for AdminAuditRuntime {
  fn default() -> Self {
    Self::disabled()
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
    let event = AdminAuditEvent {
      request_id: request::random_request_id(),
      actor: None,
      principal: None,
      subject: None,
      groups: Vec::new(),
      peer: peer_addr.to_string(),
      source_ip: Some(peer_addr.ip().to_string()),
      scheme,
      method: method.as_str().to_string(),
      path: path.to_string(),
      service: descriptor.service,
      operation: descriptor.operation,
      action: None,
      resource: None,
      target_kind: descriptor.target_kind,
      target_id: descriptor.target_id,
      status: 0,
      outcome: "unknown".to_string(),
      error: None,
      request_summary: request::request_summary_from_query(query),
    };
    Self {
      inner: Arc::new(Mutex::new(event)),
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

  pub(crate) fn request_id(&self) -> String {
    self
      .inner
      .lock()
      .expect("admin audit lock poisoned")
      .request_id
      .clone()
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

  pub fn finish(&self, status: StatusCode) -> AdminAuditEvent {
    self.finish_with_error(status, request::status_reason(status))
  }

  pub fn finish_with_error(&self, status: StatusCode, error: &str) -> AdminAuditEvent {
    let mut event = self.inner.lock().expect("admin audit lock poisoned");
    event.status = status.as_u16();
    if status == StatusCode::SWITCHING_PROTOCOLS || status.is_success() || status.is_redirection() {
      event.outcome = "applied".to_string();
      event.error = None;
    } else {
      event.outcome = "rejected".to_string();
      if event.error.is_none() {
        event.error = Some(error.to_string());
      }
    }
    event.clone()
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

fn emit_tracing(event: &AdminAuditEvent) {
  info!(
    event = "oxibelt.admin.audit",
    request_id = %event.request_id,
    actor = event.actor.as_deref(),
    principal = event.principal.as_deref(),
    groups = ?event.groups,
    peer = %event.peer,
    source_ip = event.source_ip.as_deref(),
    scheme = event.scheme,
    method = %event.method,
    path = %event.path,
    service = event.service.as_deref(),
    operation = %event.operation,
    action = event.action.as_deref(),
    resource = event.resource.as_deref(),
    target_kind = event.target_kind.as_deref(),
    target_id = event.target_id.as_deref(),
    status = event.status,
    outcome = %event.outcome,
    error = event.error.as_deref(),
    "admin operation audit"
  );
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_event() -> AdminAuditEvent {
    AdminAuditHandle::new(
      "127.0.0.1:12345".parse().expect("peer address"),
      "http",
      &Method::GET,
      "/admin/v1/config/status",
      None,
    )
    .finish(StatusCode::OK)
  }

  #[test]
  fn audit_query_parses_filters_and_limit() {
    let query = AdminAuditQuery::from_query(Some(
      "limit=25&outcome=rejected&actor=ops&principal=admin&service=config&operation=post.config.load&request_id=req-1&path_prefix=%2Fadmin%2Fv1&before_id=99",
    ))
    .expect("query should parse");

    assert_eq!(query.limit, 25);
    assert_eq!(query.outcome.as_deref(), Some("rejected"));
    assert_eq!(query.actor.as_deref(), Some("ops"));
    assert_eq!(query.principal.as_deref(), Some("admin"));
    assert_eq!(query.service.as_deref(), Some("config"));
    assert_eq!(query.operation.as_deref(), Some("post.config.load"));
    assert_eq!(query.request_id.as_deref(), Some("req-1"));
    assert_eq!(query.path_prefix.as_deref(), Some("/admin/v1"));
    assert_eq!(query.before_id, Some(99));
  }

  #[tokio::test]
  async fn audit_reservation_fails_when_queue_capacity_is_full() {
    let (sender, _receiver) = mpsc::channel(1);
    let held_permit = sender
      .clone()
      .try_reserve_owned()
      .expect("held permit should consume the only slot");
    let runtime = AdminAuditRuntime::test_with_sender(sender);

    let error = match runtime.reserve() {
      Ok(_) => panic!("reservation should fail while the only slot is held"),
      Err(error) => error,
    };

    assert!(error.to_string().contains("admin audit queue is full"));
    drop(held_permit);
  }

  #[tokio::test]
  async fn audit_reservation_commits_event_through_reserved_slot() {
    let (sender, mut receiver) = mpsc::channel(1);
    let runtime = AdminAuditRuntime::test_with_sender(sender);
    let reservation = runtime.reserve().expect("reservation should succeed");

    reservation.commit(sample_event());

    let event = receiver
      .recv()
      .await
      .expect("committed event should be queued");
    assert_eq!(event.status, StatusCode::OK.as_u16());
    assert_eq!(event.outcome, "applied");
  }

  #[test]
  fn audit_treats_only_switching_protocols_as_applied_informational() {
    let switching = AdminAuditHandle::new(
      "127.0.0.1:12345".parse().expect("peer address"),
      "http",
      &Method::GET,
      "/admin/v1/operations/op_550e8400-e29b-41d4-a716-446655440000/events/ws",
      None,
    )
    .finish(StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(switching.outcome, "applied");
    assert!(switching.error.is_none());

    let other_informational = AdminAuditHandle::new(
      "127.0.0.1:12345".parse().expect("peer address"),
      "http",
      &Method::GET,
      "/admin/v1/config/status",
      None,
    )
    .finish(StatusCode::CONTINUE);
    assert_eq!(other_informational.outcome, "rejected");
    assert!(other_informational.error.is_some());
  }
}
