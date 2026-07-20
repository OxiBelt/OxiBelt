//! Admin audit buffering and delivery.
//! Authorization and mutation records stay structured so sensitive decisions remain reviewable.

use std::collections::HashSet;
#[cfg(test)]
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
#[cfg(test)]
use http::{Method, StatusCode};
use sqlx::{Pool, Postgres};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::access_log::AccessLogSinks;
use crate::config::{AdminAuditAcknowledgement, AdminAuditExportSink, AdminAuditMode, Config};
use crate::metrics::Metrics;

pub mod anchor;
mod critical;
mod event;
mod handle;
mod integrity;
mod request;
mod required;
mod spool;
mod store;

use event::ADMIN_AUDIT_SCHEMA_VERSION;
pub use event::{AdminAuditEvent, AdminAuditQuery, AdminAuditRecord};

#[derive(Clone)]
pub struct AdminAuditRuntime {
  store: Option<PostgresAdminAuditStore>,
  spool: Option<spool::AdminAuditSpool>,
  export: AdminAuditExportRuntime,
  mode: AdminAuditMode,
  acknowledgement: AdminAuditAcknowledgement,
  required_actions: Arc<HashSet<String>>,
  instance_id: Arc<str>,
  direct_integrity: Arc<tokio::sync::Mutex<integrity::IntegrityChain>>,
  anchor: anchor::AuditAnchorRuntime,
  max_event_bytes: usize,
  metrics: Arc<Metrics>,
}

#[derive(Clone)]
struct PostgresAdminAuditStore {
  namespace: String,
  pool: Pool<Postgres>,
  sender: mpsc::Sender<AdminAuditEvent>,
}

#[derive(Clone, Default)]
struct AdminAuditExportRuntime {
  access_logs: Option<AccessLogSinks>,
}

#[derive(Clone)]
pub struct AdminAuditHandle {
  inner: Arc<Mutex<AdminAuditEvent>>,
  spool_reservation: Arc<Mutex<Option<spool::AdminAuditSpoolReservation>>>,
}

pub(crate) struct AdminAuditReservation {
  permit: Option<mpsc::OwnedPermit<AdminAuditEvent>>,
  runtime: AdminAuditRuntime,
}

impl AdminAuditRuntime {
  pub fn disabled() -> Self {
    Self {
      store: None,
      spool: None,
      export: AdminAuditExportRuntime::default(),
      mode: AdminAuditMode::BestEffort,
      acknowledgement: AdminAuditAcknowledgement::Postgres,
      required_actions: Arc::new(HashSet::new()),
      instance_id: Arc::from("disabled"),
      direct_integrity: Arc::new(tokio::sync::Mutex::new(fallback_integrity_chain())),
      anchor: anchor::AuditAnchorRuntime::disabled(),
      max_event_bytes: 64 * 1024,
      metrics: Arc::new(Metrics::default()),
    }
  }

  #[cfg(test)]
  pub(crate) fn test_with_sender(sender: mpsc::Sender<AdminAuditEvent>) -> Self {
    Self::test_with_sender_and_mode(sender, AdminAuditMode::DurableRequired)
  }

  #[cfg(test)]
  pub(crate) fn test_with_sender_and_mode(
    sender: mpsc::Sender<AdminAuditEvent>,
    mode: AdminAuditMode,
  ) -> Self {
    let options =
      sqlx::postgres::PgConnectOptions::from_str("postgres://oxibelt@localhost/oxibelt")
        .expect("lazy PostgreSQL options should parse");
    let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy_with(options);
    Self {
      store: Some(PostgresAdminAuditStore {
        namespace: "oxibelt".to_string(),
        pool,
        sender,
      }),
      spool: None,
      export: AdminAuditExportRuntime::default(),
      mode,
      acknowledgement: AdminAuditAcknowledgement::Postgres,
      required_actions: Arc::new(HashSet::new()),
      instance_id: Arc::from("test-instance"),
      direct_integrity: Arc::new(tokio::sync::Mutex::new(fallback_integrity_chain())),
      anchor: anchor::AuditAnchorRuntime::disabled(),
      max_event_bytes: 64 * 1024,
      metrics: Arc::new(Metrics::default()),
    }
  }

  #[cfg(test)]
  pub(crate) fn test_export_only() -> Self {
    Self {
      store: None,
      spool: None,
      export: AdminAuditExportRuntime::default(),
      mode: AdminAuditMode::BestEffort,
      acknowledgement: AdminAuditAcknowledgement::Postgres,
      required_actions: Arc::new(HashSet::new()),
      instance_id: Arc::from("test-instance"),
      direct_integrity: Arc::new(tokio::sync::Mutex::new(fallback_integrity_chain())),
      anchor: anchor::AuditAnchorRuntime::disabled(),
      max_event_bytes: 64 * 1024,
      metrics: Arc::new(Metrics::default()),
    }
  }

  pub(crate) async fn new(
    config: &Config,
    access_logs: AccessLogSinks,
    metrics: Arc<Metrics>,
    runtime_health: Arc<crate::runtime_health::RuntimeHealth>,
    runtime_generation: u64,
  ) -> anyhow::Result<Self> {
    if !config.admin.enabled {
      return Ok(Self {
        store: None,
        spool: None,
        export: AdminAuditExportRuntime::default(),
        mode: AdminAuditMode::BestEffort,
        acknowledgement: AdminAuditAcknowledgement::Postgres,
        required_actions: Arc::new(HashSet::new()),
        instance_id: Arc::from("admin-disabled"),
        direct_integrity: Arc::new(tokio::sync::Mutex::new(integrity::IntegrityChain::new(
          None,
        )?)),
        anchor: anchor::AuditAnchorRuntime::disabled(),
        max_event_bytes: config.admin.audit.spool.max_event_bytes,
        metrics,
      });
    }
    if !config.admin.audit.enabled {
      return Ok(Self {
        store: None,
        spool: None,
        export: AdminAuditExportRuntime {
          access_logs: Some(access_logs),
        },
        mode: AdminAuditMode::BestEffort,
        acknowledgement: AdminAuditAcknowledgement::Postgres,
        required_actions: Arc::new(HashSet::new()),
        instance_id: Arc::from("audit-disabled"),
        direct_integrity: Arc::new(tokio::sync::Mutex::new(integrity::IntegrityChain::new(
          None,
        )?)),
        anchor: anchor::AuditAnchorRuntime::disabled(),
        max_event_bytes: config.admin.audit.spool.max_event_bytes,
        metrics,
      });
    }

    let export = AdminAuditExportRuntime {
      access_logs: if config.admin.audit.export.enabled
        && config
          .admin
          .audit
          .export
          .sinks
          .contains(&AdminAuditExportSink::AccessLog)
      {
        Some(access_logs)
      } else {
        None
      },
    };
    let mode = config.admin.audit.mode;
    let hmac_key = match (
      config.admin.audit.integrity.hmac_key_env.as_deref(),
      config.admin.audit.integrity.hmac_key_id.as_deref(),
    ) {
      (Some(environment), Some(key_id)) => Some(integrity::AuditHmacKey::from_environment(
        environment,
        key_id,
      )?),
      _ => None,
    };
    let instance_id = std::env::var(&config.shared_state.instance_id_env)
      .ok()
      .filter(|value| !value.trim().is_empty())
      .unwrap_or_else(|| {
        format!(
          "{}-{}",
          std::process::id(),
          event::generate_chain_id().unwrap_or_else(|_| "identity-unavailable".to_string())
        )
      });
    let spool = if config.admin.audit.spool.enabled {
      Some(spool::AdminAuditSpool::new(
        &config.admin.audit.spool,
        hmac_key.clone(),
        metrics.clone(),
      )?)
    } else {
      None
    };
    let mut store_receiver = None;
    let store = if config.admin.audit.store.enabled {
      let backend_name = config
        .admin
        .audit
        .store
        .backend
        .as_deref()
        .context("admin.audit.store.enabled requires admin.audit.store.backend")?;
      let backend = config
        .shared_state
        .backends
        .iter()
        .find(|backend| backend.name == backend_name)
        .ok_or_else(|| anyhow::anyhow!("admin.audit.store.backend {backend_name} was not found"))?;
      let pool = store::connect_pool(backend).await.with_context(|| {
        format!("failed to connect admin audit PostgreSQL backend {backend_name}")
      })?;
      store::init_postgres(&pool)
        .await
        .context("failed to initialize admin audit PostgreSQL tables")?;
      let (sender, receiver) = mpsc::channel(config.admin.audit.queue_capacity);
      let namespace = config.shared_state.namespace.clone();
      store_receiver = Some(receiver);
      info!(
        backend = backend_name,
        mode = ?mode,
        export_access_log = export.access_logs.is_some(),
        "admin audit PostgreSQL store initialized"
      );
      Some(PostgresAdminAuditStore {
        namespace,
        pool,
        sender,
      })
    } else {
      info!(
        mode = ?mode,
        export_access_log = export.access_logs.is_some(),
        "admin audit initialized without durable store"
      );
      None
    };
    let direct_chain = if let Some(store) = &store {
      let restored = integrity::restore_postgres_chain(
        &store.pool,
        &store.namespace,
        &instance_id,
        hmac_key.clone(),
      )
      .await;
      if restored.is_err() && config.admin.audit.anchor.enabled {
        metrics.record_admin_audit_anchor_verification_failure("local_chain");
      }
      restored.context("failed to restore the current Admin audit integrity chain")?
    } else {
      integrity::IntegrityChain::new(hmac_key.clone())?
    };
    let direct_integrity = Arc::new(tokio::sync::Mutex::new(direct_chain));
    let anchor = if config.admin.audit.anchor.enabled {
      let local_pool = store
        .as_ref()
        .context("Admin audit anchoring requires a PostgreSQL audit store")?
        .pool
        .clone();
      anchor::AuditAnchorRuntime::new(
        config,
        local_pool,
        metrics.clone(),
        runtime_health,
        runtime_generation,
      )
      .await?
    } else {
      anchor::AuditAnchorRuntime::disabled()
    };
    let runtime = Self {
      store,
      spool,
      export,
      mode,
      acknowledgement: config.admin.audit.acknowledgement,
      required_actions: Arc::new(
        config
          .admin
          .audit
          .required_actions
          .iter()
          .cloned()
          .collect(),
      ),
      instance_id: Arc::from(instance_id),
      direct_integrity,
      anchor,
      max_event_bytes: config.admin.audit.spool.max_event_bytes,
      metrics,
    };
    if let (Some(spool), Some(store)) = (runtime.spool.clone(), runtime.store.clone()) {
      let metrics = runtime.metrics.clone();
      tokio::spawn(run_spool_drainer(spool, store, metrics));
    }
    if let (Some(receiver), Some(store)) = (store_receiver, runtime.store.clone()) {
      tokio::spawn(store::run_database_writer(
        store.pool,
        store.namespace,
        receiver,
        runtime.anchor.clone(),
        runtime.metrics.clone(),
      ));
    }
    Ok(runtime)
  }

  pub(crate) fn anchor_status(&self) -> anchor::AuditAnchorStatus {
    self.anchor.status()
  }

  pub(crate) fn anchoring_enabled(&self) -> bool {
    self.anchor.enabled()
  }

  pub(crate) fn reserve(&self) -> anyhow::Result<AdminAuditReservation> {
    let permit = if self.mode == AdminAuditMode::BestEffort
      && self.spool.is_none()
      && let Some(store) = &self.store
    {
      match store.sender.clone().try_reserve_owned() {
        Ok(permit) => Some(permit),
        Err(mpsc::error::TrySendError::Full(_)) => {
          self
            .metrics
            .record_admin_audit_store_enqueue_failure("full");
          self.metrics.record_admin_audit_dropped("store_queue_full");
          warn!(
            mode = ?self.mode,
              "admin audit store queue is full; continuing in best-effort mode"
          );
          None
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
          self
            .metrics
            .record_admin_audit_store_enqueue_failure("closed");
          self
            .metrics
            .record_admin_audit_dropped("store_writer_closed");
          warn!(
            mode = ?self.mode,
              "admin audit store writer is closed; continuing in best-effort mode"
          );
          None
        }
      }
    } else {
      None
    };
    Ok(AdminAuditReservation {
      permit,
      runtime: self.clone(),
    })
  }

  async fn persist_best_effort_event(
    &self,
    event: AdminAuditEvent,
    permit: Option<mpsc::OwnedPermit<AdminAuditEvent>>,
  ) {
    let event = match self.prepare_unsealed_event(event) {
      Ok(event) => event,
      Err(error) => {
        self
          .metrics
          .record_admin_audit_dropped("store_writer_closed");
        warn!(error = %error, "failed to prepare best-effort Admin audit event");
        return;
      }
    };
    if self.mode == AdminAuditMode::BestEffort
      && let Some(spool) = &self.spool
    {
      match spool.append(event.clone()).await {
        Ok(event) => {
          emit_tracing(&event);
          self.export.emit_admin_event(&event, self.metrics.as_ref());
          self
            .metrics
            .record_admin_audit_event(&event.outcome, "spool");
        }
        Err(error) => {
          warn!(error = %error, "best-effort Admin audit spool append failed");
          self
            .metrics
            .record_admin_audit_event(&event.outcome, "none");
          emit_tracing(&event);
          self.export.emit_admin_event(&event, self.metrics.as_ref());
        }
      }
      return;
    }
    if let Some(permit) = permit {
      match self.enqueue_direct_event(event, permit).await {
        Ok(event) => {
          emit_tracing(&event);
          self.export.emit_admin_event(&event, self.metrics.as_ref());
        }
        Err(error) => warn!(error = %error, "failed to seal best-effort Admin audit event"),
      }
    } else {
      emit_tracing(&event);
      self.export.emit_admin_event(&event, self.metrics.as_ref());
      self
        .metrics
        .record_admin_audit_event(&event.outcome, "none");
    }
  }

  fn prepare_unsealed_event(&self, mut event: AdminAuditEvent) -> anyhow::Result<AdminAuditEvent> {
    event.instance_id = self.instance_id.to_string();
    event.request_summary = request::sanitize_summary_for_storage(&event.request_summary);
    ensure_event_metadata(&event)?;
    Ok(event)
  }

  pub(crate) fn clone_with_export(&self, access_logs: Option<AccessLogSinks>) -> Self {
    let mut runtime = self.clone();
    runtime.export = AdminAuditExportRuntime { access_logs };
    runtime
  }

  pub(crate) fn emit_unstored(&self, event: AdminAuditEvent, error: &anyhow::Error) {
    emit_tracing(&event);
    self.export.emit_admin_event(&event, self.metrics.as_ref());
    self
      .metrics
      .record_admin_audit_event(&event.outcome, "none");
    if self.store.is_some() {
      warn!(error = %error, "admin audit unavailable; rejected admin request without durable audit row");
    } else {
      warn!(error = %error, "admin audit unavailable; rejected admin request");
    }
  }

  pub async fn query(&self, query: AdminAuditQuery) -> anyhow::Result<Vec<AdminAuditRecord>> {
    let Some(store) = &self.store else {
      bail!(
        "admin audit store is not configured; enable [admin.audit.store] with a PostgreSQL backend to query audit history"
      );
    };
    store::select_records(&store.pool, &store.namespace, query).await
  }
}

impl AdminAuditExportRuntime {
  fn emit_admin_event(&self, event: &AdminAuditEvent, metrics: &Metrics) {
    if let Some(access_logs) = &self.access_logs {
      access_logs.emit_admin_event(event);
      metrics.record_admin_audit_export_event("access_log");
    }
  }
}

impl Default for AdminAuditRuntime {
  fn default() -> Self {
    Self::disabled()
  }
}

fn ensure_event_metadata(event: &AdminAuditEvent) -> anyhow::Result<()> {
  if event.schema_version != ADMIN_AUDIT_SCHEMA_VERSION {
    bail!("unsupported Admin audit schema version");
  }
  if event.event_id.len() != 32
    || !event
      .event_id
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    bail!("Admin audit event ID is unavailable or invalid");
  }
  if event.timestamp.is_empty() || event.timestamp_unix_ms == 0 {
    bail!("Admin audit occurrence timestamp is unavailable");
  }
  Ok(())
}

#[allow(
  clippy::expect_used,
  reason = "the fixed fallback identifier and digest are valid by construction"
)]
fn fallback_integrity_chain() -> integrity::IntegrityChain {
  integrity::IntegrityChain::new(None).unwrap_or_else(|_| {
    integrity::IntegrityChain::restore(
      "00000000000000000000000000000000".to_string(),
      0,
      "0000000000000000000000000000000000000000000000000000000000000000",
      None,
    )
    .expect("static Admin audit fallback chain must be valid")
  })
}

async fn run_spool_drainer(
  spool: spool::AdminAuditSpool,
  store: PostgresAdminAuditStore,
  metrics: Arc<Metrics>,
) {
  loop {
    match spool.next_entry().await {
      Ok(Some(entry)) => {
        match store::insert_record_returning_id(&store.pool, &store.namespace, &entry.event).await {
          Ok(_) => {
            if let Err(error) = spool.acknowledge(entry.path).await {
              metrics.record_admin_audit_replay("failed");
              warn!(error = %error, "failed to acknowledge replayed Admin audit spool event");
              tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            } else {
              metrics.record_admin_audit_replay("persisted");
            }
          }
          Err(error) => {
            metrics.record_admin_audit_replay("failed");
            warn!(error = %error, "failed to replay Admin audit spool event to PostgreSQL");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
          }
        }
      }
      Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
      Err(error) => {
        metrics.record_admin_audit_integrity_failure();
        warn!(error = %error, "Admin audit spool verification failed; replay is blocked");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
      }
    }
  }
}

fn emit_tracing(event: &AdminAuditEvent) {
  info!(
    event = "oxibelt.admin.audit",
    request_id = %event.request_id,
    actor = event.actor.as_deref(),
    principal = event.principal.as_deref(),
    groups = ?event.groups,
    workload_identity_kind = event.workload_identity_kind.as_deref(),
    workload_identity = event.workload_identity.as_deref(),
    workload_principal = event.workload_principal.as_deref(),
    certificate_fingerprint_sha256 = event.certificate_fingerprint_sha256.as_deref(),
    credential_kind = event.credential_kind.as_deref(),
    credential_identity = event.credential_identity.as_deref(),
    credential_principal = event.credential_principal.as_deref(),
    authentication_reason = event.authentication_reason.as_deref(),
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
  async fn durable_reservation_does_not_expose_queue_capacity_before_authentication() {
    let (sender, _receiver) = mpsc::channel(1);
    let held_permit = sender
      .clone()
      .try_reserve_owned()
      .expect("held permit should consume the only slot");
    let runtime = AdminAuditRuntime::test_with_sender(sender);

    let reservation = runtime
      .reserve()
      .expect("pre-authentication reservation should not consume the critical lane");
    assert!(reservation.permit.is_none());
    drop(held_permit);
  }

  #[tokio::test]
  async fn audit_reservation_is_best_effort_when_queue_capacity_is_full() {
    let (sender, _receiver) = mpsc::channel(1);
    let held_permit = sender
      .clone()
      .try_reserve_owned()
      .expect("held permit should consume the only slot");
    let runtime = AdminAuditRuntime::test_with_sender_and_mode(sender, AdminAuditMode::BestEffort);

    let reservation = runtime
      .reserve()
      .expect("best-effort reservation should not reject when the queue is full");

    let audit = sample_audit_handle();
    reservation.commit(&audit, sample_event()).await.unwrap();
    drop(held_permit);
  }

  #[tokio::test]
  async fn audit_reservation_commits_event_through_reserved_slot() {
    let (sender, mut receiver) = mpsc::channel(1);
    let runtime = AdminAuditRuntime::test_with_sender_and_mode(sender, AdminAuditMode::BestEffort);
    let reservation = runtime.reserve().expect("reservation should succeed");

    let audit = sample_audit_handle();
    reservation.commit(&audit, sample_event()).await.unwrap();

    let event = receiver
      .recv()
      .await
      .expect("committed event should be queued");
    assert_eq!(event.status, StatusCode::OK.as_u16());
    assert_eq!(event.outcome, "applied");
  }

  fn sample_audit_handle() -> AdminAuditHandle {
    AdminAuditHandle::new(
      "127.0.0.1:12345".parse().unwrap(),
      "https",
      &http::Method::POST,
      "/admin/v1/config/load",
      None,
    )
  }

  #[tokio::test]
  async fn audit_query_without_store_reports_durable_store_requirement() {
    let runtime = AdminAuditRuntime::test_export_only();
    let error = runtime
      .query(AdminAuditQuery::from_query(None).expect("query should parse"))
      .await
      .expect_err("query without a durable store should fail");

    assert!(
      error
        .to_string()
        .contains("enable [admin.audit.store] with a PostgreSQL backend to query audit history"),
      "{error}"
    );
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
