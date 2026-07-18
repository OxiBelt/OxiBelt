//! Runtime store for long-running admin operations.
//! Final events are retained briefly so reconnecting clients can observe completion.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::sync::{Mutex, Semaphore, broadcast};
use tokio::sync::{OwnedSemaphorePermit, TryAcquireError};
use tracing::{info, warn};

use crate::admin_audit::AdminAuditRuntime;
use crate::config::{AdminOperationsConfig, Config};

use super::id::new_operation_id;
use super::runtime_durable::DurableOperationRuntime;
use super::types::{
  AdminOperationEvent, AdminOperationKind, AdminOperationProgress, AdminOperationRecoveryClass,
  AdminOperationSnapshot, AdminOperationState,
};
use crate::server::admin_auth::AdminActor;

pub(in crate::server) type AdminOperationWorkResult = Result<Value, String>;

#[derive(Clone)]
pub(in crate::server) struct AdminOperationRuntime {
  inner: Arc<AdminOperationRuntimeInner>,
}

struct AdminOperationRuntimeInner {
  config: AdminOperationsConfig,
  durable: Option<DurableOperationRuntime>,
  running: Arc<Semaphore>,
  webtransport_sessions: Arc<Semaphore>,
  store: Mutex<AdminOperationStore>,
}

struct AdminOperationStore {
  operations: HashMap<String, AdminOperationRecord>,
  order: VecDeque<String>,
}

struct AdminOperationRecord {
  snapshot: AdminOperationSnapshot,
  cancel: Arc<AtomicBool>,
  events: broadcast::Sender<AdminOperationEvent>,
  history: VecDeque<AdminOperationEvent>,
  next_sequence: u64,
  durable_guard: Option<Arc<Mutex<super::LeaseGuard>>>,
}

#[derive(Debug)]
pub(in crate::server) enum AdminOperationError {
  Disabled,
  QueueFull,
  StoreFull,
  NotFound,
  AlreadyTerminal,
  IdempotencyConflict,
  Unavailable,
  Internal,
}

#[derive(Debug, Clone)]
pub(in crate::server) struct AdminOperationSubmission {
  pub kind: AdminOperationKind,
  pub permission_action: String,
  pub redacted_resource: Option<String>,
  pub idempotency_key: Option<String>,
  pub command: Option<Value>,
  pub recovery_class: AdminOperationRecoveryClass,
}

impl AdminOperationSubmission {
  pub(in crate::server) fn new(
    kind: AdminOperationKind,
    permission_action: impl Into<String>,
    redacted_resource: Option<String>,
    recovery_class: AdminOperationRecoveryClass,
  ) -> Self {
    Self {
      kind,
      permission_action: permission_action.into(),
      redacted_resource,
      idempotency_key: None,
      command: None,
      recovery_class,
    }
  }

  pub(in crate::server) fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
    self.idempotency_key = Some(key.into());
    self
  }

  pub(in crate::server) fn with_command(mut self, command: Value) -> Self {
    self.command = Some(command);
    self
  }
}

#[derive(Clone)]
pub(in crate::server) struct AdminOperationContext {
  pub(super) id: String,
  pub(super) runtime: AdminOperationRuntime,
  pub(super) cancel: Arc<AtomicBool>,
  pub(super) durable_guard: Option<Arc<Mutex<super::LeaseGuard>>>,
}

impl AdminOperationRuntime {
  #[cfg_attr(not(test), allow(dead_code))]
  pub(in crate::server) fn new(config: AdminOperationsConfig) -> Self {
    Self {
      inner: Arc::new(AdminOperationRuntimeInner {
        running: Arc::new(Semaphore::new(config.max_running)),
        webtransport_sessions: Arc::new(Semaphore::new(config.webtransport_max_sessions)),
        config,
        durable: None,
        store: Mutex::new(AdminOperationStore {
          operations: HashMap::new(),
          order: VecDeque::new(),
        }),
      }),
    }
  }

  pub(in crate::server) async fn prepare(
    config: &Config,
    audit: &AdminAuditRuntime,
  ) -> anyhow::Result<Self> {
    let operations = config.admin.operations.clone();
    let durable = DurableOperationRuntime::prepare(config, audit).await?;
    Ok(Self {
      inner: Arc::new(AdminOperationRuntimeInner {
        running: Arc::new(Semaphore::new(operations.max_running)),
        webtransport_sessions: Arc::new(Semaphore::new(operations.webtransport_max_sessions)),
        config: operations,
        durable,
        store: Mutex::new(AdminOperationStore {
          operations: HashMap::new(),
          order: VecDeque::new(),
        }),
      }),
    })
  }

  pub(in crate::server) async fn shutdown(&self) {
    if let Some(durable) = self.inner.durable.as_ref() {
      durable.shutdown().await;
    }
  }

  pub(in crate::server) fn config(&self) -> &AdminOperationsConfig {
    &self.inner.config
  }

  pub(in crate::server) fn persistence_status(&self) -> Value {
    let durable = self.inner.durable.is_some();
    serde_json::json!({
      "configured": self.inner.config.persistence.as_str(),
      "effective": if durable { "postgres" } else { "ephemeral" },
      "fallback_reason": (self.inner.config.persistence == crate::config::AdminOperationsPersistence::Auto
        && !durable).then_some("prerequisites_unavailable"),
    })
  }

  pub(in crate::server) fn try_acquire_webtransport_session(
    &self,
  ) -> Result<OwnedSemaphorePermit, AdminOperationError> {
    if !self.inner.config.webtransport {
      return Err(AdminOperationError::Disabled);
    }
    self
      .inner
      .webtransport_sessions
      .clone()
      .try_acquire_owned()
      .map_err(|error| match error {
        TryAcquireError::NoPermits => AdminOperationError::QueueFull,
        TryAcquireError::Closed => AdminOperationError::Disabled,
      })
  }

  pub(in crate::server) async fn enqueue<F, Fut>(
    &self,
    kind: AdminOperationKind,
    actor: &AdminActor,
    request_id: String,
    work: F,
  ) -> Result<AdminOperationSnapshot, AdminOperationError>
  where
    F: FnOnce(AdminOperationContext) -> Fut + Send + 'static,
    Fut: Future<Output = AdminOperationWorkResult> + Send + 'static,
  {
    let submission = AdminOperationSubmission::new(
      kind,
      "operations.write",
      Some(format!("operation/{}", kind.as_str())),
      AdminOperationRecoveryClass::NonResumable,
    );
    self
      .enqueue_with_submission(submission, actor, request_id, work)
      .await
  }

  pub(in crate::server) async fn enqueue_with_submission<F, Fut>(
    &self,
    submission: AdminOperationSubmission,
    actor: &AdminActor,
    request_id: String,
    work: F,
  ) -> Result<AdminOperationSnapshot, AdminOperationError>
  where
    F: FnOnce(AdminOperationContext) -> Fut + Send + 'static,
    Fut: Future<Output = AdminOperationWorkResult> + Send + 'static,
  {
    if !self.inner.config.enabled {
      return Err(AdminOperationError::Disabled);
    }

    if let Some(durable) = self.inner.durable.as_ref()
      && !matches!(
        submission.kind,
        AdminOperationKind::WebTransportSnapshot | AdminOperationKind::WebTransportDrain
      )
    {
      return durable
        .enqueue(self.clone(), submission, actor, request_id, work)
        .await;
    }

    self
      .enqueue_ephemeral(submission.kind, actor, request_id, work)
      .await
  }

  async fn enqueue_ephemeral<F, Fut>(
    &self,
    kind: AdminOperationKind,
    actor: &AdminActor,
    request_id: String,
    work: F,
  ) -> Result<AdminOperationSnapshot, AdminOperationError>
  where
    F: FnOnce(AdminOperationContext) -> Fut + Send + 'static,
    Fut: Future<Output = AdminOperationWorkResult> + Send + 'static,
  {
    let id = new_operation_id().map_err(|_| AdminOperationError::Internal)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let (events, _) = broadcast::channel(self.inner.config.event_buffer);
    let snapshot = AdminOperationSnapshot {
      id: id.clone(),
      kind,
      state: AdminOperationState::Queued,
      created_at_unix_ms: now_unix_ms(),
      started_at_unix_ms: None,
      finished_at_unix_ms: None,
      actor: actor.name.clone(),
      principal: actor.principal.clone(),
      request_id,
      cancel_requested: false,
      progress: Some(AdminOperationProgress {
        phase: Some("queued".to_string()),
        processed: None,
        total: None,
      }),
      result: None,
      error: None,
      ..AdminOperationSnapshot::default()
    };

    {
      let mut store = self.inner.store.lock().await;
      self.prune_locked(&mut store);
      let queued = store
        .operations
        .values()
        .filter(|record| record.snapshot.state == AdminOperationState::Queued)
        .count();
      if queued >= self.inner.config.max_queued {
        return Err(AdminOperationError::QueueFull);
      }
      if store.operations.len() >= self.inner.config.max_stored {
        return Err(AdminOperationError::StoreFull);
      }
      let mut record = AdminOperationRecord {
        snapshot: snapshot.clone(),
        cancel: Arc::clone(&cancel),
        events,
        history: VecDeque::with_capacity(self.inner.config.event_buffer),
        next_sequence: 1,
        durable_guard: None,
      };
      push_event(&mut record, "operation.queued");
      store.order.push_back(id.clone());
      store.operations.insert(id.clone(), record);
    }

    let runtime = self.clone();
    let running = Arc::clone(&self.inner.running);
    let task_id = id.clone();
    tokio::spawn(async move {
      let permit = match running.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
          runtime
            .fail(&task_id, "operation runner is unavailable".to_string())
            .await;
          return;
        }
      };
      if cancel.load(Ordering::SeqCst) {
        runtime.cancelled(&task_id).await;
        drop(permit);
        return;
      }
      runtime.start(&task_id).await;
      let context = AdminOperationContext {
        id: task_id.clone(),
        runtime: runtime.clone(),
        cancel,
        durable_guard: None,
      };
      let result = work(context).await;
      drop(permit);
      match result {
        Ok(value) => runtime.succeed(&task_id, value).await,
        Err(error) if error == "operation cancelled" => runtime.cancelled(&task_id).await,
        Err(error) => runtime.fail(&task_id, error).await,
      }
    });

    info!(operation_id = %id, kind = kind.as_str(), actor = %actor.name, "admin operation queued");
    Ok(snapshot)
  }

  pub(in crate::server) async fn get(
    &self,
    id: &str,
  ) -> Result<Option<AdminOperationSnapshot>, AdminOperationError> {
    if let Some(durable) = self.inner.durable.as_ref()
      && let Some(snapshot) = durable.get(id).await?
    {
      return Ok(Some(snapshot));
    }
    let mut store = self.inner.store.lock().await;
    self.prune_locked(&mut store);
    Ok(
      store
        .operations
        .get(id)
        .map(|record| record.snapshot.clone()),
    )
  }

  pub(in crate::server) async fn list(
    &self,
  ) -> Result<Vec<AdminOperationSnapshot>, AdminOperationError> {
    let mut durable_rows = if let Some(durable) = self.inner.durable.as_ref() {
      durable.list(self.inner.config.max_stored).await?
    } else {
      Vec::new()
    };
    let mut store = self.inner.store.lock().await;
    self.prune_locked(&mut store);
    durable_rows.extend(
      store
        .order
        .iter()
        .filter_map(|id| {
          store
            .operations
            .get(id)
            .map(|record| record.snapshot.clone())
        })
        .filter(|snapshot| snapshot.durability.as_str() == "ephemeral"),
    );
    durable_rows.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.created_at_unix_ms));
    durable_rows.truncate(self.inner.config.max_stored);
    Ok(durable_rows)
  }

  pub(in crate::server) async fn cancel(
    &self,
    id: &str,
  ) -> Result<AdminOperationSnapshot, AdminOperationError> {
    if let Some(durable) = self.inner.durable.as_ref()
      && durable.contains(id).await?
    {
      return durable.cancel(self, id).await;
    }
    let mut store = self.inner.store.lock().await;
    self.prune_locked(&mut store);
    let Some(record) = store.operations.get_mut(id) else {
      return Err(AdminOperationError::NotFound);
    };
    if record.snapshot.state.is_terminal() {
      return Err(AdminOperationError::AlreadyTerminal);
    }
    record.cancel.store(true, Ordering::SeqCst);
    record.snapshot.cancel_requested = true;
    push_event(record, "operation.cancel_requested");
    Ok(record.snapshot.clone())
  }

  pub(in crate::server) async fn subscribe(
    &self,
    id: &str,
  ) -> Result<
    Option<(
      Vec<AdminOperationEvent>,
      broadcast::Receiver<AdminOperationEvent>,
      AdminOperationSnapshot,
    )>,
    AdminOperationError,
  > {
    if let Some(durable) = self.inner.durable.as_ref()
      && let Some(subscription) = durable.subscribe(self, id).await?
    {
      return Ok(Some(subscription));
    }
    let mut store = self.inner.store.lock().await;
    self.prune_locked(&mut store);
    let Some(record) = store.operations.get(id) else {
      return Ok(None);
    };
    Ok(Some((
      record.history.iter().cloned().collect(),
      record.events.subscribe(),
      record.snapshot.clone(),
    )))
  }

  async fn start(&self, id: &str) {
    self
      .update(id, |record| {
        record.snapshot.state = AdminOperationState::Running;
        record.snapshot.started_at_unix_ms = Some(now_unix_ms());
        record.snapshot.progress = Some(AdminOperationProgress {
          phase: Some("running".to_string()),
          processed: None,
          total: None,
        });
        push_event(record, "operation.running");
        info!(operation_id = %id, kind = record.snapshot.kind.as_str(), "admin operation started");
      })
      .await;
  }

  async fn succeed(&self, id: &str, result: Value) {
    let result_len = encoded_json_len(&result);
    match result_len {
      Ok(len) if len <= self.inner.config.result_max_bytes => {
        self
          .finish(id, AdminOperationState::Succeeded, Some(result), None)
          .await;
      }
      Ok(_) => {
        self
          .fail(
            id,
            "operation result exceeded admin.operations.result_max_bytes".to_string(),
          )
          .await;
      }
      Err(error) => {
        self
          .fail(id, format!("failed to encode operation result: {error}"))
          .await;
      }
    }
  }

  async fn fail(&self, id: &str, error: String) {
    self
      .finish(id, AdminOperationState::Failed, None, Some(error))
      .await;
  }

  async fn cancelled(&self, id: &str) {
    self
      .finish(
        id,
        AdminOperationState::Cancelled,
        None,
        Some("operation cancelled".to_string()),
      )
      .await;
  }

  async fn finish(
    &self,
    id: &str,
    state: AdminOperationState,
    result: Option<Value>,
    error: Option<String>,
  ) {
    self.update(id, |record| {
      if record.snapshot.state.is_terminal() {
        return;
      }
      record.snapshot.state = state;
      record.snapshot.finished_at_unix_ms = Some(now_unix_ms());
      record.snapshot.progress = None;
      record.snapshot.result = result;
      record.snapshot.error = error;
      let event = match state {
        AdminOperationState::Succeeded => "operation.result",
        AdminOperationState::Failed => "operation.error",
        AdminOperationState::Cancelled => "operation.cancelled",
        _ => "operation.finished",
      };
      push_event(record, event);
      info!(operation_id = %id, state = ?state, kind = record.snapshot.kind.as_str(), "admin operation finished");
    })
    .await;
  }

  async fn update(&self, id: &str, update: impl FnOnce(&mut AdminOperationRecord)) {
    let mut store = self.inner.store.lock().await;
    if let Some(record) = store.operations.get_mut(id) {
      update(record);
    } else {
      warn!(operation_id = %id, "admin operation update dropped for unknown id");
    }
  }

  fn prune_locked(&self, store: &mut AdminOperationStore) {
    let cutoff = now_unix_ms().saturating_sub(self.inner.config.retention_seconds * 1_000);
    for id in &store.order {
      let Some(record) = store.operations.get_mut(id) else {
        continue;
      };
      if operation_is_expired(record, cutoff) {
        record.snapshot.state = AdminOperationState::Expired;
      }
    }
    store.order.retain(|id| {
      let Some(record) = store.operations.get(id) else {
        return false;
      };
      !operation_is_expired(record, cutoff)
    });
    store
      .operations
      .retain(|_, record| !operation_is_expired(record, cutoff));
  }

  pub(super) fn running_semaphore(&self) -> Arc<Semaphore> {
    Arc::clone(&self.inner.running)
  }

  pub(super) async fn insert_durable_local(
    &self,
    snapshot: AdminOperationSnapshot,
    cancel: Arc<AtomicBool>,
  ) -> bool {
    let (events, _) = broadcast::channel(self.inner.config.event_buffer);
    let id = snapshot.id.clone();
    let record = AdminOperationRecord {
      next_sequence: snapshot.revision.saturating_add(1),
      snapshot,
      cancel,
      events,
      history: VecDeque::with_capacity(self.inner.config.event_buffer),
      durable_guard: None,
    };
    let mut store = self.inner.store.lock().await;
    if store.operations.contains_key(&id) {
      return false;
    }
    store.order.push_back(id.clone());
    store.operations.insert(id, record);
    true
  }

  pub(super) async fn set_durable_guard(&self, id: &str, guard: Arc<Mutex<super::LeaseGuard>>) {
    if let Some(record) = self.inner.store.lock().await.operations.get_mut(id) {
      record.durable_guard = Some(guard);
    }
  }

  pub(super) async fn durable_local_parts(
    &self,
    id: &str,
  ) -> Option<(
    Arc<AtomicBool>,
    Option<Arc<Mutex<super::LeaseGuard>>>,
    broadcast::Receiver<AdminOperationEvent>,
  )> {
    let store = self.inner.store.lock().await;
    let record = store.operations.get(id)?;
    Some((
      Arc::clone(&record.cancel),
      record.durable_guard.clone(),
      record.events.subscribe(),
    ))
  }

  pub(super) async fn publish_durable(&self, snapshot: AdminOperationSnapshot, event_name: &str) {
    let mut store = self.inner.store.lock().await;
    let Some(record) = store.operations.get_mut(&snapshot.id) else {
      return;
    };
    record.snapshot = snapshot.clone();
    record.next_sequence = snapshot.revision.saturating_add(1);
    let event = AdminOperationEvent {
      sequence: snapshot.revision,
      event: event_name.to_string(),
      created_at_unix_ms: snapshot
        .updated_at_unix_ms
        .unwrap_or(snapshot.created_at_unix_ms),
      operation: snapshot,
    };
    if record.history.len() >= self.inner.config.event_buffer {
      record.history.pop_front();
    }
    record.history.push_back(event.clone());
    let _ = record.events.send(event);
  }
}

fn operation_is_expired(record: &AdminOperationRecord, cutoff: u64) -> bool {
  record
    .snapshot
    .finished_at_unix_ms
    .is_some_and(|finished| record.snapshot.state.is_terminal() && finished < cutoff)
}

fn encoded_json_len(value: &Value) -> serde_json::Result<usize> {
  let mut writer = JsonLenWriter { len: 0 };
  serde_json::to_writer(&mut writer, value)?;
  Ok(writer.len)
}

struct JsonLenWriter {
  len: usize,
}

impl std::io::Write for JsonLenWriter {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    self.len = self.len.saturating_add(buf.len());
    Ok(buf.len())
  }

  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

impl AdminOperationContext {
  pub(in crate::server) fn id(&self) -> &str {
    &self.id
  }

  pub(in crate::server) fn is_cancelled(&self) -> bool {
    self.cancel.load(Ordering::SeqCst)
  }

  pub(in crate::server) async fn progress(
    &self,
    phase: impl Into<String>,
    processed: Option<u64>,
    total: Option<u64>,
  ) {
    let progress = AdminOperationProgress {
      phase: Some(phase.into()),
      processed,
      total,
    };
    if let Some(guard) = self.durable_guard.as_ref()
      && let Some(durable) = self.runtime.inner.durable.as_ref()
    {
      durable
        .progress(&self.runtime, &self.id, guard, progress)
        .await;
      return;
    }
    self
      .runtime
      .update(&self.id, |record| {
        if record.snapshot.state.is_terminal() {
          return;
        }
        record.snapshot.progress = Some(progress);
        push_event(record, "operation.progress");
      })
      .await;
  }

  pub(in crate::server) fn ensure_not_cancelled(&self) -> Result<(), String> {
    if self.is_cancelled() {
      Err("operation cancelled".to_string())
    } else {
      Ok(())
    }
  }
}

fn push_event(record: &mut AdminOperationRecord, event: &str) {
  let event = AdminOperationEvent {
    sequence: record.next_sequence,
    event: event.to_string(),
    created_at_unix_ms: now_unix_ms(),
    operation: record.snapshot.clone(),
  };
  record.next_sequence = record.next_sequence.saturating_add(1);
  if record.history.len() >= record.history.capacity().max(1) && record.history.capacity() > 0 {
    record.history.pop_front();
  }
  record.history.push_back(event.clone());
  let _ = record.events.send(event);
}

pub(in crate::server) fn now_unix_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
    .unwrap_or_default()
}

impl std::fmt::Display for AdminOperationError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Disabled => formatter.write_str("admin operations are disabled"),
      Self::QueueFull => formatter.write_str("admin operation queue is full"),
      Self::StoreFull => formatter.write_str("admin operation store is full"),
      Self::NotFound => formatter.write_str("operation not found"),
      Self::AlreadyTerminal => formatter.write_str("operation already finished"),
      Self::IdempotencyConflict => {
        formatter.write_str("Idempotency-Key conflicts with an existing operation")
      }
      Self::Unavailable => formatter.write_str("durable admin operation state is unavailable"),
      Self::Internal => formatter.write_str("admin operation state is unavailable"),
    }
  }
}

impl std::error::Error for AdminOperationError {}

pub(in crate::server) fn value_result<T: serde::Serialize>(value: T) -> AdminOperationWorkResult {
  serde_json::to_value(value).map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
