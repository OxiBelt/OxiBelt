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

use crate::config::AdminOperationsConfig;

use super::id::new_operation_id;
use super::types::{
  AdminOperationEvent, AdminOperationKind, AdminOperationProgress, AdminOperationSnapshot,
  AdminOperationState,
};
use crate::server::admin_auth::AdminActor;

pub(in crate::server) type AdminOperationWorkResult = Result<Value, String>;

#[derive(Clone)]
pub(in crate::server) struct AdminOperationRuntime {
  inner: Arc<AdminOperationRuntimeInner>,
}

struct AdminOperationRuntimeInner {
  config: AdminOperationsConfig,
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
}

#[derive(Debug)]
pub(in crate::server) enum AdminOperationError {
  Disabled,
  QueueFull,
  StoreFull,
  NotFound,
  AlreadyTerminal,
  Internal,
}

#[derive(Clone)]
pub(in crate::server) struct AdminOperationContext {
  id: String,
  runtime: AdminOperationRuntime,
  cancel: Arc<AtomicBool>,
}

impl AdminOperationRuntime {
  pub(in crate::server) fn new(config: AdminOperationsConfig) -> Self {
    Self {
      inner: Arc::new(AdminOperationRuntimeInner {
        running: Arc::new(Semaphore::new(config.max_running)),
        webtransport_sessions: Arc::new(Semaphore::new(config.webtransport_max_sessions)),
        config,
        store: Mutex::new(AdminOperationStore {
          operations: HashMap::new(),
          order: VecDeque::new(),
        }),
      }),
    }
  }

  pub(in crate::server) fn config(&self) -> &AdminOperationsConfig {
    &self.inner.config
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
    if !self.inner.config.enabled {
      return Err(AdminOperationError::Disabled);
    }

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

  pub(in crate::server) async fn get(&self, id: &str) -> Option<AdminOperationSnapshot> {
    let mut store = self.inner.store.lock().await;
    self.prune_locked(&mut store);
    store
      .operations
      .get(id)
      .map(|record| record.snapshot.clone())
  }

  pub(in crate::server) async fn list(&self) -> Vec<AdminOperationSnapshot> {
    let mut store = self.inner.store.lock().await;
    self.prune_locked(&mut store);
    store
      .order
      .iter()
      .filter_map(|id| {
        store
          .operations
          .get(id)
          .map(|record| record.snapshot.clone())
      })
      .collect()
  }

  pub(in crate::server) async fn cancel(
    &self,
    id: &str,
  ) -> Result<AdminOperationSnapshot, AdminOperationError> {
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
  ) -> Option<(
    Vec<AdminOperationEvent>,
    broadcast::Receiver<AdminOperationEvent>,
    AdminOperationSnapshot,
  )> {
    let mut store = self.inner.store.lock().await;
    self.prune_locked(&mut store);
    let record = store.operations.get(id)?;
    Some((
      record.history.iter().cloned().collect(),
      record.events.subscribe(),
      record.snapshot.clone(),
    ))
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
      Self::Internal => formatter.write_str("admin operation state is unavailable"),
    }
  }
}

impl std::error::Error for AdminOperationError {}

pub(in crate::server) fn value_result<T: serde::Serialize>(value: T) -> AdminOperationWorkResult {
  serde_json::to_value(value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn actor(name: &str) -> AdminActor {
    AdminActor {
      name: name.to_string(),
      principal: name.to_string(),
      subject: format!("{name}@example.test"),
      groups: Vec::new(),
    }
  }

  fn config() -> AdminOperationsConfig {
    AdminOperationsConfig {
      max_running: 1,
      max_queued: 1,
      max_stored: 2,
      event_buffer: 4,
      retention_seconds: 60,
      ..AdminOperationsConfig::default()
    }
  }

  async fn wait_for_terminal(runtime: &AdminOperationRuntime, id: &str) -> AdminOperationSnapshot {
    for _ in 0..100 {
      let snapshot = runtime.get(id).await.expect("operation should exist");
      if snapshot.state.is_terminal() {
        return snapshot;
      }
      tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("operation did not finish");
  }

  #[tokio::test]
  async fn queue_capacity_is_enforced() {
    let mut config = config();
    config.max_running = 0;
    config.max_queued = 1;
    let runtime = AdminOperationRuntime::new(config);
    let actor = actor("admin");
    let first = runtime
      .enqueue(
        AdminOperationKind::CacheWarm,
        &actor,
        "req1".to_string(),
        |_| async {
          tokio::time::sleep(std::time::Duration::from_millis(50)).await;
          Ok(serde_json::json!({"ok": true}))
        },
      )
      .await;
    assert!(first.is_ok());
    let second = runtime
      .enqueue(
        AdminOperationKind::CacheWarm,
        &actor,
        "req2".to_string(),
        |_| async { Ok(serde_json::json!({"ok": true})) },
      )
      .await;
    assert!(matches!(second, Err(AdminOperationError::QueueFull)));
  }

  #[tokio::test]
  async fn cancellation_marks_operation_cancel_requested() {
    let runtime = AdminOperationRuntime::new(config());
    let actor = actor("admin");
    let snapshot = runtime
      .enqueue(
        AdminOperationKind::CacheWarm,
        &actor,
        "req1".to_string(),
        |context| async move {
          while !context.is_cancelled() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
          }
          Err("operation cancelled".to_string())
        },
      )
      .await
      .expect("operation should enqueue");
    let cancelled = runtime
      .cancel(&snapshot.id)
      .await
      .expect("operation should cancel");
    assert!(cancelled.cancel_requested);
  }

  #[tokio::test]
  async fn state_transitions_to_succeeded() {
    let runtime = AdminOperationRuntime::new(config());
    let actor = actor("admin");
    let snapshot = runtime
      .enqueue(
        AdminOperationKind::SupportBundle,
        &actor,
        "req1".to_string(),
        |context| async move {
          context.progress("working", Some(1), Some(2)).await;
          Ok(serde_json::json!({"ok": true}))
        },
      )
      .await
      .expect("operation should enqueue");
    let terminal = wait_for_terminal(&runtime, &snapshot.id).await;
    assert_eq!(terminal.state, AdminOperationState::Succeeded);
    assert_eq!(terminal.result, Some(serde_json::json!({"ok": true})));
  }

  #[tokio::test]
  async fn event_history_is_bounded_and_replayed() {
    let mut config = config();
    config.event_buffer = 2;
    let runtime = AdminOperationRuntime::new(config);
    let actor = actor("admin");
    let snapshot = runtime
      .enqueue(
        AdminOperationKind::CacheWarm,
        &actor,
        "req1".to_string(),
        |context| async move {
          context.progress("one", Some(1), Some(3)).await;
          context.progress("two", Some(2), Some(3)).await;
          context.progress("three", Some(3), Some(3)).await;
          Ok(serde_json::json!({"ok": true}))
        },
      )
      .await
      .expect("operation should enqueue");
    let terminal = wait_for_terminal(&runtime, &snapshot.id).await;
    assert_eq!(terminal.state, AdminOperationState::Succeeded);

    let (history, _receiver, _) = runtime
      .subscribe(&snapshot.id)
      .await
      .expect("operation should be subscribable");
    assert!(history.len() <= 2);
    assert_eq!(
      history.last().map(|event| event.event.as_str()),
      Some("operation.result")
    );
  }

  #[tokio::test]
  async fn retention_prunes_finished_operations() {
    let mut config = config();
    config.retention_seconds = 1;
    let runtime = AdminOperationRuntime::new(config);
    let actor = actor("admin");
    let snapshot = runtime
      .enqueue(
        AdminOperationKind::CacheWarm,
        &actor,
        "req1".to_string(),
        |_| async { Ok(serde_json::json!({"ok": true})) },
      )
      .await
      .expect("operation should enqueue");
    let _terminal = wait_for_terminal(&runtime, &snapshot.id).await;
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    assert!(runtime.get(&snapshot.id).await.is_none());
  }

  #[tokio::test]
  async fn oversized_results_fail_the_operation() {
    let mut config = config();
    config.result_max_bytes = 4;
    let runtime = AdminOperationRuntime::new(config);
    let actor = actor("admin");
    let snapshot = runtime
      .enqueue(
        AdminOperationKind::CacheWarm,
        &actor,
        "req1".to_string(),
        |_| async { Ok(serde_json::json!({"too": "large"})) },
      )
      .await
      .expect("operation should enqueue");
    let terminal = wait_for_terminal(&runtime, &snapshot.id).await;
    assert_eq!(terminal.state, AdminOperationState::Failed);
    assert!(
      terminal
        .error
        .unwrap_or_default()
        .contains("result_max_bytes")
    );
  }
}
