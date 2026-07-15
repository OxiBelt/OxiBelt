//! Lifecycle state shared by listeners, connections, and admin drain operations.
//! Drain signals are explicit so shutdown does not race active proxy sessions.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::FutureExt as _;
use tokio::sync::Notify;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::runtime_health::{RuntimeHealth, RuntimePanicScope, RuntimeSubsystem, RuntimeTaskKind};

#[derive(Debug)]
pub struct LifecycleState {
  admin_draining: AtomicBool,
  overload_draining: AtomicBool,
  shutdown_draining: AtomicBool,
  drain_tx: watch::Sender<bool>,
}

impl Default for LifecycleState {
  fn default() -> Self {
    let (drain_tx, _) = watch::channel(false);
    Self {
      admin_draining: AtomicBool::new(false),
      overload_draining: AtomicBool::new(false),
      shutdown_draining: AtomicBool::new(false),
      drain_tx,
    }
  }
}

impl LifecycleState {
  pub fn is_draining(&self) -> bool {
    self.admin_draining.load(Ordering::Relaxed)
      || self.overload_draining.load(Ordering::Relaxed)
      || self.shutdown_draining.load(Ordering::Relaxed)
  }

  pub fn is_shutdown_draining(&self) -> bool {
    self.shutdown_draining.load(Ordering::Acquire)
  }

  pub fn reason(&self) -> &'static str {
    if self.shutdown_draining.load(Ordering::Relaxed) {
      "shutdown"
    } else if self.admin_draining.load(Ordering::Relaxed) {
      "admin"
    } else if self.overload_draining.load(Ordering::Relaxed) {
      "overload"
    } else {
      "ready"
    }
  }

  pub fn set_admin_draining(&self) {
    self.admin_draining.store(true, Ordering::Relaxed);
    self.publish();
  }

  pub fn clear_admin_draining(&self) {
    self.admin_draining.store(false, Ordering::Relaxed);
    self.publish();
  }

  pub fn set_overload_draining(&self) {
    self.overload_draining.store(true, Ordering::Relaxed);
    self.publish();
  }

  pub fn clear_overload_draining(&self) {
    self.overload_draining.store(false, Ordering::Relaxed);
    self.publish();
  }

  pub fn start_shutdown(&self) -> bool {
    if self.shutdown_draining.swap(true, Ordering::AcqRel) {
      return false;
    }
    self.publish();
    true
  }

  pub fn subscribe(&self) -> watch::Receiver<bool> {
    self.drain_tx.subscribe()
  }

  fn publish(&self) {
    let _ = self.drain_tx.send(self.is_draining());
  }
}

#[derive(Clone)]
pub(crate) struct ConnectionDrain {
  listener: watch::Receiver<bool>,
  lifecycle: watch::Receiver<bool>,
  data_plane: Option<watch::Receiver<bool>>,
  close_delay: Duration,
}

impl ConnectionDrain {
  pub(crate) fn new(
    listener: watch::Receiver<bool>,
    lifecycle: watch::Receiver<bool>,
    close_delay: Duration,
  ) -> Self {
    Self {
      listener,
      lifecycle,
      data_plane: None,
      close_delay,
    }
  }

  pub(crate) fn with_data_plane(
    listener: watch::Receiver<bool>,
    lifecycle: watch::Receiver<bool>,
    data_plane: watch::Receiver<bool>,
    close_delay: Duration,
  ) -> Self {
    Self {
      listener,
      lifecycle,
      data_plane: Some(data_plane),
      close_delay,
    }
  }

  pub(crate) async fn close_delay_elapsed(&mut self) {
    self.wait_for_drain().await;
    tokio::time::sleep(self.close_delay).await;
  }

  pub(crate) async fn wait_for_drain(&mut self) {
    if self.is_draining() {
      return;
    }

    if let Some(data_plane) = &mut self.data_plane {
      loop {
        tokio::select! {
          changed = self.listener.changed() => {
            if changed.is_err() || *self.listener.borrow() {
              return;
            }
          }
          changed = self.lifecycle.changed() => {
            if changed.is_err() || *self.lifecycle.borrow() {
              return;
            }
          }
          changed = data_plane.changed() => {
            if changed.is_err() || *data_plane.borrow() {
              return;
            }
          }
        }
      }
    } else {
      loop {
        tokio::select! {
          changed = self.listener.changed() => {
            if changed.is_err() || *self.listener.borrow() {
              return;
            }
          }
          changed = self.lifecycle.changed() => {
            if changed.is_err() || *self.lifecycle.borrow() {
              return;
            }
          }
        }
      }
    }
  }

  /// Reports whether this connection should begin graceful protocol shutdown.
  ///
  /// A lifecycle drain that was already active when the connection subscribed must still allow a
  /// request to reach the data plane and receive its deterministic draining response. Listener
  /// and data-plane generation drains remain immediately actionable.
  pub(crate) fn is_graceful_connection_draining(&self) -> bool {
    *self.listener.borrow()
      || self.has_lifecycle_drain_transition()
      || self
        .data_plane
        .as_ref()
        .is_some_and(|drain| *drain.borrow())
  }

  /// Waits for a drain transition that applies to this established connection.
  pub(crate) async fn wait_for_graceful_connection_drain(&mut self) {
    if self.is_graceful_connection_draining() {
      return;
    }

    if let Some(data_plane) = &mut self.data_plane {
      loop {
        tokio::select! {
          changed = self.listener.changed() => {
            if changed.is_err() || *self.listener.borrow() {
              return;
            }
          }
          changed = self.lifecycle.changed() => {
            if changed.is_err() || *self.lifecycle.borrow() {
              return;
            }
          }
          changed = data_plane.changed() => {
            if changed.is_err() || *data_plane.borrow() {
              return;
            }
          }
        }
      }
    } else {
      loop {
        tokio::select! {
          changed = self.listener.changed() => {
            if changed.is_err() || *self.listener.borrow() {
              return;
            }
          }
          changed = self.lifecycle.changed() => {
            if changed.is_err() || *self.lifecycle.borrow() {
              return;
            }
          }
        }
      }
    }
  }

  /// Returns true only when this receiver observed lifecycle drain after subscription.
  pub(crate) fn has_lifecycle_drain_transition(&self) -> bool {
    match self.lifecycle.has_changed() {
      Ok(changed) => changed && *self.lifecycle.borrow(),
      Err(_) => true,
    }
  }

  /// Waits for a lifecycle drain transition after this connection subscribed.
  pub(crate) async fn wait_for_lifecycle_drain_transition(&mut self) {
    if self.has_lifecycle_drain_transition() {
      return;
    }

    loop {
      if self.lifecycle.changed().await.is_err() || *self.lifecycle.borrow() {
        return;
      }
    }
  }

  pub(crate) fn is_draining(&self) -> bool {
    *self.listener.borrow()
      || *self.lifecycle.borrow()
      || self
        .data_plane
        .as_ref()
        .is_some_and(|drain| *drain.borrow())
  }
}

#[derive(Clone)]
pub(crate) struct TaskRegistry {
  inner: Arc<TaskRegistryInner>,
  health: Arc<RuntimeHealth>,
  kind: RuntimeTaskKind,
}

#[derive(Default)]
struct TaskRegistryInner {
  active: std::sync::atomic::AtomicUsize,
  notify: Notify,
  tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl TaskRegistry {
  pub(crate) fn new(kind: RuntimeTaskKind, health: Arc<RuntimeHealth>) -> Self {
    Self {
      inner: Arc::new(TaskRegistryInner::default()),
      health,
      kind,
    }
  }

  pub(crate) fn spawn<F>(&self, future: F)
  where
    F: std::future::Future<Output = ()> + Send + 'static,
  {
    self.reap_finished();
    self.inner.active.fetch_add(1, Ordering::Relaxed);
    let inner = self.inner.clone();
    let health = self.health.clone();
    let kind = self.kind;
    let completion = TaskCompletion { inner };
    let task = tokio::spawn(async move {
      let _completion = completion;
      if AssertUnwindSafe(future).catch_unwind().await.is_err() {
        health.record_panic(RuntimePanicScope::Connection, kind);
        tracing::error!(task = kind.as_str(), "contained connection task panicked");
      }
    });
    self.tasks_guard().push(task);
  }

  pub(crate) async fn wait_idle(&self) {
    loop {
      let notified = self.inner.notify.notified();
      if self.inner.active.load(Ordering::Relaxed) == 0 {
        break;
      }
      notified.await;
    }

    self.reap_finished();
  }

  pub(crate) fn abort_all(&self) {
    let mut tasks = self.tasks_guard();
    tasks.retain(|task| !task.is_finished());
    for task in tasks.iter() {
      task.abort();
    }
  }

  fn reap_finished(&self) {
    self.tasks_guard().retain(|task| !task.is_finished());
  }

  fn tasks_guard(&self) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
    match self.inner.tasks.lock() {
      Ok(tasks) => tasks,
      Err(poisoned) => {
        let tasks = poisoned.into_inner();
        self.inner.tasks.clear_poison();
        self
          .health
          .record_lock_recovery(RuntimeSubsystem::TaskRegistry);
        tasks
      }
    }
  }

  #[cfg(test)]
  fn active_count(&self) -> usize {
    self.inner.active.load(Ordering::Relaxed)
  }

  #[cfg(test)]
  fn tracked_task_count(&self) -> usize {
    self
      .inner
      .tasks
      .lock()
      .expect("task registry lock poisoned")
      .len()
  }
}

impl Default for TaskRegistry {
  fn default() -> Self {
    Self::new(
      RuntimeTaskKind::HttpConnection,
      Arc::new(RuntimeHealth::default()),
    )
  }
}

struct TaskCompletion {
  inner: Arc<TaskRegistryInner>,
}

impl Drop for TaskCompletion {
  fn drop(&mut self) {
    self.inner.active.fetch_sub(1, Ordering::Relaxed);
    self.inner.notify.notify_waiters();
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn lifecycle_state_reports_admin_and_shutdown_reasons() {
    let lifecycle = LifecycleState::default();
    assert!(!lifecycle.is_draining());
    assert_eq!(lifecycle.reason(), "ready");

    lifecycle.set_admin_draining();
    assert!(lifecycle.is_draining());
    assert_eq!(lifecycle.reason(), "admin");

    assert!(lifecycle.start_shutdown());
    assert!(lifecycle.is_draining());
    assert_eq!(lifecycle.reason(), "shutdown");

    lifecycle.clear_admin_draining();
    assert!(lifecycle.is_draining());
    assert_eq!(lifecycle.reason(), "shutdown");
  }

  #[test]
  fn repeated_shutdown_does_not_republish_or_reset_drain() {
    let lifecycle = LifecycleState::default();
    let mut drain = lifecycle.subscribe();

    assert!(lifecycle.start_shutdown());
    assert!(drain.has_changed().expect("first shutdown should publish"));
    assert!(*drain.borrow_and_update());

    assert!(!lifecycle.start_shutdown());
    assert!(
      !drain
        .has_changed()
        .expect("shutdown sender should remain available")
    );
  }

  #[test]
  fn connection_drain_reports_all_drain_sources() {
    let lifecycle = LifecycleState::default();
    let (listener_tx, listener_rx) = watch::channel(false);
    let (data_plane_tx, data_plane_rx) = watch::channel(false);
    let drain = ConnectionDrain::with_data_plane(
      listener_rx,
      lifecycle.subscribe(),
      data_plane_rx,
      Duration::from_millis(1),
    );

    assert!(!drain.is_draining());

    listener_tx
      .send(true)
      .expect("listener drain signal should send");
    assert!(drain.is_draining());
    assert!(drain.is_graceful_connection_draining());
    listener_tx
      .send(false)
      .expect("listener ready signal should send");
    assert!(!drain.is_draining());
    assert!(!drain.is_graceful_connection_draining());

    lifecycle.set_admin_draining();
    assert!(drain.is_draining());
    assert!(drain.is_graceful_connection_draining());
    lifecycle.clear_admin_draining();
    assert!(!drain.is_draining());
    assert!(!drain.is_graceful_connection_draining());

    data_plane_tx
      .send(true)
      .expect("data-plane drain signal should send");
    assert!(drain.is_draining());
    assert!(drain.is_graceful_connection_draining());
    data_plane_tx
      .send(false)
      .expect("data-plane ready signal should send");
    assert!(!drain.is_draining());
    assert!(!drain.is_graceful_connection_draining());
  }

  #[tokio::test]
  async fn graceful_connection_drain_ignores_active_lifecycle_until_next_transition() {
    let lifecycle = LifecycleState::default();
    let _lifecycle_observer = lifecycle.subscribe();
    lifecycle.set_admin_draining();
    let (_listener_tx, listener_rx) = watch::channel(false);
    let mut drain =
      ConnectionDrain::new(listener_rx, lifecycle.subscribe(), Duration::from_millis(1));

    assert!(drain.is_draining());
    assert!(!drain.is_graceful_connection_draining());
    assert!(
      tokio::time::timeout(
        Duration::from_millis(10),
        drain.wait_for_graceful_connection_drain(),
      )
      .await
      .is_err()
    );

    lifecycle.clear_admin_draining();
    let wait = tokio::spawn(async move {
      drain.wait_for_graceful_connection_drain().await;
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!wait.is_finished());

    lifecycle.set_admin_draining();
    tokio::time::timeout(Duration::from_secs(1), wait)
      .await
      .expect("the next lifecycle drain should close the established connection")
      .expect("connection drain task should not panic");
  }

  #[tokio::test]
  async fn connection_drain_waits_for_signal_then_delay() {
    let lifecycle = LifecycleState::default();
    let (listener_tx, listener_rx) = watch::channel(false);
    let mut drain = ConnectionDrain::new(
      listener_rx,
      lifecycle.subscribe(),
      Duration::from_millis(25),
    );

    let started = std::time::Instant::now();
    let task = tokio::spawn(async move {
      drain.close_delay_elapsed().await;
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!task.is_finished());

    let _ = listener_tx.send(true);
    task.await.expect("drain task should finish");
    assert!(started.elapsed() >= Duration::from_millis(25));
  }

  #[tokio::test]
  async fn connection_drain_waits_for_data_plane_signal_then_delay() {
    let lifecycle = LifecycleState::default();
    let (listener_tx, listener_rx) = watch::channel(false);
    let (data_plane_tx, data_plane_rx) = watch::channel(false);
    let mut drain = ConnectionDrain::with_data_plane(
      listener_rx,
      lifecycle.subscribe(),
      data_plane_rx,
      Duration::from_millis(25),
    );

    let task = tokio::spawn(async move {
      drain.close_delay_elapsed().await;
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!task.is_finished());

    let signaled = std::time::Instant::now();
    data_plane_tx
      .send(true)
      .expect("data-plane drain signal should send");
    task.await.expect("data-plane drain task should finish");
    assert!(signaled.elapsed() >= Duration::from_millis(25));

    drop(listener_tx);
  }

  #[tokio::test]
  async fn task_registry_reaps_completed_tasks_during_long_lived_generation() {
    let registry = TaskRegistry::default();

    for _ in 0..128 {
      registry.spawn(async {});
      wait_for_active_tasks(&registry, 0).await;
      assert!(
        registry.tracked_task_count() <= 1,
        "completed connection tasks should not accumulate across spawns"
      );
    }

    registry.wait_idle().await;
    assert_eq!(registry.tracked_task_count(), 0);
  }

  #[tokio::test]
  async fn task_registry_wait_idle_reaps_last_completed_task() {
    let registry = TaskRegistry::default();

    registry.spawn(async {});
    wait_for_active_tasks(&registry, 0).await;
    assert_eq!(registry.tracked_task_count(), 1);

    registry.wait_idle().await;
    assert_eq!(registry.tracked_task_count(), 0);
  }

  #[tokio::test]
  async fn task_registry_abort_all_decrements_active_tasks() {
    let registry = TaskRegistry::default();
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();

    registry.spawn(async move {
      let _ = rx.await;
    });
    wait_for_active_tasks(&registry, 1).await;

    registry.abort_all();
    wait_for_active_tasks(&registry, 0).await;
  }

  #[tokio::test]
  async fn connection_panic_is_counted_and_does_not_disable_registry() {
    let health = Arc::new(RuntimeHealth::default());
    let registry = TaskRegistry::new(RuntimeTaskKind::HttpConnection, health.clone());

    registry.spawn(async {
      panic!("injected connection panic");
    });
    wait_for_active_tasks(&registry, 0).await;

    let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
    registry.spawn(async move {
      let _ = completed_tx.send(());
    });
    completed_rx
      .await
      .expect("registry should continue accepting connection tasks");
    registry.wait_idle().await;

    let mut metrics = String::new();
    health.append_prometheus(&mut metrics);
    assert!(
      metrics
        .contains("oxibelt_runtime_panics_total{scope=\"connection\",task=\"http_connection\"} 1")
    );
  }

  async fn wait_for_active_tasks(registry: &TaskRegistry, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
      loop {
        if registry.active_count() == expected {
          break;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("task registry active count should settle");
  }
}
