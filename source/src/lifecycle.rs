use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct LifecycleState {
  admin_draining: AtomicBool,
  shutdown_draining: AtomicBool,
  drain_tx: watch::Sender<bool>,
}

impl Default for LifecycleState {
  fn default() -> Self {
    let (drain_tx, _) = watch::channel(false);
    Self {
      admin_draining: AtomicBool::new(false),
      shutdown_draining: AtomicBool::new(false),
      drain_tx,
    }
  }
}

impl LifecycleState {
  pub fn is_draining(&self) -> bool {
    self.admin_draining.load(Ordering::Relaxed) || self.shutdown_draining.load(Ordering::Relaxed)
  }

  pub fn reason(&self) -> &'static str {
    if self.shutdown_draining.load(Ordering::Relaxed) {
      "shutdown"
    } else if self.admin_draining.load(Ordering::Relaxed) {
      "admin"
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

  pub fn start_shutdown(&self) {
    self.shutdown_draining.store(true, Ordering::Relaxed);
    self.publish();
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

  fn is_draining(&self) -> bool {
    *self.listener.borrow()
      || *self.lifecycle.borrow()
      || self
        .data_plane
        .as_ref()
        .is_some_and(|drain| *drain.borrow())
  }
}

pub(crate) async fn wait_for_listener_or_data_plane_drain(
  listener: &mut watch::Receiver<bool>,
  data_plane: &mut watch::Receiver<bool>,
) {
  if *listener.borrow() || *data_plane.borrow() {
    return;
  }

  loop {
    tokio::select! {
      changed = listener.changed() => {
        if changed.is_err() || *listener.borrow() {
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
}

#[derive(Clone, Default)]
pub(crate) struct TaskRegistry {
  inner: Arc<TaskRegistryInner>,
}

#[derive(Default)]
struct TaskRegistryInner {
  active: std::sync::atomic::AtomicUsize,
  notify: Notify,
  tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl TaskRegistry {
  pub(crate) fn spawn<F>(&self, future: F)
  where
    F: std::future::Future<Output = ()> + Send + 'static,
  {
    self.reap_finished();
    self.inner.active.fetch_add(1, Ordering::Relaxed);
    let inner = self.inner.clone();
    let completion = TaskCompletion { inner };
    let task = tokio::spawn(async move {
      let _completion = completion;
      future.await;
    });
    self
      .inner
      .tasks
      .lock()
      .expect("task registry lock poisoned")
      .push(task);
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
    let mut tasks = self
      .inner
      .tasks
      .lock()
      .expect("task registry lock poisoned");
    tasks.retain(|task| !task.is_finished());
    for task in tasks.iter() {
      task.abort();
    }
  }

  fn reap_finished(&self) {
    self
      .inner
      .tasks
      .lock()
      .expect("task registry lock poisoned")
      .retain(|task| !task.is_finished());
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

    lifecycle.start_shutdown();
    assert!(lifecycle.is_draining());
    assert_eq!(lifecycle.reason(), "shutdown");

    lifecycle.clear_admin_draining();
    assert!(lifecycle.is_draining());
    assert_eq!(lifecycle.reason(), "shutdown");
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
