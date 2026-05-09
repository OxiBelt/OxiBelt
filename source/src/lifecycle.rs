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
      close_delay,
    }
  }

  pub(crate) async fn close_delay_elapsed(&mut self) {
    self.wait_for_drain().await;
    tokio::time::sleep(self.close_delay).await;
  }

  pub(crate) async fn wait_for_drain(&mut self) {
    if *self.listener.borrow() || *self.lifecycle.borrow() {
      return;
    }

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
    self.inner.active.fetch_add(1, Ordering::Relaxed);
    let inner = self.inner.clone();
    let task = tokio::spawn(async move {
      future.await;
      inner.active.fetch_sub(1, Ordering::Relaxed);
      inner.notify.notify_waiters();
    });
    self
      .inner
      .tasks
      .lock()
      .expect("task registry lock poisoned")
      .push(task);
  }

  pub(crate) async fn wait_idle(&self) {
    while self.inner.active.load(Ordering::Relaxed) > 0 {
      self.inner.notify.notified().await;
    }
  }

  pub(crate) fn abort_all(&self) {
    for task in self
      .inner
      .tasks
      .lock()
      .expect("task registry lock poisoned")
      .iter()
    {
      task.abort();
    }
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
}
