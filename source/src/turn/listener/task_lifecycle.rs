//! Lifecycle controls for a running TURN listener group.

use tokio::task::JoinHandle;

use crate::server::BoundListener;

use super::{TurnListenerKey, TurnListenerTask};

impl TurnListenerTask {
  pub(crate) fn bound_listeners(&self) -> impl Iterator<Item = BoundListener> + '_ {
    self.bound_listeners.iter().copied()
  }

  pub(crate) fn listener_key(&self) -> &TurnListenerKey {
    &self.key
  }

  pub(crate) fn quiesce(&self) {
    let _ = self.quiesce.send(true);
  }

  pub(crate) fn drain_background(self) {
    drop(self.drain());
  }

  pub(crate) fn drain(self) -> JoinHandle<bool> {
    let deadline = tokio::time::Instant::now() + self.graceful_timeout;
    self.drain_until(deadline)
  }

  pub(crate) fn drain_until(self, deadline: tokio::time::Instant) -> JoinHandle<bool> {
    tokio::spawn(async move {
      let _ = self.quiesce.send(true);
      let _ = self.shutdown.send(true);
      let wait_connections = self.connections.clone();
      let mut tasks = self.tasks;
      let wait = async {
        for task in &mut tasks {
          let _ = task.await;
        }
        wait_connections.wait_idle().await;
      };
      if tokio::time::timeout_at(deadline, wait).await.is_err() {
        for task in &tasks {
          task.abort();
        }
        self.connections.abort_all();
        for task in tasks {
          let _ = task.await;
        }
        self.connections.wait_idle().await;
        return true;
      }
      false
    })
  }
}
