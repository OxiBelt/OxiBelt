//! Remote signer connection pooling.
//! Connections are scoped to signer endpoints so signing requests do not share mutable state.

use std::os::unix::net::UnixStream;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(super) struct RemoteSignerConnectionPool {
  pub(super) max_idle: usize,
  idle: Mutex<Vec<IdleRemoteSignerConnection>>,
}

#[derive(Debug)]
struct IdleRemoteSignerConnection {
  stream: UnixStream,
  returned_at: Instant,
}

impl RemoteSignerConnectionPool {
  fn idle_guard(&self) -> MutexGuard<'_, Vec<IdleRemoteSignerConnection>> {
    match self.idle.lock() {
      Ok(idle) => idle,
      Err(poisoned) => {
        let mut idle = poisoned.into_inner();
        idle.clear();
        self.idle.clear_poison();
        tracing::warn!("rebuilt poisoned remote signer connection pool");
        idle
      }
    }
  }

  pub(super) fn new(max_idle: usize) -> Self {
    Self {
      max_idle,
      idle: Mutex::new(Vec::with_capacity(max_idle.min(64))),
    }
  }

  pub(super) fn take(&self, max_idle_age: Duration) -> Option<UnixStream> {
    if self.max_idle == 0 {
      return None;
    }
    let mut idle = self.idle_guard();
    while let Some(connection) = idle.pop() {
      if connection.returned_at.elapsed() <= max_idle_age {
        return Some(connection.stream);
      }
    }
    None
  }

  pub(super) fn put(&self, stream: UnixStream) {
    if self.max_idle == 0 {
      return;
    }
    let mut idle = self.idle_guard();
    if idle.len() >= self.max_idle {
      return;
    }
    idle.push(IdleRemoteSignerConnection {
      stream,
      returned_at: Instant::now(),
    });
  }
}
