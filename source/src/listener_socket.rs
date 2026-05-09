use std::net::SocketAddr;

use anyhow::Context;
use tokio::net::{TcpListener, TcpSocket};

use crate::config::RuntimeAcceptConfig;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct TcpListenOptions {
  pub(crate) workers: usize,
  pub(crate) reuse_port: bool,
  pub(crate) backlog: u32,
}

impl From<&RuntimeAcceptConfig> for TcpListenOptions {
  fn from(config: &RuntimeAcceptConfig) -> Self {
    Self {
      workers: config.workers,
      reuse_port: config.reuse_port,
      backlog: config.backlog,
    }
  }
}

pub(crate) fn bind_tcp_listeners(
  bind: SocketAddr,
  options: TcpListenOptions,
  purpose: &str,
) -> anyhow::Result<Vec<TcpListener>> {
  let mut listeners = Vec::with_capacity(options.workers);
  let first = bind_tcp_listener(bind, options, purpose, 0)?;
  let assigned = first
    .local_addr()
    .with_context(|| format!("failed to read {purpose} listener address"))?;
  listeners.push(first);

  if options.workers == 1 {
    return Ok(listeners);
  }

  let worker_bind = SocketAddr::new(bind.ip(), assigned.port());
  for worker_index in 1..options.workers {
    listeners.push(bind_tcp_listener(
      worker_bind,
      options,
      purpose,
      worker_index,
    )?);
  }
  Ok(listeners)
}

fn bind_tcp_listener(
  bind: SocketAddr,
  options: TcpListenOptions,
  purpose: &str,
  worker_index: usize,
) -> anyhow::Result<TcpListener> {
  let socket = match bind {
    SocketAddr::V4(_) => TcpSocket::new_v4(),
    SocketAddr::V6(_) => TcpSocket::new_v6(),
  }
  .with_context(|| format!("failed to create {purpose} TCP socket"))?;
  socket
    .set_reuseaddr(true)
    .with_context(|| format!("failed to set {purpose} TCP SO_REUSEADDR"))?;
  if options.reuse_port {
    socket
      .set_reuseport(true)
      .with_context(|| format!("failed to set {purpose} TCP SO_REUSEPORT"))?;
  }
  socket.bind(bind).with_context(|| {
    format!("failed to bind {purpose} listener worker {worker_index} to {bind}")
  })?;
  socket.listen(options.backlog).with_context(|| {
    format!(
      "failed to listen on {purpose} listener worker {worker_index} with backlog {}",
      options.backlog
    )
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn reuse_port_workers_can_bind_same_loopback_port() {
    let options = TcpListenOptions {
      workers: 2,
      reuse_port: true,
      backlog: 16,
    };
    let listeners = bind_tcp_listeners(
      "127.0.0.1:0"
        .parse()
        .expect("loopback address should parse"),
      options,
      "test",
    )
    .expect("SO_REUSEPORT listeners should bind");

    assert_eq!(listeners.len(), 2);
    let first = listeners[0].local_addr().expect("first addr");
    let second = listeners[1].local_addr().expect("second addr");
    assert_eq!(first.ip(), second.ip());
    assert_ne!(first.port(), 0);
    assert_eq!(first.port(), second.port());
  }
}
