//! TCP listener binding helpers.
//! Socket options are applied before binding so listeners have predictable kernel behavior.

use std::net::SocketAddr;

use anyhow::Context;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpListener;

use crate::config::RuntimeAcceptConfig;
use crate::netport_switcher::SwitcherTcpOptions;

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
  if let Some(listener) = crate::netport_switcher::bind_tcp_listener(
    bind,
    SwitcherTcpOptions {
      workers: options.workers,
      reuse_port: options.reuse_port,
      backlog: options.backlog,
    },
    purpose,
    worker_index,
  )? {
    return Ok(listener);
  }
  let socket = Socket::new(Domain::for_address(bind), Type::STREAM, Some(Protocol::TCP))
    .with_context(|| format!("failed to create {purpose} TCP socket"))?;
  socket
    .set_reuse_address(true)
    .with_context(|| format!("failed to set {purpose} TCP SO_REUSEADDR"))?;
  if bind.is_ipv6() {
    socket
      .set_only_v6(true)
      .with_context(|| format!("failed to set {purpose} TCP IPV6_V6ONLY"))?;
  }
  if options.reuse_port {
    socket
      .set_reuse_port(true)
      .with_context(|| format!("failed to set {purpose} TCP SO_REUSEPORT"))?;
  }
  socket.bind(&SockAddr::from(bind)).with_context(|| {
    format!("failed to bind {purpose} listener worker {worker_index} to {bind}")
  })?;
  socket.listen(options.backlog as i32).with_context(|| {
    format!(
      "failed to listen on {purpose} listener worker {worker_index} with backlog {}",
      options.backlog
    )
  })?;
  let listener: std::net::TcpListener = socket.into();
  listener
    .set_nonblocking(true)
    .with_context(|| format!("failed to set {purpose} TCP listener nonblocking"))?;
  TcpListener::from_std(listener)
    .with_context(|| format!("failed to register {purpose} TCP listener"))
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

  #[tokio::test]
  async fn ipv6_listener_sets_v6_only() {
    let options = TcpListenOptions {
      workers: 1,
      reuse_port: false,
      backlog: 16,
    };
    let listeners = bind_tcp_listeners(
      "[::1]:0".parse().expect("loopback address should parse"),
      options,
      "test",
    )
    .expect("IPv6 listener should bind");
    let socket = socket2::SockRef::from(&listeners[0]);

    assert!(socket.only_v6().expect("IPV6_V6ONLY should be readable"));
  }
}
