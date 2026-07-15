//! Listener set comparison helpers for reload preparation.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use tokio::sync::mpsc;
use tracing::info;

use crate::listener_socket::TcpListenOptions;
use crate::state::{AppHandle, AppSnapshot};

use super::{
  BoundHttp3Listener, BoundTcpListener, DrainTimeouts, Http3ListenerTask, TcpListenerKind,
  TcpListenerTask, bind_http3_listener, bind_tcp_listener,
};

pub(super) struct PendingTcpListenerSetUpdate {
  desired: Vec<SocketAddr>,
  options: TcpListenOptions,
  bound: Vec<BoundTcpListener>,
}

pub(super) struct PendingHttp3ListenerSetUpdate {
  desired: Vec<SocketAddr>,
  socket: crate::config::QuicSocketConfig,
  transport: crate::config::QuicTransportConfig,
  bound: Vec<BoundHttp3Listener>,
}

pub(super) fn tcp_listener_set_matches(
  current: &BTreeMap<SocketAddr, TcpListenerTask>,
  desired: &[SocketAddr],
  options: TcpListenOptions,
) -> bool {
  current.len() == desired.len()
    && desired.iter().all(|bind| {
      current
        .get(bind)
        .is_some_and(|task| task.options == options)
    })
}

pub(super) fn http3_listener_set_matches(
  current: &BTreeMap<SocketAddr, Http3ListenerTask>,
  desired: &[SocketAddr],
  socket: &crate::config::QuicSocketConfig,
  transport: &crate::config::QuicTransportConfig,
) -> bool {
  current.len() == desired.len()
    && desired.iter().all(|bind| {
      current
        .get(bind)
        .is_some_and(|task| task.socket == *socket && task.transport == *transport)
    })
}

pub(super) fn prepare_tcp_listener_set_update(
  current: &BTreeMap<SocketAddr, TcpListenerTask>,
  desired: Vec<SocketAddr>,
  options: TcpListenOptions,
  accept_error_backoff_ms: u64,
  kind: TcpListenerKind,
) -> anyhow::Result<Option<PendingTcpListenerSetUpdate>> {
  if tcp_listener_set_matches(current, &desired, options) {
    return Ok(None);
  }

  let mut bound = Vec::new();
  for bind in &desired {
    if current
      .get(bind)
      .is_some_and(|task| task.options == options)
    {
      continue;
    }
    bound.push(bind_tcp_listener(
      *bind,
      options,
      accept_error_backoff_ms,
      kind,
    )?);
  }
  Ok(Some(PendingTcpListenerSetUpdate {
    desired,
    options,
    bound,
  }))
}

pub(super) fn prepare_http3_listener_set_update(
  current: &BTreeMap<SocketAddr, Http3ListenerTask>,
  desired: Vec<SocketAddr>,
  snapshot: &AppSnapshot,
) -> anyhow::Result<(Option<PendingHttp3ListenerSetUpdate>, bool)> {
  if http3_listener_set_matches(
    current,
    &desired,
    &snapshot.config.quic.socket,
    &snapshot.config.quic.downstream.transport,
  ) {
    return Ok((None, !desired.is_empty()));
  }

  let mut bound = Vec::new();
  for bind in &desired {
    if current.get(bind).is_some_and(|task| {
      task.socket == snapshot.config.quic.socket
        && task.transport == snapshot.config.quic.downstream.transport
    }) {
      continue;
    }
    bound.push(bind_http3_listener(*bind, snapshot)?);
  }
  Ok((
    Some(PendingHttp3ListenerSetUpdate {
      desired,
      socket: snapshot.config.quic.socket.clone(),
      transport: snapshot.config.quic.downstream.transport.clone(),
      bound,
    }),
    false,
  ))
}

pub(super) fn commit_tcp_listener_set_update(
  current: &mut BTreeMap<SocketAddr, TcpListenerTask>,
  update: PendingTcpListenerSetUpdate,
  state: AppHandle,
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
  drain_timeouts: DrainTimeouts,
) {
  let mut old = std::mem::take(current);
  let mut bound = update
    .bound
    .into_iter()
    .map(|listener| (listener.bind, listener))
    .collect::<BTreeMap<_, _>>();
  let mut next = BTreeMap::new();

  for bind in update.desired {
    match old.remove(&bind) {
      Some(task) if task.options == update.options => {
        next.insert(bind, task);
      }
      Some(task) => {
        if let Some(listener) = bound.remove(&bind) {
          old.insert(bind, task);
          next.insert(
            bind,
            listener.start(state.clone(), error_tx.clone(), drain_timeouts),
          );
        } else {
          next.insert(bind, task);
        }
      }
      None => {
        if let Some(listener) = bound.remove(&bind) {
          next.insert(
            bind,
            listener.start(state.clone(), error_tx.clone(), drain_timeouts),
          );
        }
      }
    }
  }

  for old in old.into_values() {
    old.drain_background();
  }
  *current = next;
}

pub(super) fn commit_http3_listener_set_update(
  current: &mut BTreeMap<SocketAddr, Http3ListenerTask>,
  update: PendingHttp3ListenerSetUpdate,
  snapshot: &AppSnapshot,
  state: AppHandle,
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
  drain_timeouts: DrainTimeouts,
) {
  let mut old = std::mem::take(current);
  let mut bound = update
    .bound
    .into_iter()
    .map(|listener| (listener.bind, listener))
    .collect::<BTreeMap<_, _>>();
  let mut next = BTreeMap::new();

  for bind in update.desired {
    match old.remove(&bind) {
      Some(task) if task.socket == update.socket && task.transport == update.transport => {
        next.insert(bind, task);
      }
      Some(task) => {
        if let Some(listener) = bound.remove(&bind) {
          old.insert(bind, task);
          next.insert(
            bind,
            listener.start(state.clone(), error_tx.clone(), drain_timeouts),
          );
        } else {
          next.insert(bind, task);
        }
      }
      None => {
        if let Some(listener) = bound.remove(&bind) {
          next.insert(
            bind,
            listener.start(state.clone(), error_tx.clone(), drain_timeouts),
          );
        }
      }
    }
  }

  for old in old.into_values() {
    old.drain_background();
  }
  *current = next;
  refresh_http3_server_config(current, snapshot);
}

pub(super) fn refresh_http3_server_config(
  current: &BTreeMap<SocketAddr, Http3ListenerTask>,
  snapshot: &AppSnapshot,
) {
  if let Some(config) = &snapshot.quic_server_config {
    let configs = config.configs();
    if configs.is_empty() {
      tracing::error!("downstream QUIC config set is empty; retaining the current endpoint config");
      return;
    }
    for task in current.values() {
      for (index, endpoint) in task.endpoints.iter().enumerate() {
        if let Some(config) = configs.get(index % configs.len()) {
          endpoint.set_server_config(Some(config.clone()));
        }
      }
      info!(bind = %task.bind, "downstream HTTP/3 TLS config refreshed");
    }
  }
}
