//! Bound TCP, HTTP/3, and Admin listener task construction.

use super::*;

impl TcpListenerTask {
  pub(super) fn quiesce(&self) {
    let _ = self.quiesce.send(true);
  }

  pub(super) fn drain_background(self) {
    drop(self.drain());
  }

  pub(super) fn drain(self) -> JoinHandle<bool> {
    let deadline = tokio::time::Instant::now() + self.drain_timeouts.graceful;
    self.drain_until(deadline)
  }

  pub(super) fn drain_until(self, deadline: tokio::time::Instant) -> JoinHandle<bool> {
    tokio::spawn(async move {
      let TcpListenerTask {
        quiesce,
        shutdown,
        connections,
        mut tasks,
        ..
      } = self;
      let _ = quiesce.send(true);
      let _ = shutdown.send(true);
      let wait_connections = connections.clone();
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
        connections.abort_all();
        for task in tasks {
          let _ = task.await;
        }
        connections.wait_idle().await;
        return true;
      }
      false
    })
  }
}

impl BoundTcpListener {
  pub(super) fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
    drain_timeouts: DrainTimeouts,
  ) -> TcpListenerTask {
    let mut bound_addresses = self
      .listeners
      .iter()
      .filter_map(|listener| match listener.local_addr() {
        Ok(address) => Some(address),
        Err(error) => {
          warn!(%error, configured_bind = %self.bind, "failed to inspect bound TCP listener address");
          None
        }
      })
      .collect::<Vec<_>>();
    if bound_addresses.is_empty() {
      bound_addresses.push(self.bind);
    }
    let (quiesce, quiesce_rx) = watch::channel(false);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let options = self.options;
    let kind = self.kind;
    let accept_error_backoff = self.accept_error_backoff;
    let connections = TaskRegistry::new(
      RuntimeTaskKind::HttpConnection,
      state.snapshot().runtime_health.clone(),
    );
    let tasks = self
      .listeners
      .into_iter()
      .enumerate()
      .map(|(worker_index, listener)| {
        let worker_shutdown = shutdown_rx.clone();
        let worker_quiesce = quiesce_rx.clone();
        let worker_state = state.clone();
        let worker_error_tx = error_tx.clone();
        let worker_connections = connections.clone();
        tokio::spawn(async move {
          if let Err(error) = serve_tcp(
            listener,
            kind,
            worker_state,
            worker_quiesce,
            worker_shutdown,
            worker_index,
            accept_error_backoff,
            worker_connections,
            drain_timeouts.long_connection_close_delay,
          )
          .await
          {
            let _ = worker_error_tx.send(error.context("downstream TCP HTTP listener failed"));
          }
        })
      })
      .collect();
    TcpListenerTask {
      options,
      bound_addresses,
      quiesce,
      shutdown,
      connections,
      drain_timeouts,
      tasks,
    }
  }
}

impl Http3ListenerTask {
  pub(super) fn quiesce(&self) {
    let _ = self.quiesce.send(true);
  }

  pub(super) fn drain_background(self) {
    drop(self.drain());
  }

  pub(super) fn drain(self) -> JoinHandle<bool> {
    let deadline = tokio::time::Instant::now() + self.drain_timeouts.graceful;
    self.drain_until(deadline)
  }

  pub(super) fn drain_until(self, deadline: tokio::time::Instant) -> JoinHandle<bool> {
    tokio::spawn(async move {
      let Http3ListenerTask {
        endpoints,
        quiesce,
        shutdown,
        connections,
        mut tasks,
        ..
      } = self;
      let _ = quiesce.send(true);
      let _ = shutdown.send(true);
      let wait_endpoints = endpoints.clone();
      let wait_connections = connections.clone();
      let wait = async {
        for task in &mut tasks {
          let _ = task.await;
        }
        wait_connections.wait_idle().await;
        for endpoint in wait_endpoints {
          endpoint.wait_idle().await;
        }
      };
      if tokio::time::timeout_at(deadline, wait).await.is_err() {
        for endpoint in endpoints {
          endpoint.close(0u32.into(), b"listener drain timeout");
        }
        for task in &tasks {
          task.abort();
        }
        connections.abort_all();
        for task in tasks {
          let _ = task.await;
        }
        connections.wait_idle().await;
        return true;
      }
      false
    })
  }
}

impl BoundHttp3Listener {
  pub(super) fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
    drain_timeouts: DrainTimeouts,
  ) -> Http3ListenerTask {
    let mut bound_addresses = self
      .endpoints
      .iter()
      .filter_map(|endpoint| match endpoint.local_addr() {
        Ok(address) => Some(address),
        Err(error) => {
          warn!(%error, configured_bind = %self.bind, "failed to inspect bound HTTP/3 listener address");
          None
        }
      })
      .collect::<Vec<_>>();
    if bound_addresses.is_empty() {
      bound_addresses.push(self.bind);
    }
    let (quiesce, quiesce_rx) = watch::channel(false);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let socket = self.socket;
    let transport = self.transport;
    let connections = TaskRegistry::new(
      RuntimeTaskKind::HttpConnection,
      state.snapshot().runtime_health.clone(),
    );
    let mut tasks = crate::sni_forward::quic::spawn_demux_tasks(
      self.sni_forward_quic,
      quiesce_rx.clone(),
      shutdown_rx.clone(),
      state.clone(),
      error_tx.clone(),
    );
    tasks.extend(
      self
        .endpoints
        .iter()
        .cloned()
        .enumerate()
        .map(|(worker_index, endpoint)| {
          let worker_shutdown = shutdown_rx.clone();
          let worker_quiesce = quiesce_rx.clone();
          let worker_state = state.clone();
          let worker_error_tx = error_tx.clone();
          let worker_connections = connections.clone();
          tokio::spawn(async move {
            if let Err(error) = serve_http3(
              endpoint,
              worker_state,
              worker_quiesce,
              worker_shutdown,
              worker_index,
              worker_connections,
              drain_timeouts.long_connection_close_delay,
            )
            .await
            {
              let _ = worker_error_tx.send(error.context("downstream HTTP/3 listener failed"));
            }
          })
        }),
    );
    Http3ListenerTask {
      bind,
      bound_addresses,
      socket,
      transport,
      endpoints: self.endpoints,
      quiesce,
      shutdown,
      connections,
      drain_timeouts,
      tasks,
    }
  }
}

#[cfg(feature = "admin-runtime")]
impl AdminListenerTask {
  pub(super) fn drain_background(self) {
    drop(self.drain());
  }

  pub(super) fn drain(self) -> JoinHandle<bool> {
    let deadline = tokio::time::Instant::now() + self.drain_timeouts.graceful;
    self.drain_until(deadline)
  }

  pub(super) fn drain_until(self, deadline: tokio::time::Instant) -> JoinHandle<bool> {
    tokio::spawn(async move {
      let AdminListenerTask {
        shutdown, mut task, ..
      } = self;
      let _ = shutdown.send(true);
      tokio::select! {
        _ = &mut task => false,
        _ = tokio::time::sleep_until(deadline) => {
          task.abort();
          let _ = task.await;
          true
        }
      }
    })
  }
}

#[cfg(feature = "admin-runtime")]
impl BoundAdminListener {
  pub(super) fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
    admin_control: AdminControlHandle,
    admin_operations: AdminOperationRuntime,
    drain_timeouts: DrainTimeouts,
  ) -> AdminListenerTask {
    let bound_address = match self.listener.local_addr() {
      Ok(address) => address,
      Err(error) => {
        warn!(%error, configured_bind = %self.bind, "failed to inspect bound Admin listener address");
        self.bind
      }
    };
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let task = tokio::spawn(async move {
      if let Err(error) = serve_admin_listener(
        self.listener,
        bind,
        state,
        admin_control,
        admin_operations,
        shutdown_rx,
      )
      .await
      {
        let _ = error_tx.send(error.context("admin listener failed"));
      }
    });
    AdminListenerTask {
      bind,
      bound_address,
      shutdown,
      drain_timeouts,
      task,
    }
  }
}

pub(super) fn bind_tcp_listener(
  bind: SocketAddr,
  options: TcpListenOptions,
  accept_error_backoff_ms: u64,
  kind: TcpListenerKind,
) -> anyhow::Result<BoundTcpListener> {
  let listeners = bind_tcp_listeners(bind, options, kind.bind_purpose())
    .with_context(|| format!("failed to bind downstream listener to {bind}"))?;
  Ok(BoundTcpListener {
    bind,
    options,
    accept_error_backoff: Duration::from_millis(accept_error_backoff_ms),
    kind,
    listeners,
  })
}

impl TcpListenerKind {
  pub(super) fn bind_purpose(self) -> &'static str {
    match self {
      Self::Https => "downstream HTTPS",
      Self::PlainHttp => "downstream plain HTTP",
    }
  }
}

#[cfg(feature = "admin-runtime")]
pub(super) async fn bind_admin_listener(bind: SocketAddr) -> anyhow::Result<BoundAdminListener> {
  let listener = TcpListener::bind(bind)
    .await
    .with_context(|| format!("failed to bind admin listener to {bind}"))?;
  Ok(BoundAdminListener { bind, listener })
}

#[cfg(all(test, feature = "admin-runtime"))]
pub(super) fn test_admin_control() -> AdminControlHandle {
  AdminControlHandle::new(None, None)
    .expect("test Admin control should initialize")
    .0
}

#[cfg(all(test, feature = "admin-runtime"))]
pub(super) fn test_admin_operations() -> AdminOperationRuntime {
  AdminOperationRuntime::new(crate::config::AdminOperationsConfig::default())
}
