//! Listener ownership, prepare/commit lifecycle, quiesce, drain, and shutdown.

use super::*;

pub(crate) struct ListenerSupervisor {
  pub(super) tcp: BTreeMap<SocketAddr, TcpListenerTask>,
  pub(super) http: BTreeMap<SocketAddr, TcpListenerTask>,
  pub(super) http3: BTreeMap<SocketAddr, Http3ListenerTask>,
  #[cfg(feature = "admin-runtime")]
  pub(super) admin: Option<AdminListenerTask>,
  #[cfg(feature = "admin-runtime")]
  pub(super) admin_h3: Option<admin_h3::AdminHttp3ListenerTask>,
  pub(super) streams: BTreeMap<String, StreamListenerTask>,
  pub(super) turns: Vec<TurnListenerTask>,
  pub(super) error_tx: mpsc::UnboundedSender<anyhow::Error>,
  #[cfg(feature = "admin-runtime")]
  pub(super) admin_control: AdminControlHandle,
  #[cfg(feature = "admin-runtime")]
  pub(super) admin_operations: AdminOperationRuntime,
  pub(super) quiescing: bool,
}

pub(super) struct TcpListenerTask {
  pub(super) options: TcpListenOptions,
  pub(super) bound_addresses: Vec<SocketAddr>,
  pub(super) quiesce: watch::Sender<bool>,
  pub(super) shutdown: watch::Sender<bool>,
  pub(super) connections: TaskRegistry,
  pub(super) drain_timeouts: DrainTimeouts,
  pub(super) tasks: Vec<JoinHandle<()>>,
}

pub(super) struct BoundTcpListener {
  pub(super) bind: SocketAddr,
  pub(super) options: TcpListenOptions,
  pub(super) accept_error_backoff: Duration,
  pub(super) kind: TcpListenerKind,
  pub(super) listeners: Vec<TcpListener>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum TcpListenerKind {
  Https,
  PlainHttp,
}

pub(super) struct Http3ListenerTask {
  pub(super) bind: SocketAddr,
  pub(super) bound_addresses: Vec<SocketAddr>,
  pub(super) socket: crate::config::QuicSocketConfig,
  pub(super) transport: crate::config::QuicTransportConfig,
  pub(super) endpoints: Vec<h3_quinn::quinn::Endpoint>,
  pub(super) quiesce: watch::Sender<bool>,
  pub(super) shutdown: watch::Sender<bool>,
  pub(super) connections: TaskRegistry,
  pub(super) drain_timeouts: DrainTimeouts,
  pub(super) tasks: Vec<JoinHandle<()>>,
}

pub(super) struct BoundHttp3Listener {
  pub(super) bind: SocketAddr,
  pub(super) socket: crate::config::QuicSocketConfig,
  pub(super) transport: crate::config::QuicTransportConfig,
  pub(super) endpoints: Vec<h3_quinn::quinn::Endpoint>,
  pub(super) sni_forward_quic: Vec<crate::sni_forward::quic::BoundQuicForwardSocket>,
}

#[cfg(feature = "admin-runtime")]
pub(super) struct AdminListenerTask {
  pub(super) bind: SocketAddr,
  pub(super) bound_address: SocketAddr,
  pub(super) shutdown: watch::Sender<bool>,
  pub(super) drain_timeouts: DrainTimeouts,
  pub(super) task: JoinHandle<()>,
}

#[cfg(feature = "admin-runtime")]
pub(super) struct BoundAdminListener {
  pub(super) bind: SocketAddr,
  pub(super) listener: TcpListener,
}

pub(crate) struct PendingListenerUpdate {
  tcp: Option<listener_sets::PendingTcpListenerSetUpdate>,
  http: Option<listener_sets::PendingTcpListenerSetUpdate>,
  http3: Option<listener_sets::PendingHttp3ListenerSetUpdate>,
  #[cfg(feature = "admin-runtime")]
  admin: Option<Option<BoundAdminListener>>,
  #[cfg(feature = "admin-runtime")]
  admin_h3: Option<Option<admin_h3::BoundAdminHttp3Listener>>,
  streams: Option<listener_sets::PendingStreamListenerSetUpdate>,
  turns: Option<PendingTurnListenerUpdate>,
  refresh_http3_config: bool,
  #[cfg(feature = "admin-runtime")]
  refresh_admin_h3_config: bool,
}

struct PendingTurnListenerUpdate {
  replacements: Vec<BoundTurnListener>,
  removed_names: Vec<String>,
  tls_refreshes: Vec<(String, crate::tls::TurnTlsServerConfig)>,
}

#[cfg(test)]
impl PendingListenerUpdate {
  pub(super) fn has_stream_update(&self) -> bool {
    self.streams.is_some()
  }
}

#[derive(Clone, Copy)]
pub(super) struct DrainTimeouts {
  pub(super) graceful: Duration,
  pub(super) long_connection_close_delay: Duration,
}

impl DrainTimeouts {
  pub(super) fn from_snapshot(snapshot: &AppSnapshot) -> Self {
    Self {
      graceful: Duration::from_millis(snapshot.config.runtime.drain.graceful_timeout_ms),
      long_connection_close_delay: Duration::from_millis(
        snapshot.config.runtime.drain.long_connection_close_delay_ms,
      ),
    }
  }
}

impl ListenerSupervisor {
  #[cfg(test)]
  pub(super) async fn shutdown(&mut self, snapshot: &AppSnapshot) {
    let deadline = tokio::time::Instant::now() + DrainTimeouts::from_snapshot(snapshot).graceful;
    let _ = self.shutdown_until(deadline).await;
  }

  #[cfg(feature = "admin-runtime")]
  pub(super) async fn start(
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
    admin_control: AdminControlHandle,
    admin_operations: AdminOperationRuntime,
  ) -> anyhow::Result<Self> {
    let snapshot = state.snapshot();
    let mut supervisor = Self {
      tcp: BTreeMap::new(),
      http: BTreeMap::new(),
      http3: BTreeMap::new(),
      #[cfg(feature = "admin-runtime")]
      admin: None,
      #[cfg(feature = "admin-runtime")]
      admin_h3: None,
      streams: BTreeMap::new(),
      turns: Vec::new(),
      error_tx,
      #[cfg(feature = "admin-runtime")]
      admin_control,
      #[cfg(feature = "admin-runtime")]
      admin_operations,
      quiescing: false,
    };
    let pending = supervisor.prepare(&snapshot).await?;
    supervisor.commit(pending, &snapshot, state);
    Ok(supervisor)
  }

  #[cfg(not(feature = "admin-runtime"))]
  pub(super) async fn start(
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> anyhow::Result<Self> {
    let snapshot = state.snapshot();
    let mut supervisor = Self {
      tcp: BTreeMap::new(),
      http: BTreeMap::new(),
      http3: BTreeMap::new(),
      streams: BTreeMap::new(),
      turns: Vec::new(),
      error_tx,
      quiescing: false,
    };
    let pending = supervisor.prepare(&snapshot).await?;
    supervisor.commit(pending, &snapshot, state);
    Ok(supervisor)
  }

  pub(crate) async fn prepare(
    &self,
    snapshot: &AppSnapshot,
  ) -> anyhow::Result<PendingListenerUpdate> {
    if self.quiescing {
      bail!("data-plane listeners are quiescing");
    }
    let tcp_options = TcpListenOptions::from(&snapshot.config.runtime.accept);
    let desired_tcp = if snapshot.config.needs_https_listener() {
      snapshot.config.listeners.https_binds.clone()
    } else {
      Vec::new()
    };
    let tcp = listener_sets::prepare_tcp_listener_set_update(
      &self.tcp,
      desired_tcp,
      tcp_options,
      snapshot.config.runtime.accept.accept_error_backoff_ms,
      TcpListenerKind::Https,
    )?;

    let desired_http =
      if snapshot.config.listeners.http_mode != crate::config::HttpListenerMode::Off {
        snapshot.config.listeners.http_binds.clone()
      } else {
        Vec::new()
      };
    let http = listener_sets::prepare_tcp_listener_set_update(
      &self.http,
      desired_http,
      tcp_options,
      snapshot.config.runtime.accept.accept_error_backoff_ms,
      TcpListenerKind::PlainHttp,
    )?;

    let desired_http3 = if snapshot.config.listeners.http3 {
      snapshot.config.listeners.https_binds.clone()
    } else {
      Vec::new()
    };
    let (http3, refresh_http3_config) =
      listener_sets::prepare_http3_listener_set_update(&self.http3, desired_http3, snapshot)?;

    #[cfg(feature = "admin-runtime")]
    let admin = if snapshot.config.admin.enabled {
      let bind = snapshot.config.admin.bind;
      if self.admin.as_ref().map(|task| task.bind) == Some(bind) {
        None
      } else {
        Some(Some(bind_admin_listener(bind).await?))
      }
    } else if self.admin.is_some() {
      Some(None)
    } else {
      None
    };

    #[cfg(feature = "admin-runtime")]
    let (admin_h3, refresh_admin_h3_config) =
      if snapshot.config.admin.enabled && snapshot.config.admin.http3.enabled {
        let bind = admin_h3::configured_bind(snapshot);
        if self.admin_h3.as_ref().is_some_and(|task| {
          task.matches(
            bind,
            &snapshot.config.quic.socket,
            &snapshot.config.quic.downstream.transport,
          )
        }) {
          (None, true)
        } else {
          (
            Some(Some(admin_h3::BoundAdminHttp3Listener::bind(
              bind, snapshot,
            )?)),
            false,
          )
        }
      } else if self.admin_h3.is_some() {
        (Some(None), false)
      } else {
        (None, false)
      };

    let desired_streams = snapshot
      .config
      .stream_listeners
      .iter()
      .map(|listener| {
        StreamListenerGeneration::new(
          listener.clone(),
          tcp_options,
          snapshot.config.shared_state.clone(),
          snapshot.shared_state.clone(),
        )
      })
      .collect::<anyhow::Result<Vec<_>>>()?;
    let streams = listener_sets::prepare_stream_listener_set_update(
      &self.streams,
      desired_streams,
      snapshot.config.runtime.accept.accept_error_backoff_ms,
    )?;

    let mut replacements = Vec::new();
    let mut tls_refreshes = Vec::new();
    for listener in &snapshot.config.webrtc_turn_listeners {
      let desired_key = crate::turn::TurnListenerKey::new(listener, tcp_options);
      let current = self
        .turns
        .iter()
        .find(|task| task.listener_key().name() == desired_key.name());
      match current {
        Some(task) if task.listener_key() == &desired_key => {
          if listener.tls_binds().next().is_some() {
            tls_refreshes.push((
              listener.name.clone(),
              crate::tls::build_turn_tls_server_config_with_resumption(
                &snapshot.config.crypto,
                &listener.tls,
                &snapshot.config.tls,
                Some(&snapshot.tls_resumption),
              )?,
            ));
          }
        }
        Some(task) => {
          if desired_key.socket_overlaps(task.listener_key()) {
            bail!(
              "full hot reload cannot safely replace WebRTC TURN listener {} while its TCP/UDP bind is unchanged or overlaps the active listener; use a process restart or rollout",
              listener.name
            );
          }
          if let Some(other) = self.turns.iter().find(|other| {
            other.listener_key().name() != desired_key.name()
              && desired_key.socket_overlaps(other.listener_key())
          }) {
            bail!(
              "full hot reload cannot replace WebRTC TURN listener {} because its new bind overlaps active listener {}; use a process restart or rollout",
              listener.name,
              other.listener_key().name(),
            );
          }
          replacements.push(BoundTurnListener::bind(
            listener.clone(),
            tcp_options,
            Duration::from_millis(snapshot.config.runtime.accept.accept_error_backoff_ms),
            &snapshot.config.crypto,
            &snapshot.config.tls,
            &snapshot.tls_resumption,
          )?);
        }
        None => {
          if let Some(other) = self
            .turns
            .iter()
            .find(|other| desired_key.socket_overlaps(other.listener_key()))
          {
            bail!(
              "full hot reload cannot add WebRTC TURN listener {} because its bind overlaps active listener {}; use a process restart or rollout",
              listener.name,
              other.listener_key().name(),
            );
          }
          replacements.push(BoundTurnListener::bind(
            listener.clone(),
            tcp_options,
            Duration::from_millis(snapshot.config.runtime.accept.accept_error_backoff_ms),
            &snapshot.config.crypto,
            &snapshot.config.tls,
            &snapshot.tls_resumption,
          )?);
        }
      }
    }
    let removed_names = self
      .turns
      .iter()
      .filter_map(|task| {
        let name = task.listener_key().name();
        (!snapshot
          .config
          .webrtc_turn_listeners
          .iter()
          .any(|listener| listener.name == name))
        .then(|| name.to_owned())
      })
      .collect::<Vec<_>>();
    let turns =
      (!replacements.is_empty() || !removed_names.is_empty() || !tls_refreshes.is_empty())
        .then_some(PendingTurnListenerUpdate {
          replacements,
          removed_names,
          tls_refreshes,
        });

    Ok(PendingListenerUpdate {
      tcp,
      http,
      http3,
      #[cfg(feature = "admin-runtime")]
      admin,
      #[cfg(feature = "admin-runtime")]
      admin_h3,
      streams,
      turns,
      refresh_http3_config,
      #[cfg(feature = "admin-runtime")]
      refresh_admin_h3_config,
    })
  }

  pub(crate) fn commit(
    &mut self,
    pending: PendingListenerUpdate,
    snapshot: &AppSnapshot,
    state: AppHandle,
  ) {
    let drain_timeouts = DrainTimeouts::from_snapshot(snapshot);
    if let Some(tcp) = pending.tcp {
      listener_sets::commit_tcp_listener_set_update(
        &mut self.tcp,
        tcp,
        state.clone(),
        self.error_tx.clone(),
        drain_timeouts,
      );
    }
    if let Some(http) = pending.http {
      listener_sets::commit_tcp_listener_set_update(
        &mut self.http,
        http,
        state.clone(),
        self.error_tx.clone(),
        drain_timeouts,
      );
    }
    match pending.http3 {
      Some(http3) => {
        listener_sets::commit_http3_listener_set_update(
          &mut self.http3,
          http3,
          snapshot,
          state.clone(),
          self.error_tx.clone(),
          drain_timeouts,
        );
      }
      None if pending.refresh_http3_config => {
        listener_sets::refresh_http3_server_config(&self.http3, snapshot);
      }
      None => {}
    }
    #[cfg(feature = "admin-runtime")]
    match pending.admin {
      Some(Some(admin)) => {
        let admin = admin.start(
          state.clone(),
          self.error_tx.clone(),
          self.admin_control.clone(),
          self.admin_operations.clone(),
          drain_timeouts,
        );
        if let Some(old) = self.admin.replace(admin) {
          old.drain_background();
        }
      }
      Some(None) => {
        if let Some(old) = self.admin.take() {
          old.drain_background();
        }
      }
      None => {}
    }
    #[cfg(feature = "admin-runtime")]
    match pending.admin_h3 {
      Some(Some(admin_h3)) => {
        let admin_h3 = admin_h3.start(
          state.clone(),
          self.error_tx.clone(),
          self.admin_operations.clone(),
          drain_timeouts.graceful,
        );
        if let Some(old) = self.admin_h3.replace(admin_h3) {
          old.drain_background();
        }
      }
      Some(None) => {
        if let Some(old) = self.admin_h3.take() {
          old.drain_background();
        }
      }
      None if pending.refresh_admin_h3_config => {
        if let (Some(task), Some(config)) = (&self.admin_h3, &snapshot.admin_quic_server_config) {
          task.refresh_server_config(config.clone());
        }
      }
      None => {}
    }
    if let Some(streams) = pending.streams {
      listener_sets::commit_stream_listener_set_update(
        &mut self.streams,
        streams,
        state.clone(),
        self.error_tx.clone(),
      );
    }
    if let Some(turns) = pending.turns {
      let mut old = std::mem::take(&mut self.turns);
      let mut next = Vec::with_capacity(
        old.len()
          + turns
            .replacements
            .len()
            .saturating_sub(turns.removed_names.len()),
      );
      for replacement in turns.replacements {
        let replacement_name = replacement.key().name().to_owned();
        if let Some(index) = old
          .iter()
          .position(|task| task.listener_key().name() == replacement_name)
        {
          old.remove(index).drain_background();
        }
        next.push(replacement.start(state.clone(), self.error_tx.clone()));
      }
      for task in old {
        if turns
          .removed_names
          .iter()
          .any(|name| name == task.listener_key().name())
        {
          task.drain_background();
        } else {
          next.push(task);
        }
      }
      for (name, config) in turns.tls_refreshes {
        if let Some(task) = next.iter().find(|task| task.listener_key().name() == name) {
          task.refresh_tls_config(config);
        }
      }
      self.turns = next;
    }
  }

  pub(super) async fn shutdown_until(&mut self, deadline: tokio::time::Instant) -> bool {
    self.quiesce();
    let mut tasks = Vec::new();
    for task in std::mem::take(&mut self.tcp).into_values() {
      tasks.push(task.drain_until(deadline));
    }
    for task in std::mem::take(&mut self.http).into_values() {
      tasks.push(task.drain_until(deadline));
    }
    for task in std::mem::take(&mut self.http3).into_values() {
      tasks.push(task.drain_until(deadline));
    }
    #[cfg(feature = "admin-runtime")]
    if let Some(task) = self.admin.take() {
      tasks.push(task.drain_until(deadline));
    }
    #[cfg(feature = "admin-runtime")]
    if let Some(task) = self.admin_h3.take() {
      tasks.push(task.drain_until(deadline));
    }
    for task in std::mem::take(&mut self.streams).into_values() {
      tasks.push(task.drain_until(deadline));
    }
    for task in std::mem::take(&mut self.turns) {
      tasks.push(task.drain_until(deadline));
    }
    if tasks.is_empty() {
      return false;
    }
    futures_util::future::join_all(tasks)
      .await
      .into_iter()
      .any(|result| !matches!(result, Ok(false)))
  }

  pub(super) fn quiesce(&mut self) {
    self.quiescing = true;
    for task in self.tcp.values() {
      task.quiesce();
    }
    for task in self.http.values() {
      task.quiesce();
    }
    for task in self.http3.values() {
      task.quiesce();
    }
    for task in self.streams.values() {
      task.quiesce();
    }
    for task in &self.turns {
      task.quiesce();
    }
  }

  pub(crate) fn bound_listeners(&self) -> Vec<BoundListener> {
    let mut listeners = Vec::new();
    for task in self.tcp.values() {
      listeners.extend(
        task
          .bound_addresses
          .iter()
          .copied()
          .map(|address| BoundListener {
            kind: BoundListenerKind::Https,
            transport: BoundListenerTransport::Tcp,
            address,
          }),
      );
    }
    for task in self.http.values() {
      listeners.extend(
        task
          .bound_addresses
          .iter()
          .copied()
          .map(|address| BoundListener {
            kind: BoundListenerKind::Http,
            transport: BoundListenerTransport::Tcp,
            address,
          }),
      );
    }
    for task in self.http3.values() {
      listeners.extend(
        task
          .bound_addresses
          .iter()
          .copied()
          .map(|address| BoundListener {
            kind: BoundListenerKind::Http3,
            transport: BoundListenerTransport::Quic,
            address,
          }),
      );
    }
    #[cfg(feature = "admin-runtime")]
    if let Some(task) = &self.admin {
      listeners.push(BoundListener {
        kind: BoundListenerKind::Admin,
        transport: BoundListenerTransport::Tcp,
        address: task.bound_address,
      });
    }
    #[cfg(feature = "admin-runtime")]
    if let Some(task) = &self.admin_h3 {
      listeners.extend(task.bound_addresses().map(|address| BoundListener {
        kind: BoundListenerKind::AdminHttp3,
        transport: BoundListenerTransport::Quic,
        address,
      }));
    }
    for task in self.streams.values() {
      listeners.extend(task.bound_listeners());
    }
    for task in &self.turns {
      listeners.extend(task.bound_listeners());
    }
    listeners
  }
}

impl Drop for ListenerSupervisor {
  fn drop(&mut self) {
    for task in std::mem::take(&mut self.tcp).into_values() {
      task.drain_background();
    }
    for task in std::mem::take(&mut self.http).into_values() {
      task.drain_background();
    }
    for task in std::mem::take(&mut self.http3).into_values() {
      task.drain_background();
    }
    #[cfg(feature = "admin-runtime")]
    if let Some(task) = self.admin.take() {
      task.drain_background();
    }
    #[cfg(feature = "admin-runtime")]
    if let Some(task) = self.admin_h3.take() {
      task.drain_background();
    }
    for task in std::mem::take(&mut self.streams).into_values() {
      task.drain_background();
    }
    for task in std::mem::take(&mut self.turns) {
      task.drain_background();
    }
  }
}
