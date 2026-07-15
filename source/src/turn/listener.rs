//! TURN listener tasks for UDP and TCP transports.
//! Listener admission is separated from relay forwarding so auth and limits run first.

use crate::config::{
  CryptoConfig, TurnAuthMode, UpstreamEchConfig, UpstreamTlsResumptionConfig,
  WebRtcTurnListenerConfig, WebRtcTurnListenerMode,
};
use crate::lifecycle::{ConnectionDrain, TaskRegistry};
use crate::listener_socket::{TcpListenOptions, bind_tcp_listeners};
use crate::runtime_health::RuntimeTaskKind;
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::{AppHandle, AppSnapshot};
use crate::tls;
use anyhow::{Context, bail};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tracing::{info, warn};
use url::Url;

mod udp_task;
use crate::tls::TlsResumptionState;

use super::auth::{self, AuthDecision};
use super::edge::EdgeState;
use super::pools::TurnPoolSelection;
use super::protocol::*;

pub struct TurnListenerTask {
  key: TurnListenerKey,
  quiesce: watch::Sender<bool>,
  shutdown: watch::Sender<bool>,
  connections: TaskRegistry,
  graceful_timeout: Duration,
  tasks: Vec<JoinHandle<()>>,
}

pub struct BoundTurnListener {
  config: WebRtcTurnListenerConfig,
  udp: Option<std::net::UdpSocket>,
  tcp: Vec<TcpListener>,
  tls: Vec<TcpListener>,
  tcp_options: TcpListenOptions,
  accept_error_backoff: Duration,
  tls_config: Option<tls::TurnTlsServerConfig>,
}

pub(super) trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub(super) type BoxedIo = Box<dyn AsyncIo>;

impl BoundTurnListener {
  pub(crate) fn bind(
    config: WebRtcTurnListenerConfig,
    tcp_options: TcpListenOptions,
    accept_error_backoff: Duration,
    crypto: &CryptoConfig,
    default_tls: &crate::config::TlsConfig,
    tls_resumption: &TlsResumptionState,
  ) -> anyhow::Result<Self> {
    let udp = config
      .bind_udp
      .map(bind_udp_socket)
      .transpose()
      .with_context(|| format!("failed to bind WebRTC TURN UDP listener {}", config.name))?;
    let tcp = match config.bind_tcp {
      Some(bind) => bind_tcp_listeners(bind, tcp_options, "TURN TCP").with_context(|| {
        format!(
          "failed to bind WebRTC TURN TCP listener {} to {bind}",
          config.name
        )
      })?,
      None => Vec::new(),
    };
    let tls_listeners = match config.bind_tls {
      Some(bind) => bind_tcp_listeners(bind, tcp_options, "TURN TLS").with_context(|| {
        format!(
          "failed to bind WebRTC TURN TLS listener {} to {bind}",
          config.name
        )
      })?,
      None => Vec::new(),
    };
    let tls_config = if config.bind_tls.is_some() {
      Some(tls::build_turn_tls_server_config_with_resumption(
        crypto,
        &config.tls,
        default_tls,
        Some(tls_resumption),
      )?)
    } else {
      None
    };
    Ok(Self {
      config,
      udp,
      tcp,
      tls: tls_listeners,
      tcp_options,
      accept_error_backoff,
      tls_config,
    })
  }

  pub(crate) fn key(&self) -> TurnListenerKey {
    TurnListenerKey {
      config: self.config.clone(),
      tcp_options: self.tcp_options,
    }
  }

  pub(crate) fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> TurnListenerTask {
    let snapshot = state.snapshot();
    let graceful_timeout = Duration::from_millis(snapshot.config.runtime.drain.graceful_timeout_ms);
    let long_connection_close_delay =
      Duration::from_millis(snapshot.config.runtime.drain.long_connection_close_delay_ms);
    let runtime_health = snapshot.runtime_health.clone();
    drop(snapshot);
    let (quiesce, quiesce_rx) = watch::channel(false);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let edge = EdgeState::default();
    let key = self.key();
    let connections = TaskRegistry::new(RuntimeTaskKind::TurnConnection, runtime_health);
    let mut tasks = Vec::new();
    if let Some(udp) = self.udp {
      udp_task::spawn(
        &mut tasks,
        udp,
        self.config.clone(),
        state.clone(),
        shutdown_rx.clone(),
        edge.clone(),
        error_tx.clone(),
      );
    }
    for (index, listener) in self.tcp.into_iter().enumerate() {
      spawn_tcp_acceptor(
        &mut tasks,
        listener,
        false,
        index,
        self.config.clone(),
        state.clone(),
        quiesce_rx.clone(),
        shutdown_rx.clone(),
        error_tx.clone(),
        connections.clone(),
        long_connection_close_delay,
        self.accept_error_backoff,
        None,
        edge.clone(),
      );
    }
    for (index, listener) in self.tls.into_iter().enumerate() {
      spawn_tcp_acceptor(
        &mut tasks,
        listener,
        true,
        index,
        self.config.clone(),
        state.clone(),
        quiesce_rx.clone(),
        shutdown_rx.clone(),
        error_tx.clone(),
        connections.clone(),
        long_connection_close_delay,
        self.accept_error_backoff,
        self.tls_config.clone(),
        edge.clone(),
      );
    }
    tasks.push(spawn_health_task(state, shutdown_rx.clone()));
    TurnListenerTask {
      key,
      quiesce,
      shutdown,
      connections,
      graceful_timeout,
      tasks,
    }
  }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TurnListenerKey {
  pub(crate) config: WebRtcTurnListenerConfig,
  pub(crate) tcp_options: TcpListenOptions,
}

impl TurnListenerTask {
  pub(crate) fn listener_key(&self) -> &TurnListenerKey {
    &self.key
  }

  pub(crate) fn quiesce(&self) {
    let _ = self.quiesce.send(true);
  }

  pub(crate) fn drain_background(self) {
    drop(self.drain());
  }

  pub(crate) fn drain(self) -> JoinHandle<()> {
    tokio::spawn(async move {
      let _ = self.quiesce.send(true);
      let _ = self.shutdown.send(true);
      let wait_connections = self.connections.clone();
      let wait = async {
        for task in self.tasks {
          let _ = task.await;
        }
        wait_connections.wait_idle().await;
      };
      if tokio::time::timeout(self.graceful_timeout, wait)
        .await
        .is_err()
      {
        self.connections.abort_all();
      }
    })
  }
}

#[allow(clippy::too_many_arguments)]
fn spawn_tcp_acceptor(
  tasks: &mut Vec<JoinHandle<()>>,
  listener: TcpListener,
  is_tls: bool,
  worker_index: usize,
  config: WebRtcTurnListenerConfig,
  state: AppHandle,
  mut quiesce: watch::Receiver<bool>,
  mut shutdown: watch::Receiver<bool>,
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
  connections: TaskRegistry,
  long_connection_close_delay: Duration,
  accept_error_backoff: Duration,
  tls_config: Option<tls::TurnTlsServerConfig>,
  edge: EdgeState,
) {
  tasks.push(tokio::spawn(async move {
    let result: anyhow::Result<()> = async {
      let bind = listener.local_addr().context("failed to read TURN bind")?;
      let transport = if is_tls { "tls" } else { "tcp" };
      info!(name = %config.name, bind = %bind, transport, worker = worker_index, "WebRTC TURN listener started");
      let mut next_stream_id = worker_index as u64;
      loop {
        tokio::select! {
          biased;
          changed = quiesce.changed() => {
            if changed.is_err() || *quiesce.borrow() {
              info!(name = %config.name, bind = %bind, transport, worker = worker_index, "WebRTC TURN listener quiesced");
              return Ok(());
            }
          }
          changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
              info!(name = %config.name, bind = %bind, transport, worker = worker_index, "WebRTC TURN listener stopped");
            }
            return Ok(());
          }
          accepted = listener.accept() => {
            let (stream, peer_addr) = match accepted {
              Ok(value) => value,
              Err(error) => {
                warn!(name = %config.name, error = %error, "failed to accept TURN connection");
                tokio::time::sleep(accept_error_backoff).await;
                continue;
              }
            };
            let snapshot = state.snapshot();
            let overload_connection = match snapshot.overload.try_admit_connection() {
              Ok(lease) => lease,
              Err(_) => continue,
            };
            let connection_drain = ConnectionDrain::new(
              shutdown.clone(),
              snapshot.lifecycle.subscribe(),
              long_connection_close_delay,
            );
            let counter = if is_tls {
              RuntimeCounter::TurnTlsConnection
            } else {
              RuntimeCounter::TurnTcpConnection
            };
            let introspection_guard = snapshot.runtime_introspection.guard(counter);
            let conn_config = config.clone();
            let conn_state = state.clone();
            let conn_edge = edge.clone();
            let conn_tls_config = tls_config.clone();
            let stream_pool = if is_tls {
              conn_config.tls_pool.clone()
            } else {
              conn_config.tcp_pool.clone()
            };
            next_stream_id = next_stream_id.wrapping_add(1024);
            let stream_id = next_stream_id;
            connections.spawn(async move {
              let _overload_connection = overload_connection;
              let _introspection_guard = introspection_guard;
              conn_state.snapshot().metrics.record_turn_event(
                &conn_config.name,
                if conn_tls_config.is_some() { "tls" } else { "tcp" },
                "connection_started",
              );
              let result = if let Some(tls_config) = conn_tls_config {
                let handshake_timeout = Duration::from_millis(conn_config.idle_timeout_ms);
                let accept = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
                match tokio::time::timeout(handshake_timeout, accept).await {
                  Ok(Ok(start)) => {
                    let server_config = tls_config.select(&start.client_hello());
                    match tokio::time::timeout(handshake_timeout, start.into_stream(server_config)).await {
                      Ok(Ok(tls_stream)) => serve_turn_stream(Box::new(tls_stream), peer_addr, stream_id, stream_pool, conn_config, conn_state, connection_drain, conn_edge).await,
                      Ok(Err(error)) => Err(anyhow::anyhow!(error).context("TURN TLS handshake failed")),
                      Err(_) => Err(anyhow::anyhow!("TURN TLS handshake timed out")),
                    }
                  },
                  Ok(Err(error)) => Err(anyhow::anyhow!(error).context("TURN TLS handshake failed")),
                  Err(_) => Err(anyhow::anyhow!("TURN TLS handshake timed out")),
                }
              } else {
                serve_turn_stream(Box::new(stream), peer_addr, stream_id, stream_pool, conn_config, conn_state, connection_drain, conn_edge).await
              };
              if let Err(error) = result {
                warn!(peer = %peer_addr, error = %error, "TURN connection failed");
              }
            });
          }
        }
      }
    }
    .await;
    if let Err(error) = result {
      let _ = error_tx.send(error.context("WebRTC TURN TCP/TLS listener failed"));
    }
  }));
}

async fn serve_turn_udp(
  socket: Arc<UdpSocket>,
  config: WebRtcTurnListenerConfig,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  edge: EdgeState,
) -> anyhow::Result<()> {
  let bind = socket.local_addr()?;
  info!(name = %config.name, bind = %bind, "WebRTC TURN UDP listener started");
  let mut sessions: HashMap<SocketAddr, UdpProxySession> = HashMap::new();
  let mut buffer = vec![0u8; 65_536];
  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          info!(name = %config.name, bind = %bind, "WebRTC TURN UDP listener stopped");
        }
        return Ok(());
      }
      received = socket.recv_from(&mut buffer) => {
        let (len, client_addr) = received.context("failed to receive TURN UDP datagram")?;
        let quiescing = state.snapshot().lifecycle.is_shutdown_draining();
        let known_client = match config.mode {
          WebRtcTurnListenerMode::ProxyPool => sessions.contains_key(&client_addr),
          WebRtcTurnListenerMode::EdgeRelay => edge.has_udp_client(client_addr).await,
        };
        if !udp_client_admitted(quiescing, known_client) {
          continue;
        }
        state.snapshot().metrics.record_turn_event(&config.name, "udp", "datagram_received");
        let packet = &buffer[..len];
        match config.mode {
          WebRtcTurnListenerMode::ProxyPool => {
            proxy_udp_packet(&socket, &mut sessions, &config, &state, client_addr, packet).await?;
          }
          WebRtcTurnListenerMode::EdgeRelay => {
            super::edge::handle_udp_packet(socket.clone(), edge.clone(), &config, client_addr, packet).await?;
          }
        }
      }
    }
  }
}

fn udp_client_admitted(quiescing: bool, known_client: bool) -> bool {
  !quiescing || known_client
}

struct UdpProxySession {
  upstream: Arc<UdpSocket>,
  upstream_task: JoinHandle<()>,
  _selection: TurnPoolSelection,
  last_activity: Instant,
}

impl Drop for UdpProxySession {
  fn drop(&mut self) {
    self.upstream_task.abort();
  }
}

async fn proxy_udp_packet(
  downstream: &Arc<UdpSocket>,
  sessions: &mut HashMap<SocketAddr, UdpProxySession>,
  config: &WebRtcTurnListenerConfig,
  state: &AppHandle,
  client_addr: SocketAddr,
  packet: &[u8],
) -> anyhow::Result<()> {
  if !proxy_auth_allows(config, packet)? {
    return Ok(());
  }
  expire_udp_sessions(sessions, Duration::from_millis(config.idle_timeout_ms));
  if let std::collections::hash_map::Entry::Vacant(entry) = sessions.entry(client_addr) {
    let pool = config
      .udp_pool
      .as_deref()
      .context("TURN UDP proxy pool is unavailable")?;
    let selection =
      state
        .snapshot()
        .turn_pools
        .select(pool, client_addr.ip(), &client_addr.to_string())?;
    let upstream_addr = resolve_turn_origin(&selection.origin).await?;
    let upstream = Arc::new(UdpSocket::bind(client_bind_addr(upstream_addr)).await?);
    upstream.connect(upstream_addr).await?;
    let upstream_reader = upstream.clone();
    let downstream_writer = downstream.clone();
    let upstream_task = tokio::spawn(async move {
      let mut buf = vec![0u8; 65_536];
      while let Ok(len) = upstream_reader.recv(&mut buf).await {
        if downstream_writer
          .send_to(&buf[..len], client_addr)
          .await
          .is_err()
        {
          break;
        }
      }
    });
    entry.insert(UdpProxySession {
      upstream,
      upstream_task,
      _selection: selection,
      last_activity: Instant::now(),
    });
  }
  if let Some(session) = sessions.get_mut(&client_addr) {
    session.upstream.send(packet).await?;
    session.last_activity = Instant::now();
  }
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_turn_stream(
  downstream: BoxedIo,
  peer_addr: SocketAddr,
  stream_id: u64,
  stream_pool: Option<String>,
  config: WebRtcTurnListenerConfig,
  state: AppHandle,
  drain: ConnectionDrain,
  edge: EdgeState,
) -> anyhow::Result<()> {
  match config.mode {
    WebRtcTurnListenerMode::ProxyPool => {
      serve_proxy_stream(downstream, peer_addr, stream_pool, config, state, drain).await
    }
    WebRtcTurnListenerMode::EdgeRelay => {
      super::edge::serve_stream(downstream, stream_id, config, drain, edge).await
    }
  }
}

async fn serve_proxy_stream(
  mut downstream: BoxedIo,
  peer_addr: SocketAddr,
  stream_pool: Option<String>,
  config: WebRtcTurnListenerConfig,
  state: AppHandle,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let first = read_turn_frame_with_timeout(
    &mut downstream,
    Duration::from_millis(config.idle_timeout_ms),
  )
  .await?;
  if !proxy_auth_allows(&config, &first)? {
    return Ok(());
  }
  let pool = stream_pool
    .as_deref()
    .context("TURN stream proxy pool is unavailable")?;
  let selection =
    state
      .snapshot()
      .turn_pools
      .select(pool, peer_addr.ip(), &peer_addr.to_string())?;
  let snapshot = state.snapshot();
  let mut upstream = connect_turn_stream(&selection.origin, &snapshot).await?;
  upstream.write_all(&first).await?;
  copy_bidirectional_with_idle(
    downstream,
    upstream,
    Duration::from_millis(config.idle_timeout_ms),
    drain,
  )
  .await?;
  drop(selection);
  Ok(())
}

async fn read_turn_frame_with_timeout<R>(
  reader: &mut R,
  timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
  R: AsyncRead + Unpin,
{
  tokio::time::timeout(timeout, read_turn_frame(reader))
    .await
    .map_err(|_| anyhow::anyhow!("TURN first frame timed out"))?
}

fn proxy_auth_allows(config: &WebRtcTurnListenerConfig, packet: &[u8]) -> anyhow::Result<bool> {
  if config.auth.mode == TurnAuthMode::PassThrough || !is_stun_message(packet) {
    return Ok(true);
  }
  let message = parse_stun(packet)?;
  match auth::validate_message(&config.auth, &config.realm, &message)? {
    AuthDecision::Pass | AuthDecision::Missing => Ok(true),
    AuthDecision::Invalid => Ok(false),
  }
}

async fn connect_turn_stream(origin: &Url, snapshot: &AppSnapshot) -> anyhow::Result<BoxedIo> {
  let addr = resolve_turn_origin(origin).await?;
  let tcp = tokio::time::timeout(Duration::from_millis(3_000), TcpStream::connect(addr))
    .await
    .context("TURN upstream connect timed out")??;
  if origin.scheme() != "turns" {
    return Ok(Box::new(tcp));
  }
  let client_config = tls::build_upstream_client_config_with_crypto_resumption_and_revocation(
    &snapshot.config.crypto,
    &snapshot.config.proxy.trusted_ca_certs,
    &UpstreamEchConfig::default(),
    &UpstreamTlsResumptionConfig::default(),
    Some(&snapshot.tls_resumption),
    "turn-upstream",
    Some((
      &snapshot.outbound_revocation,
      snapshot.outbound_revocation.default_policy(),
    )),
  )?;
  let connector = TlsConnector::from(Arc::new(client_config));
  let host = origin
    .host_str()
    .context("TURN upstream missing host")?
    .to_string();
  let server_name = rustls::pki_types::ServerName::try_from(host)
    .context("invalid TURN upstream TLS server name")?;
  Ok(Box::new(connector.connect(server_name, tcp).await?))
}

async fn resolve_turn_origin(origin: &Url) -> anyhow::Result<SocketAddr> {
  let host = origin.host_str().context("TURN origin missing host")?;
  let port = origin.port().unwrap_or_else(|| {
    if origin.scheme() == "turns" {
      5349
    } else {
      3478
    }
  });
  tokio::net::lookup_host((host, port))
    .await?
    .next()
    .ok_or_else(|| anyhow::anyhow!("TURN origin resolved no addresses: {origin}"))
}

fn bind_udp_socket(bind: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  if let Some(socket) = crate::netport_switcher::bind_udp_socket(
    bind,
    crate::netport_switcher::SwitcherUdpOptions::simple(),
    "TURN UDP",
    0,
  )? {
    return Ok(socket);
  }
  let socket = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))?;
  socket.set_reuse_address(true)?;
  socket.bind(&bind.into())?;
  let socket: std::net::UdpSocket = socket.into();
  socket.set_nonblocking(true)?;
  Ok(socket)
}

fn client_bind_addr(remote: SocketAddr) -> SocketAddr {
  match remote {
    SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
    SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
  }
}

fn expire_udp_sessions(
  sessions: &mut HashMap<SocketAddr, UdpProxySession>,
  idle_timeout: Duration,
) {
  let now = Instant::now();
  sessions.retain(|_, session| now.duration_since(session.last_activity) < idle_timeout);
}

#[cfg(test)]
mod tests;

async fn copy_bidirectional_with_idle(
  left: BoxedIo,
  right: BoxedIo,
  idle_timeout: Duration,
  mut drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let (mut left_read, mut left_write) = tokio::io::split(left);
  let (mut right_read, mut right_write) = tokio::io::split(right);
  let (activity_tx, mut activity_rx) = mpsc::channel(16);
  let left_activity = activity_tx.clone();
  let mut left_to_right = tokio::spawn(async move {
    tokio::io::copy(&mut left_read, &mut right_write).await?;
    let _ = left_activity.try_send(());
    anyhow::Ok(())
  });
  let mut right_to_left = tokio::spawn(async move {
    tokio::io::copy(&mut right_read, &mut left_write).await?;
    let _ = activity_tx.try_send(());
    anyhow::Ok(())
  });
  let idle = tokio::time::sleep(idle_timeout);
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);
  loop {
    tokio::select! {
      result = &mut left_to_right => {
        right_to_left.abort();
        return result.context("TURN copy task panicked")?;
      }
      result = &mut right_to_left => {
        left_to_right.abort();
        return result.context("TURN copy task panicked")?;
      }
      activity = activity_rx.recv() => {
        if activity.is_none() {
          return Ok(());
        }
        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
      }
      _ = &mut idle => {
        left_to_right.abort();
        right_to_left.abort();
        return Ok(());
      }
      _ = &mut drain_close => {
        left_to_right.abort();
        right_to_left.abort();
        return Ok(());
      }
    }
  }
}

fn spawn_health_task(state: AppHandle, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
  tokio::spawn(async move {
    loop {
      if *shutdown.borrow() {
        return;
      }
      let snapshot = state.snapshot();
      let targets = snapshot.turn_pools.health_targets();
      let sleep_duration = targets
        .iter()
        .map(|(_, _, _, interval_ms, _)| Duration::from_millis(*interval_ms))
        .min()
        .unwrap_or_else(|| Duration::from_secs(10));
      for (pool, server, origin, _interval_ms, timeout_ms) in targets {
        let result = turn_health_check(&origin, Duration::from_millis(timeout_ms), &snapshot).await;
        let snapshot = state.snapshot();
        if result.is_ok() {
          snapshot.turn_pools.report_success(&pool, &server);
        } else {
          snapshot.turn_pools.report_failure(&pool, &server);
        }
      }
      tokio::select! {
        _ = shutdown.changed() => {},
        _ = tokio::time::sleep(sleep_duration) => {},
      }
    }
  })
}

async fn turn_health_check(
  origin: &Url,
  timeout: Duration,
  snapshot: &AppSnapshot,
) -> anyhow::Result<()> {
  let addr = resolve_turn_origin(origin).await?;
  let txid = random_transaction_id()?;
  let request = encode_binding_request(txid);
  if origin.scheme() == "turn" {
    let socket = UdpSocket::bind(client_bind_addr(addr)).await?;
    socket.send_to(&request, addr).await?;
    let mut response = [0u8; 1500];
    let len = tokio::time::timeout(timeout, socket.recv(&mut response)).await??;
    let message = parse_stun(&response[..len])?;
    if message.message_type == success_type(BINDING_REQUEST) {
      return Ok(());
    }
    bail!("unexpected STUN health response");
  }
  let mut stream: BoxedIo = if origin.scheme() == "turns" {
    tokio::time::timeout(timeout, connect_turn_stream(origin, snapshot)).await??
  } else {
    Box::new(tokio::time::timeout(timeout, TcpStream::connect(addr)).await??)
  };
  stream.write_all(&request).await?;
  let response = tokio::time::timeout(timeout, read_turn_frame(&mut stream)).await??;
  let message = parse_stun(&response)?;
  if message.message_type == success_type(BINDING_REQUEST) {
    Ok(())
  } else {
    bail!("unexpected STUN health response")
  }
}

fn random_transaction_id() -> anyhow::Result<[u8; 12]> {
  let mut txid = [0u8; 12];
  crate::crypto::random_fill(&mut txid)
    .map_err(|_| anyhow::anyhow!("failed to generate TURN transaction id"))?;
  Ok(txid)
}
