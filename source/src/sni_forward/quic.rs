use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::Context;
use h3_quinn::quinn::udp::{RecvMeta, Transmit};
use h3_quinn::quinn::{
  AsyncUdpSocket, Endpoint, ServerConfig, TokioRuntime, UdpPoller, default_runtime,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::sni_forward::SniForwardDecision;
use crate::sni_forward::client_hello::raw_client_hello_sni;
use crate::state::{AppHandle, AppSnapshot};
use crate::stream::resolve_target_addr;

const MAX_UDP_DATAGRAM_BYTES: usize = 65_535;

pub(crate) struct BoundQuicForwardSocket {
  socket: Arc<QuicDemuxSocket>,
}

impl BoundQuicForwardSocket {
  pub(crate) fn start(
    &self,
    state: AppHandle,
    shutdown: watch::Receiver<bool>,
  ) -> JoinHandle<anyhow::Result<()>> {
    let socket = self.socket.clone();
    tokio::spawn(async move { socket.run(state, shutdown).await })
  }
}

pub(crate) fn bind_server_endpoints(
  bind: SocketAddr,
  server_config: ServerConfig,
  snapshot: &AppSnapshot,
) -> anyhow::Result<(Vec<Endpoint>, Vec<BoundQuicForwardSocket>)> {
  let mut endpoints = Vec::with_capacity(snapshot.config.quic.socket.workers);
  let mut demuxes = Vec::with_capacity(snapshot.config.quic.socket.workers);

  let (first_endpoint, first_demux) = bind_server_endpoint(bind, server_config.clone(), snapshot)?;
  let assigned = first_endpoint
    .local_addr()
    .context("failed to read downstream HTTP/3 listener address")?;
  endpoints.push(first_endpoint);
  demuxes.push(first_demux);

  if snapshot.config.quic.socket.workers == 1 {
    return Ok((endpoints, demuxes));
  }

  let worker_bind = SocketAddr::new(bind.ip(), assigned.port());
  for _ in 1..snapshot.config.quic.socket.workers {
    let (endpoint, demux) = bind_server_endpoint(worker_bind, server_config.clone(), snapshot)?;
    endpoints.push(endpoint);
    demuxes.push(demux);
  }
  Ok((endpoints, demuxes))
}

pub(crate) fn bind_sni_or_plain_server_endpoints(
  bind: SocketAddr,
  server_config: ServerConfig,
  snapshot: &AppSnapshot,
) -> anyhow::Result<(Vec<Endpoint>, Vec<BoundQuicForwardSocket>)> {
  if snapshot.config.sni_forward.has_quic() {
    bind_server_endpoints(bind, server_config, snapshot)
  } else {
    Ok((
      crate::quic::bind_server_endpoints(
        bind,
        server_config,
        &snapshot.config.quic,
        snapshot.config.source_paths.cert_dir.as_deref(),
      )?,
      Vec::new(),
    ))
  }
}

pub(crate) fn spawn_demux_tasks(
  demuxes: Vec<BoundQuicForwardSocket>,
  shutdown: watch::Receiver<bool>,
  state: AppHandle,
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
) -> Vec<JoinHandle<()>> {
  demuxes
    .into_iter()
    .map(|demux| {
      let demux_shutdown = shutdown.clone();
      let demux_state = state.clone();
      let demux_error_tx = error_tx.clone();
      tokio::spawn(async move {
        match demux.start(demux_state, demux_shutdown).await {
          Ok(Ok(())) => {}
          Ok(Err(error)) => {
            let _ = demux_error_tx.send(error.context("SNI forwarding QUIC demux failed"));
          }
          Err(error) => {
            let _ = demux_error_tx.send(anyhow::anyhow!(
              "SNI forwarding QUIC demux task panicked: {error}"
            ));
          }
        }
      })
    })
    .collect()
}

fn bind_server_endpoint(
  bind: SocketAddr,
  server_config: ServerConfig,
  snapshot: &AppSnapshot,
) -> anyhow::Result<(Endpoint, BoundQuicForwardSocket)> {
  let socket = crate::quic::bind_udp_socket(bind, &snapshot.config.quic.socket)?;
  let socket = UdpSocket::from_std(socket).context("failed to register QUIC UDP socket")?;
  let demux = QuicDemuxSocket::new(
    socket,
    snapshot.config.sni_forward.quic_local_queue_capacity,
  );
  let runtime = default_runtime().unwrap_or_else(|| Arc::new(TokioRuntime));
  let endpoint = Endpoint::new_with_abstract_socket(
    crate::quic::endpoint_config(
      &snapshot.config.quic,
      &snapshot.config.quic.downstream.transport,
      "quic.downstream.transport",
      snapshot.config.source_paths.cert_dir.as_deref(),
    )?,
    Some(server_config),
    demux.clone(),
    runtime,
  )
  .with_context(|| format!("failed to bind downstream HTTP/3 listener to {bind}"))?;
  Ok((endpoint, BoundQuicForwardSocket { socket: demux }))
}

#[derive(Clone)]
struct LocalDatagram {
  bytes: Vec<u8>,
  peer: SocketAddr,
}

struct QuicDemuxSocket {
  socket: Arc<UdpSocket>,
  local_tx: mpsc::Sender<LocalDatagram>,
  local_rx: Mutex<mpsc::Receiver<LocalDatagram>>,
  sessions: Mutex<QuicForwardState>,
}

impl fmt::Debug for QuicDemuxSocket {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("QuicDemuxSocket").finish_non_exhaustive()
  }
}

impl QuicDemuxSocket {
  fn new(socket: UdpSocket, local_queue_capacity: usize) -> Arc<Self> {
    let (local_tx, local_rx) = mpsc::channel(local_queue_capacity);
    Arc::new(Self {
      socket: Arc::new(socket),
      local_tx,
      local_rx: Mutex::new(local_rx),
      sessions: Mutex::new(QuicForwardState::default()),
    })
  }

  async fn run(
    self: Arc<Self>,
    state: AppHandle,
    mut shutdown: watch::Receiver<bool>,
  ) -> anyhow::Result<()> {
    let bind = self.socket.local_addr()?;
    let mut buffer = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
    let mut expire = tokio::time::interval(Duration::from_secs(5));
    info!(bind = %bind, "SNI forwarding QUIC demux started");
    loop {
      tokio::select! {
        biased;
        changed = shutdown.changed() => {
          if changed.is_ok() && *shutdown.borrow() {
            self.expire_all(&state.snapshot());
            info!(bind = %bind, "SNI forwarding QUIC demux stopped");
            return Ok(());
          }
        }
        _ = expire.tick() => {
          self.expire_idle(&state.snapshot());
        }
        received = self.socket.recv_from(&mut buffer) => {
          let (len, peer) = received.context("failed to receive QUIC UDP datagram")?;
          let datagram = &buffer[..len];
          if let Err(error) = self.handle_datagram(datagram, peer, &state).await {
            warn!(peer = %peer, error = %error, "failed to classify QUIC datagram for SNI forwarding");
          }
        }
      }
    }
  }

  async fn handle_datagram(
    &self,
    datagram: &[u8],
    peer: SocketAddr,
    state: &AppHandle,
  ) -> anyhow::Result<()> {
    let snapshot = state.snapshot();
    if !snapshot.config.sni_forward.has_quic() {
      self.queue_local(datagram, peer);
      return Ok(());
    }

    match self.known_action(datagram, peer, snapshot.as_ref()) {
      DatagramAction::QueueLocal => {
        self.queue_local(datagram, peer);
        return Ok(());
      }
      DatagramAction::SendTo(target) => {
        self.socket.send_to(datagram, target).await?;
        snapshot
          .metrics
          .add_sni_forward_udp_bytes(datagram.len() as u64);
        return Ok(());
      }
      DatagramAction::Classify => {}
    }

    let initial = extract_initial_sni(datagram);
    let (sni, client_scid) = match initial {
      Ok(value) => value,
      Err(error) => {
        snapshot.metrics.record_sni_forward_parse_failure("quic");
        snapshot
          .metrics
          .record_sni_forward_decision("quic", "reject", "parse_failure", "none");
        warn!(peer = %peer, error = %error, "QUIC Initial SNI inspection failed");
        return Ok(());
      }
    };

    match snapshot.sni_forward.decide_quic(sni.as_deref()) {
      SniForwardDecision::Local => {
        snapshot
          .metrics
          .record_sni_forward_decision("quic", "local", "local_route", "local");
        self.remember_local(peer, client_scid, snapshot.as_ref());
        self.queue_local(datagram, peer);
      }
      SniForwardDecision::Reject => {
        snapshot
          .metrics
          .record_sni_forward_decision("quic", "reject", "no_match", "none");
      }
      SniForwardDecision::Forward(rule) => {
        snapshot
          .metrics
          .record_sni_forward_decision("quic", "forward", &rule.name, &rule.target);
        let (host, port) = crate::config::parse_stream_target(&rule.target)
          .with_context(|| format!("invalid SNI forwarding target {}", rule.target))?;
        let target = resolve_target_addr(&host, port).await?;
        self.remember_forward(
          peer,
          target,
          client_scid,
          sni.as_deref(),
          &rule,
          snapshot.as_ref(),
        );
        self.socket.send_to(datagram, target).await?;
        snapshot
          .metrics
          .add_sni_forward_udp_bytes(datagram.len() as u64);
      }
    }
    Ok(())
  }

  fn known_action(
    &self,
    datagram: &[u8],
    peer: SocketAddr,
    snapshot: &AppSnapshot,
  ) -> DatagramAction {
    let mut sessions = lock_sessions(&self.sessions);
    let mut evicted =
      sessions.enforce_pre_classification_limit(snapshot.config.sni_forward.quic_max_sessions);
    let action = sessions.known_action(datagram, peer);
    evicted.extend(
      sessions.enforce_pre_classification_limit(snapshot.config.sni_forward.quic_max_sessions),
    );
    drop(sessions);
    for session in evicted {
      end_forward_session(snapshot, session, "capacity");
    }
    action
  }

  fn remember_local(&self, peer: SocketAddr, client_scid: Vec<u8>, snapshot: &AppSnapshot) {
    let mut sessions = lock_sessions(&self.sessions);
    sessions.local_clients.insert(peer, Instant::now());
    if !client_scid.is_empty() {
      sessions.local_cids.insert(client_scid, peer);
    }
    let evicted =
      sessions.enforce_pre_classification_limit(snapshot.config.sni_forward.quic_max_sessions);
    drop(sessions);
    for session in evicted {
      end_forward_session(snapshot, session, "capacity");
    }
  }

  fn remember_forward(
    &self,
    peer: SocketAddr,
    target: SocketAddr,
    client_scid: Vec<u8>,
    sni: Option<&str>,
    rule: &crate::sni_forward::SniForwardRule,
    snapshot: &AppSnapshot,
  ) {
    let mut sessions = lock_sessions(&self.sessions);
    let inserted = sessions.forward_by_client.insert(
      peer,
      QuicForwardSession {
        target_addr: target,
        rule_name: rule.name.clone(),
        target: rule.target.clone(),
        sni: sni.unwrap_or("none").to_string(),
        started: Instant::now(),
        last_seen: Instant::now(),
        idle_timeout: rule.idle_timeout,
        client_to_target: 0,
        target_to_client: 0,
      },
    );
    if inserted.is_none() {
      snapshot.metrics.add_sni_forward_active_quic_session(1);
    }
    if !client_scid.is_empty() {
      sessions.cid_to_client.insert(client_scid, peer);
    }
    let evicted =
      sessions.enforce_pre_classification_limit(snapshot.config.sni_forward.quic_max_sessions);
    drop(sessions);
    for session in evicted {
      end_forward_session(snapshot, session, "capacity");
    }
    info!(
      protocol = "quic",
      peer = %peer,
      target = %rule.target,
      rule = %rule.name,
      sni = sni.unwrap_or("none"),
      "SNI forwarding QUIC session started"
    );
  }

  fn queue_local(&self, datagram: &[u8], peer: SocketAddr) {
    let _ = self.local_tx.try_send(LocalDatagram {
      bytes: datagram.to_vec(),
      peer,
    });
  }

  fn expire_idle(&self, snapshot: &AppSnapshot) {
    let mut sessions = lock_sessions(&self.sessions);
    let now = Instant::now();
    let expired = sessions.expire_forward(now, false);
    drop(sessions);
    for session in expired {
      end_forward_session(snapshot, session, "idle_timeout");
    }
  }

  fn expire_all(&self, snapshot: &AppSnapshot) {
    let mut sessions = lock_sessions(&self.sessions);
    let expired = sessions.expire_forward(Instant::now(), true);
    drop(sessions);
    for session in expired {
      end_forward_session(snapshot, session, "closed");
    }
  }
}

impl AsyncUdpSocket for QuicDemuxSocket {
  fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
    Box::pin(QuicDemuxPoller {
      socket: self.socket.clone(),
    })
  }

  fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
    if let Some(segment_size) = transmit.segment_size {
      for chunk in transmit.contents.chunks(segment_size) {
        self.socket.try_send_to(chunk, transmit.destination)?;
      }
      Ok(())
    } else {
      self
        .socket
        .try_send_to(transmit.contents, transmit.destination)
        .map(|_| ())
    }
  }

  fn poll_recv(
    &self,
    cx: &mut TaskContext<'_>,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
  ) -> Poll<io::Result<usize>> {
    let mut receiver = self
      .local_rx
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    match Pin::new(&mut *receiver).poll_recv(cx) {
      Poll::Ready(Some(datagram)) => {
        if bufs.is_empty() || meta.is_empty() {
          return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC receive buffers must not be empty",
          )));
        }
        if datagram.bytes.len() > bufs[0].len() {
          return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QUIC datagram does not fit receive buffer",
          )));
        }
        bufs[0][..datagram.bytes.len()].copy_from_slice(&datagram.bytes);
        meta[0] = RecvMeta {
          addr: datagram.peer,
          len: datagram.bytes.len(),
          stride: datagram.bytes.len(),
          ecn: None,
          dst_ip: None,
        };
        Poll::Ready(Ok(1))
      }
      Poll::Ready(None) => Poll::Pending,
      Poll::Pending => Poll::Pending,
    }
  }

  fn local_addr(&self) -> io::Result<SocketAddr> {
    self.socket.local_addr()
  }

  fn may_fragment(&self) -> bool {
    true
  }
}

#[derive(Debug)]
struct QuicDemuxPoller {
  socket: Arc<UdpSocket>,
}

impl UdpPoller for QuicDemuxPoller {
  fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
    match self.socket.poll_send_ready(cx) {
      Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Pending => Poll::Pending,
    }
  }
}

#[derive(Debug)]
enum DatagramAction {
  QueueLocal,
  SendTo(SocketAddr),
  Classify,
}

#[derive(Default)]
struct QuicForwardState {
  forward_by_client: HashMap<SocketAddr, QuicForwardSession>,
  cid_to_client: HashMap<Vec<u8>, SocketAddr>,
  local_clients: HashMap<SocketAddr, Instant>,
  local_cids: HashMap<Vec<u8>, SocketAddr>,
}

impl QuicForwardState {
  fn known_action(&mut self, datagram: &[u8], peer: SocketAddr) -> DatagramAction {
    if let Some(client) = self.client_for_upstream_response(peer, datagram)
      && let Some(session) = self.forward_by_client.get_mut(&client)
    {
      session.last_seen = Instant::now();
      session.target_to_client = session
        .target_to_client
        .saturating_add(datagram.len() as u64);
      return DatagramAction::SendTo(client);
    }
    if let Some(session) = self.forward_by_client.get_mut(&peer) {
      session.last_seen = Instant::now();
      session.client_to_target = session
        .client_to_target
        .saturating_add(datagram.len() as u64);
      return DatagramAction::SendTo(session.target_addr);
    }
    if let Some(local) = self.local_clients.get_mut(&peer) {
      *local = Instant::now();
      return DatagramAction::QueueLocal;
    }
    DatagramAction::Classify
  }

  fn client_for_upstream_response(
    &mut self,
    peer: SocketAddr,
    datagram: &[u8],
  ) -> Option<SocketAddr> {
    let mut matching_clients = self
      .forward_by_client
      .iter()
      .filter_map(|(client, session)| (session.target_addr == peer).then_some(*client));
    let first_matching_client = matching_clients.next()?;
    let has_multiple_clients = matching_clients.next().is_some();

    if let Ok(header) = quic_parser::parse_initial(datagram)
      && let Some(client) = self.cid_to_client.get(header.dcid).copied()
    {
      if !header.scid.is_empty() {
        self.cid_to_client.insert(header.scid.to_vec(), client);
      }
      return Some(client);
    }
    if let Some(dcid) = quic_parser::peek_long_header_dcid(datagram)
      && let Some(client) = self.cid_to_client.get(dcid).copied()
    {
      return Some(client);
    }
    for (cid, client) in &self.cid_to_client {
      if datagram.len() > cid.len() && datagram.get(1..1 + cid.len()) == Some(cid.as_slice()) {
        return Some(*client);
      }
    }
    // QUIC peers can switch to encrypted NEW_CONNECTION_ID values that are
    // invisible to this L4 demux. A single active client for the target is
    // still unambiguous; shared targets without a known CID fail closed.
    if !has_multiple_clients {
      return Some(first_matching_client);
    }
    None
  }

  fn enforce_pre_classification_limit(&mut self, max_sessions: usize) -> Vec<QuicForwardSession> {
    let mut evicted = Vec::new();
    while self.pre_classification_session_count() > max_sessions {
      let oldest_forward = self
        .forward_by_client
        .iter()
        .min_by_key(|(_, session)| session.last_seen)
        .map(|(client, session)| (*client, session.last_seen));
      let oldest_local = self
        .local_clients
        .iter()
        .min_by_key(|(_, last_seen)| **last_seen)
        .map(|(client, last_seen)| (*client, *last_seen));

      match (oldest_forward, oldest_local) {
        (Some((client, forward_seen)), Some((_local, local_seen)))
          if forward_seen <= local_seen =>
        {
          if let Some(session) = self.remove_forward_client(client) {
            evicted.push(session);
          }
        }
        (Some(_), Some((local, _))) => {
          self.remove_local_client(local);
        }
        (Some((client, _)), None) => {
          if let Some(session) = self.remove_forward_client(client) {
            evicted.push(session);
          }
        }
        (None, Some((local, _))) => {
          self.remove_local_client(local);
        }
        (None, None) => break,
      }
    }
    self.prune_cid_maps(max_sessions);
    evicted
  }

  fn pre_classification_session_count(&self) -> usize {
    self
      .forward_by_client
      .len()
      .saturating_add(self.local_clients.len())
  }

  fn remove_forward_client(&mut self, client: SocketAddr) -> Option<QuicForwardSession> {
    let session = self.forward_by_client.remove(&client)?;
    self
      .cid_to_client
      .retain(|_, mapped_client| *mapped_client != client);
    Some(session)
  }

  fn remove_local_client(&mut self, client: SocketAddr) {
    self.local_clients.remove(&client);
    self
      .local_cids
      .retain(|_, mapped_client| *mapped_client != client);
  }

  fn prune_cid_maps(&mut self, max_sessions: usize) {
    self
      .cid_to_client
      .retain(|_, client| self.forward_by_client.contains_key(client));
    self
      .local_cids
      .retain(|_, client| self.local_clients.contains_key(client));
    trim_cid_map(&mut self.cid_to_client, max_sessions);
    trim_cid_map(&mut self.local_cids, max_sessions);
  }

  fn expire_forward(&mut self, now: Instant, force: bool) -> Vec<QuicForwardSession> {
    self
      .local_clients
      .retain(|_, last_seen| !force && now.duration_since(*last_seen) < Duration::from_secs(300));
    self
      .local_cids
      .retain(|_, client| self.local_clients.contains_key(client));
    let mut expired_clients = Vec::new();
    for (client, session) in &self.forward_by_client {
      if force || now.duration_since(session.last_seen) >= session.idle_timeout {
        expired_clients.push(*client);
      }
    }
    let mut expired = Vec::with_capacity(expired_clients.len());
    for client in expired_clients {
      if let Some(session) = self.forward_by_client.remove(&client) {
        expired.push(session);
      }
    }
    self
      .cid_to_client
      .retain(|_, client| self.forward_by_client.contains_key(client));
    expired
  }
}

fn trim_cid_map(map: &mut HashMap<Vec<u8>, SocketAddr>, max_entries: usize) {
  while map.len() > max_entries {
    let Some(key) = map.keys().next().cloned() else {
      break;
    };
    map.remove(&key);
  }
}

struct QuicForwardSession {
  target_addr: SocketAddr,
  rule_name: String,
  target: String,
  sni: String,
  started: Instant,
  last_seen: Instant,
  idle_timeout: Duration,
  client_to_target: u64,
  target_to_client: u64,
}

fn extract_initial_sni(datagram: &[u8]) -> anyhow::Result<(Option<String>, Vec<u8>)> {
  let header = quic_parser::parse_initial(datagram).context("invalid QUIC Initial header")?;
  let client_scid = header.scid.to_vec();
  let decrypted =
    quic_parser::decrypt_initial(&header).context("failed to decrypt QUIC Initial")?;
  let frames =
    quic_parser::parse_crypto_frames(&decrypted).context("failed to parse QUIC CRYPTO frames")?;
  let stream = quic_parser::reassemble_crypto_stream(&frames);
  let sni = raw_client_hello_sni(&stream).context("failed to parse QUIC TLS ClientHello")?;
  Ok((sni, client_scid))
}

fn end_forward_session(snapshot: &AppSnapshot, session: QuicForwardSession, outcome: &str) {
  snapshot.metrics.add_sni_forward_active_quic_session(-1);
  snapshot.metrics.record_sni_forward_session_end(
    &snapshot.config.metrics,
    "quic",
    &session.rule_name,
    &session.target,
    outcome,
    session.started.elapsed().as_millis() as u64,
  );
  info!(
    protocol = "quic",
    target = %session.target,
    rule = %session.rule_name,
    sni = %session.sni,
    outcome = outcome,
    duration_ms = session.started.elapsed().as_millis() as u64,
    client_to_target_bytes = session.client_to_target,
    target_to_client_bytes = session.target_to_client,
    "SNI forwarding QUIC session ended"
  );
}

fn lock_sessions(
  sessions: &Mutex<QuicForwardState>,
) -> std::sync::MutexGuard<'_, QuicForwardState> {
  sessions
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
#[path = "quic_tests.rs"]
mod tests;
