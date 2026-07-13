//! QUIC SNI forwarding runtime.
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::Context;
use h3_quinn::quinn::udp::{RecvMeta, Transmit};
use h3_quinn::quinn::{AsyncUdpSocket, Endpoint, TokioRuntime, UdpPoller, default_runtime};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::sni_forward::SniForwardDecision;
use crate::sni_forward::client_hello::raw_client_hello_sni;
use crate::sni_forward::connection_limits::acquire_quic_forward_connection_permit;
use crate::state::{AppHandle, AppSnapshot};
use crate::stream::resolve_target_addr;

mod forward_record;
mod state;
use forward_record::QuicForwardRecord;
use state::{DatagramAction, LocalQuicSession, QuicForwardSession, QuicForwardState};

const MAX_UDP_DATAGRAM_BYTES: usize = 65_535;

pub(crate) struct BoundQuicForwardSocket {
  socket: Arc<QuicDemuxSocket>,
}

impl BoundQuicForwardSocket {
  pub(crate) fn start(
    &self,
    state: AppHandle,
    quiesce: watch::Receiver<bool>,
    shutdown: watch::Receiver<bool>,
  ) -> JoinHandle<anyhow::Result<()>> {
    let socket = self.socket.clone();
    tokio::spawn(async move { socket.run(state, quiesce, shutdown).await })
  }
}

pub(crate) fn bind_server_endpoints(
  bind: SocketAddr,
  server_config: crate::tls::DownstreamQuicServerConfig,
  snapshot: &AppSnapshot,
) -> anyhow::Result<(Vec<Endpoint>, Vec<BoundQuicForwardSocket>)> {
  let mut endpoints = Vec::with_capacity(snapshot.config.quic.socket.workers);
  let mut demuxes = Vec::with_capacity(snapshot.config.quic.socket.workers);

  let (first_endpoints, first_demux) = bind_server_endpoint(bind, &server_config, snapshot)?;
  let assigned = first_endpoints
    .first()
    .expect("downstream QUIC bind must create at least one endpoint")
    .local_addr()
    .context("failed to read downstream HTTP/3 listener address")?;
  endpoints.extend(first_endpoints);
  demuxes.push(first_demux);

  if snapshot.config.quic.socket.workers == 1 {
    return Ok((endpoints, demuxes));
  }

  let worker_bind = SocketAddr::new(bind.ip(), assigned.port());
  for _ in 1..snapshot.config.quic.socket.workers {
    let (worker_endpoints, demux) = bind_server_endpoint(worker_bind, &server_config, snapshot)?;
    endpoints.extend(worker_endpoints);
    demuxes.push(demux);
  }
  Ok((endpoints, demuxes))
}

pub(crate) fn bind_sni_or_plain_server_endpoints(
  bind: SocketAddr,
  server_config: crate::tls::DownstreamQuicServerConfig,
  snapshot: &AppSnapshot,
) -> anyhow::Result<(Vec<Endpoint>, Vec<BoundQuicForwardSocket>)> {
  if snapshot.config.sni_forward.has_quic() || server_config.requires_sni_policy_demux() {
    bind_server_endpoints(bind, server_config, snapshot)
  } else {
    Ok((
      crate::quic::bind_server_endpoints(
        bind,
        server_config.default_config(),
        &snapshot.config.quic,
        snapshot.config.source_paths.cert_dir.as_deref(),
      )?,
      Vec::new(),
    ))
  }
}

pub(crate) fn spawn_demux_tasks(
  demuxes: Vec<BoundQuicForwardSocket>,
  quiesce: watch::Receiver<bool>,
  shutdown: watch::Receiver<bool>,
  state: AppHandle,
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
) -> Vec<JoinHandle<()>> {
  demuxes
    .into_iter()
    .map(|demux| {
      let demux_shutdown = shutdown.clone();
      let demux_quiesce = quiesce.clone();
      let demux_state = state.clone();
      let demux_error_tx = error_tx.clone();
      tokio::spawn(async move {
        match demux
          .start(demux_state, demux_quiesce, demux_shutdown)
          .await
        {
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
  server_config: &crate::tls::DownstreamQuicServerConfig,
  snapshot: &AppSnapshot,
) -> anyhow::Result<(Vec<Endpoint>, BoundQuicForwardSocket)> {
  let socket = crate::quic::bind_udp_socket(bind, &snapshot.config.quic.socket)?;
  let socket = UdpSocket::from_std(socket).context("failed to register QUIC UDP socket")?;
  let (demux, local_sockets) = QuicDemuxSocket::new(
    socket,
    snapshot.config.sni_forward.quic_local_queue_capacity,
    server_config.configs().len(),
  );
  let runtime = default_runtime().unwrap_or_else(|| Arc::new(TokioRuntime));
  let mut endpoints = Vec::with_capacity(local_sockets.len());
  for (index, config) in server_config.configs().iter().enumerate() {
    let endpoint = Endpoint::new_with_abstract_socket(
      crate::quic::endpoint_config(
        &snapshot.config.quic,
        &snapshot.config.quic.downstream.transport,
        "quic.downstream.transport",
        snapshot.config.source_paths.cert_dir.as_deref(),
      )?,
      Some(config.clone()),
      local_sockets[index].clone(),
      runtime.clone(),
    )
    .with_context(|| format!("failed to bind downstream HTTP/3 listener to {bind}"))?;
    endpoints.push(endpoint);
  }
  Ok((endpoints, BoundQuicForwardSocket { socket: demux }))
}

#[derive(Clone)]
struct LocalDatagram {
  bytes: Vec<u8>,
  peer: SocketAddr,
}

struct QuicDemuxSocket {
  socket: Arc<UdpSocket>,
  local_txs: Vec<mpsc::Sender<LocalDatagram>>,
  sessions: Mutex<QuicForwardState>,
}

struct QuicDemuxEndpointSocket {
  demux: Arc<QuicDemuxSocket>,
  local_rx: Mutex<mpsc::Receiver<LocalDatagram>>,
}

impl fmt::Debug for QuicDemuxSocket {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("QuicDemuxSocket").finish_non_exhaustive()
  }
}

impl fmt::Debug for QuicDemuxEndpointSocket {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("QuicDemuxEndpointSocket")
      .finish_non_exhaustive()
  }
}

impl QuicDemuxSocket {
  fn new(
    socket: UdpSocket,
    local_queue_capacity: usize,
    local_policy_count: usize,
  ) -> (Arc<Self>, Vec<Arc<QuicDemuxEndpointSocket>>) {
    let policy_count = local_policy_count.max(1);
    let mut local_txs = Vec::with_capacity(policy_count);
    let mut local_rxs = Vec::with_capacity(policy_count);
    for _ in 0..policy_count {
      let (local_tx, local_rx) = mpsc::channel(local_queue_capacity);
      local_txs.push(local_tx);
      local_rxs.push(local_rx);
    }
    let demux = Arc::new(Self {
      socket: Arc::new(socket),
      local_txs,
      sessions: Mutex::new(QuicForwardState::default()),
    });
    let endpoint_sockets = local_rxs
      .into_iter()
      .map(|local_rx| {
        Arc::new(QuicDemuxEndpointSocket {
          demux: demux.clone(),
          local_rx: Mutex::new(local_rx),
        })
      })
      .collect();
    (demux, endpoint_sockets)
  }

  async fn run(
    self: Arc<Self>,
    state: AppHandle,
    mut quiesce: watch::Receiver<bool>,
    mut shutdown: watch::Receiver<bool>,
  ) -> anyhow::Result<()> {
    let bind = self.socket.local_addr()?;
    let mut buffer = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
    let mut expire = tokio::time::interval(Duration::from_secs(5));
    let mut quiescing = *quiesce.borrow();
    info!(bind = %bind, "SNI forwarding QUIC demux started");
    loop {
      tokio::select! {
        biased;
        changed = quiesce.changed() => {
          if changed.is_err() || *quiesce.borrow() {
            quiescing = true;
            info!(bind = %bind, "SNI forwarding QUIC demux quiesced");
          }
        }
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
          if let Err(error) = self.handle_datagram(datagram, peer, &state, !quiescing).await {
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
    allow_new_session: bool,
  ) -> anyhow::Result<()> {
    let snapshot = state.snapshot();
    let sni_forward_enabled = snapshot.config.sni_forward.has_quic();
    let sni_policy_demux = snapshot
      .quic_server_config
      .as_ref()
      .is_some_and(|config| config.requires_sni_policy_demux());
    match self.known_action(datagram, peer, snapshot.as_ref()) {
      DatagramAction::QueueLocal(index) => {
        self.queue_local(index, datagram, peer);
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

    if !allow_new_session {
      return Ok(());
    }
    if !sni_forward_enabled && !sni_policy_demux {
      self.queue_local(0, datagram, peer);
      return Ok(());
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
    let local_policy_index = snapshot
      .quic_server_config
      .as_ref()
      .map_or(Some(0), |config| {
        config.policy_index_for_sni(sni.as_deref())
      });

    if !sni_forward_enabled {
      let Some(local_policy_index) = local_policy_index else {
        snapshot
          .metrics
          .record_sni_forward_decision("quic", "reject", "tls_policy", "none");
        return Ok(());
      };
      self.remember_local(peer, client_scid, local_policy_index, snapshot.as_ref());
      self.queue_local(local_policy_index, datagram, peer);
      return Ok(());
    }

    match snapshot.sni_forward.decide_quic(sni.as_deref()) {
      SniForwardDecision::Local => {
        let Some(local_policy_index) = local_policy_index else {
          snapshot
            .metrics
            .record_sni_forward_decision("quic", "reject", "tls_policy", "none");
          return Ok(());
        };
        snapshot
          .metrics
          .record_sni_forward_decision("quic", "local", "local_route", "local");
        self.remember_local(peer, client_scid, local_policy_index, snapshot.as_ref());
        self.queue_local(local_policy_index, datagram, peer);
      }
      SniForwardDecision::Reject => {
        snapshot
          .metrics
          .record_sni_forward_decision("quic", "reject", "no_match", "none");
      }
      SniForwardDecision::Forward(rule) => {
        let connection_permit =
          match acquire_quic_forward_connection_permit(snapshot.as_ref(), peer).await {
            Ok(permit) => permit,
            Err(status) => {
              snapshot.metrics.record_sni_forward_decision(
                "quic",
                "reject",
                "connection_limit",
                "none",
              );
              warn!(
                peer = %peer,
                status = %status,
                "QUIC SNI forwarding rejected by connection limit"
              );
              return Ok(());
            }
          };
        snapshot
          .metrics
          .record_sni_forward_decision("quic", "forward", &rule.name, &rule.target);
        let (host, port) = crate::config::parse_stream_target(&rule.target)
          .with_context(|| format!("invalid SNI forwarding target {}", rule.target))?;
        let target = resolve_target_addr(&host, port).await?;
        self.remember_forward(
          QuicForwardRecord {
            peer,
            target,
            client_scid,
            sni: sni.as_deref(),
            rule: &rule,
            connection_permit,
          },
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

  fn remember_local(
    &self,
    peer: SocketAddr,
    client_scid: Vec<u8>,
    local_policy_index: usize,
    snapshot: &AppSnapshot,
  ) {
    let mut sessions = lock_sessions(&self.sessions);
    sessions.local_clients.insert(
      peer,
      LocalQuicSession {
        policy_index: local_policy_index,
        last_seen: Instant::now(),
      },
    );
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

  fn remember_forward(&self, record: QuicForwardRecord<'_>, snapshot: &AppSnapshot) {
    let QuicForwardRecord {
      peer,
      target,
      client_scid,
      sni,
      rule,
      connection_permit,
    } = record;
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
        _connection_permit: Some(connection_permit),
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

  fn queue_local(&self, local_policy_index: usize, datagram: &[u8], peer: SocketAddr) {
    if let Some(local_tx) = self
      .local_txs
      .get(local_policy_index)
      .or_else(|| self.local_txs.first())
    {
      let _ = local_tx.try_send(LocalDatagram {
        bytes: datagram.to_vec(),
        peer,
      });
    }
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

impl AsyncUdpSocket for QuicDemuxEndpointSocket {
  fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
    Box::pin(QuicDemuxPoller {
      socket: self.demux.socket.clone(),
    })
  }

  fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
    if let Some(segment_size) = transmit.segment_size {
      for chunk in transmit.contents.chunks(segment_size) {
        self.demux.socket.try_send_to(chunk, transmit.destination)?;
      }
      Ok(())
    } else {
      self
        .demux
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
    self.demux.socket.local_addr()
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

pub(crate) fn extract_initial_sni(datagram: &[u8]) -> anyhow::Result<(Option<String>, Vec<u8>)> {
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
