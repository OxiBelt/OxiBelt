//! TURN edge session state.
//! Allocation state is scoped to the listener that admitted it.

mod allocation;
mod operations;
mod port;
mod relay;
mod request;
mod response;
mod tcp;
mod udp;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, mpsc, watch};

use crate::config::{TurnRelayAddressFamily, WebRtcTurnListenerConfig};
use crate::lifecycle::ConnectionDrain;
use crate::runtime_introspection::{
  RuntimeCounterGuard, RuntimeIntrospectionCounter as RuntimeCounter, RuntimeIntrospectionState,
};

use super::auth::{self, AuthenticatedContext, AuthenticatedContextDecision, NonceSourceBinding};
use super::listener::BoxedIo;
use super::protocol::*;
use allocation::{ExistingAllocate, create_allocation, existing_allocate};
use operations::process_frame;
use port::{TcpRelayPortReservation, bind_tcp_relay_socket};
use relay::{
  channel_binding_conflicts, expire_client_state, remove_all_expired_client_state,
  remove_expired_client_state, send, spawn_peer_reader, stream_outbound_channel,
};
use request::{
  UdpRelayRequest, address_family_attr, allocate_families, allocation_lifetime, channel_number,
  has_tcp_forbidden_allocate_option, lifetime_attr, peer_allowed, relay_family_config,
  requested_transport, singleton_attr, singleton_xor_addr, udp_allocate_options,
};
use response::{
  EdgeRequestFailure, RequestAuthentication, authenticate_request,
  authenticated_context_if_present, encode_authenticated_error, encode_authenticated_success,
  encode_unknown_attribute_error, request_authentication, send_authenticated_error,
};
use tcp::{
  ConnectionBindOutcome, PendingTcpConnection, handle_connect_request, handle_connection_bind,
  relay_bound_tcp_connection, release_active_connection, spawn_tcp_peer_acceptor,
};
use udp::{
  ClaimedUdpRelay, FinalizedUdpRelay, InstallReadyUdpRelay, PreparedUdpRelay, claim_udp_relay,
  expire_udp_relay_reservations, prepare_udp_relay,
};

#[derive(Clone)]
pub(super) struct EdgeState {
  clients: Arc<Mutex<HashMap<EdgeClient, EdgeClientState>>>,
  runtime_introspection: Arc<RuntimeIntrospectionState>,
}

impl EdgeState {
  pub(super) fn new(runtime_introspection: Arc<RuntimeIntrospectionState>) -> Self {
    Self {
      clients: Arc::new(Mutex::new(HashMap::new())),
      runtime_introspection,
    }
  }

  pub(super) async fn has_udp_client(&self, peer: SocketAddr, local: SocketAddr) -> bool {
    self
      .clients
      .lock()
      .await
      .contains_key(&EdgeClient::Udp { peer, local })
  }

  async fn remove_client(&self, client: EdgeClient) {
    self.clients.lock().await.remove(&client);
  }

  pub(super) async fn clear(&self) {
    self.clients.lock().await.clear();
  }

  pub(super) async fn remove_expired(&self) {
    let mut clients = self.clients.lock().await;
    remove_all_expired_client_state(&mut clients);
    drop(clients);
    expire_udp_relay_reservations();
  }

  pub(super) async fn expire_until_shutdown(&self, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
      tokio::select! {
        biased;
        changed = shutdown.changed() => {
          if changed.is_err() || *shutdown.borrow() {
            break;
          }
        }
        _ = interval.tick() => self.remove_expired().await,
      }
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum EdgeClient {
  Udp { peer: SocketAddr, local: SocketAddr },
  Stream { id: u64, peer: SocketAddr },
}

impl EdgeClient {
  fn peer(self) -> SocketAddr {
    match self {
      Self::Udp { peer, .. } | Self::Stream { peer, .. } => peer,
    }
  }

  fn is_stream(self) -> bool {
    matches!(self, Self::Stream { .. })
  }
}

#[derive(Clone)]
enum EdgeSender {
  Udp(Arc<UdpSocket>, SocketAddr),
  Stream(mpsc::Sender<Vec<u8>>),
}

struct EdgeClientState {
  sender: EdgeSender,
  allocations: HashMap<TurnRelayAddressFamily, EdgeAllocation>,
  _udp_client_guard: Option<RuntimeCounterGuard>,
}

struct EdgeAllocation {
  relay: EdgeRelay,
  relayed_addr: SocketAddr,
  transaction_id: [u8; 12],
  request_digest: [u8; 32],
  reservation_token: Option<[u8; 8]>,
  auth: Arc<AuthenticatedContext>,
  permissions: HashMap<IpAddr, Instant>,
  channels: HashMap<u16, EdgeChannelBinding>,
  pending_tcp: HashMap<u32, PendingTcpConnection>,
  active_tcp: HashMap<u32, SocketAddr>,
  expires_at: Instant,
  _introspection_guard: RuntimeCounterGuard,
}

#[derive(Clone)]
enum EdgeRelay {
  Udp(Arc<UdpSocket>),
  Tcp(Arc<EdgeTcpRelay>),
}

struct EdgeTcpRelay {
  listener: TcpListener,
  _reservation: Option<TcpRelayPortReservation>,
}

impl EdgeTcpRelay {
  fn local_addr(&self) -> std::io::Result<SocketAddr> {
    self.listener.local_addr()
  }

  async fn accept(&self) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
    self.listener.accept().await
  }
}

struct EdgeChannelBinding {
  peer: SocketAddr,
  expires_at: Instant,
}

pub(super) async fn serve_stream(
  downstream: BoxedIo,
  peer_addr: SocketAddr,
  stream_id: u64,
  config: WebRtcTurnListenerConfig,
  mut drain: ConnectionDrain,
  edge: EdgeState,
) -> anyhow::Result<()> {
  let (mut reader, mut writer) = tokio::io::split(downstream);
  let (tx, mut rx) = stream_outbound_channel(&config);
  let client = EdgeClient::Stream {
    id: stream_id,
    peer: peer_addr,
  };
  let idle = tokio::time::sleep(Duration::from_millis(config.idle_timeout_ms));
  tokio::pin!(idle);
  let bound_peer = async {
    let drain_close = drain.close_delay_elapsed();
    tokio::pin!(drain_close);
    loop {
      tokio::select! {
        frame = read_turn_frame(&mut reader) => {
          let frame = frame?;
          if parse_stun(&frame).is_ok_and(|message| message.message_type == CONNECTION_BIND_REQUEST) {
            match handle_connection_bind(&edge, &config, client, &frame).await? {
                    ConnectionBindOutcome::Bound { connection, response } => {
                        if let Err(error) = writer.write_all(&response).await {
                            release_active_connection(
                              &edge,
                              connection.owner,
                              connection.family,
                              connection.connection_id,
                            )
                            .await;
                            return Err(error.into());
                        }
                        break anyhow::Ok(Some(connection));
              }
              ConnectionBindOutcome::Rejected(response) => {
                writer.write_all(&response).await?;
                idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(config.idle_timeout_ms));
                continue;
              }
            }
          }
          process_frame(edge.clone(), &config, client, EdgeSender::Stream(tx.clone()), &frame).await?;
          idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(config.idle_timeout_ms));
        }
        Some(out) = rx.recv() => {
          writer.write_all(&out).await?;
          idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(config.idle_timeout_ms));
        }
        _ = &mut idle => break Ok(None),
        _ = &mut drain_close => break Ok(None),
      }
    }
  }
  .await;
  edge.remove_client(client).await;
  let bound_peer = bound_peer?;
  if let Some(connection) = bound_peer {
    let downstream = reader.unsplit(writer);
    relay_bound_tcp_connection(
      downstream,
      edge,
      connection,
      drain,
      Duration::from_millis(config.idle_timeout_ms),
    )
    .await?;
  }
  Ok(())
}

pub(super) async fn handle_udp_packet(
  socket: Arc<UdpSocket>,
  edge: EdgeState,
  config: &WebRtcTurnListenerConfig,
  client_addr: SocketAddr,
  packet: &[u8],
) -> anyhow::Result<()> {
  if !super::listener::turn_datagram_consumes_exact_frame(packet) {
    return Ok(());
  }
  // UDP datagram boundaries make structural parse failures attributable to
  // this untrusted packet. Drop only that packet; I/O, authentication, and
  // relay-state failures from processing a well-formed frame still propagate.
  let malformed = if packet
    .first()
    .is_some_and(|byte| byte & 0b1100_0000 == 0b0100_0000)
  {
    parse_channel_data(packet).is_err()
  } else {
    parse_stun(packet).is_err()
  };
  if malformed {
    return Ok(());
  }
  process_frame(
    edge,
    config,
    EdgeClient::Udp {
      peer: client_addr,
      local: socket.local_addr()?,
    },
    EdgeSender::Udp(socket, client_addr),
    packet,
  )
  .await
}
