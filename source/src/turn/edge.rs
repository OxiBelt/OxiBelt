//! TURN edge session state.
//! Allocation state is scoped to the listener that admitted it.

mod relay;
mod request;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};

use crate::config::{TurnRelayAddressFamily, WebRtcTurnListenerConfig};
use crate::lifecycle::ConnectionDrain;

use super::auth::{self, AuthDecision};
use super::listener::BoxedIo;
use super::protocol::*;
use relay::{
  bind_relay_socket, expire_client_state, remove_expired_client_state, send,
  send_allocation_mismatch, send_turn_error, spawn_peer_reader, stream_outbound_channel,
};
use request::{
  address_family_attr, allocate_families, allocation_lifetime, peer_allowed, relay_family_config,
};

#[derive(Clone, Default)]
pub(super) struct EdgeState {
  clients: Arc<Mutex<HashMap<EdgeClient, EdgeClientState>>>,
}

impl EdgeState {
  pub(super) async fn has_udp_client(&self, client: SocketAddr) -> bool {
    self
      .clients
      .lock()
      .await
      .contains_key(&EdgeClient::Udp(client))
  }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
enum EdgeClient {
  Udp(SocketAddr),
  Stream(u64),
}

#[derive(Clone)]
enum EdgeSender {
  Udp(Arc<UdpSocket>, SocketAddr),
  Stream(mpsc::Sender<Vec<u8>>),
}

struct EdgeClientState {
  sender: EdgeSender,
  allocations: HashMap<TurnRelayAddressFamily, EdgeAllocation>,
}

struct EdgeAllocation {
  relay: Arc<UdpSocket>,
  transaction_id: [u8; 12],
  permissions: HashMap<IpAddr, Instant>,
  channels: HashMap<u16, EdgeChannelBinding>,
  expires_at: Instant,
}

struct EdgeChannelBinding {
  peer: SocketAddr,
  expires_at: Instant,
}

pub(super) async fn serve_stream(
  downstream: BoxedIo,
  stream_id: u64,
  config: WebRtcTurnListenerConfig,
  mut drain: ConnectionDrain,
  edge: EdgeState,
) -> anyhow::Result<()> {
  let (mut reader, mut writer) = tokio::io::split(downstream);
  let (tx, mut rx) = stream_outbound_channel(&config);
  let client = EdgeClient::Stream(stream_id);
  let idle = tokio::time::sleep(Duration::from_millis(config.idle_timeout_ms));
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);
  loop {
    tokio::select! {
      frame = read_turn_frame(&mut reader) => {
        let frame = frame?;
        process_frame(edge.clone(), &config, client, EdgeSender::Stream(tx.clone()), &frame).await?;
        idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(config.idle_timeout_ms));
      }
      Some(out) = rx.recv() => {
        writer.write_all(&out).await?;
      }
      _ = &mut idle => return Ok(()),
      _ = &mut drain_close => return Ok(()),
    }
  }
}

pub(super) async fn handle_udp_packet(
  socket: Arc<UdpSocket>,
  edge: EdgeState,
  config: &WebRtcTurnListenerConfig,
  client_addr: SocketAddr,
  packet: &[u8],
) -> anyhow::Result<()> {
  process_frame(
    edge,
    config,
    EdgeClient::Udp(client_addr),
    EdgeSender::Udp(socket, client_addr),
    packet,
  )
  .await
}

async fn process_frame(
  edge: EdgeState,
  config: &WebRtcTurnListenerConfig,
  client: EdgeClient,
  sender: EdgeSender,
  packet: &[u8],
) -> anyhow::Result<()> {
  if packet
    .first()
    .is_some_and(|byte| byte & 0b1100_0000 == 0b0100_0000)
  {
    let channel = parse_channel_data(packet)?;
    let mut clients = edge.clients.lock().await;
    remove_expired_client_state(&mut clients, client);
    if let Some(state) = clients.get_mut(&client) {
      state.sender = sender.clone();
      expire_client_state(state);
      for allocation in state.allocations.values_mut() {
        if let Some(binding) = allocation.channels.get(&channel.channel) {
          allocation
            .relay
            .send_to(channel.payload, binding.peer)
            .await?;
          break;
        }
      }
    }
    return Ok(());
  }
  let message = parse_stun(packet)?;
  match message.message_type {
    BINDING_REQUEST => {
      let mapped = match &sender {
        EdgeSender::Udp(_, addr) => *addr,
        EdgeSender::Stream(_) => config
          .relay_families
          .first()
          .map(|family| SocketAddr::new(family.public_ip, 0))
          .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
      };
      send(
        &sender,
        encode_success(
          BINDING_REQUEST,
          message.transaction_id,
          &[(
            ATTR_XOR_MAPPED_ADDRESS,
            encode_xor_address(mapped, &message.transaction_id),
          )],
        ),
      )
      .await?;
    }
    ALLOCATE_REQUEST => {
      if !auth_allows(config, &message, &sender).await? {
        return Ok(());
      }
      let Some(requested_transport) =
        attr_bytes(&message, ATTR_REQUESTED_TRANSPORT).and_then(|value| value.first().copied())
      else {
        send_turn_error(
          &sender,
          ALLOCATE_REQUEST,
          message.transaction_id,
          400,
          "Bad Request",
        )
        .await?;
        return Ok(());
      };
      if requested_transport != 17 {
        send_turn_error(
          &sender,
          ALLOCATE_REQUEST,
          message.transaction_id,
          442,
          "Unsupported Transport Protocol",
        )
        .await?;
        return Ok(());
      }
      let families = match allocate_families(config, &message) {
        Ok(families) => families,
        Err(error) => {
          error
            .send(&sender, ALLOCATE_REQUEST, message.transaction_id)
            .await?;
          return Ok(());
        }
      };
      let lifetime = allocation_lifetime(config, attr_u32(&message, ATTR_LIFETIME));
      let mut bound_relays = Vec::with_capacity(families.len());
      for family in families {
        let Some(relay_config) = relay_family_config(config, family) else {
          send_turn_error(
            &sender,
            ALLOCATE_REQUEST,
            message.transaction_id,
            440,
            "Address Family not Supported",
          )
          .await?;
          return Ok(());
        };
        let relay = match bind_relay_socket(relay_config) {
          Ok(relay) => relay,
          Err(_) => {
            send_turn_error(
              &sender,
              ALLOCATE_REQUEST,
              message.transaction_id,
              508,
              "Insufficient Capacity",
            )
            .await?;
            return Ok(());
          }
        };
        let relayed_addr = SocketAddr::new(relay_config.public_ip, relay.local_addr()?.port());
        bound_relays.push((family, relay, relayed_addr));
      }
      let mut response_attrs = Vec::with_capacity(bound_relays.len() + 1);
      let mut peer_readers = Vec::with_capacity(bound_relays.len());
      {
        let mut clients = edge.clients.lock().await;
        remove_expired_client_state(&mut clients, client);
        let total_allocations = clients
          .values()
          .map(|state| state.allocations.len())
          .sum::<usize>();
        let client_allocations = clients
          .get(&client)
          .map(|state| state.allocations.len())
          .unwrap_or(0);
        if total_allocations + bound_relays.len() > config.limits.max_allocations_per_listener {
          send_turn_error(
            &sender,
            ALLOCATE_REQUEST,
            message.transaction_id,
            508,
            "Insufficient Capacity",
          )
          .await?;
          return Ok(());
        }
        if client_allocations + bound_relays.len() > config.limits.max_allocations_per_client {
          send_turn_error(
            &sender,
            ALLOCATE_REQUEST,
            message.transaction_id,
            486,
            "Allocation Quota Reached",
          )
          .await?;
          return Ok(());
        }
        let state = clients.entry(client).or_insert_with(|| EdgeClientState {
          sender: sender.clone(),
          allocations: HashMap::new(),
        });
        state.sender = sender.clone();
        if bound_relays
          .iter()
          .any(|(family, _, _)| state.allocations.contains_key(family))
        {
          send_allocation_mismatch(&sender, ALLOCATE_REQUEST, message.transaction_id).await?;
          return Ok(());
        }
        for (family, relay, relayed_addr) in bound_relays {
          let relay = Arc::new(UdpSocket::from_std(relay)?);
          response_attrs.push((
            ATTR_XOR_RELAYED_ADDRESS,
            encode_xor_address(relayed_addr, &message.transaction_id),
          ));
          peer_readers.push((family, relay.clone()));
          state.allocations.insert(
            family,
            EdgeAllocation {
              relay,
              transaction_id: message.transaction_id,
              permissions: HashMap::new(),
              channels: HashMap::new(),
              expires_at: Instant::now() + Duration::from_secs(u64::from(lifetime)),
            },
          );
        }
      }
      response_attrs.push((ATTR_LIFETIME, lifetime.to_be_bytes().to_vec()));
      for (family, relay) in peer_readers {
        spawn_peer_reader(edge.clone(), client, family, relay);
      }
      send(
        &sender,
        encode_success(ALLOCATE_REQUEST, message.transaction_id, &response_attrs),
      )
      .await?;
    }
    REFRESH_REQUEST => {
      if !auth_allows(config, &message, &sender).await? {
        return Ok(());
      }
      let requested_family = match address_family_attr(&message, ATTR_REQUESTED_ADDRESS_FAMILY) {
        Ok(family) => family,
        Err(error) => {
          error
            .send(&sender, REFRESH_REQUEST, message.transaction_id)
            .await?;
          return Ok(());
        }
      };
      let requested_lifetime = attr_u32(&message, ATTR_LIFETIME);
      let lifetime = allocation_lifetime(config, requested_lifetime);
      let mut clients = edge.clients.lock().await;
      remove_expired_client_state(&mut clients, client);
      let Some(state) = clients.get_mut(&client) else {
        send_allocation_mismatch(&sender, REFRESH_REQUEST, message.transaction_id).await?;
        return Ok(());
      };
      expire_client_state(state);
      let families = if let Some(family) = requested_family {
        if !state.allocations.contains_key(&family) {
          send_turn_error(
            &sender,
            REFRESH_REQUEST,
            message.transaction_id,
            443,
            "Peer Address Family Mismatch",
          )
          .await?;
          return Ok(());
        }
        vec![family]
      } else {
        state.allocations.keys().copied().collect::<Vec<_>>()
      };
      if requested_lifetime == Some(0) {
        for family in families {
          state.allocations.remove(&family);
        }
      } else {
        for family in families {
          if let Some(allocation) = state.allocations.get_mut(&family) {
            allocation.expires_at = Instant::now() + Duration::from_secs(u64::from(lifetime));
          }
        }
      }
      if state.allocations.is_empty() {
        clients.remove(&client);
      }
      send(
        &sender,
        encode_success(
          REFRESH_REQUEST,
          message.transaction_id,
          &[(ATTR_LIFETIME, lifetime.to_be_bytes().to_vec())],
        ),
      )
      .await?;
    }
    CREATE_PERMISSION_REQUEST => {
      if !auth_allows(config, &message, &sender).await? {
        return Ok(());
      }
      let peers = attr_xor_addrs(&message, ATTR_XOR_PEER_ADDRESS)?;
      if peers.is_empty() {
        send_turn_error(
          &sender,
          CREATE_PERMISSION_REQUEST,
          message.transaction_id,
          400,
          "Bad Request",
        )
        .await?;
        return Ok(());
      }
      if peers
        .iter()
        .any(|peer| !peer_allowed(peer.ip(), &config.peer_policy))
      {
        send_turn_error(
          &sender,
          CREATE_PERMISSION_REQUEST,
          message.transaction_id,
          403,
          "Forbidden",
        )
        .await?;
        return Ok(());
      }
      let mut clients = edge.clients.lock().await;
      remove_expired_client_state(&mut clients, client);
      let Some(state) = clients.get_mut(&client) else {
        send_allocation_mismatch(&sender, CREATE_PERMISSION_REQUEST, message.transaction_id)
          .await?;
        return Ok(());
      };
      expire_client_state(state);
      for peer in peers {
        let family = TurnRelayAddressFamily::from_ip(peer.ip());
        let Some(allocation) = state.allocations.get_mut(&family) else {
          send_turn_error(
            &sender,
            CREATE_PERMISSION_REQUEST,
            message.transaction_id,
            443,
            "Peer Address Family Mismatch",
          )
          .await?;
          return Ok(());
        };
        if !allocation.permissions.contains_key(&peer.ip())
          && allocation.permissions.len() >= config.limits.max_permissions_per_allocation
        {
          send_turn_error(
            &sender,
            CREATE_PERMISSION_REQUEST,
            message.transaction_id,
            508,
            "Insufficient Capacity",
          )
          .await?;
          return Ok(());
        }
        allocation
          .permissions
          .insert(peer.ip(), Instant::now() + Duration::from_secs(300));
      }
      send(
        &sender,
        encode_success(CREATE_PERMISSION_REQUEST, message.transaction_id, &[]),
      )
      .await?;
    }
    CHANNEL_BIND_REQUEST => {
      if !auth_allows(config, &message, &sender).await? {
        return Ok(());
      }
      let Some(peer) = attr_xor_addr(&message, ATTR_XOR_PEER_ADDRESS)? else {
        send_turn_error(
          &sender,
          CHANNEL_BIND_REQUEST,
          message.transaction_id,
          400,
          "Bad Request",
        )
        .await?;
        return Ok(());
      };
      if !peer_allowed(peer.ip(), &config.peer_policy) {
        send_turn_error(
          &sender,
          CHANNEL_BIND_REQUEST,
          message.transaction_id,
          403,
          "Forbidden",
        )
        .await?;
        return Ok(());
      }
      let Some(channel) = attr_bytes(&message, ATTR_CHANNEL_NUMBER)
        .filter(|value| value.len() >= 2)
        .map(|value| u16::from_be_bytes([value[0], value[1]]))
      else {
        send_turn_error(
          &sender,
          CHANNEL_BIND_REQUEST,
          message.transaction_id,
          400,
          "Bad Request",
        )
        .await?;
        return Ok(());
      };
      if !(0x4000..=0x7fff).contains(&channel) {
        send_turn_error(
          &sender,
          CHANNEL_BIND_REQUEST,
          message.transaction_id,
          400,
          "Bad Request",
        )
        .await?;
        return Ok(());
      }
      let mut clients = edge.clients.lock().await;
      remove_expired_client_state(&mut clients, client);
      let Some(state) = clients.get_mut(&client) else {
        send_allocation_mismatch(&sender, CHANNEL_BIND_REQUEST, message.transaction_id).await?;
        return Ok(());
      };
      expire_client_state(state);
      let family = TurnRelayAddressFamily::from_ip(peer.ip());
      let Some(allocation) = state.allocations.get_mut(&family) else {
        send_turn_error(
          &sender,
          CHANNEL_BIND_REQUEST,
          message.transaction_id,
          443,
          "Peer Address Family Mismatch",
        )
        .await?;
        return Ok(());
      };
      if !allocation.permissions.contains_key(&peer.ip())
        && allocation.permissions.len() >= config.limits.max_permissions_per_allocation
      {
        send_turn_error(
          &sender,
          CHANNEL_BIND_REQUEST,
          message.transaction_id,
          508,
          "Insufficient Capacity",
        )
        .await?;
        return Ok(());
      }
      if !allocation.channels.contains_key(&channel)
        && allocation.channels.len() >= config.limits.max_channels_per_allocation
      {
        send_turn_error(
          &sender,
          CHANNEL_BIND_REQUEST,
          message.transaction_id,
          508,
          "Insufficient Capacity",
        )
        .await?;
        return Ok(());
      }
      allocation
        .permissions
        .insert(peer.ip(), Instant::now() + Duration::from_secs(300));
      allocation.channels.insert(
        channel,
        EdgeChannelBinding {
          peer,
          expires_at: Instant::now() + Duration::from_secs(600),
        },
      );
      send(
        &sender,
        encode_success(CHANNEL_BIND_REQUEST, message.transaction_id, &[]),
      )
      .await?;
    }
    SEND_INDICATION => {
      let Some(peer) = attr_xor_addr(&message, ATTR_XOR_PEER_ADDRESS)? else {
        return Ok(());
      };
      let data = attr_bytes(&message, ATTR_DATA).unwrap_or_default();
      let mut clients = edge.clients.lock().await;
      remove_expired_client_state(&mut clients, client);
      if let Some(state) = clients.get_mut(&client) {
        expire_client_state(state);
        let family = TurnRelayAddressFamily::from_ip(peer.ip());
        if let Some(allocation) = state.allocations.get_mut(&family)
          && allocation.permissions.contains_key(&peer.ip())
        {
          allocation.relay.send_to(data, peer).await?;
        }
      }
    }
    _ => {
      send(
        &sender,
        encode_error(
          message.message_type,
          message.transaction_id,
          400,
          "Bad Request",
          None,
          None,
        ),
      )
      .await?;
    }
  }
  Ok(())
}

async fn auth_allows(
  config: &WebRtcTurnListenerConfig,
  message: &StunMessage<'_>,
  sender: &EdgeSender,
) -> anyhow::Result<bool> {
  match auth::enforce_message(&config.auth, &config.realm, message)? {
    AuthDecision::Pass => Ok(true),
    AuthDecision::Missing => {
      let nonce = auth::create_nonce(&config.realm, &config.auth)?;
      send(
        sender,
        encode_error(
          message.message_type,
          message.transaction_id,
          401,
          "Unauthorized",
          Some(&config.realm),
          Some(&nonce),
        ),
      )
      .await?;
      Ok(false)
    }
    AuthDecision::Invalid => {
      let nonce = auth::create_nonce(&config.realm, &config.auth)?;
      send(
        sender,
        encode_error(
          message.message_type,
          message.transaction_id,
          438,
          "Stale Nonce",
          Some(&config.realm),
          Some(&nonce),
        ),
      )
      .await?;
      Ok(false)
    }
  }
}
