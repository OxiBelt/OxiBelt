use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};

use crate::config::WebRtcTurnListenerConfig;
use crate::lifecycle::ConnectionDrain;

use super::auth::{self, AuthDecision};
use super::listener::BoxedIo;
use super::protocol::*;

const STREAM_OUTBOUND_QUEUE_CAPACITY: usize = 32;

#[derive(Clone, Default)]
pub(super) struct EdgeState {
  allocations: Arc<Mutex<HashMap<EdgeClient, EdgeAllocation>>>,
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

struct EdgeAllocation {
  relay: Arc<UdpSocket>,
  sender: EdgeSender,
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
  let (tx, mut rx) = mpsc::channel(STREAM_OUTBOUND_QUEUE_CAPACITY);
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
    let mut allocations = edge.allocations.lock().await;
    remove_expired_allocation(&mut allocations, client);
    if let Some(allocation) = allocations.get_mut(&client) {
      expire_allocation_state(allocation);
      if let Some(binding) = allocation.channels.get(&channel.channel) {
        allocation
          .relay
          .send_to(channel.payload, binding.peer)
          .await?;
      }
    }
    return Ok(());
  }
  let message = parse_stun(packet)?;
  match message.message_type {
    BINDING_REQUEST => {
      let mapped = match &sender {
        EdgeSender::Udp(_, addr) => *addr,
        EdgeSender::Stream(_) => "0.0.0.0:0".parse().expect("static socket addr"),
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
      if attr_bytes(&message, ATTR_REQUESTED_TRANSPORT).and_then(|value| value.first().copied())
        != Some(17)
      {
        send(
          &sender,
          encode_error(
            ALLOCATE_REQUEST,
            message.transaction_id,
            400,
            "Bad Request",
            None,
            None,
          ),
        )
        .await?;
        return Ok(());
      }
      let relay = bind_relay_socket(config)?;
      let relayed_addr = SocketAddr::new(
        config.public_ip.expect("validated public_ip"),
        relay.local_addr()?.port(),
      );
      let relay = Arc::new(UdpSocket::from_std(relay)?);
      edge.allocations.lock().await.insert(
        client,
        EdgeAllocation {
          relay: relay.clone(),
          sender: sender.clone(),
          transaction_id: message.transaction_id,
          permissions: HashMap::new(),
          channels: HashMap::new(),
          expires_at: Instant::now() + Duration::from_secs(600),
        },
      );
      spawn_peer_reader(edge.clone(), client, relay);
      send(
        &sender,
        encode_success(
          ALLOCATE_REQUEST,
          message.transaction_id,
          &[
            (
              ATTR_XOR_RELAYED_ADDRESS,
              encode_xor_address(relayed_addr, &message.transaction_id),
            ),
            (ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
          ],
        ),
      )
      .await?;
    }
    REFRESH_REQUEST => {
      if !auth_allows(config, &message, &sender).await? {
        return Ok(());
      }
      let lifetime = attr_u32(&message, ATTR_LIFETIME).unwrap_or(600);
      let mut allocations = edge.allocations.lock().await;
      remove_expired_allocation(&mut allocations, client);
      if lifetime == 0 {
        allocations.remove(&client);
      } else if let Some(allocation) = allocations.get_mut(&client) {
        allocation.expires_at = Instant::now() + Duration::from_secs(lifetime as u64);
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
      let Some(peer) = attr_xor_addr(&message, ATTR_XOR_PEER_ADDRESS)? else {
        send(
          &sender,
          encode_error(
            CREATE_PERMISSION_REQUEST,
            message.transaction_id,
            400,
            "Bad Request",
            None,
            None,
          ),
        )
        .await?;
        return Ok(());
      };
      let mut allocations = edge.allocations.lock().await;
      remove_expired_allocation(&mut allocations, client);
      let Some(allocation) = allocations.get_mut(&client) else {
        send_allocation_mismatch(&sender, CREATE_PERMISSION_REQUEST, message.transaction_id)
          .await?;
        return Ok(());
      };
      {
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
        send(
          &sender,
          encode_error(
            CHANNEL_BIND_REQUEST,
            message.transaction_id,
            400,
            "Bad Request",
            None,
            None,
          ),
        )
        .await?;
        return Ok(());
      };
      let Some(channel) = attr_bytes(&message, ATTR_CHANNEL_NUMBER)
        .filter(|value| value.len() >= 2)
        .map(|value| u16::from_be_bytes([value[0], value[1]]))
      else {
        send(
          &sender,
          encode_error(
            CHANNEL_BIND_REQUEST,
            message.transaction_id,
            400,
            "Bad Request",
            None,
            None,
          ),
        )
        .await?;
        return Ok(());
      };
      let mut allocations = edge.allocations.lock().await;
      remove_expired_allocation(&mut allocations, client);
      let Some(allocation) = allocations.get_mut(&client) else {
        send_allocation_mismatch(&sender, CHANNEL_BIND_REQUEST, message.transaction_id).await?;
        return Ok(());
      };
      {
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
      }
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
      let mut allocations = edge.allocations.lock().await;
      remove_expired_allocation(&mut allocations, client);
      if let Some(allocation) = allocations.get_mut(&client) {
        expire_allocation_state(allocation);
        if allocation.permissions.contains_key(&peer.ip()) {
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

fn spawn_peer_reader(edge: EdgeState, client: EdgeClient, relay: Arc<UdpSocket>) {
  tokio::spawn(async move {
    let mut buffer = vec![0u8; 65_536];
    while let Ok((len, peer)) = relay.recv_from(&mut buffer).await {
      let out = {
        let mut allocations = edge.allocations.lock().await;
        remove_expired_allocation(&mut allocations, client);
        let Some(allocation) = allocations.get_mut(&client) else {
          break;
        };
        expire_allocation_state(allocation);
        let channel = allocation
          .channels
          .iter()
          .find_map(|(channel, binding)| (binding.peer == peer).then_some(*channel));
        match channel {
          Some(channel) => encode_channel_data(channel, &buffer[..len]),
          None => encode_data_indication(allocation.transaction_id, peer, &buffer[..len]),
        }
      };
      let sender = {
        let allocations = edge.allocations.lock().await;
        allocations
          .get(&client)
          .map(|allocation| allocation.sender.clone())
      };
      if let Some(sender) = sender
        && send(&sender, out).await.is_err()
      {
        break;
      }
    }
  });
}

async fn send(sender: &EdgeSender, bytes: Vec<u8>) -> anyhow::Result<()> {
  match sender {
    EdgeSender::Udp(socket, addr) => {
      socket.send_to(&bytes, addr).await?;
    }
    EdgeSender::Stream(tx) => {
      tx.try_send(bytes).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => {
          anyhow::anyhow!("TURN stream outbound queue is full")
        }
        mpsc::error::TrySendError::Closed(_) => anyhow::anyhow!("TURN stream closed"),
      })?;
    }
  }
  Ok(())
}

fn bind_relay_socket(config: &WebRtcTurnListenerConfig) -> anyhow::Result<std::net::UdpSocket> {
  let bind_ip = config.relay_bind_ip.expect("validated relay_bind_ip");
  let range = config
    .relay_port_range
    .as_ref()
    .expect("validated relay_port_range");
  for port in range.start..=range.end {
    let bind = SocketAddr::new(bind_ip, port);
    if let Ok(socket) = bind_udp_socket(bind) {
      return Ok(socket);
    }
  }
  bail!(
    "no available TURN relay UDP ports in configured range {}..={}",
    range.start,
    range.end
  )
}

fn bind_udp_socket(bind: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  let socket = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))?;
  socket.set_reuse_address(true)?;
  socket.bind(&bind.into())?;
  let socket: std::net::UdpSocket = socket.into();
  socket.set_nonblocking(true)?;
  Ok(socket)
}

fn expire_allocation_state(allocation: &mut EdgeAllocation) {
  let now = Instant::now();
  allocation.permissions.retain(|_, expires| *expires > now);
  allocation
    .channels
    .retain(|_, binding| binding.expires_at > now);
}

fn remove_expired_allocation(
  allocations: &mut HashMap<EdgeClient, EdgeAllocation>,
  client: EdgeClient,
) {
  let expired = allocations
    .get(&client)
    .is_some_and(|allocation| allocation.expires_at <= Instant::now());
  if expired {
    allocations.remove(&client);
  }
}

async fn send_allocation_mismatch(
  sender: &EdgeSender,
  request_type: u16,
  transaction_id: [u8; 12],
) -> anyhow::Result<()> {
  send(
    sender,
    encode_error(
      request_type,
      transaction_id,
      437,
      "Allocation Mismatch",
      None,
      None,
    ),
  )
  .await
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn allocation_state_expiry_removes_permissions_and_channels() {
    let now = Instant::now();
    let mut allocation = EdgeAllocation {
      relay: Arc::new(bind_loopback_udp().await),
      sender: EdgeSender::Stream(mpsc::channel(1).0),
      transaction_id: [7; 12],
      permissions: HashMap::from([
        (
          "127.0.0.1".parse().expect("ip"),
          now - Duration::from_secs(1),
        ),
        (
          "127.0.0.2".parse().expect("ip"),
          now + Duration::from_secs(60),
        ),
      ]),
      channels: HashMap::from([
        (
          0x4000,
          EdgeChannelBinding {
            peer: "127.0.0.1:9000".parse().expect("socket addr"),
            expires_at: now - Duration::from_secs(1),
          },
        ),
        (
          0x4001,
          EdgeChannelBinding {
            peer: "127.0.0.2:9000".parse().expect("socket addr"),
            expires_at: now + Duration::from_secs(60),
          },
        ),
      ]),
      expires_at: now + Duration::from_secs(600),
    };

    expire_allocation_state(&mut allocation);

    assert_eq!(allocation.permissions.len(), 1);
    assert!(
      allocation
        .permissions
        .contains_key(&"127.0.0.2".parse().expect("ip"))
    );
    assert_eq!(allocation.channels.len(), 1);
    assert!(allocation.channels.contains_key(&0x4001));
  }

  #[tokio::test]
  async fn expired_allocation_is_removed() {
    let client = EdgeClient::Stream(1);
    let mut allocations = HashMap::from([(
      client,
      EdgeAllocation {
        relay: Arc::new(bind_loopback_udp().await),
        sender: EdgeSender::Stream(mpsc::channel(1).0),
        transaction_id: [3; 12],
        permissions: HashMap::new(),
        channels: HashMap::new(),
        expires_at: Instant::now() - Duration::from_secs(1),
      },
    )]);

    remove_expired_allocation(&mut allocations, client);

    assert!(!allocations.contains_key(&client));
  }

  async fn bind_loopback_udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0")
      .await
      .expect("bind loopback UDP")
  }

  #[tokio::test]
  async fn stream_sender_rejects_when_outbound_queue_is_full() -> anyhow::Result<()> {
    let (tx, _rx) = mpsc::channel(1);
    let sender = EdgeSender::Stream(tx);

    send(&sender, vec![1]).await?;
    let error = send(&sender, vec![2])
      .await
      .expect_err("full stream queue must reject more relay data");

    assert!(
      error
        .to_string()
        .contains("TURN stream outbound queue is full"),
      "unexpected error: {error:#}"
    );
    Ok(())
  }
}
