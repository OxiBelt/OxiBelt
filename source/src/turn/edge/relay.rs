//! TURN edge relay socket and allocation-state helpers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::bail;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::config::{TurnRelayAddressFamily, TurnRelayFamilyConfig, WebRtcTurnListenerConfig};

use super::super::protocol::{encode_channel_data, encode_data_indication, encode_error};
use super::{EdgeAllocation, EdgeClient, EdgeClientState, EdgeSender, EdgeState};

pub(super) fn stream_outbound_channel(
  config: &WebRtcTurnListenerConfig,
) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
  mpsc::channel(config.stream_outbound_queue_capacity)
}

pub(super) fn spawn_peer_reader(
  edge: EdgeState,
  client: EdgeClient,
  family: TurnRelayAddressFamily,
  relay: Arc<UdpSocket>,
) {
  tokio::spawn(async move {
    let mut buffer = vec![0u8; 65_536];
    while let Ok((len, peer)) = relay.recv_from(&mut buffer).await {
      let out = {
        let mut clients = edge.clients.lock().await;
        remove_expired_client_state(&mut clients, client);
        let Some(state) = clients.get_mut(&client) else {
          break;
        };
        let Some(allocation) = state.allocations.get_mut(&family) else {
          break;
        };
        expire_allocation_state(allocation);
        if !allocation.permissions.contains_key(&peer.ip()) {
          continue;
        }
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
        let clients = edge.clients.lock().await;
        clients.get(&client).map(|state| state.sender.clone())
      };
      if let Some(sender) = sender
        && send(&sender, out).await.is_err()
      {
        break;
      }
    }
  });
}

pub(super) async fn send(sender: &EdgeSender, bytes: Vec<u8>) -> anyhow::Result<()> {
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

pub(super) fn bind_relay_socket(
  config: &TurnRelayFamilyConfig,
) -> anyhow::Result<std::net::UdpSocket> {
  for port in config.relay_port_range.start..=config.relay_port_range.end {
    let bind = SocketAddr::new(config.relay_bind_ip, port);
    if let Ok(socket) = bind_udp_socket(bind) {
      return Ok(socket);
    }
  }
  bail!(
    "no available TURN relay UDP ports in configured range {}..={}",
    config.relay_port_range.start,
    config.relay_port_range.end
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

pub(super) fn expire_allocation_state(allocation: &mut EdgeAllocation) {
  let now = Instant::now();
  allocation.permissions.retain(|_, expires| *expires > now);
  allocation
    .channels
    .retain(|_, binding| binding.expires_at > now);
}

pub(super) fn expire_client_state(state: &mut EdgeClientState) {
  for allocation in state.allocations.values_mut() {
    expire_allocation_state(allocation);
  }
  let now = Instant::now();
  state
    .allocations
    .retain(|_, allocation| allocation.expires_at > now);
}

pub(super) fn remove_expired_client_state(
  clients: &mut HashMap<EdgeClient, EdgeClientState>,
  client: EdgeClient,
) {
  if let Some(state) = clients.get_mut(&client) {
    expire_client_state(state);
    if state.allocations.is_empty() {
      clients.remove(&client);
    }
  }
}

pub(super) async fn send_allocation_mismatch(
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

pub(super) async fn send_turn_error(
  sender: &EdgeSender,
  request_type: u16,
  transaction_id: [u8; 12],
  code: u16,
  reason: &str,
) -> anyhow::Result<()> {
  send(
    sender,
    encode_error(request_type, transaction_id, code, reason, None, None),
  )
  .await
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use crate::config::{
    TurnAuthConfig, TurnEdgeRelayLimitsConfig, TurnEdgeRelayPeerPolicyConfig,
    TurnListenerTlsConfig, TurnRelayPortRange, WebRtcTurnListenerMode,
  };

  use super::super::{EdgeChannelBinding, EdgeSender};
  use super::*;

  #[tokio::test]
  async fn allocation_state_expiry_removes_permissions_and_channels() {
    let now = Instant::now();
    let mut allocation = EdgeAllocation {
      relay: Arc::new(bind_loopback_udp().await),
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
    let mut clients = HashMap::from([(
      client,
      EdgeClientState {
        sender: EdgeSender::Stream(mpsc::channel(1).0),
        allocations: HashMap::from([(
          TurnRelayAddressFamily::Ipv4,
          EdgeAllocation {
            relay: Arc::new(bind_loopback_udp().await),
            transaction_id: [3; 12],
            permissions: HashMap::new(),
            channels: HashMap::new(),
            expires_at: Instant::now() - Duration::from_secs(1),
          },
        )]),
      },
    )]);

    remove_expired_client_state(&mut clients, client);

    assert!(!clients.contains_key(&client));
  }

  #[test]
  fn stream_outbound_channel_uses_configured_capacity() {
    let config = edge_relay_config_with_stream_queue_capacity(2);
    let (tx, _rx) = stream_outbound_channel(&config);

    tx.try_send(vec![1]).expect("first queued frame should fit");
    tx.try_send(vec![2])
      .expect("second queued frame should fit");
    let error = tx
      .try_send(vec![3])
      .expect_err("configured stream queue capacity should be enforced");

    assert!(matches!(error, mpsc::error::TrySendError::Full(_)));
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

  async fn bind_loopback_udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0")
      .await
      .expect("bind loopback UDP")
  }

  fn edge_relay_config_with_stream_queue_capacity(
    stream_outbound_queue_capacity: usize,
  ) -> WebRtcTurnListenerConfig {
    WebRtcTurnListenerConfig {
      name: "edge-relay".to_string(),
      mode: WebRtcTurnListenerMode::EdgeRelay,
      bind_udp: None,
      bind_tcp: Some("127.0.0.1:0".parse().expect("socket addr")),
      bind_tls: None,
      idle_timeout_ms: 75_000,
      realm: "example.test".to_string(),
      auth: TurnAuthConfig::default(),
      udp_pool: None,
      tcp_pool: None,
      tls_pool: None,
      public_ip: Some("127.0.0.1".parse().expect("ip addr")),
      relay_bind_ip: Some("127.0.0.1".parse().expect("ip addr")),
      relay_port_range: Some(TurnRelayPortRange {
        start: 49152,
        end: 49160,
      }),
      relay_families: vec![TurnRelayFamilyConfig {
        family: TurnRelayAddressFamily::Ipv4,
        public_ip: "127.0.0.1".parse().expect("ip addr"),
        relay_bind_ip: "127.0.0.1".parse().expect("ip addr"),
        relay_port_range: TurnRelayPortRange {
          start: 49152,
          end: 49160,
        },
      }],
      limits: TurnEdgeRelayLimitsConfig::default(),
      peer_policy: TurnEdgeRelayPeerPolicyConfig {
        allow_loopback_peers: true,
        ..TurnEdgeRelayPeerPolicyConfig::default()
      },
      stream_outbound_queue_capacity,
      tls: TurnListenerTlsConfig::default(),
    }
  }
}
