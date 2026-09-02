//! RFC 6062 TURN TCP allocation and data-connection lifecycle.

use std::collections::{HashMap, hash_map::Entry};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
use tokio::net::TcpListener;
use tokio::net::{TcpSocket, TcpStream};

use super::*;

const PENDING_LIFETIME: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct PendingTcpConnection {
  pub(super) stream: Option<TcpStream>,
  pub(super) peer: SocketAddr,
  pub(super) expires_at: Instant,
}

pub(super) struct BoundTcpConnection {
  pub(super) peer: TcpStream,
  pub(super) owner: EdgeClient,
  pub(super) family: TurnRelayAddressFamily,
  pub(super) connection_id: u32,
}

pub(super) enum ConnectionBindOutcome {
  Bound {
    connection: BoundTcpConnection,
    response: Vec<u8>,
  },
  Rejected(Vec<u8>),
}

pub(super) async fn handle_connect_request(
  edge: &EdgeState,
  config: &WebRtcTurnListenerConfig,
  client: EdgeClient,
  sender: &EdgeSender,
  message: &StunMessage<'_>,
  request_auth: &Arc<AuthenticatedContext>,
) -> anyhow::Result<()> {
  if !client.is_stream() {
    return send_authenticated_error(
      sender,
      request_auth,
      CONNECT_REQUEST,
      message.transaction_id,
      400,
      "Bad Request",
    )
    .await;
  }
  let peer = match singleton_xor_addr(message, ATTR_XOR_PEER_ADDRESS) {
    Ok(Some(peer)) => peer,
    Ok(None) | Err(_) => {
      return send_authenticated_error(
        sender,
        request_auth,
        CONNECT_REQUEST,
        message.transaction_id,
        400,
        "Bad Request",
      )
      .await;
    }
  };
  if !peer_allowed(peer.ip(), &config.peer_policy) {
    return send_authenticated_error(
      sender,
      request_auth,
      CONNECT_REQUEST,
      message.transaction_id,
      403,
      "Forbidden",
    )
    .await;
  }
  let family = TurnRelayAddressFamily::from_ip(peer.ip());
  let reservation = 'reservation: {
    let mut clients = edge.clients.lock().await;
    remove_expired_client_state(&mut clients, client);
    let pending_count = pending_connection_count(&clients);
    let connection_id = match next_connection_id(&clients) {
      Ok(connection_id) => connection_id,
      Err(_) => {
        break 'reservation Err(EdgeRequestFailure::Turn(508, "Insufficient Capacity"));
      }
    };
    let Some(state) = clients.get_mut(&client) else {
      break 'reservation Err(EdgeRequestFailure::AllocationMismatch);
    };
    let Some(allocation) = state.allocations.get_mut(&family) else {
      break 'reservation Err(EdgeRequestFailure::AllocationMismatch);
    };
    if allocation.auth.username() != request_auth.username() {
      Err(EdgeRequestFailure::Turn(441, "Wrong Credentials"))
    } else if !matches!(allocation.relay, EdgeRelay::Tcp(_)) {
      Err(EdgeRequestFailure::AllocationMismatch)
    } else if !allocation.permissions.contains_key(&peer.ip()) {
      Err(EdgeRequestFailure::Turn(403, "Forbidden"))
    } else if peer_has_connection(allocation, peer) {
      Err(EdgeRequestFailure::Turn(446, "Connection Already Exists"))
    } else if pending_count >= config.limits.max_pending_tcp_connections {
      Err(EdgeRequestFailure::Turn(508, "Insufficient Capacity"))
    } else {
      let relay_addr = match &allocation.relay {
        EdgeRelay::Tcp(relay) => match relay.local_addr() {
          Ok(relay_addr) => relay_addr,
          Err(_) => break 'reservation Err(EdgeRequestFailure::Turn(508, "Insufficient Capacity")),
        },
        EdgeRelay::Udp(_) => break 'reservation Err(EdgeRequestFailure::AllocationMismatch),
      };
      allocation.pending_tcp.insert(
        connection_id,
        PendingTcpConnection {
          stream: None,
          peer,
          expires_at: Instant::now() + PENDING_LIFETIME,
        },
      );
      Ok((connection_id, relay_addr))
    }
  };
  let (connection_id, relay_addr) = match reservation {
    Ok(reservation) => reservation,
    Err(failure) => {
      return failure
        .send(
          sender,
          CONNECT_REQUEST,
          message.transaction_id,
          request_auth,
        )
        .await;
    }
  };

  let stream =
    match tokio::time::timeout(CONNECT_TIMEOUT, connect_from_relay(relay_addr, peer)).await {
      Ok(Ok(stream)) => stream,
      Ok(Err(_)) | Err(_) => {
        remove_pending_connection(edge, client, family, connection_id).await;
        return send_authenticated_error(
          sender,
          request_auth,
          CONNECT_REQUEST,
          message.transaction_id,
          447,
          "Connection Timeout or Failure",
        )
        .await;
      }
    };
  let installed = {
    let mut clients = edge.clients.lock().await;
    clients
      .get_mut(&client)
      .and_then(|state| state.allocations.get_mut(&family))
      .and_then(|allocation| allocation.pending_tcp.get_mut(&connection_id))
      .is_some_and(|pending| {
        pending.stream = Some(stream);
        true
      })
  };
  if !installed {
    return send_authenticated_error(
      sender,
      request_auth,
      CONNECT_REQUEST,
      message.transaction_id,
      447,
      "Connection Timeout or Failure",
    )
    .await;
  }
  send(
    sender,
    encode_authenticated_success(
      request_auth,
      CONNECT_REQUEST,
      message.transaction_id,
      &[(ATTR_CONNECTION_ID, connection_id.to_be_bytes().to_vec())],
    ),
  )
  .await
}

pub(super) async fn handle_connection_bind(
  edge: &EdgeState,
  config: &WebRtcTurnListenerConfig,
  client: EdgeClient,
  packet: &[u8],
) -> anyhow::Result<ConnectionBindOutcome> {
  let message = parse_stun(packet)?;
  let request_auth = match request_authentication(config, &message, client)? {
    RequestAuthentication::Pass(context) => context,
    RequestAuthentication::Challenge(response) => {
      return Ok(ConnectionBindOutcome::Rejected(response));
    }
  };
  let unknown = unknown_required_attributes(&message);
  if !unknown.is_empty() {
    return Ok(ConnectionBindOutcome::Rejected(
      encode_unknown_attribute_error(&message, &unknown, Some(&request_auth)),
    ));
  }
  let connection_id_attrs = semantic_attributes(&message)
    .iter()
    .filter(|attr| attr.kind == ATTR_CONNECTION_ID)
    .count();
  let Some(connection_id) = (connection_id_attrs == 1)
    .then(|| attr_u32(&message, ATTR_CONNECTION_ID))
    .flatten()
  else {
    return Ok(ConnectionBindOutcome::Rejected(encode_authenticated_error(
      &request_auth,
      CONNECTION_BIND_REQUEST,
      message.transaction_id,
      400,
      "Bad Request",
    )));
  };
  let bound = {
    let mut clients = edge.clients.lock().await;
    remove_all_expired_client_state(&mut clients);
    let mut found = None;
    for (owner, state) in clients.iter_mut() {
      for (family, allocation) in &mut state.allocations {
        let Entry::Occupied(entry) = allocation.pending_tcp.entry(connection_id) else {
          continue;
        };
        if !allocation.auth.has_same_credentials(&request_auth) {
          found = Some(Err(EdgeRequestFailure::Turn(441, "Wrong Credentials")));
        } else {
          let pending = entry.remove();
          found = Some(match pending.stream {
            Some(stream) => {
              allocation.active_tcp.insert(connection_id, pending.peer);
              Ok(BoundTcpConnection {
                peer: stream,
                owner: *owner,
                family: *family,
                connection_id,
              })
            }
            None => Err(EdgeRequestFailure::Turn(
              447,
              "Connection Timeout or Failure",
            )),
          });
        }
        break;
      }
      if found.is_some() {
        break;
      }
    }
    found.unwrap_or(Err(EdgeRequestFailure::Turn(400, "Bad Request")))
  };
  match bound {
    Ok(connection) => Ok(ConnectionBindOutcome::Bound {
      connection,
      response: encode_authenticated_success(
        &request_auth,
        CONNECTION_BIND_REQUEST,
        message.transaction_id,
        &[],
      ),
    }),
    Err(failure) => {
      let (code, reason) = match failure {
        EdgeRequestFailure::AllocationMismatch => (437, "Allocation Mismatch"),
        EdgeRequestFailure::Turn(code, reason) => (code, reason),
      };
      Ok(ConnectionBindOutcome::Rejected(encode_authenticated_error(
        &request_auth,
        CONNECTION_BIND_REQUEST,
        message.transaction_id,
        code,
        reason,
      )))
    }
  }
}

pub(super) fn spawn_tcp_peer_acceptor(
  edge: EdgeState,
  owner: EdgeClient,
  family: TurnRelayAddressFamily,
  relay: Arc<EdgeTcpRelay>,
  config: WebRtcTurnListenerConfig,
) {
  tokio::spawn(async move {
    loop {
      let accepted = tokio::time::timeout(Duration::from_secs(1), relay.accept()).await;
      let (stream, peer) = match accepted {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(_)) => break,
        Err(_) => {
          if !allocation_exists(&edge, owner, family).await {
            break;
          }
          continue;
        }
      };
      if !peer_allowed(peer.ip(), &config.peer_policy) {
        continue;
      }
      let admitted = {
        let mut clients = edge.clients.lock().await;
        remove_expired_client_state(&mut clients, owner);
        let pending_count = pending_connection_count(&clients);
        let connection_id = next_connection_id(&clients).ok();
        let Some(state) = clients.get_mut(&owner) else {
          break;
        };
        let sender = state.sender.clone();
        let Some(allocation) = state.allocations.get_mut(&family) else {
          break;
        };
        if !allocation.permissions.contains_key(&peer.ip())
          || peer_has_connection(allocation, peer)
          || pending_count >= config.limits.max_pending_tcp_connections
        {
          None
        } else if let Some(connection_id) = connection_id {
          allocation.pending_tcp.insert(
            connection_id,
            PendingTcpConnection {
              stream: Some(stream),
              peer,
              expires_at: Instant::now() + PENDING_LIFETIME,
            },
          );
          Some((connection_id, sender, allocation.auth.clone()))
        } else {
          None
        }
      };
      let Some((connection_id, sender, allocation_auth)) = admitted else {
        continue;
      };
      let mut transaction_id = [0u8; 12];
      if crate::crypto::random_fill(&mut transaction_id).is_err() {
        remove_pending_connection(&edge, owner, family, connection_id).await;
        continue;
      }
      let indication = with_fingerprint(allocation_auth.with_response_integrity(encode_message(
        CONNECTION_ATTEMPT_INDICATION,
        transaction_id,
        &[
          (ATTR_CONNECTION_ID, connection_id.to_be_bytes().to_vec()),
          (
            ATTR_XOR_PEER_ADDRESS,
            encode_xor_address(peer, &transaction_id),
          ),
        ],
      )));
      if send(&sender, indication).await.is_err() {
        remove_pending_connection(&edge, owner, family, connection_id).await;
      }
    }
  });
}

pub(super) async fn relay_bound_tcp_connection(
  downstream: BoxedIo,
  edge: EdgeState,
  connection: BoundTcpConnection,
  drain: ConnectionDrain,
  idle_timeout: Duration,
) -> anyhow::Result<()> {
  let BoundTcpConnection {
    peer,
    owner,
    family,
    connection_id,
  } = connection;
  let relay = super::super::listener::copy_bidirectional_with_idle(
    downstream,
    Box::new(peer),
    idle_timeout,
    drain,
  );
  tokio::pin!(relay);
  let mut interval = tokio::time::interval(Duration::from_millis(250));
  interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
  loop {
    tokio::select! {
      result = &mut relay => {
        release_active_connection(&edge, owner, family, connection_id).await;
        return result;
      }
      _ = interval.tick() => {
        if !active_connection_exists(&edge, owner, family, connection_id).await {
          release_active_connection(&edge, owner, family, connection_id).await;
          return Ok(());
        }
      }
    }
  }
}

async fn allocation_exists(
  edge: &EdgeState,
  owner: EdgeClient,
  family: TurnRelayAddressFamily,
) -> bool {
  let mut clients = edge.clients.lock().await;
  remove_expired_client_state(&mut clients, owner);
  clients
    .get(&owner)
    .and_then(|state| state.allocations.get(&family))
    .is_some_and(|allocation| matches!(allocation.relay, EdgeRelay::Tcp(_)))
}

async fn active_connection_exists(
  edge: &EdgeState,
  owner: EdgeClient,
  family: TurnRelayAddressFamily,
  connection_id: u32,
) -> bool {
  let mut clients = edge.clients.lock().await;
  remove_expired_client_state(&mut clients, owner);
  clients
    .get(&owner)
    .and_then(|state| state.allocations.get(&family))
    .is_some_and(|allocation| allocation.active_tcp.contains_key(&connection_id))
}

pub(super) async fn release_active_connection(
  edge: &EdgeState,
  owner: EdgeClient,
  family: TurnRelayAddressFamily,
  connection_id: u32,
) {
  let mut clients = edge.clients.lock().await;
  if let Some(allocation) = clients
    .get_mut(&owner)
    .and_then(|state| state.allocations.get_mut(&family))
  {
    allocation.active_tcp.remove(&connection_id);
  }
}

async fn remove_pending_connection(
  edge: &EdgeState,
  owner: EdgeClient,
  family: TurnRelayAddressFamily,
  connection_id: u32,
) {
  let mut clients = edge.clients.lock().await;
  if let Some(allocation) = clients
    .get_mut(&owner)
    .and_then(|state| state.allocations.get_mut(&family))
  {
    allocation.pending_tcp.remove(&connection_id);
  }
}

fn pending_connection_count(clients: &HashMap<EdgeClient, EdgeClientState>) -> usize {
  clients
    .values()
    .flat_map(|state| state.allocations.values())
    .map(|allocation| allocation.pending_tcp.len() + allocation.active_tcp.len())
    .sum()
}

fn peer_has_connection(allocation: &EdgeAllocation, peer: SocketAddr) -> bool {
  allocation
    .pending_tcp
    .values()
    .any(|pending| pending.peer == peer)
    || allocation
      .active_tcp
      .values()
      .any(|active_peer| *active_peer == peer)
}

fn next_connection_id(clients: &HashMap<EdgeClient, EdgeClientState>) -> anyhow::Result<u32> {
  for _ in 0..32 {
    let mut bytes = [0u8; 4];
    crate::crypto::random_fill(&mut bytes)
      .map_err(|_| anyhow::anyhow!("TURN TCP connection ID generation failed"))?;
    let candidate = u32::from_be_bytes(bytes);
    let collision = clients.values().any(|state| {
      state.allocations.values().any(|allocation| {
        allocation.pending_tcp.contains_key(&candidate)
          || allocation.active_tcp.contains_key(&candidate)
      })
    });
    if !collision {
      return Ok(candidate);
    }
  }
  anyhow::bail!("TURN TCP connection ID space unavailable")
}

async fn connect_from_relay(
  relay_addr: SocketAddr,
  peer: SocketAddr,
) -> std::io::Result<TcpStream> {
  let socket = if relay_addr.is_ipv4() {
    TcpSocket::new_v4()?
  } else {
    TcpSocket::new_v6()?
  };
  socket.set_reuseaddr(true)?;
  #[cfg(unix)]
  socket2::SockRef::from(&socket).set_reuse_port(true)?;
  socket.bind(relay_addr)?;
  socket.connect(peer).await
}

#[cfg(test)]
pub(super) mod tests {
  use std::net::Ipv4Addr;

  use super::*;

  use sha2::{Digest, Sha256};

  use crate::config::{
    TurnAuthConfig, TurnAuthMode, TurnEdgeRelayLimitsConfig, TurnEdgeRelayPeerPolicyConfig,
    TurnListenerTlsConfig, TurnPasswordAlgorithm, TurnRelayFamilyConfig, TurnRelayPortRange,
    TurnStaticCredentialConfig, WebRtcTurnListenerMode,
  };

  const TEST_USERNAME: &str = "test-user";
  const TEST_PASSWORD: &str = "test-password";
  const TEST_REALM: &str = "example.test";

  pub(in crate::turn::edge) fn test_authenticated_context() -> Arc<AuthenticatedContext> {
    test_authenticated_context_with_password("test-password")
  }

  pub(in crate::turn::edge) fn test_authenticated_context_with_password(
    password: &str,
  ) -> Arc<AuthenticatedContext> {
    let auth = TurnAuthConfig {
      mode: TurnAuthMode::Enforce,
      static_credentials: vec![TurnStaticCredentialConfig {
        username: TEST_USERNAME.to_string(),
        password: Some(password.to_string()),
        password_env: None,
        password_file: None,
      }],
      password_algorithms: vec![TurnPasswordAlgorithm::Sha256],
      ..TurnAuthConfig::default()
    };
    let key = Sha256::digest(format!("{TEST_USERNAME}:{TEST_REALM}:{password}").as_bytes());
    let password_algorithms = crate::turn::auth::password_algorithms_challenge_attribute(&auth);
    let raw = crate::turn::protocol::with_message_integrity_sha256(
      encode_message(
        ALLOCATE_REQUEST,
        [1; 12],
        &[
          (ATTR_USERNAME, TEST_USERNAME.as_bytes().to_vec()),
          (ATTR_REALM, TEST_REALM.as_bytes().to_vec()),
          password_algorithms,
          (ATTR_PASSWORD_ALGORITHM, vec![0, 2, 0, 0]),
        ],
      ),
      &key,
    );
    let message = parse_stun(&raw).expect("authenticated test message");
    let AuthenticatedContextDecision::Pass(context) =
      auth::authenticated_context_for_source(&auth, TEST_REALM, None, &message)
        .expect("test authentication must be evaluated")
    else {
      panic!("test credentials must authenticate");
    };
    Arc::new(context)
  }

  fn connection_bind_config() -> WebRtcTurnListenerConfig {
    WebRtcTurnListenerConfig {
      name: "tcp-bind-test".to_string(),
      mode: WebRtcTurnListenerMode::EdgeRelay,
      bind_udp: None,
      bind_udp_additional: Vec::new(),
      bind_tcp: Some(SocketAddr::from(([127, 0, 0, 1], 3478))),
      bind_tcp_additional: Vec::new(),
      bind_tls: None,
      bind_tls_additional: Vec::new(),
      idle_timeout_ms: 75_000,
      realm: TEST_REALM.to_string(),
      auth: TurnAuthConfig {
        mode: TurnAuthMode::Enforce,
        static_credentials: vec![TurnStaticCredentialConfig {
          username: TEST_USERNAME.to_string(),
          password: Some(TEST_PASSWORD.to_string()),
          password_env: None,
          password_file: None,
        }],
        password_algorithms: vec![TurnPasswordAlgorithm::Sha256],
        ..TurnAuthConfig::default()
      },
      udp_pool: None,
      tcp_pool: None,
      tls_pool: None,
      public_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
      relay_bind_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
      relay_port_range: Some(TurnRelayPortRange {
        start: 49_152,
        end: 49_160,
      }),
      relay_families: vec![TurnRelayFamilyConfig {
        family: TurnRelayAddressFamily::Ipv4,
        public_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        relay_bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        relay_port_range: TurnRelayPortRange {
          start: 49_152,
          end: 49_160,
        },
      }],
      limits: TurnEdgeRelayLimitsConfig::default(),
      peer_policy: TurnEdgeRelayPeerPolicyConfig::default(),
      stream_outbound_queue_capacity: 32,
      tls: TurnListenerTlsConfig::default(),
    }
  }

  fn authenticated_connection_bind(
    config: &WebRtcTurnListenerConfig,
    client: EdgeClient,
    connection_id: u32,
  ) -> Vec<u8> {
    let nonce = auth::create_nonce_for_source(
      &config.realm,
      NonceSourceBinding::from_peer(client.peer()),
      &config.auth,
    )
    .expect("connection-bind nonce");
    let attrs = vec![
      (ATTR_CONNECTION_ID, connection_id.to_be_bytes().to_vec()),
      (ATTR_USERNAME, TEST_USERNAME.as_bytes().to_vec()),
      (ATTR_REALM, config.realm.as_bytes().to_vec()),
      (ATTR_NONCE, nonce.into_bytes()),
      auth::password_algorithms_challenge_attribute(&config.auth),
      (
        ATTR_PASSWORD_ALGORITHM,
        encode_password_algorithm(PASSWORD_ALGORITHM_SHA256),
      ),
    ];
    let key =
      Sha256::digest(format!("{TEST_USERNAME}:{}:{TEST_PASSWORD}", config.realm).as_bytes());
    with_message_integrity_sha256(
      encode_message(CONNECTION_BIND_REQUEST, [9; 12], &attrs),
      &key,
    )
  }

  fn response_error_code(response: &[u8]) -> u16 {
    let message = parse_stun(response).expect("STUN response");
    let value = attr_bytes(&message, ATTR_ERROR_CODE).expect("ERROR-CODE");
    u16::from(value[2]) * 100 + u16::from(value[3])
  }

  async fn connected_tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("bind peer listener");
    let peer_addr = listener.local_addr().expect("peer listener address");
    let first = TcpStream::connect(peer_addr)
      .await
      .expect("connect peer stream");
    let (second, _) = listener.accept().await.expect("accept peer stream");
    (first, second)
  }

  async fn edge_with_tcp_allocation(
    expires_at: Instant,
    pending_tcp: HashMap<u32, PendingTcpConnection>,
    active_tcp: HashMap<u32, SocketAddr>,
  ) -> (EdgeState, EdgeClient) {
    edge_with_tcp_allocation_auth(
      expires_at,
      pending_tcp,
      active_tcp,
      test_authenticated_context(),
    )
    .await
  }

  async fn edge_with_tcp_allocation_auth(
    expires_at: Instant,
    pending_tcp: HashMap<u32, PendingTcpConnection>,
    active_tcp: HashMap<u32, SocketAddr>,
    allocation_auth: Arc<AuthenticatedContext>,
  ) -> (EdgeState, EdgeClient) {
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind TCP relay");
    let std_listener_addr = std_listener.local_addr().expect("TCP relay address");
    std_listener
      .set_nonblocking(true)
      .expect("make TCP relay nonblocking");
    let runtime = crate::runtime_introspection::RuntimeIntrospectionState::new();
    let edge = EdgeState::new(runtime.clone());
    let client = EdgeClient::Stream {
      id: 7,
      peer: "127.0.0.1:50000".parse().expect("client peer"),
    };
    edge.clients.lock().await.insert(
      client,
      EdgeClientState {
        sender: EdgeSender::Stream(mpsc::channel(1).0),
        allocations: HashMap::from([(
          TurnRelayAddressFamily::Ipv4,
          EdgeAllocation {
            relay: EdgeRelay::Tcp(Arc::new(EdgeTcpRelay {
              listener: TcpListener::from_std(std_listener).expect("create async TCP relay"),
              _reservation: None,
            })),
            relayed_addr: std_listener_addr,
            transaction_id: [2; 12],
            request_digest: [0; 32],
            reservation_token: None,
            auth: allocation_auth,
            permissions: HashMap::new(),
            channels: HashMap::new(),
            pending_tcp,
            active_tcp,
            expires_at,
            _introspection_guard: runtime.guard(RuntimeCounter::TurnAllocation),
          },
        )]),
        _udp_client_guard: None,
      },
    );
    (edge, client)
  }

  #[tokio::test]
  async fn connection_bind_wrong_credentials_preserves_pending_connection() {
    let connection_id = 41;
    let (pending_stream, _peer_guard) = connected_tcp_pair().await;
    let pending_peer = pending_stream.peer_addr().expect("pending peer address");
    let (edge, _) = edge_with_tcp_allocation_auth(
      Instant::now() + Duration::from_secs(60),
      HashMap::from([(
        connection_id,
        PendingTcpConnection {
          stream: Some(pending_stream),
          peer: pending_peer,
          expires_at: Instant::now() + PENDING_LIFETIME,
        },
      )]),
      HashMap::new(),
      test_authenticated_context_with_password("different-password"),
    )
    .await;
    let config = connection_bind_config();
    let client = EdgeClient::Stream {
      id: 8,
      peer: SocketAddr::from(([127, 0, 0, 1], 50_001)),
    };
    let request = authenticated_connection_bind(&config, client, connection_id);

    let ConnectionBindOutcome::Rejected(response) =
      handle_connection_bind(&edge, &config, client, &request)
        .await
        .expect("connection bind must be evaluated")
    else {
      panic!("wrong credentials must reject connection binding");
    };
    assert_eq!(response_error_code(&response), 441);
    let clients = edge.clients.lock().await;
    let allocation = clients
      .values()
      .flat_map(|state| state.allocations.values())
      .next()
      .expect("allocation remains");
    assert!(allocation.pending_tcp.contains_key(&connection_id));
    assert!(!allocation.active_tcp.contains_key(&connection_id));
  }

  #[tokio::test]
  async fn connection_bind_matching_credentials_consumes_only_target_pending_connection() {
    let connection_id = 42;
    let untouched_connection_id = 43;
    let (pending_stream, _peer_guard) = connected_tcp_pair().await;
    let pending_peer = pending_stream.peer_addr().expect("pending peer address");
    let (edge, owner) = edge_with_tcp_allocation(
      Instant::now() + Duration::from_secs(60),
      HashMap::from([
        (
          connection_id,
          PendingTcpConnection {
            stream: Some(pending_stream),
            peer: pending_peer,
            expires_at: Instant::now() + PENDING_LIFETIME,
          },
        ),
        (
          untouched_connection_id,
          PendingTcpConnection {
            stream: None,
            peer: SocketAddr::from(([127, 0, 0, 1], 51_043)),
            expires_at: Instant::now() + PENDING_LIFETIME,
          },
        ),
      ]),
      HashMap::new(),
    )
    .await;
    let config = connection_bind_config();
    let client = EdgeClient::Stream {
      id: 9,
      peer: SocketAddr::from(([127, 0, 0, 1], 50_002)),
    };
    let request = authenticated_connection_bind(&config, client, connection_id);

    let ConnectionBindOutcome::Bound {
      connection,
      response,
    } = handle_connection_bind(&edge, &config, client, &request)
      .await
      .expect("connection bind must be evaluated")
    else {
      panic!("matching credentials must bind the pending connection");
    };
    assert_eq!(
      parse_stun(&response)
        .expect("success response")
        .message_type,
      success_type(CONNECTION_BIND_REQUEST)
    );
    assert_eq!(connection.owner, owner);
    assert_eq!(connection.family, TurnRelayAddressFamily::Ipv4);
    assert_eq!(connection.connection_id, connection_id);
    {
      let clients = edge.clients.lock().await;
      let allocation = clients
        .get(&owner)
        .and_then(|state| state.allocations.get(&TurnRelayAddressFamily::Ipv4))
        .expect("allocation remains");
      assert!(!allocation.pending_tcp.contains_key(&connection_id));
      assert!(
        allocation
          .pending_tcp
          .contains_key(&untouched_connection_id)
      );
      assert_eq!(
        allocation.active_tcp.get(&connection_id),
        Some(&pending_peer)
      );
    }
    drop(connection.peer);
    release_active_connection(&edge, owner, TurnRelayAddressFamily::Ipv4, connection_id).await;
  }

  #[tokio::test]
  async fn two_connections_cleanup_independently_and_count_toward_capacity() {
    let first_peer = "127.0.0.1:51001".parse().expect("first peer");
    let second_peer = "127.0.0.1:51002".parse().expect("second peer");
    let pending_peer = "127.0.0.1:51003".parse().expect("pending peer");
    let (edge, client) = edge_with_tcp_allocation(
      Instant::now() + Duration::from_secs(60),
      HashMap::from([(
        30,
        PendingTcpConnection {
          stream: None,
          peer: pending_peer,
          expires_at: Instant::now() + PENDING_LIFETIME,
        },
      )]),
      HashMap::from([(10, first_peer), (20, second_peer)]),
    )
    .await;
    assert_eq!(pending_connection_count(&*edge.clients.lock().await), 3);

    release_active_connection(&edge, client, TurnRelayAddressFamily::Ipv4, 10).await;
    assert!(!active_connection_exists(&edge, client, TurnRelayAddressFamily::Ipv4, 10).await);
    assert!(active_connection_exists(&edge, client, TurnRelayAddressFamily::Ipv4, 20).await);
    assert_eq!(pending_connection_count(&*edge.clients.lock().await), 2);

    remove_pending_connection(&edge, client, TurnRelayAddressFamily::Ipv4, 30).await;
    let mut clients = edge.clients.lock().await;
    let allocation = clients
      .get_mut(&client)
      .and_then(|state| state.allocations.get_mut(&TurnRelayAddressFamily::Ipv4))
      .expect("allocation remains");
    assert!(!peer_has_connection(allocation, pending_peer));
    assert!(peer_has_connection(allocation, second_peer));
    allocation.pending_tcp.insert(
      40,
      PendingTcpConnection {
        stream: None,
        peer: pending_peer,
        expires_at: Instant::now() + PENDING_LIFETIME,
      },
    );
    assert!(peer_has_connection(allocation, pending_peer));
    assert!(peer_has_connection(allocation, second_peer));
  }

  #[tokio::test]
  async fn allocation_expiry_invalidates_only_its_active_relay_state() {
    let (edge, client) = edge_with_tcp_allocation(
      Instant::now() - Duration::from_millis(1),
      HashMap::new(),
      HashMap::from([(10, "127.0.0.1:51001".parse().expect("peer"))]),
    )
    .await;

    assert!(!active_connection_exists(&edge, client, TurnRelayAddressFamily::Ipv4, 10).await);
    assert!(!edge.clients.lock().await.contains_key(&client));
  }

  #[tokio::test]
  async fn active_relay_observes_refresh_extension_and_allocation_deletion() {
    let (edge, client) = edge_with_tcp_allocation(
      Instant::now() + Duration::from_millis(20),
      HashMap::new(),
      HashMap::from([(10, "127.0.0.1:51001".parse().expect("peer"))]),
    )
    .await;
    {
      let mut clients = edge.clients.lock().await;
      let allocation = clients
        .get_mut(&client)
        .and_then(|state| state.allocations.get_mut(&TurnRelayAddressFamily::Ipv4))
        .expect("allocation exists");
      allocation.expires_at = Instant::now() + Duration::from_secs(60);
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(active_connection_exists(&edge, client, TurnRelayAddressFamily::Ipv4, 10).await);

    edge.clients.lock().await.remove(&client);
    assert!(!active_connection_exists(&edge, client, TurnRelayAddressFamily::Ipv4, 10).await);
  }

  #[tokio::test]
  async fn outgoing_connection_uses_allocations_relay_port() {
    use socket2::{Domain, Protocol, Socket, Type};

    let listener_socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
      .expect("create relay listener socket");
    listener_socket
      .set_reuse_address(true)
      .expect("set relay reuse-address");
    listener_socket
      .bind(
        &"127.0.0.1:0"
          .parse::<SocketAddr>()
          .expect("relay addr")
          .into(),
      )
      .expect("bind relay listener");
    listener_socket.listen(8).expect("listen on relay socket");
    #[cfg(unix)]
    listener_socket
      .set_reuse_port(true)
      .expect("allow connected sockets to share relay port");
    let relay_listener: std::net::TcpListener = listener_socket.into();
    let relay_addr = relay_listener.local_addr().expect("relay local addr");

    let peer = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
    let peer_addr = peer.local_addr().expect("peer local addr");
    let connected = tokio::time::timeout(
      Duration::from_secs(2),
      connect_from_relay(relay_addr, peer_addr),
    )
    .await
    .expect("outgoing connection should complete")
    .expect("connect from relay address");
    let (_, observed_source) = tokio::time::timeout(Duration::from_secs(2), peer.accept())
      .await
      .expect("peer accept should complete")
      .expect("accept outgoing connection");

    assert_eq!(
      connected.local_addr().expect("connected local addr").port(),
      relay_addr.port()
    );
    assert_eq!(observed_source.port(), relay_addr.port());
  }
}
