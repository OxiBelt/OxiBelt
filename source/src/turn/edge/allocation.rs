//! TURN allocation retransmission and duplicate-allocation handling.

use super::*;

enum PreparedEdgeRelay {
  Tcp {
    family: TurnRelayAddressFamily,
    relay: Arc<EdgeTcpRelay>,
    relayed_addr: SocketAddr,
  },
  Udp(PreparedUdpRelay),
  ClaimedUdp(ClaimedUdpRelay),
}

impl PreparedEdgeRelay {
  fn finalize(self) -> anyhow::Result<FinalizedEdgeRelay> {
    match self {
      Self::Tcp {
        family,
        relay,
        relayed_addr,
      } => Ok(FinalizedEdgeRelay::Tcp {
        family,
        relay,
        relayed_addr,
      }),
      Self::Udp(relay) => Ok(FinalizedEdgeRelay::Udp(relay.finalize()?)),
      Self::ClaimedUdp(relay) => Ok(FinalizedEdgeRelay::Udp(relay.into_finalized())),
    }
  }
}

enum FinalizedEdgeRelay {
  Tcp {
    family: TurnRelayAddressFamily,
    relay: Arc<EdgeTcpRelay>,
    relayed_addr: SocketAddr,
  },
  Udp(FinalizedUdpRelay),
}

enum InstallReadyEdgeRelay {
  Tcp {
    family: TurnRelayAddressFamily,
    relay: Arc<EdgeTcpRelay>,
    relayed_addr: SocketAddr,
  },
  Udp(InstallReadyUdpRelay),
}

impl FinalizedEdgeRelay {
  fn into_install_ready(self) -> std::io::Result<InstallReadyEdgeRelay> {
    match self {
      Self::Tcp {
        family,
        relay,
        relayed_addr,
      } => Ok(InstallReadyEdgeRelay::Tcp {
        family,
        relay,
        relayed_addr,
      }),
      Self::Udp(relay) => Ok(InstallReadyEdgeRelay::Udp(relay.into_install_ready()?)),
    }
  }
}

pub(super) enum ExistingAllocate {
  None,
  Replay(Vec<u8>),
  Failure(EdgeRequestFailure),
}

pub(super) async fn existing_allocate(
  edge: &EdgeState,
  client: EdgeClient,
  message: &StunMessage<'_>,
  request_auth: &AuthenticatedContext,
) -> ExistingAllocate {
  let mut clients = edge.clients.lock().await;
  remove_expired_client_state(&mut clients, client);
  let Some(state) = clients.get(&client) else {
    return ExistingAllocate::None;
  };
  if state.allocations.is_empty() {
    return ExistingAllocate::None;
  }
  let request_digest = crate::crypto::sha256(message.raw);
  let exact_udp_retransmission = matches!(client, EdgeClient::Udp { .. })
    && state.allocations.values().all(|allocation| {
      allocation.transaction_id == message.transaction_id
        && allocation.request_digest == request_digest
        && allocation.auth.has_same_credentials(request_auth)
        && matches!(&allocation.relay, EdgeRelay::Udp(_))
    });
  if !exact_udp_retransmission {
    return ExistingAllocate::Failure(EdgeRequestFailure::AllocationMismatch);
  }

  let now = Instant::now();
  let mut attrs = Vec::with_capacity(state.allocations.len() + 2);
  let mut remaining = u32::MAX;
  for allocation in state.allocations.values() {
    let EdgeRelay::Udp(_) = &allocation.relay else {
      return ExistingAllocate::Failure(EdgeRequestFailure::AllocationMismatch);
    };
    let seconds = allocation
      .expires_at
      .saturating_duration_since(now)
      .as_secs();
    remaining = remaining.min(u32::try_from(seconds).unwrap_or(u32::MAX));
    attrs.push((
      ATTR_XOR_RELAYED_ADDRESS,
      encode_xor_address(allocation.relayed_addr, &message.transaction_id),
    ));
    if let Some(token) = allocation.reservation_token {
      attrs.push((ATTR_RESERVATION_TOKEN, token.to_vec()));
    }
  }
  attrs.push((
    ATTR_XOR_MAPPED_ADDRESS,
    encode_xor_address(client.peer(), &message.transaction_id),
  ));
  attrs.push((ATTR_LIFETIME, remaining.to_be_bytes().to_vec()));
  ExistingAllocate::Replay(encode_authenticated_success(
    request_auth,
    ALLOCATE_REQUEST,
    message.transaction_id,
    &attrs,
  ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn create_allocation(
  edge: &EdgeState,
  config: &WebRtcTurnListenerConfig,
  client: EdgeClient,
  sender: &EdgeSender,
  message: &StunMessage<'_>,
  request_auth: &Arc<AuthenticatedContext>,
  requested_transport: u8,
  families: Vec<TurnRelayAddressFamily>,
  udp_relay_request: UdpRelayRequest,
  mut claimed_udp: Option<ClaimedUdpRelay>,
) -> anyhow::Result<()> {
  let requested_lifetime = match lifetime_attr(message) {
    Ok(lifetime) => lifetime,
    Err(error) => {
      let (code, reason) = error.response();
      send_authenticated_error(
        sender,
        request_auth,
        ALLOCATE_REQUEST,
        message.transaction_id,
        code,
        reason,
      )
      .await?;
      return Ok(());
    }
  };
  let lifetime = allocation_lifetime(config, requested_lifetime);
  let mut prepared_relays = Vec::with_capacity(families.len());
  for family in families {
    if let Some(claim) = claimed_udp.take() {
      prepared_relays.push(PreparedEdgeRelay::ClaimedUdp(claim));
      continue;
    }
    let Some(relay_config) = relay_family_config(config, family) else {
      send_authenticated_error(
        sender,
        request_auth,
        ALLOCATE_REQUEST,
        message.transaction_id,
        440,
        "Address Family not Supported",
      )
      .await?;
      return Ok(());
    };
    let prepared: anyhow::Result<PreparedEdgeRelay> = if requested_transport == 6 {
      (|| {
        let (relay, reservation) = bind_tcp_relay_socket(relay_config)?;
        let port = relay.local_addr()?.port();
        Ok(PreparedEdgeRelay::Tcp {
          family,
          relay: Arc::new(EdgeTcpRelay {
            listener: TcpListener::from_std(relay)?,
            _reservation: Some(reservation),
          }),
          relayed_addr: SocketAddr::new(relay_config.public_ip, port),
        })
      })()
    } else {
      prepare_udp_relay(relay_config, udp_relay_request).map(PreparedEdgeRelay::Udp)
    };
    let prepared = match prepared {
      Ok(prepared) => prepared,
      Err(_) => {
        send_authenticated_error(
          sender,
          request_auth,
          ALLOCATE_REQUEST,
          message.transaction_id,
          508,
          "Insufficient Capacity",
        )
        .await?;
        return Ok(());
      }
    };
    prepared_relays.push(prepared);
  }
  let installed = 'installed: {
    let mut clients = edge.clients.lock().await;
    remove_all_expired_client_state(&mut clients);
    let total_allocations = clients
      .values()
      .map(|state| state.allocations.len())
      .sum::<usize>();
    let client_allocations = clients
      .get(&client)
      .map(|state| state.allocations.len())
      .unwrap_or(0);
    if total_allocations + prepared_relays.len() > config.limits.max_allocations_per_listener {
      Err(EdgeRequestFailure::Turn(508, "Insufficient Capacity"))
    } else if client_allocations + prepared_relays.len() > config.limits.max_allocations_per_client
    {
      Err(EdgeRequestFailure::Turn(486, "Allocation Quota Reached"))
    } else if clients
      .get(&client)
      .is_some_and(|state| !state.allocations.is_empty())
    {
      Err(EdgeRequestFailure::AllocationMismatch)
    } else {
      let finalized = match prepared_relays
        .into_iter()
        .map(PreparedEdgeRelay::finalize)
        .collect::<anyhow::Result<Vec<_>>>()
      {
        Ok(finalized) => finalized,
        Err(_) => {
          break 'installed Err(EdgeRequestFailure::Turn(508, "Insufficient Capacity"));
        }
      };
      let install_ready = match finalized
        .into_iter()
        .map(FinalizedEdgeRelay::into_install_ready)
        .collect::<std::io::Result<Vec<_>>>()
      {
        Ok(install_ready) => install_ready,
        Err(_) => {
          break 'installed Err(EdgeRequestFailure::Turn(508, "Insufficient Capacity"));
        }
      };
      let state = clients.entry(client).or_insert_with(|| EdgeClientState {
        sender: sender.clone(),
        allocations: HashMap::new(),
        _udp_client_guard: matches!(client, EdgeClient::Udp { .. }).then(|| {
          edge
            .runtime_introspection
            .guard(RuntimeCounter::TurnUdpClient)
        }),
      });
      state.sender = sender.clone();
      let mut response_attrs = Vec::with_capacity(install_ready.len() + 2);
      let mut installed_relays = Vec::with_capacity(install_ready.len());
      for install_ready_relay in install_ready {
        let (family, relay, relayed_addr, reservation_token) = match install_ready_relay {
          InstallReadyEdgeRelay::Tcp {
            family,
            relay,
            relayed_addr,
          } => (family, EdgeRelay::Tcp(relay), relayed_addr, None),
          InstallReadyEdgeRelay::Udp(relay) => {
            let (socket, family, relayed_addr, token) = relay.into_parts();
            (
              family,
              EdgeRelay::Udp(Arc::new(socket)),
              relayed_addr,
              token,
            )
          }
        };
        response_attrs.push((
          ATTR_XOR_RELAYED_ADDRESS,
          encode_xor_address(relayed_addr, &message.transaction_id),
        ));
        if let Some(token) = reservation_token {
          response_attrs.push((ATTR_RESERVATION_TOKEN, token.to_vec()));
        }
        installed_relays.push((family, relay.clone()));
        state.allocations.insert(
          family,
          EdgeAllocation {
            relay,
            relayed_addr,
            transaction_id: message.transaction_id,
            request_digest: crate::crypto::sha256(message.raw),
            reservation_token,
            auth: request_auth.clone(),
            permissions: HashMap::new(),
            channels: HashMap::new(),
            pending_tcp: HashMap::new(),
            active_tcp: HashMap::new(),
            expires_at: Instant::now() + Duration::from_secs(u64::from(lifetime)),
            _introspection_guard: edge
              .runtime_introspection
              .guard(RuntimeCounter::TurnAllocation),
          },
        );
      }
      Ok((response_attrs, installed_relays))
    }
  };
  let (mut response_attrs, installed_relays) = match installed {
    Ok(installed) => installed,
    Err(failure) => {
      failure
        .send(
          sender,
          ALLOCATE_REQUEST,
          message.transaction_id,
          request_auth,
        )
        .await?;
      return Ok(());
    }
  };
  response_attrs.push((
    ATTR_XOR_MAPPED_ADDRESS,
    encode_xor_address(client.peer(), &message.transaction_id),
  ));
  response_attrs.push((ATTR_LIFETIME, lifetime.to_be_bytes().to_vec()));
  for (family, relay) in installed_relays {
    match relay {
      EdgeRelay::Udp(relay) => spawn_peer_reader(edge.clone(), client, family, relay),
      EdgeRelay::Tcp(relay) => {
        spawn_tcp_peer_acceptor(edge.clone(), client, family, relay, config.clone())
      }
    }
  }
  send(
    sender,
    encode_authenticated_success(
      request_auth,
      ALLOCATE_REQUEST,
      message.transaction_id,
      &response_attrs,
    ),
  )
  .await
}

#[cfg(test)]
mod tests {
  use super::super::tcp::tests::{
    test_authenticated_context, test_authenticated_context_with_password,
  };
  use super::*;

  #[tokio::test]
  async fn udp_allocate_retransmission_reuses_allocation_but_new_transaction_is_rejected() {
    let relay = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind relay"));
    let runtime = crate::runtime_introspection::RuntimeIntrospectionState::new();
    let edge = EdgeState::new(runtime.clone());
    let client = EdgeClient::Udp {
      peer: "127.0.0.1:50000".parse().expect("client"),
      local: "127.0.0.1:3478".parse().expect("listener"),
    };
    edge.clients.lock().await.insert(
      client,
      EdgeClientState {
        sender: EdgeSender::Stream(mpsc::channel(1).0),
        allocations: HashMap::from([(
          TurnRelayAddressFamily::Ipv4,
          EdgeAllocation {
            relay: EdgeRelay::Udp(relay),
            relayed_addr: "127.0.0.1:49152".parse().expect("relayed address"),
            transaction_id: [9; 12],
            request_digest: crate::crypto::sha256(&encode_message(
              ALLOCATE_REQUEST,
              [9; 12],
              &[(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
            )),
            reservation_token: None,
            auth: test_authenticated_context(),
            permissions: HashMap::new(),
            channels: HashMap::new(),
            pending_tcp: HashMap::new(),
            active_tcp: HashMap::new(),
            expires_at: Instant::now() + Duration::from_secs(600),
            _introspection_guard: runtime.guard(RuntimeCounter::TurnAllocation),
          },
        )]),
        _udp_client_guard: None,
      },
    );
    let request_auth = test_authenticated_context();
    let same_bytes = encode_message(
      ALLOCATE_REQUEST,
      [9; 12],
      &[(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
    );
    let same = parse_stun(&same_bytes).expect("same Allocate request");
    let replay = existing_allocate(&edge, client, &same, &request_auth).await;
    let ExistingAllocate::Replay(response) = replay else {
      panic!("same UDP transaction must replay allocation success");
    };
    assert_eq!(
      parse_stun(&response).expect("replay response").message_type,
      success_type(ALLOCATE_REQUEST)
    );

    let changed_bytes = encode_message(
      ALLOCATE_REQUEST,
      [10; 12],
      &[(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
    );
    let changed = parse_stun(&changed_bytes).expect("changed Allocate request");
    assert!(matches!(
      existing_allocate(&edge, client, &changed, &request_auth).await,
      ExistingAllocate::Failure(EdgeRequestFailure::AllocationMismatch)
    ));

    let different_auth = test_authenticated_context_with_password("different-password");
    assert!(matches!(
      existing_allocate(&edge, client, &same, &different_auth).await,
      ExistingAllocate::Failure(EdgeRequestFailure::AllocationMismatch)
    ));
  }
}
