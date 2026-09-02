//! TURN allocation, permission, channel, and control-request operations.

use super::*;

fn is_indication(message_type: u16) -> bool {
  message_type & 0x0110 == 0x0010
}

async fn reject_unknown_attributes(
  sender: &EdgeSender,
  message: &StunMessage<'_>,
  unknown: &[u16],
  auth: Option<&AuthenticatedContext>,
) -> anyhow::Result<bool> {
  if unknown.is_empty() {
    return Ok(false);
  }
  send(
    sender,
    encode_unknown_attribute_error(message, unknown, auth),
  )
  .await?;
  Ok(true)
}

pub(super) async fn process_frame(
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
    if packet.len() < 2 || u16::from_be_bytes([packet[0], packet[1]]) > 0x4fff {
      return Ok(());
    }
    let channel = parse_channel_data(packet)?;
    let target = {
      let mut clients = edge.clients.lock().await;
      remove_expired_client_state(&mut clients, client);
      clients.get_mut(&client).and_then(|state| {
        state.sender = sender.clone();
        expire_client_state(state);
        state.allocations.values().find_map(|allocation| {
          let EdgeRelay::Udp(relay) = &allocation.relay else {
            return None;
          };
          allocation
            .channels
            .get(&channel.channel)
            .map(|binding| (relay.clone(), binding.peer))
        })
      })
    };
    if let Some((relay, peer)) = target {
      relay.send_to(channel.payload, peer).await?;
    }
    return Ok(());
  }
  let message = parse_stun(packet)?;
  let unknown = unknown_required_attributes(&message);
  if is_indication(message.message_type) && message.message_type != SEND_INDICATION {
    return Ok(());
  }
  match message.message_type {
    BINDING_REQUEST => {
      let auth = authenticated_context_if_present(config, &message, client)?;
      if reject_unknown_attributes(&sender, &message, &unknown, auth.as_ref()).await? {
        return Ok(());
      }
      let attrs = [(
        ATTR_XOR_MAPPED_ADDRESS,
        encode_xor_address(client.peer(), &message.transaction_id),
      )];
      let response = match auth {
        Some(context) => {
          encode_authenticated_success(&context, BINDING_REQUEST, message.transaction_id, &attrs)
        }
        None => encode_success(BINDING_REQUEST, message.transaction_id, &attrs),
      };
      send(&sender, response).await?;
    }
    ALLOCATE_REQUEST => {
      let Some(request_auth) = authenticate_request(config, &message, client, &sender).await?
      else {
        return Ok(());
      };
      if reject_unknown_attributes(&sender, &message, &unknown, Some(&request_auth)).await? {
        return Ok(());
      }
      match existing_allocate(&edge, client, &message, &request_auth).await {
        ExistingAllocate::None => {}
        ExistingAllocate::Replay(response) => {
          send(&sender, response).await?;
          return Ok(());
        }
        ExistingAllocate::Failure(failure) => {
          failure
            .send(
              &sender,
              ALLOCATE_REQUEST,
              message.transaction_id,
              &request_auth,
            )
            .await?;
          return Ok(());
        }
      }
      let requested_transport = match requested_transport(&message) {
        Ok(transport) => transport,
        Err(error) => {
          let (code, reason) = error.response();
          send_authenticated_error(
            &sender,
            &request_auth,
            ALLOCATE_REQUEST,
            message.transaction_id,
            code,
            reason,
          )
          .await?;
          return Ok(());
        }
      };
      if requested_transport == 6 && !client.is_stream() {
        send_authenticated_error(
          &sender,
          &request_auth,
          ALLOCATE_REQUEST,
          message.transaction_id,
          400,
          "Bad Request",
        )
        .await?;
        return Ok(());
      }
      if requested_transport == 6 && has_tcp_forbidden_allocate_option(&message) {
        send_authenticated_error(
          &sender,
          &request_auth,
          ALLOCATE_REQUEST,
          message.transaction_id,
          400,
          "Bad Request",
        )
        .await?;
        return Ok(());
      }
      if !matches!(requested_transport, 6 | 17) {
        send_authenticated_error(
          &sender,
          &request_auth,
          ALLOCATE_REQUEST,
          message.transaction_id,
          442,
          "Unsupported Transport Protocol",
        )
        .await?;
        return Ok(());
      }

      let mut udp_relay_request = UdpRelayRequest::Any;
      let mut claimed_udp = None;
      let families_result = if requested_transport == 6 {
        allocate_families(config, &message)
      } else {
        let options = match udp_allocate_options(&message) {
          Ok(options) => options,
          Err(error) => {
            let (code, reason) = error.response();
            send_authenticated_error(
              &sender,
              &request_auth,
              ALLOCATE_REQUEST,
              message.transaction_id,
              code,
              reason,
            )
            .await?;
            return Ok(());
          }
        };
        if options.dont_fragment {
          send(
            &sender,
            encode_unknown_attribute_error(&message, &[ATTR_DONT_FRAGMENT], Some(&request_auth)),
          )
          .await?;
          return Ok(());
        }
        udp_relay_request = options.relay;
        match options.relay {
          UdpRelayRequest::Reservation(token) => match claim_udp_relay(token)? {
            Some(claim) => {
              let family = claim.family()?;
              claimed_udp = Some(claim);
              Ok(vec![family])
            }
            None => {
              send_authenticated_error(
                &sender,
                &request_auth,
                ALLOCATE_REQUEST,
                message.transaction_id,
                508,
                "Insufficient Capacity",
              )
              .await?;
              return Ok(());
            }
          },
          _ => allocate_families(config, &message),
        }
      };
      let families = match families_result {
        Ok(families) => families,
        Err(error) => {
          let (code, reason) = error.response();
          send_authenticated_error(
            &sender,
            &request_auth,
            ALLOCATE_REQUEST,
            message.transaction_id,
            code,
            reason,
          )
          .await?;
          return Ok(());
        }
      };
      if requested_transport == 6 && families.len() != 1 {
        send_authenticated_error(
          &sender,
          &request_auth,
          ALLOCATE_REQUEST,
          message.transaction_id,
          440,
          "Address Family not Supported",
        )
        .await?;
        return Ok(());
      }
      create_allocation(
        &edge,
        config,
        client,
        &sender,
        &message,
        &request_auth,
        requested_transport,
        families,
        udp_relay_request,
        claimed_udp,
      )
      .await?;
    }
    REFRESH_REQUEST => {
      let Some(request_auth) = authenticate_request(config, &message, client, &sender).await?
      else {
        return Ok(());
      };
      if reject_unknown_attributes(&sender, &message, &unknown, Some(&request_auth)).await? {
        return Ok(());
      }
      let requested_family = match address_family_attr(&message, ATTR_REQUESTED_ADDRESS_FAMILY) {
        Ok(family) => family,
        Err(error) => {
          let (code, reason) = error.response();
          send_authenticated_error(
            &sender,
            &request_auth,
            REFRESH_REQUEST,
            message.transaction_id,
            code,
            reason,
          )
          .await?;
          return Ok(());
        }
      };
      let requested_lifetime = match lifetime_attr(&message) {
        Ok(lifetime) => lifetime,
        Err(error) => {
          let (code, reason) = error.response();
          send_authenticated_error(
            &sender,
            &request_auth,
            REFRESH_REQUEST,
            message.transaction_id,
            code,
            reason,
          )
          .await?;
          return Ok(());
        }
      };
      let lifetime = if requested_lifetime == Some(0) {
        0
      } else {
        allocation_lifetime(config, requested_lifetime)
      };
      let mutation = 'mutation: {
        let mut clients = edge.clients.lock().await;
        remove_expired_client_state(&mut clients, client);
        if let Some(state) = clients.get_mut(&client) {
          expire_client_state(state);
          let families = if let Some(family) = requested_family {
            if !state.allocations.contains_key(&family) {
              break 'mutation Err(EdgeRequestFailure::Turn(
                443,
                "Peer Address Family Mismatch",
              ));
            }
            vec![family]
          } else {
            state.allocations.keys().copied().collect::<Vec<_>>()
          };
          if families.iter().any(|family| {
            state
              .allocations
              .get(family)
              .is_some_and(|allocation| allocation.auth.username() != request_auth.username())
          }) {
            break 'mutation Err(EdgeRequestFailure::Turn(441, "Wrong Credentials"));
          }
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
          let empty = state.allocations.is_empty();
          if empty {
            clients.remove(&client);
          }
          Ok(())
        } else {
          Err(EdgeRequestFailure::AllocationMismatch)
        }
      };
      if let Err(failure) = mutation {
        failure
          .send(
            &sender,
            REFRESH_REQUEST,
            message.transaction_id,
            &request_auth,
          )
          .await?;
        return Ok(());
      }
      send(
        &sender,
        encode_authenticated_success(
          &request_auth,
          REFRESH_REQUEST,
          message.transaction_id,
          &[(ATTR_LIFETIME, lifetime.to_be_bytes().to_vec())],
        ),
      )
      .await?;
    }
    CREATE_PERMISSION_REQUEST => {
      let Some(request_auth) = authenticate_request(config, &message, client, &sender).await?
      else {
        return Ok(());
      };
      if reject_unknown_attributes(&sender, &message, &unknown, Some(&request_auth)).await? {
        return Ok(());
      }
      let peers = match attr_xor_addrs(&message, ATTR_XOR_PEER_ADDRESS) {
        Ok(peers) => peers,
        Err(_) => {
          send_authenticated_error(
            &sender,
            &request_auth,
            CREATE_PERMISSION_REQUEST,
            message.transaction_id,
            400,
            "Bad Request",
          )
          .await?;
          return Ok(());
        }
      };
      if peers.is_empty() {
        send_authenticated_error(
          &sender,
          &request_auth,
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
        send_authenticated_error(
          &sender,
          &request_auth,
          CREATE_PERMISSION_REQUEST,
          message.transaction_id,
          403,
          "Forbidden",
        )
        .await?;
        return Ok(());
      }
      let mutation = 'mutation: {
        let mut clients = edge.clients.lock().await;
        remove_expired_client_state(&mut clients, client);
        let Some(state) = clients.get_mut(&client) else {
          break 'mutation Err(EdgeRequestFailure::AllocationMismatch);
        };
        expire_client_state(state);
        for peer in peers {
          let family = TurnRelayAddressFamily::from_ip(peer.ip());
          let Some(allocation) = state.allocations.get_mut(&family) else {
            break 'mutation Err(EdgeRequestFailure::Turn(
              443,
              "Peer Address Family Mismatch",
            ));
          };
          if allocation.auth.username() != request_auth.username() {
            break 'mutation Err(EdgeRequestFailure::Turn(441, "Wrong Credentials"));
          }
          if !allocation.permissions.contains_key(&peer.ip())
            && allocation.permissions.len() >= config.limits.max_permissions_per_allocation
          {
            break 'mutation Err(EdgeRequestFailure::Turn(508, "Insufficient Capacity"));
          }
          allocation
            .permissions
            .insert(peer.ip(), Instant::now() + Duration::from_secs(300));
        }
        Ok(())
      };
      if let Err(failure) = mutation {
        failure
          .send(
            &sender,
            CREATE_PERMISSION_REQUEST,
            message.transaction_id,
            &request_auth,
          )
          .await?;
        return Ok(());
      }
      send(
        &sender,
        encode_authenticated_success(
          &request_auth,
          CREATE_PERMISSION_REQUEST,
          message.transaction_id,
          &[],
        ),
      )
      .await?;
    }
    CHANNEL_BIND_REQUEST => {
      let Some(request_auth) = authenticate_request(config, &message, client, &sender).await?
      else {
        return Ok(());
      };
      if reject_unknown_attributes(&sender, &message, &unknown, Some(&request_auth)).await? {
        return Ok(());
      }
      let peer = match singleton_xor_addr(&message, ATTR_XOR_PEER_ADDRESS) {
        Ok(Some(peer)) => peer,
        Ok(None) | Err(_) => {
          send_authenticated_error(
            &sender,
            &request_auth,
            CHANNEL_BIND_REQUEST,
            message.transaction_id,
            400,
            "Bad Request",
          )
          .await?;
          return Ok(());
        }
      };
      if !peer_allowed(peer.ip(), &config.peer_policy) {
        send_authenticated_error(
          &sender,
          &request_auth,
          CHANNEL_BIND_REQUEST,
          message.transaction_id,
          403,
          "Forbidden",
        )
        .await?;
        return Ok(());
      }
      let channel = match channel_number(&message) {
        Ok(channel) => channel,
        Err(error) => {
          let (code, reason) = error.response();
          send_authenticated_error(
            &sender,
            &request_auth,
            CHANNEL_BIND_REQUEST,
            message.transaction_id,
            code,
            reason,
          )
          .await?;
          return Ok(());
        }
      };
      let mutation = 'mutation: {
        let mut clients = edge.clients.lock().await;
        remove_expired_client_state(&mut clients, client);
        let Some(state) = clients.get_mut(&client) else {
          break 'mutation Err(EdgeRequestFailure::AllocationMismatch);
        };
        expire_client_state(state);
        let family = TurnRelayAddressFamily::from_ip(peer.ip());
        let Some(allocation) = state.allocations.get_mut(&family) else {
          break 'mutation Err(EdgeRequestFailure::Turn(
            443,
            "Peer Address Family Mismatch",
          ));
        };
        if allocation.auth.username() != request_auth.username() {
          break 'mutation Err(EdgeRequestFailure::Turn(441, "Wrong Credentials"));
        }
        if matches!(allocation.relay, EdgeRelay::Tcp(_)) {
          break 'mutation Err(EdgeRequestFailure::Turn(400, "Bad Request"));
        }
        if !allocation.permissions.contains_key(&peer.ip())
          && allocation.permissions.len() >= config.limits.max_permissions_per_allocation
        {
          break 'mutation Err(EdgeRequestFailure::Turn(508, "Insufficient Capacity"));
        }
        if !allocation.channels.contains_key(&channel)
          && allocation.channels.len() >= config.limits.max_channels_per_allocation
        {
          break 'mutation Err(EdgeRequestFailure::Turn(508, "Insufficient Capacity"));
        }
        if channel_binding_conflicts(&allocation.channels, channel, peer) {
          break 'mutation Err(EdgeRequestFailure::Turn(400, "Bad Request"));
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
        Ok(())
      };
      if let Err(failure) = mutation {
        failure
          .send(
            &sender,
            CHANNEL_BIND_REQUEST,
            message.transaction_id,
            &request_auth,
          )
          .await?;
        return Ok(());
      }
      send(
        &sender,
        encode_authenticated_success(
          &request_auth,
          CHANNEL_BIND_REQUEST,
          message.transaction_id,
          &[],
        ),
      )
      .await?;
    }
    CONNECT_REQUEST => {
      let Some(request_auth) = authenticate_request(config, &message, client, &sender).await?
      else {
        return Ok(());
      };
      if reject_unknown_attributes(&sender, &message, &unknown, Some(&request_auth)).await? {
        return Ok(());
      }
      handle_connect_request(&edge, config, client, &sender, &message, &request_auth).await?;
    }
    SEND_INDICATION => {
      if !unknown.is_empty()
        || semantic_attributes(&message)
          .iter()
          .any(|attr| attr.kind == ATTR_DONT_FRAGMENT)
      {
        return Ok(());
      }
      let Ok(Some(peer)) = singleton_xor_addr(&message, ATTR_XOR_PEER_ADDRESS) else {
        return Ok(());
      };
      let Ok(Some(data)) = singleton_attr(&message, ATTR_DATA) else {
        return Ok(());
      };
      let relay = {
        let mut clients = edge.clients.lock().await;
        remove_expired_client_state(&mut clients, client);
        clients.get_mut(&client).and_then(|state| {
          expire_client_state(state);
          let family = TurnRelayAddressFamily::from_ip(peer.ip());
          state.allocations.get(&family).and_then(|allocation| {
            let EdgeRelay::Udp(relay) = &allocation.relay else {
              return None;
            };
            allocation
              .permissions
              .contains_key(&peer.ip())
              .then(|| relay.clone())
          })
        })
      };
      if let Some(relay) = relay {
        relay.send_to(data, peer).await?;
      }
    }
    _ => {
      let auth = authenticated_context_if_present(config, &message, client)?;
      if reject_unknown_attributes(&sender, &message, &unknown, auth.as_ref()).await? {
        return Ok(());
      }
      let response = match auth {
        Some(context) => encode_authenticated_error(
          &context,
          message.message_type,
          message.transaction_id,
          400,
          "Bad Request",
        ),
        None => encode_error(
          message.message_type,
          message.transaction_id,
          400,
          "Bad Request",
          None,
          None,
        ),
      };
      send(&sender, response).await?;
    }
  }
  Ok(())
}

#[cfg(test)]
#[path = "operations/tests.rs"]
mod tests;
