use super::*;

#[test]
fn short_header_cid_lookup_uses_byte_after_flags() {
  let mut state = QuicForwardState::default();
  let client = "127.0.0.1:12345".parse().unwrap();
  let target = "127.0.0.1:443".parse().unwrap();
  state.forward_by_client.insert(client, test_session(target));
  state.cid_to_client.insert(vec![1, 2, 3, 4], client);

  assert_eq!(
    state.client_for_upstream_response(target, &[0x40, 1, 2, 3, 4, 0xaa]),
    Some(client)
  );
}

#[test]
fn single_target_response_can_fallback_to_client_tuple() {
  let mut state = QuicForwardState::default();
  let client = "127.0.0.1:12345".parse().unwrap();
  let target = "127.0.0.1:443".parse().unwrap();
  state.forward_by_client.insert(client, test_session(target));

  assert_eq!(
    state.client_for_upstream_response(target, &[0x40, 0xaa, 0xbb]),
    Some(client)
  );
}

#[test]
fn shared_target_response_without_known_cid_fails_closed() {
  let mut state = QuicForwardState::default();
  let first_client = "127.0.0.1:12345".parse().unwrap();
  let second_client = "127.0.0.1:12346".parse().unwrap();
  let target = "127.0.0.1:443".parse().unwrap();
  state
    .forward_by_client
    .insert(first_client, test_session(target));
  state
    .forward_by_client
    .insert(second_client, test_session(target));

  assert_eq!(
    state.client_for_upstream_response(target, &[0x40, 0xaa, 0xbb]),
    None
  );
}

#[test]
fn pre_classification_limit_evicts_oldest_across_local_and_forwarded_clients() {
  let now = Instant::now();
  let old_forward = "127.0.0.1:12345".parse().unwrap();
  let local = "127.0.0.1:12346".parse().unwrap();
  let new_forward = "127.0.0.1:12347".parse().unwrap();
  let target = "127.0.0.1:443".parse().unwrap();
  let mut state = QuicForwardState::default();
  state.forward_by_client.insert(
    old_forward,
    test_session_with_last_seen(target, now - Duration::from_secs(30)),
  );
  state
    .local_clients
    .insert(local, now - Duration::from_secs(20));
  state.forward_by_client.insert(
    new_forward,
    test_session_with_last_seen(target, now - Duration::from_secs(10)),
  );
  state.cid_to_client.insert(vec![1], old_forward);
  state.local_cids.insert(vec![2], local);
  state.cid_to_client.insert(vec![3], new_forward);

  let evicted = state.enforce_pre_classification_limit(2);

  assert_eq!(evicted.len(), 1);
  assert_eq!(evicted[0].target_addr, target);
  assert!(!state.forward_by_client.contains_key(&old_forward));
  assert!(state.local_clients.contains_key(&local));
  assert!(state.forward_by_client.contains_key(&new_forward));
  assert!(
    !state
      .cid_to_client
      .values()
      .any(|client| *client == old_forward)
  );
  assert!(state.local_cids.values().any(|client| *client == local));
}

#[test]
fn pre_classification_limit_bounds_cid_maps_to_session_limit() {
  let client = "127.0.0.1:12345".parse().unwrap();
  let local = "127.0.0.1:12346".parse().unwrap();
  let target = "127.0.0.1:443".parse().unwrap();
  let mut state = QuicForwardState::default();
  state.forward_by_client.insert(client, test_session(target));
  state.local_clients.insert(local, Instant::now());
  for index in 0..8u8 {
    state.cid_to_client.insert(vec![index], client);
    state.local_cids.insert(vec![index + 16], local);
  }

  let evicted = state.enforce_pre_classification_limit(2);

  assert!(evicted.is_empty());
  assert!(state.cid_to_client.len() <= 2);
  assert!(state.local_cids.len() <= 2);
  assert!(state.cid_to_client.values().all(|mapped| *mapped == client));
  assert!(state.local_cids.values().all(|mapped| *mapped == local));
}

#[tokio::test]
async fn local_datagram_queue_drops_when_capacity_is_full() {
  let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
  let demux = QuicDemuxSocket::new(socket, 2);
  let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

  demux.queue_local(&[1], peer);
  demux.queue_local(&[2], peer);
  demux.queue_local(&[3], peer);

  let mut receiver = demux
    .local_rx
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner());
  assert_eq!(receiver.try_recv().unwrap().bytes, vec![1]);
  assert_eq!(receiver.try_recv().unwrap().bytes, vec![2]);
  assert!(receiver.try_recv().is_err());
}

fn test_session(target: SocketAddr) -> QuicForwardSession {
  test_session_with_last_seen(target, Instant::now())
}

fn test_session_with_last_seen(target: SocketAddr, last_seen: Instant) -> QuicForwardSession {
  QuicForwardSession {
    target_addr: target,
    rule_name: "test".to_string(),
    target: target.to_string(),
    sni: "example.com".to_string(),
    started: Instant::now(),
    last_seen,
    idle_timeout: Duration::from_secs(1),
    client_to_target: 0,
    target_to_client: 0,
  }
}
