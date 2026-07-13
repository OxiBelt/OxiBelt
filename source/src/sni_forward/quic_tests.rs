use super::*;
use crate::config::{Config, LimitsConfig};
use crate::limits::LimitState;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

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
    .insert(local, local_session(now - Duration::from_secs(20)));
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
  state
    .local_clients
    .insert(local, local_session(Instant::now()));
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

#[test]
fn known_local_session_keeps_selected_policy_index() {
  let client = "127.0.0.1:12345".parse().unwrap();
  let mut state = QuicForwardState::default();
  state.local_clients.insert(
    client,
    LocalQuicSession {
      policy_index: 2,
      last_seen: Instant::now() - Duration::from_secs(10),
    },
  );

  match state.known_action(&[0x40, 0xaa, 0xbb], client) {
    DatagramAction::QueueLocal(index) => assert_eq!(index, 2),
    action => panic!("unexpected action: {action:?}"),
  }
  assert!(
    state
      .local_clients
      .get(&client)
      .expect("local client should remain")
      .last_seen
      > Instant::now() - Duration::from_secs(5)
  );
}

#[test]
fn forwarded_quic_session_holds_connection_permit_until_removed() {
  let limits = LimitsConfig {
    max_connections: 1,
    max_connections_per_ip: 1,
    ..LimitsConfig::default()
  };
  let state = LimitState::new(None);
  let client: SocketAddr = "127.0.0.1:12345".parse().unwrap();
  let permit = state
    .acquire_connection(client.ip(), &limits, &[])
    .expect("first permit should succeed");
  let mut sessions = QuicForwardState::default();
  sessions.forward_by_client.insert(
    client,
    QuicForwardSession {
      _connection_permit: Some(permit),
      ..test_session("127.0.0.1:443".parse().unwrap())
    },
  );

  assert!(state.acquire_connection(client.ip(), &limits, &[]).is_err());

  drop(sessions.remove_forward_client(client));
  assert!(state.acquire_connection(client.ip(), &limits, &[]).is_ok());
}

#[tokio::test]
async fn policy_demux_parse_failure_fails_closed_without_sni_forwarding() {
  let temp_dir = common::TempDir::new("quic-policy-demux-parse-failure");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "quic-policy-demux-parse-failure");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("http3 = false", "http3 = true")
    + r#"

[routes.tls.1_3]
key_exchange_groups = ["x25519"]

[quic.socket]
workers = 1
"#;
  let snapshot = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("application snapshot should initialize");
  let quic_config = snapshot
    .quic_server_config
    .as_ref()
    .expect("HTTP/3 snapshot should build QUIC config");
  assert!(quic_config.requires_sni_policy_demux());
  assert_ne!(
    quic_config.policy_index_for_sni(Some("example.com")),
    Some(0)
  );
  let policy_count = quic_config.configs().len();

  let state = AppHandle::new(snapshot);
  let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
  let (demux, sockets) = QuicDemuxSocket::new(socket, 4, policy_count);
  let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

  demux
    .handle_datagram(b"not a QUIC Initial", peer, &state, true)
    .await
    .expect("parse failures should be rejected without surfacing an I/O error");

  for endpoint in sockets {
    let mut receiver = endpoint
      .local_rx
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(receiver.try_recv().is_err());
  }
}

#[tokio::test]
async fn tls12_only_sni_policy_requires_demux_and_rejects_quic() {
  let temp_dir = common::TempDir::new("quic-policy-demux-tls12-reject");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "quic-policy-demux-tls12-reject");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace("http3 = false", "http3 = true")
    + r#"

[routes.tls]
min_version = "tls1.2"
max_version = "tls1.2"

[quic.socket]
workers = 1
"#;
  let snapshot = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("application snapshot should initialize");
  let quic_config = snapshot
    .quic_server_config
    .as_ref()
    .expect("HTTP/3 snapshot should build QUIC config");

  assert!(quic_config.requires_sni_policy_demux());
  assert_eq!(quic_config.configs().len(), 1);
  assert_eq!(quic_config.policy_index_for_sni(Some("example.com")), None);
  assert_eq!(
    quic_config.policy_index_for_sni(Some("other.example.com")),
    Some(0)
  );
}

#[tokio::test]
async fn parse_failure_queues_default_when_no_classification_is_required() {
  let temp_dir = common::TempDir::new("quic-no-demux-parse-failure");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "quic-no-demux-parse-failure");
  let snapshot = AppSnapshot::new(parse_config(&common::minimal_config_toml(
    &cert_path, &key_path,
  )))
  .await
  .expect("application snapshot should initialize");
  assert!(
    snapshot.quic_server_config.is_none(),
    "HTTP/3 disabled config should not require QUIC classification"
  );

  let state = AppHandle::new(snapshot);
  let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
  let (demux, sockets) = QuicDemuxSocket::new(socket, 4, 1);
  let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

  demux
    .handle_datagram(b"not a QUIC Initial", peer, &state, true)
    .await
    .expect("unclassified local datagram should queue");

  let mut receiver = sockets[0]
    .local_rx
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner());
  let queued = receiver.try_recv().expect("datagram should queue locally");
  assert_eq!(queued.bytes, b"not a QUIC Initial");
  assert_eq!(queued.peer, peer);
}

#[tokio::test]
async fn local_datagram_queue_drops_when_capacity_is_full() {
  let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
  let (demux, sockets) = QuicDemuxSocket::new(socket, 2, 1);
  let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

  demux.queue_local(0, &[1], peer);
  demux.queue_local(0, &[2], peer);
  demux.queue_local(0, &[3], peer);

  let mut receiver = sockets[0]
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
    _connection_permit: None,
  }
}

fn local_session(last_seen: Instant) -> LocalQuicSession {
  LocalQuicSession {
    policy_index: 0,
    last_seen,
  }
}
