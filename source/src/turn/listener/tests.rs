use std::future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::oneshot;

use crate::config::{
  LoadBalancingAlgorithm, TurnAuthConfig, TurnAuthMode, TurnListenerTlsConfig,
  TurnStaticCredentialConfig, TurnUpstreamPoolConfig, TurnUpstreamPoolHealthCheckConfig,
  TurnUpstreamPoolServerConfig, UpstreamPoolServerState,
};
use crate::turn::pools::TurnPoolState;

use super::*;

#[test]
fn paired_wildcard_families_can_share_a_turn_udp_port() -> anyhow::Result<()> {
  let ipv4 = bind_udp_socket("0.0.0.0:0".parse()?)?;
  let port = ipv4.local_addr()?.port();
  let ipv6 = bind_udp_socket(format!("[::]:{port}").parse()?)?;

  assert_eq!(ipv6.local_addr()?.port(), port);
  assert!(socket2::SockRef::from(&ipv6).only_v6()?);
  Ok(())
}

#[test]
fn turn_listener_key_preserves_state_for_tls_only_refreshes() {
  let config = WebRtcTurnListenerConfig {
    name: "turn-a".to_string(),
    mode: WebRtcTurnListenerMode::EdgeRelay,
    bind_udp: Some("127.0.0.1:3478".parse().expect("valid UDP bind")),
    bind_udp_additional: Vec::new(),
    bind_tcp: Some("127.0.0.1:3478".parse().expect("valid TCP bind")),
    bind_tcp_additional: Vec::new(),
    bind_tls: Some("127.0.0.1:5349".parse().expect("valid TLS bind")),
    bind_tls_additional: Vec::new(),
    idle_timeout_ms: 60_000,
    realm: "turn.example.test".to_string(),
    auth: TurnAuthConfig::default(),
    udp_pool: None,
    tcp_pool: None,
    tls_pool: None,
    public_ip: None,
    relay_bind_ip: None,
    relay_port_range: None,
    relay_families: Vec::new(),
    limits: Default::default(),
    peer_policy: Default::default(),
    stream_outbound_queue_capacity: 16,
    tls: TurnListenerTlsConfig::default(),
  };
  let options = TcpListenOptions {
    workers: 1,
    reuse_port: false,
    backlog: 1024,
  };
  let baseline = TurnListenerKey::new(&config, options);

  let mut tls_only = config.clone();
  tls_only.tls.cert_chain = Some(PathBuf::from("current/fullchain.pem"));
  tls_only.tls.private_key = Some(PathBuf::from("current/privkey.pem"));
  tls_only.tls.resumption = Some(Default::default());
  assert_eq!(baseline, TurnListenerKey::new(&tls_only, options));

  let mut state_change = config;
  state_change.realm = "other.example.test".to_string();
  assert_ne!(baseline, TurnListenerKey::new(&state_change, options));
}

#[test]
fn turn_listener_socket_keys_detect_wildcard_specific_overlap() {
  let base = WebRtcTurnListenerConfig {
    name: "turn-a".to_string(),
    mode: WebRtcTurnListenerMode::ProxyPool,
    bind_udp: None,
    bind_udp_additional: Vec::new(),
    bind_tcp: None,
    bind_tcp_additional: Vec::new(),
    bind_tls: None,
    bind_tls_additional: Vec::new(),
    idle_timeout_ms: 60_000,
    realm: "turn.example.test".to_string(),
    auth: TurnAuthConfig::default(),
    udp_pool: None,
    tcp_pool: None,
    tls_pool: None,
    public_ip: None,
    relay_bind_ip: None,
    relay_port_range: None,
    relay_families: Vec::new(),
    limits: Default::default(),
    peer_policy: Default::default(),
    stream_outbound_queue_capacity: 32,
    tls: TurnListenerTlsConfig::default(),
  };
  let options = TcpListenOptions {
    workers: 1,
    reuse_port: false,
    backlog: 1024,
  };

  let mut udp_wildcard = base.clone();
  udp_wildcard.bind_udp = Some("0.0.0.0:3478".parse().expect("wildcard UDP bind"));
  let mut udp_specific = base.clone();
  udp_specific.bind_udp = Some("127.0.0.1:3478".parse().expect("specific UDP bind"));
  assert!(
    TurnListenerKey::new(&udp_wildcard, options)
      .socket_overlaps(&TurnListenerKey::new(&udp_specific, options))
  );

  let mut tcp_wildcard = base.clone();
  tcp_wildcard.bind_tcp = Some("0.0.0.0:5349".parse().expect("wildcard TCP bind"));
  let mut tls_specific = base;
  tls_specific.bind_tls = Some("127.0.0.1:5349".parse().expect("specific TLS bind"));
  assert!(
    TurnListenerKey::new(&tcp_wildcard, options)
      .socket_overlaps(&TurnListenerKey::new(&tls_specific, options))
  );
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
  fn drop(&mut self) {
    self.0.store(true, Ordering::SeqCst);
  }
}

async fn spawn_tracked_reader() -> (Arc<AtomicBool>, JoinHandle<()>) {
  let dropped = Arc::new(AtomicBool::new(false));
  let task_dropped = dropped.clone();
  let (started_tx, started_rx) = oneshot::channel();
  let task = tokio::spawn(async move {
    let _drop_flag = DropFlag(task_dropped);
    let _ = started_tx.send(());
    future::pending::<()>().await;
  });
  started_rx.await.expect("reader task should start");
  (dropped, task)
}

async fn assert_reader_aborted(dropped: &AtomicBool) {
  for _ in 0..50 {
    if dropped.load(Ordering::SeqCst) {
      return;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert!(
    dropped.load(Ordering::SeqCst),
    "UDP session reader task was not aborted"
  );
}

async fn udp_proxy_session(
  last_activity: Instant,
  runtime: &Arc<crate::runtime_introspection::RuntimeIntrospectionState>,
) -> anyhow::Result<(Arc<AtomicBool>, UdpProxySession)> {
  let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
  let (dropped, upstream_task) = spawn_tracked_reader().await;
  Ok((
    dropped,
    UdpProxySession {
      upstream,
      upstream_task,
      _selection: turn_pool_selection(),
      last_activity: Arc::new(std::sync::Mutex::new(last_activity)),
      _introspection_guard: runtime.guard(RuntimeCounter::TurnUdpClient),
      _overload_connection: crate::overload::OverloadRuntime::new(
        &crate::config::OverloadConfig::default(),
      )
      .try_admit_connection()
      .expect("normal overload state should admit a test connection"),
    },
  ))
}

fn turn_pool_selection() -> TurnPoolSelection {
  let pools = TurnPoolState::new(&[TurnUpstreamPoolConfig {
    name: "turn-udp".to_string(),
    algorithm: LoadBalancingAlgorithm::PowerOfTwoChoices,
    hash_key: None,
    servers: vec![TurnUpstreamPoolServerConfig {
      id: Some("turn-a".to_string()),
      origin: Url::parse("turn://127.0.0.1:3478").expect("valid TURN URL"),
      weight: 1,
      max_conns: 0,
      backup: false,
      state: UpstreamPoolServerState::Ready,
      tls: Default::default(),
    }],
    health_check: TurnUpstreamPoolHealthCheckConfig {
      enabled: false,
      ..TurnUpstreamPoolHealthCheckConfig::default()
    },
  }]);
  pools
    .select(
      "turn-udp",
      "127.0.0.1".parse().expect("valid client IP"),
      "127.0.0.1:49152",
    )
    .expect("TURN pool selection should succeed")
}

#[tokio::test]
async fn expire_udp_sessions_aborts_expired_reader_task() -> anyhow::Result<()> {
  let mut sessions = HashMap::new();
  let runtime = crate::runtime_introspection::RuntimeIntrospectionState::new();
  runtime.set_enabled(true);
  let (dropped, session) =
    udp_proxy_session(Instant::now() - Duration::from_millis(100), &runtime).await?;
  sessions.insert("127.0.0.1:49152".parse()?, session);
  assert_eq!(runtime.connections().turn.udp_clients_active, 1);

  expire_udp_sessions(&mut sessions, Duration::from_millis(1));

  assert!(sessions.is_empty());
  assert_eq!(runtime.connections().turn.udp_clients_active, 0);
  assert_reader_aborted(&dropped).await;
  Ok(())
}

#[tokio::test]
async fn first_turn_frame_read_times_out_idle_stream() -> anyhow::Result<()> {
  let (_client, mut server) = tokio::io::duplex(64);

  let error = read_turn_frame_with_timeout(&mut server, Duration::from_millis(5))
    .await
    .expect_err("idle TURN TCP stream should time out before first frame");

  assert_eq!(error.to_string(), "TURN first frame timed out");
  Ok(())
}

#[tokio::test]
async fn expire_udp_sessions_keeps_active_reader_task() -> anyhow::Result<()> {
  let mut sessions = HashMap::new();
  let runtime = crate::runtime_introspection::RuntimeIntrospectionState::new();
  runtime.set_enabled(true);
  let (dropped, session) = udp_proxy_session(Instant::now(), &runtime).await?;
  sessions.insert("127.0.0.1:49152".parse()?, session);

  expire_udp_sessions(&mut sessions, Duration::from_secs(60));

  assert_eq!(sessions.len(), 1);
  assert_eq!(runtime.connections().turn.udp_clients_active, 1);
  assert!(
    !dropped.load(Ordering::SeqCst),
    "active UDP session reader task should keep running"
  );
  drop(sessions);
  assert_eq!(runtime.connections().turn.udp_clients_active, 0);
  assert_reader_aborted(&dropped).await;
  Ok(())
}

#[tokio::test]
async fn expire_udp_sessions_keeps_recently_refreshed_session() -> anyhow::Result<()> {
  let mut sessions = HashMap::new();
  let runtime = crate::runtime_introspection::RuntimeIntrospectionState::new();
  let (_, session) = udp_proxy_session(Instant::now() - Duration::from_secs(60), &runtime).await?;
  mark_udp_session_active(&session.last_activity);
  sessions.insert("127.0.0.1:49152".parse()?, session);

  expire_udp_sessions(&mut sessions, Duration::from_secs(1));

  assert_eq!(sessions.len(), 1);
  Ok(())
}

#[test]
fn turn_udp_quiesce_keeps_known_clients_and_rejects_new_clients() {
  assert!(udp_client_admitted(false, false));
  assert!(udp_client_admitted(true, true));
  assert!(!udp_client_admitted(true, false));
}

#[test]
fn turn_stream_ids_are_process_unique() {
  let ids = (0..4096)
    .map(|_| next_turn_stream_id().expect("stream identity space must remain available"))
    .collect::<std::collections::HashSet<_>>();
  assert_eq!(ids.len(), 4096);
}

#[test]
fn proxy_udp_session_capacity_rejects_only_new_sessions_at_the_limit() {
  assert!(proxy_udp_session_admitted(0, 1));
  assert!(!proxy_udp_session_admitted(1, 1));
  assert!(!proxy_udp_session_admitted(4096, 4096));
}

#[test]
fn turn_datagrams_must_consume_exactly_one_frame() {
  let stun = encode_message(BINDING_REQUEST, [4u8; 12], &[]);
  assert!(turn_datagram_consumes_exact_frame(&stun));
  let mut appended_stun = stun;
  appended_stun.extend_from_slice(b"trailing");
  assert!(!turn_datagram_consumes_exact_frame(&appended_stun));

  let padded_channel = encode_channel_data(0x4001, b"x").expect("valid ChannelData");
  assert!(turn_datagram_consumes_exact_frame(&padded_channel));
  let mut unpadded_channel = padded_channel.clone();
  unpadded_channel.truncate(5);
  assert!(turn_datagram_consumes_exact_frame(&unpadded_channel));
  let mut appended_channel = padded_channel;
  appended_channel.push(0);
  assert!(!turn_datagram_consumes_exact_frame(&appended_channel));
}

#[tokio::test]
async fn proxy_stream_idle_timeout_tracks_active_bytes() -> anyhow::Result<()> {
  let (mut left_client, left_server) = tokio::io::duplex(64);
  let (right_server, mut right_client) = tokio::io::duplex(64);
  let (_listener_tx, listener_rx) = tokio::sync::watch::channel(false);
  let lifecycle = crate::lifecycle::LifecycleState::default();
  let drain =
    crate::lifecycle::ConnectionDrain::new(listener_rx, lifecycle.subscribe(), Duration::ZERO);
  let task = tokio::spawn(copy_bidirectional_with_idle(
    Box::new(left_server),
    Box::new(right_server),
    Duration::from_millis(30),
    drain,
  ));

  for byte in 0u8..5 {
    left_client.write_all(&[byte]).await?;
    let mut received = [0u8; 1];
    right_client.read_exact(&mut received).await?;
    assert_eq!(received[0], byte);
    tokio::time::sleep(Duration::from_millis(15)).await;
  }
  assert!(
    !task.is_finished(),
    "active traffic must refresh the idle timer"
  );

  drop(left_client);
  drop(right_client);
  tokio::time::timeout(Duration::from_secs(1), task).await???;
  Ok(())
}

#[test]
fn malformed_validate_datagram_is_dropped_without_poisoning_the_next_packet() -> anyhow::Result<()>
{
  let config = WebRtcTurnListenerConfig {
    name: "turn-udp".to_string(),
    mode: WebRtcTurnListenerMode::ProxyPool,
    bind_udp: None,
    bind_udp_additional: Vec::new(),
    bind_tcp: None,
    bind_tcp_additional: Vec::new(),
    bind_tls: None,
    bind_tls_additional: Vec::new(),
    idle_timeout_ms: 1_000,
    realm: "turn.example.test".to_string(),
    auth: TurnAuthConfig {
      mode: TurnAuthMode::Validate,
      static_credentials: vec![TurnStaticCredentialConfig {
        username: "turn-user".to_string(),
        password: Some("turn-password".to_string()),
        password_env: None,
        password_file: None,
      }],
      ..TurnAuthConfig::default()
    },
    udp_pool: Some("turn-udp".to_string()),
    tcp_pool: None,
    tls_pool: None,
    public_ip: None,
    relay_bind_ip: None,
    relay_port_range: None,
    relay_families: Vec::new(),
    limits: Default::default(),
    peer_policy: Default::default(),
    stream_outbound_queue_capacity: 16,
    tls: Default::default(),
  };
  let valid = encode_message(ALLOCATE_REQUEST, [7u8; 12], &[]);
  let mut malformed = valid.clone();
  malformed[2..4].copy_from_slice(&4u16.to_be_bytes());

  assert!(!proxy_auth_allows(&config, &malformed)?);
  assert!(proxy_auth_allows(&config, &valid)?);
  Ok(())
}

#[tokio::test]
async fn malformed_edge_datagram_is_dropped_and_a_later_binding_request_succeeds()
-> anyhow::Result<()> {
  let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
  let client = UdpSocket::bind("127.0.0.1:0").await?;
  let config = WebRtcTurnListenerConfig {
    name: "turn-edge-udp".to_string(),
    mode: WebRtcTurnListenerMode::EdgeRelay,
    bind_udp: None,
    bind_udp_additional: Vec::new(),
    bind_tcp: None,
    bind_tcp_additional: Vec::new(),
    bind_tls: None,
    bind_tls_additional: Vec::new(),
    idle_timeout_ms: 1_000,
    realm: "turn.example.test".to_string(),
    auth: TurnAuthConfig::default(),
    udp_pool: None,
    tcp_pool: None,
    tls_pool: None,
    public_ip: None,
    relay_bind_ip: None,
    relay_port_range: None,
    relay_families: Vec::new(),
    limits: Default::default(),
    peer_policy: Default::default(),
    stream_outbound_queue_capacity: 16,
    tls: Default::default(),
  };
  let runtime = crate::runtime_introspection::RuntimeIntrospectionState::new();
  let edge = super::super::edge::EdgeState::new(runtime);
  let client_addr = client.local_addr()?;

  super::super::edge::handle_udp_packet(
    socket.clone(),
    edge.clone(),
    &config,
    client_addr,
    &[0x40, 0x00, 0x00, 0x04],
  )
  .await?;

  let request = encode_message(BINDING_REQUEST, [9u8; 12], &[]);
  super::super::edge::handle_udp_packet(socket, edge, &config, client_addr, &request).await?;
  let mut response = [0u8; 256];
  let len = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut response)).await??;
  let response = parse_stun(&response[..len])?;
  assert_eq!(response.message_type, success_type(BINDING_REQUEST));
  assert_eq!(response.transaction_id, [9u8; 12]);
  Ok(())
}
