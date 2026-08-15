use std::future;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::oneshot;

use super::*;
use crate::config::{
  LoadBalancingAlgorithm, TurnAuthConfig, TurnAuthMode, TurnStaticCredentialConfig,
  TurnUpstreamPoolConfig, TurnUpstreamPoolHealthCheckConfig, TurnUpstreamPoolServerConfig,
  UpstreamPoolServerState,
};
use crate::turn::pools::TurnPoolState;

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
      last_activity,
      _introspection_guard: runtime.guard(RuntimeCounter::TurnUdpClient),
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

#[test]
fn turn_udp_quiesce_keeps_known_clients_and_rejects_new_clients() {
  assert!(udp_client_admitted(false, false));
  assert!(udp_client_admitted(true, true));
  assert!(!udp_client_admitted(true, false));
}

#[test]
fn malformed_validate_datagram_is_dropped_without_poisoning_the_next_packet() -> anyhow::Result<()>
{
  let config = WebRtcTurnListenerConfig {
    name: "turn-udp".to_string(),
    mode: WebRtcTurnListenerMode::ProxyPool,
    bind_udp: None,
    bind_tcp: None,
    bind_tls: None,
    idle_timeout_ms: 1_000,
    realm: "turn.example.test".to_string(),
    auth: TurnAuthConfig {
      mode: TurnAuthMode::Validate,
      static_credentials: vec![TurnStaticCredentialConfig {
        username: "turn-user".to_string(),
        password: Some("turn-password".to_string()),
        password_env: None,
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
    bind_tcp: None,
    bind_tls: None,
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
