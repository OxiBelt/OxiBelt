use std::future;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::oneshot;

use super::*;
use crate::config::{
  LoadBalancingAlgorithm, TurnUpstreamPoolConfig, TurnUpstreamPoolHealthCheckConfig,
  TurnUpstreamPoolServerConfig, UpstreamPoolServerState,
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
    },
  ))
}

fn turn_pool_selection() -> TurnPoolSelection {
  let pools = TurnPoolState::new(&[TurnUpstreamPoolConfig {
    name: "turn-udp".to_string(),
    algorithm: LoadBalancingAlgorithm::RoundRobin,
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
  let (dropped, session) = udp_proxy_session(Instant::now() - Duration::from_millis(100)).await?;
  sessions.insert("127.0.0.1:49152".parse()?, session);

  expire_udp_sessions(&mut sessions, Duration::from_millis(1));

  assert!(sessions.is_empty());
  assert_reader_aborted(&dropped).await;
  Ok(())
}

#[tokio::test]
async fn expire_udp_sessions_keeps_active_reader_task() -> anyhow::Result<()> {
  let mut sessions = HashMap::new();
  let (dropped, session) = udp_proxy_session(Instant::now()).await?;
  sessions.insert("127.0.0.1:49152".parse()?, session);

  expire_udp_sessions(&mut sessions, Duration::from_secs(60));

  assert_eq!(sessions.len(), 1);
  assert!(
    !dropped.load(Ordering::SeqCst),
    "active UDP session reader task should keep running"
  );
  drop(sessions);
  assert_reader_aborted(&dropped).await;
  Ok(())
}
