use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::oneshot;

use super::RedisPool;
use crate::cache::CacheStats;
use crate::config::MetricsConfig;
use crate::config::{
  CryptoConfig, RedisPlaintextPolicy, RedisPoolConfig, SharedStateBackendConfig,
  SharedStateBackendKind,
};
use crate::metrics::Metrics;
use crate::tls::TlsServerSessionStorageStats;

fn pool_config(url: String, command_timeout_ms: u64) -> SharedStateBackendConfig {
  SharedStateBackendConfig {
    name: "redis-test".to_string(),
    kind: SharedStateBackendKind::Redis,
    connection_url: Some(url),
    connection_url_env: None,
    max_connections: 1,
    connect_timeout_ms: 100,
    redis_pool: Some(RedisPoolConfig {
      max_waiters: Some(1),
      pool_wait_timeout_ms: Some(50),
      command_timeout_ms: Some(command_timeout_ms),
      idle_timeout_ms: 60_000,
      health_check_interval_ms: 60_000,
      reconnect_min_backoff_ms: 1,
      reconnect_max_backoff_ms: 1,
      ..Default::default()
    }),
    redis_tls: Default::default(),
    redis_auth: Default::default(),
    tls: Default::default(),
  }
}

async fn read_command(reader: &mut BufReader<OwnedReadHalf>) -> std::io::Result<Vec<Vec<u8>>> {
  let mut header = String::new();
  reader.read_line(&mut header).await?;
  let count = header
    .strip_prefix('*')
    .and_then(|line| line.trim_end().parse::<usize>().ok())
    .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid RESP array header"))?;
  let mut command = Vec::with_capacity(count);
  for _ in 0..count {
    let mut length = String::new();
    reader.read_line(&mut length).await?;
    let length = length
      .strip_prefix('$')
      .and_then(|line| line.trim_end().parse::<usize>().ok())
      .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid RESP bulk header"))?;
    let mut value = vec![0; length + 2];
    reader.read_exact(&mut value).await?;
    if value[length..] != *b"\r\n" {
      return Err(Error::new(
        ErrorKind::InvalidData,
        "invalid RESP bulk terminator",
      ));
    }
    value.truncate(length);
    command.push(value);
  }
  Ok(command)
}

#[tokio::test]
async fn sequential_commands_reuse_one_initialized_connection() {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("test listener should bind");
  let address = listener
    .local_addr()
    .expect("test listener should have an address");
  let accepted = Arc::new(AtomicUsize::new(0));
  let server_accepted = accepted.clone();
  let server = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("client should connect");
    server_accepted.fetch_add(1, Ordering::Relaxed);
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut commands = Vec::new();
    for _ in 0..4 {
      let command = read_command(&mut reader)
        .await
        .expect("command should use RESP framing");
      let reply = match command.first().map(Vec::as_slice) {
        Some(b"AUTH") | Some(b"SELECT") => b"+OK\r\n".as_slice(),
        Some(b"GET") => b"$1\r\nv\r\n".as_slice(),
        _ => b"-ERR unexpected command\r\n".as_slice(),
      };
      writer
        .write_all(reply)
        .await
        .expect("server should reply to command");
      commands.push(command);
    }
    commands
  });

  let mut config = pool_config(format!("redis://user:password@{}/2", address), 100);
  config
    .redis_pool
    .as_mut()
    .expect("test pool configuration should exist")
    .min_idle_connections = 1;
  let metrics = Metrics::new();
  let pool = RedisPool::new(
    &config,
    Duration::from_millis(200),
    &CryptoConfig::default(),
    RedisPlaintextPolicy::Allow,
    metrics.clone(),
  )
  .expect("pool should build");
  pool
    .prewarm()
    .await
    .expect("required idle connection should prewarm");
  let first = pool
    .command(&[b"GET".to_vec(), b"first".to_vec()])
    .await
    .expect("first command should succeed");
  let second = pool
    .command(&[b"GET".to_vec(), b"second".to_vec()])
    .await
    .expect("second command should succeed");
  assert!(matches!(first, super::Resp::Bulk(Some(value)) if value == b"v"));
  assert!(matches!(second, super::Resp::Bulk(Some(value)) if value == b"v"));

  let commands = server.await.expect("test server should not panic");
  assert_eq!(accepted.load(Ordering::Relaxed), 1);
  assert_eq!(commands.len(), 4);
  assert_eq!(commands[0][0], b"AUTH");
  assert_eq!(commands[1][0], b"SELECT");
  assert_eq!(commands[2][0], b"GET");
  assert_eq!(commands[3][0], b"GET");
  let prometheus = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );
  assert!(prometheus.contains(
    "oxibelt_shared_state_pool_connections{backend=\"redis-test\",kind=\"redis\",state=\"idle\"} 1"
  ));
  assert!(prometheus.contains(
    "oxibelt_shared_state_pool_acquisitions_total{backend=\"redis-test\",kind=\"redis\",outcome=\"success\"} 2"
  ));
  assert!(!prometheus.contains("password"));
}

#[tokio::test]
async fn password_file_authentication_uses_single_argument_auth_without_mtls() {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("test listener should bind");
  let address = listener
    .local_addr()
    .expect("test listener should have an address");
  let server = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("client should connect");
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let auth = read_command(&mut reader)
      .await
      .expect("AUTH should use RESP framing");
    writer
      .write_all(b"+OK\r\n")
      .await
      .expect("server should accept password authentication");
    auth
  });
  let temp_dir = tempfile::tempdir().expect("test secret directory should create");
  let password_file = temp_dir.path().join("redis-password");
  std::fs::write(&password_file, "test-password\n").expect("test password should write");

  let mut config = pool_config(format!("redis://{address}"), 100);
  config.redis_auth.password_file = Some(password_file);
  let pool = RedisPool::new(
    &config,
    Duration::from_millis(200),
    &CryptoConfig::default(),
    RedisPlaintextPolicy::Allow,
    Metrics::new(),
  )
  .expect("password-file Redis pool should build");
  pool
    .prewarm()
    .await
    .expect("password authentication must complete before activation");

  assert_eq!(
    server.await.expect("server should not panic"),
    vec![b"AUTH".to_vec(), b"test-password".to_vec()]
  );
}

#[test]
fn changed_password_file_replaces_the_pool_on_full_reload() {
  let temp_dir = tempfile::tempdir().expect("test secret directory should create");
  let password_file = temp_dir.path().join("redis-password");
  std::fs::write(&password_file, "old-password\n").expect("test password should write");
  let mut config = pool_config("redis://127.0.0.1:0".to_string(), 100);
  config.redis_auth.password_file = Some(password_file.clone());
  let pool = RedisPool::new(
    &config,
    Duration::from_millis(200),
    &CryptoConfig::default(),
    RedisPlaintextPolicy::Allow,
    Metrics::new(),
  )
  .expect("password-file Redis pool should build");

  std::fs::write(&password_file, "new-password\n").expect("rotated password should write");
  assert!(
    !pool
      .matches_config(
        &config,
        Duration::from_millis(200),
        &CryptoConfig::default(),
        RedisPlaintextPolicy::Allow,
      )
      .expect("rotated password configuration should resolve"),
    "password-file content must participate in the pool identity"
  );
}

#[test]
fn secure_redis_pool_rebuilds_on_full_reload_to_refresh_tls_material() {
  let config = pool_config("rediss://redis.edge.test:6380/0".to_string(), 100);
  let pool = RedisPool::new(
    &config,
    Duration::from_millis(200),
    &CryptoConfig::default(),
    RedisPlaintextPolicy::Deny,
    Metrics::new(),
  )
  .expect("secure Redis pool should build");

  assert!(
    !pool
      .matches_config(
        &config,
        Duration::from_millis(200),
        &CryptoConfig::default(),
        RedisPlaintextPolicy::Deny,
      )
      .expect("secure Redis configuration should resolve"),
    "rediss pools must re-read certificate and trust material on full reload"
  );
}

#[tokio::test]
async fn timed_out_command_discards_its_connection_before_reuse() {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("test listener should bind");
  let address = listener
    .local_addr()
    .expect("test listener should have an address");
  let accepted = Arc::new(AtomicUsize::new(0));
  let server_accepted = accepted.clone();
  let (first_command_tx, first_command_rx) = oneshot::channel();
  let server = tokio::spawn(async move {
    let (first, _) = listener
      .accept()
      .await
      .expect("first client should connect");
    server_accepted.fetch_add(1, Ordering::Relaxed);
    let (first_reader, _first_writer) = first.into_split();
    let mut first_reader = BufReader::new(first_reader);
    let first_command = read_command(&mut first_reader)
      .await
      .expect("first command should use RESP framing");
    assert_eq!(first_command[0], b"GET");
    let _ = first_command_tx.send(());

    let (second, _) = listener
      .accept()
      .await
      .expect("replacement client should connect");
    server_accepted.fetch_add(1, Ordering::Relaxed);
    let (second_reader, mut second_writer) = second.into_split();
    let mut second_reader = BufReader::new(second_reader);
    let second_command = read_command(&mut second_reader)
      .await
      .expect("replacement command should use RESP framing");
    assert_eq!(second_command[0], b"GET");
    second_writer
      .write_all(b"$1\r\nv\r\n")
      .await
      .expect("replacement response should write");
  });

  let config = pool_config(format!("redis://{address}"), 20);
  let pool = RedisPool::new(
    &config,
    Duration::from_millis(100),
    &CryptoConfig::default(),
    RedisPlaintextPolicy::Allow,
    Metrics::new(),
  )
  .expect("pool should build");
  let first_pool = pool.clone();
  let first = tokio::spawn(async move {
    first_pool
      .command(&[b"GET".to_vec(), b"slow".to_vec()])
      .await
  });
  first_command_rx
    .await
    .expect("server should receive the first command");
  assert!(
    first
      .await
      .expect("first client task should not panic")
      .is_err()
  );
  tokio::time::sleep(Duration::from_millis(5)).await;

  let response = pool
    .command(&[b"GET".to_vec(), b"replacement".to_vec()])
    .await
    .expect("replacement command should use a new connection");
  assert!(matches!(response, super::Resp::Bulk(Some(value)) if value == b"v"));
  server.await.expect("test server should not panic");
  assert_eq!(accepted.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn zero_waiters_rejects_excess_work_without_opening_another_socket() {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("test listener should bind");
  let address = listener
    .local_addr()
    .expect("test listener should have an address");
  let accepted = Arc::new(AtomicUsize::new(0));
  let server_accepted = accepted.clone();
  let (started_tx, started_rx) = oneshot::channel();
  let (release_tx, release_rx) = oneshot::channel();
  let server = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("client should connect");
    server_accepted.fetch_add(1, Ordering::Relaxed);
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let command = read_command(&mut reader)
      .await
      .expect("first command should use RESP framing");
    assert_eq!(command[0], b"GET");
    let _ = started_tx.send(());
    release_rx
      .await
      .expect("test should release the held command");
    writer
      .write_all(b"$1\r\nv\r\n")
      .await
      .expect("server should complete held command");
  });

  let mut config = pool_config(format!("redis://{address}"), 100);
  config
    .redis_pool
    .as_mut()
    .expect("test pool configuration should exist")
    .max_waiters = Some(0);
  let metrics = Metrics::new();
  let pool = RedisPool::new(
    &config,
    Duration::from_millis(100),
    &CryptoConfig::default(),
    RedisPlaintextPolicy::Allow,
    metrics.clone(),
  )
  .expect("pool should build");
  let first_pool = pool.clone();
  let first = tokio::spawn(async move {
    first_pool
      .command(&[b"GET".to_vec(), b"held".to_vec()])
      .await
  });
  started_rx
    .await
    .expect("server should receive the held command");

  let prometheus = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );
  assert!(prometheus.contains(
    "oxibelt_shared_state_pool_connections{backend=\"redis-test\",kind=\"redis\",state=\"active\"} 1"
  ));

  let error = pool
    .command(&[b"GET".to_vec(), b"rejected".to_vec()])
    .await
    .expect_err("zero waiters should reject excess work immediately");
  assert!(error.to_string().contains("command queue is full"));
  assert_eq!(accepted.load(Ordering::Relaxed), 1);

  release_tx
    .send(())
    .expect("held command should still be pending");
  assert!(
    first
      .await
      .expect("first client task should not panic")
      .is_ok()
  );
  server.await.expect("test server should not panic");
  let prometheus = metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  );
  assert!(prometheus.contains(
    "oxibelt_shared_state_pool_acquisitions_total{backend=\"redis-test\",kind=\"redis\",outcome=\"queue_full\"} 1"
  ));
}
