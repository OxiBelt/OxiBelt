//! Persistent, bounded Redis connections for shared-state commands.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use deadpool::Runtime;
use deadpool::managed::{Object, Pool, PoolError, QueueMode, TimeoutType, Timeouts};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{RedisPoolSettings, SharedStateBackendConfig};
use crate::metrics::{Metrics, SharedStatePoolStatus};

use super::redis_connection::{
  ReconnectCircuit, RedisConnection, RedisConnectionManager, RedisManagerError, RedisPoolIdentity,
};
use super::redis_protocol::{Resp, read_resp, write_resp_command};
use super::runtime::SharedStateTimeout;

type RedisObject = Object<RedisConnectionManager>;
type RedisDeadpool = Pool<RedisConnectionManager>;

#[derive(Clone)]
pub(super) struct RedisPool {
  inner: Arc<RedisPoolInner>,
}

impl fmt::Debug for RedisPool {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RedisPool")
      .field("backend", &self.inner.backend_name)
      .field("endpoint", &self.inner.identity.redacted_endpoint())
      .field("max_connections", &self.inner.identity.max_connections)
      .field("settings", &self.inner.settings)
      .finish_non_exhaustive()
  }
}

struct RedisPoolInner {
  pool: RedisDeadpool,
  admission: Arc<Semaphore>,
  identity: RedisPoolIdentity,
  settings: RedisPoolSettings,
  backend_name: Arc<str>,
  metrics: Arc<Metrics>,
  circuit: ReconnectCircuit,
}

impl RedisPool {
  pub(super) fn new(
    config: &SharedStateBackendConfig,
    operation_timeout: Duration,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    let identity = RedisPoolIdentity::from_config(config, operation_timeout)?;
    let settings = identity.settings.clone();
    let backend_name: Arc<str> = Arc::from(config.name.as_str());
    let circuit = ReconnectCircuit::new(backend_name.clone(), settings.clone(), metrics.clone());
    let manager = RedisConnectionManager {
      endpoint: identity.endpoint.clone(),
      connect_timeout: identity.connect_timeout,
      health_check_interval: settings.health_check_interval,
      command_timeout: settings.command_timeout,
      backend_name: backend_name.clone(),
      metrics: metrics.clone(),
      circuit: circuit.clone(),
    };
    let pool = RedisDeadpool::builder(manager)
      .max_size(identity.max_connections)
      .wait_timeout(Some(settings.pool_wait_timeout))
      .create_timeout(Some(identity.connect_timeout))
      .recycle_timeout(Some(settings.command_timeout))
      .queue_mode(QueueMode::Fifo)
      .runtime(Runtime::Tokio1)
      .build()
      .context("failed to build shared state Redis pool")?;
    let admission_size = identity
      .max_connections
      .checked_add(settings.max_waiters)
      .ok_or_else(|| anyhow!("shared state Redis pool admission capacity overflow"))?;
    let inner = Arc::new(RedisPoolInner {
      pool,
      admission: Arc::new(Semaphore::new(admission_size)),
      identity,
      settings,
      backend_name,
      metrics,
      circuit,
    });
    let pool = Self { inner };
    pool.refresh_metrics();
    pool.spawn_maintenance();
    Ok(pool)
  }

  pub(super) async fn prewarm(&self) -> anyhow::Result<()> {
    self.prewarm_minimum(true).await
  }

  pub(super) fn matches_config(
    &self,
    config: &SharedStateBackendConfig,
    operation_timeout: Duration,
  ) -> anyhow::Result<bool> {
    Ok(self.inner.identity == RedisPoolIdentity::from_config(config, operation_timeout)?)
  }

  #[cfg(test)]
  pub(super) fn test_identity(&self) -> usize {
    Arc::as_ptr(&self.inner) as usize
  }

  pub(super) async fn command(&self, args: &[Vec<u8>]) -> anyhow::Result<Resp> {
    let status_refresh = PoolStatusRefresh::new(self.inner.clone());
    let admission = match self.inner.admission.clone().try_acquire_owned() {
      Ok(permit) => permit,
      Err(_) => {
        self.record_acquisition("queue_full");
        bail!(
          "shared state Redis backend {} command queue is full",
          self.inner.backend_name
        );
      }
    };
    let timeouts = Timeouts {
      wait: Some(self.inner.settings.pool_wait_timeout),
      create: Some(self.inner.identity.connect_timeout),
      recycle: Some(self.inner.settings.command_timeout),
    };
    let object = match self.inner.pool.timeout_get(&timeouts).await {
      Ok(object) => object,
      Err(error) => return self.pool_error(error),
    };
    drop(status_refresh);
    self.record_acquisition("success");
    let mut lease = RedisCommandLease::new(object, admission, self.inner.clone());
    lease.mark_command_started();
    let result = tokio::time::timeout(self.inner.settings.command_timeout, async {
      write_resp_command(&mut lease.connection_mut().writer, args).await?;
      read_resp(&mut lease.connection_mut().reader)
        .await
        .context("failed to read Redis response")
    })
    .await;
    match result {
      Ok(Ok(response)) => {
        lease.mark_reusable();
        self.refresh_metrics();
        Ok(response)
      }
      Ok(Err(_)) => {
        self.refresh_metrics();
        bail!(
          "shared state Redis backend {} command failed",
          self.inner.backend_name
        );
      }
      Err(_) => {
        self.record_connection_event("command_timeout");
        self.refresh_metrics();
        self.timeout("command timed out")
      }
    }
  }

  fn pool_error<T>(&self, error: PoolError<RedisManagerError>) -> anyhow::Result<T> {
    let outcome = match error {
      PoolError::Timeout(TimeoutType::Wait) => "wait_timeout",
      PoolError::Timeout(TimeoutType::Create) => "create_timeout",
      PoolError::Timeout(TimeoutType::Recycle) => "recycle_timeout",
      PoolError::Backend(RedisManagerError::CircuitOpen) => "circuit_open",
      PoolError::Closed => "closed",
      PoolError::Backend(_) | PoolError::NoRuntimeSpecified | PoolError::PostCreateHook(_) => {
        "backend_error"
      }
    };
    self.record_acquisition(outcome);
    self.refresh_metrics();
    match outcome {
      "wait_timeout" => self.timeout("pool wait timed out"),
      "create_timeout" => self.timeout("connection creation timed out"),
      "recycle_timeout" => self.timeout("health check timed out"),
      "circuit_open" => bail!(
        "shared state Redis backend {} reconnect circuit is open",
        self.inner.backend_name
      ),
      "closed" => bail!(
        "shared state Redis backend {} pool is closed",
        self.inner.backend_name
      ),
      _ => bail!(
        "shared state Redis backend {} connection acquisition failed",
        self.inner.backend_name
      ),
    }
  }

  fn timeout<T>(&self, stage: &'static str) -> anyhow::Result<T> {
    Err(
      SharedStateTimeout::new(format!(
        "shared state Redis backend {} {stage}",
        self.inner.backend_name
      ))
      .into(),
    )
  }

  fn spawn_maintenance(&self) {
    let weak_pool = self.inner.pool.weak();
    let weak_inner = Arc::downgrade(&self.inner);
    let interval = self.inner.settings.health_check_interval;
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
      return;
    };
    handle.spawn(async move {
      let mut ticker = tokio::time::interval(interval);
      ticker.tick().await;
      loop {
        ticker.tick().await;
        let (Some(pool), Some(inner)) = (weak_pool.upgrade(), weak_inner.upgrade()) else {
          return;
        };
        RedisPool::maintain(&pool, &inner).await;
      }
    });
  }

  async fn maintain(pool: &RedisDeadpool, inner: &Arc<RedisPoolInner>) {
    let status = pool.status();
    if status.waiting > 0 {
      Self::refresh_inner_metrics(inner);
      return;
    }
    let mut remaining_to_drop = status
      .available
      .saturating_sub(inner.settings.min_idle_connections);
    let removed = pool.retain(|_, metrics| {
      if remaining_to_drop > 0 && metrics.last_used() >= inner.settings.idle_timeout {
        remaining_to_drop -= 1;
        false
      } else {
        true
      }
    });
    for _ in removed.removed {
      inner.metrics.record_shared_state_pool_connection_event(
        inner.backend_name.as_ref(),
        "redis",
        "discarded",
      );
    }

    let available = pool.status().available;
    let mut checked = Vec::with_capacity(available);
    let timeouts = Timeouts {
      wait: Some(inner.settings.pool_wait_timeout),
      create: Some(inner.identity.connect_timeout),
      recycle: Some(inner.settings.command_timeout),
    };
    for _ in 0..available {
      match pool.timeout_get(&timeouts).await {
        Ok(object) => checked.push(object),
        Err(_) => break,
      }
    }
    drop(checked);
    let pooled = Self {
      inner: inner.clone(),
    };
    let _ = pooled.prewarm_minimum(false).await;
    Self::refresh_inner_metrics(inner);
  }

  async fn prewarm_minimum(&self, required: bool) -> anyhow::Result<()> {
    let status = self.inner.pool.status();
    let missing = self
      .inner
      .settings
      .min_idle_connections
      .saturating_sub(status.available);
    if missing == 0 {
      self.refresh_metrics();
      return Ok(());
    }
    let timeouts = Timeouts {
      wait: Some(self.inner.settings.pool_wait_timeout),
      create: Some(self.inner.identity.connect_timeout),
      recycle: Some(self.inner.settings.command_timeout),
    };
    let mut objects = Vec::with_capacity(missing);
    for _ in 0..missing {
      match self.inner.pool.timeout_get(&timeouts).await {
        Ok(object) => objects.push(object),
        Err(error) if required => return self.pool_error(error),
        Err(_) => break,
      }
    }
    drop(objects);
    self.refresh_metrics();
    if required && self.inner.pool.status().available < self.inner.settings.min_idle_connections {
      bail!(
        "shared state Redis backend {} could not prewarm its required idle connections",
        self.inner.backend_name
      );
    }
    Ok(())
  }

  fn record_acquisition(&self, outcome: &'static str) {
    self.inner.metrics.record_shared_state_pool_acquisition(
      self.inner.backend_name.as_ref(),
      "redis",
      outcome,
    );
  }

  fn record_connection_event(&self, event: &'static str) {
    self
      .inner
      .metrics
      .record_shared_state_pool_connection_event(self.inner.backend_name.as_ref(), "redis", event);
  }

  fn refresh_metrics(&self) {
    Self::refresh_inner_metrics(&self.inner);
  }

  fn refresh_inner_metrics(inner: &RedisPoolInner) {
    let status = inner.pool.status();
    inner.metrics.record_shared_state_pool_status(
      inner.backend_name.as_ref(),
      "redis",
      SharedStatePoolStatus {
        active: status.size.saturating_sub(status.available),
        idle: status.available,
        waiting: status.waiting,
        max_connections: status.max_size,
        circuit_state: inner.circuit.state_label(),
      },
    );
  }
}

struct PoolStatusRefresh {
  inner: Arc<RedisPoolInner>,
}

impl PoolStatusRefresh {
  fn new(inner: Arc<RedisPoolInner>) -> Self {
    Self { inner }
  }
}

impl Drop for PoolStatusRefresh {
  fn drop(&mut self) {
    RedisPool::refresh_inner_metrics(&self.inner);
  }
}

struct RedisCommandLease {
  object: Option<RedisObject>,
  _admission: OwnedSemaphorePermit,
  inner: Arc<RedisPoolInner>,
  command_started: bool,
  reusable: bool,
}

impl RedisCommandLease {
  fn new(object: RedisObject, admission: OwnedSemaphorePermit, inner: Arc<RedisPoolInner>) -> Self {
    Self {
      object: Some(object),
      _admission: admission,
      inner,
      command_started: false,
      reusable: false,
    }
  }

  fn connection_mut(&mut self) -> &mut RedisConnection {
    self
      .object
      .as_mut()
      .expect("Redis command lease must hold an object")
  }

  fn mark_command_started(&mut self) {
    self.command_started = true;
  }

  fn mark_reusable(&mut self) {
    self.reusable = true;
  }
}

impl Drop for RedisCommandLease {
  fn drop(&mut self) {
    if self.reusable {
      if let Some(object) = self.object.take() {
        drop(object);
      }
      RedisPool::refresh_inner_metrics(&self.inner);
      return;
    }
    if self.command_started {
      self.inner.circuit.record_transport_failure();
    }
    if let Some(object) = self.object.take() {
      drop(Object::take(object));
      self
        .inner
        .metrics
        .record_shared_state_pool_connection_event(
          self.inner.backend_name.as_ref(),
          "redis",
          "discarded",
        );
    }
    RedisPool::refresh_inner_metrics(&self.inner);
  }
}

#[cfg(test)]
mod tests {
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
  use crate::config::{RedisPoolConfig, SharedStateBackendConfig, SharedStateBackendKind};
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
    let pool = RedisPool::new(&config, Duration::from_millis(200), metrics.clone())
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
    let pool = RedisPool::new(&config, Duration::from_millis(100), Metrics::new())
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
    let pool = RedisPool::new(&config, Duration::from_millis(100), metrics.clone())
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
}
