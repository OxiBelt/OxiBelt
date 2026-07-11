//! Persistent, bounded Redis connections for shared-state commands.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use deadpool::Runtime;
use deadpool::managed::{Object, Pool, PoolError, QueueMode, TimeoutType, Timeouts};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{
  CryptoConfig, RedisPlaintextPolicy, RedisPoolSettings, SharedStateBackendConfig,
};
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
    crypto: &CryptoConfig,
    plaintext_policy: RedisPlaintextPolicy,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<Self> {
    let resolution =
      RedisPoolIdentity::resolve(config, operation_timeout, crypto, plaintext_policy)?;
    let identity = resolution.identity;
    let settings = identity.settings.clone();
    let backend_name: Arc<str> = Arc::from(config.name.as_str());
    let circuit = ReconnectCircuit::new(backend_name.clone(), settings.clone(), metrics.clone());
    let manager = RedisConnectionManager {
      endpoint: identity.endpoint.clone(),
      credentials: identity.credentials.clone(),
      tls: resolution.tls,
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
    // A configured TLS transport or ACL/password must be proven usable before
    // the new runtime snapshot becomes active. This intentionally creates one
    // connection even when min_idle_connections is zero.
    let required = self
      .inner
      .settings
      .min_idle_connections
      .max(usize::from(self.inner.identity.requires_activation_probe()));
    self.prewarm_at_least(required, true).await
  }

  pub(super) fn matches_config(
    &self,
    config: &SharedStateBackendConfig,
    operation_timeout: Duration,
    crypto: &CryptoConfig,
    plaintext_policy: RedisPlaintextPolicy,
  ) -> anyhow::Result<bool> {
    let candidate =
      RedisPoolIdentity::resolve(config, operation_timeout, crypto, plaintext_policy)?;
    // Rebuild secure pools on every configuration reload. In addition to
    // credential content, this refreshes trust roots and client certificate
    // material that can change at the same configured file path.
    Ok(
      self.inner.identity.tls_identity.is_none()
        && candidate.identity.tls_identity.is_none()
        && self.inner.identity == candidate.identity,
    )
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
    self
      .prewarm_at_least(self.inner.settings.min_idle_connections, required)
      .await
  }

  async fn prewarm_at_least(&self, target: usize, required: bool) -> anyhow::Result<()> {
    let status = self.inner.pool.status();
    let missing = target.saturating_sub(status.available);
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
    if required && self.inner.pool.status().available < target {
      bail!(
        "shared state Redis backend {} could not establish its required activation connection",
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
#[path = "redis_pool_tests.rs"]
mod tests;
