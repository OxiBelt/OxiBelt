//! Redis connection creation, health checks, endpoint parsing, and reconnect control.

use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use deadpool::managed::{Manager, Metrics as DeadpoolMetrics, RecycleError, RecycleResult};
use tokio::io::BufReader;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;

use crate::config::{RedisPoolSettings, SharedStateBackendConfig};
use crate::metrics::Metrics;

use super::redis_protocol::{expect_ok, read_resp, write_resp_command};

pub(super) struct RedisConnection {
  pub(super) reader: BufReader<OwnedReadHalf>,
  pub(super) writer: OwnedWriteHalf,
}

impl fmt::Debug for RedisConnection {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("RedisConnection(..)")
  }
}

#[derive(Clone)]
pub(super) struct RedisConnectionManager {
  pub(super) endpoint: RedisEndpoint,
  pub(super) connect_timeout: Duration,
  pub(super) health_check_interval: Duration,
  pub(super) command_timeout: Duration,
  pub(super) backend_name: Arc<str>,
  pub(super) metrics: Arc<Metrics>,
  pub(super) circuit: ReconnectCircuit,
}

impl fmt::Debug for RedisConnectionManager {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RedisConnectionManager")
      .field("backend", &self.backend_name)
      .field("endpoint", &self.endpoint.redacted())
      .finish_non_exhaustive()
  }
}

impl Manager for RedisConnectionManager {
  type Type = RedisConnection;
  type Error = RedisManagerError;

  fn create(&self) -> impl Future<Output = Result<Self::Type, Self::Error>> + Send {
    let manager = self.clone();
    async move {
      let attempt = manager.circuit.begin().await?;
      match manager.connect().await {
        Ok(connection) => {
          attempt.succeed();
          manager.metrics.record_shared_state_pool_connection_event(
            manager.backend_name.as_ref(),
            "redis",
            "created",
          );
          Ok(connection)
        }
        Err(error) => Err(error),
      }
    }
  }

  fn recycle(
    &self,
    connection: &mut Self::Type,
    metrics: &DeadpoolMetrics,
  ) -> impl Future<Output = RecycleResult<Self::Error>> + Send {
    let manager = self.clone();
    let should_check = metrics.last_used() >= self.health_check_interval;
    async move {
      if !should_check {
        return Ok(());
      }
      let ping = async {
        write_resp_command(&mut connection.writer, &[b"PING".to_vec()]).await?;
        expect_ok(read_resp(&mut connection.reader).await?)
      };
      match tokio::time::timeout(manager.command_timeout, ping).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => {
          manager.circuit.record_transport_failure();
          manager.metrics.record_shared_state_pool_connection_event(
            manager.backend_name.as_ref(),
            "redis",
            "health_failed",
          );
          Err(RecycleError::Backend(RedisManagerError::HealthCheck))
        }
      }
    }
  }
}

impl RedisConnectionManager {
  async fn connect(&self) -> Result<RedisConnection, RedisManagerError> {
    tokio::time::timeout(self.connect_timeout, async {
      let stream = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
        .await
        .map_err(|_| RedisManagerError::Connection)?;
      stream
        .set_nodelay(true)
        .map_err(|_| RedisManagerError::Connection)?;
      let (reader, mut writer) = stream.into_split();
      let mut reader = BufReader::new(reader);
      if let Some(password) = &self.endpoint.password {
        let mut auth = vec![b"AUTH".to_vec()];
        if let Some(username) = &self.endpoint.username {
          auth.push(username.as_bytes().to_vec());
        }
        auth.push(password.as_bytes().to_vec());
        write_resp_command(&mut writer, &auth)
          .await
          .map_err(|_| RedisManagerError::Authentication)?;
        expect_ok(
          read_resp(&mut reader)
            .await
            .map_err(|_| RedisManagerError::Authentication)?,
        )
        .map_err(|_| RedisManagerError::Authentication)?;
      }
      if let Some(database) = self.endpoint.database {
        let select = vec![b"SELECT".to_vec(), database.to_string().into_bytes()];
        write_resp_command(&mut writer, &select)
          .await
          .map_err(|_| RedisManagerError::DatabaseSelection)?;
        expect_ok(
          read_resp(&mut reader)
            .await
            .map_err(|_| RedisManagerError::DatabaseSelection)?,
        )
        .map_err(|_| RedisManagerError::DatabaseSelection)?;
      }
      Ok(RedisConnection { reader, writer })
    })
    .await
    .map_err(|_| RedisManagerError::Connection)?
  }
}

#[derive(Debug)]
pub(super) enum RedisManagerError {
  CircuitOpen,
  Connection,
  Authentication,
  DatabaseSelection,
  HealthCheck,
}

impl fmt::Display for RedisManagerError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let message = match self {
      Self::CircuitOpen => "Redis reconnect circuit is open",
      Self::Connection => "Redis connection failed",
      Self::Authentication => "Redis authentication failed",
      Self::DatabaseSelection => "Redis database selection failed",
      Self::HealthCheck => "Redis health check failed",
    };
    formatter.write_str(message)
  }
}

impl std::error::Error for RedisManagerError {}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct RedisPoolIdentity {
  pub(super) endpoint: RedisEndpoint,
  pub(super) max_connections: usize,
  pub(super) connect_timeout: Duration,
  pub(super) settings: RedisPoolSettings,
}

impl RedisPoolIdentity {
  pub(super) fn from_config(
    config: &SharedStateBackendConfig,
    operation_timeout: Duration,
  ) -> anyhow::Result<Self> {
    let settings = config.redis_pool_settings(duration_ms(operation_timeout))?;
    let connection_url =
      config.connection_url_with_prefix(&format!("shared_state.backends.{}", config.name))?;
    let endpoint = RedisEndpoint::parse(&connection_url, &config.name)?;
    Ok(Self {
      endpoint,
      max_connections: usize::try_from(config.max_connections).map_err(|_| {
        anyhow!(
          "shared state Redis backend {} max_connections is too large",
          config.name
        )
      })?,
      connect_timeout: Duration::from_millis(config.connect_timeout_ms),
      settings,
    })
  }

  pub(super) fn redacted_endpoint(&self) -> String {
    self.endpoint.redacted()
  }
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct RedisEndpoint {
  host: String,
  port: u16,
  username: Option<String>,
  password: Option<String>,
  database: Option<u32>,
}

impl RedisEndpoint {
  fn parse(connection_url: &str, backend_name: &str) -> anyhow::Result<Self> {
    let url = Url::parse(connection_url)
      .with_context(|| format!("failed to parse shared_state Redis URL {backend_name}"))?;
    if url.scheme() != "redis" {
      bail!(
        "shared_state Redis backend {backend_name} must use redis://; rediss:// requires the P0-5 TLS implementation"
      );
    }
    if url.query().is_some() || url.fragment().is_some() {
      bail!("shared_state Redis backend {backend_name} URL must not include a query or fragment");
    }
    let host = url
      .host_str()
      .filter(|host| !host.is_empty())
      .ok_or_else(|| anyhow!("shared_state Redis backend {backend_name} URL is missing host"))?
      .to_string();
    let database = match url.path() {
      "" | "/" => None,
      value => Some(
        value
          .strip_prefix('/')
          .filter(|database| !database.is_empty() && !database.contains('/'))
          .ok_or_else(|| {
            anyhow!("shared_state Redis backend {backend_name} URL database path is invalid")
          })?
          .parse::<u32>()
          .map_err(|_| {
            anyhow!(
              "shared_state Redis backend {backend_name} URL database must be an unsigned integer"
            )
          })?,
      ),
    };
    let username = (!url.username().is_empty()).then(|| url.username().to_string());
    let password = url
      .password()
      .filter(|password| !password.is_empty())
      .map(str::to_string);
    Ok(Self {
      host,
      port: url.port().unwrap_or(6379),
      username,
      password,
      database,
    })
  }

  fn redacted(&self) -> String {
    let database = self
      .database
      .map(|database| format!("/{database}"))
      .unwrap_or_default();
    format!("redis://{}:{}{database}", self.host, self.port)
  }
}

#[derive(Clone)]
pub(super) struct ReconnectCircuit {
  inner: Arc<ReconnectCircuitInner>,
}

struct ReconnectCircuitInner {
  state: Mutex<CircuitState>,
  creation_gate: Arc<Semaphore>,
  settings: RedisPoolSettings,
  backend_name: Arc<str>,
  metrics: Arc<Metrics>,
}

#[derive(Default)]
struct CircuitState {
  phase: CircuitPhase,
  failures: u32,
  retry_at: Option<Instant>,
  next_attempt: u64,
  active_attempt: Option<u64>,
}

#[derive(Default, Eq, PartialEq)]
enum CircuitPhase {
  #[default]
  Closed,
  Open,
  HalfOpen,
}

impl ReconnectCircuit {
  pub(super) fn new(
    backend_name: Arc<str>,
    settings: RedisPoolSettings,
    metrics: Arc<Metrics>,
  ) -> Self {
    Self {
      inner: Arc::new(ReconnectCircuitInner {
        state: Mutex::new(CircuitState::default()),
        creation_gate: Arc::new(Semaphore::new(1)),
        settings,
        backend_name,
        metrics,
      }),
    }
  }

  async fn begin(&self) -> Result<ReconnectAttempt, RedisManagerError> {
    let permit = self
      .inner
      .creation_gate
      .clone()
      .acquire_owned()
      .await
      .map_err(|_| RedisManagerError::CircuitOpen)?;
    let now = Instant::now();
    let mut state = self.lock();
    if state.retry_at.is_some_and(|retry_at| retry_at > now) {
      return Err(RedisManagerError::CircuitOpen);
    }
    if state.phase == CircuitPhase::Open {
      state.phase = CircuitPhase::HalfOpen;
    } else if state.phase == CircuitPhase::HalfOpen {
      return Err(RedisManagerError::CircuitOpen);
    }
    state.next_attempt = state.next_attempt.wrapping_add(1);
    let attempt = state.next_attempt;
    state.active_attempt = Some(attempt);
    drop(state);
    Ok(ReconnectAttempt {
      circuit: self.clone(),
      _permit: permit,
      attempt,
      completed: false,
    })
  }

  pub(super) fn state_label(&self) -> &'static str {
    match self.lock().phase {
      CircuitPhase::Closed => "closed",
      CircuitPhase::Open => "open",
      CircuitPhase::HalfOpen => "half_open",
    }
  }

  pub(super) fn record_transport_failure(&self) {
    let mut state = self.lock();
    state.active_attempt = None;
    state.next_attempt = state.next_attempt.wrapping_add(1);
    self.record_failure_locked(&mut state);
  }

  fn record_success(&self, attempt: u64) {
    let mut state = self.lock();
    if state.active_attempt != Some(attempt) {
      return;
    }
    state.active_attempt = None;
    state.failures = 0;
    state.retry_at = None;
    state.phase = CircuitPhase::Closed;
  }

  fn record_attempt_failure(&self, attempt: u64) {
    let mut state = self.lock();
    if state.active_attempt != Some(attempt) {
      return;
    }
    state.active_attempt = None;
    self.record_failure_locked(&mut state);
  }

  fn record_failure_locked(&self, state: &mut CircuitState) {
    state.failures = state.failures.saturating_add(1);
    let delay = self.backoff_delay(state.failures);
    let open = state.failures >= self.inner.settings.circuit_breaker_failure_threshold;
    state.phase = if open {
      CircuitPhase::Open
    } else {
      CircuitPhase::Closed
    };
    state.retry_at = Some(
      Instant::now()
        + if open {
          delay.max(self.inner.settings.circuit_breaker_open_timeout)
        } else {
          delay
        },
    );
    self
      .inner
      .metrics
      .record_shared_state_pool_connection_event(
        self.inner.backend_name.as_ref(),
        "redis",
        "reconnect_failed",
      );
  }

  fn backoff_delay(&self, failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(63);
    let factor = 1_u128 << exponent;
    let maximum = self.inner.settings.reconnect_max_backoff.as_millis();
    let target = self
      .inner
      .settings
      .reconnect_min_backoff
      .as_millis()
      .saturating_mul(factor)
      .min(maximum)
      .max(1);
    let minimum = (target / 2).max(1);
    let span = target.saturating_sub(minimum).saturating_add(1);
    let mut random = [0_u8; 16];
    let offset = if crate::crypto::random_fill(&mut random).is_ok() {
      u128::from_le_bytes(random) % span
    } else {
      0
    };
    Duration::from_millis(u64::try_from(minimum.saturating_add(offset)).unwrap_or(u64::MAX))
  }

  fn lock(&self) -> MutexGuard<'_, CircuitState> {
    self
      .inner
      .state
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
  }
}

struct ReconnectAttempt {
  circuit: ReconnectCircuit,
  _permit: OwnedSemaphorePermit,
  attempt: u64,
  completed: bool,
}

impl ReconnectAttempt {
  fn succeed(mut self) {
    self.circuit.record_success(self.attempt);
    self.completed = true;
  }
}

impl Drop for ReconnectAttempt {
  fn drop(&mut self) {
    if !self.completed {
      self.circuit.record_attempt_failure(self.attempt);
    }
  }
}

fn duration_ms(duration: Duration) -> u64 {
  duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
  use super::RedisEndpoint;

  #[test]
  fn redis_endpoint_rejects_tls_and_ambiguous_url_forms() {
    for url in [
      "rediss://cache.example.test:6379/0",
      "redis://cache.example.test:6379/0?insecure=true",
      "redis://cache.example.test:6379/not-a-database",
    ] {
      assert!(
        RedisEndpoint::parse(url, "test").is_err(),
        "{url} must not be accepted by the plaintext Redis pool"
      );
    }
  }

  #[test]
  fn redis_endpoint_debug_representation_redacts_credentials() {
    let endpoint = RedisEndpoint::parse("redis://user:secret@cache.example.test:6380/2", "test")
      .expect("Redis endpoint should parse");
    assert_eq!(endpoint.redacted(), "redis://cache.example.test:6380/2");
  }
}
