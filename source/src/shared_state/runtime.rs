//! Bounded execution and deferred cleanup for shared-state backends.

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use tokio::sync::{Semaphore, mpsc};
use tracing::warn;

use crate::config::SharedStateBackendConfig;
use crate::metrics::Metrics;

use super::Backend;

const SHARED_POOL_WARNING_INTERVAL_MS: u64 = 60_000;

#[derive(Debug)]
pub(super) struct SharedStateTimeout {
  message: String,
}

impl SharedStateTimeout {
  pub(super) fn new(message: String) -> Self {
    Self { message }
  }
}

impl fmt::Display for SharedStateTimeout {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.message)
  }
}

impl std::error::Error for SharedStateTimeout {}

#[derive(Debug, Default)]
pub(super) struct SharedPoolWarningLimiter {
  next_warning_ms: AtomicU64,
}

impl SharedPoolWarningLimiter {
  pub(super) fn should_emit(&self) -> bool {
    self.should_emit_at(monotonic_millis())
  }

  fn should_emit_at(&self, now_ms: u64) -> bool {
    let mut next_warning_ms = self.next_warning_ms.load(Ordering::Relaxed);
    loop {
      if now_ms < next_warning_ms || next_warning_ms == u64::MAX {
        return false;
      }
      match self.next_warning_ms.compare_exchange_weak(
        next_warning_ms,
        now_ms.saturating_add(SHARED_POOL_WARNING_INTERVAL_MS),
        Ordering::Relaxed,
        Ordering::Relaxed,
      ) {
        Ok(_) => return true,
        Err(current) => next_warning_ms = current,
      }
    }
  }
}

fn monotonic_millis() -> u64 {
  static START: OnceLock<Instant> = OnceLock::new();
  START
    .get_or_init(Instant::now)
    .elapsed()
    .as_millis()
    .min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Debug)]
pub(super) struct BackendRuntime {
  pub(super) name: Arc<str>,
  pub(super) kind: &'static str,
  pub(super) operation_timeout: Duration,
  pub(super) connect_timeout: Duration,
  semaphore: Option<Arc<Semaphore>>,
  pub(super) metrics: Arc<Metrics>,
}

impl BackendRuntime {
  pub(super) fn new(
    config: &SharedStateBackendConfig,
    kind: &'static str,
    operation_timeout: Duration,
    metrics: Arc<Metrics>,
  ) -> Self {
    Self {
      name: Arc::from(config.name.as_str()),
      kind,
      operation_timeout,
      connect_timeout: Duration::from_millis(config.connect_timeout_ms),
      // Redis uses its persistent pool as the sole physical-connection and
      // bounded-wait admission boundary. PostgreSQL retains this operation
      // semaphore because its sqlx pool is not configured here with an
      // equivalent queue cap.
      semaphore: (kind != "redis")
        .then(|| Arc::new(Semaphore::new(config.max_connections as usize))),
      metrics,
    }
  }

  pub(super) async fn execute<T, F, Fut>(
    &self,
    operation: &'static str,
    operation_future: F,
  ) -> anyhow::Result<T>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
  {
    let started = Instant::now();
    let mut queue_observation = QueueObservation::new(self, operation, started);
    let permit = if let Some(semaphore) = &self.semaphore {
      match tokio::time::timeout(self.operation_timeout, semaphore.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Some(permit),
        Ok(Err(_)) => {
          queue_observation.finish("closed");
          bail!("shared state backend {} queue is closed", self.name);
        }
        Err(_) => {
          queue_observation.finish("timeout");
          bail!("shared state backend {} queue timed out", self.name);
        }
      }
    } else {
      None
    };
    queue_observation.finish("acquired");
    let elapsed = started.elapsed();
    let Some(remaining) = self.operation_timeout.checked_sub(elapsed) else {
      bail!(
        "shared state backend {} operation timed out while queued",
        self.name
      );
    };
    let mut operation_observation = OperationObservation::new(self, operation, Instant::now());
    let result = tokio::time::timeout(remaining, operation_future()).await;
    drop(permit);
    match result {
      Ok(Ok(value)) => {
        operation_observation.finish("success");
        Ok(value)
      }
      Ok(Err(error)) => {
        let outcome = if error.downcast_ref::<SharedStateTimeout>().is_some() {
          "timeout"
        } else {
          "error"
        };
        operation_observation.finish(outcome);
        Err(error)
      }
      Err(_) => {
        operation_observation.finish("timeout");
        bail!("shared state backend {} operation timed out", self.name)
      }
    }
  }

  pub(super) async fn connect<T, F, Fut>(&self, future: F) -> anyhow::Result<T>
  where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
  {
    tokio::time::timeout(self.connect_timeout, future())
      .await
      .context("shared state backend connection timed out")?
  }
}

#[derive(Debug)]
struct QueueObservation {
  metrics: Arc<Metrics>,
  backend: Arc<str>,
  kind: &'static str,
  operation: &'static str,
  started: Instant,
  finished: bool,
}

impl QueueObservation {
  fn new(runtime: &BackendRuntime, operation: &'static str, started: Instant) -> Self {
    runtime
      .metrics
      .shared_state_queue_started(runtime.name.as_ref(), runtime.kind);
    Self {
      metrics: runtime.metrics.clone(),
      backend: runtime.name.clone(),
      kind: runtime.kind,
      operation,
      started,
      finished: false,
    }
  }

  fn finish(&mut self, outcome: &'static str) {
    if self.finished {
      return;
    }
    self.metrics.shared_state_queue_finished(
      self.backend.as_ref(),
      self.kind,
      self.operation,
      outcome,
      duration_ms(self.started),
    );
    self.finished = true;
  }
}

impl Drop for QueueObservation {
  fn drop(&mut self) {
    self.finish("cancelled");
  }
}

#[derive(Debug)]
struct OperationObservation {
  metrics: Arc<Metrics>,
  backend: Arc<str>,
  kind: &'static str,
  operation: &'static str,
  started: Instant,
  finished: bool,
}

impl OperationObservation {
  fn new(runtime: &BackendRuntime, operation: &'static str, started: Instant) -> Self {
    runtime
      .metrics
      .shared_state_operation_started(runtime.name.as_ref(), runtime.kind);
    Self {
      metrics: runtime.metrics.clone(),
      backend: runtime.name.clone(),
      kind: runtime.kind,
      operation,
      started,
      finished: false,
    }
  }

  fn finish(&mut self, outcome: &'static str) {
    if self.finished {
      return;
    }
    self.metrics.shared_state_operation_finished(
      self.backend.as_ref(),
      self.kind,
      self.operation,
      outcome,
      duration_ms(self.started),
    );
    self.finished = true;
  }
}

impl Drop for OperationObservation {
  fn drop(&mut self) {
    self.finish("cancelled");
  }
}

fn duration_ms(started: Instant) -> u64 {
  started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

#[derive(Debug)]
enum CleanupRequest {
  ConnectionRelease {
    backend: Arc<Backend>,
    keys: Vec<String>,
  },
  Unlock {
    backend: Arc<Backend>,
    key: String,
    token: String,
  },
  CounterAdd {
    backend: Arc<Backend>,
    key: String,
    delta: i64,
    ttl: Option<Duration>,
    pool_warning_limiter: Arc<SharedPoolWarningLimiter>,
  },
}

#[derive(Debug)]
pub(super) struct CleanupDispatcher {
  sender: Option<mpsc::Sender<CleanupRequest>>,
}

impl CleanupDispatcher {
  pub(super) fn new() -> Arc<Self> {
    let (sender, receiver) = mpsc::channel(1024);
    match tokio::runtime::Handle::try_current() {
      Ok(handle) => {
        handle.spawn(cleanup_worker(receiver));
        Arc::new(Self {
          sender: Some(sender),
        })
      }
      Err(_) => Arc::new(Self { sender: None }),
    }
  }

  pub(super) fn defer_connection_release(&self, backend: Arc<Backend>, keys: Vec<String>) {
    self.try_send(CleanupRequest::ConnectionRelease { backend, keys });
  }

  pub(super) fn defer_unlock(&self, backend: Arc<Backend>, key: String, token: String) {
    self.try_send(CleanupRequest::Unlock {
      backend,
      key,
      token,
    });
  }

  pub(super) fn defer_counter_add(
    &self,
    backend: Arc<Backend>,
    key: String,
    delta: i64,
    ttl: Option<Duration>,
    pool_warning_limiter: Arc<SharedPoolWarningLimiter>,
  ) {
    self.try_send(CleanupRequest::CounterAdd {
      backend,
      key,
      delta,
      ttl,
      pool_warning_limiter,
    });
  }

  fn try_send(&self, request: CleanupRequest) {
    let backend = match &request {
      CleanupRequest::ConnectionRelease { backend, .. }
      | CleanupRequest::Unlock { backend, .. }
      | CleanupRequest::CounterAdd { backend, .. } => backend.clone(),
    };
    let Some(sender) = &self.sender else {
      backend.record_cleanup_drop();
      return;
    };
    if sender.try_send(request).is_err() {
      backend.record_cleanup_drop();
    }
  }
}

async fn cleanup_worker(mut receiver: mpsc::Receiver<CleanupRequest>) {
  while let Some(request) = receiver.recv().await {
    let (result, pool_warning_limiter) = match request {
      CleanupRequest::ConnectionRelease { backend, keys } => {
        (backend.connection_release(&keys).await, None)
      }
      CleanupRequest::Unlock {
        backend,
        key,
        token,
      } => (backend.unlock(&key, &token).await, None),
      CleanupRequest::CounterAdd {
        backend,
        key,
        delta,
        ttl,
        pool_warning_limiter,
      } => (
        backend.counter_add(&key, delta, ttl).await.map(|_| ()),
        Some(pool_warning_limiter),
      ),
    };
    if let Err(error) = result
      && pool_warning_limiter
        .as_ref()
        .is_none_or(|limiter| limiter.should_emit())
    {
      warn!(error = %error, "failed to run deferred shared-state cleanup");
    }
  }
}

#[cfg(test)]
mod tests {
  use std::sync::{Arc, Barrier};
  use std::time::Duration;

  use tokio::sync::oneshot;

  use super::{
    BackendRuntime, SHARED_POOL_WARNING_INTERVAL_MS, SharedPoolWarningLimiter, SharedStateTimeout,
  };
  use crate::cache::CacheStats;
  use crate::config::MetricsConfig;
  use crate::metrics::Metrics;
  use crate::tls::TlsServerSessionStorageStats;

  fn test_runtime(metrics: Arc<Metrics>, permits: usize, timeout: Duration) -> Arc<BackendRuntime> {
    Arc::new(BackendRuntime {
      name: Arc::from("shared-state-test"),
      kind: "redis",
      operation_timeout: timeout,
      connect_timeout: timeout,
      semaphore: Some(Arc::new(tokio::sync::Semaphore::new(permits))),
      metrics,
    })
  }

  #[test]
  fn shared_pool_warning_limiter_reopens_only_after_interval() {
    let limiter = SharedPoolWarningLimiter::default();

    assert!(limiter.should_emit_at(0));
    assert!(!limiter.should_emit_at(0));
    assert!(!limiter.should_emit_at(SHARED_POOL_WARNING_INTERVAL_MS - 1));
    assert!(limiter.should_emit_at(SHARED_POOL_WARNING_INTERVAL_MS));
    assert!(!limiter.should_emit_at(SHARED_POOL_WARNING_INTERVAL_MS - 1));
    assert!(!limiter.should_emit_at(2 * SHARED_POOL_WARNING_INTERVAL_MS - 1));
    assert!(limiter.should_emit_at(2 * SHARED_POOL_WARNING_INTERVAL_MS));
  }

  #[test]
  fn shared_pool_warning_limiter_admits_one_concurrent_failure() {
    const WORKERS: usize = 16;
    let limiter = Arc::new(SharedPoolWarningLimiter::default());
    let barrier = Arc::new(Barrier::new(WORKERS + 1));
    let workers = (0..WORKERS)
      .map(|_| {
        let limiter = limiter.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
          barrier.wait();
          limiter.should_emit_at(0)
        })
      })
      .collect::<Vec<_>>();

    barrier.wait();
    let admitted = workers
      .into_iter()
      .map(|worker| {
        worker
          .join()
          .expect("warning limiter worker should not panic")
      })
      .filter(|admitted| *admitted)
      .count();
    assert_eq!(admitted, 1);
  }

  #[tokio::test]
  async fn cancelled_operations_release_permits_and_export_bounded_metrics() {
    let metrics = Metrics::new();
    let runtime = test_runtime(metrics.clone(), 1, Duration::from_millis(100));
    let (started_tx, started_rx) = oneshot::channel();
    let (_release_tx, release_rx) = oneshot::channel::<()>();

    let first_runtime = runtime.clone();
    let first = tokio::spawn(async move {
      let _ = first_runtime
        .execute("rate_limit", || async move {
          let _ = started_tx.send(());
          let _ = release_rx.await;
          Ok::<_, anyhow::Error>(())
        })
        .await;
    });
    started_rx
      .await
      .expect("first operation should hold the only permit");

    let queued_runtime = runtime.clone();
    let queued = tokio::spawn(async move {
      let _ = queued_runtime
        .execute("rate_limit", || async { Ok::<_, anyhow::Error>(()) })
        .await;
    });
    tokio::task::yield_now().await;
    queued.abort();
    first.abort();
    let _ = queued.await;
    let _ = first.await;

    tokio::time::timeout(
      Duration::from_millis(50),
      runtime.execute("rate_limit", || async { Ok::<_, anyhow::Error>(()) }),
    )
    .await
    .expect("cancelled work must release the semaphore permit")
    .expect("recovered operation should succeed");

    let prometheus = metrics.prometheus(
      &MetricsConfig::default(),
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );
    assert!(prometheus.contains("oxibelt_shared_state_queue_duration_ms"));
    assert!(prometheus.contains("oxibelt_shared_state_operation_duration_ms"));
    assert!(prometheus.contains("outcome=\"cancelled\""));
    assert!(prometheus.contains(
      "oxibelt_shared_state_queued_operations{backend=\"shared-state-test\",kind=\"redis\"} 0"
    ));
    assert!(prometheus.contains(
      "oxibelt_shared_state_in_flight_operations{backend=\"shared-state-test\",kind=\"redis\"} 0"
    ));
  }

  #[tokio::test]
  async fn delayed_backend_load_keeps_the_runtime_responsive() {
    let runtime = test_runtime(Metrics::new(), 1, Duration::from_millis(20));
    let heartbeat = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ticking = heartbeat.clone();
    let ticker = tokio::spawn(async move {
      for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        ticking.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
      }
    });

    let mut operations = tokio::task::JoinSet::new();
    for _ in 0..16 {
      let runtime = runtime.clone();
      operations.spawn(async move {
        runtime
          .execute("rate_limit", || async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok::<_, anyhow::Error>(())
          })
          .await
      });
    }
    let mut timed_out = 0;
    while let Some(result) = operations.join_next().await {
      assert!(result.expect("load task should not panic").is_err());
      timed_out += 1;
    }
    assert_eq!(timed_out, 16, "all delayed operations should be bounded");
    ticker.await.expect("heartbeat task should complete");
    assert!(
      heartbeat.load(std::sync::atomic::Ordering::Relaxed) > 0,
      "an unrelated Tokio task should progress while backend I/O is delayed"
    );
  }

  #[tokio::test]
  async fn pool_timeout_errors_preserve_the_operation_timeout_metric() {
    let metrics = Metrics::new();
    let runtime = test_runtime(metrics.clone(), 1, Duration::from_millis(100));
    let error = runtime
      .execute("rate_limit", || async {
        Err::<(), _>(
          SharedStateTimeout::new("shared state Redis backend test command timed out".to_string())
            .into(),
        )
      })
      .await
      .expect_err("typed pool timeout should propagate");
    assert!(error.to_string().contains("command timed out"));

    let prometheus = metrics.prometheus(
      &MetricsConfig::default(),
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );
    assert!(prometheus.contains(
      "oxibelt_shared_state_operations_total{backend=\"shared-state-test\",kind=\"redis\",operation=\"rate_limit\",outcome=\"timeout\"} 1"
    ));
  }
}
