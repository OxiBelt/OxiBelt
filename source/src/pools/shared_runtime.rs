//! Async shared-state synchronization for pool construction and selection.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::bail;
use http::HeaderValue;

use crate::config::{BackendFailureMode, UpstreamPoolConfig};
use crate::metrics::Metrics;
use crate::shared_state::{SharedState, SharedStateFeature};

use super::{PoolRuntime, PoolSelection, PoolState, now_millis, set_server_health};

impl PoolState {
  pub async fn new_with_previous_and_metrics_async(
    configs: &[UpstreamPoolConfig],
    shared_state: Option<Arc<SharedState>>,
    previous: Option<&PoolState>,
    metrics: Option<Arc<Metrics>>,
  ) -> Arc<Self> {
    let state = Self::new_with_previous_and_metrics(configs, shared_state, previous, metrics);
    state.initialize_shared_sticky_secrets().await;
    state
  }

  async fn initialize_shared_sticky_secrets(&self) {
    let Some(shared) = self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_sticky_sessions())
    else {
      return;
    };
    for pool in self.pools.values() {
      match shared.sticky_session_secret(&pool.config.name).await {
        Ok(Some(secret)) => {
          *pool
            .sticky_secret
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = secret;
        }
        Ok(None) => {}
        Err(error) => {
          if shared.backend_failure_mode(SharedStateFeature::StickySessions)
            == BackendFailureMode::LocalFallback
          {
            shared.record_backend_local_fallback(SharedStateFeature::StickySessions);
          }
          tracing::warn!(pool = %pool.config.name, error = %error, "failed to load shared sticky session secret");
        }
      }
    }
  }

  pub async fn select_with_cookie_header_async(
    &self,
    pool_name: &str,
    client_ip: std::net::IpAddr,
    hash_key: &str,
    policy_override: Option<&str>,
    cookie_header: Option<&HeaderValue>,
  ) -> anyhow::Result<PoolSelection> {
    self
      .select_with_cookie_header_excluding_async(
        pool_name,
        client_ip,
        hash_key,
        policy_override,
        cookie_header,
        &[],
      )
      .await
  }

  pub async fn select_with_cookie_header_excluding_async(
    &self,
    pool_name: &str,
    client_ip: std::net::IpAddr,
    hash_key: &str,
    policy_override: Option<&str>,
    cookie_header: Option<&HeaderValue>,
    excluded_upstreams: &[String],
  ) -> anyhow::Result<PoolSelection> {
    let Some(pool) = self.pools.get(pool_name).cloned() else {
      bail!("unknown upstream pool {pool_name}");
    };
    self.refresh_shared_pool_view(&pool).await;
    let mut selection = self.select_with_cookie_header_excluding(
      pool_name,
      client_ip,
      hash_key,
      policy_override,
      cookie_header,
      excluded_upstreams,
    )?;
    if let Some(shared) = &self.shared_state {
      match shared.pool_active_acquire(&selection.upstream_name).await {
        Ok(Some(lease)) => selection.shared_lease = Some(lease),
        Ok(None) => {}
        Err(error) if shared.should_log_pool_warning() => {
          record_upstream_health_stale_snapshot(shared);
          tracing::warn!(error = %error, upstream = %selection.upstream_name, "failed to update shared upstream active count");
        }
        Err(_) => record_upstream_health_stale_snapshot(shared),
      }
    }
    Ok(selection)
  }

  pub(crate) async fn snapshots_async(&self) -> Vec<super::PoolRuntimeSnapshot> {
    for pool in self.pools.values() {
      self.refresh_shared_pool_view(pool).await;
    }
    self.snapshots()
  }

  pub(crate) async fn snapshot_async(&self, pool_name: &str) -> Option<super::PoolRuntimeSnapshot> {
    let pool = self.pools.get(pool_name)?;
    self.refresh_shared_pool_view(pool).await;
    Some(super::pool_snapshot(pool))
  }

  pub(super) async fn report_shared_health_async(&self, upstream_name: &str, success: bool) {
    let Some(shared) = &self.shared_state else {
      return;
    };
    let Some((pool, server)) = self.find_pool_server(upstream_name) else {
      return;
    };
    match shared
      .pool_report(
        upstream_name,
        success,
        pool.config.health_check.enabled,
        pool.config.health_check.healthy_threshold,
        pool.config.health_check.unhealthy_threshold,
      )
      .await
    {
      Ok(Some(healthy)) => {
        set_server_health(&server, healthy, now_millis());
        self.publish_server_count_metrics();
      }
      Ok(None) => {}
      Err(error) => {
        record_upstream_health_stale_snapshot(shared);
        if shared.should_log_pool_warning() {
          tracing::warn!(error = %error, upstream = %upstream_name, "failed to report shared upstream health");
        }
      }
    }
  }

  async fn refresh_shared_pool_view(&self, pool: &Arc<PoolRuntime>) {
    let Some(shared) = self.shared_state.clone() else {
      return;
    };
    let mut tasks = tokio::task::JoinSet::new();
    for server in &pool.servers {
      let server = server.clone();
      let shared = shared.clone();
      tasks.spawn(async move {
        let (health, active) = tokio::join!(
          shared.pool_health(&server.upstream_name),
          shared.pool_active(&server.upstream_name),
        );
        (server, health, active)
      });
    }
    while let Some(result) = tasks.join_next().await {
      let (server, health, active) = match result {
        Ok(result) => result,
        Err(error) => {
          record_upstream_health_stale_snapshot(&shared);
          if shared.should_log_pool_warning() {
            tracing::warn!(error = %error, "shared upstream pool refresh task failed");
          }
          continue;
        }
      };
      match health {
        Ok(Some(healthy)) => set_server_health(&server, healthy, now_millis()),
        Ok(None) => {}
        Err(error) => {
          record_upstream_health_stale_snapshot(&shared);
          if shared.should_log_pool_warning() {
            tracing::warn!(error = %error, upstream = %server.upstream_name, "failed to refresh shared upstream health");
          }
        }
      }
      match active {
        Ok(Some(active)) => server.shared_active.store(active, Ordering::Relaxed),
        Ok(None) => {}
        Err(error) => {
          if shared.should_log_pool_warning() {
            tracing::warn!(error = %error, upstream = %server.upstream_name, "failed to refresh shared upstream active count");
          }
        }
      }
    }
  }
}

fn record_upstream_health_stale_snapshot(shared: &SharedState) {
  if shared.backend_failure_mode(SharedStateFeature::UpstreamHealth)
    == BackendFailureMode::StaleSnapshot
  {
    shared.record_backend_stale_snapshot(SharedStateFeature::UpstreamHealth);
  }
}

#[cfg(test)]
mod tests {
  use std::io::{self, Write};
  use std::sync::{Arc, Mutex};
  use std::time::Duration;

  use tracing_subscriber::fmt::MakeWriter;

  use super::super::PoolState;
  use super::super::tests::test_pool;
  use crate::cache::CacheStats;
  use crate::config::{LoadBalancingAlgorithm, MetricsConfig};
  use crate::metrics::Metrics;
  use crate::shared_state::SharedState;
  use crate::tls::TlsServerSessionStorageStats;

  const REQUESTS: usize = 8;

  #[derive(Clone, Default)]
  struct LogBuffer(Arc<Mutex<Vec<u8>>>);

  struct LogWriter(Arc<Mutex<Vec<u8>>>);

  impl Write for LogWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
      self
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .extend_from_slice(buffer);
      Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
      Ok(())
    }
  }

  impl<'writer> MakeWriter<'writer> for LogBuffer {
    type Writer = LogWriter;

    fn make_writer(&'writer self) -> Self::Writer {
      LogWriter(self.0.clone())
    }
  }

  impl LogBuffer {
    fn contents(&self) -> String {
      String::from_utf8(
        self
          .0
          .lock()
          .unwrap_or_else(|poisoned| poisoned.into_inner())
          .clone(),
      )
      .expect("captured tracing output should be UTF-8")
    }
  }

  fn shared_state_operation_count(metrics: &Metrics, operation: &str, outcome: &str) -> u64 {
    metrics
      .prometheus(
        &MetricsConfig::default(),
        CacheStats::default(),
        TlsServerSessionStorageStats::default(),
      )
      .lines()
      .find(|line| {
        line.starts_with("oxibelt_shared_state_operations_total{")
          && line.contains(&format!("operation=\"{operation}\""))
          && line.contains(&format!("outcome=\"{outcome}\""))
      })
      .and_then(|line| line.split_whitespace().last())
      .and_then(|value| value.parse().ok())
      .unwrap_or_default()
  }

  #[test]
  fn degraded_shared_pool_warning_burst_is_rate_limited() {
    let runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .expect("current-thread test runtime should build");
    let metrics = Metrics::new();
    let state = runtime.block_on(async {
      let shared =
        SharedState::test_redis("pool-warning-test", "redis://127.0.0.1:0/", metrics.clone());
      PoolState::new_with_previous_and_metrics_async(
        &[test_pool(LoadBalancingAlgorithm::WeightedLeastConn)],
        Some(shared),
        None,
        Some(metrics.clone()),
      )
      .await
    });
    let logs = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
      .with_max_level(tracing::Level::WARN)
      .with_ansi(false)
      .without_time()
      .with_target(false)
      .with_writer(logs.clone())
      .finish();

    tracing::subscriber::with_default(subscriber, || {
      runtime.block_on(async {
        let mut requests = tokio::task::JoinSet::new();
        for request in 0..REQUESTS {
          let state = state.clone();
          requests.spawn(async move {
            let hash_key = format!("/warning-burst-{request}");
            state
              .select_with_cookie_header_async(
                "app-pool",
                "203.0.113.10".parse().expect("test client IP should parse"),
                &hash_key,
                None,
                None,
              )
              .await
          });
        }

        let mut selections = Vec::with_capacity(REQUESTS);
        while let Some(result) = requests.join_next().await {
          let selection = result
            .expect("pool selection task should not panic")
            .expect("degraded shared state must preserve local pool selection");
          state.report_failure_async(&selection.upstream_name).await;
          selections.push(selection);
        }
        drop(selections);

        tokio::time::timeout(Duration::from_secs(2), async {
          while shared_state_operation_count(&metrics, "counter_update", "error")
            < (REQUESTS * 2) as u64
          {
            tokio::task::yield_now().await;
          }
        })
        .await
        .expect("deferred pool active-count cleanup should finish");
      });
    });

    assert_eq!(
      shared_state_operation_count(&metrics, "health_read", "error"),
      (REQUESTS * 2) as u64
    );
    assert_eq!(
      shared_state_operation_count(&metrics, "counter_read", "error"),
      (REQUESTS * 2) as u64
    );
    assert_eq!(
      shared_state_operation_count(&metrics, "health_update", "error"),
      REQUESTS as u64
    );
    assert_eq!(
      shared_state_operation_count(&metrics, "counter_update", "error"),
      (REQUESTS * 2) as u64
    );

    let logs = logs.contents();
    let warnings = logs
      .lines()
      .filter(|line| !line.trim().is_empty())
      .collect::<Vec<_>>();
    assert_eq!(warnings.len(), 1, "degraded pool warning output:\n{logs}");
    assert!(
      warnings[0].contains("failed to refresh shared upstream"),
      "unexpected degraded pool warning: {}",
      warnings[0]
    );
  }
}
