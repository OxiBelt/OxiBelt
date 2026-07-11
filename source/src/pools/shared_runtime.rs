//! Async shared-state synchronization for pool construction and selection.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::bail;
use http::HeaderValue;

use crate::config::UpstreamPoolConfig;
use crate::metrics::Metrics;
use crate::shared_state::SharedState;

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
    let selection = self.select_with_cookie_header_excluding(
      pool_name,
      client_ip,
      hash_key,
      policy_override,
      cookie_header,
      excluded_upstreams,
    )?;
    if let Some(shared) = &self.shared_state
      && let Err(error) = shared.pool_active_add(&selection.upstream_name, 1).await
    {
      tracing::warn!(error = %error, upstream = %selection.upstream_name, "failed to update shared upstream active count");
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
          tracing::warn!(error = %error, "shared upstream pool refresh task failed");
          continue;
        }
      };
      match health {
        Ok(Some(healthy)) => set_server_health(&server, healthy, now_millis()),
        Ok(None) => {}
        Err(error) => {
          tracing::warn!(error = %error, upstream = %server.upstream_name, "failed to refresh shared upstream health");
        }
      }
      match active {
        Ok(Some(active)) => server.shared_active.store(active, Ordering::Relaxed),
        Ok(None) => {}
        Err(error) => {
          tracing::warn!(error = %error, upstream = %server.upstream_name, "failed to refresh shared upstream active count");
        }
      }
    }
  }
}
