use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use anyhow::bail;
use url::Url;

use crate::config::{
  LoadBalancingAlgorithm, TurnUpstreamPoolConfig, TurnUpstreamPoolServerConfig,
  UpstreamPoolServerState, turn_upstream_pool_server_id,
};

pub struct TurnPoolState {
  pools: HashMap<String, Arc<TurnPoolRuntime>>,
}

#[derive(Debug)]
struct TurnPoolRuntime {
  config: TurnUpstreamPoolConfig,
  servers: Vec<Arc<TurnServerRuntime>>,
  round_robin: AtomicUsize,
  random: AtomicUsize,
}

#[derive(Debug)]
struct TurnServerRuntime {
  server_id: String,
  origin: Url,
  active: AtomicUsize,
  healthy: AtomicBool,
  consecutive_successes: AtomicU32,
  consecutive_failures: AtomicU32,
}

pub struct TurnPoolSelection {
  pub pool_name: String,
  pub server_id: String,
  pub origin: Url,
  server: Arc<TurnServerRuntime>,
}

impl Drop for TurnPoolSelection {
  fn drop(&mut self) {
    self.server.active.fetch_sub(1, Ordering::Relaxed);
  }
}

impl TurnPoolState {
  pub fn new(configs: &[TurnUpstreamPoolConfig]) -> Arc<Self> {
    let pools = configs
      .iter()
      .map(|config| {
        let servers = config
          .servers
          .iter()
          .enumerate()
          .map(|(index, server)| {
            Arc::new(TurnServerRuntime {
              server_id: turn_upstream_pool_server_id(index, server),
              origin: server.origin.clone(),
              active: AtomicUsize::new(0),
              healthy: AtomicBool::new(server.state == UpstreamPoolServerState::Ready),
              consecutive_successes: AtomicU32::new(0),
              consecutive_failures: AtomicU32::new(0),
            })
          })
          .collect();
        (
          config.name.clone(),
          Arc::new(TurnPoolRuntime {
            config: config.clone(),
            servers,
            round_robin: AtomicUsize::new(0),
            random: AtomicUsize::new(0x9e37_79b9),
          }),
        )
      })
      .collect();
    Arc::new(Self { pools })
  }

  pub fn select(
    &self,
    pool_name: &str,
    client_ip: IpAddr,
    hash_key: &str,
  ) -> anyhow::Result<TurnPoolSelection> {
    let Some(pool) = self.pools.get(pool_name).cloned() else {
      bail!("unknown TURN upstream pool {pool_name}");
    };
    let server = match pool.config.algorithm {
      LoadBalancingAlgorithm::RoundRobin => select_round_robin(&pool),
      LoadBalancingAlgorithm::LeastConn => select_least_conn(&pool),
      LoadBalancingAlgorithm::Random => select_random(&pool),
      LoadBalancingAlgorithm::Hash => select_hash(&pool, hash_key),
      LoadBalancingAlgorithm::IpHash => select_hash(&pool, &client_ip.to_string()),
      LoadBalancingAlgorithm::StickyCookie => None,
    }
    .ok_or_else(|| anyhow::anyhow!("TURN upstream pool {pool_name} has no available servers"))?;

    server.active.fetch_add(1, Ordering::Relaxed);
    Ok(TurnPoolSelection {
      pool_name: pool_name.to_string(),
      server_id: server.server_id.clone(),
      origin: server.origin.clone(),
      server,
    })
  }

  pub fn report_success(&self, pool_name: &str, server_id: &str) {
    if let Some((pool, server)) = self.find(pool_name, server_id) {
      server.consecutive_failures.store(0, Ordering::Relaxed);
      let successes = server.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
      if successes >= pool.config.health_check.healthy_threshold {
        server.healthy.store(true, Ordering::Relaxed);
      }
    }
  }

  pub fn report_failure(&self, pool_name: &str, server_id: &str) {
    if let Some((pool, server)) = self.find(pool_name, server_id) {
      server.consecutive_successes.store(0, Ordering::Relaxed);
      let failures = server.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
      if failures >= pool.config.health_check.unhealthy_threshold {
        server.healthy.store(false, Ordering::Relaxed);
      }
    }
  }

  pub fn health_targets(&self) -> Vec<(String, String, Url, u64, u64)> {
    self
      .pools
      .values()
      .filter(|pool| pool.config.health_check.enabled)
      .flat_map(|pool| {
        pool.servers.iter().map(|server| {
          (
            pool.config.name.clone(),
            server.server_id.clone(),
            server.origin.clone(),
            pool.config.health_check.interval_ms,
            pool.config.health_check.timeout_ms,
          )
        })
      })
      .collect()
  }

  fn find(
    &self,
    pool_name: &str,
    server_id: &str,
  ) -> Option<(Arc<TurnPoolRuntime>, Arc<TurnServerRuntime>)> {
    let pool = self.pools.get(pool_name)?.clone();
    let server = pool
      .servers
      .iter()
      .find(|server| server.server_id == server_id)?
      .clone();
    Some((pool, server))
  }
}

fn select_round_robin(pool: &Arc<TurnPoolRuntime>) -> Option<Arc<TurnServerRuntime>> {
  let candidates = candidates(pool);
  if candidates.is_empty() {
    return None;
  }
  let next = pool.round_robin.fetch_add(1, Ordering::Relaxed);
  Some(candidates[next % candidates.len()].clone())
}

fn select_least_conn(pool: &Arc<TurnPoolRuntime>) -> Option<Arc<TurnServerRuntime>> {
  candidates(pool)
    .into_iter()
    .min_by_key(|server| server.active.load(Ordering::Relaxed))
}

fn select_random(pool: &Arc<TurnPoolRuntime>) -> Option<Arc<TurnServerRuntime>> {
  let candidates = candidates(pool);
  if candidates.is_empty() {
    return None;
  }
  let old = pool.random.load(Ordering::Relaxed);
  let next = old.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
  pool.random.store(next, Ordering::Relaxed);
  Some(candidates[next % candidates.len()].clone())
}

fn select_hash(pool: &Arc<TurnPoolRuntime>, key: &str) -> Option<Arc<TurnServerRuntime>> {
  let candidates = candidates(pool);
  if candidates.is_empty() {
    return None;
  }
  let mut hash = 0xcbf2_9ce4_8422_2325u64;
  for byte in key.as_bytes() {
    hash ^= *byte as u64;
    hash = hash.wrapping_mul(0x100_0000_01b3);
  }
  Some(candidates[(hash as usize) % candidates.len()].clone())
}

fn candidates(pool: &Arc<TurnPoolRuntime>) -> Vec<Arc<TurnServerRuntime>> {
  pool
    .servers
    .iter()
    .zip(&pool.config.servers)
    .filter(|(runtime, config)| server_available(runtime, config))
    .map(|(runtime, _)| runtime.clone())
    .collect()
}

fn server_available(runtime: &TurnServerRuntime, config: &TurnUpstreamPoolServerConfig) -> bool {
  matches!(config.state, UpstreamPoolServerState::Ready)
    && runtime.healthy.load(Ordering::Relaxed)
    && (config.max_conns == 0 || runtime.active.load(Ordering::Relaxed) < config.max_conns)
}
