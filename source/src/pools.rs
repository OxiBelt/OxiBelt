use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use anyhow::bail;

use crate::config::{
  HealthCheckProtocol, HttpVersion, LoadBalancingAlgorithm, ProxyProtocolEgressMode,
  UpstreamConfig, UpstreamPoolConfig, UpstreamTlsConfig,
};

#[derive(Debug)]
pub struct PoolState {
  pools: HashMap<String, Arc<PoolRuntime>>,
}

#[derive(Debug)]
struct PoolRuntime {
  config: UpstreamPoolConfig,
  servers: Vec<Arc<PoolServerRuntime>>,
  round_robin: AtomicUsize,
  random: AtomicUsize,
}

#[derive(Debug)]
struct PoolServerRuntime {
  upstream_name: String,
  active: AtomicUsize,
  healthy: AtomicBool,
  consecutive_successes: AtomicU32,
  consecutive_failures: AtomicU32,
}

pub struct PoolSelection {
  pub pool_name: String,
  pub upstream_name: String,
  server: Arc<PoolServerRuntime>,
}

impl Drop for PoolSelection {
  fn drop(&mut self) {
    self.server.active.fetch_sub(1, Ordering::Relaxed);
  }
}

impl PoolState {
  pub fn new(configs: &[UpstreamPoolConfig]) -> Arc<Self> {
    let pools = configs
      .iter()
      .map(|config| {
        let servers = config
          .servers
          .iter()
          .enumerate()
          .map(|(index, _)| {
            Arc::new(PoolServerRuntime {
              upstream_name: synthetic_upstream_name(&config.name, index),
              active: AtomicUsize::new(0),
              healthy: AtomicBool::new(true),
              consecutive_successes: AtomicU32::new(0),
              consecutive_failures: AtomicU32::new(0),
            })
          })
          .collect();
        (
          config.name.clone(),
          Arc::new(PoolRuntime {
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

  pub fn synthetic_upstreams(configs: &[UpstreamPoolConfig]) -> Vec<UpstreamConfig> {
    configs
      .iter()
      .flat_map(|pool| {
        pool
          .servers
          .iter()
          .enumerate()
          .map(|(index, server)| UpstreamConfig {
            name: synthetic_upstream_name(&pool.name, index),
            origin: server.origin.clone(),
            max_http_version: if server.origin.scheme() == "http"
              && pool.health_check.protocol != HealthCheckProtocol::Grpc
            {
              HttpVersion::H1
            } else {
              HttpVersion::H2
            },
            connect_timeout_ms: 3_000,
            request_timeout_ms: 30_000,
            first_byte_timeout_ms: 30_000,
            read_timeout_ms: 30_000,
            send_timeout_ms: 30_000,
            idle_timeout_ms: pool.keepalive.idle_timeout_ms,
            preserve_host: false,
            websocket: true,
            webrtc: true,
            webtransport: true,
            proxy_protocol_egress: ProxyProtocolEgressMode::Off,
            tls: UpstreamTlsConfig::default(),
          })
      })
      .collect()
  }

  pub fn select(
    &self,
    pool_name: &str,
    client_ip: IpAddr,
    hash_key: &str,
    policy_override: Option<&str>,
  ) -> anyhow::Result<PoolSelection> {
    let Some(pool) = self.pools.get(pool_name).cloned() else {
      bail!("unknown upstream pool {pool_name}");
    };
    let algorithm = policy_override
      .and_then(parse_policy_override)
      .unwrap_or(pool.config.algorithm);

    let server = match algorithm {
      LoadBalancingAlgorithm::RoundRobin => select_round_robin(&pool),
      LoadBalancingAlgorithm::LeastConn => select_least_conn(&pool),
      LoadBalancingAlgorithm::Random => select_random(&pool),
      LoadBalancingAlgorithm::Hash => select_hash(&pool, hash_key),
      LoadBalancingAlgorithm::IpHash => select_hash(&pool, &client_ip.to_string()),
      LoadBalancingAlgorithm::StickyCookie => None,
    }
    .ok_or_else(|| anyhow::anyhow!("upstream pool {pool_name} has no available servers"))?;

    server.active.fetch_add(1, Ordering::Relaxed);
    Ok(PoolSelection {
      pool_name: pool_name.to_string(),
      upstream_name: server.upstream_name.clone(),
      server,
    })
  }

  pub fn report_success(&self, upstream_name: &str) {
    if let Some((pool, server)) = self.find_pool_server(upstream_name) {
      server.consecutive_failures.store(0, Ordering::Relaxed);
      let successes = server.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
      if !pool.config.health_check.enabled
        || successes >= pool.config.health_check.healthy_threshold
      {
        server.healthy.store(true, Ordering::Relaxed);
      }
    }
  }

  pub fn report_failure(&self, upstream_name: &str) {
    if let Some((pool, server)) = self.find_pool_server(upstream_name) {
      server.consecutive_successes.store(0, Ordering::Relaxed);
      let failures = server.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
      if pool.config.health_check.enabled
        && failures >= pool.config.health_check.unhealthy_threshold
      {
        server.healthy.store(false, Ordering::Relaxed);
      }
    }
  }

  fn find_pool_server(
    &self,
    upstream_name: &str,
  ) -> Option<(Arc<PoolRuntime>, Arc<PoolServerRuntime>)> {
    for pool in self.pools.values() {
      for server in &pool.servers {
        if server.upstream_name == upstream_name {
          return Some((pool.clone(), server.clone()));
        }
      }
    }
    None
  }
}

fn parse_policy_override(raw: &str) -> Option<LoadBalancingAlgorithm> {
  match raw {
    "round_robin" => Some(LoadBalancingAlgorithm::RoundRobin),
    "least_conn" | "least_connections" => Some(LoadBalancingAlgorithm::LeastConn),
    "random" => Some(LoadBalancingAlgorithm::Random),
    "hash" => Some(LoadBalancingAlgorithm::Hash),
    "ip_hash" => Some(LoadBalancingAlgorithm::IpHash),
    _ => None,
  }
}

fn select_round_robin(pool: &Arc<PoolRuntime>) -> Option<Arc<PoolServerRuntime>> {
  let weighted = weighted_available(pool);
  if weighted.is_empty() {
    return None;
  }
  let next = pool.round_robin.fetch_add(1, Ordering::Relaxed);
  weighted.get(next % weighted.len()).cloned()
}

fn select_least_conn(pool: &Arc<PoolRuntime>) -> Option<Arc<PoolServerRuntime>> {
  available_servers(pool)
    .into_iter()
    .min_by_key(|server| server.active.load(Ordering::Relaxed))
}

fn select_random(pool: &Arc<PoolRuntime>) -> Option<Arc<PoolServerRuntime>> {
  let available = weighted_available(pool);
  if available.is_empty() {
    return None;
  }
  let old = pool.random.load(Ordering::Relaxed);
  let next = old.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
  pool.random.store(next, Ordering::Relaxed);
  available.get(next % available.len()).cloned()
}

fn select_hash(pool: &Arc<PoolRuntime>, key: &str) -> Option<Arc<PoolServerRuntime>> {
  let available = weighted_available(pool);
  if available.is_empty() {
    return None;
  }
  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  key.hash(&mut hasher);
  available
    .get(hasher.finish() as usize % available.len())
    .cloned()
}

fn weighted_available(pool: &Arc<PoolRuntime>) -> Vec<Arc<PoolServerRuntime>> {
  let mut result = Vec::new();
  for (index, server) in pool.servers.iter().enumerate() {
    if !server_available(pool, index, server) {
      continue;
    }
    let weight = pool.config.servers[index].weight;
    for _ in 0..weight {
      result.push(server.clone());
    }
  }
  if result.is_empty() {
    for (index, server) in pool.servers.iter().enumerate() {
      if pool.config.servers[index].backup && server_capacity_available(&pool.config, index, server)
      {
        result.push(server.clone());
      }
    }
  }
  result
}

fn available_servers(pool: &Arc<PoolRuntime>) -> Vec<Arc<PoolServerRuntime>> {
  let primary = pool
    .servers
    .iter()
    .enumerate()
    .filter(|(index, server)| server_available(pool, *index, server))
    .map(|(_, server)| server.clone())
    .collect::<Vec<_>>();
  if !primary.is_empty() {
    return primary;
  }
  pool
    .servers
    .iter()
    .enumerate()
    .filter(|(index, server)| {
      pool.config.servers[*index].backup && server_capacity_available(&pool.config, *index, server)
    })
    .map(|(_, server)| server.clone())
    .collect()
}

fn server_available(
  pool: &Arc<PoolRuntime>,
  index: usize,
  server: &Arc<PoolServerRuntime>,
) -> bool {
  !pool.config.servers[index].backup
    && server.healthy.load(Ordering::Relaxed)
    && server_capacity_available(&pool.config, index, server)
}

fn server_capacity_available(
  config: &UpstreamPoolConfig,
  index: usize,
  server: &Arc<PoolServerRuntime>,
) -> bool {
  let max_conns = config.servers[index].max_conns;
  max_conns == 0 || server.active.load(Ordering::Relaxed) < max_conns
}

pub(crate) fn synthetic_upstream_name(pool: &str, index: usize) -> String {
  format!("pool:{pool}:{index}")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{
    UpstreamPoolHealthCheckConfig, UpstreamPoolKeepaliveConfig, UpstreamPoolServerConfig,
  };

  fn test_pool(algorithm: LoadBalancingAlgorithm) -> UpstreamPoolConfig {
    UpstreamPoolConfig {
      name: "app-pool".to_string(),
      algorithm,
      hash_key: None,
      keepalive: UpstreamPoolKeepaliveConfig::default(),
      servers: vec![
        UpstreamPoolServerConfig {
          origin: "http://app-a.example".parse().unwrap(),
          weight: 1,
          max_conns: 0,
          backup: false,
        },
        UpstreamPoolServerConfig {
          origin: "http://app-b.example".parse().unwrap(),
          weight: 1,
          max_conns: 0,
          backup: false,
        },
      ],
      health_check: UpstreamPoolHealthCheckConfig::default(),
    }
  }

  #[test]
  fn round_robin_rotates_pool_servers() {
    let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::RoundRobin)]);

    let first = state
      .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
      .unwrap();
    assert_eq!(first.upstream_name, synthetic_upstream_name("app-pool", 0));
    drop(first);

    let second = state
      .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
      .unwrap();
    assert_eq!(second.upstream_name, synthetic_upstream_name("app-pool", 1));
  }

  #[test]
  fn max_conns_excludes_busy_pool_server() {
    let mut pool = test_pool(LoadBalancingAlgorithm::LeastConn);
    pool.servers[0].max_conns = 1;
    let state = PoolState::new(&[pool]);

    let first = state
      .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
      .unwrap();
    assert_eq!(first.upstream_name, synthetic_upstream_name("app-pool", 0));

    let second = state
      .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
      .unwrap();
    assert_eq!(second.upstream_name, synthetic_upstream_name("app-pool", 1));
  }
}
