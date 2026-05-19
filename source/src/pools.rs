use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use anyhow::bail;
use http::HeaderValue;
use serde::Serialize;

use crate::config::{
  HealthCheckProtocol, HttpVersion, LoadBalancingAlgorithm, ProxyProtocolEgressMode,
  UpstreamConfig, UpstreamPoolConfig, UpstreamPoolServerConfig, UpstreamTlsConfig,
  upstream_pool_server_id,
};
use crate::shared_state::SharedState;

mod sticky;

#[derive(Debug)]
pub struct PoolState {
  pools: HashMap<String, Arc<PoolRuntime>>,
  shared_state: Option<Arc<SharedState>>,
}

#[derive(Debug)]
struct PoolRuntime {
  config: UpstreamPoolConfig,
  servers: Vec<Arc<PoolServerRuntime>>,
  round_robin: AtomicUsize,
  random: AtomicUsize,
  sticky_secret: [u8; 32],
  shared_state: Option<Arc<SharedState>>,
}

#[derive(Debug)]
struct PoolServerRuntime {
  server_id: String,
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
  shared_state: Option<Arc<SharedState>>,
  sticky_cookie: Option<HeaderValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolRuntimeSnapshot {
  pub name: String,
  pub algorithm: String,
  pub servers: Vec<PoolServerRuntimeSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolServerRuntimeSnapshot {
  pub id: String,
  pub upstream_name: String,
  pub origin: String,
  pub source: String,
  pub state: String,
  pub weight: u32,
  pub max_conns: usize,
  pub backup: bool,
  pub active: usize,
  pub healthy: bool,
}

impl Drop for PoolSelection {
  fn drop(&mut self) {
    self.server.active.fetch_sub(1, Ordering::Relaxed);
    if let Some(shared) = &self.shared_state
      && let Err(error) = shared.pool_active_add(&self.upstream_name, -1)
    {
      tracing::warn!(error = %error, upstream = %self.upstream_name, "failed to release shared upstream active count");
    }
  }
}

impl PoolState {
  pub fn new(configs: &[UpstreamPoolConfig], shared_state: Option<Arc<SharedState>>) -> Arc<Self> {
    let pools = configs
      .iter()
      .map(|config| {
        let servers = config
          .servers
          .iter()
          .enumerate()
          .map(|(index, _)| {
            let server_id = upstream_pool_server_id(index, &config.servers[index]);
            Arc::new(PoolServerRuntime {
              upstream_name: synthetic_upstream_name_for_id(&config.name, &server_id),
              server_id,
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
            sticky_secret: sticky::sticky_secret_for_pool(config, shared_state.as_ref()),
            shared_state: shared_state.clone(),
          }),
        )
      })
      .collect();
    Arc::new(Self {
      pools,
      shared_state,
    })
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
            name: synthetic_upstream_name_for_id(
              &pool.name,
              &upstream_pool_server_id(index, server),
            ),
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
            pool_max_idle_per_host: pool.keepalive.max_idle,
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
    self.select_with_cookie_header(pool_name, client_ip, hash_key, policy_override, None)
  }

  pub fn select_with_cookie_header(
    &self,
    pool_name: &str,
    client_ip: IpAddr,
    hash_key: &str,
    policy_override: Option<&str>,
    cookie_header: Option<&HeaderValue>,
  ) -> anyhow::Result<PoolSelection> {
    let Some(pool) = self.pools.get(pool_name).cloned() else {
      bail!("unknown upstream pool {pool_name}");
    };
    let algorithm = policy_override
      .and_then(parse_policy_override)
      .unwrap_or(pool.config.algorithm);

    let (server, sticky_cookie) = if algorithm == LoadBalancingAlgorithm::StickyCookie {
      sticky::select_sticky_cookie(&pool, client_ip, hash_key, cookie_header)
    } else {
      (
        select_by_algorithm(&pool, algorithm, client_ip, hash_key),
        None,
      )
    };
    let server = server
      .ok_or_else(|| anyhow::anyhow!("upstream pool {pool_name} has no available servers"))?;
    Ok(self.selection_from_server(pool_name, server, sticky_cookie))
  }

  pub fn snapshots(&self) -> Vec<PoolRuntimeSnapshot> {
    let mut snapshots = self.pools.values().map(pool_snapshot).collect::<Vec<_>>();
    snapshots.sort_by(|left, right| left.name.cmp(&right.name));
    snapshots
  }

  pub fn snapshot(&self, pool_name: &str) -> Option<PoolRuntimeSnapshot> {
    self.pools.get(pool_name).map(pool_snapshot)
  }

  pub fn report_success(&self, upstream_name: &str) {
    if self.pools.is_empty() {
      return;
    }
    if let Some((pool, server)) = self.find_pool_server(upstream_name) {
      if let Some(shared) = &self.shared_state
        && let Ok(Some(healthy)) = shared.pool_report(
          upstream_name,
          true,
          pool.config.health_check.enabled,
          pool.config.health_check.healthy_threshold,
          pool.config.health_check.unhealthy_threshold,
        )
      {
        server.healthy.store(healthy, Ordering::Relaxed);
        return;
      }
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
    if self.pools.is_empty() {
      return;
    }
    if let Some((pool, server)) = self.find_pool_server(upstream_name) {
      if let Some(shared) = &self.shared_state
        && let Ok(Some(healthy)) = shared.pool_report(
          upstream_name,
          false,
          pool.config.health_check.enabled,
          pool.config.health_check.healthy_threshold,
          pool.config.health_check.unhealthy_threshold,
        )
      {
        server.healthy.store(healthy, Ordering::Relaxed);
        return;
      }
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

  fn selection_from_server(
    &self,
    pool_name: &str,
    server: Arc<PoolServerRuntime>,
    sticky_cookie: Option<HeaderValue>,
  ) -> PoolSelection {
    server.active.fetch_add(1, Ordering::Relaxed);
    if let Some(shared) = &self.shared_state
      && let Err(error) = shared.pool_active_add(&server.upstream_name, 1)
    {
      tracing::warn!(error = %error, upstream = %server.upstream_name, "failed to update shared upstream active count");
    }
    PoolSelection {
      pool_name: pool_name.to_string(),
      upstream_name: server.upstream_name.clone(),
      server,
      shared_state: self.shared_state.clone(),
      sticky_cookie,
    }
  }
}

impl PoolSelection {
  pub fn sticky_cookie(&self) -> Option<HeaderValue> {
    self.sticky_cookie.clone()
  }
}

fn parse_policy_override(raw: &str) -> Option<LoadBalancingAlgorithm> {
  match raw {
    "round_robin" => Some(LoadBalancingAlgorithm::RoundRobin),
    "least_conn" | "least_connections" => Some(LoadBalancingAlgorithm::LeastConn),
    "random" => Some(LoadBalancingAlgorithm::Random),
    "hash" => Some(LoadBalancingAlgorithm::Hash),
    "ip_hash" => Some(LoadBalancingAlgorithm::IpHash),
    "sticky_cookie" => Some(LoadBalancingAlgorithm::StickyCookie),
    _ => None,
  }
}

fn select_by_algorithm(
  pool: &Arc<PoolRuntime>,
  algorithm: LoadBalancingAlgorithm,
  client_ip: IpAddr,
  hash_key: &str,
) -> Option<Arc<PoolServerRuntime>> {
  match algorithm {
    LoadBalancingAlgorithm::RoundRobin => select_round_robin(pool),
    LoadBalancingAlgorithm::LeastConn => select_least_conn(pool),
    LoadBalancingAlgorithm::Random => select_random(pool),
    LoadBalancingAlgorithm::Hash => select_hash(pool, hash_key),
    LoadBalancingAlgorithm::IpHash => select_hash(pool, &client_ip.to_string()),
    LoadBalancingAlgorithm::StickyCookie => None,
  }
}

fn build_sticky_fallback(
  pool: &Arc<PoolRuntime>,
  algorithm: LoadBalancingAlgorithm,
  client_ip: IpAddr,
  hash_key: &str,
) -> Option<Arc<PoolServerRuntime>> {
  select_by_algorithm(pool, algorithm, client_ip, hash_key)
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
    .min_by_key(|server| active_count(pool, server))
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
    let weight = server_config(pool, index).weight;
    for _ in 0..weight {
      result.push(server.clone());
    }
  }
  if result.is_empty() {
    for (index, server) in pool.servers.iter().enumerate() {
      let config = server_config(pool, index);
      if config.backup
        && config.state.accepts_new_requests()
        && server_capacity_available(pool, index, server)
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
      let config = server_config(pool, *index);
      config.backup
        && config.state.accepts_new_requests()
        && server_capacity_available(pool, *index, server)
    })
    .map(|(_, server)| server.clone())
    .collect()
}

fn server_available(
  pool: &Arc<PoolRuntime>,
  index: usize,
  server: &Arc<PoolServerRuntime>,
) -> bool {
  let config = server_config(pool, index);
  !config.backup
    && config.state.accepts_new_requests()
    && server_healthy(pool, server)
    && server_capacity_available(pool, index, server)
}

fn server_capacity_available(
  pool: &PoolRuntime,
  index: usize,
  server: &Arc<PoolServerRuntime>,
) -> bool {
  let max_conns = pool.config.servers[index].max_conns;
  max_conns == 0 || active_count(pool, server) < max_conns
}

fn active_count(pool: &PoolRuntime, server: &PoolServerRuntime) -> usize {
  if let Some(shared) = &pool.shared_state
    && let Ok(Some(active)) = shared.pool_active(&server.upstream_name)
  {
    return active;
  }
  server.active.load(Ordering::Relaxed)
}

fn server_config(pool: &PoolRuntime, index: usize) -> &UpstreamPoolServerConfig {
  &pool.config.servers[index]
}

fn server_healthy(pool: &PoolRuntime, server: &PoolServerRuntime) -> bool {
  if let Some(shared) = &pool.shared_state
    && let Ok(Some(healthy)) = shared.pool_health(&server.upstream_name)
  {
    return healthy;
  }
  server.healthy.load(Ordering::Relaxed)
}

#[allow(dead_code)]
pub(crate) fn synthetic_upstream_name(pool: &str, index: usize) -> String {
  format!("pool:{pool}:{index}")
}

pub(crate) fn synthetic_upstream_name_for_id(pool: &str, server_id: &str) -> String {
  format!("pool:{pool}:{server_id}")
}

fn pool_snapshot(pool: &Arc<PoolRuntime>) -> PoolRuntimeSnapshot {
  let mut servers = pool
    .servers
    .iter()
    .enumerate()
    .map(|(index, server)| {
      let config = server_config(pool, index);
      PoolServerRuntimeSnapshot {
        id: server.server_id.clone(),
        upstream_name: server.upstream_name.clone(),
        origin: config.origin.to_string(),
        source: config.source.as_str().to_string(),
        state: config.state.as_str().to_string(),
        weight: config.weight,
        max_conns: config.max_conns,
        backup: config.backup,
        active: active_count(pool, server),
        healthy: server_healthy(pool, server),
      }
    })
    .collect::<Vec<_>>();
  servers.sort_by(|left, right| left.id.cmp(&right.id));
  PoolRuntimeSnapshot {
    name: pool.config.name.clone(),
    algorithm: format!("{:?}", pool.config.algorithm),
    servers,
  }
}

#[cfg(test)]
mod tests;
