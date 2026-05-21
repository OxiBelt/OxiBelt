use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

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

const SCORE_SCALE: u128 = 1_000;
const EWMA_FAILURE_PENALTY_MS: u64 = 30_000;
const EWMA_ACTIVE_PENALTY_MS: u64 = 5;

#[derive(Debug)]
pub struct PoolState {
  pools: HashMap<String, Arc<PoolRuntime>>,
  shared_state: Option<Arc<SharedState>>,
}

#[derive(Debug)]
struct PoolRuntime {
  config: UpstreamPoolConfig,
  servers: Vec<Arc<PoolServerRuntime>>,
  chooser: AtomicUsize,
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
  ewma_latency_ms: AtomicU64,
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
              ewma_latency_ms: AtomicU64::new(0),
            })
          })
          .collect();
        (
          config.name.clone(),
          Arc::new(PoolRuntime {
            config: config.clone(),
            servers,
            chooser: AtomicUsize::new(0x9e37_79b9),
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
    self.select_with_cookie_header_excluding(
      pool_name,
      client_ip,
      hash_key,
      policy_override,
      cookie_header,
      &[],
    )
  }

  pub fn select_with_cookie_header_excluding(
    &self,
    pool_name: &str,
    client_ip: IpAddr,
    hash_key: &str,
    policy_override: Option<&str>,
    cookie_header: Option<&HeaderValue>,
    excluded_upstreams: &[String],
  ) -> anyhow::Result<PoolSelection> {
    let Some(pool) = self.pools.get(pool_name).cloned() else {
      bail!("unknown upstream pool {pool_name}");
    };
    let algorithm = policy_override
      .and_then(parse_policy_override)
      .unwrap_or(pool.config.algorithm);
    let excluded_upstreams = excluded_upstreams
      .iter()
      .map(String::as_str)
      .collect::<HashSet<_>>();

    let (server, sticky_cookie) = if algorithm == LoadBalancingAlgorithm::StickyCookie {
      sticky::select_sticky_cookie(
        &pool,
        client_ip,
        hash_key,
        cookie_header,
        &excluded_upstreams,
      )
    } else {
      (
        select_by_algorithm(&pool, algorithm, client_ip, hash_key, &excluded_upstreams),
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

  pub fn report_success_latency(&self, upstream_name: &str, latency_ms: u64) {
    if let Some((_, server)) = self.find_pool_server(upstream_name) {
      observe_ewma_latency(&server, latency_ms);
    }
    self.report_success(upstream_name);
  }

  pub fn report_failure(&self, upstream_name: &str) {
    if self.pools.is_empty() {
      return;
    }
    if let Some((pool, server)) = self.find_pool_server(upstream_name) {
      observe_ewma_latency(&server, EWMA_FAILURE_PENALTY_MS);
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
    "power_of_two_choices" => Some(LoadBalancingAlgorithm::PowerOfTwoChoices),
    "weighted_least_conn" => Some(LoadBalancingAlgorithm::WeightedLeastConn),
    "rendezvous_hash" => Some(LoadBalancingAlgorithm::RendezvousHash),
    "rendezvous_ip_hash" => Some(LoadBalancingAlgorithm::RendezvousIpHash),
    "ewma" => Some(LoadBalancingAlgorithm::Ewma),
    "least_time" => Some(LoadBalancingAlgorithm::LeastTime),
    _ => None,
  }
}

fn select_by_algorithm(
  pool: &Arc<PoolRuntime>,
  algorithm: LoadBalancingAlgorithm,
  client_ip: IpAddr,
  hash_key: &str,
  excluded_upstreams: &HashSet<&str>,
) -> Option<Arc<PoolServerRuntime>> {
  match algorithm {
    LoadBalancingAlgorithm::PowerOfTwoChoices => {
      select_power_of_two_choices(pool, excluded_upstreams)
    }
    LoadBalancingAlgorithm::WeightedLeastConn => {
      select_weighted_least_conn(pool, excluded_upstreams)
    }
    LoadBalancingAlgorithm::RendezvousHash => {
      select_rendezvous_hash(pool, hash_key, excluded_upstreams)
    }
    LoadBalancingAlgorithm::RendezvousIpHash => {
      select_rendezvous_hash(pool, &client_ip.to_string(), excluded_upstreams)
    }
    LoadBalancingAlgorithm::Ewma => select_ewma(pool, excluded_upstreams),
    LoadBalancingAlgorithm::LeastTime => select_least_time(pool, excluded_upstreams),
    LoadBalancingAlgorithm::StickyCookie => None,
  }
}

fn build_sticky_fallback(
  pool: &Arc<PoolRuntime>,
  algorithm: LoadBalancingAlgorithm,
  client_ip: IpAddr,
  hash_key: &str,
  excluded_upstreams: &HashSet<&str>,
) -> Option<Arc<PoolServerRuntime>> {
  select_by_algorithm(pool, algorithm, client_ip, hash_key, excluded_upstreams)
}

fn select_power_of_two_choices(
  pool: &Arc<PoolRuntime>,
  excluded_upstreams: &HashSet<&str>,
) -> Option<Arc<PoolServerRuntime>> {
  let weighted = weighted_available(pool, excluded_upstreams);
  if weighted.is_empty() {
    return None;
  }
  if weighted.len() == 1 {
    return weighted.first().cloned();
  }
  let first_index = next_choice(pool, weighted.len());
  let mut second_index = next_choice(pool, weighted.len());
  if first_index == second_index {
    second_index = (second_index + 1) % weighted.len();
  }
  let first = weighted[first_index].clone();
  let second = weighted[second_index].clone();
  Some(select_lower_active_score(pool, first, second))
}

fn select_weighted_least_conn(
  pool: &Arc<PoolRuntime>,
  excluded_upstreams: &HashSet<&str>,
) -> Option<Arc<PoolServerRuntime>> {
  available_candidates(pool, excluded_upstreams)
    .into_iter()
    .min_by_key(|(index, server)| {
      (
        normalized_active_score(pool, *index, server),
        stable_hash64(&server.server_id),
      )
    })
    .map(|(_, server)| server)
}

fn select_rendezvous_hash(
  pool: &Arc<PoolRuntime>,
  key: &str,
  excluded_upstreams: &HashSet<&str>,
) -> Option<Arc<PoolServerRuntime>> {
  available_candidates(pool, excluded_upstreams)
    .into_iter()
    .max_by_key(|(index, server)| rendezvous_score(pool, *index, server, key))
    .map(|(_, server)| server)
}

fn select_ewma(
  pool: &Arc<PoolRuntime>,
  excluded_upstreams: &HashSet<&str>,
) -> Option<Arc<PoolServerRuntime>> {
  available_candidates(pool, excluded_upstreams)
    .into_iter()
    .min_by_key(|(index, server)| {
      (
        ewma_score(pool, *index, server, true),
        stable_hash64(&server.server_id),
      )
    })
    .map(|(_, server)| server)
}

fn select_least_time(
  pool: &Arc<PoolRuntime>,
  excluded_upstreams: &HashSet<&str>,
) -> Option<Arc<PoolServerRuntime>> {
  available_candidates(pool, excluded_upstreams)
    .into_iter()
    .min_by_key(|(index, server)| {
      (
        ewma_score(pool, *index, server, false),
        normalized_active_score(pool, *index, server),
        stable_hash64(&server.server_id),
      )
    })
    .map(|(_, server)| server)
}

fn weighted_available(
  pool: &Arc<PoolRuntime>,
  excluded_upstreams: &HashSet<&str>,
) -> Vec<Arc<PoolServerRuntime>> {
  let mut result = Vec::new();
  for (index, server) in available_candidates(pool, excluded_upstreams) {
    let weight = server_config(pool, index).weight;
    for _ in 0..weight {
      result.push(server.clone());
    }
  }
  result
}

fn available_candidates(
  pool: &Arc<PoolRuntime>,
  excluded_upstreams: &HashSet<&str>,
) -> Vec<(usize, Arc<PoolServerRuntime>)> {
  let primary = pool
    .servers
    .iter()
    .enumerate()
    .filter(|(index, server)| server_available(pool, *index, server, excluded_upstreams))
    .map(|(index, server)| (index, server.clone()))
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
        && !excluded_upstreams.contains(server.upstream_name.as_str())
        && config.state.accepts_new_requests()
        && server_healthy(pool, server)
        && server_capacity_available(pool, *index, server)
    })
    .map(|(index, server)| (index, server.clone()))
    .collect()
}

fn select_lower_active_score(
  pool: &PoolRuntime,
  first: Arc<PoolServerRuntime>,
  second: Arc<PoolServerRuntime>,
) -> Arc<PoolServerRuntime> {
  let first_index = server_index(pool, &first).unwrap_or(0);
  let second_index = server_index(pool, &second).unwrap_or(first_index);
  let first_score = normalized_active_score(pool, first_index, &first);
  let second_score = normalized_active_score(pool, second_index, &second);
  if first_score <= second_score {
    first
  } else {
    second
  }
}

fn next_choice(pool: &PoolRuntime, len: usize) -> usize {
  let current = pool.chooser.fetch_add(1, Ordering::Relaxed) as u64;
  (mix64(current) as usize) % len
}

fn normalized_active_score(pool: &PoolRuntime, index: usize, server: &PoolServerRuntime) -> u128 {
  let weight = u128::from(server_config(pool, index).weight.max(1));
  active_count(pool, server) as u128 * SCORE_SCALE / weight
}

fn rendezvous_score(
  pool: &PoolRuntime,
  index: usize,
  server: &PoolServerRuntime,
  key: &str,
) -> u128 {
  let hash = stable_hash64_pair(key, &server.server_id).max(1);
  u128::from(hash) * u128::from(server_config(pool, index).weight.max(1))
}

fn ewma_score(
  pool: &PoolRuntime,
  index: usize,
  server: &PoolServerRuntime,
  include_active: bool,
) -> u128 {
  let weight = u128::from(server_config(pool, index).weight.max(1));
  let latency = u128::from(latency_sample_for_score(pool, server));
  let active = if include_active {
    active_count(pool, server) as u128 * u128::from(EWMA_ACTIVE_PENALTY_MS)
  } else {
    0
  };
  latency.saturating_add(active) * SCORE_SCALE / weight
}

fn latency_sample_for_score(pool: &PoolRuntime, server: &PoolServerRuntime) -> u64 {
  let current = server.ewma_latency_ms.load(Ordering::Relaxed);
  if current > 0 {
    return current;
  }
  let (sum, count) = pool
    .servers
    .iter()
    .fold((0u128, 0u128), |(sum, count), server| {
      let value = server.ewma_latency_ms.load(Ordering::Relaxed);
      if value == 0 {
        (sum, count)
      } else {
        (sum + u128::from(value), count + 1)
      }
    });
  sum
    .checked_div(count)
    .unwrap_or(0)
    .min(u128::from(u64::MAX)) as u64
}

fn server_index(pool: &PoolRuntime, target: &PoolServerRuntime) -> Option<usize> {
  pool
    .servers
    .iter()
    .position(|server| server.server_id == target.server_id)
}

fn observe_ewma_latency(server: &PoolServerRuntime, sample_ms: u64) {
  let sample_ms = sample_ms.max(1);
  let _ = server
    .ewma_latency_ms
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
      Some(if current == 0 {
        sample_ms
      } else {
        current
          .saturating_mul(7)
          .saturating_add(sample_ms)
          .saturating_div(8)
      })
    });
}

fn stable_hash64(value: &str) -> u64 {
  let mut hash = 0xcbf2_9ce4_8422_2325u64;
  for byte in value.as_bytes() {
    hash ^= u64::from(*byte);
    hash = hash.wrapping_mul(0x100_0000_01b3);
  }
  mix64(hash)
}

fn stable_hash64_pair(left: &str, right: &str) -> u64 {
  let mut hash = 0xcbf2_9ce4_8422_2325u64;
  for byte in left
    .as_bytes()
    .iter()
    .copied()
    .chain(std::iter::once(0xff))
    .chain(right.as_bytes().iter().copied())
  {
    hash ^= u64::from(byte);
    hash = hash.wrapping_mul(0x100_0000_01b3);
  }
  mix64(hash)
}

fn mix64(mut value: u64) -> u64 {
  value ^= value >> 33;
  value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
  value ^= value >> 33;
  value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
  value ^ (value >> 33)
}

fn server_available(
  pool: &Arc<PoolRuntime>,
  index: usize,
  server: &Arc<PoolServerRuntime>,
  excluded_upstreams: &HashSet<&str>,
) -> bool {
  let config = server_config(pool, index);
  !config.backup
    && !excluded_upstreams.contains(server.upstream_name.as_str())
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
