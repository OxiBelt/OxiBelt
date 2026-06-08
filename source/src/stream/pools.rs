//! Generic TCP/UDP stream upstream-pool selection.
//! Stream pools stay separate from HTTP and TURN pools because their schemes and health semantics differ.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::bail;
use serde::Serialize;
use url::Url;

use crate::config::{
  LoadBalancingAlgorithm, StreamNetwork, StreamUpstreamPoolConfig, StreamUpstreamPoolServerConfig,
  UpstreamPoolServerState, stream_upstream_pool_server_id,
};

pub struct StreamPoolState {
  pools: HashMap<String, Arc<StreamPoolRuntime>>,
}

#[derive(Debug)]
struct StreamPoolRuntime {
  config: StreamUpstreamPoolConfig,
  servers: Vec<Arc<StreamServerRuntime>>,
  chooser: AtomicUsize,
}

#[derive(Debug)]
struct StreamServerRuntime {
  server_id: String,
  origin: Url,
  active: AtomicUsize,
  healthy: AtomicBool,
}

pub struct StreamPoolSelection {
  pub pool_name: String,
  pub server_id: String,
  pub origin: Url,
  server: Arc<StreamServerRuntime>,
}

impl Drop for StreamPoolSelection {
  fn drop(&mut self) {
    self.server.active.fetch_sub(1, Ordering::Relaxed);
  }
}

#[derive(Debug, Serialize)]
pub struct StreamPoolSnapshot {
  pub name: String,
  pub algorithm: LoadBalancingAlgorithm,
  pub hash_key: Option<String>,
  pub servers: Vec<StreamPoolServerSnapshot>,
}

#[derive(Debug, Serialize)]
pub struct StreamPoolServerSnapshot {
  pub id: String,
  pub origin: String,
  pub weight: u32,
  pub max_conns: usize,
  pub backup: bool,
  pub state: UpstreamPoolServerState,
  pub active: usize,
  pub healthy: bool,
}

impl StreamPoolState {
  pub fn new(configs: &[StreamUpstreamPoolConfig]) -> Arc<Self> {
    let pools = configs
      .iter()
      .map(|config| {
        let servers = config
          .servers
          .iter()
          .enumerate()
          .map(|(index, server)| {
            Arc::new(StreamServerRuntime {
              server_id: stream_upstream_pool_server_id(index, server),
              origin: server.origin.clone(),
              active: AtomicUsize::new(0),
              healthy: AtomicBool::new(server.state == UpstreamPoolServerState::Ready),
            })
          })
          .collect();
        (
          config.name.clone(),
          Arc::new(StreamPoolRuntime {
            config: config.clone(),
            servers,
            chooser: AtomicUsize::new(0x517c_c1b7),
          }),
        )
      })
      .collect();
    Arc::new(Self { pools })
  }

  pub fn select(
    &self,
    pool_name: &str,
    network: StreamNetwork,
    client_ip: IpAddr,
    hash_key: &str,
  ) -> anyhow::Result<StreamPoolSelection> {
    let Some(pool) = self.pools.get(pool_name).cloned() else {
      bail!("unknown stream upstream pool {pool_name}");
    };
    let hash_key = pool.config.hash_key.as_deref().unwrap_or(hash_key);
    let server = match pool.config.algorithm {
      LoadBalancingAlgorithm::PowerOfTwoChoices => select_power_of_two_choices(&pool, network),
      LoadBalancingAlgorithm::WeightedLeastConn => select_weighted_least_conn(&pool, network),
      LoadBalancingAlgorithm::RendezvousHash => select_rendezvous_hash(&pool, network, hash_key),
      LoadBalancingAlgorithm::RendezvousIpHash => {
        select_rendezvous_hash(&pool, network, &client_ip.to_string())
      }
      LoadBalancingAlgorithm::Ewma
      | LoadBalancingAlgorithm::LeastTime
      | LoadBalancingAlgorithm::StickyCookie => None,
    }
    .ok_or_else(|| anyhow::anyhow!("stream upstream pool {pool_name} has no available servers"))?;

    server.active.fetch_add(1, Ordering::Relaxed);
    Ok(StreamPoolSelection {
      pool_name: pool_name.to_string(),
      server_id: server.server_id.clone(),
      origin: server.origin.clone(),
      server,
    })
  }

  pub fn snapshots(&self) -> Vec<StreamPoolSnapshot> {
    let mut snapshots = self
      .pools
      .values()
      .map(stream_pool_snapshot)
      .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| left.name.cmp(&right.name));
    snapshots
  }

  pub fn snapshot(&self, pool_name: &str) -> Option<StreamPoolSnapshot> {
    self.pools.get(pool_name).map(stream_pool_snapshot)
  }
}

fn stream_pool_snapshot(pool: &Arc<StreamPoolRuntime>) -> StreamPoolSnapshot {
  StreamPoolSnapshot {
    name: pool.config.name.clone(),
    algorithm: pool.config.algorithm,
    hash_key: pool.config.hash_key.clone(),
    servers: pool
      .servers
      .iter()
      .zip(&pool.config.servers)
      .map(|(runtime, config)| StreamPoolServerSnapshot {
        id: runtime.server_id.clone(),
        origin: runtime.origin.to_string(),
        weight: config.weight,
        max_conns: config.max_conns,
        backup: config.backup,
        state: config.state,
        active: runtime.active.load(Ordering::Relaxed),
        healthy: runtime.healthy.load(Ordering::Relaxed),
      })
      .collect(),
  }
}

fn select_power_of_two_choices(
  pool: &Arc<StreamPoolRuntime>,
  network: StreamNetwork,
) -> Option<Arc<StreamServerRuntime>> {
  let weighted = weighted_candidates(pool, network);
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
  if normalized_active_score(pool, &first) <= normalized_active_score(pool, &second) {
    Some(first)
  } else {
    Some(second)
  }
}

fn select_weighted_least_conn(
  pool: &Arc<StreamPoolRuntime>,
  network: StreamNetwork,
) -> Option<Arc<StreamServerRuntime>> {
  candidates(pool, network).into_iter().min_by_key(|server| {
    (
      normalized_active_score(pool, server),
      stable_hash64(&server.server_id),
    )
  })
}

fn select_rendezvous_hash(
  pool: &Arc<StreamPoolRuntime>,
  network: StreamNetwork,
  key: &str,
) -> Option<Arc<StreamServerRuntime>> {
  candidates(pool, network).into_iter().max_by_key(|server| {
    u128::from(stable_hash64_pair(key, &server.server_id).max(1))
      * u128::from(server_config(pool, server).weight.max(1))
  })
}

fn candidates(
  pool: &Arc<StreamPoolRuntime>,
  network: StreamNetwork,
) -> Vec<Arc<StreamServerRuntime>> {
  let primary = pool
    .servers
    .iter()
    .zip(&pool.config.servers)
    .filter(|(runtime, config)| !config.backup && server_available(runtime, config, network))
    .map(|(runtime, _)| runtime.clone())
    .collect::<Vec<_>>();
  if !primary.is_empty() {
    return primary;
  }
  pool
    .servers
    .iter()
    .zip(&pool.config.servers)
    .filter(|(runtime, config)| config.backup && server_available(runtime, config, network))
    .map(|(runtime, _)| runtime.clone())
    .collect()
}

fn weighted_candidates(
  pool: &Arc<StreamPoolRuntime>,
  network: StreamNetwork,
) -> Vec<Arc<StreamServerRuntime>> {
  let mut result = Vec::new();
  for server in candidates(pool, network) {
    for _ in 0..server_config(pool, &server).weight {
      result.push(server.clone());
    }
  }
  result
}

fn normalized_active_score(pool: &StreamPoolRuntime, server: &StreamServerRuntime) -> u128 {
  let weight = u128::from(server_config(pool, server).weight.max(1));
  server.active.load(Ordering::Relaxed) as u128 * 1_000 / weight
}

fn server_config<'a>(
  pool: &'a StreamPoolRuntime,
  server: &StreamServerRuntime,
) -> &'a StreamUpstreamPoolServerConfig {
  let index = pool
    .servers
    .iter()
    .position(|candidate| candidate.server_id == server.server_id)
    .unwrap_or(0);
  &pool.config.servers[index]
}

fn server_available(
  runtime: &StreamServerRuntime,
  config: &StreamUpstreamPoolServerConfig,
  network: StreamNetwork,
) -> bool {
  matches!(config.state, UpstreamPoolServerState::Ready)
    && runtime.healthy.load(Ordering::Relaxed)
    && config.origin.scheme() == stream_origin_scheme(network)
    && (config.max_conns == 0 || runtime.active.load(Ordering::Relaxed) < config.max_conns)
}

fn stream_origin_scheme(network: StreamNetwork) -> &'static str {
  match network {
    StreamNetwork::Tcp => "tcp",
    StreamNetwork::Udp => "udp",
  }
}

fn next_choice(pool: &StreamPoolRuntime, len: usize) -> usize {
  let value = pool.chooser.fetch_add(0x9e37_79b9, Ordering::Relaxed);
  mix64(value as u64) as usize % len
}

fn stable_hash64(value: &str) -> u64 {
  stable_hash64_pair(value, "")
}

fn stable_hash64_pair(left: &str, right: &str) -> u64 {
  let mut hash = 0xcbf2_9ce4_8422_2325u64;
  for byte in left.bytes().chain([0xff]).chain(right.bytes()) {
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
