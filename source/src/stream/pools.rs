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

  /// Restores an earlier logical flow selection against the active pool.
  ///
  /// The stored server identifier is never treated as an origin.  Recovery
  /// succeeds only while the current configuration still contains the same
  /// enabled, healthy, protocol-compatible server and its local connection
  /// bound admits another socket.
  pub fn select_exact(
    &self,
    pool_name: &str,
    server_id: &str,
    network: StreamNetwork,
  ) -> anyhow::Result<StreamPoolSelection> {
    let Some(pool) = self.pools.get(pool_name).cloned() else {
      bail!("unknown stream upstream pool {pool_name}");
    };
    let Some((index, server)) = pool
      .servers
      .iter()
      .enumerate()
      .find(|(_, server)| server.server_id == server_id)
    else {
      bail!("stream upstream pool {pool_name} has no server {server_id}");
    };
    let config = &pool.config.servers[index];
    if !server_available(server, config, network) {
      bail!("stream upstream pool {pool_name} server {server_id} is unavailable");
    }

    server.active.fetch_add(1, Ordering::Relaxed);
    Ok(StreamPoolSelection {
      pool_name: pool_name.to_string(),
      server_id: server.server_id.clone(),
      origin: server.origin.clone(),
      server: server.clone(),
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
  let candidates = candidates(pool, network);
  let (first_index, first) = weighted_sample(pool, &candidates, None, next_choice(pool))?;
  let Some((second_index, second)) = weighted_sample(
    pool,
    &candidates,
    Some(first.server_id.as_str()),
    next_choice(pool),
  ) else {
    return Some(first);
  };
  if normalized_active_score(pool, first_index, &first)
    <= normalized_active_score(pool, second_index, &second)
  {
    Some(first)
  } else {
    Some(second)
  }
}

fn select_weighted_least_conn(
  pool: &Arc<StreamPoolRuntime>,
  network: StreamNetwork,
) -> Option<Arc<StreamServerRuntime>> {
  candidates(pool, network)
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
  pool: &Arc<StreamPoolRuntime>,
  network: StreamNetwork,
  key: &str,
) -> Option<Arc<StreamServerRuntime>> {
  candidates(pool, network)
    .into_iter()
    .max_by_key(|(index, server)| {
      u128::from(stable_hash64_pair(key, &server.server_id).max(1))
        * u128::from(pool.config.servers[*index].weight.max(1))
    })
    .map(|(_, server)| server)
}

fn candidates(
  pool: &Arc<StreamPoolRuntime>,
  network: StreamNetwork,
) -> Vec<(usize, Arc<StreamServerRuntime>)> {
  let primary = pool
    .servers
    .iter()
    .enumerate()
    .zip(&pool.config.servers)
    .filter(|((_, runtime), config)| !config.backup && server_available(runtime, config, network))
    .map(|((index, runtime), _)| (index, runtime.clone()))
    .collect::<Vec<_>>();
  if !primary.is_empty() {
    return primary;
  }
  pool
    .servers
    .iter()
    .enumerate()
    .zip(&pool.config.servers)
    .filter(|((_, runtime), config)| config.backup && server_available(runtime, config, network))
    .map(|((index, runtime), _)| (index, runtime.clone()))
    .collect()
}

fn weighted_sample(
  pool: &Arc<StreamPoolRuntime>,
  candidates: &[(usize, Arc<StreamServerRuntime>)],
  excluded_server_id: Option<&str>,
  choice: u64,
) -> Option<(usize, Arc<StreamServerRuntime>)> {
  let total = candidates
    .iter()
    .filter(|(_, server)| excluded_server_id != Some(server.server_id.as_str()))
    .fold(0u128, |total, (index, _)| {
      total.saturating_add(u128::from(pool.config.servers[*index].weight.max(1)))
    });
  if total == 0 {
    return None;
  }
  let mut ticket = u128::from(choice) % total;
  for (index, server) in candidates {
    if excluded_server_id == Some(server.server_id.as_str()) {
      continue;
    }
    let weight = u128::from(pool.config.servers[*index].weight.max(1));
    if ticket < weight {
      return Some((*index, server.clone()));
    }
    ticket -= weight;
  }
  None
}

fn normalized_active_score(
  pool: &StreamPoolRuntime,
  index: usize,
  server: &StreamServerRuntime,
) -> u128 {
  let weight = u128::from(pool.config.servers[index].weight.max(1));
  server.active.load(Ordering::Relaxed) as u128 * 1_000 / weight
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

fn next_choice(pool: &StreamPoolRuntime) -> u64 {
  let value = pool.chooser.fetch_add(0x9e37_79b9, Ordering::Relaxed);
  mix64(value as u64)
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

#[cfg(test)]
mod tests {
  use super::*;

  fn exact_restore_pool(state: UpstreamPoolServerState, max_conns: usize) -> StreamPoolState {
    let state = StreamPoolState::new(&[StreamUpstreamPoolConfig {
      name: "udp-pool".to_string(),
      algorithm: LoadBalancingAlgorithm::PowerOfTwoChoices,
      hash_key: None,
      servers: vec![StreamUpstreamPoolServerConfig {
        id: Some("stable-backend".to_string()),
        origin: Url::parse("udp://127.0.0.1:5300").unwrap(),
        weight: 1,
        max_conns,
        backup: false,
        state,
      }],
    }]);
    match Arc::try_unwrap(state) {
      Ok(state) => state,
      Err(_) => panic!("test pool should have one owner"),
    }
  }

  #[test]
  fn exact_restore_resolves_only_current_authorized_server() {
    let state = exact_restore_pool(UpstreamPoolServerState::Ready, 0);
    let selection = state
      .select_exact("udp-pool", "stable-backend", StreamNetwork::Udp)
      .expect("configured UDP server should restore");

    assert_eq!(selection.pool_name, "udp-pool");
    assert_eq!(selection.server_id, "stable-backend");
    assert_eq!(selection.origin.as_str(), "udp://127.0.0.1:5300");
    assert!(
      state
        .select_exact("udp-pool", "removed-backend", StreamNetwork::Udp)
        .is_err(),
      "a stored identifier must not become arbitrary routing authority"
    );
    assert!(
      state
        .select_exact("udp-pool", "stable-backend", StreamNetwork::Tcp)
        .is_err(),
      "a stored identifier must not cross protocol boundaries"
    );
  }

  #[test]
  fn exact_restore_honors_state_and_connection_bounds() {
    let unavailable = exact_restore_pool(UpstreamPoolServerState::Drain, 0);
    assert!(
      unavailable
        .select_exact("udp-pool", "stable-backend", StreamNetwork::Udp)
        .is_err()
    );

    let bounded = exact_restore_pool(UpstreamPoolServerState::Ready, 1);
    let first = bounded
      .select_exact("udp-pool", "stable-backend", StreamNetwork::Udp)
      .expect("first restored selection should fit");
    assert!(
      bounded
        .select_exact("udp-pool", "stable-backend", StreamNetwork::Udp)
        .is_err(),
      "restoration must not bypass max_conns"
    );
    drop(first);
    assert!(
      bounded
        .select_exact("udp-pool", "stable-backend", StreamNetwork::Udp)
        .is_ok(),
      "dropping the restored selection should release its active count"
    );
  }

  #[test]
  fn stream_pool_weight_biases_bounded_candidate_sampling() {
    let pool = StreamUpstreamPoolConfig {
      name: "udp-pool".to_string(),
      algorithm: LoadBalancingAlgorithm::PowerOfTwoChoices,
      hash_key: None,
      servers: vec![
        StreamUpstreamPoolServerConfig {
          id: Some("weighted".to_string()),
          origin: Url::parse("udp://127.0.0.1:5300").unwrap(),
          weight: 3,
          max_conns: 0,
          backup: false,
          state: UpstreamPoolServerState::Ready,
        },
        StreamUpstreamPoolServerConfig {
          id: Some("baseline".to_string()),
          origin: Url::parse("udp://127.0.0.1:5301").unwrap(),
          weight: 1,
          max_conns: 0,
          backup: false,
          state: UpstreamPoolServerState::Ready,
        },
      ],
    };
    let state = StreamPoolState::new(&[pool]);
    let weighted = (0..256)
      .filter(|_| {
        state
          .select(
            "udp-pool",
            StreamNetwork::Udp,
            "203.0.113.10".parse().unwrap(),
            "flow",
          )
          .unwrap()
          .server_id
          == "weighted"
      })
      .count();

    assert!(
      weighted > 128,
      "higher-weight stream server should be sampled more often without weight-expanded storage"
    );
  }
}
