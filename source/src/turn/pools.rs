//! TURN upstream-pool selection state.
//! TURN relay targets are selected independently from HTTP upstream pools.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use anyhow::bail;
use url::Url;

use crate::config::{
  LoadBalancingAlgorithm, TurnUpstreamPoolConfig, TurnUpstreamPoolServerConfig,
  UpstreamPoolServerState, UpstreamTlsConfig, turn_upstream_pool_server_id,
};

pub struct TurnPoolState {
  pools: HashMap<String, Arc<TurnPoolRuntime>>,
}

type TurnHealthTarget = (String, String, Url, UpstreamTlsConfig, u64, u64, u64, u64);

#[derive(Debug)]
struct TurnPoolRuntime {
  config: TurnUpstreamPoolConfig,
  servers: Vec<Arc<TurnServerRuntime>>,
  chooser: AtomicUsize,
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
  pub tls: UpstreamTlsConfig,
  pub connect_timeout_ms: u64,
  pub tls_handshake_timeout_ms: u64,
  server: Arc<TurnServerRuntime>,
}

impl Drop for TurnPoolSelection {
  fn drop(&mut self) {
    self.server.active.fetch_sub(1, Ordering::Relaxed);
  }
}

impl TurnPoolState {
  pub fn new(configs: &[TurnUpstreamPoolConfig]) -> Arc<Self> {
    Self::new_with_previous(configs, None)
  }

  pub fn new_with_previous(
    configs: &[TurnUpstreamPoolConfig],
    previous: Option<&TurnPoolState>,
  ) -> Arc<Self> {
    let pools = configs
      .iter()
      .map(|config| {
        let previous_pool = previous.and_then(|state| state.pools.get(&config.name));
        let servers = config
          .servers
          .iter()
          .enumerate()
          .map(|(index, server)| {
            let server_id = turn_upstream_pool_server_id(index, server);
            previous_pool
              .and_then(|pool| {
                pool
                  .servers
                  .iter()
                  .find(|runtime| runtime.server_id == server_id && runtime.origin == server.origin)
              })
              .cloned()
              .unwrap_or_else(|| {
                Arc::new(TurnServerRuntime {
                  server_id,
                  origin: server.origin.clone(),
                  active: AtomicUsize::new(0),
                  healthy: AtomicBool::new(server.state == UpstreamPoolServerState::Ready),
                  consecutive_successes: AtomicU32::new(0),
                  consecutive_failures: AtomicU32::new(0),
                })
              })
          })
          .collect();
        let chooser = previous_pool
          .map(|pool| pool.chooser.load(Ordering::Relaxed))
          .unwrap_or(0x9e37_79b9);
        (
          config.name.clone(),
          Arc::new(TurnPoolRuntime {
            config: config.clone(),
            servers,
            chooser: AtomicUsize::new(chooser),
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
      LoadBalancingAlgorithm::PowerOfTwoChoices => select_power_of_two_choices(&pool),
      LoadBalancingAlgorithm::WeightedLeastConn => select_weighted_least_conn(&pool),
      LoadBalancingAlgorithm::RendezvousHash => select_rendezvous_hash(&pool, hash_key),
      LoadBalancingAlgorithm::RendezvousIpHash => {
        select_rendezvous_hash(&pool, &client_ip.to_string())
      }
      LoadBalancingAlgorithm::Ewma
      | LoadBalancingAlgorithm::LeastTime
      | LoadBalancingAlgorithm::StickyCookie => None,
    }
    .ok_or_else(|| anyhow::anyhow!("TURN upstream pool {pool_name} has no available servers"))?;

    let tls = server_config(&pool, &server).tls.clone();
    server.active.fetch_add(1, Ordering::Relaxed);
    Ok(TurnPoolSelection {
      pool_name: pool_name.to_string(),
      server_id: server.server_id.clone(),
      origin: server.origin.clone(),
      tls,
      connect_timeout_ms: pool.config.health_check.connect_timeout_ms,
      tls_handshake_timeout_ms: pool.config.health_check.tls_handshake_timeout_ms,
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

  pub fn health_targets(&self) -> Vec<TurnHealthTarget> {
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
            server_config(pool, server).tls.clone(),
            pool.config.health_check.interval_ms,
            pool.config.health_check.timeout_ms,
            pool.config.health_check.connect_timeout_ms,
            pool.config.health_check.tls_handshake_timeout_ms,
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

fn select_power_of_two_choices(pool: &Arc<TurnPoolRuntime>) -> Option<Arc<TurnServerRuntime>> {
  let weighted = weighted_candidates(pool);
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

fn select_weighted_least_conn(pool: &Arc<TurnPoolRuntime>) -> Option<Arc<TurnServerRuntime>> {
  candidates(pool).into_iter().min_by_key(|server| {
    (
      normalized_active_score(pool, server),
      stable_hash64(&server.server_id),
    )
  })
}

fn select_rendezvous_hash(
  pool: &Arc<TurnPoolRuntime>,
  key: &str,
) -> Option<Arc<TurnServerRuntime>> {
  let candidates = candidates(pool);
  if candidates.is_empty() {
    return None;
  }
  candidates.into_iter().max_by_key(|server| {
    u128::from(stable_hash64_pair(key, &server.server_id).max(1))
      * u128::from(server_config(pool, server).weight.max(1))
  })
}

fn candidates(pool: &Arc<TurnPoolRuntime>) -> Vec<Arc<TurnServerRuntime>> {
  let primary = pool
    .servers
    .iter()
    .zip(&pool.config.servers)
    .filter(|(runtime, config)| !config.backup && server_available(runtime, config))
    .map(|(runtime, _)| runtime.clone())
    .collect::<Vec<_>>();
  if !primary.is_empty() {
    return primary;
  }
  pool
    .servers
    .iter()
    .zip(&pool.config.servers)
    .filter(|(runtime, config)| config.backup && server_available(runtime, config))
    .map(|(runtime, _)| runtime.clone())
    .collect()
}

fn weighted_candidates(pool: &Arc<TurnPoolRuntime>) -> Vec<Arc<TurnServerRuntime>> {
  let mut result = Vec::new();
  for server in candidates(pool) {
    for _ in 0..server_config(pool, &server).weight {
      result.push(server.clone());
    }
  }
  result
}

fn normalized_active_score(pool: &TurnPoolRuntime, server: &TurnServerRuntime) -> u128 {
  let weight = u128::from(server_config(pool, server).weight.max(1));
  server.active.load(Ordering::Relaxed) as u128 * 1_000 / weight
}

fn server_config<'a>(
  pool: &'a TurnPoolRuntime,
  server: &TurnServerRuntime,
) -> &'a TurnUpstreamPoolServerConfig {
  let index = pool
    .servers
    .iter()
    .position(|candidate| candidate.server_id == server.server_id)
    .unwrap_or(0);
  &pool.config.servers[index]
}

fn next_choice(pool: &TurnPoolRuntime, len: usize) -> usize {
  let current = pool.chooser.fetch_add(1, Ordering::Relaxed) as u64;
  (mix64(current) as usize) % len
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

fn server_available(runtime: &TurnServerRuntime, config: &TurnUpstreamPoolServerConfig) -> bool {
  matches!(config.state, UpstreamPoolServerState::Ready)
    && runtime.healthy.load(Ordering::Relaxed)
    && (config.max_conns == 0 || runtime.active.load(Ordering::Relaxed) < config.max_conns)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn pool(origin: &str) -> TurnUpstreamPoolConfig {
    TurnUpstreamPoolConfig {
      name: "turn".to_string(),
      algorithm: LoadBalancingAlgorithm::PowerOfTwoChoices,
      hash_key: None,
      servers: vec![TurnUpstreamPoolServerConfig {
        id: Some("stable".to_string()),
        origin: Url::parse(origin).expect("test TURN URL"),
        weight: 1,
        max_conns: 0,
        backup: false,
        state: UpstreamPoolServerState::Ready,
        tls: UpstreamTlsConfig::default(),
      }],
      health_check: crate::config::TurnUpstreamPoolHealthCheckConfig {
        healthy_threshold: 1,
        unhealthy_threshold: 1,
        ..crate::config::TurnUpstreamPoolHealthCheckConfig::default()
      },
    }
  }

  #[test]
  fn compatible_snapshot_reuses_turn_server_runtime_state() {
    let config = pool("turn://127.0.0.1:3478");
    let previous = TurnPoolState::new(std::slice::from_ref(&config));
    previous.report_failure("turn", "stable");

    let replacement =
      TurnPoolState::new_with_previous(std::slice::from_ref(&config), Some(previous.as_ref()));

    let old_server = &previous.pools["turn"].servers[0];
    let replacement_server = &replacement.pools["turn"].servers[0];
    assert!(Arc::ptr_eq(old_server, replacement_server));
    assert!(
      replacement
        .select("turn", "127.0.0.1".parse().unwrap(), "client")
        .is_err(),
      "the failed health state must survive a compatible snapshot rebuild"
    );
  }

  #[test]
  fn changed_turn_server_origin_gets_fresh_runtime_state() {
    let previous_config = pool("turn://127.0.0.1:3478");
    let previous = TurnPoolState::new(std::slice::from_ref(&previous_config));
    previous.report_failure("turn", "stable");

    let replacement_config = pool("turn://127.0.0.1:3479");
    let replacement = TurnPoolState::new_with_previous(
      std::slice::from_ref(&replacement_config),
      Some(previous.as_ref()),
    );

    assert!(!Arc::ptr_eq(
      &previous.pools["turn"].servers[0],
      &replacement.pools["turn"].servers[0]
    ));
    assert!(
      replacement
        .select("turn", "127.0.0.1".parse().unwrap(), "client")
        .is_ok(),
      "a new origin must not inherit a failed health state"
    );
  }
}
