//! Upstream-pool selection algorithms.
//! Selection input is explicit so retries, sticky sessions, and exclusions agree.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::config::LoadBalancingAlgorithm;

use super::{
  PoolRuntime, PoolServerRuntime, active_count, effective_server_weight, server_capacity_available,
  server_config, server_healthy,
};

const SCORE_SCALE: u128 = 1_000;
const EWMA_ACTIVE_PENALTY_MS: u64 = 5;

pub(super) fn parse_policy_override(raw: &str) -> Option<LoadBalancingAlgorithm> {
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

pub(super) fn select_by_algorithm(
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

pub(super) fn build_sticky_fallback(
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

pub(super) fn weighted_available(
  pool: &Arc<PoolRuntime>,
  excluded_upstreams: &HashSet<&str>,
) -> Vec<Arc<PoolServerRuntime>> {
  let mut result = Vec::new();
  for (index, server) in available_candidates(pool, excluded_upstreams) {
    let weight = effective_server_weight(pool, index, &server);
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

pub(super) fn normalized_active_score(
  pool: &PoolRuntime,
  index: usize,
  server: &PoolServerRuntime,
) -> u128 {
  let weight = u128::from(effective_server_weight(pool, index, server).max(1));
  active_count(pool, server) as u128 * SCORE_SCALE / weight
}

fn rendezvous_score(
  pool: &PoolRuntime,
  index: usize,
  server: &PoolServerRuntime,
  key: &str,
) -> u128 {
  let hash = stable_hash64_pair(key, &server.server_id).max(1);
  u128::from(hash) * u128::from(effective_server_weight(pool, index, server).max(1))
}

fn ewma_score(
  pool: &PoolRuntime,
  index: usize,
  server: &PoolServerRuntime,
  include_active: bool,
) -> u128 {
  let weight = u128::from(effective_server_weight(pool, index, server).max(1));
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
