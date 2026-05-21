use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::*;
use crate::config::{
  UpstreamPoolHealthCheckConfig, UpstreamPoolKeepaliveConfig, UpstreamPoolServerConfig,
  UpstreamPoolServerState,
};

fn test_pool(algorithm: LoadBalancingAlgorithm) -> UpstreamPoolConfig {
  UpstreamPoolConfig {
    name: "app-pool".to_string(),
    algorithm,
    hash_key: None,
    sticky_cookie: Default::default(),
    keepalive: UpstreamPoolKeepaliveConfig::default(),
    servers: vec![
      UpstreamPoolServerConfig {
        id: None,
        origin: "http://app-a.example".parse().unwrap(),
        weight: 1,
        max_conns: 0,
        backup: false,
        state: Default::default(),
        source: Default::default(),
      },
      UpstreamPoolServerConfig {
        id: None,
        origin: "http://app-b.example".parse().unwrap(),
        weight: 1,
        max_conns: 0,
        backup: false,
        state: Default::default(),
        source: Default::default(),
      },
    ],
    discovery: Vec::new(),
    health_check: UpstreamPoolHealthCheckConfig::default(),
  }
}

fn app_pool_runtime(state: &Arc<PoolState>) -> &Arc<PoolRuntime> {
  state.pools.get("app-pool").unwrap()
}

fn snapshot_server<'a>(
  snapshot: &'a PoolRuntimeSnapshot,
  upstream_name: &str,
) -> &'a PoolServerRuntimeSnapshot {
  snapshot
    .servers
    .iter()
    .find(|server| server.upstream_name == upstream_name)
    .expect("snapshot should contain selected server")
}

#[test]
fn synthetic_upstreams_preserve_keepalive_pool_cap() {
  let mut pool = test_pool(LoadBalancingAlgorithm::PowerOfTwoChoices);
  pool.keepalive.max_idle = 7;
  pool.keepalive.idle_timeout_ms = 12_345;

  let upstreams = PoolState::synthetic_upstreams(&[pool]);

  assert_eq!(upstreams.len(), 2);
  for upstream in upstreams {
    assert_eq!(upstream.pool_max_idle_per_host, 7);
    assert_eq!(upstream.idle_timeout_ms, 12_345);
  }
}

#[test]
fn default_power_of_two_choices_respects_capacity() {
  let mut pool = test_pool(LoadBalancingAlgorithm::PowerOfTwoChoices);
  pool.servers[0].max_conns = 1;
  pool.servers[1].max_conns = 1;
  let state = PoolState::new(&[pool], None);

  let first = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  let second = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_ne!(first.upstream_name, second.upstream_name);

  let error = match state.select("app-pool", "203.0.113.10".parse().unwrap(), "/", None) {
    Ok(selection) => panic!(
      "all capacity-limited servers should be busy, got {}",
      selection.upstream_name
    ),
    Err(error) => error,
  };
  assert!(error.to_string().contains("no available servers"));
}

#[test]
fn power_of_two_choices_ties_preserve_sample_distribution() {
  let state = PoolState::new(
    &[test_pool(LoadBalancingAlgorithm::PowerOfTwoChoices)],
    None,
  );
  let first = synthetic_upstream_name("app-pool", 0);
  let second = synthetic_upstream_name("app-pool", 1);
  let mut first_seen = false;
  let mut second_seen = false;

  for index in 0..16 {
    let selection = state
      .select(
        "app-pool",
        "203.0.113.10".parse().unwrap(),
        &format!("/request-{index}"),
        None,
      )
      .unwrap();
    first_seen |= selection.upstream_name == first;
    second_seen |= selection.upstream_name == second;
    drop(selection);
  }

  assert!(first_seen);
  assert!(second_seen);
}

#[test]
fn weighted_least_conn_excludes_busy_pool_server() {
  let mut pool = test_pool(LoadBalancingAlgorithm::WeightedLeastConn);
  pool.servers[0].max_conns = 1;
  pool.servers[1].max_conns = 1;
  let state = PoolState::new(&[pool], None);

  let first = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  let second = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();

  assert_ne!(first.upstream_name, second.upstream_name);
}

#[test]
fn retry_style_failure_releases_active_count_before_reselection() {
  let mut pool = test_pool(LoadBalancingAlgorithm::PowerOfTwoChoices);
  pool.health_check.enabled = true;
  pool.health_check.unhealthy_threshold = 1;
  let state = PoolState::new(&[pool], None);

  let first = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/retry", None)
    .unwrap();
  let failed_upstream = first.upstream_name.clone();
  assert_eq!(
    snapshot_server(&state.snapshot("app-pool").unwrap(), &failed_upstream).active,
    1
  );

  state.report_failure(&failed_upstream);
  drop(first);

  let after_failure = state.snapshot("app-pool").unwrap();
  let failed = snapshot_server(&after_failure, &failed_upstream);
  assert_eq!(failed.active, 0);
  assert!(!failed.healthy);

  let second = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/retry", None)
    .unwrap();
  assert_ne!(second.upstream_name, failed_upstream);
  let after_reselect = state.snapshot("app-pool").unwrap();
  assert_eq!(
    snapshot_server(&after_reselect, &second.upstream_name).active,
    1
  );
}

#[test]
fn retry_reselection_excludes_failed_upstreams() {
  let state = PoolState::new(
    &[test_pool(LoadBalancingAlgorithm::PowerOfTwoChoices)],
    None,
  );

  let first = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/retry", None)
    .unwrap();
  let excluded = vec![first.upstream_name.clone()];
  drop(first);

  let second = state
    .select_with_cookie_header_excluding(
      "app-pool",
      "203.0.113.10".parse().unwrap(),
      "/retry",
      None,
      None,
      &excluded,
    )
    .unwrap();
  assert!(!excluded.contains(&second.upstream_name));
}

#[test]
fn retry_reselection_excludes_rendezvous_hash_target() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::RendezvousHash)], None);
  let first = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "stable", None)
    .unwrap();
  let excluded = vec![first.upstream_name.clone()];
  drop(first);

  let second = state
    .select_with_cookie_header_excluding(
      "app-pool",
      "203.0.113.10".parse().unwrap(),
      "stable",
      None,
      None,
      &excluded,
    )
    .unwrap();
  assert!(!excluded.contains(&second.upstream_name));
}

#[test]
fn runtime_state_excludes_servers_from_new_selection() {
  let mut pool = test_pool(LoadBalancingAlgorithm::PowerOfTwoChoices);
  pool.servers[0].state = UpstreamPoolServerState::Drain;
  pool.servers[1].state = UpstreamPoolServerState::Maintenance;
  let state = PoolState::new(&[pool], None);

  let error = match state.select("app-pool", "203.0.113.10".parse().unwrap(), "/", None) {
    Ok(selection) => panic!(
      "drain and maintenance servers should not be selected, got {}",
      selection.upstream_name
    ),
    Err(error) => error,
  };
  assert!(error.to_string().contains("no available servers"));
}

#[test]
fn runtime_weight_is_used_for_candidate_sampling() {
  let mut pool = test_pool(LoadBalancingAlgorithm::PowerOfTwoChoices);
  pool.servers[0].weight = 3;
  pool.servers[1].weight = 1;
  let state = PoolState::new(&[pool], None);
  let runtime = app_pool_runtime(&state);

  let weighted = weighted_available(runtime, &HashSet::new());

  assert_eq!(weighted.len(), 4);
  assert_eq!(
    weighted
      .iter()
      .filter(|server| server.upstream_name == synthetic_upstream_name("app-pool", 0))
      .count(),
    3
  );
  assert_eq!(
    weighted
      .iter()
      .filter(|server| server.upstream_name == synthetic_upstream_name("app-pool", 1))
      .count(),
    1
  );
}

#[test]
fn weighted_least_conn_normalizes_active_count_by_weight() {
  let mut pool = test_pool(LoadBalancingAlgorithm::WeightedLeastConn);
  pool.servers[0].weight = 2;
  pool.servers[1].weight = 1;
  let state = PoolState::new(&[pool], None);
  let runtime = app_pool_runtime(&state);

  runtime.servers[0].active.store(1, Ordering::Relaxed);
  runtime.servers[1].active.store(1, Ordering::Relaxed);

  assert!(
    normalized_active_score(runtime, 0, &runtime.servers[0])
      < normalized_active_score(runtime, 1, &runtime.servers[1])
  );
}

#[test]
fn backup_servers_are_used_only_when_primary_servers_are_unavailable() {
  let mut pool = test_pool(LoadBalancingAlgorithm::WeightedLeastConn);
  pool.servers[1].backup = true;
  let state = PoolState::new(&[pool.clone()], None);

  let primary = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(
    primary.upstream_name,
    synthetic_upstream_name("app-pool", 0)
  );
  drop(primary);

  pool.servers[0].state = UpstreamPoolServerState::Maintenance;
  let fallback_state = PoolState::new(&[pool], None);
  let backup = fallback_state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(backup.upstream_name, synthetic_upstream_name("app-pool", 1));
}

#[test]
fn rendezvous_hash_selection_is_stable_for_same_hash_key() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::RendezvousHash)], None);

  let first = state
    .select(
      "app-pool",
      "203.0.113.10".parse().unwrap(),
      "stable-key",
      None,
    )
    .unwrap();
  let expected = first.upstream_name.clone();
  drop(first);

  for _ in 0..5 {
    let selection = state
      .select(
        "app-pool",
        "203.0.113.10".parse().unwrap(),
        "stable-key",
        None,
      )
      .unwrap();
    assert_eq!(selection.upstream_name, expected);
    drop(selection);
  }
}

#[test]
fn rendezvous_ip_hash_selection_is_stable_for_same_client_ip() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::RendezvousIpHash)], None);

  let first = state
    .select(
      "app-pool",
      "203.0.113.44".parse().unwrap(),
      "first-request-path",
      None,
    )
    .unwrap();
  let expected = first.upstream_name.clone();
  drop(first);

  for hash_key in ["other-path", "unrelated-key", "/"] {
    let selection = state
      .select("app-pool", "203.0.113.44".parse().unwrap(), hash_key, None)
      .unwrap();
    assert_eq!(selection.upstream_name, expected);
    drop(selection);
  }
}

#[test]
fn ewma_prefers_lower_latency_server() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::Ewma)], None);
  let fast = synthetic_upstream_name("app-pool", 0);
  let slow = synthetic_upstream_name("app-pool", 1);

  state.report_success_latency(&fast, 20);
  state.report_success_latency(&slow, 200);

  let selection = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(selection.upstream_name, fast);
}

#[test]
fn least_time_prefers_lower_latency_server_without_active_penalty() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::LeastTime)], None);
  let fast = synthetic_upstream_name("app-pool", 0);
  let slow = synthetic_upstream_name("app-pool", 1);

  state.report_success_latency(&fast, 30);
  state.report_success_latency(&slow, 300);

  let selection = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(selection.upstream_name, fast);
}

#[test]
fn ewma_failure_penalty_avoids_recently_failed_server() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::Ewma)], None);
  let failed = synthetic_upstream_name("app-pool", 0);
  let healthy = synthetic_upstream_name("app-pool", 1);

  state.report_success_latency(&failed, 20);
  state.report_success_latency(&healthy, 20);
  state.report_failure(&failed);

  let selection = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(selection.upstream_name, healthy);
}

#[test]
fn policy_override_strings_take_precedence_over_pool_algorithm() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::StickyCookie)], None);

  let selection = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert!(selection.sticky_cookie().is_some());
  drop(selection);

  for policy in [
    "power_of_two_choices",
    "weighted_least_conn",
    "rendezvous_hash",
    "rendezvous_ip_hash",
    "ewma",
    "least_time",
  ] {
    let selection = state
      .select(
        "app-pool",
        "203.0.113.10".parse().unwrap(),
        "override-key",
        Some(policy),
      )
      .unwrap();
    assert!(selection.upstream_name.starts_with("pool:app-pool:"));
    assert!(selection.sticky_cookie().is_none());
    drop(selection);
  }
}

#[test]
fn legacy_policy_override_strings_are_ignored() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::StickyCookie)], None);

  for policy in [
    "round_robin",
    "least_conn",
    "least_connections",
    "random",
    "hash",
    "ip_hash",
  ] {
    let selection = state
      .select(
        "app-pool",
        "203.0.113.10".parse().unwrap(),
        "override-key",
        Some(policy),
      )
      .unwrap();
    assert!(selection.sticky_cookie().is_some());
    drop(selection);
  }
}

#[test]
fn sticky_cookie_reuses_valid_server_cookie() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::StickyCookie)], None);

  let first = state
    .select_with_cookie_header("app-pool", "203.0.113.10".parse().unwrap(), "/", None, None)
    .unwrap();
  let expected = first.upstream_name.clone();
  let set_cookie = first
    .sticky_cookie()
    .expect("first sticky selection should issue cookie");
  let cookie_pair = set_cookie
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_string();
  drop(first);

  let cookie_header = HeaderValue::from_str(&cookie_pair).unwrap();
  let second = state
    .select_with_cookie_header(
      "app-pool",
      "203.0.113.10".parse().unwrap(),
      "/",
      None,
      Some(&cookie_header),
    )
    .unwrap();
  assert_eq!(second.upstream_name, expected);
  assert!(second.sticky_cookie().is_none());
}

#[test]
fn sticky_cookie_falls_back_when_cookie_target_is_excluded() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::StickyCookie)], None);

  let first = state
    .select_with_cookie_header("app-pool", "203.0.113.10".parse().unwrap(), "/", None, None)
    .unwrap();
  let excluded = vec![first.upstream_name.clone()];
  let set_cookie = first
    .sticky_cookie()
    .expect("first sticky selection should issue cookie");
  let cookie_pair = set_cookie
    .to_str()
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_string();
  drop(first);

  let cookie_header = HeaderValue::from_str(&cookie_pair).unwrap();
  let second = state
    .select_with_cookie_header_excluding(
      "app-pool",
      "203.0.113.10".parse().unwrap(),
      "/",
      None,
      Some(&cookie_header),
      &excluded,
    )
    .unwrap();

  assert!(!excluded.contains(&second.upstream_name));
  assert!(second.sticky_cookie().is_some());
}

#[test]
fn shared_state_coordinates_pool_active_counts_and_health() {
  let shared = SharedState::test_memory("pool-test");
  let mut pool = test_pool(LoadBalancingAlgorithm::WeightedLeastConn);
  pool.servers[0].max_conns = 1;
  pool.servers[1].max_conns = 1;
  pool.health_check.enabled = true;
  pool.health_check.healthy_threshold = 1;
  pool.health_check.unhealthy_threshold = 1;
  let first_state = PoolState::new(&[pool.clone()], Some(shared.clone()));
  let second_state = PoolState::new(&[pool], Some(shared));

  let first = first_state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  let first_upstream = first.upstream_name.clone();

  let second = second_state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_ne!(second.upstream_name, first_upstream);
  drop(second);
  drop(first);

  first_state.report_failure(&first_upstream);
  let after_failure = second_state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_ne!(after_failure.upstream_name, first_upstream);
}
