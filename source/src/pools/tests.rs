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

#[test]
fn synthetic_upstreams_preserve_keepalive_pool_cap() {
  let mut pool = test_pool(LoadBalancingAlgorithm::RoundRobin);
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
fn round_robin_rotates_pool_servers() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::RoundRobin)], None);

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
  let state = PoolState::new(&[pool], None);

  let first = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(first.upstream_name, synthetic_upstream_name("app-pool", 0));

  let second = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(second.upstream_name, synthetic_upstream_name("app-pool", 1));
}

#[test]
fn retry_style_failure_releases_active_count_before_reselection() {
  let mut pool = test_pool(LoadBalancingAlgorithm::RoundRobin);
  pool.health_check.enabled = true;
  pool.health_check.unhealthy_threshold = 1;
  let state = PoolState::new(&[pool], None);

  let first = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/retry", None)
    .unwrap();
  assert_eq!(first.upstream_name, synthetic_upstream_name("app-pool", 0));
  assert_eq!(state.snapshot("app-pool").unwrap().servers[0].active, 1);

  state.report_failure(&first.upstream_name);
  drop(first);

  let after_failure = state.snapshot("app-pool").unwrap();
  assert_eq!(after_failure.servers[0].active, 0);
  assert!(!after_failure.servers[0].healthy);

  let second = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/retry", None)
    .unwrap();
  assert_eq!(second.upstream_name, synthetic_upstream_name("app-pool", 1));
  let after_reselect = state.snapshot("app-pool").unwrap();
  assert_eq!(after_reselect.servers[0].active, 0);
  assert_eq!(after_reselect.servers[1].active, 1);
}

#[test]
fn retry_reselection_excludes_failed_upstreams() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::RoundRobin)], None);

  let first = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/retry", None)
    .unwrap();
  assert_eq!(first.upstream_name, synthetic_upstream_name("app-pool", 0));
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
  assert_eq!(second.upstream_name, synthetic_upstream_name("app-pool", 1));
}

#[test]
fn retry_reselection_excludes_hash_target() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::Hash)], None);
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
  let mut pool = test_pool(LoadBalancingAlgorithm::RoundRobin);
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
fn runtime_weight_is_used_for_round_robin_selection() {
  let mut pool = test_pool(LoadBalancingAlgorithm::RoundRobin);
  pool.servers[0].weight = 2;
  pool.servers[1].weight = 1;
  let state = PoolState::new(&[pool], None);

  let first = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(first.upstream_name, synthetic_upstream_name("app-pool", 0));
  drop(first);

  let second = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(second.upstream_name, synthetic_upstream_name("app-pool", 0));
  drop(second);

  let third = state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(third.upstream_name, synthetic_upstream_name("app-pool", 1));
}

#[test]
fn random_selection_excludes_busy_capacity_limited_servers() {
  let mut pool = test_pool(LoadBalancingAlgorithm::Random);
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
fn hash_selection_is_stable_for_same_hash_key() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::Hash)], None);

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
  }
}

#[test]
fn ip_hash_selection_is_stable_for_same_client_ip() {
  let state = PoolState::new(&[test_pool(LoadBalancingAlgorithm::IpHash)], None);

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
  }
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
    "least_connections",
    "random",
    "hash",
    "ip_hash",
    "sticky_cookie",
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
  let mut pool = test_pool(LoadBalancingAlgorithm::LeastConn);
  pool.servers[0].max_conns = 1;
  pool.health_check.enabled = true;
  pool.health_check.healthy_threshold = 1;
  pool.health_check.unhealthy_threshold = 1;
  let first_state = PoolState::new(&[pool.clone()], Some(shared.clone()));
  let second_state = PoolState::new(&[pool], Some(shared));

  let first = first_state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(first.upstream_name, synthetic_upstream_name("app-pool", 0));

  let second = second_state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(second.upstream_name, synthetic_upstream_name("app-pool", 1));
  drop(second);
  drop(first);

  first_state.report_failure(&synthetic_upstream_name("app-pool", 0));
  let after_failure = second_state
    .select("app-pool", "203.0.113.10".parse().unwrap(), "/", None)
    .unwrap();
  assert_eq!(
    after_failure.upstream_name,
    synthetic_upstream_name("app-pool", 1)
  );
}
