//! Pool projection coverage for per-server TLS policy.

use super::PoolState;
use super::tests::test_pool;
use crate::config::{LoadBalancingAlgorithm, UpstreamTlsTrust};

#[test]
fn synthetic_forwarding_and_health_clients_preserve_server_tls_policy() {
  let mut pool = test_pool(LoadBalancingAlgorithm::PowerOfTwoChoices);
  pool.servers.truncate(1);
  pool.servers[0].origin = "https://app-a.default.svc.cluster.local:8443/"
    .parse()
    .unwrap();
  pool.servers[0].tls.server_name = Some("backend.example.test".to_string());
  pool.servers[0].tls.trust = UpstreamTlsTrust::System;

  let forwarding = PoolState::synthetic_upstreams(&[pool.clone()]);
  let health = PoolState::health_check_upstreams(&[pool]);

  assert_eq!(
    forwarding[0].tls.server_name.as_deref(),
    Some("backend.example.test")
  );
  assert_eq!(forwarding[0].tls.trust, UpstreamTlsTrust::System);
  assert_eq!(
    health[0].tls.server_name.as_deref(),
    Some("backend.example.test")
  );
  assert_eq!(health[0].tls.trust, UpstreamTlsTrust::System);
}
