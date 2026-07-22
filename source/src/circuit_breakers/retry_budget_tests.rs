use crate::config::{CapacitySetting, Config, UpstreamPoolConfig};

use super::{AdmissionRejectionReason, CircuitBreakerRuntime};

fn config() -> Config {
  toml::from_str(include_str!("../../config/oxibelt.toml")).expect("example config parses")
}

fn assert_metric(metrics: &str, expected: &str) {
  assert!(
    metrics.lines().any(|line| line == expected),
    "expected metric line `{expected}` in:\n{metrics}"
  );
}

#[tokio::test]
async fn retry_budget_rejections_preserve_the_active_lease_and_metrics() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(16);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(16);
  config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(0);
  config.circuit_breakers.pool_defaults.max_active_requests = CapacitySetting::Fixed(16);
  config.circuit_breakers.pool_defaults.max_pending_requests = CapacitySetting::Fixed(0);
  config.circuit_breakers.retry_budget.min_concurrency = 1;
  config.circuit_breakers.retry_budget.max_concurrency = CapacitySetting::Fixed(1);
  config.circuit_breakers.retry_budget.max_queue = CapacitySetting::Fixed(0);

  let route = config.routes[0].name.clone();
  let pool = "retry-budget-test-pool";
  config.upstream_pools.push(
    toml::from_str::<UpstreamPoolConfig>("name = \"retry-budget-test-pool\"")
      .expect("test upstream pool parses"),
  );
  let runtime = CircuitBreakerRuntime::new(&config);

  let active_retry = runtime
    .admit_retry_attempt(&route, Some(pool), None, 1.0)
    .await
    .expect("the first retry should consume the sole retry-budget slot");
  for _ in 0..15 {
    let rejection = runtime
      .admit_retry_attempt(&route, Some(pool), None, 1.0)
      .await
      .expect_err("an excess retry should be rejected immediately");
    assert_eq!(rejection.reason, AdmissionRejectionReason::RetryBudget);
  }

  let mut metrics = String::new();
  runtime.append_prometheus(&mut metrics);
  assert_metric(
    &metrics,
    "oxibelt_circuit_breaker_active{scope_kind=\"global\",scope=\"global\",kind=\"retry\"} 1",
  );
  assert_metric(
    &metrics,
    "oxibelt_circuit_breaker_queued{scope_kind=\"global\",scope=\"global\",kind=\"retry\"} 0",
  );
  assert_metric(
    &metrics,
    "oxibelt_upstream_attempts_total{kind=\"retry\"} 1",
  );
  assert_metric(
    &metrics,
    "oxibelt_circuit_breaker_rejections_total{reason=\"retry_budget\"} 15",
  );

  drop(active_retry);
  metrics.clear();
  runtime.append_prometheus(&mut metrics);
  assert_metric(
    &metrics,
    "oxibelt_circuit_breaker_active{scope_kind=\"global\",scope=\"global\",kind=\"retry\"} 0",
  );
}
