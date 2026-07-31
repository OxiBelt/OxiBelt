use std::time::Duration;

use crate::config::{CapacitySetting, Config};

use super::compio_direct_h1_budget;

fn config() -> Config {
  toml::from_str(include_str!("../../config/oxibelt.toml")).expect("example config parses")
}

#[test]
fn compio_budget_projects_existing_queue_and_connection_limits() {
  let mut config = config();
  config.runtime.workers.compio_direct_h1 = 4;
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(4);
  config.circuit_breakers.global.pending_queue_timeout_ms = 37;
  config.circuit_breakers.global.max_connections = CapacitySetting::Fixed(20);
  config.circuit_breakers.pool_defaults.max_connections = CapacitySetting::Fixed(7);

  let budget = compio_direct_h1_budget(&config).expect("fixed limits should resolve");

  assert_eq!(budget.worker_count, 4);
  assert_eq!(budget.queue_capacity_per_worker, 5);
  assert_eq!(budget.max_waiters, 4);
  assert_eq!(budget.queue_wait_timeout, Duration::from_millis(37));
  assert_eq!(budget.max_connections_global, 20);
  assert_eq!(budget.max_connections_per_origin, 7);
}

#[test]
fn compio_budget_keeps_physical_queues_bounded_when_waiting_is_disabled() {
  let mut config = config();
  config.runtime.workers.compio_direct_h1 = 3;
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  config.circuit_breakers.global.max_connections = CapacitySetting::Fixed(2);
  config.circuit_breakers.pool_defaults.max_connections = CapacitySetting::Fixed(8);

  let budget = compio_direct_h1_budget(&config).expect("zero waiters should remain valid");

  assert_eq!(budget.queue_capacity_per_worker, 1);
  assert_eq!(budget.max_waiters, 0);
  assert_eq!(budget.max_connections_global, 2);
  assert_eq!(budget.max_connections_per_origin, 2);
}

#[test]
fn compio_budget_handoff_covers_each_workers_share_of_active_operations() {
  let mut config = config();
  config.runtime.workers.compio_direct_h1 = 4;
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  config.circuit_breakers.global.max_connections = CapacitySetting::Fixed(120);

  let budget =
    compio_direct_h1_budget(&config).expect("the bounded operation share should resolve");

  assert_eq!(budget.queue_capacity_per_worker, 30);
  assert_eq!(budget.max_waiters, 0);
  assert_eq!(budget.max_connections_global, 120);
}

#[test]
fn compio_budget_rejects_invalid_or_overflowing_worker_projections() {
  let mut config = config();
  config.runtime.workers.compio_direct_h1 = 0;
  assert!(compio_direct_h1_budget(&config).is_err());

  config.runtime.workers.compio_direct_h1 = usize::MAX;
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(usize::MAX);
  let error = compio_direct_h1_budget(&config)
    .expect_err("impossible worker and queue allocations must fail closed");
  assert!(error.to_string().contains("internal resource safety limit"));
}

#[test]
fn compio_budget_rejects_impossible_fixed_queue_and_connection_limits() {
  let mut config = config();
  config.runtime.workers.compio_direct_h1 = 1;
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(usize::MAX);
  let queue_error =
    compio_direct_h1_budget(&config).expect_err("an impossible fixed queue must fail closed");
  assert!(queue_error.to_string().contains("queue"));

  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.max_connections = CapacitySetting::Fixed(usize::MAX);
  let connection_error =
    compio_direct_h1_budget(&config).expect_err("an impossible connection cap must fail closed");
  assert!(
    connection_error
      .to_string()
      .contains("global connection capacity")
  );
}

#[test]
fn compio_budget_counts_physical_queue_slots_and_waiters_together() {
  let mut config = config();
  config.runtime.workers.compio_direct_h1 = 1;
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(4_096);
  let error = compio_direct_h1_budget(&config)
    .expect_err("the combined physical queue and waiter population must fail closed");
  assert!(
    error.to_string().contains("combined capacity"),
    "unexpected error: {error}"
  );
}
