use std::time::Duration;

use crate::config::{CapacitySetting, Config};

use super::CircuitBreakerRuntime;

fn config() -> Config {
  toml::from_str(include_str!("../../config/oxibelt.toml")).expect("example config parses")
}

async fn wait_for_queued(runtime: &CircuitBreakerRuntime, expected: usize) {
  let expected = format!(
    "oxibelt_circuit_breaker_queued{{scope_kind=\"global\",scope=\"global\",kind=\"upstream_request\"}} {expected}"
  );
  for _ in 0..64 {
    let mut metrics = String::new();
    runtime.append_prometheus(&mut metrics);
    if metrics.contains(&expected) {
      return;
    }
    tokio::task::yield_now().await;
  }
  let mut metrics = String::new();
  runtime.append_prometheus(&mut metrics);
  assert!(
    metrics.contains(&expected),
    "expected queued metric: {expected}"
  );
}

#[tokio::test(flavor = "current_thread")]
async fn dequeued_overlap_head_wakes_waiters_for_remaining_shared_capacity() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(2);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(3);
  config.circuit_breakers.global.pending_queue_timeout_ms = 1_000;
  config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(3);
  config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(3);
  config
    .circuit_breakers
    .route_defaults
    .pending_queue_timeout_ms = 1_000;
  let first_route = config.routes[0].name.clone();
  let mut second_route = config.routes[0].clone();
  second_route.name = "second-route".to_string();
  let second_route_name = second_route.name.clone();
  config.routes.push(second_route);
  let runtime = CircuitBreakerRuntime::new(&config);

  let first_held = runtime
    .admit_upstream_attempt(&second_route_name, None, None)
    .await
    .expect("first holder should occupy shared upstream capacity");
  let second_held = runtime
    .admit_upstream_attempt(&second_route_name, None, None)
    .await
    .expect("second holder should occupy shared upstream capacity");
  let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
  let older_runtime = runtime.clone();
  let older_route = first_route.clone();
  let older_waiter = tokio::spawn(async move {
    let lease = older_runtime
      .admit_upstream_attempt(&older_route, None, None)
      .await
      .expect("oldest overlapping waiter should be admitted");
    sender
      .send(lease)
      .expect("oldest waiter receiver should remain available");
  });
  wait_for_queued(&runtime, 1).await;

  drop(first_held);
  drop(second_held);
  let newer = tokio::time::timeout(
    Duration::from_millis(100),
    runtime.admit_upstream_attempt(&second_route_name, None, None),
  )
  .await
  .expect("a dequeued waiter must wake the next overlapping lane")
  .expect("newer route should use remaining shared capacity");
  let older = receiver
    .try_recv()
    .expect("older overlapping waiter must run before the newer route");

  drop(older);
  drop(newer);
  older_waiter
    .await
    .expect("older waiter task should not panic");
}
