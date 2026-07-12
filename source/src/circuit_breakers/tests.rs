use std::sync::Arc;
use std::time::Duration;

use crate::config::{
  CapacitySetting, CircuitBreakerPriorityClassConfig, Config, PriorityClass,
  PriorityRejectionPolicy,
};

use super::{
  AdmissionLease, AdmissionRejectionReason, CircuitBreakerRuntime, CircuitOutcome,
  CircuitOutcomeFailure,
};

fn config() -> Config {
  toml::from_str(include_str!("../../config/oxibelt.toml")).expect("example config parses")
}

async fn wait_for_queued(
  runtime: &CircuitBreakerRuntime,
  scope_kind: &str,
  scope: &str,
  kind: &str,
  expected: usize,
) {
  let expected = format!(
    "oxibelt_circuit_breaker_queued{{scope_kind=\"{scope_kind}\",scope=\"{scope}\",kind=\"{kind}\"}} {expected}"
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

async fn wait_for_priority_queued(
  runtime: &CircuitBreakerRuntime,
  priority: PriorityClass,
  expected: usize,
) {
  let expected = format!(
    "oxibelt_circuit_breaker_priority_queued{{priority=\"{}\"}} {expected}",
    priority.as_str()
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
    "expected priority queued metric: {expected}"
  );
}

#[tokio::test]
async fn queue_full_releases_after_lease_drop() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  let route = config.routes[0].name.clone();
  let mut other_route = config.routes[0].clone();
  other_route.name = "other-route".to_string();
  let other_route_name = other_route.name.clone();
  config.routes.push(other_route);
  let runtime = CircuitBreakerRuntime::new(&config);
  let first = runtime
    .admit_route_request(&route, None)
    .await
    .expect("first request should be admitted");
  let rejection = runtime
    .admit_route_request(&other_route_name, None)
    .await
    .expect_err("global capacity should bound an independent route");
  assert_eq!(rejection.reason, AdmissionRejectionReason::ActiveLimit);
  drop(first);
  runtime
    .admit_route_request(&other_route_name, None)
    .await
    .expect("released request lease should restore capacity");
}

#[tokio::test]
async fn bounded_queue_times_out_and_releases_its_waiter() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.pending_queue_timeout_ms = 1;
  let route = config.routes[0].name.clone();
  let runtime = CircuitBreakerRuntime::new(&config);
  let first = runtime
    .admit_route_request(&route, None)
    .await
    .expect("first request should be admitted");
  let rejection = runtime
    .admit_route_request(&route, None)
    .await
    .expect_err("bounded waiter should time out");
  assert_eq!(rejection.reason, AdmissionRejectionReason::QueueTimeout);
  drop(first);
  runtime
    .admit_route_request(&route, None)
    .await
    .expect("timed out waiter must not leak capacity");
}

#[tokio::test]
async fn cancelling_a_queued_admission_removes_its_waiter() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.pending_queue_timeout_ms = 1_000;
  let route = config.routes[0].name.clone();
  let runtime = CircuitBreakerRuntime::new(&config);
  let first = runtime
    .admit_route_request(&route, None)
    .await
    .expect("first request should occupy the only slot");
  let queued_runtime = runtime.clone();
  let queued_route = route.clone();
  let queued = tokio::spawn(async move {
    queued_runtime
      .admit_route_request(&queued_route, None)
      .await
  });
  wait_for_queued(&runtime, "global", "global", "request", 1).await;

  queued.abort();
  let _ = queued.await;

  wait_for_queued(&runtime, "global", "global", "request", 0).await;
  drop(first);
  runtime
    .admit_route_request(&route, None)
    .await
    .expect("cancelled waiter must not block the next admission");
}

#[tokio::test]
async fn blocked_route_waiter_does_not_block_spare_global_admission() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(4);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(4);
  config.circuit_breakers.global.pending_queue_timeout_ms = 1_000;
  config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(2);
  config
    .circuit_breakers
    .route_defaults
    .pending_queue_timeout_ms = 1_000;
  let route = config.routes[0].name.clone();
  let runtime = CircuitBreakerRuntime::new(&config);

  let _first_global = runtime
    .admit_global_request(None)
    .await
    .expect("first global request should be admitted");
  let _first_route = runtime
    .admit_route_scope_request(&route, None)
    .await
    .expect("first route request should be admitted");
  let _queued_global = runtime
    .admit_global_request(None)
    .await
    .expect("second global request should be admitted");
  let queued_runtime = runtime.clone();
  let queued_route = route.clone();
  let queued = tokio::spawn(async move {
    queued_runtime
      .admit_route_scope_request(&queued_route, None)
      .await
  });
  wait_for_queued(&runtime, "route", &route, "request", 1).await;

  let spare_global = tokio::time::timeout(
    Duration::from_millis(50),
    runtime.admit_global_request(None),
  )
  .await
  .expect("a route-only waiter must not block spare global capacity")
  .expect("spare global capacity should be admitted");

  drop(spare_global);
  wait_for_queued(&runtime, "route", &route, "request", 1).await;
  queued.abort();
  let _ = queued.await;
  wait_for_queued(&runtime, "route", &route, "request", 0).await;
}

#[tokio::test]
async fn blocked_request_waiter_does_not_block_later_upstream_admission() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(4);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(4);
  config.circuit_breakers.global.pending_queue_timeout_ms = 1_000;
  config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(2);
  config
    .circuit_breakers
    .route_defaults
    .pending_queue_timeout_ms = 1_000;
  let route = config.routes[0].name.clone();
  let runtime = CircuitBreakerRuntime::new(&config);

  let _first_global = runtime
    .admit_global_request(None)
    .await
    .expect("first global request should be admitted");
  let _first_route = runtime
    .admit_route_scope_request(&route, None)
    .await
    .expect("first route request should be admitted");
  let _queued_global = runtime
    .admit_global_request(None)
    .await
    .expect("second global request should be admitted");
  let queued_runtime = runtime.clone();
  let queued_route = route.clone();
  let queued = tokio::spawn(async move {
    queued_runtime
      .admit_route_scope_request(&queued_route, None)
      .await
  });
  wait_for_queued(&runtime, "route", &route, "request", 1).await;

  let upstream = tokio::time::timeout(
    Duration::from_millis(50),
    runtime.admit_upstream_attempt(&route, None, None),
  )
  .await
  .expect("a blocked route request must not block later upstream admission")
  .expect("available upstream capacity should be admitted");

  drop(upstream);
  queued.abort();
  let _ = queued.await;
}

#[tokio::test]
async fn blocked_route_waiter_does_not_block_another_route() {
  let mut config = config();
  config.circuit_breakers.route_defaults.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(2);
  config
    .circuit_breakers
    .route_defaults
    .pending_queue_timeout_ms = 1_000;
  let route = config.routes[0].name.clone();
  let mut other_route = config.routes[0].clone();
  other_route.name = "independent-route".to_string();
  let other_route_name = other_route.name.clone();
  config.routes.push(other_route);
  let runtime = CircuitBreakerRuntime::new(&config);

  let _first = runtime
    .admit_route_scope_request(&route, None)
    .await
    .expect("first route request should be admitted");
  let queued_runtime = runtime.clone();
  let queued_route = route.clone();
  let queued = tokio::spawn(async move {
    queued_runtime
      .admit_route_scope_request(&queued_route, None)
      .await
  });
  wait_for_queued(&runtime, "route", &route, "request", 1).await;

  let independent = tokio::time::timeout(
    Duration::from_millis(50),
    runtime.admit_route_scope_request(&other_route_name, None),
  )
  .await
  .expect("a blocked route must not block an independent route")
  .expect("independent route capacity should be admitted");

  drop(independent);
  queued.abort();
  let _ = queued.await;
}

#[tokio::test]
async fn compatible_waiters_remain_fifo() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(2);
  config.circuit_breakers.global.pending_queue_timeout_ms = 1_000;
  let runtime = CircuitBreakerRuntime::new(&config);
  let first = runtime
    .admit_global_request(None)
    .await
    .expect("first global request should be admitted");
  let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

  let first_runtime = runtime.clone();
  let first_sender = sender.clone();
  let first_waiter = tokio::spawn(async move {
    let lease = first_runtime
      .admit_global_request(None)
      .await
      .expect("first queued waiter should be admitted");
    first_sender
      .send(("first", lease))
      .expect("first queued waiter receiver should remain available");
  });
  wait_for_queued(&runtime, "global", "global", "request", 1).await;

  let second_runtime = runtime.clone();
  let second_waiter = tokio::spawn(async move {
    let lease = second_runtime
      .admit_global_request(None)
      .await
      .expect("second queued waiter should be admitted");
    sender
      .send(("second", lease))
      .expect("second queued waiter receiver should remain available");
  });
  wait_for_queued(&runtime, "global", "global", "request", 2).await;

  drop(first);
  let (name, first_lease) = tokio::time::timeout(Duration::from_millis(50), receiver.recv())
    .await
    .expect("a compatible queued waiter should be notified")
    .expect("first queued waiter should send its lease");
  assert_eq!(name, "first", "compatible waiters must remain FIFO");
  drop(first_lease);

  let (name, second_lease) = tokio::time::timeout(Duration::from_millis(50), receiver.recv())
    .await
    .expect("the second waiter should be notified after the first releases")
    .expect("second queued waiter should send its lease");
  assert_eq!(name, "second");
  drop(second_lease);
  first_waiter
    .await
    .expect("first waiter task should not panic");
  second_waiter
    .await
    .expect("second waiter task should not panic");
}

#[tokio::test]
async fn queue_timeout_is_not_extended_by_notifications() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.pending_queue_timeout_ms = 40;
  let runtime = CircuitBreakerRuntime::new(&config);
  let first = runtime
    .admit_global_request(None)
    .await
    .expect("first global request should be admitted");
  let queued_runtime = runtime.clone();
  let queued = tokio::spawn(async move { queued_runtime.admit_global_request(None).await });
  wait_for_queued(&runtime, "global", "global", "request", 1).await;

  let notifier_runtime = runtime.clone();
  let notifier_config = config.clone();
  let notifier = tokio::spawn(async move {
    loop {
      notifier_runtime.configure(&notifier_config);
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
  });
  let rejection = tokio::time::timeout(Duration::from_millis(150), queued)
    .await
    .expect("queue timeout must not restart after notifications")
    .expect("queued admission task should not panic")
    .expect_err("waiter should time out while capacity remains occupied");
  assert_eq!(rejection.reason, AdmissionRejectionReason::QueueTimeout);

  notifier.abort();
  let _ = notifier.await;
  drop(first);
}

#[tokio::test]
async fn background_priority_cannot_consume_all_global_capacity() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(4);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  let runtime = CircuitBreakerRuntime::new(&config);

  let first_background = runtime
    .admit_priority_global_request(PriorityClass::Background, false, None)
    .await
    .expect("first background request should fit its class cap");
  let second_background = runtime
    .admit_priority_global_request(PriorityClass::Background, false, None)
    .await
    .expect("second background request should fit its class cap");
  assert_eq!(
    runtime
      .admit_priority_global_request(PriorityClass::Background, false, None)
      .await
      .expect_err("background must not use more than half of global capacity")
      .reason,
    AdmissionRejectionReason::ActiveLimit
  );

  let first_default = runtime
    .admit_priority_global_request(PriorityClass::Default, false, None)
    .await
    .expect("shared capacity should remain available to default traffic");
  let second_default = runtime
    .admit_priority_global_request(PriorityClass::Default, false, None)
    .await
    .expect("background traffic must not consume the final shared slot");
  let mut metrics = String::new();
  runtime.append_prometheus(&mut metrics);
  assert!(metrics.contains(
    "oxibelt_circuit_breaker_priority_rejections_total{priority=\"background\",reason=\"share_limit\"} 1"
  ));

  drop(first_background);
  drop(second_background);
  drop(first_default);
  drop(second_default);
}

#[tokio::test]
async fn public_routes_cannot_claim_an_authenticated_request_reservation() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(4);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  config
    .circuit_breakers
    .priority
    .classes
    .push(CircuitBreakerPriorityClassConfig {
      name: PriorityClass::SecurityCallback,
      reserved_requests: Some(1),
      max_share: Some(1.0),
      max_pending_requests: Some(CapacitySetting::Fixed(0)),
      pending_queue_timeout_ms: None,
      rejection_policy: Some(PriorityRejectionPolicy::Reject),
    });
  let runtime = CircuitBreakerRuntime::new(&config);

  let first_default = runtime
    .admit_priority_global_request(PriorityClass::Default, false, None)
    .await
    .expect("first shared slot should be admitted");
  let second_default = runtime
    .admit_priority_global_request(PriorityClass::Default, false, None)
    .await
    .expect("second shared slot should be admitted");
  let third_default = runtime
    .admit_priority_global_request(PriorityClass::Default, false, None)
    .await
    .expect("third shared slot should be admitted");

  assert_eq!(
    runtime
      .admit_priority_global_request(PriorityClass::SecurityCallback, false, None)
      .await
      .expect_err("unauthenticated public traffic must not borrow a reserved slot")
      .reason,
    AdmissionRejectionReason::ActiveLimit
  );
  let trusted = runtime
    .admit_priority_global_request(PriorityClass::SecurityCallback, true, None)
    .await
    .expect("trusted classification should use the strict reservation");

  let mut metrics = String::new();
  runtime.append_prometheus(&mut metrics);
  assert!(metrics.contains(
    "oxibelt_circuit_breaker_priority_capacity{priority=\"security_callback\",capacity=\"reserved\"} 1"
  ));
  assert!(metrics.contains(
    "oxibelt_circuit_breaker_priority_active{priority=\"security_callback\",capacity=\"reserved\"} 1"
  ));

  drop(first_default);
  drop(second_default);
  drop(third_default);
  drop(trusted);
}

#[tokio::test]
async fn shared_priority_waiters_remain_fifo_across_classes() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(2);
  config.circuit_breakers.global.pending_queue_timeout_ms = 1_000;
  let runtime = CircuitBreakerRuntime::new(&config);
  let first = runtime
    .admit_priority_global_request(PriorityClass::Default, false, None)
    .await
    .expect("first request should occupy global capacity");
  let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

  let interactive_runtime = runtime.clone();
  let interactive_sender = sender.clone();
  let interactive_waiter = tokio::spawn(async move {
    let lease = interactive_runtime
      .admit_priority_global_request(PriorityClass::Interactive, false, None)
      .await
      .expect("interactive waiter should be admitted after release");
    interactive_sender
      .send(("interactive", lease))
      .expect("interactive receiver should remain available");
  });
  wait_for_priority_queued(&runtime, PriorityClass::Interactive, 1).await;

  let default_runtime = runtime.clone();
  let default_waiter = tokio::spawn(async move {
    let lease = default_runtime
      .admit_priority_global_request(PriorityClass::Default, false, None)
      .await
      .expect("default waiter should be admitted after the older waiter releases");
    sender
      .send(("default", lease))
      .expect("default receiver should remain available");
  });
  wait_for_priority_queued(&runtime, PriorityClass::Default, 1).await;

  drop(first);
  let (name, interactive_lease) = tokio::time::timeout(Duration::from_millis(50), receiver.recv())
    .await
    .expect("one priority waiter should be admitted")
    .expect("interactive waiter should send its lease");
  assert_eq!(
    name, "interactive",
    "older compatible priority work must progress first"
  );
  drop(interactive_lease);

  let (name, default_lease) = tokio::time::timeout(Duration::from_millis(50), receiver.recv())
    .await
    .expect("the next priority waiter should be admitted")
    .expect("default waiter should send its lease");
  assert_eq!(name, "default");
  drop(default_lease);
  interactive_waiter
    .await
    .expect("interactive waiter task should not panic");
  default_waiter
    .await
    .expect("default waiter task should not panic");
}

#[tokio::test]
async fn cancelling_a_priority_waiter_releases_its_class_queue_slot() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.pending_queue_timeout_ms = 1_000;
  let runtime = CircuitBreakerRuntime::new(&config);
  let first = runtime
    .admit_priority_global_request(PriorityClass::Default, false, None)
    .await
    .expect("first request should occupy global capacity");
  let queued_runtime = runtime.clone();
  let queued = tokio::spawn(async move {
    queued_runtime
      .admit_priority_global_request(PriorityClass::Interactive, false, None)
      .await
  });
  wait_for_priority_queued(&runtime, PriorityClass::Interactive, 1).await;

  queued.abort();
  let _ = queued.await;
  wait_for_priority_queued(&runtime, PriorityClass::Interactive, 0).await;
  drop(first);
  runtime
    .admit_priority_global_request(PriorityClass::Interactive, false, None)
    .await
    .expect("cancelled priority waiter must not leak global or class capacity");
}

#[tokio::test]
async fn upstream_stream_limit_is_held_until_its_lease_drops() {
  let mut config = config();
  config.circuit_breakers.global.max_streams = CapacitySetting::Fixed(2);
  config.circuit_breakers.route_defaults.max_streams = CapacitySetting::Fixed(1);
  config.circuit_breakers.route_defaults.max_pending_requests = CapacitySetting::Fixed(0);
  let route = config.routes[0].name.clone();
  let runtime = CircuitBreakerRuntime::new(&config);
  let first = runtime
    .admit_upstream_stream(&route, None, None)
    .await
    .expect("first stream should be admitted");
  assert_eq!(
    runtime
      .admit_upstream_stream(&route, None, None)
      .await
      .expect_err("route stream limit should reject the second stream")
      .reason,
    AdmissionRejectionReason::ActiveLimit
  );
  drop(first);
  runtime
    .admit_upstream_stream(&route, None, None)
    .await
    .expect("dropped stream lease should restore route capacity");
}

#[tokio::test]
async fn failure_circuit_opens_and_recovers_through_probe() {
  let mut config = config();
  config.circuit_breakers.failure.consecutive_failures = 1;
  config.circuit_breakers.failure.minimum_requests = 100;
  config.circuit_breakers.failure.open_timeout_ms = 1;
  config.circuit_breakers.failure.max_open_timeout_ms = 1;
  config.circuit_breakers.failure.half_open_successes = 1;
  let route = config.routes[0].name.clone();
  let runtime = CircuitBreakerRuntime::new(&config);
  let mut first = runtime
    .admit_upstream_attempt(&route, None, None)
    .await
    .expect("initial request should be admitted");
  first.record_outcome(CircuitOutcome::Failure(CircuitOutcomeFailure::ConnectError));
  drop(first);
  assert_eq!(
    runtime
      .admit_upstream_attempt(&route, None, None)
      .await
      .expect_err("open circuit must reject")
      .reason,
    AdmissionRejectionReason::CircuitOpen
  );
  tokio::time::sleep(Duration::from_millis(3)).await;
  let mut probe = runtime
    .admit_upstream_attempt(&route, None, None)
    .await
    .expect("half-open probe should be admitted");
  probe.record_outcome(CircuitOutcome::Success);
  drop(probe);
  runtime
    .admit_upstream_attempt(&route, None, None)
    .await
    .expect("successful probe should close circuit");
}

#[test]
fn disabled_lease_is_send_sync() {
  fn assert_send_sync<T: Send + Sync>() {}
  assert_send_sync::<AdmissionLease>();
  let _ = Arc::new(CircuitBreakerRuntime::new(&config()));
}
