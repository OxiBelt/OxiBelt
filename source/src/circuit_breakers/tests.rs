use std::sync::Arc;
use std::time::Duration;

use crate::config::{CapacitySetting, Config};

use super::{
  AdmissionLease, AdmissionRejectionReason, CircuitBreakerRuntime, CircuitOutcome,
  CircuitOutcomeFailure,
};

fn config() -> Config {
  toml::from_str(include_str!("../../config/oxibelt.toml")).expect("example config parses")
}

#[tokio::test]
async fn queue_full_releases_after_lease_drop() {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  let runtime = CircuitBreakerRuntime::new(&config);
  let first = runtime
    .admit_route_request(&config.routes[0].name, None)
    .await
    .expect("first request should be admitted");
  let rejection = runtime
    .admit_route_request(&config.routes[0].name, None)
    .await
    .expect_err("second request should be bounded");
  assert_eq!(rejection.reason, AdmissionRejectionReason::ActiveLimit);
  drop(first);
  runtime
    .admit_route_request(&config.routes[0].name, None)
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
  for _ in 0..16 {
    let mut metrics = String::new();
    runtime.append_prometheus(&mut metrics);
    if metrics.contains("scope_kind=\"global\",scope=\"global\",kind=\"request\"} 1") {
      break;
    }
    tokio::task::yield_now().await;
  }
  let mut metrics = String::new();
  runtime.append_prometheus(&mut metrics);
  assert!(metrics.contains("scope_kind=\"global\",scope=\"global\",kind=\"request\"} 1"));

  queued.abort();
  let _ = queued.await;

  let mut metrics = String::new();
  runtime.append_prometheus(&mut metrics);
  assert!(metrics.contains("scope_kind=\"global\",scope=\"global\",kind=\"request\"} 0"));
  drop(first);
  runtime
    .admit_route_request(&route, None)
    .await
    .expect("cancelled waiter must not block the next admission");
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
