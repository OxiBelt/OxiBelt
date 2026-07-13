use crate::config::{
  CapacitySetting, CircuitBreakerPriorityClassConfig, Config, PriorityClass,
  PriorityRejectionPolicy,
};

use super::{AdmissionRejectionReason, CircuitBreakerRuntime};

fn config() -> Config {
  toml::from_str(include_str!("../../config/oxibelt.toml")).expect("example config parses")
}

fn reserved_security_callback() -> CircuitBreakerPriorityClassConfig {
  CircuitBreakerPriorityClassConfig {
    name: PriorityClass::SecurityCallback,
    reserved_requests: Some(3),
    max_share: Some(0.50),
    max_pending_requests: Some(CapacitySetting::Fixed(0)),
    pending_queue_timeout_ms: None,
    rejection_policy: Some(PriorityRejectionPolicy::Reject),
  }
}

fn runtime_with_reserved_security_callback() -> std::sync::Arc<CircuitBreakerRuntime> {
  let mut config = config();
  config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(10);
  config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
  config
    .circuit_breakers
    .priority
    .classes
    .push(reserved_security_callback());
  CircuitBreakerRuntime::new(&config)
}

#[tokio::test]
async fn same_class_shared_traffic_cannot_starve_reserved_slots() {
  let runtime = runtime_with_reserved_security_callback();
  let first_shared = runtime
    .admit_priority_global_request(PriorityClass::SecurityCallback, false, None)
    .await
    .expect("the class may use its non-reserved shared capacity");
  let second_shared = runtime
    .admit_priority_global_request(PriorityClass::SecurityCallback, false, None)
    .await
    .expect("the class may use its remaining non-reserved shared capacity");
  assert_eq!(
    runtime
      .admit_priority_global_request(PriorityClass::SecurityCallback, false, None)
      .await
      .expect_err("same-class shared traffic must not consume reserved capacity")
      .reason,
    AdmissionRejectionReason::ActiveLimit
  );

  let mut reserved = Vec::new();
  for _ in 0..3 {
    reserved.push(
      runtime
        .admit_priority_global_request(PriorityClass::SecurityCallback, true, None)
        .await
        .expect("trusted traffic must retain its configured reservation"),
    );
  }

  let mut metrics = String::new();
  runtime.append_prometheus(&mut metrics);
  assert!(metrics.contains(
    "oxibelt_circuit_breaker_priority_active{priority=\"security_callback\",capacity=\"shared\"} 2"
  ));
  assert!(metrics.contains(
    "oxibelt_circuit_breaker_priority_active{priority=\"security_callback\",capacity=\"reserved\"} 3"
  ));
  assert!(metrics.contains(
    "oxibelt_circuit_breaker_priority_capacity{priority=\"security_callback\",capacity=\"maximum\"} 5"
  ));
  assert!(metrics.contains(
    "oxibelt_circuit_breaker_priority_rejections_total{priority=\"security_callback\",reason=\"share_limit\"} 1"
  ));

  drop(reserved);
  drop(second_shared);
  drop(first_shared);
}

#[tokio::test]
async fn eligible_traffic_falls_back_to_class_shared_capacity_after_reservations_fill() {
  let runtime = runtime_with_reserved_security_callback();
  let mut reservations = Vec::new();
  for _ in 0..3 {
    reservations.push(
      runtime
        .admit_priority_global_request(PriorityClass::SecurityCallback, true, None)
        .await
        .expect("trusted traffic should use each reserved slot"),
    );
  }

  let first_shared = runtime
    .admit_priority_global_request(PriorityClass::SecurityCallback, true, None)
    .await
    .expect("eligible traffic may fall back to class shared capacity");
  let second_shared = runtime
    .admit_priority_global_request(PriorityClass::SecurityCallback, true, None)
    .await
    .expect("eligible traffic may use the remaining class shared capacity");
  assert_eq!(
    runtime
      .admit_priority_global_request(PriorityClass::SecurityCallback, true, None)
      .await
      .expect_err("the total class max_share cap must remain enforced")
      .reason,
    AdmissionRejectionReason::ActiveLimit
  );

  drop(second_shared);
  drop(first_shared);
  drop(reservations);
}
