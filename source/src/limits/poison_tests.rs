use super::*;

#[test]
fn poisoned_connection_limit_state_fails_closed_and_changes_readiness() {
  let health = Arc::new(RuntimeHealth::default());
  let generation = health.allocate_generation();
  health.activate_generation(generation);
  let state = LimitState::new_with_health(None, health.clone());
  let poison_target = state.clone();
  let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
    let _guard = poison_target.connections.lock().unwrap();
    panic!("injected connection-limit lock poison");
  }));
  assert!(poisoned.is_err());

  let result = state.acquire_global_connection(&LimitsConfig::default());
  assert_eq!(result.err(), Some(StatusCode::SERVICE_UNAVAILABLE));
  assert!(!health.is_ready());
  assert_eq!(
    health.snapshot().failed_subsystems,
    vec![RuntimeSubsystem::Limits.as_str()]
  );
}
