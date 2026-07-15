use std::sync::Arc;
use std::time::Duration;

use super::*;

#[test]
fn active_generation_filters_retired_failures() {
  let health = RuntimeHealth::default();
  let first = health.allocate_generation();
  let second = health.allocate_generation();
  health.activate_generation(first);
  health.set_subsystem_state(
    first,
    RuntimeSubsystem::Limits,
    RuntimeSubsystemState::Failed,
    true,
  );
  assert!(!health.is_ready());

  health.activate_generation(second);
  assert!(health.is_ready());
  assert_eq!(health.snapshot().status, RuntimeSubsystemState::Healthy);
}

#[test]
fn optional_degradation_does_not_fail_readiness() {
  let health = RuntimeHealth::default();
  let generation = health.allocate_generation();
  health.activate_generation(generation);
  health.set_task_state(
    generation,
    RuntimeTaskKind::MetricsListener,
    RuntimeTaskPolicy::RestartableOptional,
    RuntimeSubsystemState::Degraded,
  );
  assert!(health.is_ready());
  assert_eq!(health.snapshot().status, RuntimeSubsystemState::Degraded);
}

#[tokio::test(start_paused = true)]
async fn critical_task_restarts_unready_then_recovers() {
  let health = Arc::new(RuntimeHealth::default());
  let generation = health.allocate_generation();
  health.activate_generation(generation);
  let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
  let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel();
  let attempts = Arc::new(std::sync::atomic::AtomicU64::new(0));
  let task_attempts = attempts.clone();
  let task = spawn_supervised_task(
    health.clone(),
    generation,
    RuntimeTaskKind::PoolHealth,
    RuntimeTaskPolicy::RestartableCritical,
    shutdown_rx,
    fatal_tx,
    move |mut shutdown| {
      let task_attempts = task_attempts.clone();
      async move {
        let attempt = task_attempts.fetch_add(1, Ordering::Relaxed);
        if attempt == 0 {
          anyhow::bail!("injected task failure");
        }
        let _ = shutdown.changed().await;
        Ok(())
      }
    },
  );

  tokio::task::yield_now().await;
  assert!(!health.is_ready());
  tokio::time::advance(Duration::from_millis(100)).await;
  tokio::task::yield_now().await;
  assert!(!health.is_ready());
  tokio::time::advance(Duration::from_secs(5)).await;
  tokio::task::yield_now().await;
  assert!(health.is_ready());
  assert!(fatal_rx.try_recv().is_err());

  let _ = shutdown_tx.send(true);
  tokio::task::yield_now().await;
  task.await.expect("supervisor task should stop cleanly");
}
