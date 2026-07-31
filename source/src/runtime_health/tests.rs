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

#[test]
fn admin_mutation_cluster_health_uses_fixed_labels_and_fails_closed() {
  let health = RuntimeHealth::default();
  let generation = health.allocate_generation();
  health.activate_generation(generation);
  health.set_subsystem_state(
    generation,
    RuntimeSubsystem::AdminMutation,
    RuntimeSubsystemState::Failed,
    true,
  );
  health.set_task_state(
    generation,
    RuntimeTaskKind::AdminMutationCoordinator,
    RuntimeTaskPolicy::RestartableCritical,
    RuntimeSubsystemState::Failed,
  );

  assert!(!health.is_ready());
  assert_eq!(health.snapshot().failed_subsystems, vec!["admin_mutation"]);
  assert_eq!(
    health.snapshot().failed_tasks,
    vec!["admin_mutation_coordinator"]
  );

  let mut metrics = String::new();
  health.append_prometheus(&mut metrics);
  for label in [
    "admin_mutation_heartbeat",
    "admin_mutation_member",
    "admin_mutation_coordinator",
  ] {
    assert!(
      metrics.contains(&format!("task=\"{label}\"")),
      "runtime metrics should expose the fixed {label} task label"
    );
  }
  assert!(metrics.contains("subsystem=\"admin_mutation\""));
}

#[test]
fn compio_direct_h1_health_uses_fixed_labels_and_can_fail_readiness() {
  let health = RuntimeHealth::default();
  let generation = health.allocate_generation();
  health.activate_generation(generation);
  health.set_subsystem_state(
    generation,
    RuntimeSubsystem::CompioDirectH1,
    RuntimeSubsystemState::Failed,
    true,
  );
  health.set_task_state(
    generation,
    RuntimeTaskKind::CompioDirectH1Worker,
    RuntimeTaskPolicy::Contained,
    RuntimeSubsystemState::Failed,
  );

  assert!(!health.is_ready());
  assert_eq!(
    health.snapshot().failed_subsystems,
    vec!["compio_direct_h1"]
  );
  assert_eq!(
    health.snapshot().failed_tasks,
    vec!["compio_direct_h1_worker"]
  );

  let mut metrics = String::new();
  health.append_prometheus(&mut metrics);
  assert!(metrics.contains("subsystem=\"compio_direct_h1\""));
  assert!(metrics.contains("task=\"compio_direct_h1_worker\""));
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

#[tokio::test(start_paused = true)]
async fn panicked_critical_task_restarts_and_reports_stable_recovery() {
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
        if task_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
          panic!("injected supervised task panic");
        }
        let _ = shutdown.changed().await;
        Ok(())
      }
    },
  );

  wait_until(|| !health.is_ready()).await;
  assert_eq!(attempts.load(Ordering::Relaxed), 1);
  tokio::time::advance(Duration::from_millis(100)).await;
  wait_until(|| attempts.load(Ordering::Relaxed) == 2).await;
  assert!(!health.is_ready());
  tokio::time::advance(Duration::from_secs(5)).await;
  wait_until(|| health.is_ready()).await;
  assert!(fatal_rx.try_recv().is_err());

  let mut metrics = String::new();
  health.append_prometheus(&mut metrics);
  assert!(
    metrics.contains("oxibelt_runtime_panics_total{scope=\"background\",task=\"pool_health\"} 1")
  );
  assert!(
    metrics
      .contains("oxibelt_runtime_task_restarts_total{task=\"pool_health\",outcome=\"attempt\"} 1")
  );
  assert!(
    metrics
      .contains("oxibelt_runtime_task_restarts_total{task=\"pool_health\",outcome=\"stable\"} 1")
  );

  let _ = shutdown_tx.send(true);
  task.await.expect("supervisor task should stop cleanly");
}

#[tokio::test(start_paused = true)]
async fn optional_unexpected_return_degrades_then_recovers_without_failing_readiness() {
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
    RuntimeTaskKind::MetricsListener,
    RuntimeTaskPolicy::RestartableOptional,
    shutdown_rx,
    fatal_tx,
    move |mut shutdown| {
      let task_attempts = task_attempts.clone();
      async move {
        if task_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
          return Ok(());
        }
        let _ = shutdown.changed().await;
        Ok(())
      }
    },
  );

  wait_until(|| attempts.load(Ordering::Relaxed) == 1).await;
  wait_until(|| health.snapshot().status == RuntimeSubsystemState::Degraded).await;
  assert!(health.is_ready());
  tokio::time::advance(Duration::from_millis(100)).await;
  wait_until(|| attempts.load(Ordering::Relaxed) == 2).await;
  assert_eq!(health.snapshot().status, RuntimeSubsystemState::Degraded);
  tokio::time::advance(Duration::from_secs(5)).await;
  wait_until(|| health.snapshot().status == RuntimeSubsystemState::Healthy).await;
  assert!(fatal_rx.try_recv().is_err());

  let mut metrics = String::new();
  health.append_prometheus(&mut metrics);
  assert!(metrics.contains(
    "oxibelt_runtime_task_restarts_total{task=\"metrics_listener\",outcome=\"attempt\"} 1"
  ));
  assert!(metrics.contains(
    "oxibelt_runtime_task_restarts_total{task=\"metrics_listener\",outcome=\"stable\"} 1"
  ));

  let _ = shutdown_tx.send(true);
  task.await.expect("supervisor task should stop cleanly");
}

#[tokio::test(start_paused = true)]
async fn fatal_unexpected_return_fails_readiness_and_notifies_process_supervisor() {
  let health = Arc::new(RuntimeHealth::default());
  let generation = health.allocate_generation();
  health.activate_generation(generation);
  let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
  let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::unbounded_channel();
  let task = spawn_supervised_task(
    health.clone(),
    generation,
    RuntimeTaskKind::HealthListener,
    RuntimeTaskPolicy::Fatal,
    shutdown_rx,
    fatal_tx,
    |_| async { Ok(()) },
  );

  task
    .await
    .expect("fatal task supervisor should stop cleanly");
  assert!(!health.is_ready());
  let error = fatal_rx
    .recv()
    .await
    .expect("fatal task termination should notify the process supervisor");
  assert!(error.to_string().contains("fatal runtime task failed"));
  assert!(format!("{error:#}").contains("unexpected_return"));
}

#[tokio::test(start_paused = true)]
async fn shutdown_during_restart_backoff_prevents_replacement_task() {
  let health = Arc::new(RuntimeHealth::default());
  let generation = health.allocate_generation();
  health.activate_generation(generation);
  let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
  let (fatal_tx, _fatal_rx) = tokio::sync::mpsc::unbounded_channel();
  let attempts = Arc::new(std::sync::atomic::AtomicU64::new(0));
  let task_attempts = attempts.clone();
  let task = spawn_supervised_task(
    health.clone(),
    generation,
    RuntimeTaskKind::UpstreamDiscovery,
    RuntimeTaskPolicy::RestartableCritical,
    shutdown_rx,
    fatal_tx,
    move |_| {
      let task_attempts = task_attempts.clone();
      async move {
        task_attempts.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("injected task failure before shutdown")
      }
    },
  );

  wait_until(|| !health.is_ready()).await;
  assert_eq!(attempts.load(Ordering::Relaxed), 1);
  shutdown_tx
    .send(true)
    .expect("shutdown signal should remain connected");
  task.await.expect("supervisor should stop during backoff");
  tokio::time::advance(Duration::from_secs(60)).await;
  assert_eq!(
    attempts.load(Ordering::Relaxed),
    1,
    "shutdown must not start a replacement task"
  );

  let mut metrics = String::new();
  health.append_prometheus(&mut metrics);
  assert!(metrics.contains(
    "oxibelt_runtime_task_restarts_total{task=\"upstream_discovery\",outcome=\"attempt\"} 1"
  ));
  assert!(metrics.contains(
    "oxibelt_runtime_task_restarts_total{task=\"upstream_discovery\",outcome=\"stable\"} 0"
  ));
}

#[test]
fn retired_generation_task_failure_does_not_change_active_readiness() {
  let health = RuntimeHealth::default();
  let retired = health.allocate_generation();
  let active = health.allocate_generation();
  health.activate_generation(active);
  health.set_task_state(
    retired,
    RuntimeTaskKind::PoolHealth,
    RuntimeTaskPolicy::RestartableCritical,
    RuntimeSubsystemState::Failed,
  );

  assert!(health.is_ready());
  assert_eq!(health.snapshot().status, RuntimeSubsystemState::Healthy);
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
  for _ in 0..100 {
    if condition() {
      return;
    }
    tokio::task::yield_now().await;
  }
  panic!("condition did not settle after bounded task yields");
}
