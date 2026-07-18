use super::*;

fn actor(name: &str) -> AdminActor {
  AdminActor {
    name: name.to_string(),
    principal: name.to_string(),
    subject: format!("{name}@example.test"),
    groups: Vec::new(),
  }
}

fn config() -> AdminOperationsConfig {
  AdminOperationsConfig {
    max_running: 1,
    max_queued: 1,
    max_stored: 2,
    event_buffer: 4,
    retention_seconds: 60,
    ..AdminOperationsConfig::default()
  }
}

#[test]
fn unprepared_auto_runtime_reports_visible_ephemeral_fallback() {
  let runtime = AdminOperationRuntime::new(config());
  assert_eq!(
    runtime.persistence_status(),
    serde_json::json!({
      "configured": "auto",
      "effective": "ephemeral",
      "fallback_reason": "prerequisites_unavailable",
    })
  );
}

async fn wait_for_terminal(runtime: &AdminOperationRuntime, id: &str) -> AdminOperationSnapshot {
  for _ in 0..100 {
    let snapshot = runtime
      .get(id)
      .await
      .expect("operation store should be available")
      .expect("operation should exist");
    if snapshot.state.is_terminal() {
      return snapshot;
    }
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
  }
  panic!("operation did not finish");
}

#[tokio::test]
async fn queue_capacity_is_enforced() {
  let mut config = config();
  config.max_running = 0;
  config.max_queued = 1;
  let runtime = AdminOperationRuntime::new(config);
  let actor = actor("admin");
  let first = runtime
    .enqueue(
      AdminOperationKind::CacheWarm,
      &actor,
      "req1".to_string(),
      |_| async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        Ok(serde_json::json!({"ok": true}))
      },
    )
    .await;
  assert!(first.is_ok());
  let second = runtime
    .enqueue(
      AdminOperationKind::CacheWarm,
      &actor,
      "req2".to_string(),
      |_| async { Ok(serde_json::json!({"ok": true})) },
    )
    .await;
  assert!(matches!(second, Err(AdminOperationError::QueueFull)));
}

#[tokio::test]
async fn cancellation_marks_operation_cancel_requested() {
  let runtime = AdminOperationRuntime::new(config());
  let actor = actor("admin");
  let snapshot = runtime
    .enqueue(
      AdminOperationKind::CacheWarm,
      &actor,
      "req1".to_string(),
      |context| async move {
        while !context.is_cancelled() {
          tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        Err("operation cancelled".to_string())
      },
    )
    .await
    .expect("operation should enqueue");
  let cancelled = runtime
    .cancel(&snapshot.id)
    .await
    .expect("operation should cancel");
  assert!(cancelled.cancel_requested);
}

#[tokio::test]
async fn state_transitions_to_succeeded() {
  let runtime = AdminOperationRuntime::new(config());
  let actor = actor("admin");
  let snapshot = runtime
    .enqueue(
      AdminOperationKind::SupportBundle,
      &actor,
      "req1".to_string(),
      |context| async move {
        context.progress("working", Some(1), Some(2)).await;
        Ok(serde_json::json!({"ok": true}))
      },
    )
    .await
    .expect("operation should enqueue");
  let terminal = wait_for_terminal(&runtime, &snapshot.id).await;
  assert_eq!(terminal.state, AdminOperationState::Succeeded);
  assert_eq!(terminal.result, Some(serde_json::json!({"ok": true})));
}

#[tokio::test]
async fn event_history_is_bounded_and_replayed() {
  let mut config = config();
  config.event_buffer = 2;
  let runtime = AdminOperationRuntime::new(config);
  let actor = actor("admin");
  let snapshot = runtime
    .enqueue(
      AdminOperationKind::CacheWarm,
      &actor,
      "req1".to_string(),
      |context| async move {
        context.progress("one", Some(1), Some(3)).await;
        context.progress("two", Some(2), Some(3)).await;
        context.progress("three", Some(3), Some(3)).await;
        Ok(serde_json::json!({"ok": true}))
      },
    )
    .await
    .expect("operation should enqueue");
  let terminal = wait_for_terminal(&runtime, &snapshot.id).await;
  assert_eq!(terminal.state, AdminOperationState::Succeeded);

  let (history, _receiver, _) = runtime
    .subscribe(&snapshot.id)
    .await
    .expect("operation store should be available")
    .expect("operation should be subscribable");
  assert!(history.len() <= 2);
  assert_eq!(
    history.last().map(|event| event.event.as_str()),
    Some("operation.result")
  );
}

#[tokio::test]
async fn retention_prunes_finished_operations() {
  let mut config = config();
  config.retention_seconds = 1;
  let runtime = AdminOperationRuntime::new(config);
  let actor = actor("admin");
  let snapshot = runtime
    .enqueue(
      AdminOperationKind::CacheWarm,
      &actor,
      "req1".to_string(),
      |_| async { Ok(serde_json::json!({"ok": true})) },
    )
    .await
    .expect("operation should enqueue");
  let _terminal = wait_for_terminal(&runtime, &snapshot.id).await;
  tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
  assert!(
    runtime
      .get(&snapshot.id)
      .await
      .expect("operation store should be available")
      .is_none()
  );
}

#[tokio::test]
async fn oversized_results_fail_the_operation() {
  let mut config = config();
  config.result_max_bytes = 4;
  let runtime = AdminOperationRuntime::new(config);
  let actor = actor("admin");
  let snapshot = runtime
    .enqueue(
      AdminOperationKind::CacheWarm,
      &actor,
      "req1".to_string(),
      |_| async { Ok(serde_json::json!({"too": "large"})) },
    )
    .await
    .expect("operation should enqueue");
  let terminal = wait_for_terminal(&runtime, &snapshot.id).await;
  assert_eq!(terminal.state, AdminOperationState::Failed);
  assert!(
    terminal
      .error
      .unwrap_or_default()
      .contains("result_max_bytes")
  );
}
