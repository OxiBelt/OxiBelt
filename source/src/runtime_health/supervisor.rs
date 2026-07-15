use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::{
  RuntimeHealth, RuntimePanicScope, RuntimeRestartOutcome, RuntimeSubsystemError,
  RuntimeSubsystemState, RuntimeTaskKind, RuntimeTaskPolicy, RuntimeTaskTermination,
};

const INITIAL_RESTART_DELAY: Duration = Duration::from_millis(100);
const MAX_RESTART_DELAY: Duration = Duration::from_secs(30);
const STABLE_AFTER: Duration = Duration::from_secs(5);
const RESET_BACKOFF_AFTER: Duration = Duration::from_secs(60);

pub(crate) fn spawn_supervised_task<F, Fut>(
  health: Arc<RuntimeHealth>,
  generation: u64,
  task: RuntimeTaskKind,
  policy: RuntimeTaskPolicy,
  mut shutdown: watch::Receiver<bool>,
  fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
  mut factory: F,
) -> JoinHandle<()>
where
  F: FnMut(watch::Receiver<bool>) -> Fut + Send + 'static,
  Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
  tokio::spawn(async move {
    let mut restart_delay = INITIAL_RESTART_DELAY;
    let mut restarted = false;
    loop {
      if *shutdown.borrow() {
        return;
      }
      health.set_task_state(
        generation,
        task,
        policy,
        if restarted {
          RuntimeSubsystemState::Degraded
        } else {
          RuntimeSubsystemState::Healthy
        },
      );
      let started_at = tokio::time::Instant::now();
      let future = AssertUnwindSafe(factory(shutdown.clone())).catch_unwind();
      tokio::pin!(future);
      let mut stable = Box::pin(tokio::time::sleep(STABLE_AFTER));
      let termination = loop {
        tokio::select! {
          biased;
          changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
              health.set_task_state(
                generation,
                task,
                policy,
                RuntimeSubsystemState::Healthy,
              );
              return;
            }
          }
          result = &mut future => {
            break match result {
              Ok(Ok(())) => RuntimeTaskTermination::UnexpectedReturn,
              Ok(Err(error)) => {
                tracing::warn!(task = task.as_str(), error = %error, "supervised task failed");
                RuntimeTaskTermination::Error
              }
              Err(_) => {
                health.record_panic(RuntimePanicScope::Background, task);
                tracing::error!(task = task.as_str(), "supervised task panicked");
                RuntimeTaskTermination::Panic
              }
            };
          }
          () = &mut stable, if restarted => {
            health.set_task_state(
              generation,
              task,
              policy,
              RuntimeSubsystemState::Healthy,
            );
            health.record_restart(task, RuntimeRestartOutcome::Stable);
            restarted = false;
          }
        }
      };

      if started_at.elapsed() >= RESET_BACKOFF_AFTER {
        restart_delay = INITIAL_RESTART_DELAY;
      }

      if policy == RuntimeTaskPolicy::Fatal {
        health.set_task_state(generation, task, policy, RuntimeSubsystemState::Failed);
        let error = RuntimeSubsystemError::TaskTerminated { task, termination };
        let _ = fatal_tx.send(anyhow::Error::new(error).context("fatal runtime task failed"));
        return;
      }

      if !policy.restartable() {
        health.set_task_state(generation, task, policy, RuntimeSubsystemState::Degraded);
        return;
      }

      health.set_task_state(
        generation,
        task,
        policy,
        if policy.readiness_critical() {
          RuntimeSubsystemState::Failed
        } else {
          RuntimeSubsystemState::Degraded
        },
      );
      health.record_restart(task, RuntimeRestartOutcome::Attempt);
      restarted = true;
      tokio::select! {
        changed = shutdown.changed() => {
          if changed.is_err() || *shutdown.borrow() {
            return;
          }
        }
        () = tokio::time::sleep(restart_delay) => {}
      }
      restart_delay = restart_delay.saturating_mul(2).min(MAX_RESTART_DELAY);
    }
  })
}
