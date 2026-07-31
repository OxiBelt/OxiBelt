//! Process signal registration for graceful shutdown and Kubernetes pre-stop drain.

use std::time::Duration;

use anyhow::{Context, ensure};
use tracing::{error, info};

use super::{AppHandle, ListenerSupervisor};
use crate::proxy::http::fast_path::direct_h1::CompioDirectH1ShutdownSummary;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum ProcessSignal {
  PreDrain,
  Shutdown,
}

pub(super) struct ProcessSignals {
  #[cfg(unix)]
  interrupt: tokio::signal::unix::Signal,
  #[cfg(unix)]
  terminate: tokio::signal::unix::Signal,
  #[cfg(unix)]
  pre_drain: tokio::signal::unix::Signal,
}

impl ProcessSignals {
  pub(super) fn new() -> anyhow::Result<Self> {
    #[cfg(unix)]
    {
      use tokio::signal::unix::{SignalKind, signal};

      Ok(Self {
        interrupt: signal(SignalKind::interrupt()).context("failed to install SIGINT listener")?,
        terminate: signal(SignalKind::terminate()).context("failed to install SIGTERM listener")?,
        pre_drain: signal(SignalKind::user_defined1())
          .context("failed to install SIGUSR1 listener")?,
      })
    }
    #[cfg(not(unix))]
    {
      Ok(Self {})
    }
  }

  pub(super) async fn recv(&mut self) -> anyhow::Result<ProcessSignal> {
    #[cfg(unix)]
    {
      tokio::select! {
        _ = self.interrupt.recv() => Ok(ProcessSignal::Shutdown),
        _ = self.terminate.recv() => Ok(ProcessSignal::Shutdown),
        _ = self.pre_drain.recv() => Ok(ProcessSignal::PreDrain),
      }
    }
    #[cfg(not(unix))]
    {
      tokio::signal::ctrl_c()
        .await
        .context("failed to wait for ctrl_c signal")?;
      Ok(ProcessSignal::Shutdown)
    }
  }
}

pub(super) fn begin_process_predrain(state: &AppHandle, listeners: &mut ListenerSupervisor) {
  let snapshot = state.snapshot();
  if snapshot.lifecycle.start_shutdown() {
    info!("pre-drain signal received");
  }
  state.begin_compio_direct_h1_drain();
  listeners.quiesce();
}

pub(super) async fn graceful_process_shutdown(
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
) -> anyhow::Result<()> {
  let snapshot = state.snapshot();
  snapshot.lifecycle.start_shutdown();
  state.begin_compio_direct_h1_drain();
  listeners.quiesce();
  let shutdown_delay = Duration::from_millis(snapshot.config.runtime.drain.shutdown_delay_ms);
  if !shutdown_delay.is_zero() {
    tokio::time::sleep(shutdown_delay).await;
  }
  let required = snapshot
    .compio_direct_h1_service
    .as_ref()
    .is_some_and(|service| service.is_required());
  let deadline = tokio::time::Instant::now()
    + Duration::from_millis(snapshot.config.runtime.drain.graceful_timeout_ms);
  let ((), summary) = tokio::join!(
    listeners.shutdown(snapshot.as_ref()),
    state.shutdown_compio_direct_h1(deadline)
  );
  let shutdown_succeeded = compio_direct_h1_shutdown_succeeded(required, summary);
  log_compio_direct_h1_shutdown_summary(summary, !shutdown_succeeded);
  ensure!(
    shutdown_succeeded,
    "required Compio direct-H1 service did not join every worker during bounded shutdown (started {}, joined {}, failures {})",
    summary.workers_started,
    summary.workers_joined,
    summary.worker_failures
  );
  Ok(())
}

pub(super) async fn shutdown_compio_direct_h1_after_error(state: &AppHandle) {
  let snapshot = state.snapshot();
  snapshot.lifecycle.start_shutdown();
  state.begin_compio_direct_h1_drain();
  let required = snapshot
    .compio_direct_h1_service
    .as_ref()
    .is_some_and(|service| service.is_required());
  let deadline = tokio::time::Instant::now()
    + Duration::from_millis(snapshot.config.runtime.drain.graceful_timeout_ms);
  let summary = state.shutdown_compio_direct_h1(deadline).await;
  log_compio_direct_h1_shutdown_summary(
    summary,
    !compio_direct_h1_shutdown_succeeded(required, summary),
  );
}

fn compio_direct_h1_shutdown_succeeded(
  required: bool,
  summary: CompioDirectH1ShutdownSummary,
) -> bool {
  !required
    || (summary.workers_started > 0
      && summary.workers_joined == summary.workers_started
      && summary.worker_failures == 0)
}

fn log_compio_direct_h1_shutdown_summary(summary: CompioDirectH1ShutdownSummary, abnormal: bool) {
  if abnormal {
    error!(
      workers_started = summary.workers_started,
      workers_joined = summary.workers_joined,
      worker_failures = summary.worker_failures,
      operations_cancelled = summary.operations_cancelled,
      queued_operations_rejected = summary.queued_operations_rejected,
      "Compio direct-H1 service completed abnormal bounded shutdown"
    );
  } else {
    info!(
      workers_started = summary.workers_started,
      workers_joined = summary.workers_joined,
      worker_failures = summary.worker_failures,
      operations_cancelled = summary.operations_cancelled,
      queued_operations_rejected = summary.queued_operations_rejected,
      "Compio direct-H1 service completed bounded shutdown"
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn process_signal_kinds_keep_predrain_distinct_from_shutdown() {
    assert_ne!(ProcessSignal::PreDrain, ProcessSignal::Shutdown);
  }

  #[test]
  fn required_compio_shutdown_requires_a_complete_worker_join() {
    assert!(compio_direct_h1_shutdown_succeeded(
      true,
      CompioDirectH1ShutdownSummary {
        workers_started: 2,
        workers_joined: 2,
        ..CompioDirectH1ShutdownSummary::default()
      }
    ));
    assert!(!compio_direct_h1_shutdown_succeeded(
      true,
      CompioDirectH1ShutdownSummary {
        workers_started: 2,
        workers_joined: 1,
        worker_failures: 1,
        ..CompioDirectH1ShutdownSummary::default()
      }
    ));
    assert!(!compio_direct_h1_shutdown_succeeded(
      true,
      CompioDirectH1ShutdownSummary::default()
    ));
    assert!(compio_direct_h1_shutdown_succeeded(
      false,
      CompioDirectH1ShutdownSummary::default()
    ));
  }
}
