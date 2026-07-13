//! Process signal registration for graceful shutdown and Kubernetes pre-stop drain.

use std::time::Duration;

use anyhow::Context;
use tracing::info;

use super::{AppHandle, ListenerSupervisor};

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
  listeners.quiesce();
}

pub(super) async fn graceful_process_shutdown(
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
) -> anyhow::Result<()> {
  let snapshot = state.snapshot();
  snapshot.lifecycle.start_shutdown();
  listeners.quiesce();
  let shutdown_delay = Duration::from_millis(snapshot.config.runtime.drain.shutdown_delay_ms);
  if !shutdown_delay.is_zero() {
    tokio::time::sleep(shutdown_delay).await;
  }
  listeners.shutdown(snapshot.as_ref()).await;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn process_signal_kinds_keep_predrain_distinct_from_shutdown() {
    assert_ne!(ProcessSignal::PreDrain, ProcessSignal::Shutdown);
  }
}
