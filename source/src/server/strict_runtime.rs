//! Runtime orchestration for the strict data-plane artifact.

use std::path::PathBuf;

use anyhow::Context;
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::{RuntimeArtifact, RuntimeOverrides};
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::state::AppHandle;

use super::ListenerSupervisor;
use super::ops::OpsTasks;
use super::process_signals::{
  ProcessSignal, ProcessSignals, begin_process_predrain, graceful_process_shutdown,
};

pub async fn serve(
  state: AppHandle,
  config_path: Option<PathBuf>,
  runtime_overrides: RuntimeOverrides,
) -> anyhow::Result<()> {
  state
    .snapshot()
    .config
    .validate_for_artifact(RuntimeArtifact::StrictDataPlane)?;
  let (error_tx, mut error_rx) = mpsc::unbounded_channel();
  let mut listeners = ListenerSupervisor::start(state.clone(), error_tx.clone()).await?;
  let mut process_signals = ProcessSignals::new()?;
  let _ops = OpsTasks::start(state.clone(), error_tx.clone()).await?;
  let reload = if state.snapshot().config.runtime.hot_reload.mode.enabled() {
    match config_path {
      Some(config_path) => Some(ReloadManager::new(
        config_path,
        runtime_overrides,
        state.snapshot().as_ref(),
      )?),
      None => {
        warn!("hot reload is enabled but no configuration path is available; reload disabled");
        None
      }
    }
  } else {
    None
  };
  drop(error_tx);
  if let Some(reload) = reload {
    serve_with_reload(
      state,
      &mut listeners,
      &mut error_rx,
      reload,
      &mut process_signals,
    )
    .await
  } else {
    serve_until_shutdown(state, &mut listeners, &mut error_rx, &mut process_signals).await
  }
}

async fn serve_until_shutdown(
  state: AppHandle,
  listeners: &mut ListenerSupervisor,
  error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>,
  process_signals: &mut ProcessSignals,
) -> anyhow::Result<()> {
  loop {
    tokio::select! {
      result = process_signals.recv() => {
        match result? {
          ProcessSignal::PreDrain => begin_process_predrain(&state, listeners),
          ProcessSignal::Shutdown => return graceful_process_shutdown(&state, listeners).await,
        }
      }
      Some(error) = error_rx.recv() => return Err(error),
    }
  }
}

async fn serve_with_reload(
  state: AppHandle,
  listeners: &mut ListenerSupervisor,
  error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>,
  mut reload: ReloadManager,
  process_signals: &mut ProcessSignals,
) -> anyhow::Result<()> {
  #[cfg(unix)]
  let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
    .context("failed to install SIGHUP listener")?;

  loop {
    let poll_sleep = tokio::time::sleep(reload.poll_interval());
    tokio::pin!(poll_sleep);
    tokio::select! {
      result = process_signals.recv() => {
        match result? {
          ProcessSignal::PreDrain => begin_process_predrain(&state, listeners),
          ProcessSignal::Shutdown => return graceful_process_shutdown(&state, listeners).await,
        }
      }
      Some(error) = error_rx.recv() => return Err(error),
      _ = &mut poll_sleep, if !state.snapshot().lifecycle.is_shutdown_draining() => {
        reload.reload_if_changed(ReloadTrigger::Poll, &state, listeners).await;
      }
      _ = hup.recv(), if !state.snapshot().lifecycle.is_shutdown_draining() => {
        reload.reload_if_changed(ReloadTrigger::Signal, &state, listeners).await;
      }
    }
  }
}
