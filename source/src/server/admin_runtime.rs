//! Compatibility runtime orchestration for the integrated Admin and data-plane artifact.

use std::path::PathBuf;

use anyhow::Context;
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::{Config, RuntimeOverrides};
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::state::AppHandle;

use super::ListenerSupervisor;
use super::admin_cluster_runtime::PreparedAdminClusterRuntime;
use super::admin_control::{self, AdminControlCommand, AdminControlHandle, RollbackSnapshot};
use super::admin_operations::AdminOperationRuntime;
use super::ops::OpsTasks;
use super::process_signals::{
  ProcessSignal, ProcessSignals, begin_process_predrain, graceful_process_shutdown,
  shutdown_compio_direct_h1_after_error,
};

pub async fn serve(
  state: AppHandle,
  config_path: Option<PathBuf>,
  runtime_overrides: RuntimeOverrides,
) -> anyhow::Result<()> {
  let result = serve_inner(state.clone(), config_path, runtime_overrides).await;
  if result.is_err() {
    shutdown_compio_direct_h1_after_error(&state).await;
  }
  result
}

async fn serve_inner(
  state: AppHandle,
  config_path: Option<PathBuf>,
  runtime_overrides: RuntimeOverrides,
) -> anyhow::Result<()> {
  let (error_tx, mut error_rx) = mpsc::unbounded_channel();
  let activation_config = config_path
    .as_ref()
    .and_then(|path| Config::load_effective_toml_for_activation(path).ok());
  let effective_config = activation_config
    .as_ref()
    .map(Config::redact_effective_toml_value)
    .and_then(|value| toml::to_string_pretty(&value).ok());
  let (admin_control, admin_control_rx) =
    AdminControlHandle::new(effective_config, activation_config.as_ref())?;
  let prepared_cluster =
    PreparedAdminClusterRuntime::prepare(&state, &admin_control, error_tx.clone()).await?;
  let admin_operations = {
    let snapshot = state.snapshot();
    AdminOperationRuntime::prepare(&snapshot.config, &snapshot.admin_audit).await?
  };
  let mut listeners = ListenerSupervisor::start(
    state.clone(),
    error_tx.clone(),
    admin_control.clone(),
    admin_operations.clone(),
  )
  .await?;
  let (cluster_heartbeat, cluster_runtime_tasks) =
    prepared_cluster.start_workers(state.clone(), admin_control.clone(), error_tx.clone());
  let mut process_signals = ProcessSignals::new()?;
  let _ops = OpsTasks::start(state.clone(), error_tx.clone()).await?;
  let reload = if state.snapshot().config.runtime.hot_reload.mode.enabled() {
    match config_path {
      Some(config_path) => Some(ReloadManager::new(
        config_path,
        runtime_overrides.clone(),
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
  let admin_control = AdminControlContext {
    receiver: admin_control_rx,
    handle: admin_control,
    runtime_overrides,
  };
  drop(error_tx);
  let result = if let Some(reload) = reload {
    serve_with_reload(
      state,
      &mut listeners,
      &mut error_rx,
      admin_control,
      reload,
      &mut process_signals,
    )
    .await
  } else {
    serve_until_shutdown(
      state,
      &mut listeners,
      &mut error_rx,
      admin_control,
      &mut process_signals,
    )
    .await
  };
  admin_operations.shutdown().await;
  if let Some(tasks) = cluster_runtime_tasks {
    tasks.shutdown().await;
  }
  if let Some(cluster_heartbeat) = cluster_heartbeat
    && let Err(error) = cluster_heartbeat.shutdown().await
  {
    if result.is_ok() {
      return Err(error.context("failed to release Admin cluster member authority"));
    }
    warn!(error = %error, "failed to release Admin cluster member authority");
  }
  result
}

struct AdminControlContext {
  receiver: mpsc::UnboundedReceiver<AdminControlCommand>,
  handle: AdminControlHandle,
  runtime_overrides: RuntimeOverrides,
}

async fn serve_until_shutdown(
  state: AppHandle,
  listeners: &mut ListenerSupervisor,
  error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>,
  mut admin_control: AdminControlContext,
  process_signals: &mut ProcessSignals,
) -> anyhow::Result<()> {
  let mut rollback: Option<RollbackSnapshot> = None;
  loop {
    tokio::select! {
      result = process_signals.recv() => {
          match result? {
            ProcessSignal::PreDrain => begin_process_predrain(&state, listeners),
            ProcessSignal::Shutdown => return graceful_process_shutdown(&state, listeners).await,
          }
      }
      Some(error) = error_rx.recv() => return Err(error),
      Some(command) = admin_control.receiver.recv() => {
        admin_control::handle_admin_control_command(
          command,
          &state,
          listeners,
          &admin_control.handle,
          &admin_control.runtime_overrides,
          &mut rollback,
        ).await;
      }
    }
  }
}

async fn serve_with_reload(
  state: AppHandle,
  listeners: &mut ListenerSupervisor,
  error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>,
  mut admin_control: AdminControlContext,
  mut reload: ReloadManager,
  process_signals: &mut ProcessSignals,
) -> anyhow::Result<()> {
  #[cfg(unix)]
  let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
    .context("failed to install SIGHUP listener")?;

  let mut rollback: Option<RollbackSnapshot> = None;
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
        Some(command) = admin_control.receiver.recv() => {
            admin_control::handle_admin_control_command(
              command,
              &state,
              listeners,
              &admin_control.handle,
              &admin_control.runtime_overrides,
              &mut rollback,
            ).await;
        }
        _ = &mut poll_sleep, if !state.snapshot().lifecycle.is_shutdown_draining() => {
            reload.reload_if_changed(ReloadTrigger::Poll, &state, listeners).await;
        }
        _ = hup.recv(), if !state.snapshot().lifecycle.is_shutdown_draining() => {
            reload.reload_if_changed(ReloadTrigger::Signal, &state, listeners).await;
        }
    }
  }
}
