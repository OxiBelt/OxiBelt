//! Compatibility runtime orchestration for the integrated Admin and data-plane artifact.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{error, warn};

use crate::admin_mutation::ClusterHeartbeatTask;
use crate::config::{Config, RuntimeOverrides};
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::state::AppHandle;

use super::admin_cluster_runtime::{AdminClusterRuntimeTasks, PreparedAdminClusterRuntime};
use super::admin_control::{self, AdminControlCommand, AdminControlHandle, RollbackSnapshot};
use super::admin_operations::AdminOperationRuntime;
use super::ops::OpsTasks;
use super::process_signals::{
  ProcessSignal, ProcessSignals, begin_process_predrain, controlled_process_shutdown,
};
use super::{
  ControlCommand, ListenerSupervisor, PreparedServer, ReadinessReason, ReadinessSnapshot,
  ServerHandle, ServerLifecycle, ServerReadiness, ShutdownOutcome, ShutdownReason, ShutdownResult,
  SignalMode, readiness_for_snapshot,
};

pub async fn serve(
  state: AppHandle,
  config_path: Option<PathBuf>,
  runtime_overrides: RuntimeOverrides,
) -> anyhow::Result<()> {
  let result = start_controlled(state, config_path, runtime_overrides, SignalMode::Process)
    .await?
    .wait()
    .await?;
  if result.outcome == ShutdownOutcome::Failed {
    anyhow::bail!("server lifecycle failed");
  }
  Ok(())
}

pub(crate) async fn start_controlled(
  state: AppHandle,
  config_path: Option<PathBuf>,
  runtime_overrides: RuntimeOverrides,
  signal_mode: SignalMode,
) -> anyhow::Result<ServerHandle> {
  Ok(
    prepare_controlled(state, config_path, runtime_overrides, signal_mode)
      .await?
      .spawn(),
  )
}

pub(crate) async fn prepare_controlled(
  state: AppHandle,
  config_path: Option<PathBuf>,
  runtime_overrides: RuntimeOverrides,
  signal_mode: SignalMode,
) -> anyhow::Result<PreparedServer> {
  let process_signals = match signal_mode {
    SignalMode::Process => Some(ProcessSignals::new()?),
    SignalMode::CallerManaged => None,
  };
  let (error_tx, error_rx) = mpsc::unbounded_channel();
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
  let ops = match OpsTasks::start(state.clone(), error_tx.clone()).await {
    Ok(ops) => ops,
    Err(error) => {
      let snapshot = state.snapshot();
      let deadline = tokio::time::Instant::now()
        + Duration::from_millis(snapshot.config.runtime.drain.graceful_timeout_ms);
      let _ = listeners.shutdown_until(deadline).await;
      admin_operations.shutdown().await;
      return Err(error);
    }
  };
  let (cluster_heartbeat, cluster_runtime_tasks) =
    prepared_cluster.start_workers(state.clone(), admin_control.clone(), error_tx.clone());
  let reload = prepare_reload(&state, config_path, runtime_overrides.clone())?;
  let admin_control = AdminControlContext {
    receiver: admin_control_rx,
    handle: admin_control,
    runtime_overrides,
  };
  let mut bound = listeners.bound_listeners();
  bound.extend(ops.bound_listeners());
  let topology = state.snapshot().runtime_topology.clone();
  let (handle, lifecycle) = ServerLifecycle::new(topology, bound);
  lifecycle.publish(readiness_for_snapshot(&state.snapshot()));
  drop(error_tx);
  Ok(PreparedServer::new(
    handle,
    drive_server(
      state,
      listeners,
      ops,
      error_rx,
      admin_control,
      reload,
      process_signals,
      admin_operations,
      cluster_runtime_tasks,
      cluster_heartbeat,
      lifecycle,
    ),
  ))
}

fn prepare_reload(
  state: &AppHandle,
  config_path: Option<PathBuf>,
  runtime_overrides: RuntimeOverrides,
) -> anyhow::Result<Option<ReloadManager>> {
  if !state.snapshot().config.runtime.hot_reload.mode.enabled() {
    return Ok(None);
  }
  match config_path {
    Some(config_path) => Ok(Some(ReloadManager::new(
      config_path,
      runtime_overrides,
      state.snapshot().as_ref(),
    )?)),
    None => {
      warn!("hot reload is enabled but no configuration path is available; reload disabled");
      Ok(None)
    }
  }
}

struct AdminControlContext {
  receiver: mpsc::UnboundedReceiver<AdminControlCommand>,
  handle: AdminControlHandle,
  runtime_overrides: RuntimeOverrides,
}

#[allow(clippy::too_many_arguments)]
async fn drive_server(
  state: AppHandle,
  mut listeners: ListenerSupervisor,
  ops: OpsTasks,
  mut error_rx: mpsc::UnboundedReceiver<anyhow::Error>,
  mut admin_control: AdminControlContext,
  mut reload: Option<ReloadManager>,
  mut process_signals: Option<ProcessSignals>,
  admin_operations: AdminOperationRuntime,
  cluster_runtime_tasks: Option<AdminClusterRuntimeTasks>,
  cluster_heartbeat: Option<ClusterHeartbeatTask>,
  mut lifecycle: ServerLifecycle,
) {
  #[cfg(unix)]
  let mut hup = if process_signals.is_some() && reload.is_some() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
      Ok(signal) => Some(signal),
      Err(error) => {
        error!(%error, "failed to install SIGHUP listener");
        None
      }
    }
  } else {
    None
  };
  #[cfg(not(unix))]
  let mut hup: Option<()> = None;
  let poll_interval = reload
    .as_ref()
    .map_or(Duration::from_secs(86_400), ReloadManager::poll_interval);
  let mut reload_tick = tokio::time::interval(poll_interval);
  reload_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
  let mut readiness_tick = tokio::time::interval(Duration::from_millis(100));
  readiness_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
  let mut rollback: Option<RollbackSnapshot> = None;

  let stop = loop {
    tokio::select! {
      command = lifecycle.command_rx.recv() => match command {
        Some(ControlCommand::PreDrain) => {
          begin_process_predrain(&state, &mut listeners);
          lifecycle.publish(ReadinessSnapshot {
            state: ServerReadiness::Draining,
            reason: ReadinessReason::PreDrainRequested,
          });
        }
        Some(ControlCommand::Reload) => {
          if let Some(manager) = &mut reload
            && !state.snapshot().lifecycle.is_shutdown_draining()
          {
            manager.reload_if_changed(ReloadTrigger::Signal, &state, &mut listeners).await;
          }
        }
        Some(ControlCommand::Graceful { deadline }) => {
          break StopRequest::Graceful {
            deadline,
            reason: ShutdownReason::CallerRequested,
            apply_delay: true,
          };
        }
        None => break StopRequest::Immediate,
      },
      _ = lifecycle.cancellation.cancelled() => break StopRequest::Immediate,
      result = recv_process_signal(&mut process_signals) => match result {
        Ok(ProcessSignal::PreDrain) => {
          begin_process_predrain(&state, &mut listeners);
          lifecycle.publish(ReadinessSnapshot {
            state: ServerReadiness::Draining,
            reason: ReadinessReason::PreDrainRequested,
          });
        }
        Ok(ProcessSignal::Shutdown) => {
          let timeout = Duration::from_millis(
            state.snapshot().config.runtime.drain.graceful_timeout_ms,
          );
          break StopRequest::Graceful {
            deadline: Instant::now() + timeout,
            reason: ShutdownReason::ProcessSignal,
            apply_delay: true,
          };
        }
        Err(error) => break StopRequest::Failed(error),
      },
      Some(error) = error_rx.recv() => break StopRequest::Failed(error),
      Some(command) = admin_control.receiver.recv() => {
        admin_control::handle_admin_control_command(
          command,
          &state,
          &mut listeners,
          &admin_control.handle,
          &admin_control.runtime_overrides,
          &mut rollback,
        ).await;
      }
      _ = readiness_tick.tick() => lifecycle.publish(readiness_for_snapshot(&state.snapshot())),
      _ = reload_tick.tick(), if reload.is_some() && !state.snapshot().lifecycle.is_shutdown_draining() => {
        if let Some(manager) = &mut reload {
          manager.reload_if_changed(ReloadTrigger::Poll, &state, &mut listeners).await;
        }
      }
      _ = recv_hup(&mut hup), if hup.is_some() && !state.snapshot().lifecycle.is_shutdown_draining() => {
        if let Some(manager) = &mut reload {
          manager.reload_if_changed(ReloadTrigger::Signal, &state, &mut listeners).await;
        }
      }
    }
  };

  let (deadline, reason, apply_delay, requested_outcome) = match stop {
    StopRequest::Graceful {
      deadline,
      reason,
      apply_delay,
    } => (deadline, reason, apply_delay, ShutdownOutcome::Graceful),
    StopRequest::Immediate => (
      Instant::now(),
      ShutdownReason::ImmediateCancellation,
      false,
      ShutdownOutcome::Cancelled,
    ),
    StopRequest::Failed(error) => {
      error!(%error, "server lifecycle driver failed");
      (
        Instant::now(),
        ShutdownReason::RuntimeFailure,
        false,
        ShutdownOutcome::Failed,
      )
    }
  };
  lifecycle.publish(ReadinessSnapshot {
    state: ServerReadiness::Draining,
    reason: ReadinessReason::ShutdownRequested,
  });
  let shutdown =
    controlled_process_shutdown(&state, &mut listeners, ops, deadline, apply_delay).await;
  let admin_cleanup = async move {
    admin_operations.shutdown().await;
    if let Some(tasks) = cluster_runtime_tasks {
      tasks.shutdown().await;
    }
    match cluster_heartbeat {
      Some(heartbeat) => heartbeat.shutdown().await,
      None => Ok(()),
    }
  };
  let (admin_forced, heartbeat_result) =
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), admin_cleanup).await {
      Ok(result) => (false, result),
      Err(_) => (true, Ok(())),
    };
  let result = match (shutdown, heartbeat_result) {
    (Ok(forced), Ok(())) => ShutdownResult {
      outcome: if requested_outcome == ShutdownOutcome::Graceful && (forced || admin_forced) {
        ShutdownOutcome::Forced
      } else {
        requested_outcome
      },
      reason: if requested_outcome == ShutdownOutcome::Graceful && (forced || admin_forced) {
        ShutdownReason::DeadlineExpired
      } else {
        reason
      },
    },
    (Err(error), _) | (_, Err(error)) => {
      error!(%error, "server lifecycle cleanup failed");
      failed_result()
    }
  };
  drop(listeners);
  drop(reload);
  drop(rollback);
  drop(admin_control);
  drop(state);
  lifecycle.publish_final(result);
}

enum StopRequest {
  Graceful {
    deadline: Instant,
    reason: ShutdownReason,
    apply_delay: bool,
  },
  Immediate,
  Failed(anyhow::Error),
}

const fn failed_result() -> ShutdownResult {
  ShutdownResult {
    outcome: ShutdownOutcome::Failed,
    reason: ShutdownReason::RuntimeFailure,
  }
}

async fn recv_process_signal(
  signals: &mut Option<ProcessSignals>,
) -> anyhow::Result<ProcessSignal> {
  match signals {
    Some(signals) => signals.recv().await,
    None => std::future::pending().await,
  }
}

#[cfg(unix)]
async fn recv_hup(signal: &mut Option<tokio::signal::unix::Signal>) {
  match signal {
    Some(signal) => {
      signal.recv().await;
    }
    None => std::future::pending().await,
  }
}

#[cfg(not(unix))]
async fn recv_hup(_signal: &mut Option<()>) {
  std::future::pending().await
}
