//! Runtime initialization for async execution, tracing, and telemetry resources.

use std::sync::{Mutex, OnceLock};

use anyhow::Context;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, LoggingConfig};
use crate::telemetry::TelemetryRuntime;

pub mod backend;
pub mod compio;
pub mod main_runtime;
pub mod tokio_island;
pub mod topology;
pub mod topology_config;

pub(crate) const TOKIO_RUNTIME_THREAD_STACK_SIZE: usize = 32 * 1024 * 1024;

pub fn init_tracing(config: &LoggingConfig) -> anyhow::Result<()> {
  init_logging(config)
}

/// Initializes only the synchronous tracing subscriber.
///
/// Process-wide hardening must run after this function and before
/// [`init_telemetry`], because an enabled OTLP exporter owns a background
/// thread that would otherwise escape thread-scoped Landlock installation.
pub fn init_startup_logging(config: &LoggingConfig) -> anyhow::Result<()> {
  init_logging(config)
}

/// Starts telemetry resources after process-wide hardening is active.
pub fn init_telemetry(config: &Config) -> anyhow::Result<TelemetryRuntime> {
  TelemetryRuntime::new(&config.telemetry.tracing).context("failed to initialize telemetry")
}

pub struct ObservabilityGuard {
  telemetry: TelemetryRuntime,
}

impl ObservabilityGuard {
  pub fn into_telemetry(self) -> TelemetryRuntime {
    self.telemetry
  }
}

pub fn init_observability(config: &Config) -> anyhow::Result<ObservabilityGuard> {
  init_startup_logging(&config.logging)?;
  let telemetry = init_telemetry(config)?;
  Ok(ObservabilityGuard { telemetry })
}

fn init_logging(config: &crate::config::LoggingConfig) -> anyhow::Result<()> {
  match install_startup_logging(config) {
    Ok(TracingInstall::Applied | TracingInstall::AlreadyMatching) => Ok(()),
    Err(TracingInstallError::InvalidFilter(error)) => Err(error),
    Err(TracingInstallError::AlreadyInitialized) => {
      anyhow::bail!("a process-global tracing subscriber is already initialized")
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum TracingInstall {
  Applied,
  AlreadyMatching,
}

#[derive(Debug)]
pub(crate) enum TracingInstallError {
  InvalidFilter(anyhow::Error),
  AlreadyInitialized,
}

pub(crate) fn install_startup_logging(
  config: &crate::config::LoggingConfig,
) -> Result<TracingInstall, TracingInstallError> {
  static INSTALL_LOCK: Mutex<()> = Mutex::new(());
  static INSTALLED_FILTER: OnceLock<String> = OnceLock::new();

  let env_filter = EnvFilter::try_from_default_env()
    .or_else(|_| EnvFilter::try_new(config.level.clone()))
    .context("failed to configure log filter")
    .map_err(TracingInstallError::InvalidFilter)?;
  let filter_fingerprint = env_filter.to_string();
  let _install_guard = INSTALL_LOCK
    .lock()
    .map_err(|_| TracingInstallError::AlreadyInitialized)?;
  if let Some(outcome) = classify_installed_filter(
    INSTALLED_FILTER.get().map(String::as_str),
    &filter_fingerprint,
  ) {
    return outcome;
  }

  tracing_subscriber::fmt()
    .with_env_filter(env_filter)
    .with_writer(std::io::stdout)
    .with_target(false)
    .compact()
    .try_init()
    .map_err(|_| TracingInstallError::AlreadyInitialized)?;
  if INSTALLED_FILTER.set(filter_fingerprint).is_err() {
    return Err(TracingInstallError::AlreadyInitialized);
  }
  Ok(TracingInstall::Applied)
}

fn classify_installed_filter(
  installed: Option<&str>,
  requested: &str,
) -> Option<Result<TracingInstall, TracingInstallError>> {
  installed.map(|installed| {
    if installed == requested {
      Ok(TracingInstall::AlreadyMatching)
    } else {
      Err(TracingInstallError::AlreadyInitialized)
    }
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn initialized_tracing_filter_is_idempotent_or_a_structured_conflict() {
    let installed = "oxibelt=info".to_string();
    assert!(matches!(
      classify_installed_filter(Some(&installed), "oxibelt=info"),
      Some(Ok(TracingInstall::AlreadyMatching))
    ));
    assert!(matches!(
      classify_installed_filter(Some(&installed), "oxibelt=debug"),
      Some(Err(TracingInstallError::AlreadyInitialized))
    ));
    assert!(classify_installed_filter(None, "oxibelt=info").is_none());
  }
}
