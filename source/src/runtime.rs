//! Runtime initialization for async execution, tracing, and telemetry resources.

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
  let env_filter = EnvFilter::try_from_default_env()
    .or_else(|_| EnvFilter::try_new(config.level.clone()))
    .context("failed to configure log filter")?;

  tracing_subscriber::fmt()
    .with_env_filter(env_filter)
    .with_writer(std::io::stdout)
    .with_target(false)
    .compact()
    .try_init()
    .ok();

  Ok(())
}
