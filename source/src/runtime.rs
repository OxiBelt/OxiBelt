//! Runtime initialization for tracing and telemetry resources.

use anyhow::Context;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, LoggingConfig};
use crate::telemetry::TelemetryRuntime;

pub fn init_tracing(config: &LoggingConfig) -> anyhow::Result<()> {
  init_logging(config)
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
  init_logging(&config.logging)?;
  let telemetry =
    TelemetryRuntime::new(&config.telemetry.tracing).context("failed to initialize telemetry")?;
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
