use anyhow::Context;
use tracing_subscriber::EnvFilter;

use crate::config::LoggingConfig;

pub fn init_tracing(config: &LoggingConfig) -> anyhow::Result<()> {
  let env_filter = EnvFilter::try_from_default_env()
    .or_else(|_| EnvFilter::try_new(config.level.clone()))
    .context("failed to configure log filter")?;

  tracing_subscriber::fmt()
    .with_env_filter(env_filter)
    .with_target(false)
    .compact()
    .try_init()
    .ok();

  Ok(())
}
