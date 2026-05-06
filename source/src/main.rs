use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use oxibelt::config::{Config, HotReloadMode, RuntimeOverrides};

#[derive(Debug, Parser)]
#[command(name = "oxibelt")]
#[command(about = "OxiBelt reverse proxy")]
struct Cli {
  #[arg(long, value_name = "FILE")]
  config: PathBuf,

  #[arg(long, value_name = "MODE", value_parser = parse_hot_reload_mode)]
  hot_reload_mode: Option<HotReloadMode>,

  #[arg(long, value_name = "MILLISECONDS")]
  hot_reload_poll_interval_ms: Option<u64>,

  #[arg(long)]
  check: bool,

  #[arg(long)]
  dump_effective_config: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let cli = Cli::parse();
  let runtime_overrides = RuntimeOverrides {
    hot_reload_mode: cli.hot_reload_mode,
    hot_reload_poll_interval_ms: cli.hot_reload_poll_interval_ms,
  };
  let mut config = Config::load(&cli.config)
    .with_context(|| format!("failed to load {}", cli.config.display()))?;
  let override_warnings = config.apply_runtime_overrides(&runtime_overrides);

  oxibelt::runtime::init_tracing(&config.logging)?;
  for warning in override_warnings {
    tracing::warn!("{warning}");
  }
  config.validate()?;
  oxibelt::tls::install_default_provider()?;

  if cli.dump_effective_config {
    let value = Config::load_effective_toml_redacted(&cli.config)
      .with_context(|| format!("failed to load effective {}", cli.config.display()))?;
    println!("{}", toml::to_string_pretty(&value)?);
    return Ok(());
  }

  let state = oxibelt::state::AppHandle::new(
    oxibelt::state::AppSnapshot::new(config)
      .await
      .context("failed to initialize application state")?,
  );
  if cli.check {
    return Ok(());
  }
  oxibelt::server::serve(
    state,
    Some(cli.config),
    RuntimeOverrides {
      hot_reload_mode: runtime_overrides.hot_reload_mode,
      hot_reload_poll_interval_ms: runtime_overrides.hot_reload_poll_interval_ms,
    },
  )
  .await
}

fn parse_hot_reload_mode(value: &str) -> Result<HotReloadMode, String> {
  value
    .parse()
    .map_err(|error: anyhow::Error| error.to_string())
}
