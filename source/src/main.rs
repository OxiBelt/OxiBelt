use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use oxibelt::config::{Config, HotReloadMode, RuntimeOverrides};
use tokio::runtime::{Builder, Runtime};

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

fn main() -> anyhow::Result<()> {
  let cli = Cli::parse();
  let runtime_overrides = RuntimeOverrides {
    hot_reload_mode: cli.hot_reload_mode,
    hot_reload_poll_interval_ms: cli.hot_reload_poll_interval_ms,
  };
  let mut config = Config::load(&cli.config)
    .with_context(|| format!("failed to load {}", cli.config.display()))?;
  let override_warnings = config.apply_runtime_overrides(&runtime_overrides);

  let observability = oxibelt::runtime::init_observability(&config)?;
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

  config.log_worker_resolution();
  let worker_threads = config.runtime.worker_threads;
  let runtime = build_runtime(worker_threads)?;
  runtime.block_on(async move {
    let state = oxibelt::state::AppHandle::new(
      oxibelt::state::AppSnapshot::new_with_telemetry(config, observability.telemetry())
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
  })
}

fn parse_hot_reload_mode(value: &str) -> Result<HotReloadMode, String> {
  value
    .parse()
    .map_err(|error: anyhow::Error| error.to_string())
}

fn build_runtime(worker_threads: usize) -> anyhow::Result<Runtime> {
  let mut builder = Builder::new_multi_thread();
  builder.enable_all();
  builder.worker_threads(worker_threads);
  builder.build().context("failed to build Tokio runtime")
}
