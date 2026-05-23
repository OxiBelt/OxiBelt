use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use oxibelt::config::{Config, HotReloadMode, RuntimeOverrides};
use oxibelt::diagnostics::{DoctorFailOn, DoctorOptions, DoctorOutputFormat, ExternalProbeKind};
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
  doctor: bool,

  #[arg(long, value_name = "FORMAT", value_parser = parse_doctor_output_format, default_value = "text")]
  doctor_format: DoctorOutputFormat,

  #[arg(long, value_name = "SEVERITY", value_parser = parse_doctor_fail_on, default_value = "error")]
  doctor_fail_on: DoctorFailOn,

  #[arg(long = "doctor-external-probe", value_name = "KIND", value_parser = parse_external_probe)]
  doctor_external_probes: Vec<ExternalProbeKind>,

  #[arg(long)]
  dump_effective_config: bool,
}

fn main() -> anyhow::Result<()> {
  let cli = Cli::parse();
  if cli.doctor {
    let runtime = Builder::new_current_thread()
      .enable_all()
      .build()
      .context("failed to build Tokio runtime")?;
    let options = DoctorOptions {
      external_probes: cli.doctor_external_probes,
    };
    let report = runtime.block_on(oxibelt::diagnostics::diagnose_config_path(
      &cli.config,
      &options,
    ));
    match cli.doctor_format {
      DoctorOutputFormat::Text => print!("{}", oxibelt::diagnostics::format_text(&report)),
      DoctorOutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }
    if report.fails_on(cli.doctor_fail_on) {
      std::process::exit(1);
    }
    return Ok(());
  }

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
      oxibelt::state::AppSnapshot::new_with_telemetry(config, observability.into_telemetry())
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

fn parse_doctor_output_format(value: &str) -> Result<DoctorOutputFormat, String> {
  value
    .parse()
    .map_err(|error: anyhow::Error| error.to_string())
}

fn parse_doctor_fail_on(value: &str) -> Result<DoctorFailOn, String> {
  value
    .parse()
    .map_err(|error: anyhow::Error| error.to_string())
}

fn parse_external_probe(value: &str) -> Result<ExternalProbeKind, String> {
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
