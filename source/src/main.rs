//! Binary entrypoint for loading configuration and starting the OxiBelt runtime.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use oxibelt::config::{Config, HotReloadMode, RuntimeMainRuntimeMode, RuntimeOverrides};
use oxibelt::runtime::backend::{CompioDriverSelection, RuntimeBackendSnapshot};
use oxibelt::runtime::main_runtime::{ActiveMainRuntime, MainRuntime};

mod runtime_diagnostics;
use runtime_diagnostics::{
  RuntimeCheckCommand, RuntimeProbeCommand, handle_runtime_check_command,
  handle_runtime_probe_command, run_compio_main_child, run_compio_probe_child,
};

const COMPAT_RUNTIME_HINT: &str =
  "set runtime.main_runtime = \"tokio_hyper\" or \"auto\" to avoid Compio in this environment";

#[derive(Debug, Parser)]
#[command(name = "oxibelt")]
#[command(about = "OxiBelt reverse proxy")]
struct Cli {
  #[arg(long, value_name = "FILE")]
  config: Option<PathBuf>,

  #[arg(long, value_name = "MODE", value_parser = parse_hot_reload_mode)]
  hot_reload_mode: Option<HotReloadMode>,

  #[arg(long, value_name = "MILLISECONDS")]
  hot_reload_poll_interval_ms: Option<u64>,

  #[arg(long)]
  check: bool,

  #[arg(long)]
  dump_effective_config: bool,

  #[command(subcommand)]
  command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
  #[command(name = "runtime-check")]
  RuntimeCheck(RuntimeCheckCommand),
  #[command(name = "__runtime-probe", hide = true)]
  RuntimeProbe(RuntimeProbeCommand),
  #[command(name = "oxirule")]
  OxiRule(OxiRuleCommand),
}

#[derive(Debug, Args)]
struct OxiRuleCommand {
  #[command(subcommand)]
  command: OxiRuleSubcommand,
}

#[derive(Debug, Subcommand)]
enum OxiRuleSubcommand {
  Check(OxiRuleRuleArgs),
  Test(OxiRuleFixtureArgs),
  Explain(OxiRuleFixtureArgs),
  Cost(OxiRuleRuleArgs),
  Replay(OxiRuleReplayArgs),
  Template(OxiRuleTemplateCommand),
  FalsePositive(OxiRuleFalsePositiveArgs),
}

#[derive(Debug, Args)]
struct OxiRuleRuleArgs {
  #[arg(long, value_name = "FILE")]
  rule: PathBuf,
  #[arg(long, value_name = "FILE")]
  group: Vec<PathBuf>,
}

#[derive(Debug, Args)]
struct OxiRuleFixtureArgs {
  #[arg(long, value_name = "FILE")]
  rule: PathBuf,
  #[arg(long, value_name = "FILE")]
  group: Vec<PathBuf>,
  #[arg(long, value_name = "JSON_OR_FILE")]
  fixture: String,
}

#[derive(Debug, Args)]
struct OxiRuleReplayArgs {
  #[arg(long, value_name = "FILE")]
  rule: PathBuf,
  #[arg(long, value_name = "FILE")]
  group: Vec<PathBuf>,
  #[arg(long, value_name = "NDJSON_FILE")]
  input: PathBuf,
}

#[derive(Debug, Args)]
struct OxiRuleTemplateCommand {
  #[command(subcommand)]
  command: OxiRuleTemplateSubcommand,
}

#[derive(Debug, Subcommand)]
enum OxiRuleTemplateSubcommand {
  List,
  Render(OxiRuleTemplateRenderArgs),
}

#[derive(Debug, Args)]
struct OxiRuleTemplateRenderArgs {
  #[arg(long)]
  name: String,
  #[arg(long = "var", value_name = "KEY=VALUE")]
  vars: Vec<String>,
}

#[derive(Debug, Args)]
struct OxiRuleFalsePositiveArgs {
  #[arg(long, value_name = "JSON_OR_FILE")]
  finding: String,
}

fn main() -> anyhow::Result<()> {
  let cli = Cli::parse();
  if let Some(command) = &cli.command {
    return handle_command(command, cli.config.as_ref());
  }

  run_server(cli)
}

fn run_server(cli: Cli) -> anyhow::Result<()> {
  let config_path = cli
    .config
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("--config is required"))?;

  let runtime_overrides = RuntimeOverrides {
    hot_reload_mode: cli.hot_reload_mode,
    hot_reload_poll_interval_ms: cli.hot_reload_poll_interval_ms,
  };
  let mut config = Config::load(config_path)
    .with_context(|| format!("failed to load {}", config_path.display()))?;
  let override_warnings = config.apply_runtime_overrides(&runtime_overrides);

  let observability = oxibelt::runtime::init_observability(&config)?;
  for warning in override_warnings {
    tracing::warn!("{warning}");
  }
  config.validate()?;
  oxibelt::configure_crypto_runtime(&config);
  oxibelt::tls::install_configured_provider(&config.crypto)?;

  if cli.dump_effective_config {
    let value = Config::load_effective_toml_redacted(config_path)
      .with_context(|| format!("failed to load effective {}", config_path.display()))?;
    println!("{}", toml::to_string_pretty(&value)?);
    return Ok(());
  }
  if !cli.check {
    oxibelt::netport_switcher::ensure_required_runtime_socket(&config)?;
    oxibelt::hardening::apply_runtime_hardening(&config.runtime.hardening)?;
  }

  config.log_worker_resolution();
  let worker_threads = config.runtime.worker_threads;
  let compio_preflight = preflight_compio_for_startup(config.runtime.main_runtime, worker_threads)?;
  let active_runtime = active_runtime_for_startup(config.runtime.main_runtime, &compio_preflight)?;
  let runtime_backend = startup_stage("runtime_backend_snapshot", || {
    Ok::<_, anyhow::Error>(runtime_backend_snapshot(
      active_runtime,
      compio_preflight.driver,
    ))
  })?;
  oxibelt::runtime::backend::set_runtime_backend_snapshot(runtime_backend);
  tracing::info!(
    target_runtime = runtime_backend.target_runtime,
    target_io_driver = runtime_backend.target_io_driver,
    active_runtime = runtime_backend.active_runtime,
    compatibility_runtime = runtime_backend.compatibility_runtime,
    compatibility_island_count = runtime_backend.compatibility_island_count,
    "resolved async runtime backend"
  );
  let runtime = build_main_runtime(active_runtime, worker_threads)?;
  let check = cli.check;
  runtime.block_on(async move {
    let state = startup_stage_async(
      "app_snapshot_new_with_telemetry",
      build_app_handle(config, observability.into_telemetry()),
    )
    .await?;
    if check {
      return Ok(());
    }
    startup_stage_async("server_serve", async {
      oxibelt::server::serve(
        state,
        Some(config_path.clone()),
        RuntimeOverrides {
          hot_reload_mode: runtime_overrides.hot_reload_mode,
          hot_reload_poll_interval_ms: runtime_overrides.hot_reload_poll_interval_ms,
        },
      )
      .await
    })
    .await
  })
}

async fn build_app_handle(
  config: Config,
  telemetry: oxibelt::telemetry::TelemetryRuntime,
) -> anyhow::Result<oxibelt::state::AppHandle> {
  tokio::task::spawn(async move {
    oxibelt::state::AppSnapshot::new_with_telemetry(config, telemetry)
      .await
      .context("failed to initialize application state")
      .map(oxibelt::state::AppHandle::new)
  })
  .await
  .context("application state initialization task failed")?
}

#[derive(Debug, Clone, Copy)]
struct CompioStartupPreflight {
  driver: Option<CompioDriverSelection>,
  failed: bool,
}

fn preflight_compio_for_startup(
  mode: RuntimeMainRuntimeMode,
  worker_threads: usize,
) -> anyhow::Result<CompioStartupPreflight> {
  if mode == RuntimeMainRuntimeMode::TokioHyper {
    return Ok(CompioStartupPreflight {
      driver: None,
      failed: false,
    });
  }
  let driver = match startup_stage("compio_probe_runtime_build", run_compio_probe_child) {
    Ok(driver) => driver,
    Err(error) if mode == RuntimeMainRuntimeMode::Auto => {
      tracing::warn!(
        error = %error,
        worker_threads,
        "Compio runtime probe failed; falling back to Tokio/Hyper main runtime"
      );
      return Ok(CompioStartupPreflight {
        driver: None,
        failed: true,
      });
    }
    Err(error) => {
      return Err(error.context(format!(
        "Compio runtime probe failed; {COMPAT_RUNTIME_HINT}"
      )));
    }
  };
  if mode == RuntimeMainRuntimeMode::Auto && !compio_driver_safe_for_auto_main_runtime(driver) {
    tracing::warn!(
      driver = driver.as_str(),
      worker_threads,
      "Compio probe selected a fallback I/O driver; falling back to Tokio/Hyper main runtime"
    );
    return Ok(CompioStartupPreflight {
      driver: Some(driver),
      failed: true,
    });
  }

  match startup_stage("main_compio_runtime_build", || {
    run_compio_main_child(worker_threads)
  }) {
    Ok(()) => Ok(CompioStartupPreflight {
      driver: Some(driver),
      failed: false,
    }),
    Err(error) if mode == RuntimeMainRuntimeMode::Auto => {
      tracing::warn!(
        error = %error,
        worker_threads,
        "Compio main runtime preflight failed; falling back to Tokio/Hyper main runtime"
      );
      Ok(CompioStartupPreflight {
        driver: None,
        failed: true,
      })
    }
    Err(error) => Err(error.context(format!(
      "Compio main runtime preflight failed; {COMPAT_RUNTIME_HINT}"
    ))),
  }
}

fn compio_driver_safe_for_auto_main_runtime(driver: CompioDriverSelection) -> bool {
  matches!(
    driver,
    CompioDriverSelection::IoUring | CompioDriverSelection::Iocp
  )
}

fn active_runtime_for_startup(
  mode: RuntimeMainRuntimeMode,
  preflight: &CompioStartupPreflight,
) -> anyhow::Result<ActiveMainRuntime> {
  match mode {
    RuntimeMainRuntimeMode::Compio => {
      if preflight.failed {
        bail!("Compio startup preflight failed");
      }
      Ok(ActiveMainRuntime::Compio)
    }
    RuntimeMainRuntimeMode::TokioHyper => Ok(ActiveMainRuntime::TokioHyper),
    RuntimeMainRuntimeMode::Auto if preflight.failed => Ok(ActiveMainRuntime::TokioHyper),
    RuntimeMainRuntimeMode::Auto => Ok(ActiveMainRuntime::Compio),
  }
}

fn build_main_runtime(
  active_runtime: ActiveMainRuntime,
  worker_threads: usize,
) -> anyhow::Result<MainRuntime> {
  match active_runtime {
    ActiveMainRuntime::Compio => startup_stage("runtime_compio_build", || {
      MainRuntime::build_compio(worker_threads)
    }),
    ActiveMainRuntime::TokioHyper => startup_stage("runtime_tokio_hyper_build", || {
      MainRuntime::build_tokio(worker_threads)
    }),
  }
}

fn runtime_backend_snapshot(
  active_runtime: ActiveMainRuntime,
  driver: Option<CompioDriverSelection>,
) -> RuntimeBackendSnapshot {
  oxibelt::runtime::backend::runtime_backend_snapshot_for(active_runtime, driver)
}

fn startup_stage<T>(
  name: &'static str,
  action: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
  let started = Instant::now();
  tracing::info!(startup_stage = name, "startup stage started");
  let result = action();
  match &result {
    Ok(_) => tracing::info!(
      startup_stage = name,
      elapsed_ms = started.elapsed().as_millis(),
      "startup stage completed"
    ),
    Err(error) => tracing::error!(
      startup_stage = name,
      elapsed_ms = started.elapsed().as_millis(),
      error = %error,
      "startup stage failed"
    ),
  }
  result
}

async fn startup_stage_async<T>(
  name: &'static str,
  future: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
  let started = Instant::now();
  tracing::info!(startup_stage = name, "startup stage started");
  let result = future.await;
  match &result {
    Ok(_) => tracing::info!(
      startup_stage = name,
      elapsed_ms = started.elapsed().as_millis(),
      "startup stage completed"
    ),
    Err(error) => tracing::error!(
      startup_stage = name,
      elapsed_ms = started.elapsed().as_millis(),
      error = %error,
      "startup stage failed"
    ),
  }
  result
}

fn handle_command(command: &CliCommand, config_path: Option<&PathBuf>) -> anyhow::Result<()> {
  match command {
    CliCommand::RuntimeCheck(command) => handle_runtime_check_command(command, config_path),
    CliCommand::RuntimeProbe(command) => handle_runtime_probe_command(command),
    CliCommand::OxiRule(command) => handle_oxirule_command(command, config_path),
  }
}

fn handle_oxirule_command(
  command: &OxiRuleCommand,
  config_path: Option<&PathBuf>,
) -> anyhow::Result<()> {
  match &command.command {
    OxiRuleSubcommand::Template(template) => match &template.command {
      OxiRuleTemplateSubcommand::List => print_report(oxibelt::waf::list_oxirule_templates()),
      OxiRuleTemplateSubcommand::Render(args) => {
        let report =
          oxibelt::waf::render_oxirule_template(oxibelt::waf::OxiRuleTemplateRenderRequest {
            name: args.name.clone(),
            variables: parse_template_vars(&args.vars)?,
          });
        print_report(report)
      }
    },
    OxiRuleSubcommand::FalsePositive(args) => {
      let report = oxibelt::waf::plan_false_positive(oxibelt::waf::OxiRuleFalsePositiveRequest {
        finding: read_json_value_or_file(&args.finding)?,
      });
      print_report(report)
    }
    OxiRuleSubcommand::Check(args) => {
      let config = load_command_config(config_path)?;
      let report = oxibelt::waf::check_oxirule(
        &config,
        oxibelt::waf::OxiRuleDevtoolsCheckRequest {
          rule: Some(rule_candidate_from_file(&args.rule)?),
          groups: group_candidates_from_files(&args.group)?,
          include_active_rules: false,
        },
      );
      print_report(report)
    }
    OxiRuleSubcommand::Cost(args) => {
      let config = load_command_config(config_path)?;
      let report = oxibelt::waf::cost_oxirule(
        &config,
        oxibelt::waf::OxiRuleDevtoolsCheckRequest {
          rule: Some(rule_candidate_from_file(&args.rule)?),
          groups: group_candidates_from_files(&args.group)?,
          include_active_rules: false,
        },
      );
      print_report(report)
    }
    OxiRuleSubcommand::Test(args) => {
      let config = load_command_config(config_path)?;
      let report = oxibelt::waf::test_oxirule(
        &config,
        oxibelt::waf::OxiRuleDevtoolsEvalRequest {
          rule: rule_candidate_from_file(&args.rule)?,
          groups: group_candidates_from_files(&args.group)?,
          include_active_rules: false,
          fixture: read_fixture_or_file(&args.fixture)?,
          expected: None,
        },
      );
      print_report(report)
    }
    OxiRuleSubcommand::Explain(args) => {
      let config = load_command_config(config_path)?;
      let report = oxibelt::waf::explain_oxirule(
        &config,
        oxibelt::waf::OxiRuleDevtoolsEvalRequest {
          rule: rule_candidate_from_file(&args.rule)?,
          groups: group_candidates_from_files(&args.group)?,
          include_active_rules: false,
          fixture: read_fixture_or_file(&args.fixture)?,
          expected: None,
        },
      );
      print_report(report)
    }
    OxiRuleSubcommand::Replay(args) => {
      let config = load_command_config(config_path)?;
      let report = oxibelt::waf::replay_oxirule(
        &config,
        oxibelt::waf::OxiRuleDevtoolsReplayRequest {
          rule: rule_candidate_from_file(&args.rule)?,
          groups: group_candidates_from_files(&args.group)?,
          include_active_rules: false,
          input: std::fs::read_to_string(&args.input)
            .with_context(|| format!("failed to read {}", args.input.display()))?,
        },
      );
      print_report(report)
    }
  }
}

fn load_command_config(config_path: Option<&PathBuf>) -> anyhow::Result<Config> {
  let config_path = config_path.ok_or_else(|| anyhow::anyhow!("--config is required"))?;
  let config = Config::load(config_path)
    .with_context(|| format!("failed to load {}", config_path.display()))?;
  config.validate()?;
  oxibelt::configure_crypto_runtime(&config);
  oxibelt::tls::install_configured_provider(&config.crypto)?;
  Ok(config)
}

fn rule_candidate_from_file(path: &PathBuf) -> anyhow::Result<oxibelt::waf::OxiRuleCandidate> {
  let content =
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
  Ok(oxibelt::waf::OxiRuleCandidate {
    content,
    name: path
      .file_stem()
      .and_then(|name| name.to_str())
      .map(sanitize_rule_name),
    id: None,
    tags: Vec::new(),
    mode: None,
    phase: None,
    priority: None,
    route: None,
  })
}

fn group_candidates_from_files(
  paths: &[PathBuf],
) -> anyhow::Result<Vec<oxibelt::waf::OxiRuleGroupCandidate>> {
  paths
    .iter()
    .map(|path| {
      Ok(oxibelt::waf::OxiRuleGroupCandidate {
        content: std::fs::read_to_string(path)
          .with_context(|| format!("failed to read {}", path.display()))?,
        route: None,
        name: path
          .file_stem()
          .and_then(|name| name.to_str())
          .map(sanitize_rule_name),
      })
    })
    .collect()
}

fn read_fixture_or_file(value: &str) -> anyhow::Result<oxibelt::waf::OxiRuleFixture> {
  serde_json::from_str(&read_inline_or_file(value)?).context("failed to parse fixture JSON")
}

fn read_json_value_or_file(value: &str) -> anyhow::Result<serde_json::Value> {
  serde_json::from_str(&read_inline_or_file(value)?).context("failed to parse JSON")
}

fn read_inline_or_file(value: &str) -> anyhow::Result<String> {
  let path = PathBuf::from(value);
  if path.exists() {
    std::fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))
  } else {
    Ok(value.to_string())
  }
}

fn parse_template_vars(
  values: &[String],
) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
  let mut vars = std::collections::BTreeMap::new();
  for value in values {
    let Some((key, val)) = value.split_once('=') else {
      anyhow::bail!("template variables must use KEY=VALUE syntax");
    };
    vars.insert(key.to_string(), val.to_string());
  }
  Ok(vars)
}

fn sanitize_rule_name(value: &str) -> String {
  value
    .chars()
    .map(|ch| {
      if ch.is_ascii_alphanumeric() || ch == '-' {
        ch
      } else {
        '-'
      }
    })
    .collect()
}

fn print_report(report: oxibelt::waf::OxiRuleDevtoolsReport) -> anyhow::Result<()> {
  println!("{}", serde_json::to_string_pretty(&report)?);
  if report.ok {
    Ok(())
  } else {
    std::process::exit(1);
  }
}

fn parse_hot_reload_mode(value: &str) -> Result<HotReloadMode, String> {
  value
    .parse()
    .map_err(|error: anyhow::Error| error.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn auto_main_runtime_treats_polling_compio_driver_as_unsafe() {
    assert!(!compio_driver_safe_for_auto_main_runtime(
      CompioDriverSelection::Polling
    ));

    let selected = active_runtime_for_startup(
      RuntimeMainRuntimeMode::Auto,
      &CompioStartupPreflight {
        driver: Some(CompioDriverSelection::Polling),
        failed: true,
      },
    )
    .expect("auto should fall back after an unsafe Compio preflight");

    assert_eq!(selected, ActiveMainRuntime::TokioHyper);
  }

  #[test]
  fn auto_main_runtime_allows_production_compio_drivers() {
    assert!(compio_driver_safe_for_auto_main_runtime(
      CompioDriverSelection::IoUring
    ));
    assert!(compio_driver_safe_for_auto_main_runtime(
      CompioDriverSelection::Iocp
    ));
  }

  #[test]
  fn explicit_compio_runtime_still_selects_compio_after_successful_polling_preflight() {
    let selected = active_runtime_for_startup(
      RuntimeMainRuntimeMode::Compio,
      &CompioStartupPreflight {
        driver: Some(CompioDriverSelection::Polling),
        failed: false,
      },
    )
    .expect("explicit Compio should preserve the caller's selected runtime");

    assert_eq!(selected, ActiveMainRuntime::Compio);
  }
}
