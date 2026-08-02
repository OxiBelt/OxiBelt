//! Binary entrypoint for loading configuration and starting the OxiBelt runtime.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use oxibelt::config::{Config, HotReloadMode, RuntimeOverrides};
use oxibelt::runtime::backend::CompioDriverSelection;
use oxibelt::runtime::main_runtime::{ActiveMainRuntime, MainRuntime};
use oxibelt::runtime::topology::{
  RuntimeCapability, RuntimeRequestedPreset, RuntimeResolvedPreset, RuntimeTopologyPolicy,
  RuntimeTopologyReason, RuntimeTopologySnapshot, resolve_runtime_topology,
};
use oxibelt::runtime::topology_config::{available_capabilities, request_from_config};

mod runtime_diagnostics;
use runtime_diagnostics::{
  RuntimeCheckCommand, RuntimeProbeCommand, handle_runtime_check_command,
  handle_runtime_probe_command, run_compio_main_child, run_compio_probe_child,
};

const LIFECYCLE_PRESTOP_COMMAND: &str = "__lifecycle-prestop";
const LIFECYCLE_PRESTOP_MIN_WAIT_SECONDS: u64 = 1;
const LIFECYCLE_PRESTOP_MAX_WAIT_SECONDS: u64 = 86_400;

#[derive(Debug, Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(about = "OxiBelt reverse proxy")]
#[command(
  version = oxibelt_build_identity::SHORT_VERSION,
  long_version = oxibelt_build_identity::LONG_VERSION
)]
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
  let args = std::env::args_os().collect::<Vec<_>>();
  if let Some(wait_seconds) = parse_lifecycle_prestop_args(&args)? {
    return run_lifecycle_prestop(wait_seconds);
  }
  let cli = Cli::parse();
  if let Some(command) = &cli.command {
    return handle_command(command, cli.config.as_ref());
  }

  run_server(cli)
}

fn parse_lifecycle_prestop_args(args: &[OsString]) -> anyhow::Result<Option<u64>> {
  if args.get(1).and_then(|value| value.to_str()) != Some(LIFECYCLE_PRESTOP_COMMAND) {
    return Ok(None);
  }
  if args.len() != 4 || args.get(2).and_then(|value| value.to_str()) != Some("--wait-seconds") {
    bail!("{LIFECYCLE_PRESTOP_COMMAND} requires exactly --wait-seconds <SECONDS>");
  }
  let raw = args[3]
    .to_str()
    .ok_or_else(|| anyhow::anyhow!("lifecycle pre-stop wait must be valid UTF-8"))?;
  let wait_seconds = raw
    .parse::<u64>()
    .with_context(|| format!("invalid lifecycle pre-stop wait {raw}"))?;
  if !(LIFECYCLE_PRESTOP_MIN_WAIT_SECONDS..=LIFECYCLE_PRESTOP_MAX_WAIT_SECONDS)
    .contains(&wait_seconds)
  {
    bail!(
      "lifecycle pre-stop wait must be between {LIFECYCLE_PRESTOP_MIN_WAIT_SECONDS} and {LIFECYCLE_PRESTOP_MAX_WAIT_SECONDS} seconds"
    );
  }
  Ok(Some(wait_seconds))
}

fn run_lifecycle_prestop(wait_seconds: u64) -> anyhow::Result<()> {
  nix::sys::signal::kill(
    nix::unistd::Pid::from_raw(1),
    nix::sys::signal::Signal::SIGUSR1,
  )
  .context("failed to signal OxiBelt PID 1 for pre-drain")?;
  std::thread::sleep(Duration::from_secs(wait_seconds));
  Ok(())
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
  let config = Config::load(config_path)
    .with_context(|| format!("failed to load {}", config_path.display()))?;
  let mut effective_config = config.clone();
  effective_config.resolve_rollout_identity_from_environment()?;
  let override_warnings = effective_config.apply_runtime_overrides(&runtime_overrides);

  if env!("CARGO_PKG_NAME") == "oxibelt-dataplane-strict" {
    effective_config.validate_for_artifact(oxibelt::config::RuntimeArtifact::StrictDataPlane)?;
  }
  effective_config.validate()?;

  if cli.dump_effective_config {
    let value = Config::load_effective_toml_redacted(config_path)
      .with_context(|| format!("failed to load effective {}", config_path.display()))?;
    println!("{}", toml::to_string_pretty(&value)?);
    return Ok(());
  }
  if cli.check {
    return run_configuration_check(effective_config, override_warnings);
  }

  let worker_threads = effective_config.runtime.workers.tokio;
  let request = request_from_config(&effective_config);
  let compio_preflight = preflight_compio_for_startup(request.requested_preset, worker_threads);
  let mut capabilities = available_capabilities(compio_preflight.driver);
  if let Some(reason) = compio_preflight.failure_reason {
    capabilities.compio_main = RuntimeCapability::Unavailable(reason);
  }
  let result = oxibelt::OxiBelt::builder(config)
    .run_options(oxibelt::RunOptions {
      config_path: Some(config_path.clone()),
      runtime_overrides,
    })
    .runtime_policy(oxibelt::RuntimePolicy::FromConfig)
    .process_policy(oxibelt::ProcessPolicy::Standalone)
    .runtime_capabilities(capabilities)
    .build_owned()?
    .run()?;
  if result.outcome == oxibelt::server::ShutdownOutcome::Failed {
    bail!("server lifecycle failed");
  }
  Ok(())
}

#[allow(deprecated)]
fn run_configuration_check(config: Config, override_warnings: Vec<String>) -> anyhow::Result<()> {
  oxibelt::runtime::init_startup_logging(&config.logging)?;
  for warning in override_warnings {
    tracing::warn!("{warning}");
  }
  if let Some(mode) = config.runtime.hardening.seccomp.legacy_mode() {
    tracing::warn!(
      code = "CFG_RUNTIME_SECCOMP_MODE_COMPATIBILITY_ALIAS",
      legacy_mode = ?mode,
      expectation = config.runtime.hardening.seccomp.expectation.as_str(),
      "legacy runtime.hardening.seccomp.mode maps to runtime.hardening.seccomp.expectation"
    );
  }
  oxibelt::configure_crypto_runtime(&config);
  oxibelt::tls::install_configured_provider(&config.crypto)?;
  oxibelt::tls::preload_native_redis_roots(&config)
    .context("failed to preload native Redis trust roots before runtime confinement")?;
  let filesystem_manifest =
    oxibelt::filesystem_access::FilesystemAccessManifest::from_config(&config)
      .context("failed to generate filesystem-access manifest")?;
  let projection = filesystem_manifest.landlock_projection();
  let hardening =
    oxibelt::hardening::observe_runtime_hardening(&config.runtime.hardening, Some(&projection));
  tracing::info!(
    hardening = %serde_json::to_string(&hardening)?,
    "resolved runtime hardening contract"
  );
  let telemetry = oxibelt::runtime::init_telemetry(&config)?;
  config.log_worker_resolution();
  let worker_threads = config.runtime.workers.tokio;
  let request = request_from_config(&config);
  let compio_preflight = preflight_compio_for_startup(request.requested_preset, worker_threads);
  let mut capabilities = available_capabilities(compio_preflight.driver);
  if let Some(reason) = compio_preflight.failure_reason {
    capabilities.compio_main = RuntimeCapability::Unavailable(reason);
  }
  let mut topology = resolve_runtime_topology(request, capabilities)
    .context("requested runtime topology cannot be activated")?;
  let mut active_runtime = active_runtime_for_topology(&topology);
  let runtime = match build_main_runtime(active_runtime, worker_threads) {
    Ok(runtime) => runtime,
    Err(_error)
      if request.requested_preset == RuntimeRequestedPreset::Auto
        && request.policy == RuntimeTopologyPolicy::AllowFallback
        && active_runtime == ActiveMainRuntime::Compio =>
    {
      tracing::warn!(
        reason = RuntimeTopologyReason::CompioRuntimeBuildFailed.as_str(),
        worker_threads,
        "runtime topology capability changed during activation; resolving once more"
      );
      capabilities.compio_main =
        RuntimeCapability::Unavailable(RuntimeTopologyReason::CompioRuntimeBuildFailed);
      topology = resolve_runtime_topology(request, capabilities)
        .context("fallback runtime topology cannot be activated")?;
      active_runtime = active_runtime_for_topology(&topology);
      build_main_runtime(active_runtime, worker_threads).with_context(|| {
        format!(
          "fallback runtime build failed after {}",
          RuntimeTopologyReason::CompioRuntimeBuildFailed.as_str()
        )
      })?
    }
    Err(error) => return Err(error.context("resolved main runtime failed to build")),
  };
  oxibelt::runtime::backend::set_runtime_backend_snapshot(topology.legacy_backend_snapshot());
  runtime.block_on(async move {
    startup_stage_async(
      "app_snapshot_new_with_telemetry",
      build_app_handle(config, telemetry, topology, hardening),
    )
    .await
    .map(|_| ())
  })
}

async fn build_app_handle(
  config: Config,
  telemetry: oxibelt::telemetry::TelemetryRuntime,
  topology: RuntimeTopologySnapshot,
  hardening: oxibelt::hardening::RuntimeHardeningSnapshot,
) -> anyhow::Result<oxibelt::state::AppHandle> {
  tokio::task::spawn(async move {
    oxibelt::state::AppSnapshot::new_with_telemetry_and_topology_and_hardening(
      config, telemetry, topology, hardening,
    )
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
  failure_reason: Option<RuntimeTopologyReason>,
}

fn preflight_compio_for_startup(
  requested_preset: RuntimeRequestedPreset,
  worker_threads: usize,
) -> CompioStartupPreflight {
  if requested_preset == RuntimeRequestedPreset::TokioHyper {
    return CompioStartupPreflight {
      driver: None,
      failure_reason: None,
    };
  }
  let driver = match startup_capability_stage(
    "compio_probe_runtime_build",
    RuntimeTopologyReason::CompioProbeFailed,
    run_compio_probe_child,
  ) {
    Ok(driver) => driver,
    Err(_) => {
      tracing::warn!(
        reason = RuntimeTopologyReason::CompioProbeFailed.as_str(),
        worker_threads,
        "Compio runtime capability preflight failed"
      );
      return CompioStartupPreflight {
        driver: None,
        failure_reason: Some(RuntimeTopologyReason::CompioProbeFailed),
      };
    }
  };
  if requested_preset == RuntimeRequestedPreset::Auto
    && !compio_driver_safe_for_auto_main_runtime(driver)
  {
    tracing::warn!(
      driver = driver.as_str(),
      reason = RuntimeTopologyReason::UnsafeCompioDriver.as_str(),
      worker_threads,
      "Compio probe selected a driver that is unsafe for automatic activation"
    );
    return CompioStartupPreflight {
      driver: Some(driver),
      failure_reason: Some(RuntimeTopologyReason::UnsafeCompioDriver),
    };
  }

  match startup_capability_stage(
    "main_compio_runtime_build",
    RuntimeTopologyReason::CompioRuntimeBuildFailed,
    || run_compio_main_child(worker_threads),
  ) {
    Ok(()) => CompioStartupPreflight {
      driver: Some(driver),
      failure_reason: None,
    },
    Err(_) => {
      tracing::warn!(
        reason = RuntimeTopologyReason::CompioRuntimeBuildFailed.as_str(),
        worker_threads,
        "Compio main runtime capability preflight failed"
      );
      CompioStartupPreflight {
        driver: None,
        failure_reason: Some(RuntimeTopologyReason::CompioRuntimeBuildFailed),
      }
    }
  }
}

fn compio_driver_safe_for_auto_main_runtime(driver: CompioDriverSelection) -> bool {
  matches!(
    driver,
    CompioDriverSelection::IoUring | CompioDriverSelection::Iocp
  )
}

fn active_runtime_for_topology(topology: &RuntimeTopologySnapshot) -> ActiveMainRuntime {
  match topology.resolved_preset {
    RuntimeResolvedPreset::HybridCompio => ActiveMainRuntime::Compio,
    RuntimeResolvedPreset::TokioHyper | RuntimeResolvedPreset::External => {
      ActiveMainRuntime::TokioHyper
    }
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

fn startup_capability_stage<T>(
  name: &'static str,
  failure_reason: RuntimeTopologyReason,
  action: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
  let started = Instant::now();
  tracing::info!(startup_stage = name, "startup capability stage started");
  let result = action();
  match &result {
    Ok(_) => tracing::info!(
      startup_stage = name,
      elapsed_ms = started.elapsed().as_millis(),
      "startup capability stage completed"
    ),
    Err(_) => tracing::error!(
      startup_stage = name,
      elapsed_ms = started.elapsed().as_millis(),
      reason = failure_reason.as_str(),
      "startup capability stage failed"
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

#[allow(deprecated)]
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
#[path = "main/tests.rs"]
mod tests;
