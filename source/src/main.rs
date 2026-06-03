//! Binary entrypoint for loading configuration and starting the OxiBelt runtime.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use oxibelt::config::{Config, HotReloadMode, RuntimeOverrides};
use tokio::runtime::{Builder, Runtime};

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
  oxibelt::tls::install_default_provider()?;

  if cli.dump_effective_config {
    let value = Config::load_effective_toml_redacted(config_path)
      .with_context(|| format!("failed to load effective {}", config_path.display()))?;
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
      Some(config_path.clone()),
      RuntimeOverrides {
        hot_reload_mode: runtime_overrides.hot_reload_mode,
        hot_reload_poll_interval_ms: runtime_overrides.hot_reload_poll_interval_ms,
      },
    )
    .await
  })
}

fn handle_command(command: &CliCommand, config_path: Option<&PathBuf>) -> anyhow::Result<()> {
  match command {
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

fn build_runtime(worker_threads: usize) -> anyhow::Result<Runtime> {
  let mut builder = Builder::new_multi_thread();
  builder.enable_all();
  builder.worker_threads(worker_threads);
  builder.build().context("failed to build Tokio runtime")
}
