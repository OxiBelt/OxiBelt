use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use url::Url;

#[derive(Debug, Args)]
pub(crate) struct RulepackCommand {
  #[command(subcommand)]
  pub(crate) command: RulepackSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RulepackSubcommand {
  List,
  Repo(RulepackRepoCommand),
  Search(RulepackSearchArgs),
  Info(RulepackInfoArgs),
  Install(RulepackCatalogInstallArgs),
  Update(RulepackUpdateArgs),
  Fit(RulepackFitArgs),
  Plan(RulepackPlanArgs),
  Diff(RulepackDiffArgs),
  Inspect(RulepackInspectArgs),
  Render(RulepackRenderArgs),
  Check(RulepackCheckArgs),
  Adapt(RulepackAdaptArgs),
  Apply(RulepackApplyArgs),
  Remove(RulepackRemoveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RulepackRepoCommand {
  #[command(subcommand)]
  pub(crate) command: RulepackRepoSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RulepackRepoSubcommand {
  Add(Box<RulepackRepoAddArgs>),
  List,
  Remove(RulepackRepoRemoveArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RulepackRepoAddArgs {
  pub(crate) name: String,
  pub(crate) url: Url,
  #[arg(long = "rulepack-ca-cert", value_name = "FILE")]
  pub(crate) ca_certs: Vec<PathBuf>,
  #[arg(long = "rulepack-token-env")]
  pub(crate) token_env: Option<String>,
  #[arg(long = "allow-insecure-rulepack-url")]
  pub(crate) allow_insecure_rulepack_url: bool,
  #[arg(long = "require-rulepack-openpgp-signature")]
  pub(crate) require_openpgp_signature: bool,
  #[arg(long = "rulepack-openpgp-key", value_name = "FILE")]
  pub(crate) openpgp_key_files: Vec<PathBuf>,
  #[arg(long = "rulepack-openpgp-keyring", value_name = "DIR")]
  pub(crate) openpgp_keyring_dirs: Vec<PathBuf>,
  #[arg(long = "rulepack-openpgp-fingerprint", value_name = "HEX")]
  pub(crate) openpgp_fingerprints: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackRepoRemoveArgs {
  pub(crate) name: String,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackSearchArgs {
  pub(crate) query: String,
  #[arg(long = "repo", value_name = "NAME")]
  pub(crate) repo: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackInfoArgs {
  pub(crate) name: String,
  #[arg(long = "version", value_name = "VERSION")]
  pub(crate) version: Option<String>,
  #[arg(long = "repo", value_name = "NAME")]
  pub(crate) repo: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackCatalogInstallArgs {
  pub(crate) name: String,
  #[arg(long = "version", value_name = "VERSION")]
  pub(crate) version: Option<String>,
  #[arg(long = "repo", value_name = "NAME")]
  pub(crate) repo: Option<String>,
  #[arg(long = "values", value_name = "FILE")]
  pub(crate) values: Option<PathBuf>,
  #[arg(long = "var", value_name = "KEY=VALUE")]
  pub(crate) vars: Vec<String>,
  #[arg(long = "bind", value_name = "KEY=VALUE")]
  pub(crate) binds: Vec<String>,
  #[arg(long, value_enum)]
  pub(crate) mode: Option<RulepackModeArg>,
  #[arg(long = "profile", value_name = "NAME")]
  pub(crate) profile: Option<String>,
  #[arg(long)]
  pub(crate) force_mode: bool,
  #[arg(long)]
  pub(crate) interactive: bool,
  #[arg(long)]
  pub(crate) dry_run: bool,
  #[arg(long, value_name = "FILE", requires = "dry_run")]
  pub(crate) fixture: Option<PathBuf>,
  #[arg(long, value_name = "FILE", requires = "dry_run")]
  pub(crate) replay: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackUpdateArgs {
  #[arg(long, required = true)]
  pub(crate) plan: bool,
  #[arg(long = "repo", value_name = "NAME")]
  pub(crate) repo: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackFitArgs {
  #[command(flatten)]
  pub(crate) source: RulepackSourceArgs,
  #[arg(long = "values", value_name = "FILE")]
  pub(crate) values: Option<PathBuf>,
  #[arg(long = "var", value_name = "KEY=VALUE")]
  pub(crate) vars: Vec<String>,
  #[arg(long = "bind", value_name = "KEY=VALUE")]
  pub(crate) binds: Vec<String>,
  #[arg(long = "profile", value_name = "NAME")]
  pub(crate) profile: Option<String>,
  #[arg(long, value_enum)]
  pub(crate) mode: Option<RulepackModeArg>,
  #[arg(long)]
  pub(crate) force_mode: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackPlanArgs {
  #[command(flatten)]
  pub(crate) source: RulepackSourceArgs,
  #[arg(long = "values", value_name = "FILE")]
  pub(crate) values: Option<PathBuf>,
  #[arg(long = "var", value_name = "KEY=VALUE")]
  pub(crate) vars: Vec<String>,
  #[arg(long = "bind", value_name = "KEY=VALUE")]
  pub(crate) binds: Vec<String>,
  #[arg(long = "profile", value_name = "NAME")]
  pub(crate) profile: Option<String>,
  #[arg(long, value_enum)]
  pub(crate) mode: Option<RulepackModeArg>,
  #[arg(long)]
  pub(crate) force_mode: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackDiffArgs {
  #[command(flatten)]
  pub(crate) source: RulepackSourceArgs,
  #[arg(long = "values", value_name = "FILE")]
  pub(crate) values: Option<PathBuf>,
  #[arg(long = "var", value_name = "KEY=VALUE")]
  pub(crate) vars: Vec<String>,
  #[arg(long = "bind", value_name = "KEY=VALUE")]
  pub(crate) binds: Vec<String>,
  #[arg(long = "profile", value_name = "NAME")]
  pub(crate) profile: Option<String>,
  #[arg(long, value_enum)]
  pub(crate) mode: Option<RulepackModeArg>,
  #[arg(long)]
  pub(crate) force_mode: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackInspectArgs {
  #[command(flatten)]
  pub(crate) source: RulepackSourceArgs,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackRenderArgs {
  #[command(flatten)]
  pub(crate) source: RulepackSourceArgs,
  #[arg(long = "values", value_name = "FILE")]
  pub(crate) values: Option<PathBuf>,
  #[arg(long = "var", value_name = "KEY=VALUE")]
  pub(crate) vars: Vec<String>,
  #[arg(long = "bind", value_name = "KEY=VALUE")]
  pub(crate) binds: Vec<String>,
  #[arg(long = "profile", value_name = "NAME")]
  pub(crate) profile: Option<String>,
  #[arg(long, value_enum)]
  pub(crate) mode: Option<RulepackModeArg>,
  #[arg(long)]
  pub(crate) force_mode: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackCheckArgs {
  #[command(flatten)]
  pub(crate) source: RulepackSourceArgs,
  #[arg(long = "values", value_name = "FILE")]
  pub(crate) values: Option<PathBuf>,
  #[arg(long = "var", value_name = "KEY=VALUE")]
  pub(crate) vars: Vec<String>,
  #[arg(long = "bind", value_name = "KEY=VALUE")]
  pub(crate) binds: Vec<String>,
  #[arg(long = "profile", value_name = "NAME")]
  pub(crate) profile: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackAdaptArgs {
  #[arg(long, value_enum)]
  pub(crate) adapter: RulepackAdapterArg,
  #[arg(long = "input", value_name = "FILE")]
  pub(crate) input: PathBuf,
  #[arg(long = "output", value_name = "FILE")]
  pub(crate) output: Option<PathBuf>,
  #[arg(long = "route", value_name = "NAME")]
  pub(crate) routes: Vec<String>,
  #[arg(long = "method", value_name = "METHOD")]
  pub(crate) methods: Vec<String>,
  #[arg(long = "path-prefix", value_name = "PREFIX")]
  pub(crate) path_prefixes: Vec<String>,
  #[arg(
    long = "reason",
    value_name = "TEXT",
    default_value = "adapted from ModSecurity CRS exclusion"
  )]
  pub(crate) reason: String,
  #[arg(
    long = "name-prefix",
    value_name = "NAME",
    default_value = "adapted-crs"
  )]
  pub(crate) name_prefix: String,
  #[arg(long = "allow-global-disable")]
  pub(crate) allow_global_disable: bool,
  #[arg(long)]
  pub(crate) force: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackApplyArgs {
  #[command(flatten)]
  pub(crate) source: RulepackSourceArgs,
  #[arg(long = "values", value_name = "FILE")]
  pub(crate) values: Option<PathBuf>,
  #[arg(long = "var", value_name = "KEY=VALUE")]
  pub(crate) vars: Vec<String>,
  #[arg(long = "bind", value_name = "KEY=VALUE")]
  pub(crate) binds: Vec<String>,
  #[arg(long, value_enum)]
  pub(crate) mode: Option<RulepackModeArg>,
  #[arg(long = "profile", value_name = "NAME")]
  pub(crate) profile: Option<String>,
  #[arg(long)]
  pub(crate) force_mode: bool,
  #[arg(long)]
  pub(crate) interactive: bool,
  #[arg(long)]
  pub(crate) dry_run: bool,
  #[arg(long, value_name = "FILE", requires = "dry_run")]
  pub(crate) fixture: Option<PathBuf>,
  #[arg(long, value_name = "FILE", requires = "dry_run")]
  pub(crate) replay: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackRemoveArgs {
  pub(crate) name: String,
  #[arg(long, required = true)]
  pub(crate) apply: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RulepackSourceArgs {
  #[arg(long, value_name = "FILE", conflicts_with_all = ["dir", "url", "git"])]
  pub(crate) file: Option<PathBuf>,
  #[arg(long, value_name = "DIR", conflicts_with_all = ["file", "url", "git"])]
  pub(crate) dir: Option<PathBuf>,
  #[arg(long, value_name = "URL", conflicts_with_all = ["file", "dir", "git"])]
  pub(crate) url: Option<Url>,
  #[arg(long, value_name = "GIT_URL", conflicts_with_all = ["file", "dir", "url"])]
  pub(crate) git: Option<String>,
  #[arg(
    long,
    value_name = "FILE",
    default_value = "rulepack.oxirule-rulepack.toml"
  )]
  pub(crate) manifest: PathBuf,
  #[arg(long = "rulepack-ca-cert", value_name = "FILE", requires = "url")]
  pub(crate) ca_certs: Vec<PathBuf>,
  #[arg(long = "rulepack-token-env", requires = "url")]
  pub(crate) token_env: Option<String>,
  #[arg(long = "sha256", requires = "url")]
  pub(crate) sha256: Option<String>,
  #[arg(long = "allow-unpinned-rulepack", requires = "url")]
  pub(crate) allow_unpinned_rulepack: bool,
  #[arg(long = "allow-insecure-rulepack-url", requires = "url")]
  pub(crate) allow_insecure_rulepack_url: bool,
  #[arg(long = "require-rulepack-openpgp-signature", requires = "url")]
  pub(crate) require_openpgp_signature: bool,
  #[arg(
    long = "rulepack-openpgp-signature-url",
    value_name = "URL",
    requires = "url",
    conflicts_with = "openpgp_signature_file"
  )]
  pub(crate) openpgp_signature_url: Option<Url>,
  #[arg(
    long = "rulepack-openpgp-signature-file",
    value_name = "FILE",
    requires = "url",
    conflicts_with = "openpgp_signature_url"
  )]
  pub(crate) openpgp_signature_file: Option<PathBuf>,
  #[arg(long = "rulepack-openpgp-key", value_name = "FILE", requires = "url")]
  pub(crate) openpgp_key_files: Vec<PathBuf>,
  #[arg(
    long = "rulepack-openpgp-keyring",
    value_name = "DIR",
    requires = "url"
  )]
  pub(crate) openpgp_keyring_dirs: Vec<PathBuf>,
  #[arg(
    long = "rulepack-openpgp-fingerprint",
    value_name = "HEX",
    requires = "url"
  )]
  pub(crate) openpgp_fingerprints: Vec<String>,
  #[arg(long = "git-ref", requires = "git")]
  pub(crate) git_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum RulepackModeArg {
  Monitor,
  Enforcing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum RulepackAdapterArg {
  #[value(name = "modsecurity-crs-exclusion")]
  ModsecurityCrsExclusion,
}
