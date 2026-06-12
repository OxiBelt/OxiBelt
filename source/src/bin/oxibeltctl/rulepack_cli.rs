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
  Fit(RulepackFitArgs),
  Inspect(RulepackInspectArgs),
  Render(RulepackRenderArgs),
  Check(RulepackCheckArgs),
  Apply(RulepackApplyArgs),
  Remove(RulepackRemoveArgs),
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
