use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use oxibelt::admin_client::{BREAK_GLASS_TOKEN_ENV, DEFAULT_ADMIN_TOKEN_ENV, DEFAULT_ADMIN_URL};
use url::Url;

#[derive(Debug, Parser)]
#[command(name = "oxibeltctl")]
#[command(about = "OxiBelt operations CLI")]
pub(crate) struct Cli {
  #[command(flatten)]
  pub(crate) admin: AdminArgs,
  #[command(subcommand)]
  pub(crate) command: Command,
}

#[derive(Debug, Args)]
pub(crate) struct AdminArgs {
  #[arg(long, default_value = DEFAULT_ADMIN_URL)]
  pub(crate) admin_url: Url,
  #[arg(long, conflicts_with = "break_glass_access")]
  pub(crate) token_env: Option<String>,
  #[arg(long, value_name = "FILE", conflicts_with = "break_glass_access")]
  pub(crate) token_file: Option<PathBuf>,
  #[arg(long = "break-glass-access")]
  pub(crate) break_glass_access: bool,
  #[arg(long = "ca-cert", value_name = "FILE")]
  pub(crate) ca_certs: Vec<PathBuf>,
  #[arg(long, value_name = "FILE", requires = "client_key")]
  pub(crate) client_cert: Option<PathBuf>,
  #[arg(long, value_name = "FILE", requires = "client_cert")]
  pub(crate) client_key: Option<PathBuf>,
  #[arg(long, default_value_t = 10_000)]
  pub(crate) timeout_ms: u64,
  #[arg(long, value_enum, default_value_t = OutputFormat::PrettyJson)]
  pub(crate) output: OutputFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum OutputFormat {
  #[value(name = "pretty-json")]
  PrettyJson,
  Json,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
  Status,
  Doctor(DoctorArgs),
  Config(ConfigCommand),
  Tls(TlsCommand),
  Lifecycle(LifecycleCommand),
  Pool(PoolCommand),
  Waf(WafCommand),
  OxiRule(OxiRuleCommand),
  DynamicPolicy(DynamicPolicyCommand),
  Block(MitigationArgs),
  Allow(MitigationArgs),
  RateLimit(RateLimitArgs),
  Cache(CacheCommand),
  Ipm(IpmCommand),
  Auth(AuthCommand),
  Files(FilesCommand),
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
  #[arg(long, value_name = "FILE")]
  pub(crate) candidate: Option<PathBuf>,
  #[arg(long = "external-probe", value_name = "KIND")]
  pub(crate) external_probes: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct ConfigCommand {
  #[command(subcommand)]
  pub(crate) command: ConfigSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConfigSubcommand {
  Status,
  Effective,
  Validate(FileArg),
  Diff(FileArg),
  Apply(ConfigApplyArgs),
  Rollback(EtagsArgs),
}

#[derive(Debug, Args)]
pub(crate) struct FileArg {
  pub(crate) file: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct ConfigApplyArgs {
  pub(crate) file: PathBuf,
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct EtagsArgs {
  #[arg(long)]
  pub(crate) etag: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct TlsCommand {
  #[command(subcommand)]
  pub(crate) command: TlsSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TlsSubcommand {
  Status,
  Reload(EtagsArgs),
}

#[derive(Debug, Args)]
pub(crate) struct LifecycleCommand {
  #[command(subcommand)]
  pub(crate) command: LifecycleSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum LifecycleSubcommand {
  Status,
  Drain,
  Undrain,
}

#[derive(Debug, Args)]
pub(crate) struct PoolCommand {
  #[command(subcommand)]
  pub(crate) command: PoolSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PoolSubcommand {
  List,
  Get(PoolArg),
  AddServer(PoolAddServerArgs),
  UpdateServer(PoolUpdateServerArgs),
  RemoveServer(PoolServerArg),
  Ready(PoolServerArg),
  Drain(PoolServerArg),
  Down(PoolServerArg),
  Maintenance(PoolServerArg),
}

#[derive(Debug, Args)]
pub(crate) struct PoolArg {
  pub(crate) pool: String,
}

#[derive(Debug, Args)]
pub(crate) struct PoolServerArg {
  pub(crate) pool: String,
  pub(crate) server_id: String,
}

#[derive(Debug, Args)]
pub(crate) struct PoolAddServerArgs {
  pub(crate) pool: String,
  #[arg(long)]
  pub(crate) id: String,
  #[arg(long)]
  pub(crate) origin: String,
  #[arg(long, default_value = "ready")]
  pub(crate) state: String,
  #[arg(long, default_value_t = 1)]
  pub(crate) weight: u32,
  #[arg(long, default_value_t = 0)]
  pub(crate) max_conns: usize,
  #[arg(long)]
  pub(crate) backup: bool,
}

#[derive(Debug, Args)]
pub(crate) struct PoolUpdateServerArgs {
  pub(crate) pool: String,
  pub(crate) server_id: String,
  #[arg(long)]
  pub(crate) state: Option<String>,
  #[arg(long)]
  pub(crate) weight: Option<u32>,
  #[arg(long)]
  pub(crate) max_conns: Option<usize>,
  #[arg(long)]
  pub(crate) backup: Option<bool>,
}

#[derive(Debug, Args)]
pub(crate) struct WafCommand {
  #[command(subcommand)]
  pub(crate) command: WafSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum WafSubcommand {
  Hits(TopArgs),
  Costs(TopArgs),
  CrsCompatibility,
}

#[derive(Debug, Args)]
pub(crate) struct TopArgs {
  #[arg(long)]
  pub(crate) top: Option<usize>,
}

#[derive(Debug, Args)]
pub(crate) struct OxiRuleCommand {
  #[command(subcommand)]
  pub(crate) command: OxiRuleSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum OxiRuleSubcommand {
  Check(OxiRuleRuleArgs),
  Test(OxiRuleFixtureArgs),
  Explain(OxiRuleFixtureArgs),
  Cost(OxiRuleRuleArgs),
  Replay(OxiRuleReplayArgs),
  Templates,
  RenderTemplate(OxiRuleTemplateArgs),
  FalsePositive(JsonInputArg),
}

#[derive(Debug, Args)]
pub(crate) struct OxiRuleRuleArgs {
  #[arg(long, value_name = "FILE")]
  pub(crate) rule: PathBuf,
  #[arg(long, value_name = "FILE")]
  pub(crate) group: Vec<PathBuf>,
  #[arg(long)]
  pub(crate) include_active_rules: bool,
}

#[derive(Debug, Args)]
pub(crate) struct OxiRuleFixtureArgs {
  #[arg(long, value_name = "FILE")]
  pub(crate) rule: PathBuf,
  #[arg(long, value_name = "FILE")]
  pub(crate) group: Vec<PathBuf>,
  #[arg(long, value_name = "FILE")]
  pub(crate) fixture: PathBuf,
  #[arg(long)]
  pub(crate) include_active_rules: bool,
}

#[derive(Debug, Args)]
pub(crate) struct OxiRuleReplayArgs {
  #[arg(long, value_name = "FILE")]
  pub(crate) rule: PathBuf,
  #[arg(long, value_name = "FILE")]
  pub(crate) group: Vec<PathBuf>,
  #[arg(long, value_name = "NDJSON_FILE")]
  pub(crate) input: PathBuf,
  #[arg(long)]
  pub(crate) include_active_rules: bool,
}

#[derive(Debug, Args)]
pub(crate) struct OxiRuleTemplateArgs {
  #[arg(long)]
  pub(crate) name: String,
  #[arg(long = "var", value_name = "KEY=VALUE")]
  pub(crate) vars: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct DynamicPolicyCommand {
  #[command(subcommand)]
  pub(crate) command: DynamicPolicySubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum DynamicPolicySubcommand {
  List,
  Get(IdArg),
  Create(JsonFileArg),
  Patch(PatchJsonArg),
  Delete(IdArg),
  Export,
  Import(JsonFileArg),
}

#[derive(Debug, Args)]
pub(crate) struct IdArg {
  pub(crate) id: i64,
}

#[derive(Debug, Args)]
pub(crate) struct JsonFileArg {
  #[arg(long = "json", value_name = "FILE")]
  pub(crate) json: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct PatchJsonArg {
  pub(crate) id: i64,
  #[arg(long = "json", value_name = "FILE")]
  pub(crate) json: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct JsonInputArg {
  #[arg(value_name = "JSON_OR_FILE")]
  pub(crate) input: String,
}

#[derive(Debug, Args)]
pub(crate) struct MitigationArgs {
  #[command(subcommand)]
  pub(crate) subject: MitigationSubject,
}

#[derive(Debug, Subcommand)]
pub(crate) enum MitigationSubject {
  Ip(MitigationSubjectArgs),
  Cidr(MitigationSubjectArgs),
}

#[derive(Debug, Args)]
pub(crate) struct MitigationSubjectArgs {
  pub(crate) subject: String,
  #[arg(long)]
  pub(crate) ttl: Option<i64>,
  #[arg(long)]
  pub(crate) reason: Option<String>,
  #[arg(long)]
  pub(crate) name: Option<String>,
  #[arg(long, default_value_t = 100)]
  pub(crate) priority: i32,
}

#[derive(Debug, Args)]
pub(crate) struct RateLimitArgs {
  #[command(subcommand)]
  pub(crate) subject: RateLimitSubject,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RateLimitSubject {
  Ip(RateLimitSubjectArgs),
  Cidr(RateLimitSubjectArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RateLimitSubjectArgs {
  pub(crate) subject: String,
  #[arg(long)]
  pub(crate) rate: String,
  #[arg(long)]
  pub(crate) burst: i32,
  #[arg(long)]
  pub(crate) ttl: Option<i64>,
  #[arg(long)]
  pub(crate) reason: Option<String>,
  #[arg(long)]
  pub(crate) name: Option<String>,
  #[arg(long, default_value_t = 100)]
  pub(crate) priority: i32,
}

#[derive(Debug, Args)]
pub(crate) struct CacheCommand {
  #[command(subcommand)]
  pub(crate) command: CacheSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CacheSubcommand {
  Purge(CachePurgeCommand),
  Warm(JsonFileArg),
  KeyExplain(JsonFileArg),
}

#[derive(Debug, Args)]
pub(crate) struct CachePurgeCommand {
  #[command(subcommand)]
  pub(crate) command: CachePurgeSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CachePurgeSubcommand {
  Exact(CacheExactArgs),
  Prefix(CachePrefixArgs),
  Tag(CacheTagArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CacheExactArgs {
  #[arg(long, default_value = "default")]
  pub(crate) policy: String,
  #[arg(long, default_value = "https")]
  pub(crate) scheme: String,
  #[arg(long)]
  pub(crate) host: String,
  #[arg(long)]
  pub(crate) uri: String,
  #[arg(long)]
  pub(crate) partition: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct CachePrefixArgs {
  #[arg(long, default_value = "default")]
  pub(crate) policy: String,
  #[arg(long)]
  pub(crate) scheme: Option<String>,
  #[arg(long)]
  pub(crate) host: Option<String>,
  #[arg(long = "path-prefix")]
  pub(crate) path_prefix: String,
  #[arg(long)]
  pub(crate) partition: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct CacheTagArgs {
  #[arg(long, default_value = "default")]
  pub(crate) policy: String,
  #[arg(long)]
  pub(crate) scheme: Option<String>,
  #[arg(long)]
  pub(crate) host: Option<String>,
  #[arg(long)]
  pub(crate) tag: String,
  #[arg(long)]
  pub(crate) partition: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct IpmCommand {
  #[command(subcommand)]
  pub(crate) command: IpmSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IpmSubcommand {
  List(IpmListArgs),
  Simulate(AuthCheckArgs),
}

#[derive(Debug, Args)]
pub(crate) struct IpmListArgs {
  #[command(subcommand)]
  pub(crate) target: IpmListTarget,
}

#[derive(Debug, Subcommand)]
pub(crate) enum IpmListTarget {
  Principals,
  Credentials,
  Policies,
  Bindings,
}

#[derive(Debug, Args)]
pub(crate) struct AuthCommand {
  #[command(subcommand)]
  pub(crate) command: AuthSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuthSubcommand {
  Check(AuthCheckArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AuthCheckArgs {
  #[arg(long)]
  pub(crate) action: String,
  #[arg(long)]
  pub(crate) resource: String,
}

#[derive(Debug, Args)]
pub(crate) struct FilesCommand {
  #[command(subcommand)]
  pub(crate) command: FilesSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum FilesSubcommand {
  Sync(JsonFileArg),
}

pub(crate) fn selected_token_env(args: &AdminArgs) -> &str {
  if args.break_glass_access {
    BREAK_GLASS_TOKEN_ENV
  } else {
    args.token_env.as_deref().unwrap_or(DEFAULT_ADMIN_TOKEN_ENV)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn token_env_defaults_to_admin_token() {
    let args = test_admin_args(false);
    assert_eq!(selected_token_env(&args), DEFAULT_ADMIN_TOKEN_ENV);
  }

  #[test]
  fn break_glass_access_selects_break_glass_token_env() {
    let args = test_admin_args(true);
    assert_eq!(selected_token_env(&args), BREAK_GLASS_TOKEN_ENV);
  }

  fn test_admin_args(break_glass_access: bool) -> AdminArgs {
    AdminArgs {
      admin_url: Url::parse(DEFAULT_ADMIN_URL).expect("url"),
      token_env: None,
      token_file: None,
      break_glass_access,
      ca_certs: Vec::new(),
      client_cert: None,
      client_key: None,
      timeout_ms: 1000,
      output: OutputFormat::PrettyJson,
    }
  }
}
