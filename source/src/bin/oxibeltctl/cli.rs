use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use oxibelt::admin_client::{BREAK_GLASS_TOKEN_ENV, DEFAULT_ADMIN_TOKEN_ENV, DEFAULT_ADMIN_URL};
use oxibelt::diagnostics::{DoctorFailOn, DoctorOutputFormat, ExternalProbeKind};
use url::Url;

#[path = "ipm_cli.rs"]
mod ipm_cli;
#[path = "rulepack_cli.rs"]
mod rulepack_cli;
pub(crate) use ipm_cli::*;
pub(crate) use rulepack_cli::*;

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
  Audit(AdminAuditArgs),
  Doctor(DoctorArgs),
  SupportBundle(SupportBundleArgs),
  Runtime(RuntimeCommand),
  Config(ConfigCommand),
  Tls(TlsCommand),
  Lifecycle(LifecycleCommand),
  Pool(PoolCommand),
  Waf(WafCommand),
  OxiRule(OxiRuleCommand),
  Rulepack(RulepackCommand),
  DynamicPolicy(DynamicPolicyCommand),
  Block(MitigationArgs),
  Allow(MitigationArgs),
  Challenge(ChallengeArgs),
  RateLimit(RateLimitArgs),
  Mitigate(MitigateArgs),
  Cache(CacheCommand),
  Ipm(IpmCommand),
  Auth(AuthCommand),
  Files(FilesCommand),
}

#[derive(Debug, Args)]
pub(crate) struct AdminAuditArgs {
  #[arg(long)]
  pub(crate) outcome: Option<String>,
  #[arg(long)]
  pub(crate) actor: Option<String>,
  #[arg(long)]
  pub(crate) principal: Option<String>,
  #[arg(long)]
  pub(crate) service: Option<String>,
  #[arg(long)]
  pub(crate) operation: Option<String>,
  #[arg(long = "request-id")]
  pub(crate) request_id: Option<String>,
  #[arg(long = "path-prefix")]
  pub(crate) path_prefix: Option<String>,
  #[arg(long = "before-id")]
  pub(crate) before_id: Option<i64>,
  #[arg(long, default_value_t = 100)]
  pub(crate) limit: i64,
}

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
  #[arg(long, value_name = "FILE", conflicts_with = "candidate")]
  pub(crate) config: Option<PathBuf>,
  #[arg(long, value_name = "FILE")]
  pub(crate) candidate: Option<PathBuf>,
  #[arg(long, value_name = "FORMAT", value_parser = parse_doctor_output_format, default_value = "text")]
  pub(crate) format: DoctorOutputFormat,
  #[arg(long = "fail-on", value_name = "SEVERITY", value_parser = parse_doctor_fail_on, default_value = "error")]
  pub(crate) fail_on: DoctorFailOn,
  #[arg(long = "external-probe", value_name = "KIND", value_parser = parse_external_probe)]
  pub(crate) external_probes: Vec<ExternalProbeKind>,
}

#[derive(Debug, Args)]
pub(crate) struct SupportBundleArgs {
  #[arg(long, required = true)]
  pub(crate) redact: bool,
  #[arg(long = "external-probe", value_name = "KIND")]
  pub(crate) external_probes: Vec<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RuntimeCommand {
  #[command(subcommand)]
  pub(crate) command: RuntimeSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RuntimeSubcommand {
  Introspection(RuntimeIntrospectionArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RuntimeIntrospectionArgs {
  #[arg(long, required = true)]
  pub(crate) redact: bool,
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
  Apply(JsonFileArg),
  Patch(PatchJsonArg),
  Delete(IdArg),
  Audit(DynamicPolicyAuditArgs),
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
pub(crate) struct DynamicPolicyAuditArgs {
  #[arg(long)]
  pub(crate) policy_id: Option<i64>,
  #[arg(long, default_value_t = 100)]
  pub(crate) limit: i64,
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

#[derive(Clone, Debug, Subcommand)]
pub(crate) enum MitigationSubject {
  Ip(MitigationSubjectArgs),
  Cidr(MitigationSubjectArgs),
}

#[derive(Clone, Debug, Args)]
pub(crate) struct MitigationSubjectArgs {
  pub(crate) subject: String,
  #[arg(long, value_parser = parse_ttl_seconds)]
  pub(crate) ttl: Option<i64>,
  #[arg(long)]
  pub(crate) reason: Option<String>,
  #[arg(long)]
  pub(crate) name: Option<String>,
  #[arg(long, default_value_t = 100)]
  pub(crate) priority: i32,
  #[arg(long)]
  pub(crate) route: Option<String>,
  #[arg(long = "path-prefix")]
  pub(crate) path_prefix: Option<String>,
  #[arg(long)]
  pub(crate) method: Option<String>,
  #[arg(long)]
  pub(crate) dry_run: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ChallengeArgs {
  #[arg(long = "person-proof", required = true)]
  pub(crate) person_proof: bool,
  #[command(subcommand)]
  pub(crate) subject: MitigationSubject,
}

#[derive(Debug, Args)]
pub(crate) struct RateLimitArgs {
  #[command(subcommand)]
  pub(crate) subject: RateLimitSubject,
}

#[derive(Debug, Subcommand)]
pub(crate) enum RateLimitSubject {
  Source(RateLimitSubjectArgs),
  Ip(RateLimitSubjectArgs),
  Cidr(RateLimitSubjectArgs),
}

#[derive(Debug, Args)]
pub(crate) struct RateLimitSubjectArgs {
  pub(crate) subject: String,
  #[arg(long, conflicts_with = "rps")]
  pub(crate) rate: Option<String>,
  #[arg(long, conflicts_with = "rate")]
  pub(crate) rps: Option<f64>,
  #[arg(long)]
  pub(crate) burst: Option<i32>,
  #[arg(long, value_parser = parse_ttl_seconds)]
  pub(crate) ttl: Option<i64>,
  #[arg(long)]
  pub(crate) reason: Option<String>,
  #[arg(long)]
  pub(crate) name: Option<String>,
  #[arg(long, default_value_t = 100)]
  pub(crate) priority: i32,
  #[arg(long)]
  pub(crate) route: Option<String>,
  #[arg(long = "path-prefix")]
  pub(crate) path_prefix: Option<String>,
  #[arg(long)]
  pub(crate) method: Option<String>,
  #[arg(long)]
  pub(crate) dry_run: bool,
}

#[derive(Debug, Args)]
pub(crate) struct MitigateArgs {
  pub(crate) profile: String,
  #[arg(
    long = "profile-file",
    value_name = "FILE",
    required_unless_present = "profile_url",
    conflicts_with = "profile_url"
  )]
  pub(crate) profile_file: Option<PathBuf>,
  #[arg(
    long = "profile-url",
    value_name = "URL",
    required_unless_present = "profile_file",
    conflicts_with = "profile_file"
  )]
  pub(crate) profile_url: Option<Url>,
  #[arg(
    long = "profile-ca-cert",
    value_name = "FILE",
    requires = "profile_url"
  )]
  pub(crate) profile_ca_certs: Vec<PathBuf>,
  #[arg(long = "profile-token-env", requires = "profile_url")]
  pub(crate) profile_token_env: Option<String>,
  #[arg(long = "profile-sha256", requires = "profile_url")]
  pub(crate) profile_sha256: Option<String>,
  #[arg(long = "allow-insecure-profile-url", requires = "profile_url")]
  pub(crate) allow_insecure_profile_url: bool,
  #[arg(long)]
  pub(crate) source: String,
  #[arg(long, value_parser = parse_ttl_seconds)]
  pub(crate) ttl: Option<i64>,
  #[arg(long)]
  pub(crate) reason: Option<String>,
  #[arg(long)]
  pub(crate) name: Option<String>,
  #[arg(long)]
  pub(crate) priority: Option<i32>,
  #[arg(long)]
  pub(crate) route: Option<String>,
  #[arg(long = "path-prefix")]
  pub(crate) path_prefix: Option<String>,
  #[arg(long)]
  pub(crate) method: Option<String>,
  #[arg(long)]
  pub(crate) dry_run: bool,
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

fn parse_ttl_seconds(value: &str) -> Result<i64, String> {
  let value = value.trim();
  if value.is_empty() {
    return Err("ttl must not be empty".to_string());
  }
  let (number, multiplier) = match value.as_bytes().last().copied() {
    Some(b's') | Some(b'S') => (&value[..value.len() - 1], 1_i64),
    Some(b'm') | Some(b'M') => (&value[..value.len() - 1], 60_i64),
    Some(b'h') | Some(b'H') => (&value[..value.len() - 1], 3_600_i64),
    Some(b'd') | Some(b'D') => (&value[..value.len() - 1], 86_400_i64),
    Some(byte) if byte.is_ascii_digit() => (value, 1_i64),
    _ => return Err("ttl must be seconds or use s, m, h, or d suffix".to_string()),
  };
  let amount = number
    .parse::<i64>()
    .map_err(|_| "ttl amount must be an integer".to_string())?;
  if amount <= 0 {
    return Err("ttl must be greater than 0".to_string());
  }
  amount
    .checked_mul(multiplier)
    .ok_or_else(|| "ttl is too large".to_string())
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
