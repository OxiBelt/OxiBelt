use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};
use url::Url;

pub(crate) const DEFAULT_CT_POSTGRES_URL_ENV: &str = "OXIBELT_CT_POSTGRES_URL";

#[derive(Debug, Args)]
pub(crate) struct CtCommand {
  #[command(subcommand)]
  pub(crate) command: CtSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CtSubcommand {
  Postgres(CtPostgresCommand),
  Roots(CtRootsCommand),
  Shard(CtShardCommand),
  Monitor(CtMonitorArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CtPostgresCommand {
  #[command(subcommand)]
  pub(crate) command: CtPostgresSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CtPostgresSubcommand {
  /// Apply the explicit Certificate Transparency PostgreSQL schema migration.
  Migrate(CtPostgresArgs),
  /// Read and validate CT schema and database capability state without mutating it.
  #[command(name = "storage-check")]
  StorageCheck(CtPostgresArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CtPostgresArgs {
  /// Environment variable containing the PostgreSQL URL.
  #[arg(long, value_name = "ENV", conflicts_with = "database_url_file")]
  pub(crate) database_url_env: Option<String>,
  /// File containing the PostgreSQL URL. Prefer a mounted secret with mode 0600.
  #[arg(long, value_name = "FILE")]
  pub(crate) database_url_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct CtRootsCommand {
  #[command(subcommand)]
  pub(crate) command: CtRootsSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CtRootsSubcommand {
  /// Build a canonical unsigned accepted-root bundle.
  Build(CtRootsBuildArgs),
  /// Add or replace one Ed25519 signature on a canonical bundle.
  Sign(CtRootsSignArgs),
  /// Verify the digest, canonical encoding, roots, and signature threshold.
  Verify(CtRootsVerifyArgs),
  /// Compare two accepted-root bundles without trusting their signatures.
  Diff(CtRootsDiffArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CtRootsBuildArgs {
  #[arg(long, value_name = "ID")]
  pub(crate) snapshot_id: String,
  #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
  pub(crate) serial: u64,
  #[arg(long, value_name = "UNIX_SECONDS")]
  pub(crate) created_at: i64,
  #[arg(long = "root", value_name = "CERTIFICATE", required = true)]
  pub(crate) roots: Vec<PathBuf>,
  #[arg(long, value_name = "FILE")]
  pub(crate) output: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CtRootsSignArgs {
  #[arg(long, value_name = "FILE")]
  pub(crate) bundle: PathBuf,
  #[arg(long, value_name = "ID")]
  pub(crate) key_id: String,
  #[arg(long, value_name = "PKCS8_KEY")]
  pub(crate) private_key: PathBuf,
  #[arg(long, value_name = "FILE")]
  pub(crate) output: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CtRootsVerifyArgs {
  #[arg(long, value_name = "FILE")]
  pub(crate) bundle: PathBuf,
  /// Trusted raw 32-byte Ed25519 public key in KEY_ID=FILE form.
  #[arg(long = "trusted-key", value_name = "KEY_ID=FILE", required = true)]
  pub(crate) trusted_keys: Vec<String>,
  #[arg(long, value_parser = parse_root_threshold)]
  pub(crate) threshold: usize,
  #[arg(long)]
  pub(crate) production: bool,
  /// Expected sha256:<lowercase-hex>. Defaults to the bundle's current digest.
  #[arg(long, value_name = "DIGEST")]
  pub(crate) expected_digest: Option<String>,
}

fn parse_root_threshold(value: &str) -> Result<usize, String> {
  let threshold = value
    .parse::<usize>()
    .map_err(|_| "threshold must be an integer within 1..=32".to_string())?;
  if !(1..=32).contains(&threshold) {
    return Err("threshold must be within 1..=32".to_string());
  }
  Ok(threshold)
}

#[derive(Debug, Args)]
pub(crate) struct CtRootsDiffArgs {
  pub(crate) old: PathBuf,
  pub(crate) new: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CtShardCommand {
  #[command(subcommand)]
  pub(crate) command: CtShardSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CtShardSubcommand {
  /// Generate a bounded contiguous shard schedule.
  Plan(CtShardPlanArgs),
  /// Validate a shard schedule and its canonical encoding.
  Validate(CtShardValidateArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CtProtocolArg {
  #[value(name = "rfc6962-v1")]
  Rfc6962V1,
  #[value(name = "rfc9162-v2")]
  Rfc9162V2,
}

#[derive(Debug, Args)]
pub(crate) struct CtShardPlanArgs {
  #[arg(long, value_name = "PREFIX")]
  pub(crate) log_prefix: String,
  #[arg(long, value_enum)]
  pub(crate) protocol: CtProtocolArg,
  #[arg(long, value_name = "UNIX_SECONDS")]
  pub(crate) start: i64,
  #[arg(long, value_name = "UNIX_SECONDS")]
  pub(crate) end: i64,
  #[arg(long, default_value_t = 31_536_000, value_parser = clap::value_parser!(u64).range(86_400..=126_230_400))]
  pub(crate) period_seconds: u64,
  #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=86_400))]
  pub(crate) mmd_seconds: u64,
  #[arg(long, default_value_t = 604_800, value_parser = clap::value_parser!(u64).range(86_400..=31_536_000))]
  pub(crate) preprovision_seconds: u64,
  #[arg(long, value_name = "FILE")]
  pub(crate) output: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CtShardValidateArgs {
  pub(crate) file: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CtMonitorArgs {
  /// RFC 6962 log base URL.
  #[arg(long)]
  pub(crate) url: Url,
  /// Expected 32-byte RFC 6962 LogID as 64 lowercase hexadecimal characters.
  #[arg(long, value_name = "HEX")]
  pub(crate) log_id: String,
  /// Raw 65-byte uncompressed P-256 log public key.
  #[arg(long, value_name = "FILE")]
  pub(crate) public_key: PathBuf,
  /// Additional PEM trust roots for the CT log HTTPS endpoint.
  #[arg(long = "log-ca-cert", value_name = "FILE")]
  pub(crate) ca_certs: Vec<PathBuf>,
  /// Durable consistency witness updated only after successful verification.
  #[arg(long, value_name = "FILE")]
  pub(crate) witness: PathBuf,
  /// Explicitly create a missing witness from the first verified STH.
  #[arg(long)]
  pub(crate) initialize_witness: bool,
  /// Permit plaintext HTTP only for loopback development endpoints.
  #[arg(long)]
  pub(crate) allow_loopback_http: bool,
  #[arg(long, default_value_t = 10_000, value_parser = clap::value_parser!(u64).range(100..=120_000))]
  pub(crate) timeout_ms: u64,
  /// Reject an otherwise valid STH older than this availability window.
  #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(60..=86_400))]
  pub(crate) max_sth_age_seconds: u64,
}
