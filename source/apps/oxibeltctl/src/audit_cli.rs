use std::path::PathBuf;

use clap::{Args, Subcommand};

pub(crate) const DEFAULT_LOCAL_AUDIT_POSTGRES_URL_ENV: &str =
  "OXIBELT_AUDIT_VERIFY_LOCAL_POSTGRES_URL";
pub(crate) const DEFAULT_ANCHOR_POSTGRES_URL_ENV: &str = "OXIBELT_AUDIT_VERIFY_ANCHOR_POSTGRES_URL";

#[derive(Debug, Args)]
pub(crate) struct AdminAuditArgs {
  #[command(subcommand)]
  pub(crate) command: Option<AdminAuditSubcommand>,
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

#[derive(Debug, Subcommand)]
pub(crate) enum AdminAuditSubcommand {
  /// Verify local audit evidence against externally anchored checkpoints.
  Verify(AdminAuditVerifyArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AdminAuditVerifyArgs {
  /// Environment variable containing the read-only local audit PostgreSQL URL.
  #[arg(
    long,
    value_name = "ENV",
    default_value = DEFAULT_LOCAL_AUDIT_POSTGRES_URL_ENV
  )]
  pub(crate) local_postgres_url_env: String,
  /// Environment variable containing the read-only external anchor PostgreSQL URL.
  #[arg(
    long,
    value_name = "ENV",
    default_value = DEFAULT_ANCHOR_POSTGRES_URL_ENV
  )]
  pub(crate) anchor_postgres_url_env: String,
  /// Manifest naming the exact audit streams expected for this verification.
  #[arg(long, value_name = "FILE")]
  pub(crate) expected_streams: PathBuf,
  /// Trusted Ed25519 public key in KEY_ID=FILE form. May be repeated for rotation.
  #[arg(long = "trusted-key", value_name = "KEY_ID=FILE", required = true)]
  pub(crate) trusted_keys: Vec<String>,
  /// Trusted raw 32-byte local-chain HMAC key in KEY_ID=FILE form. Repeat for rotation.
  #[arg(long = "trusted-hmac-key", value_name = "KEY_ID=FILE")]
  pub(crate) trusted_hmac_keys: Vec<String>,
  /// Maximum local audit events loaded across all expected streams.
  #[arg(long, default_value_t = 1_000_000, value_parser = clap::value_parser!(u64).range(1..=10_000_000))]
  pub(crate) max_events: u64,
  /// Maximum external checkpoints loaded across all expected streams.
  #[arg(long, default_value_t = 100_000, value_parser = clap::value_parser!(u64).range(1..=1_000_000))]
  pub(crate) max_checkpoints: u64,
  /// Maximum serialized evidence bytes loaded across local events and checkpoints.
  #[arg(long, default_value_t = 536_870_912, value_parser = clap::value_parser!(u64).range(131_072..=17_179_869_184))]
  pub(crate) max_evidence_bytes: u64,
  /// Maximum bytes accepted for one event; match the producer's max_event_bytes.
  #[arg(long, default_value_t = 131_072, value_parser = clap::value_parser!(u64).range(1_024..=67_108_864))]
  pub(crate) max_event_bytes: u64,
  /// Maximum serialized bytes accepted for one external checkpoint.
  #[arg(long, default_value_t = 65_536, value_parser = clap::value_parser!(u64).range(4_096..=16_777_216))]
  pub(crate) max_checkpoint_bytes: u64,
  /// Durable verifier witness used to detect rollback of the external authority.
  #[arg(long, value_name = "FILE")]
  pub(crate) witness: PathBuf,
  /// Explicitly initialize a missing witness after all other verification succeeds.
  #[arg(long)]
  pub(crate) initialize_witness: bool,
}
