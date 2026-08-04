use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Args)]
pub(crate) struct SupplyChainCommand {
  #[command(subcommand)]
  pub(crate) command: SupplyChainSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SupplyChainSubcommand {
  /// Verify exact GitHub-hosted release evidence and write a signed admission bundle.
  #[command(name = "admission-bundle")]
  AdmissionBundle(SupplyChainAdmissionBundleArgs),
  /// Serve a credential-free Kubernetes validating admission webhook.
  #[command(name = "admission-server")]
  AdmissionServer(SupplyChainAdmissionServerArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum SupplyChainRole {
  Standalone,
  Dataplane,
  #[value(name = "dataplane-strict")]
  DataplaneStrict,
  Controller,
  Tools,
  Keysigner,
}

impl SupplyChainRole {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Standalone => "standalone",
      Self::Dataplane => "dataplane",
      Self::DataplaneStrict => "dataplane-strict",
      Self::Controller => "controller",
      Self::Tools => "tools",
      Self::Keysigner => "keysigner",
    }
  }

  pub(crate) const fn repository(self) -> &'static str {
    match self {
      Self::Standalone => "ghcr.io/oxibelt/oxibelt",
      Self::Dataplane => "ghcr.io/oxibelt/oxibelt-dataplane",
      Self::DataplaneStrict => "ghcr.io/oxibelt/oxibelt-dataplane-strict",
      Self::Controller => "ghcr.io/oxibelt/oxibelt-gateway-controller",
      Self::Tools => "ghcr.io/oxibelt/oxibelt-tools",
      Self::Keysigner => "ghcr.io/oxibelt/oxibelt-keysigner",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum SupplyChainReleaseChannel {
  Stable,
  Beta,
}

impl SupplyChainReleaseChannel {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Stable => "stable",
      Self::Beta => "beta",
    }
  }
}

#[derive(Debug, Args)]
pub(crate) struct SupplyChainAdmissionBundleArgs {
  #[arg(long)]
  pub(crate) repository: String,
  #[arg(long, value_enum)]
  pub(crate) role: SupplyChainRole,
  #[arg(long)]
  pub(crate) digest: String,
  #[arg(long = "source-ref")]
  pub(crate) source_ref: String,
  #[arg(long = "source-revision")]
  pub(crate) source_revision: String,
  #[arg(long = "release-channel", value_enum, default_value_t = SupplyChainReleaseChannel::Stable)]
  pub(crate) release_channel: SupplyChainReleaseChannel,
  /// Successful automatic `verify-release-rebuild.yml` run containing all role/architecture receipts.
  #[arg(long = "independent-rebuild-run-id")]
  pub(crate) independent_rebuild_run_id: u64,
  /// Approved full Git revision of the verifier workflow used by that run.
  #[arg(long = "independent-rebuild-workflow-sha")]
  pub(crate) independent_rebuild_workflow_sha: String,
  #[arg(long = "revocations", value_name = "FILE")]
  pub(crate) revocations: Option<PathBuf>,
  /// Strict auxiliary-container approvals to include in the signed v2 bundle.
  #[arg(long = "workload-policy", value_name = "FILE")]
  pub(crate) workload_policy: Option<PathBuf>,
  /// Verification time as Unix seconds; defaults to the current clock.
  #[arg(long = "verification-time")]
  pub(crate) verification_time: Option<u64>,
  #[arg(long = "max-evidence-age-seconds", default_value_t = 604_800)]
  pub(crate) max_evidence_age_seconds: u64,
  #[arg(long = "expires-after-seconds", default_value_t = 86_400)]
  pub(crate) expires_after_seconds: u64,
  #[arg(long = "signing-key-file", value_name = "FILE")]
  pub(crate) signing_key_file: PathBuf,
  /// Write the corresponding raw 32-byte Ed25519 public key.
  #[arg(long = "public-key-output", value_name = "FILE")]
  pub(crate) public_key_output: Option<PathBuf>,
  #[arg(long = "key-id")]
  pub(crate) key_id: String,
  #[arg(long, value_name = "FILE")]
  pub(crate) output: PathBuf,
  #[arg(long)]
  pub(crate) force: bool,
}

#[derive(Debug, Args)]
pub(crate) struct SupplyChainAdmissionServerArgs {
  #[arg(long, value_name = "FILE")]
  pub(crate) bundle: PathBuf,
  #[arg(long = "public-key-file", value_name = "FILE")]
  pub(crate) public_key_file: PathBuf,
  #[arg(long = "key-id")]
  pub(crate) key_id: String,
  #[arg(long = "revocations", value_name = "FILE")]
  pub(crate) revocations: Option<PathBuf>,
  #[arg(long = "tls-cert", value_name = "FILE")]
  pub(crate) tls_cert: PathBuf,
  #[arg(long = "tls-key", value_name = "FILE")]
  pub(crate) tls_key: PathBuf,
  #[arg(long, default_value = "0.0.0.0:8443")]
  pub(crate) listen: SocketAddr,
}
