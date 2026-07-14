use std::path::PathBuf;

use clap::Args;

pub(crate) const DEFAULT_MUTATION_NAMESPACE: &str = "oxibelt";
pub(crate) const DEFAULT_MUTATION_VALIDITY_SECONDS: u64 = 300;

#[derive(Debug, Args, Default)]
pub(crate) struct MutationArgs {
  /// Sign high-risk Admin mutations with X-OxiBelt-Mutation.
  #[arg(long = "sign-mutation")]
  pub(crate) enabled: bool,
  #[arg(long = "mutation-signer-id", requires = "enabled")]
  pub(crate) signer_id: Option<String>,
  #[arg(long = "mutation-principal", requires = "enabled")]
  pub(crate) principal: Option<String>,
  #[arg(
    long = "mutation-ed25519-key-file",
    value_name = "FILE",
    requires = "enabled",
    conflicts_with = "ed25519_key_file_env"
  )]
  pub(crate) ed25519_key_file: Option<PathBuf>,
  /// Read the Ed25519 private-key file path from this environment variable.
  #[arg(
    long = "mutation-ed25519-key-file-env",
    value_name = "ENV",
    requires = "enabled",
    conflicts_with = "ed25519_key_file"
  )]
  pub(crate) ed25519_key_file_env: Option<String>,
  #[arg(
    long = "mutation-ml-dsa-44-key-file",
    value_name = "FILE",
    requires = "enabled",
    conflicts_with = "ml_dsa_44_key_file_env"
  )]
  pub(crate) ml_dsa_44_key_file: Option<PathBuf>,
  /// Read the ML-DSA-44 private-key file path from this environment variable.
  #[arg(
    long = "mutation-ml-dsa-44-key-file-env",
    value_name = "ENV",
    requires = "enabled",
    conflicts_with = "ml_dsa_44_key_file"
  )]
  pub(crate) ml_dsa_44_key_file_env: Option<String>,
  #[arg(long = "mutation-namespace", default_value = DEFAULT_MUTATION_NAMESPACE, requires = "enabled")]
  pub(crate) namespace: String,
  #[arg(long = "mutation-expected-revision", requires = "enabled")]
  pub(crate) expected_revision: Option<String>,
  #[arg(long = "mutation-new-revision", requires = "enabled")]
  pub(crate) new_revision: Option<String>,
  #[arg(long = "mutation-cluster-id", requires = "enabled")]
  pub(crate) cluster_id: Option<String>,
  #[arg(long = "mutation-membership-revision", requires = "enabled")]
  pub(crate) membership_revision: Option<String>,
  /// Reuse this UUID to retry the exact same mutation after an uncertain response.
  #[arg(long = "mutation-request-id", requires = "enabled")]
  pub(crate) request_id: Option<String>,
  /// Preserve this canonical UTC issuance time when retrying an exact mutation.
  #[arg(
    long = "mutation-issued-at",
    value_name = "YYYY-MM-DDTHH:MM:SSZ",
    requires_all = ["enabled", "expires_at"]
  )]
  pub(crate) issued_at: Option<String>,
  /// Preserve this canonical UTC expiration time when retrying an exact mutation.
  #[arg(
    long = "mutation-expires-at",
    value_name = "YYYY-MM-DDTHH:MM:SSZ",
    requires_all = ["enabled", "issued_at"]
  )]
  pub(crate) expires_at: Option<String>,
  #[arg(
    long = "mutation-validity-seconds",
    default_value_t = DEFAULT_MUTATION_VALIDITY_SECONDS,
    value_parser = clap::value_parser!(u64).range(1..=3_600),
    requires = "enabled"
  )]
  pub(crate) validity_seconds: u64,
}
