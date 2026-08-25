use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Parser;
use oxibelt::remote_signer::{
  self, CtLogProfile, DEFAULT_REMOTE_SIGNER_IO_TIMEOUT_MS, DEFAULT_REMOTE_SIGNER_MAX_CONNECTIONS,
  DEFAULT_REMOTE_SIGNER_TOKEN_RELOAD_INTERVAL_MS, SignerServerConfig,
};

#[derive(Debug, Parser)]
#[command(name = "oxibelt-keysigner")]
#[command(about = "OxiBelt purpose-bound IPC private-key signer")]
#[command(
  version = oxibelt_build_identity::SHORT_VERSION,
  long_version = oxibelt_build_identity::LONG_VERSION
)]
struct Cli {
  #[arg(long, value_name = "PATH")]
  socket: PathBuf,

  #[arg(long = "key", value_name = "KEY_ID=PRIVATE_KEY_PEM", value_parser = parse_key)]
  keys: Vec<(String, PathBuf)>,

  #[arg(
    long = "audit-checkpoint-key",
    value_name = "KEY_ID=ED25519_PRIVATE_KEY_PEM",
    value_parser = parse_audit_checkpoint_key
  )]
  audit_checkpoint_keys: Vec<(String, PathBuf)>,

  #[arg(long = "ct-log-key", value_name = "KEY_ID=PRIVATE_KEY_PEM", value_parser = parse_key)]
  ct_log_keys: Vec<(String, PathBuf)>,

  #[arg(long = "ct-log-profile", value_name = "KEY_ID=PROFILE", value_parser = parse_ct_log_profile)]
  ct_log_profiles: Vec<(String, CtLogProfile)>,

  #[arg(long, default_value = "OXIBELT_KEYSIGNER_TOKEN")]
  token_env: String,

  #[arg(long, value_name = "PATH")]
  token_file: Option<PathBuf>,

  #[arg(long, default_value_t = DEFAULT_REMOTE_SIGNER_TOKEN_RELOAD_INTERVAL_MS, value_parser = parse_nonzero_u64)]
  token_reload_interval_ms: u64,

  #[arg(long, default_value = "0660", value_parser = parse_socket_mode)]
  socket_mode: u32,

  #[arg(long, default_value_t = DEFAULT_REMOTE_SIGNER_MAX_CONNECTIONS, value_parser = parse_nonzero_usize)]
  max_connections: usize,

  #[arg(long, default_value_t = DEFAULT_REMOTE_SIGNER_IO_TIMEOUT_MS, value_parser = parse_nonzero_u64)]
  io_timeout_ms: u64,

  #[arg(long = "allow-peer-uid")]
  allow_peer_uids: Vec<u32>,

  #[arg(long = "allow-peer-gid")]
  allow_peer_gids: Vec<u32>,

  #[arg(long)]
  allow_tls12_unstructured_signing: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let cli = Cli::parse();
  oxibelt::runtime::init_tracing(&oxibelt::config::LoggingConfig::default())?;
  oxibelt::tls::install_default_provider()?;
  let ct_log_key = resolve_ct_log_key(&cli.ct_log_keys, &cli.ct_log_profiles)?;
  remote_signer::serve_with_audit_checkpoint_keys(
    SignerServerConfig {
      socket_path: cli.socket,
      socket_mode: cli.socket_mode,
      keys: cli.keys,
      ct_log_key,
      token_env: cli.token_env,
      token_file: cli.token_file,
      token_reload_interval: Duration::from_millis(cli.token_reload_interval_ms),
      max_connections: cli.max_connections,
      io_timeout: Duration::from_millis(cli.io_timeout_ms),
      allow_peer_uids: cli.allow_peer_uids,
      allow_peer_gids: cli.allow_peer_gids,
      allow_tls12_unstructured_signing: cli.allow_tls12_unstructured_signing,
    },
    cli.audit_checkpoint_keys,
  )
  .await
}

fn resolve_ct_log_key(
  keys: &[(String, PathBuf)],
  profiles: &[(String, CtLogProfile)],
) -> anyhow::Result<Option<(String, CtLogProfile, PathBuf)>> {
  if keys.is_empty() && profiles.is_empty() {
    return Ok(None);
  }
  if keys.len() != 1 || profiles.len() != 1 {
    bail!(
      "CT log signer requires exactly one --ct-log-key and one matching --ct-log-profile; rotate by creating a new CT log signer daemon"
    );
  }
  let (key_id, key_path) = &keys[0];
  let (profile_key_id, profile) = profiles[0];
  if key_id != profile_key_id {
    bail!("--ct-log-profile key id must match --ct-log-key");
  }
  Ok(Some((key_id.clone(), profile, key_path.clone())))
}

fn parse_key(value: &str) -> anyhow::Result<(String, PathBuf)> {
  let Some((key_id, path)) = value.split_once('=') else {
    bail!("--key must use KEY_ID=PRIVATE_KEY_PEM");
  };
  if key_id.trim().is_empty() {
    bail!("--key key id must not be empty");
  }
  if path.trim().is_empty() {
    bail!("--key private key path must not be empty");
  }
  Ok((key_id.to_string(), PathBuf::from(path)))
}

fn parse_audit_checkpoint_key(value: &str) -> anyhow::Result<(String, PathBuf)> {
  let Some((key_id, path)) = value.split_once('=') else {
    bail!("--audit-checkpoint-key must use KEY_ID=ED25519_PRIVATE_KEY_PEM");
  };
  if key_id.trim().is_empty() {
    bail!("--audit-checkpoint-key key id must not be empty");
  }
  if path.trim().is_empty() {
    bail!("--audit-checkpoint-key private key path must not be empty");
  }
  Ok((key_id.to_string(), PathBuf::from(path)))
}

fn parse_ct_log_profile(value: &str) -> anyhow::Result<(String, CtLogProfile)> {
  let Some((key_id, profile)) = value.split_once('=') else {
    bail!("--ct-log-profile must use KEY_ID=PROFILE");
  };
  if key_id.trim().is_empty() {
    bail!("--ct-log-profile key id must not be empty");
  }
  let profile = match profile {
    "rfc6962_p256_sha256" => CtLogProfile::Rfc6962P256Sha256,
    "rfc9162_p256_sha256" => CtLogProfile::Rfc9162P256Sha256,
    "rfc9162_ed25519" => CtLogProfile::Rfc9162Ed25519,
    _ => bail!(
      "--ct-log-profile must use one of {}",
      CtLogProfile::WIRE_VALUES.join(", ")
    ),
  };
  Ok((key_id.to_string(), profile))
}

fn parse_socket_mode(value: &str) -> anyhow::Result<u32> {
  u32::from_str_radix(value.trim_start_matches('0'), 8)
    .with_context(|| format!("invalid octal socket mode {value}"))
}

fn parse_nonzero_usize(value: &str) -> anyhow::Result<usize> {
  let parsed = value
    .parse::<usize>()
    .with_context(|| format!("invalid positive integer {value}"))?;
  if parsed == 0 {
    bail!("value must be greater than 0");
  }
  Ok(parsed)
}

fn parse_nonzero_u64(value: &str) -> anyhow::Result<u64> {
  let parsed = value
    .parse::<u64>()
    .with_context(|| format!("invalid positive integer {value}"))?;
  if parsed == 0 {
    bail!("value must be greater than 0");
  }
  Ok(parsed)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn version_flag_reports_canonical_build_identity() {
    let error = Cli::try_parse_from(["oxibelt-keysigner", "--version"])
      .expect_err("--version should exit through Clap");
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
    assert!(
      error
        .to_string()
        .contains(oxibelt_build_identity::MACHINE_IDENTITY_MARKER)
    );
  }

  #[test]
  fn cli_accepts_an_audit_only_keyset() {
    let cli = Cli::try_parse_from([
      "oxibelt-keysigner",
      "--socket",
      "/run/oxibelt/audit.sock",
      "--audit-checkpoint-key",
      "audit-2026=/run/keys/audit.pem",
      "--audit-checkpoint-key",
      "audit-next=/run/keys/audit-next.pem",
    ])
    .expect("audit-only CLI should parse");

    assert!(cli.keys.is_empty());
    assert_eq!(cli.audit_checkpoint_keys.len(), 2);
  }

  #[test]
  fn audit_checkpoint_key_rejects_missing_id_or_path() {
    assert!(parse_audit_checkpoint_key("=/run/keys/audit.pem").is_err());
    assert!(parse_audit_checkpoint_key("audit=").is_err());
    assert!(parse_audit_checkpoint_key("audit").is_err());
  }

  #[test]
  fn ct_log_key_requires_one_matching_immutable_profile() {
    let key = ("log-2026".to_string(), PathBuf::from("/run/keys/log.pem"));
    let profile = ("log-2026".to_string(), CtLogProfile::Rfc9162Ed25519);
    assert!(matches!(
      resolve_ct_log_key(&[key.clone()], &[profile]),
      Ok(Some((key_id, CtLogProfile::Rfc9162Ed25519, _))) if key_id == "log-2026"
    ));
    assert!(resolve_ct_log_key(&[key.clone(), key.clone()], &[]).is_err());
    assert!(
      resolve_ct_log_key(
        &[key],
        &[("other".to_string(), CtLogProfile::Rfc9162Ed25519)],
      )
      .is_err()
    );
  }

  #[test]
  fn ct_log_profile_parser_rejects_unknown_profiles() {
    assert!(parse_ct_log_profile("log=future").is_err());
    assert!(parse_ct_log_profile("=rfc9162_ed25519").is_err());
  }
}
