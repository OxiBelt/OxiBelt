use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::Parser;
use oxibelt::remote_signer::{
  self, DEFAULT_REMOTE_SIGNER_IO_TIMEOUT_MS, DEFAULT_REMOTE_SIGNER_MAX_CONNECTIONS,
  SignerServerConfig,
};

#[derive(Debug, Parser)]
#[command(name = "oxibelt-keysigner")]
#[command(about = "OxiBelt IPC remote TLS private-key signer")]
struct Cli {
  #[arg(long, value_name = "PATH")]
  socket: PathBuf,

  #[arg(long = "key", value_name = "KEY_ID=PRIVATE_KEY_PEM", value_parser = parse_key)]
  keys: Vec<(String, PathBuf)>,

  #[arg(long, default_value = "OXIBELT_KEYSIGNER_TOKEN")]
  token_env: String,

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
  oxibelt::tls::install_default_provider()?;
  remote_signer::serve(SignerServerConfig {
    socket_path: cli.socket,
    socket_mode: cli.socket_mode,
    keys: cli.keys,
    token_env: cli.token_env,
    max_connections: cli.max_connections,
    io_timeout: Duration::from_millis(cli.io_timeout_ms),
    allow_peer_uids: cli.allow_peer_uids,
    allow_peer_gids: cli.allow_peer_gids,
    allow_tls12_unstructured_signing: cli.allow_tls12_unstructured_signing,
  })
  .await
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
