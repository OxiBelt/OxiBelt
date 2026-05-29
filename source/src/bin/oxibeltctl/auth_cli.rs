use std::net::IpAddr;

use clap::{Args, Subcommand};

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
  #[arg(long = "source-ip")]
  pub(crate) source_ip: Option<IpAddr>,
  #[arg(long)]
  pub(crate) method: Option<String>,
  #[arg(long)]
  pub(crate) host: Option<String>,
  #[arg(long)]
  pub(crate) path: Option<String>,
  #[arg(long)]
  pub(crate) route: Option<String>,
  #[arg(long)]
  pub(crate) protocol: Option<String>,
  #[arg(long = "claim", value_name = "KEY=VALUE")]
  pub(crate) claims: Vec<String>,
}
