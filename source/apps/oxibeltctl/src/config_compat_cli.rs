use std::path::PathBuf;

use clap::{Args, ValueEnum};

#[derive(Debug, Args)]
pub(crate) struct ConfigLbPolicyCompatArgs {
  pub(crate) file: PathBuf,
  #[arg(long, value_enum)]
  pub(crate) profile: ConfigLbPolicyCompatProfile,
  #[arg(long, value_enum, default_value = "text")]
  pub(crate) format: ConfigLbPolicyCompatOutputFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ConfigLbPolicyCompatProfile {
  Nginx,
  Caddy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ConfigLbPolicyCompatOutputFormat {
  Text,
  Json,
}
