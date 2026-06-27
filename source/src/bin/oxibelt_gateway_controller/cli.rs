use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use oxibelt::admin_client::{DEFAULT_ADMIN_TOKEN_ENV, DEFAULT_ADMIN_URL};
use url::Url;

pub const DEFAULT_CONTROLLER_NAME: &str = "oxibelt.dev/gateway-controller";
pub const DEFAULT_MANAGED_CONFIG_PATH: &str = "conf.d/gateway-api.generated.toml";

#[derive(Debug, Parser)]
#[command(name = "oxibelt-gateway-controller")]
#[command(about = "Translate Kubernetes Gateway API resources into OxiBelt configuration")]
pub struct Cli {
  #[command(flatten)]
  pub shared: SharedArgs,
  #[command(subcommand)]
  pub command: Command,
}

#[derive(Debug, Args)]
pub struct SharedArgs {
  #[arg(long, global = true, default_value = DEFAULT_CONTROLLER_NAME)]
  pub controller_name: String,
  #[arg(long, global = true, default_value = DEFAULT_MANAGED_CONFIG_PATH)]
  pub managed_config_path: String,
  #[arg(long, global = true, default_value = DEFAULT_ADMIN_URL)]
  pub admin_url: Url,
  #[arg(long, global = true, default_value = DEFAULT_ADMIN_TOKEN_ENV)]
  pub admin_token_env: String,
  #[arg(long, global = true, value_name = "FILE")]
  pub admin_token_file: Option<PathBuf>,
  #[arg(long = "ca-cert", global = true, value_name = "FILE")]
  pub ca_certs: Vec<PathBuf>,
  #[arg(long, global = true, value_name = "FILE", requires = "client_key")]
  pub client_cert: Option<PathBuf>,
  #[arg(long, global = true, value_name = "FILE", requires = "client_cert")]
  pub client_key: Option<PathBuf>,
  #[arg(long, global = true)]
  pub watch_namespace: Option<String>,
  #[arg(long, global = true)]
  pub status_address: Vec<String>,
  #[arg(long, global = true)]
  pub status_service: Option<String>,
  #[arg(long, global = true, value_enum, default_value = "cluster_dns")]
  pub backend_resolution: BackendResolution,
  #[arg(long, global = true)]
  pub dry_run: bool,
  #[arg(long, global = true)]
  pub health_bind: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum BackendResolution {
  #[default]
  ClusterDns,
  EndpointSliceWatch,
}

#[derive(Debug, Subcommand)]
pub enum Command {
  Run(RunArgs),
  Render(RenderArgs),
}

#[derive(Debug, Args)]
pub struct RunArgs {
  #[arg(long, default_value_t = 5000)]
  pub poll_interval_ms: u64,
}

#[derive(Debug, Args)]
pub struct RenderArgs {
  #[arg(long)]
  pub input: PathBuf,
  #[arg(long, default_value = "-")]
  pub output: String,
}
