use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum RolloutTargetKind {
  #[default]
  Deployment,
  #[value(name = "daemonset")]
  DaemonSet,
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
  #[arg(long = "rollout-target-namespace")]
  pub rollout_target_namespace: String,
  #[arg(long = "rollout-target-kind", value_enum, default_value = "deployment")]
  pub rollout_target_kind: RolloutTargetKind,
  #[arg(long = "rollout-target-name")]
  pub rollout_target_name: String,
  #[arg(long = "rollout-target-container-name", default_value = "oxibelt")]
  pub rollout_target_container_name: String,
  #[arg(long = "rollout-volume-name", default_value = "gateway-config")]
  pub rollout_volume_name: String,
  #[arg(long = "rollout-timeout-seconds", default_value_t = 300)]
  pub rollout_timeout_seconds: u64,
  #[arg(
    long = "rollout-config-map-prefix",
    default_value = "oxibelt-gateway-config"
  )]
  pub rollout_config_map_prefix: String,
  #[arg(long = "leader-election-namespace")]
  pub leader_election_namespace: String,
  #[arg(long = "leader-election-lease-name")]
  pub leader_election_lease_name: String,
  #[arg(long = "leader-election-lease-duration-seconds", default_value_t = 15)]
  pub leader_election_lease_duration_seconds: u64,
  #[arg(long = "leader-election-renew-deadline-seconds", default_value_t = 10)]
  pub leader_election_renew_deadline_seconds: u64,
  #[arg(long = "leader-election-retry-period-seconds", default_value_t = 2)]
  pub leader_election_retry_period_seconds: u64,
}

#[derive(Debug, Args)]
pub struct RenderArgs {
  #[arg(long)]
  pub input: PathBuf,
  #[arg(long, default_value = "-")]
  pub output: String,
}
