use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

pub const DEFAULT_CONTROLLER_NAME: &str = "oxibelt.dev/gateway-controller";
pub const DEFAULT_MANAGED_CONFIG_PATH: &str = "conf.d/gateway-api.generated.toml";

#[derive(Debug, Parser)]
#[command(name = "oxibelt-gateway-controller")]
#[command(about = "Translate Kubernetes Gateway API resources into OxiBelt configuration")]
#[command(
  version = oxibelt_build_identity::SHORT_VERSION,
  long_version = oxibelt_build_identity::LONG_VERSION
)]
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
  #[arg(long, global = true, default_value = "0.0.0.0")]
  pub l4_bind_address: IpAddr,
  #[arg(long, global = true, default_value_t = 3000)]
  pub l4_connect_timeout_ms: u64,
  #[arg(long, global = true, default_value_t = 75_000)]
  pub l4_idle_timeout_ms: u64,
  #[arg(long, global = true, default_value_t = 8192)]
  pub udp_max_flows: usize,
  #[arg(long, global = true, default_value = "200r/s")]
  pub udp_new_flow_rate: String,
  #[arg(long, global = true, default_value_t = 400)]
  pub udp_new_flow_burst: u32,
  #[arg(long, global = true, default_value = "200r/s")]
  pub udp_datagram_rate: String,
  #[arg(long, global = true, default_value_t = 400)]
  pub udp_datagram_burst: u32,
  #[arg(long, global = true, value_enum, default_value = "auto")]
  pub udp_batch: UdpBatchMode,
  #[arg(long, global = true, default_value_t = 16)]
  pub udp_batch_size: usize,
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
pub enum UdpBatchMode {
  #[default]
  Auto,
  Off,
  Required,
}

impl UdpBatchMode {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Auto => "auto",
      Self::Off => "off",
      Self::Required => "required",
    }
  }
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

#[cfg(test)]
mod tests {
  use super::Cli;
  use clap::Parser;

  #[test]
  fn version_flag_reports_canonical_build_identity() {
    let error = Cli::try_parse_from(["oxibelt-gateway-controller", "--version"])
      .expect_err("--version should exit through Clap");
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
    assert!(
      error
        .to_string()
        .contains(oxibelt_build_identity::MACHINE_IDENTITY_MARKER)
    );
  }
}
