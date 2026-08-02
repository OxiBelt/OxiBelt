use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::bail;
use clap::{Args, Parser, Subcommand, ValueEnum};

pub const DEFAULT_CONTROLLER_NAME: &str = "oxibelt.dev/gateway-controller";
pub const DEFAULT_MANAGED_CONFIG_PATH: &str = "conf.d/gateway-api.generated.toml";
pub const MAX_REQUEST_MIRROR_BODY_BYTES: usize = 16 * 1024 * 1024;

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
  #[arg(long, global = true, value_enum, default_value = "disabled")]
  pub udp_flow_state: UdpFlowState,
  #[arg(long, global = true, default_value_t = 3072)]
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
  #[arg(long, global = true, default_value_t = 0)]
  pub request_mirror_max_body_bytes: usize,
  #[arg(long, global = true, default_value_t = 0)]
  pub external_auth_max_body_bytes: usize,
  #[arg(long = "external-auth-allowed-content-type", global = true)]
  pub external_auth_allowed_content_types: Vec<String>,
  #[arg(long = "external-auth-allowed-request-header", global = true)]
  pub external_auth_allowed_request_headers: Vec<String>,
  #[arg(long = "external-auth-allowed-identity-header", global = true)]
  pub external_auth_allowed_identity_headers: Vec<String>,
  #[arg(long = "external-auth-allowed-terminal-header", global = true)]
  pub external_auth_allowed_terminal_headers: Vec<String>,
  #[arg(long, global = true, default_value_t = false)]
  pub external_auth_allow_credentials: bool,
  #[arg(long, global = true, default_value_t = 10_485_760)]
  pub route_policy_max_request_body_bytes: u64,
  #[arg(long, global = true, default_value_t = 30_000)]
  pub route_policy_max_timeout_ms: u64,
  #[arg(long, global = true)]
  pub dry_run: bool,
  #[arg(long, global = true)]
  pub health_bind: Option<SocketAddr>,
}

impl SharedArgs {
  pub fn validate(&self) -> anyhow::Result<()> {
    if self.request_mirror_max_body_bytes > MAX_REQUEST_MIRROR_BODY_BYTES {
      bail!(
        "request-mirror-max-body-bytes must not exceed {}",
        MAX_REQUEST_MIRROR_BODY_BYTES
      );
    }
    if self.external_auth_max_body_bytes > usize::from(u16::MAX) {
      bail!("external-auth-max-body-bytes must not exceed 65535");
    }
    if self.external_auth_max_body_bytes > 0 && self.external_auth_allowed_content_types.is_empty()
    {
      bail!(
        "external-auth-max-body-bytes > 0 requires at least one --external-auth-allowed-content-type"
      );
    }
    validate_content_types(&self.external_auth_allowed_content_types)?;
    validate_header_allowlist(
      "external-auth-allowed-request-header",
      &self.external_auth_allowed_request_headers,
      ExternalAuthHeaderScope::ProtectedRequest,
    )?;
    validate_header_allowlist(
      "external-auth-allowed-identity-header",
      &self.external_auth_allowed_identity_headers,
      ExternalAuthHeaderScope::ProtectedRequest,
    )?;
    validate_header_allowlist(
      "external-auth-allowed-terminal-header",
      &self.external_auth_allowed_terminal_headers,
      ExternalAuthHeaderScope::TerminalResponse,
    )?;
    if self.route_policy_max_request_body_bytes == 0
      || self.route_policy_max_request_body_bytes > 104_857_600
    {
      bail!("route-policy-max-request-body-bytes must be between 1 and 104857600");
    }
    if self.route_policy_max_timeout_ms == 0 || self.route_policy_max_timeout_ms > 300_000 {
      bail!("route-policy-max-timeout-ms must be between 1 and 300000");
    }
    Ok(())
  }
}

fn validate_content_types(values: &[String]) -> anyhow::Result<()> {
  let mut unique = std::collections::HashSet::new();
  for value in values {
    let normalized = value.trim().to_ascii_lowercase();
    let Some((kind, subtype)) = normalized.split_once('/') else {
      bail!("external-auth-allowed-content-type must use a type/subtype media type");
    };
    let valid_token = |token: &str| {
      !token.is_empty()
        && token.bytes().all(|byte| {
          byte.is_ascii_alphanumeric()
            || matches!(
              byte,
              b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
            )
        })
    };
    if normalized != value.as_str()
      || !valid_token(kind)
      || !valid_token(subtype)
      || kind == "*"
      || subtype == "*"
    {
      bail!(
        "external-auth-allowed-content-type values must be lowercase exact media types without parameters or wildcards"
      );
    }
    if !unique.insert(normalized) {
      bail!("external-auth-allowed-content-type contains a duplicate value");
    }
  }
  Ok(())
}

fn validate_header_allowlist(
  label: &str,
  values: &[String],
  scope: ExternalAuthHeaderScope,
) -> anyhow::Result<()> {
  let mut unique = std::collections::HashSet::new();
  for value in values {
    let normalized = oxibelt_control_protocol::normalize_route_action_header_name(value)?;
    let forbidden = match scope {
      ExternalAuthHeaderScope::ProtectedRequest => {
        oxibelt_control_protocol::is_reserved_route_request_header(&normalized)
      }
      ExternalAuthHeaderScope::TerminalResponse => {
        oxibelt_control_protocol::is_forbidden_route_action_header(&normalized)
      }
    };
    if forbidden {
      bail!("{label} contains forbidden header {normalized}");
    }
    if !unique.insert(normalized) {
      bail!("{label} contains a duplicate header");
    }
  }
  Ok(())
}

#[derive(Clone, Copy)]
enum ExternalAuthHeaderScope {
  ProtectedRequest,
  TerminalResponse,
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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum UdpFlowState {
  #[default]
  Disabled,
  SharedRequired,
}

impl UdpFlowState {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Disabled => "disabled",
      Self::SharedRequired => "shared_required",
    }
  }
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

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum CompatibilityMode {
  #[default]
  Exact,
  RollingUpgrade,
}

impl CompatibilityMode {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Exact => "exact",
      Self::RollingUpgrade => "rolling_upgrade",
    }
  }
}

#[derive(Debug, Subcommand)]
pub enum Command {
  Explain(ExplainArgs),
  Run(Box<RunArgs>),
  Render(RenderArgs),
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum ExplainFormat {
  #[default]
  Json,
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
  #[arg(long)]
  pub input: PathBuf,
  #[arg(long)]
  pub gateway: Option<String>,
  #[arg(long)]
  pub route: Option<String>,
  #[arg(long, value_enum, default_value = "json")]
  pub format: ExplainFormat,
  #[arg(long, default_value = "-")]
  pub output: String,
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
  #[arg(long = "compatibility-mode", value_enum, default_value = "exact")]
  pub compatibility_mode: CompatibilityMode,
  #[arg(long = "compatibility-previous-version")]
  pub compatibility_previous_version: Option<String>,
  #[arg(long = "compatibility-deadline")]
  pub compatibility_deadline: Option<String>,
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
  use super::{Cli, Command, CompatibilityMode, UdpFlowState};
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

  #[test]
  fn run_command_parses_explicit_rolling_upgrade_contract() {
    let cli = Cli::try_parse_from([
      "oxibelt-gateway-controller",
      "run",
      "--rollout-target-namespace=default",
      "--rollout-target-name=oxibelt",
      "--leader-election-namespace=default",
      "--leader-election-lease-name=controller",
      "--compatibility-mode=rolling_upgrade",
      "--compatibility-previous-version=0.6.5",
      "--compatibility-deadline=2026-07-25T00:00:00Z",
    ])
    .expect("rolling-upgrade CLI should parse");
    let Command::Run(args) = cli.command else {
      panic!("expected run command");
    };

    assert_eq!(args.compatibility_mode, CompatibilityMode::RollingUpgrade);
    assert_eq!(
      args.compatibility_previous_version.as_deref(),
      Some("0.6.5")
    );
    assert_eq!(
      args.compatibility_deadline.as_deref(),
      Some("2026-07-25T00:00:00Z")
    );
  }

  #[test]
  fn udp_flow_state_defaults_disabled_and_accepts_shared_required() {
    let default = Cli::try_parse_from([
      "oxibelt-gateway-controller",
      "render",
      "--input=objects.yaml",
    ])
    .expect("default CLI should parse");
    assert_eq!(default.shared.udp_flow_state, UdpFlowState::Disabled);

    let shared = Cli::try_parse_from([
      "oxibelt-gateway-controller",
      "--udp-flow-state=shared_required",
      "render",
      "--input=objects.yaml",
    ])
    .expect("shared-required CLI should parse");
    assert_eq!(shared.shared.udp_flow_state, UdpFlowState::SharedRequired);

    let invalid = Cli::try_parse_from([
      "oxibelt-gateway-controller",
      "--udp-flow-state=local",
      "render",
      "--input=objects.yaml",
    ])
    .expect_err("controller CLI must reject process-local UDP flow activation");
    assert_eq!(invalid.kind(), clap::error::ErrorKind::InvalidValue);
  }

  #[test]
  fn explain_command_accepts_bounded_source_selectors_and_json_format() {
    let cli = Cli::try_parse_from([
      "oxibelt-gateway-controller",
      "explain",
      "--input=objects.yaml",
      "--gateway=default/edge",
      "--route=default/app",
      "--format=json",
    ])
    .expect("explain CLI should parse");
    let Command::Explain(args) = cli.command else {
      panic!("expected explain command");
    };
    assert_eq!(args.gateway.as_deref(), Some("default/edge"));
    assert_eq!(args.route.as_deref(), Some("default/app"));
  }

  #[test]
  fn request_mirror_body_cap_cannot_exceed_the_runtime_admission_unit() {
    let cli = Cli::try_parse_from([
      "oxibelt-gateway-controller",
      "--request-mirror-max-body-bytes=16777217",
      "render",
      "--input=objects.yaml",
    ])
    .expect("CLI shape should parse before semantic validation");
    let error = cli
      .shared
      .validate()
      .expect_err("oversized mirror capture must fail");
    assert!(error.to_string().contains("must not exceed 16777216"));
  }

  #[test]
  fn external_auth_operator_allowlists_reject_reserved_and_framing_headers() {
    for (option, header) in [
      ("--external-auth-allowed-request-header", "host"),
      ("--external-auth-allowed-identity-header", "content-length"),
      (
        "--external-auth-allowed-terminal-header",
        "transfer-encoding",
      ),
    ] {
      let cli = Cli::try_parse_from([
        "oxibelt-gateway-controller",
        option,
        header,
        "render",
        "--input=objects.yaml",
      ])
      .expect("CLI shape should parse before semantic validation");
      let error = cli
        .shared
        .validate()
        .expect_err("external auth must not receive message-framing authority");
      assert!(
        error
          .to_string()
          .contains(&format!("contains forbidden header {header}")),
        "unexpected error for {option}: {error}"
      );
    }
  }
}
