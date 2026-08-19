//! Runtime and HTTP proxy configuration schema.

use super::*;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RuntimeDrainConfig {
  #[serde(default = "default_drain_graceful_timeout_ms")]
  pub graceful_timeout_ms: u64,
  #[serde(default = "default_drain_long_connection_close_delay_ms")]
  pub long_connection_close_delay_ms: u64,
  #[serde(default)]
  pub shutdown_delay_ms: u64,
}

impl Default for RuntimeDrainConfig {
  fn default() -> Self {
    Self {
      graceful_timeout_ms: default_drain_graceful_timeout_ms(),
      long_connection_close_delay_ms: default_drain_long_connection_close_delay_ms(),
      shutdown_delay_ms: 0,
    }
  }
}

impl RuntimeDrainConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    if self.graceful_timeout_ms == 0 {
      bail!("runtime.drain.graceful_timeout_ms must be greater than 0");
    }
    if self.long_connection_close_delay_ms == 0 {
      bail!("runtime.drain.long_connection_close_delay_ms must be greater than 0");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HotReloadConfig {
  #[serde(default)]
  pub mode: HotReloadMode,
  #[serde(default = "default_hot_reload_poll_interval_ms")]
  pub poll_interval_ms: u64,
}

impl Default for HotReloadConfig {
  fn default() -> Self {
    Self {
      mode: HotReloadMode::Off,
      poll_interval_ms: default_hot_reload_poll_interval_ms(),
    }
  }
}

impl HotReloadConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    if self.poll_interval_ms == 0 {
      bail!("runtime.hot_reload.poll_interval_ms must be greater than 0");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HotReloadMode {
  #[default]
  Off,
  #[serde(rename = "oxirule")]
  OxiRule,
  Full,
  DownstreamTls,
}

impl HotReloadMode {
  pub fn enabled(self) -> bool {
    self != Self::Off
  }
}

impl std::fmt::Display for HotReloadMode {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(match self {
      Self::Off => "off",
      Self::OxiRule => "oxirule",
      Self::Full => "full",
      Self::DownstreamTls => "downstream_tls",
    })
  }
}

impl FromStr for HotReloadMode {
  type Err = anyhow::Error;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "off" => Ok(Self::Off),
      "oxirule" => Ok(Self::OxiRule),
      "full" => Ok(Self::Full),
      "downstream_tls" => Ok(Self::DownstreamTls),
      _ => {
        bail!("unsupported hot reload mode {value}; expected off, oxirule, full, or downstream_tls")
      }
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ProxyConfig {
  #[serde(default)]
  pub upstream_resolution: UpstreamResolutionConfig,
  #[serde(default)]
  pub auto_upgrade: AutoUpgradeConfig,
  #[serde(default)]
  pub forwarded_headers: ForwardedHeadersConfig,
  #[serde(default)]
  pub real_ip: RealIpConfig,
  #[serde(default)]
  pub upgrades: ProxyUpgradesConfig,
  #[serde(default)]
  pub grpc_web: ProxyGrpcWebConfig,
  #[serde(default)]
  pub retry: ProxyRetryConfig,
  #[serde(default)]
  pub buffering: ProxyBufferingConfig,
  #[serde(default)]
  pub http: ProxyHttpConfig,
  #[serde(default)]
  pub http2: ProxyHttp2Config,
  #[serde(default)]
  pub http3: ProxyHttp3Config,
  #[serde(default)]
  pub static_files: ProxyStaticFilesConfig,
  #[serde(default)]
  pub trusted_ca_certs: Vec<PathBuf>,
  #[serde(default)]
  pub upstream_revocation: OutboundTlsRevocationConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamResolutionConfig {
  #[serde(default = "default_upstream_resolution_max_endpoint_count")]
  pub max_endpoint_count: usize,
  #[serde(default = "default_upstream_resolution_min_ttl_ms")]
  pub min_ttl_ms: u64,
  #[serde(default = "default_upstream_resolution_max_ttl_ms")]
  pub max_ttl_ms: u64,
  #[serde(default = "default_upstream_resolution_negative_ttl_ms")]
  pub negative_ttl_ms: u64,
  #[serde(default = "default_upstream_resolution_cooldown_ms")]
  pub cooldown_base_ms: u64,
  #[serde(default = "default_upstream_resolution_cooldown_max_ms")]
  pub cooldown_max_ms: u64,
  #[serde(default)]
  pub happy_eyeballs: HappyEyeballsConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HappyEyeballsConfig {
  #[serde(default)]
  pub mode: HappyEyeballsPolicyMode,
  #[serde(default = "default_upstream_resolution_delay_ms")]
  pub resolution_delay_ms: u64,
  #[serde(default = "default_upstream_resolution_stagger_ms")]
  pub connection_attempt_delay_ms: u64,
  #[serde(default = "default_upstream_resolution_minimum_stagger_ms")]
  pub minimum_connection_attempt_delay_ms: u64,
  #[serde(default = "default_upstream_resolution_maximum_stagger_ms")]
  pub maximum_connection_attempt_delay_ms: u64,
  #[serde(default = "default_upstream_resolution_attempts")]
  pub max_connect_attempts: usize,
  #[serde(default = "default_upstream_resolution_max_concurrent_attempts")]
  pub max_concurrent_attempts: usize,
  #[serde(default = "default_upstream_resolution_preferred_family_count")]
  pub preferred_address_family_count: usize,
  #[serde(default = "default_upstream_resolution_last_resort_delay_ms")]
  pub last_resort_local_synthesis_delay_ms: u64,
  #[serde(default)]
  pub svcb: UpstreamResolutionDnsMode,
  #[serde(default)]
  pub pref64: UpstreamResolutionDnsMode,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HappyEyeballsPolicyMode {
  #[default]
  V3,
  Legacy,
}
#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamResolutionDnsMode {
  #[default]
  Auto,
  Disabled,
}

impl Default for UpstreamResolutionConfig {
  fn default() -> Self {
    Self {
      max_endpoint_count: default_upstream_resolution_max_endpoint_count(),
      min_ttl_ms: default_upstream_resolution_min_ttl_ms(),
      max_ttl_ms: default_upstream_resolution_max_ttl_ms(),
      negative_ttl_ms: default_upstream_resolution_negative_ttl_ms(),
      cooldown_base_ms: default_upstream_resolution_cooldown_ms(),
      cooldown_max_ms: default_upstream_resolution_cooldown_max_ms(),
      happy_eyeballs: HappyEyeballsConfig::default(),
    }
  }
}

impl Default for HappyEyeballsConfig {
  fn default() -> Self {
    Self {
      mode: HappyEyeballsPolicyMode::V3,
      resolution_delay_ms: default_upstream_resolution_delay_ms(),
      connection_attempt_delay_ms: default_upstream_resolution_stagger_ms(),
      minimum_connection_attempt_delay_ms: default_upstream_resolution_minimum_stagger_ms(),
      maximum_connection_attempt_delay_ms: default_upstream_resolution_maximum_stagger_ms(),
      max_connect_attempts: default_upstream_resolution_attempts(),
      max_concurrent_attempts: default_upstream_resolution_max_concurrent_attempts(),
      preferred_address_family_count: default_upstream_resolution_preferred_family_count(),
      last_resort_local_synthesis_delay_ms: default_upstream_resolution_last_resort_delay_ms(),
      svcb: UpstreamResolutionDnsMode::Auto,
      pref64: UpstreamResolutionDnsMode::Auto,
    }
  }
}

fn default_upstream_resolution_max_endpoint_count() -> usize {
  16
}
fn default_upstream_resolution_min_ttl_ms() -> u64 {
  1_000
}
fn default_upstream_resolution_max_ttl_ms() -> u64 {
  30_000
}
fn default_upstream_resolution_negative_ttl_ms() -> u64 {
  1_000
}
fn default_upstream_resolution_cooldown_ms() -> u64 {
  1_000
}
fn default_upstream_resolution_cooldown_max_ms() -> u64 {
  30_000
}
fn default_upstream_resolution_delay_ms() -> u64 {
  50
}
fn default_upstream_resolution_stagger_ms() -> u64 {
  250
}
fn default_upstream_resolution_minimum_stagger_ms() -> u64 {
  100
}
fn default_upstream_resolution_maximum_stagger_ms() -> u64 {
  2_000
}
fn default_upstream_resolution_attempts() -> usize {
  4
}
fn default_upstream_resolution_max_concurrent_attempts() -> usize {
  2
}
fn default_upstream_resolution_preferred_family_count() -> usize {
  1
}
fn default_upstream_resolution_last_resort_delay_ms() -> u64 {
  2_000
}

impl UpstreamResolutionConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    const MAX_TTL_MS: u64 = 3_600_000;
    const MAX_NEGATIVE_TTL_MS: u64 = 30_000;
    const MAX_COOLDOWN_MS: u64 = 300_000;
    const HARD_MINIMUM_ATTEMPT_DELAY_MS: u64 = 10;
    const MAX_ATTEMPT_DELAY_MS: u64 = 5_000;

    if !(1..=64).contains(&self.max_endpoint_count) {
      bail!("proxy.upstream_resolution.max_endpoint_count must be between 1 and 64");
    }
    if self.min_ttl_ms == 0 || self.min_ttl_ms > MAX_TTL_MS {
      bail!("proxy.upstream_resolution.min_ttl_ms must be between 1 and {MAX_TTL_MS}");
    }
    if self.max_ttl_ms == 0 || self.max_ttl_ms > MAX_TTL_MS {
      bail!("proxy.upstream_resolution.max_ttl_ms must be between 1 and {MAX_TTL_MS}");
    }
    if self.min_ttl_ms > self.max_ttl_ms {
      bail!(
        "proxy.upstream_resolution.min_ttl_ms must be less than or equal to proxy.upstream_resolution.max_ttl_ms"
      );
    }
    let maximum_negative_ttl_ms = self.max_ttl_ms.min(MAX_NEGATIVE_TTL_MS);
    if self.negative_ttl_ms == 0 || self.negative_ttl_ms > maximum_negative_ttl_ms {
      bail!(
        "proxy.upstream_resolution.negative_ttl_ms must be between 1 and {maximum_negative_ttl_ms}"
      );
    }
    if self.cooldown_base_ms == 0 {
      bail!("proxy.upstream_resolution.cooldown_base_ms must be greater than 0");
    }
    if self.cooldown_max_ms == 0 || self.cooldown_max_ms > MAX_COOLDOWN_MS {
      bail!("proxy.upstream_resolution.cooldown_max_ms must be between 1 and {MAX_COOLDOWN_MS}");
    }
    if self.cooldown_base_ms > self.cooldown_max_ms {
      bail!(
        "proxy.upstream_resolution.cooldown_base_ms must be less than or equal to proxy.upstream_resolution.cooldown_max_ms"
      );
    }

    let happy = &self.happy_eyeballs;
    if happy.resolution_delay_ms == 0 || happy.resolution_delay_ms > MAX_ATTEMPT_DELAY_MS {
      bail!(
        "proxy.upstream_resolution.happy_eyeballs.resolution_delay_ms must be between 1 and {MAX_ATTEMPT_DELAY_MS}"
      );
    }
    if !(HARD_MINIMUM_ATTEMPT_DELAY_MS..=MAX_ATTEMPT_DELAY_MS)
      .contains(&happy.minimum_connection_attempt_delay_ms)
    {
      bail!(
        "proxy.upstream_resolution.happy_eyeballs.minimum_connection_attempt_delay_ms must be between {HARD_MINIMUM_ATTEMPT_DELAY_MS} and {MAX_ATTEMPT_DELAY_MS}"
      );
    }
    if happy.maximum_connection_attempt_delay_ms < happy.minimum_connection_attempt_delay_ms
      || happy.maximum_connection_attempt_delay_ms > MAX_ATTEMPT_DELAY_MS
    {
      bail!(
        "proxy.upstream_resolution.happy_eyeballs.maximum_connection_attempt_delay_ms must be between minimum_connection_attempt_delay_ms and {MAX_ATTEMPT_DELAY_MS}"
      );
    }
    if happy.connection_attempt_delay_ms < happy.minimum_connection_attempt_delay_ms
      || happy.connection_attempt_delay_ms > happy.maximum_connection_attempt_delay_ms
    {
      bail!(
        "proxy.upstream_resolution.happy_eyeballs.connection_attempt_delay_ms must be within the configured minimum and maximum attempt delays"
      );
    }
    if !(1..=16).contains(&happy.max_connect_attempts) {
      bail!(
        "proxy.upstream_resolution.happy_eyeballs.max_connect_attempts must be between 1 and 16"
      );
    }
    if !(1..=2).contains(&happy.max_concurrent_attempts) {
      bail!(
        "proxy.upstream_resolution.happy_eyeballs.max_concurrent_attempts must be between 1 and 2"
      );
    }
    if !(1..=2).contains(&happy.preferred_address_family_count) {
      bail!(
        "proxy.upstream_resolution.happy_eyeballs.preferred_address_family_count must be between 1 and 2"
      );
    }
    if happy.last_resort_local_synthesis_delay_ms < happy.connection_attempt_delay_ms
      || happy.last_resort_local_synthesis_delay_ms > 60_000
    {
      bail!(
        "proxy.upstream_resolution.happy_eyeballs.last_resort_local_synthesis_delay_ms must be between connection_attempt_delay_ms and 60000"
      );
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
pub struct ForwardedHeadersConfig {
  #[serde(default)]
  pub mode: ForwardedHeaderMode,
  #[serde(default)]
  pub client_ip_source: ForwardedClientIpSource,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedHeaderMode {
  #[default]
  Overwrite,
  Append,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedClientIpSource {
  #[default]
  Resolved,
  DirectPeer,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RealIpConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub trusted_proxies: Vec<String>,
  #[serde(default)]
  pub header: RealIpHeader,
  #[serde(default = "default_true")]
  pub recursive: bool,
  #[serde(default)]
  pub fail_on_untrusted_forwarded_headers: bool,
}

impl Default for RealIpConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      trusted_proxies: Vec::new(),
      header: RealIpHeader::XForwardedFor,
      recursive: true,
      fail_on_untrusted_forwarded_headers: false,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RealIpHeader {
  #[default]
  XForwardedFor,
  XRealIp,
  Forwarded,
  CfConnectingIp,
}

impl RealIpHeader {
  pub fn header_name(self) -> &'static str {
    match self {
      Self::XForwardedFor => "x-forwarded-for",
      Self::XRealIp => "x-real-ip",
      Self::Forwarded => "forwarded",
      Self::CfConnectingIp => "cf-connecting-ip",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyUpgradesConfig {
  #[serde(default = "default_true")]
  pub websocket: bool,
  #[serde(default)]
  pub generic_http_upgrade: bool,
  #[serde(default)]
  pub connect_tunneling: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
pub struct ProxyGrpcWebConfig {
  #[serde(default)]
  pub enabled: bool,
}

impl Default for ProxyUpgradesConfig {
  fn default() -> Self {
    Self {
      websocket: true,
      generic_http_upgrade: false,
      connect_tunneling: false,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyBufferingConfig {
  #[serde(default)]
  pub request: BufferingMode,
  #[serde(default)]
  pub response: BufferingMode,
  #[serde(default = "default_buffering_max_memory_body_bytes")]
  pub max_memory_body_bytes: usize,
  #[serde(default)]
  pub max_temp_file_bytes: usize,
  #[serde(default)]
  pub temp_dir: Option<PathBuf>,
}

impl Default for ProxyBufferingConfig {
  fn default() -> Self {
    Self {
      request: BufferingMode::Streaming,
      response: BufferingMode::Streaming,
      max_memory_body_bytes: default_buffering_max_memory_body_bytes(),
      max_temp_file_bytes: 0,
      temp_dir: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BufferingMode {
  #[default]
  Streaming,
  Memory,
  Spool,
  RejectIfTooLarge,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyHttpConfig {
  #[serde(default)]
  pub early_hints: EarlyHintsMode,
  #[serde(default)]
  pub trailers: TrailerMode,
  #[serde(default)]
  pub expect_continue: ExpectContinueMode,
  #[serde(default)]
  pub priority: PriorityMode,
  #[serde(default = "default_true")]
  pub sse_auto_streaming: bool,
  #[serde(default = "default_direct_h1_small_request_body_max_bytes")]
  pub direct_h1_small_request_body_max_bytes: usize,
  #[serde(default)]
  pub grpc: ProxyHttpGrpcConfig,
  #[serde(default)]
  pub errors: ProxyHttpErrorsConfig,
}

impl Default for ProxyHttpConfig {
  fn default() -> Self {
    Self {
      early_hints: EarlyHintsMode::Drop,
      trailers: TrailerMode::Pass,
      expect_continue: ExpectContinueMode::Auto,
      priority: PriorityMode::Pass,
      sse_auto_streaming: true,
      direct_h1_small_request_body_max_bytes: default_direct_h1_small_request_body_max_bytes(),
      grpc: ProxyHttpGrpcConfig::default(),
      errors: ProxyHttpErrorsConfig::default(),
    }
  }
}

pub(crate) fn default_direct_h1_small_request_body_max_bytes() -> usize {
  16 * 1024
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EarlyHintsMode {
  #[default]
  Drop,
  Pass,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrailerMode {
  #[default]
  Pass,
  Drop,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectContinueMode {
  #[default]
  Auto,
  Reject,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PriorityMode {
  #[default]
  Pass,
  Ignore,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyHttpGrpcConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub respect_grpc_timeout: bool,
  #[serde(default)]
  pub retry: GrpcRetryMode,
}

impl Default for ProxyHttpGrpcConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      respect_grpc_timeout: true,
      retry: GrpcRetryMode::Off,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrpcRetryMode {
  #[default]
  Off,
  SafeUnary,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ProxyHttpErrorsConfig {
  #[serde(default)]
  pub mode: ErrorResponseMode,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorResponseMode {
  #[default]
  LegacyPlain,
  Plain,
  Json,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AutoUpgradeConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_proxy_max_http_version")]
  pub max_http_version: HttpVersion,
}

impl Default for AutoUpgradeConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      max_http_version: HttpVersion::H2,
    }
  }
}
