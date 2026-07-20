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
