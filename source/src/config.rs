use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
  #[serde(default)]
  pub logging: LoggingConfig,
  #[serde(default)]
  pub runtime: RuntimeConfig,
  pub listeners: ListenerConfig,
  pub tls: TlsConfig,
  #[serde(default)]
  pub proxy: ProxyConfig,
  #[serde(default)]
  pub compression: CompressionConfig,
  pub upstreams: Vec<UpstreamConfig>,
  pub routes: Vec<RouteConfig>,
}

impl Config {
  pub fn load(path: &Path) -> anyhow::Result<Self> {
    let raw = std::fs::read_to_string(path)
      .with_context(|| format!("failed to read {}", path.display()))?;
    let config: Self = toml::from_str(&raw)
      .with_context(|| format!("failed to parse TOML from {}", path.display()))?;
    Ok(config)
  }

  pub fn validate(&self) -> anyhow::Result<()> {
    if !self.listeners.http1 && !self.listeners.http2 && !self.listeners.http3 {
      bail!("at least one downstream HTTP version must be enabled");
    }

    if self.runtime.unprivileged_mode && self.listeners.https_bind.port() < 1024 {
      bail!(
        "https_bind {} requires a privileged port but unprivileged_mode=true",
        self.listeners.https_bind
      );
    }

    if self.runtime.linux_only && !cfg!(target_os = "linux") {
      bail!("this build is configured for Linux only");
    }

    if self.upstreams.is_empty() {
      bail!("at least one upstream must be configured");
    }

    if self.routes.is_empty() {
      bail!("at least one route must be configured");
    }

    let mut upstream_names = HashSet::new();
    for upstream in &self.upstreams {
      if upstream.name.trim().is_empty() {
        bail!("upstream name must not be empty");
      }
      if !upstream_names.insert(upstream.name.clone()) {
        bail!("duplicate upstream name: {}", upstream.name);
      }

      if upstream.origin.scheme() != "http" && upstream.origin.scheme() != "https" {
        bail!(
          "upstream {} must use http:// or https:// origin, got {}",
          upstream.name,
          upstream.origin
        );
      }
    }

    let mut route_names = HashSet::new();
    for route in &self.routes {
      if route.name.trim().is_empty() {
        bail!("route name must not be empty");
      }
      if !route_names.insert(route.name.clone()) {
        bail!("duplicate route name: {}", route.name);
      }
      if route.hosts.is_empty() {
        bail!("route {} must have at least one host match", route.name);
      }
      if !route.path_prefix.starts_with('/') {
        bail!("route {} path_prefix must start with '/'", route.name);
      }
      if let Some(replacement) = &route.replace_prefix_with {
        if !replacement.starts_with('/') {
          bail!(
            "route {} replace_prefix_with must start with '/'",
            route.name
          );
        }
      }
      if !upstream_names.contains(&route.upstream) {
        bail!(
          "route {} references unknown upstream {}",
          route.name,
          route.upstream
        );
      }
    }

    match self.tls.ocsp.mode {
      OcspMode::Disabled => {}
      OcspMode::StaticFile => {
        if self.tls.ocsp.response_file.is_none() {
          bail!("tls.ocsp.response_file is required when tls.ocsp.mode = \"static_file\"");
        }
      }
      OcspMode::LiveFetch => {
        return Err(anyhow!(
          "tls.ocsp.mode = \"live_fetch\" is reserved but not implemented yet"
        ));
      }
    }

    if self.listeners.http3 {
      return Err(anyhow!(
        "downstream HTTP/3 is reserved in config but not implemented in this initial build"
      ));
    }

    if self.proxy.auto_upgrade.enabled
      && self.proxy.auto_upgrade.max_http_version == HttpVersion::H3
    {
      return Err(anyhow!(
        "auto-upgrade to HTTP/3 is not implemented yet in this initial build"
      ));
    }

    if self
      .upstreams
      .iter()
      .any(|upstream| upstream.max_http_version == HttpVersion::H3)
    {
      return Err(anyhow!(
        "upstream HTTP/3 routing is reserved but not implemented yet in this initial build"
      ));
    }

    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
  #[serde(default = "default_log_level")]
  pub level: String,
}

impl Default for LoggingConfig {
  fn default() -> Self {
    Self {
      level: default_log_level(),
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
  #[serde(default = "default_true")]
  pub linux_only: bool,
  #[serde(default = "default_true")]
  pub read_only_rootfs_compatible: bool,
  #[serde(default = "default_true")]
  pub memory_only_state: bool,
  #[serde(default = "default_true")]
  pub unprivileged_mode: bool,
}

impl Default for RuntimeConfig {
  fn default() -> Self {
    Self {
      linux_only: true,
      read_only_rootfs_compatible: true,
      memory_only_state: true,
      unprivileged_mode: true,
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
  pub https_bind: SocketAddr,
  #[serde(default = "default_true")]
  pub http1: bool,
  #[serde(default = "default_true")]
  pub http2: bool,
  #[serde(default)]
  pub http3: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
  pub cert_chain: PathBuf,
  pub private_key: PathBuf,
  #[serde(default)]
  pub ocsp: OcspConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OcspConfig {
  #[serde(default)]
  pub mode: OcspMode,
  #[serde(default)]
  pub response_file: Option<PathBuf>,
}

impl Default for OcspConfig {
  fn default() -> Self {
    Self {
      mode: OcspMode::Disabled,
      response_file: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OcspMode {
  #[default]
  Disabled,
  StaticFile,
  LiveFetch,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
  #[serde(default)]
  pub auto_upgrade: AutoUpgradeConfig,
  #[serde(default)]
  pub trusted_ca_certs: Vec<PathBuf>,
}

impl Default for ProxyConfig {
  fn default() -> Self {
    Self {
      auto_upgrade: AutoUpgradeConfig::default(),
      trusted_ca_certs: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct CompressionConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub gzip: bool,
  #[serde(default = "default_true")]
  pub deflate: bool,
  #[serde(default = "default_true")]
  pub zstd: bool,
}

impl CompressionConfig {
  pub fn accept_encoding_value(&self) -> Option<String> {
    if !self.enabled {
      return None;
    }

    let mut values = Vec::new();
    if self.zstd {
      values.push("zstd");
    }
    if self.gzip {
      values.push("gzip");
    }
    if self.deflate {
      values.push("deflate");
    }

    if values.is_empty() {
      None
    } else {
      Some(values.join(", "))
    }
  }
}

impl Default for CompressionConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      gzip: true,
      deflate: true,
      zstd: true,
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
  pub name: String,
  pub origin: Url,
  #[serde(default = "default_proxy_max_http_version")]
  pub max_http_version: HttpVersion,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub request_timeout_ms: u64,
  #[serde(default)]
  pub preserve_host: bool,
  #[serde(default = "default_true")]
  pub websocket: bool,
  #[serde(default = "default_true")]
  pub webrtc: bool,
  #[serde(default = "default_true")]
  pub webtransport: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
  pub name: String,
  #[serde(default = "default_hosts")]
  pub hosts: Vec<String>,
  #[serde(default = "default_path_prefix")]
  pub path_prefix: String,
  #[serde(default)]
  pub replace_prefix_with: Option<String>,
  pub upstream: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub enum HttpVersion {
  #[serde(rename = "h1")]
  H1,
  #[serde(rename = "h2")]
  H2,
  #[serde(rename = "h3")]
  H3,
}

impl HttpVersion {
  pub fn as_alpn(self) -> &'static [u8] {
    match self {
      Self::H1 => b"http/1.1",
      Self::H2 => b"h2",
      Self::H3 => b"h3",
    }
  }
}

fn default_true() -> bool {
  true
}

fn default_log_level() -> String {
  "info".to_string()
}

fn default_hosts() -> Vec<String> {
  vec!["*".to_string()]
}

fn default_path_prefix() -> String {
  "/".to_string()
}

fn default_connect_timeout_ms() -> u64 {
  3_000
}

fn default_request_timeout_ms() -> u64 {
  30_000
}

fn default_proxy_max_http_version() -> HttpVersion {
  HttpVersion::H2
}
