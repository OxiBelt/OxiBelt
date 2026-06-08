//! Raw stream listener and upstream-pool configuration validation.
//! Stream routes are checked before they can bypass HTTP-specific safeguards.

use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use url::Url;

use super::{
  Config, LoadBalancingAlgorithm, ProxyProtocolEgressMode, UpstreamPoolServerState,
  default_client_idle_timeout_ms, default_connect_timeout_ms, default_pool_server_weight,
  normalize_sni_pattern, validate_runtime_identifier, validate_sni_server_name,
};

const DEFAULT_MAX_UDP_FLOWS: usize = 8192;
const DEFAULT_UDP_RATE_LIMIT_BURST: u32 = 0;

impl Config {
  pub(super) fn validate_stream_upstream_pools(&self) -> anyhow::Result<()> {
    let mut names = HashSet::new();
    for pool in &self.stream_upstream_pools {
      validate_runtime_identifier("stream upstream pool name", &pool.name)?;
      if !names.insert(pool.name.clone()) {
        bail!("duplicate stream upstream pool name: {}", pool.name);
      }
      validate_stream_pool_algorithm(&pool.name, pool.algorithm)?;
      if pool.servers.is_empty() {
        bail!(
          "stream upstream pool {} must include at least one server",
          pool.name
        );
      }
      let mut server_ids = HashSet::new();
      for (index, server) in pool.servers.iter().enumerate() {
        validate_stream_origin(
          &format!("stream upstream pool {} server {}", pool.name, index),
          &server.origin,
        )?;
        if server.weight == 0 {
          bail!(
            "stream upstream pool {} server {} weight must be greater than 0",
            pool.name,
            stream_upstream_pool_server_id(index, server)
          );
        }
        if let Some(id) = server.id.as_deref() {
          validate_runtime_identifier("stream upstream pool server id", id)?;
        }
        let server_id = stream_upstream_pool_server_id(index, server);
        if !server_ids.insert(server_id.clone()) {
          bail!(
            "duplicate stream upstream pool {} server id {}",
            pool.name,
            server_id
          );
        }
      }
    }
    Ok(())
  }

  pub(super) fn validate_stream_listeners(&self) -> anyhow::Result<()> {
    let mut names = HashSet::new();
    let mut binds = HashSet::new();
    for listener in &self.stream_listeners {
      if listener.name.trim().is_empty() {
        bail!("stream listener name must not be empty");
      }
      if !names.insert(listener.name.clone()) {
        bail!("duplicate stream listener name: {}", listener.name);
      }
      if !binds.insert(listener.bind) {
        bail!(
          "duplicate stream listener bind {} on listener {}",
          listener.bind,
          listener.name
        );
      }
      if listener.connect_timeout_ms == 0 || listener.idle_timeout_ms == 0 {
        bail!(
          "stream listener {} timeout values must be greater than 0",
          listener.name
        );
      }
      if listener.max_udp_flows == 0 {
        bail!(
          "stream listener {} max_udp_flows must be greater than 0",
          listener.name
        );
      }
      if let Some(rate) = listener.udp_datagram_rate.as_deref() {
        crate::limits::parse_rate(rate)
          .with_context(|| format!("stream listener {} udp_datagram_rate", listener.name))?;
      }
      if listener.network == StreamNetwork::Udp
        && listener.proxy_protocol_egress != ProxyProtocolEgressMode::Off
      {
        bail!(
          "stream listener {} cannot enable proxy_protocol_egress for UDP",
          listener.name
        );
      }
      validate_stream_default_target(self, listener)?;
      let mut rule_names = HashSet::new();
      let mut patterns = HashSet::new();
      for rule in &listener.sni_rules {
        rule.validate(self, listener, &mut rule_names, &mut patterns)?;
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StreamListenerConfig {
  pub name: String,
  #[serde(default)]
  pub network: StreamNetwork,
  pub bind: SocketAddr,
  #[serde(default)]
  pub target: Option<String>,
  #[serde(default)]
  pub upstream_pool: Option<String>,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default)]
  pub proxy_protocol_egress: ProxyProtocolEgressMode,
  #[serde(default = "default_max_udp_flows")]
  pub max_udp_flows: usize,
  #[serde(default)]
  pub udp_datagram_rate: Option<String>,
  #[serde(default = "default_udp_rate_limit_burst")]
  pub udp_datagram_burst: u32,
  #[serde(default)]
  pub sni_rules: Vec<StreamSniRuleConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StreamNetwork {
  #[default]
  Tcp,
  Udp,
}

pub const STREAM_NETWORK_WIRE_VALUES: &[&str] = &["tcp", "udp"];
pub const STREAM_POOL_LOAD_BALANCING_ALGORITHM_WIRE_VALUES: &[&str] = &[
  "power_of_two_choices",
  "weighted_least_conn",
  "rendezvous_hash",
  "rendezvous_ip_hash",
];
pub const STREAM_UPSTREAM_POOL_SERVER_STATE_WIRE_VALUES: &[&str] =
  &["ready", "drain", "down", "maintenance"];

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StreamSniRuleConfig {
  pub name: String,
  pub server_names: Vec<String>,
  #[serde(default)]
  pub target: Option<String>,
  #[serde(default)]
  pub upstream_pool: Option<String>,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default)]
  pub proxy_protocol_egress: ProxyProtocolEgressMode,
}

impl StreamSniRuleConfig {
  fn validate(
    &self,
    config: &Config,
    listener: &StreamListenerConfig,
    names: &mut HashSet<String>,
    patterns: &mut HashSet<String>,
  ) -> anyhow::Result<()> {
    if self.name.trim() != self.name || self.name.is_empty() {
      bail!(
        "stream listener {} SNI rule name must not be empty or padded",
        listener.name
      );
    }
    if !names.insert(self.name.clone()) {
      bail!(
        "duplicate stream listener {} SNI rule name: {}",
        listener.name,
        self.name
      );
    }
    if self.server_names.is_empty() {
      bail!(
        "stream listener {} SNI rule {} must include at least one server_name",
        listener.name,
        self.name
      );
    }
    if self.connect_timeout_ms == 0 || self.idle_timeout_ms == 0 {
      bail!(
        "stream listener {} SNI rule {} timeout values must be greater than 0",
        listener.name,
        self.name
      );
    }
    if listener.network == StreamNetwork::Udp
      && self.proxy_protocol_egress != ProxyProtocolEgressMode::Off
    {
      bail!(
        "stream listener {} SNI rule {} cannot enable proxy_protocol_egress for UDP",
        listener.name,
        self.name
      );
    }
    validate_stream_route_target(
      config,
      listener.network,
      &format!("stream listener {} SNI rule {}", listener.name, self.name),
      self.target.as_deref(),
      self.upstream_pool.as_deref(),
      true,
    )?;
    for pattern in &self.server_names {
      validate_sni_server_name(pattern).with_context(|| {
        format!(
          "stream listener {} SNI rule {} server_names",
          listener.name, self.name
        )
      })?;
      let normalized = normalize_sni_pattern(pattern);
      if !patterns.insert(normalized.clone()) {
        bail!(
          "duplicate stream listener {} SNI server_name pattern: {}",
          listener.name,
          normalized
        );
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StreamUpstreamPoolConfig {
  pub name: String,
  #[serde(default)]
  pub algorithm: LoadBalancingAlgorithm,
  #[serde(default)]
  pub hash_key: Option<String>,
  #[serde(default)]
  pub servers: Vec<StreamUpstreamPoolServerConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StreamUpstreamPoolServerConfig {
  #[serde(default)]
  pub id: Option<String>,
  pub origin: Url,
  #[serde(default = "default_pool_server_weight")]
  pub weight: u32,
  #[serde(default)]
  pub max_conns: usize,
  #[serde(default)]
  pub backup: bool,
  #[serde(default)]
  pub state: UpstreamPoolServerState,
}

pub fn stream_upstream_pool_server_id(
  index: usize,
  server: &StreamUpstreamPoolServerConfig,
) -> String {
  server
    .id
    .clone()
    .unwrap_or_else(|| format!("server-{}", index + 1))
}

fn validate_stream_default_target(
  config: &Config,
  listener: &StreamListenerConfig,
) -> anyhow::Result<()> {
  validate_stream_route_target(
    config,
    listener.network,
    &format!("stream listener {}", listener.name),
    listener.target.as_deref(),
    listener.upstream_pool.as_deref(),
    listener.sni_rules.is_empty(),
  )
}

fn validate_stream_route_target(
  config: &Config,
  network: StreamNetwork,
  label: &str,
  target: Option<&str>,
  upstream_pool: Option<&str>,
  required: bool,
) -> anyhow::Result<()> {
  match (target, upstream_pool) {
    (Some(_), Some(_)) => bail!("{label} must set only one of target or upstream_pool"),
    (None, None) if required => bail!("{label} must set target or upstream_pool"),
    (None, None) => Ok(()),
    (Some(target), None) => validate_stream_target(label, target),
    (None, Some(pool)) => validate_stream_pool_reference(config, network, label, pool),
  }
}

fn validate_stream_pool_reference(
  config: &Config,
  network: StreamNetwork,
  label: &str,
  pool_name: &str,
) -> anyhow::Result<()> {
  validate_runtime_identifier(&format!("{label} upstream_pool"), pool_name)?;
  let Some(pool) = config
    .stream_upstream_pools
    .iter()
    .find(|pool| pool.name == pool_name)
  else {
    bail!("{label} references unknown stream upstream pool {pool_name}");
  };
  let expected = stream_origin_scheme(network);
  let has_matching_server = pool
    .servers
    .iter()
    .any(|server| server.origin.scheme() == expected);
  if !has_matching_server {
    bail!("{label} requires stream upstream pool {pool_name} to include {expected}:// servers");
  }
  Ok(())
}

fn validate_stream_target(label: &str, target: &str) -> anyhow::Result<()> {
  let (host, port) = parse_stream_target(target)
    .with_context(|| format!("{label} target must be in host:port form"))?;
  if host.trim().is_empty() {
    bail!("{label} target host must not be empty");
  }
  if port == 0 {
    bail!("{label} target port must be greater than 0");
  }
  Ok(())
}

fn validate_stream_origin(label: &str, origin: &Url) -> anyhow::Result<()> {
  if !matches!(origin.scheme(), "tcp" | "udp") {
    bail!("{label} origin must use tcp:// or udp://, got {}", origin);
  }
  if origin.host_str().is_none() {
    bail!("{label} origin must include a host");
  }
  if origin.port().unwrap_or(0) == 0 {
    bail!("{label} origin port must be greater than 0");
  }
  if !origin.username().is_empty() || origin.password().is_some() {
    bail!("{label} origin must not include credentials");
  }
  if !matches!(origin.path(), "" | "/") || origin.query().is_some() || origin.fragment().is_some() {
    bail!("{label} origin must not include a path, query, or fragment");
  }
  Ok(())
}

fn validate_stream_pool_algorithm(
  pool_name: &str,
  algorithm: LoadBalancingAlgorithm,
) -> anyhow::Result<()> {
  match algorithm {
    LoadBalancingAlgorithm::PowerOfTwoChoices
    | LoadBalancingAlgorithm::WeightedLeastConn
    | LoadBalancingAlgorithm::RendezvousHash
    | LoadBalancingAlgorithm::RendezvousIpHash => Ok(()),
    LoadBalancingAlgorithm::Ewma
    | LoadBalancingAlgorithm::LeastTime
    | LoadBalancingAlgorithm::StickyCookie => {
      bail!("stream upstream pool {pool_name} algorithm is only supported for HTTP upstream pools")
    }
  }
}

fn stream_origin_scheme(network: StreamNetwork) -> &'static str {
  match network {
    StreamNetwork::Tcp => "tcp",
    StreamNetwork::Udp => "udp",
  }
}

fn default_max_udp_flows() -> usize {
  DEFAULT_MAX_UDP_FLOWS
}

fn default_udp_rate_limit_burst() -> u32 {
  DEFAULT_UDP_RATE_LIMIT_BURST
}

pub fn parse_stream_target(target: &str) -> anyhow::Result<(String, u16)> {
  if let Some(stripped) = target.strip_prefix('[') {
    let Some(end) = stripped.find(']') else {
      bail!("missing closing ']' in IPv6 stream target");
    };
    let host = stripped[..end].to_string();
    let port = stripped
      .get(end + 1..)
      .and_then(|rest| rest.strip_prefix(':'))
      .ok_or_else(|| anyhow!("missing port in stream target"))?
      .parse::<u16>()
      .context("invalid stream target port")?;
    return Ok((host, port));
  }

  let (host, port) = target
    .rsplit_once(':')
    .ok_or_else(|| anyhow!("missing port in stream target"))?;
  if host.contains(':') {
    bail!("IPv6 stream targets must use [addr]:port form");
  }
  Ok((
    host.to_string(),
    port.parse::<u16>().context("invalid stream target port")?,
  ))
}
