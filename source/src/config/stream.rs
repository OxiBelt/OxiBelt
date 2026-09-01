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
  normalize_sni_pattern, validate_base64_32_byte_env, validate_runtime_identifier,
  validate_sni_server_name,
};

const DEFAULT_MAX_UDP_FLOWS: usize = 8192;
const DEFAULT_UDP_RATE_LIMIT_BURST: u32 = 0;
const MAX_UDP_FLOWS: usize = 1_048_576;
const MAX_UDP_RATE_LIMIT_BURST: u32 = 1_048_576;
const MAX_UDP_BATCH_SIZE: usize = 1024;
pub(crate) const MIN_SHARED_UDP_RATE_PER_SECOND: f64 = 0.000_001;
pub(crate) const MAX_SHARED_UDP_RATE_PER_SECOND: u64 = 1_048_576;
pub(crate) const SHARED_UDP_RENEW_BATCH_SIZE: u64 = 64;
pub(crate) const SHARED_UDP_RENEW_PARALLEL_BATCHES: u64 = 8;
pub(crate) const MAX_SHARED_UDP_IDLE_TIMEOUT_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

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
    let mut binds = Vec::new();
    for listener in &self.stream_listeners {
      if listener.name.trim().is_empty() {
        bail!("stream listener name must not be empty");
      }
      if !names.insert(listener.name.clone()) {
        bail!("duplicate stream listener name: {}", listener.name);
      }
      if binds.iter().any(|(network, bind)| {
        *network == listener.network && stream_binds_overlap(*bind, listener.bind)
      }) {
        bail!(
          "overlapping stream listener bind {} for {:?} on listener {}",
          listener.bind,
          listener.network,
          listener.name
        );
      }
      binds.push((listener.network, listener.bind));
      validate_stream_listener_bind_conflicts(self, listener)?;
      if self.rejects_privileged_data_plane_ports()
        && super::workers::is_privileged_bind(listener.bind)
      {
        bail!(
          "stream listener {} bind {} requires a privileged port but unprivileged_mode=true",
          listener.name,
          listener.bind
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
      if listener.max_udp_flows > MAX_UDP_FLOWS {
        bail!(
          "stream listener {} max_udp_flows must not exceed {MAX_UDP_FLOWS}",
          listener.name
        );
      }
      if listener.udp_batch_size == 0 || listener.udp_batch_size > MAX_UDP_BATCH_SIZE {
        bail!(
          "stream listener {} udp_batch_size must be between 1 and {MAX_UDP_BATCH_SIZE}",
          listener.name,
        );
      }
      #[cfg(not(target_os = "linux"))]
      if listener.udp_batch == UdpBatchMode::Required {
        bail!(
          "stream listener {} udp_batch = \"required\" is Linux-only",
          listener.name
        );
      }
      if let Some(rate) = listener.udp_datagram_rate.as_deref() {
        let rate = crate::limits::parse_rate(rate)
          .with_context(|| format!("stream listener {} udp_datagram_rate", listener.name))?;
        if !rate.per_second().is_finite() {
          bail!(
            "stream listener {} udp_datagram_rate must be finite",
            listener.name
          );
        }
        validate_shared_udp_rate(listener, "udp_datagram_rate", rate.per_second())?;
        if listener.udp_datagram_burst == 0 {
          bail!(
            "stream listener {} udp_datagram_burst must be greater than 0 when udp_datagram_rate is set",
            listener.name
          );
        }
        if listener.udp_datagram_burst > MAX_UDP_RATE_LIMIT_BURST {
          bail!(
            "stream listener {} udp_datagram_burst must not exceed {MAX_UDP_RATE_LIMIT_BURST}",
            listener.name
          );
        }
      } else if listener.udp_datagram_burst != 0 {
        bail!(
          "stream listener {} udp_datagram_burst requires udp_datagram_rate",
          listener.name
        );
      }
      if let Some(rate) = listener.udp_new_flow_rate.as_deref() {
        let rate = crate::limits::parse_rate(rate)
          .with_context(|| format!("stream listener {} udp_new_flow_rate", listener.name))?;
        if !rate.per_second().is_finite() {
          bail!(
            "stream listener {} udp_new_flow_rate must be finite",
            listener.name
          );
        }
        validate_shared_udp_rate(listener, "udp_new_flow_rate", rate.per_second())?;
        if listener.udp_new_flow_burst == 0 {
          bail!(
            "stream listener {} udp_new_flow_burst must be greater than 0 when udp_new_flow_rate is set",
            listener.name
          );
        }
        if listener.udp_new_flow_burst > MAX_UDP_RATE_LIMIT_BURST {
          bail!(
            "stream listener {} udp_new_flow_burst must not exceed {MAX_UDP_RATE_LIMIT_BURST}",
            listener.name
          );
        }
      } else if listener.udp_new_flow_burst != 0 {
        bail!(
          "stream listener {} udp_new_flow_burst requires udp_new_flow_rate",
          listener.name
        );
      }
      if listener.network == StreamNetwork::Udp
        && listener.proxy_protocol_egress != ProxyProtocolEgressMode::Off
      {
        bail!(
          "stream listener {} cannot enable proxy_protocol_egress for UDP",
          listener.name
        );
      }
      validate_udp_flow_state(self, listener)?;
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

fn validate_shared_udp_rate(
  listener: &StreamListenerConfig,
  field: &str,
  per_second: f64,
) -> anyhow::Result<()> {
  if listener.udp_flow_state == UdpFlowState::SharedRequired
    && !(MIN_SHARED_UDP_RATE_PER_SECOND..=MAX_SHARED_UDP_RATE_PER_SECOND as f64)
      .contains(&per_second)
  {
    bail!(
      "stream listener {} {field} must be between {MIN_SHARED_UDP_RATE_PER_SECOND} and {MAX_SHARED_UDP_RATE_PER_SECOND} requests per second when udp_flow_state = \"shared_required\"",
      listener.name
    );
  }
  Ok(())
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
  #[serde(default)]
  pub udp_flow_state: UdpFlowState,
  #[serde(default = "default_max_udp_flows")]
  pub max_udp_flows: usize,
  #[serde(default)]
  pub udp_datagram_rate: Option<String>,
  #[serde(default = "default_udp_rate_limit_burst")]
  pub udp_datagram_burst: u32,
  #[serde(default)]
  pub udp_new_flow_rate: Option<String>,
  #[serde(default = "default_udp_rate_limit_burst")]
  pub udp_new_flow_burst: u32,
  #[serde(default)]
  pub udp_batch: UdpBatchMode,
  #[serde(default = "default_udp_batch_size")]
  pub udp_batch_size: usize,
  #[serde(default)]
  pub sni_rules: Vec<StreamSniRuleConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StreamNetwork {
  #[default]
  Tcp,
  Udp,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UdpBatchMode {
  #[default]
  Auto,
  Off,
  Required,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UdpFlowState {
  #[default]
  Local,
  SharedRequired,
}

pub const STREAM_NETWORK_WIRE_VALUES: &[&str] = &["tcp", "udp"];
pub const UDP_FLOW_STATE_WIRE_VALUES: &[&str] = &["local", "shared_required"];
pub const STREAM_POOL_LOAD_BALANCING_ALGORITHM_WIRE_VALUES: &[&str] = &[
  "power_of_two_choices",
  "weighted_least_conn",
  "rendezvous_hash",
  "rendezvous_ip_hash",
];
pub const STREAM_UPSTREAM_POOL_SERVER_STATE_WIRE_VALUES: &[&str] =
  &["ready", "drain", "down", "maintenance"];

fn validate_udp_flow_state(config: &Config, listener: &StreamListenerConfig) -> anyhow::Result<()> {
  if listener.udp_flow_state == UdpFlowState::Local {
    return Ok(());
  }
  if listener.network != StreamNetwork::Udp {
    bail!(
      "stream listener {} udp_flow_state = \"shared_required\" requires network = \"udp\"",
      listener.name
    );
  }
  if !config.shared_state.enabled {
    bail!(
      "stream listener {} udp_flow_state = \"shared_required\" requires shared_state.enabled = true",
      listener.name
    );
  }
  let Some(udp_backend_name) = config.shared_state.udp_flows_backend.as_deref() else {
    bail!(
      "stream listener {} udp_flow_state = \"shared_required\" requires shared_state.udp_flows_backend",
      listener.name
    );
  };
  let connection_backend_name = config
    .shared_state
    .connection_limits_backend
    .as_deref()
    .or(config.shared_state.default_backend.as_deref())
    .or_else(|| {
      config
        .shared_state
        .backends
        .first()
        .map(|backend| backend.name.as_str())
    });
  if connection_backend_name.is_some_and(|name| name != udp_backend_name) {
    bail!(
      "stream listener {} shared UDP flows and shared connection limits must use the same backend",
      listener.name
    );
  }
  let minimum_idle_timeout_ms = config
    .shared_state
    .operation_timeout_ms
    .checked_mul(6)
    .ok_or_else(|| {
      anyhow!(
        "shared_state.operation_timeout_ms is too large for shared UDP flow timeout validation"
      )
    })?;
  if listener.idle_timeout_ms < minimum_idle_timeout_ms {
    bail!(
      "stream listener {} idle_timeout_ms must be at least six times shared_state.operation_timeout_ms ({minimum_idle_timeout_ms}) when udp_flow_state = \"shared_required\"",
      listener.name
    );
  }
  if listener.idle_timeout_ms > MAX_SHARED_UDP_IDLE_TIMEOUT_MS {
    bail!(
      "stream listener {} idle_timeout_ms must not exceed {MAX_SHARED_UDP_IDLE_TIMEOUT_MS} when udp_flow_state = \"shared_required\"",
      listener.name
    );
  }
  let (renew_interval_ms, owner_ttl_ms) = shared_udp_flow_lease_timing_ms(
    config.shared_state.operation_timeout_ms,
    listener.idle_timeout_ms,
  );
  if renew_interval_ms < 10 {
    bail!(
      "stream listener {} shared_required renewal interval must be at least 10ms; increase idle_timeout_ms or shared_state.operation_timeout_ms",
      listener.name
    );
  }
  let renewal_waves = owner_ttl_ms
    .saturating_sub(renew_interval_ms)
    .checked_div(config.shared_state.operation_timeout_ms)
    .unwrap_or(0)
    .saturating_sub(1);
  let Some(udp_backend) = config
    .shared_state
    .backends
    .iter()
    .find(|backend| backend.name == udp_backend_name)
  else {
    bail!(
      "stream listener {} shared UDP backend {udp_backend_name} is not configured",
      listener.name
    );
  };
  if udp_backend.max_connections < 2 {
    bail!(
      "stream listener {} shared UDP backend {udp_backend_name} must configure at least 2 max_connections",
      listener.name
    );
  }
  let backend_parallelism = shared_udp_renew_parallelism(udp_backend.max_connections);
  let renewable_capacity = renewal_waves
    .saturating_mul(SHARED_UDP_RENEW_BATCH_SIZE)
    .saturating_mul(backend_parallelism)
    .min(MAX_UDP_FLOWS as u64);
  if u64::try_from(listener.max_udp_flows).unwrap_or(u64::MAX) > renewable_capacity {
    bail!(
      "stream listener {} max_udp_flows must not exceed {renewable_capacity} for shared_required renewal timing (operation_timeout_ms={}, idle_timeout_ms={}, backend_parallelism={backend_parallelism})",
      listener.name,
      config.shared_state.operation_timeout_ms,
      listener.idle_timeout_ms
    );
  }
  validate_base64_32_byte_env(
    "shared_state.udp_flow_identity_key_env",
    &config.shared_state.udp_flow_identity_key_env,
  )
}

pub(crate) fn shared_udp_flow_lease_timing_ms(
  operation_timeout_ms: u64,
  idle_timeout_ms: u64,
) -> (u64, u64) {
  let renew_interval_ms =
    operation_timeout_ms.max(5_000_u64.min(idle_timeout_ms.saturating_div(6)));
  let owner_ttl_ms = renew_interval_ms.saturating_mul(3).min(idle_timeout_ms);
  (renew_interval_ms, owner_ttl_ms)
}

pub(crate) fn shared_udp_renew_parallelism(max_connections: u32) -> u64 {
  u64::from(max_connections.saturating_sub(1)).clamp(1, SHARED_UDP_RENEW_PARALLEL_BATCHES)
}

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

fn validate_stream_listener_bind_conflicts(
  config: &Config,
  listener: &StreamListenerConfig,
) -> anyhow::Result<()> {
  let mut conflicts = Vec::new();
  match listener.network {
    StreamNetwork::Tcp => {
      if config.needs_https_listener() {
        conflicts.extend(
          config
            .listeners
            .https_binds
            .iter()
            .copied()
            .map(|bind| ("listeners.https_binds", bind)),
        );
      }
      if config.listeners.http_mode != super::HttpListenerMode::Off {
        conflicts.extend(
          config
            .listeners
            .http_binds
            .iter()
            .copied()
            .map(|bind| ("listeners.http_binds", bind)),
        );
      }
      if config.admin.enabled {
        conflicts.push(("admin.bind", config.admin.bind));
      }
      if config.metrics.enabled {
        conflicts.push(("metrics.bind", config.metrics.bind));
      }
      if config.health.enabled {
        conflicts.push(("health.bind", config.health.bind));
      }
      for turn in &config.webrtc_turn_listeners {
        conflicts.extend(
          turn
            .tcp_binds()
            .chain(turn.tls_binds())
            .map(|bind| ("webrtc_turn_listeners TCP/TLS", bind)),
        );
      }
    }
    StreamNetwork::Udp => {
      if config.listeners.http3 {
        conflicts.extend(
          config
            .listeners
            .https_binds
            .iter()
            .copied()
            .map(|bind| ("listeners HTTP/3", bind)),
        );
      }
      if config.admin.enabled && config.admin.http3.enabled {
        conflicts.push((
          "admin.http3.bind",
          config.admin.http3.bind.unwrap_or(config.admin.bind),
        ));
      }
      conflicts.extend(
        config
          .webrtc_turn_listeners
          .iter()
          .flat_map(|turn| turn.udp_binds())
          .map(|bind| ("webrtc_turn_listeners UDP", bind)),
      );
    }
  }

  if let Some((field, bind)) = conflicts
    .into_iter()
    .find(|(_, bind)| stream_binds_overlap(listener.bind, *bind))
  {
    bail!(
      "stream listener {} {:?} bind {} overlaps {field} bind {bind}",
      listener.name,
      listener.network,
      listener.bind
    );
  }
  Ok(())
}

fn stream_binds_overlap(left: SocketAddr, right: SocketAddr) -> bool {
  left.port() == right.port()
    && left.is_ipv4() == right.is_ipv4()
    && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

fn default_max_udp_flows() -> usize {
  DEFAULT_MAX_UDP_FLOWS
}

fn default_udp_rate_limit_burst() -> u32 {
  DEFAULT_UDP_RATE_LIMIT_BURST
}

fn default_udp_batch_size() -> usize {
  16
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
