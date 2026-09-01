//! TURN listener and pool configuration validation.
//! TURN credentials and upstream references are checked before UDP/TCP listeners bind.

mod auth;
mod relay;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};
use serde::Deserialize;
use url::Url;

use super::turn_queue::{
  DEFAULT_TURN_STREAM_OUTBOUND_QUEUE_CAPACITY, TurnStreamOutboundQueueCapacitySetting,
  default_turn_stream_outbound_queue_capacity,
};
use super::upstream_pool::{
  default_health_check_healthy_threshold, default_health_check_interval_ms,
  default_health_check_timeout_ms, default_health_check_unhealthy_threshold,
};
use super::{
  Config, LoadBalancingAlgorithm, TlsServerResumptionConfig, TurnListenerTlsSourcePaths,
  UpstreamPoolServerState, UpstreamTlsConfig, default_client_idle_timeout_ms,
  default_pool_server_weight, default_true, resolve_existing_local_config_file_path_with_logical,
  turn_upstream_pool_server_id, validate_runtime_identifier,
};

use auth::validate_turn_opaque_string;
pub use auth::{TurnAuthConfig, TurnAuthMode, TurnPasswordAlgorithm, TurnStaticCredentialConfig};
use relay::resolve_relay_families;
pub use relay::{
  TurnEdgeRelayLimitsConfig, TurnEdgeRelayPeerPolicyConfig, TurnRelayAddressFamily,
  TurnRelayFamilyConfig,
};

const MAX_TURN_ADDITIONAL_BINDS: usize = 7;

impl Config {
  pub(super) fn validate_turn_forwarding(
    &self,
  ) -> anyhow::Result<HashMap<String, HashSet<&'static str>>> {
    let mut names = HashMap::new();
    for pool in &self.turn_upstream_pools {
      if pool.name.trim().is_empty() {
        bail!("TURN upstream pool name must not be empty");
      }
      if names.contains_key(&pool.name) {
        bail!("duplicate TURN upstream pool name: {}", pool.name);
      }
      if matches!(
        pool.algorithm,
        LoadBalancingAlgorithm::Ewma
          | LoadBalancingAlgorithm::LeastTime
          | LoadBalancingAlgorithm::StickyCookie
      ) {
        bail!(
          "TURN upstream pool {} uses unsupported load-balancing algorithm {:?}",
          pool.name,
          pool.algorithm
        );
      }
      if pool.servers.is_empty() {
        bail!(
          "TURN upstream pool {} must define at least one server",
          pool.name
        );
      }
      let mut server_ids = HashSet::new();
      let mut schemes = HashSet::new();
      for (index, server) in pool.servers.iter().enumerate() {
        let server_id = turn_upstream_pool_server_id(index, server);
        validate_runtime_identifier(
          &format!("TURN upstream pool {} server id", pool.name),
          &server_id,
        )?;
        if !server_ids.insert(server_id.clone()) {
          bail!(
            "TURN upstream pool {} has duplicate server id {server_id}",
            pool.name
          );
        }
        validate_turn_origin(&format!("TURN upstream pool {}", pool.name), &server.origin)?;
        if server.origin.scheme() != "turns" && server.tls != UpstreamTlsConfig::default() {
          bail!(
            "TURN upstream pool {} server {} tls is only valid for turns:// origins",
            pool.name,
            server_id
          );
        }
        if server.origin.scheme() == "turns" {
          server.tls.validate(&format!(
            "TURN upstream pool {} server {}",
            pool.name, server_id
          ))?;
        }
        schemes.insert(turn_origin_scheme(server.origin.scheme()));
        if server.weight == 0 {
          bail!(
            "TURN upstream pool {} server weight must be greater than 0",
            pool.name
          );
        }
      }
      names.insert(pool.name.clone(), schemes);
      if pool.health_check.enabled {
        if pool.health_check.interval_ms == 0
          || pool.health_check.timeout_ms == 0
          || pool.health_check.connect_timeout_ms == 0
          || pool.health_check.tls_handshake_timeout_ms == 0
        {
          bail!(
            "TURN upstream pool {} health_check interval, timeout, connect_timeout_ms, and tls_handshake_timeout_ms must be greater than 0",
            pool.name
          );
        }
        if pool.health_check.healthy_threshold == 0 || pool.health_check.unhealthy_threshold == 0 {
          bail!(
            "TURN upstream pool {} health_check thresholds must be greater than 0",
            pool.name
          );
        }
      }
    }
    Ok(names)
  }

  pub(super) fn validate_webrtc_turn_listeners(
    &self,
    turn_pools: &HashMap<String, HashSet<&'static str>>,
  ) -> anyhow::Result<()> {
    let mut names = HashSet::new();
    let mut binds = Vec::<(&'static str, SocketAddr, String)>::new();
    for listener in &self.webrtc_turn_listeners {
      if listener.name.trim().is_empty() {
        bail!("WebRTC TURN listener name must not be empty");
      }
      if !names.insert(listener.name.clone()) {
        bail!("duplicate WebRTC TURN listener name: {}", listener.name);
      }
      for (transport, count) in [
        ("UDP", listener.bind_udp_additional.len()),
        ("TCP", listener.bind_tcp_additional.len()),
        ("TLS", listener.bind_tls_additional.len()),
      ] {
        if count > MAX_TURN_ADDITIONAL_BINDS {
          bail!(
            "WebRTC TURN listener {} {transport} permits at most {MAX_TURN_ADDITIONAL_BINDS} additional bind addresses",
            listener.name
          );
        }
      }
      if listener.udp_binds().next().is_none()
        && listener.tcp_binds().next().is_none()
        && listener.tls_binds().next().is_none()
      {
        bail!(
          "WebRTC TURN listener {} must configure at least one bind address",
          listener.name
        );
      }
      for (transport, listener_binds) in [
        ("udp", listener.udp_binds().collect::<Vec<_>>()),
        ("tcp", listener.tcp_binds().collect::<Vec<_>>()),
        ("tls", listener.tls_binds().collect::<Vec<_>>()),
      ] {
        for bind in listener_binds {
          let socket_transport = if transport == "udp" { "UDP" } else { "TCP/TLS" };
          if let Some((_, existing_bind, existing_listener)) =
            binds.iter().find(|(existing_transport, existing_bind, _)| {
              *existing_transport == socket_transport
                && super::socket_addrs_overlap(*existing_bind, bind)
            })
          {
            bail!(
              "overlapping WebRTC TURN {socket_transport} binds {} on listener {} and {} on listener {}",
              existing_bind,
              existing_listener,
              bind,
              listener.name
            );
          }
          binds.push((socket_transport, bind, listener.name.clone()));
          if self.rejects_privileged_data_plane_ports() && super::workers::is_privileged_bind(bind)
          {
            bail!(
              "WebRTC TURN listener {} {transport} bind {} requires a privileged port but unprivileged_mode=true",
              listener.name,
              bind
            );
          }
        }
      }
      if listener.idle_timeout_ms == 0 {
        bail!(
          "WebRTC TURN listener {} idle_timeout_ms must be greater than 0",
          listener.name
        );
      }
      validate_turn_opaque_string(&listener.name, "realm", &listener.realm, 763)?;
      listener.auth.validate(&listener.name)?;
      listener.limits.validate(&listener.name)?;
      match listener.mode {
        WebRtcTurnListenerMode::ProxyPool => {
          if listener.stream_outbound_queue_capacity != DEFAULT_TURN_STREAM_OUTBOUND_QUEUE_CAPACITY
          {
            bail!(
              "WebRTC TURN listener {} stream_outbound_queue_capacity is only valid when mode = \"edge_relay\"",
              listener.name
            );
          }
          if listener.auth.mode == TurnAuthMode::Enforce {
            bail!(
              "WebRTC TURN listener {} proxy_pool allows auth.mode = \"pass_through\" or \"validate\"",
              listener.name
            );
          }
          if listener.udp_binds().next().is_some() {
            validate_turn_listener_pool(
              &listener.name,
              "udp_pool",
              listener.udp_pool.as_deref(),
              "turn",
              turn_pools,
            )?;
          }
          if listener.tcp_binds().next().is_some() {
            validate_turn_listener_pool(
              &listener.name,
              "tcp_pool",
              listener.tcp_pool.as_deref(),
              "turn+tcp",
              turn_pools,
            )?;
          }
          if listener.tls_binds().next().is_some() {
            validate_turn_listener_pool(
              &listener.name,
              "tls_pool",
              listener.tls_pool.as_deref(),
              "turns",
              turn_pools,
            )?;
          }
          if listener.public_ip.is_some()
            || listener.relay_bind_ip.is_some()
            || listener.relay_port_range.is_some()
            || !listener.relay_families.is_empty()
          {
            bail!(
              "WebRTC TURN listener {} edge relay fields are only valid when mode = \"edge_relay\"",
              listener.name
            );
          }
        }
        WebRtcTurnListenerMode::EdgeRelay => {
          if listener.auth.mode != TurnAuthMode::Enforce {
            bail!(
              "WebRTC TURN listener {} edge_relay requires auth.mode = \"enforce\"",
              listener.name
            );
          }
          if listener.relay_families.is_empty() {
            bail!(
              "WebRTC TURN listener {} edge_relay requires relay_families or legacy public_ip/relay_bind_ip/relay_port_range",
              listener.name
            );
          }
          let mut relay_families = HashSet::new();
          for family in &listener.relay_families {
            if !relay_families.insert(family.family) {
              bail!(
                "WebRTC TURN listener {} has duplicate relay family {:?}",
                listener.name,
                family.family
              );
            }
            family.validate(&listener.name)?;
          }
          if listener.udp_pool.is_some()
            || listener.tcp_pool.is_some()
            || listener.tls_pool.is_some()
          {
            bail!(
              "WebRTC TURN listener {} upstream pools are only valid when mode = \"proxy_pool\"",
              listener.name
            );
          }
        }
      }
      if listener.tls_binds().next().is_none() && listener.tls.has_override() {
        bail!(
          "WebRTC TURN listener {} tls override is only valid with bind_tls",
          listener.name
        );
      }
      listener.tls.validate(&listener.name)?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct RawWebRtcTurnListenerConfig {
  name: String,
  #[serde(default)]
  mode: WebRtcTurnListenerMode,
  #[serde(default)]
  bind_udp: Option<SocketAddr>,
  #[serde(default)]
  bind_udp_additional: Vec<SocketAddr>,
  #[serde(default)]
  bind_tcp: Option<SocketAddr>,
  #[serde(default)]
  bind_tcp_additional: Vec<SocketAddr>,
  #[serde(default)]
  bind_tls: Option<SocketAddr>,
  #[serde(default)]
  bind_tls_additional: Vec<SocketAddr>,
  #[serde(default = "default_client_idle_timeout_ms")]
  idle_timeout_ms: u64,
  #[serde(default = "default_turn_realm")]
  realm: String,
  #[serde(default)]
  auth: TurnAuthConfig,
  #[serde(default)]
  udp_pool: Option<String>,
  #[serde(default)]
  tcp_pool: Option<String>,
  #[serde(default)]
  tls_pool: Option<String>,
  #[serde(default)]
  public_ip: Option<IpAddr>,
  #[serde(default)]
  relay_bind_ip: Option<IpAddr>,
  #[serde(default)]
  relay_port_range: Option<TurnRelayPortRange>,
  #[serde(default)]
  relay_families: Vec<TurnRelayFamilyConfig>,
  #[serde(default)]
  limits: TurnEdgeRelayLimitsConfig,
  #[serde(default)]
  peer_policy: TurnEdgeRelayPeerPolicyConfig,
  #[serde(default)]
  stream_outbound_queue_capacity: Option<TurnStreamOutboundQueueCapacitySetting>,
  #[serde(default)]
  tls: TurnListenerTlsConfig,
}

impl RawWebRtcTurnListenerConfig {
  pub(super) fn resolve(
    self,
    available_parallelism: usize,
  ) -> anyhow::Result<WebRtcTurnListenerConfig> {
    if self.mode == WebRtcTurnListenerMode::ProxyPool
      && self.stream_outbound_queue_capacity.is_some()
    {
      bail!(
        "WebRTC TURN listener {} stream_outbound_queue_capacity is only valid when mode = \"edge_relay\"",
        self.name
      );
    }
    let stream_outbound_queue_capacity = match self.stream_outbound_queue_capacity {
      Some(setting) => setting.resolve(&self.name, available_parallelism)?,
      None => DEFAULT_TURN_STREAM_OUTBOUND_QUEUE_CAPACITY,
    };
    let relay_families = resolve_relay_families(
      &self.name,
      self.public_ip,
      self.relay_bind_ip,
      self.relay_port_range.clone(),
      self.relay_families,
    )?;
    Ok(WebRtcTurnListenerConfig {
      name: self.name,
      mode: self.mode,
      bind_udp: self.bind_udp,
      bind_udp_additional: self.bind_udp_additional,
      bind_tcp: self.bind_tcp,
      bind_tcp_additional: self.bind_tcp_additional,
      bind_tls: self.bind_tls,
      bind_tls_additional: self.bind_tls_additional,
      idle_timeout_ms: self.idle_timeout_ms,
      realm: self.realm,
      auth: self.auth,
      udp_pool: self.udp_pool,
      tcp_pool: self.tcp_pool,
      tls_pool: self.tls_pool,
      public_ip: self.public_ip,
      relay_bind_ip: self.relay_bind_ip,
      relay_port_range: self.relay_port_range,
      relay_families,
      limits: self.limits,
      peer_policy: self.peer_policy,
      stream_outbound_queue_capacity,
      tls: self.tls,
    })
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WebRtcTurnListenerConfig {
  pub name: String,
  #[serde(default)]
  pub mode: WebRtcTurnListenerMode,
  #[serde(default)]
  pub bind_udp: Option<SocketAddr>,
  #[serde(default)]
  pub bind_udp_additional: Vec<SocketAddr>,
  #[serde(default)]
  pub bind_tcp: Option<SocketAddr>,
  #[serde(default)]
  pub bind_tcp_additional: Vec<SocketAddr>,
  #[serde(default)]
  pub bind_tls: Option<SocketAddr>,
  #[serde(default)]
  pub bind_tls_additional: Vec<SocketAddr>,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default = "default_turn_realm")]
  pub realm: String,
  #[serde(default)]
  pub auth: TurnAuthConfig,
  #[serde(default)]
  pub udp_pool: Option<String>,
  #[serde(default)]
  pub tcp_pool: Option<String>,
  #[serde(default)]
  pub tls_pool: Option<String>,
  #[serde(default)]
  pub public_ip: Option<IpAddr>,
  #[serde(default)]
  pub relay_bind_ip: Option<IpAddr>,
  #[serde(default)]
  pub relay_port_range: Option<TurnRelayPortRange>,
  #[serde(default)]
  pub relay_families: Vec<TurnRelayFamilyConfig>,
  #[serde(default)]
  pub limits: TurnEdgeRelayLimitsConfig,
  #[serde(default)]
  pub peer_policy: TurnEdgeRelayPeerPolicyConfig,
  #[serde(default = "default_turn_stream_outbound_queue_capacity")]
  pub stream_outbound_queue_capacity: usize,
  #[serde(default)]
  pub tls: TurnListenerTlsConfig,
}

impl WebRtcTurnListenerConfig {
  pub fn udp_binds(&self) -> impl Iterator<Item = SocketAddr> + '_ {
    self
      .bind_udp
      .into_iter()
      .chain(self.bind_udp_additional.iter().copied())
  }

  pub fn tcp_binds(&self) -> impl Iterator<Item = SocketAddr> + '_ {
    self
      .bind_tcp
      .into_iter()
      .chain(self.bind_tcp_additional.iter().copied())
  }

  pub fn tls_binds(&self) -> impl Iterator<Item = SocketAddr> + '_ {
    self
      .bind_tls
      .into_iter()
      .chain(self.bind_tls_additional.iter().copied())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcTurnListenerMode {
  #[default]
  ProxyPool,
  EdgeRelay,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnRelayPortRange {
  pub start: u16,
  pub end: u16,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct TurnListenerTlsConfig {
  #[serde(default)]
  pub cert_chain: Option<PathBuf>,
  #[serde(default)]
  pub private_key: Option<PathBuf>,
  #[serde(default)]
  pub remote_signer_key_id: Option<String>,
  #[serde(default)]
  pub resumption: Option<TlsServerResumptionConfig>,
}

impl TurnListenerTlsConfig {
  pub fn has_override(&self) -> bool {
    self.cert_chain.is_some()
      || self.private_key.is_some()
      || self.remote_signer_key_id.is_some()
      || self.resumption.is_some()
  }

  fn validate(&self, listener_name: &str) -> anyhow::Result<()> {
    match (
      &self.cert_chain,
      &self.private_key,
      &self.remote_signer_key_id,
    ) {
      (None, None, None) => Ok(()),
      (Some(_), Some(_), None) => Ok(()),
      (Some(_), None, Some(key_id)) => {
        if key_id.trim().is_empty() {
          bail!(
            "WebRTC TURN listener {} tls.remote_signer_key_id must not be empty",
            listener_name
          );
        }
        Ok(())
      }
      (Some(_), Some(_), Some(_)) => bail!(
        "WebRTC TURN listener {} tls override must set exactly one of private_key or remote_signer_key_id",
        listener_name
      ),
      _ => bail!(
        "WebRTC TURN listener {} tls override requires cert_chain and exactly one of private_key or remote_signer_key_id",
        listener_name
      ),
    }
  }

  pub(super) fn resolve_relative_paths(
    &mut self,
    cert_dir: &Path,
  ) -> anyhow::Result<TurnListenerTlsSourcePaths> {
    let mut source_paths = TurnListenerTlsSourcePaths::default();
    self.cert_chain = self
      .cert_chain
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "webrtc_turn_listeners.tls.cert_chain",
          cert_dir,
          &path,
        )?;
        source_paths.cert_chain = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    self.private_key = self
      .private_key
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "webrtc_turn_listeners.tls.private_key",
          cert_dir,
          &path,
        )?;
        source_paths.private_key = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    Ok(source_paths)
  }

  pub(crate) fn reload_relative_paths(
    &mut self,
    cert_dir: &Path,
    source_paths: &TurnListenerTlsSourcePaths,
  ) -> anyhow::Result<()> {
    self.cert_chain = source_paths
      .cert_chain
      .as_ref()
      .map(|path| reload_turn_tls_path("webrtc_turn_listeners.tls.cert_chain", cert_dir, path))
      .transpose()?;
    self.private_key = source_paths
      .private_key
      .as_ref()
      .map(|path| reload_turn_tls_path("webrtc_turn_listeners.tls.private_key", cert_dir, path))
      .transpose()?;
    Ok(())
  }
}

fn reload_turn_tls_path(field_name: &str, cert_dir: &Path, path: &Path) -> anyhow::Result<PathBuf> {
  let relative = path
    .strip_prefix(cert_dir)
    .map_err(|_| anyhow!("{field_name} must stay within the configured directory"))?;
  resolve_existing_local_config_file_path_with_logical(field_name, cert_dir, relative)
    .map(|(resolved, _)| resolved)
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnUpstreamPoolConfig {
  pub name: String,
  #[serde(default)]
  pub algorithm: LoadBalancingAlgorithm,
  #[serde(default)]
  pub hash_key: Option<String>,
  #[serde(default)]
  pub servers: Vec<TurnUpstreamPoolServerConfig>,
  #[serde(default)]
  pub health_check: TurnUpstreamPoolHealthCheckConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnUpstreamPoolServerConfig {
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
  #[serde(default)]
  pub tls: UpstreamTlsConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnUpstreamPoolHealthCheckConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_health_check_interval_ms")]
  pub interval_ms: u64,
  #[serde(default = "default_health_check_timeout_ms")]
  pub timeout_ms: u64,
  #[serde(default = "default_turn_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_turn_tls_handshake_timeout_ms")]
  pub tls_handshake_timeout_ms: u64,
  #[serde(default = "default_health_check_healthy_threshold")]
  pub healthy_threshold: u32,
  #[serde(default = "default_health_check_unhealthy_threshold")]
  pub unhealthy_threshold: u32,
}

impl Default for TurnUpstreamPoolHealthCheckConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      interval_ms: default_health_check_interval_ms(),
      timeout_ms: default_health_check_timeout_ms(),
      connect_timeout_ms: default_turn_connect_timeout_ms(),
      tls_handshake_timeout_ms: default_turn_tls_handshake_timeout_ms(),
      healthy_threshold: default_health_check_healthy_threshold(),
      unhealthy_threshold: default_health_check_unhealthy_threshold(),
    }
  }
}

fn validate_turn_origin(label: &str, origin: &Url) -> anyhow::Result<()> {
  if !matches!(origin.scheme(), "turn" | "turn+tcp" | "turns") {
    bail!(
      "{label} server origin must use turn://, turn+tcp://, or turns://, got {}",
      origin
    );
  }
  if origin.host_str().is_none() {
    bail!("{label} server origin must include a host");
  }
  if !matches!(origin.path(), "" | "/") || origin.query().is_some() || origin.fragment().is_some() {
    bail!("{label} server origin must not include a path, query, or fragment");
  }
  Ok(())
}

fn turn_origin_scheme(scheme: &str) -> &'static str {
  match scheme {
    "turn" => "turn",
    "turn+tcp" => "turn+tcp",
    "turns" => "turns",
    _ => unreachable!("validated TURN origin scheme"),
  }
}

fn validate_turn_listener_pool(
  listener_name: &str,
  field: &str,
  pool: Option<&str>,
  expected_scheme: &'static str,
  turn_pools: &HashMap<String, HashSet<&'static str>>,
) -> anyhow::Result<()> {
  let pool = pool
    .ok_or_else(|| anyhow!("WebRTC TURN listener {listener_name} proxy_pool requires {field}"))?;
  let Some(schemes) = turn_pools.get(pool) else {
    bail!("WebRTC TURN listener {listener_name} references unknown TURN upstream pool {pool}");
  };
  if schemes.iter().any(|scheme| *scheme != expected_scheme) {
    bail!(
      "WebRTC TURN listener {listener_name} {field} requires TURN upstream pool {pool} to use {expected_scheme}:// servers only"
    );
  }
  Ok(())
}

fn default_turn_realm() -> String {
  "oxibelt".to_string()
}

fn default_turn_connect_timeout_ms() -> u64 {
  3_000
}

fn default_turn_tls_handshake_timeout_ms() -> u64 {
  5_000
}
