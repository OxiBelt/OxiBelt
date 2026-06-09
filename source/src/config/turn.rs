//! TURN listener and pool configuration validation.
//! TURN credentials and upstream references are checked before UDP/TCP listeners bind.

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
  Config, LoadBalancingAlgorithm, TlsServerResumptionConfig, UpstreamPoolServerState,
  default_client_idle_timeout_ms, default_pool_server_weight, default_true,
  resolve_existing_local_config_file_path_with_logical, turn_upstream_pool_server_id,
  validate_runtime_identifier,
};

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
        if pool.health_check.interval_ms == 0 || pool.health_check.timeout_ms == 0 {
          bail!(
            "TURN upstream pool {} health_check interval and timeout must be greater than 0",
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
    let mut binds = HashSet::new();
    for listener in &self.webrtc_turn_listeners {
      if listener.name.trim().is_empty() {
        bail!("WebRTC TURN listener name must not be empty");
      }
      if !names.insert(listener.name.clone()) {
        bail!("duplicate WebRTC TURN listener name: {}", listener.name);
      }
      if listener.bind_udp.is_none() && listener.bind_tcp.is_none() && listener.bind_tls.is_none() {
        bail!(
          "WebRTC TURN listener {} must configure at least one bind address",
          listener.name
        );
      }
      for (transport, bind) in [
        ("udp", listener.bind_udp),
        ("tcp", listener.bind_tcp),
        ("tls", listener.bind_tls),
      ] {
        if let Some(bind) = bind {
          if !binds.insert((transport, bind)) {
            bail!(
              "duplicate WebRTC TURN {transport} bind {} on listener {}",
              bind,
              listener.name
            );
          }
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
      listener.auth.validate(&listener.name)?;
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
          if listener.bind_udp.is_some() {
            validate_turn_listener_pool(
              &listener.name,
              "udp_pool",
              listener.udp_pool.as_deref(),
              "turn",
              turn_pools,
            )?;
          }
          if listener.bind_tcp.is_some() {
            validate_turn_listener_pool(
              &listener.name,
              "tcp_pool",
              listener.tcp_pool.as_deref(),
              "turn+tcp",
              turn_pools,
            )?;
          }
          if listener.bind_tls.is_some() {
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
          if listener.public_ip.is_none() {
            bail!(
              "WebRTC TURN listener {} edge_relay requires public_ip",
              listener.name
            );
          }
          if listener.relay_bind_ip.is_none() {
            bail!(
              "WebRTC TURN listener {} edge_relay requires relay_bind_ip",
              listener.name
            );
          }
          let range = listener.relay_port_range.as_ref().ok_or_else(|| {
            anyhow!(
              "WebRTC TURN listener {} edge_relay requires relay_port_range",
              listener.name
            )
          })?;
          if range.start == 0 || range.end == 0 || range.start > range.end {
            bail!(
              "WebRTC TURN listener {} relay_port_range must have positive start <= end",
              listener.name
            );
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
      if listener.bind_tls.is_none() && listener.tls.has_override() {
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
  bind_tcp: Option<SocketAddr>,
  #[serde(default)]
  bind_tls: Option<SocketAddr>,
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
    Ok(WebRtcTurnListenerConfig {
      name: self.name,
      mode: self.mode,
      bind_udp: self.bind_udp,
      bind_tcp: self.bind_tcp,
      bind_tls: self.bind_tls,
      idle_timeout_ms: self.idle_timeout_ms,
      realm: self.realm,
      auth: self.auth,
      udp_pool: self.udp_pool,
      tcp_pool: self.tcp_pool,
      tls_pool: self.tls_pool,
      public_ip: self.public_ip,
      relay_bind_ip: self.relay_bind_ip,
      relay_port_range: self.relay_port_range,
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
  pub bind_tcp: Option<SocketAddr>,
  #[serde(default)]
  pub bind_tls: Option<SocketAddr>,
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
  #[serde(default = "default_turn_stream_outbound_queue_capacity")]
  pub stream_outbound_queue_capacity: usize,
  #[serde(default)]
  pub tls: TurnListenerTlsConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcTurnListenerMode {
  #[default]
  ProxyPool,
  EdgeRelay,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnAuthConfig {
  #[serde(default)]
  pub mode: TurnAuthMode,
  #[serde(default)]
  pub static_credentials: Vec<TurnStaticCredentialConfig>,
  #[serde(default)]
  pub rest_shared_secret: Option<String>,
  #[serde(default)]
  pub rest_shared_secret_env: Option<String>,
  #[serde(default = "default_turn_nonce_ttl_seconds")]
  pub nonce_ttl_seconds: u64,
}

impl Default for TurnAuthConfig {
  fn default() -> Self {
    Self {
      mode: TurnAuthMode::PassThrough,
      static_credentials: Vec::new(),
      rest_shared_secret: None,
      rest_shared_secret_env: None,
      nonce_ttl_seconds: default_turn_nonce_ttl_seconds(),
    }
  }
}

impl TurnAuthConfig {
  fn validate(&self, listener_name: &str) -> anyhow::Result<()> {
    if self.nonce_ttl_seconds == 0 {
      bail!(
        "WebRTC TURN listener {} auth.nonce_ttl_seconds must be greater than 0",
        listener_name
      );
    }
    if self.rest_shared_secret.is_some() && self.rest_shared_secret_env.is_some() {
      bail!(
        "WebRTC TURN listener {} auth must not set both rest_shared_secret and rest_shared_secret_env",
        listener_name
      );
    }
    let has_static = !self.static_credentials.is_empty();
    let has_rest = self.rest_shared_secret.is_some() || self.rest_shared_secret_env.is_some();
    if matches!(self.mode, TurnAuthMode::Validate | TurnAuthMode::Enforce)
      && !has_static
      && !has_rest
    {
      bail!(
        "WebRTC TURN listener {} auth.mode requires static_credentials or rest_shared_secret",
        listener_name
      );
    }
    let mut usernames = HashSet::new();
    for credential in &self.static_credentials {
      if credential.username.trim().is_empty() {
        bail!(
          "WebRTC TURN listener {} static credential username must not be empty",
          listener_name
        );
      }
      if !usernames.insert(credential.username.as_str()) {
        bail!(
          "WebRTC TURN listener {} has duplicate static credential username {}",
          listener_name,
          credential.username
        );
      }
      if credential.password.is_some() && credential.password_env.is_some() {
        bail!(
          "WebRTC TURN listener {} static credential {} must not set both password and password_env",
          listener_name,
          credential.username
        );
      }
      if credential.password.is_none() && credential.password_env.is_none() {
        bail!(
          "WebRTC TURN listener {} static credential {} requires password or password_env",
          listener_name,
          credential.username
        );
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TurnAuthMode {
  #[default]
  PassThrough,
  Validate,
  Enforce,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnStaticCredentialConfig {
  pub username: String,
  #[serde(default)]
  pub password: Option<String>,
  #[serde(default)]
  pub password_env: Option<String>,
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

  pub(super) fn resolve_relative_paths(&mut self, cert_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut source_paths = Vec::new();
    self.cert_chain = self
      .cert_chain
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "webrtc_turn_listeners.tls.cert_chain",
          cert_dir,
          &path,
        )?;
        source_paths.push(logical);
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
        source_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    Ok(source_paths)
  }
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
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnUpstreamPoolHealthCheckConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_health_check_interval_ms")]
  pub interval_ms: u64,
  #[serde(default = "default_health_check_timeout_ms")]
  pub timeout_ms: u64,
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

fn default_turn_nonce_ttl_seconds() -> u64 {
  600
}
