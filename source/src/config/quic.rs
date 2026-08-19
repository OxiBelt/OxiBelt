//! QUIC transport configuration validation.
//! Retry, key, and stream settings are checked before endpoint construction.

use std::net::SocketAddr;

use anyhow::bail;
use serde::Deserialize;

use super::default_true;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QuicZeroRttMode {
  #[default]
  Off,
  SafeMethods,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicAltSvcConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_quic_alt_svc_max_age_seconds")]
  pub max_age_seconds: u64,
  #[serde(default)]
  pub persist: bool,
  #[serde(default)]
  pub port_overrides: Vec<QuicAltSvcPortOverrideConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicAltSvcPortOverrideConfig {
  pub bind: SocketAddr,
  pub advertised_port: u16,
}

impl Default for QuicAltSvcConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      max_age_seconds: default_quic_alt_svc_max_age_seconds(),
      persist: false,
      port_overrides: Vec::new(),
    }
  }
}

const QUIC_VARINT_MAX: u64 = 4_611_686_018_427_387_903;
const QUIC_MIN_UDP_PAYLOAD_SIZE: u16 = 1200;
const QUIC_MAX_UDP_PAYLOAD_SIZE: u16 = 65_527;
const QUIC_UPSTREAM_RESOLUTION_MAX_ENDPOINT_COUNT: usize = 64;
const QUIC_UPSTREAM_RESOLUTION_MAX_TTL_MS: u64 = 3_600_000;
const QUIC_UPSTREAM_RESOLUTION_MAX_NEGATIVE_TTL_MS: u64 = 30_000;
const QUIC_UPSTREAM_RESOLUTION_MIN_ADDRESS_FAMILY_STAGGER_MS: u64 = 10;
const QUIC_UPSTREAM_RESOLUTION_MAX_ADDRESS_FAMILY_STAGGER_MS: u64 = 5_000;
const QUIC_UPSTREAM_RESOLUTION_MAX_CONNECT_ATTEMPTS: usize = 16;
const QUIC_UPSTREAM_RESOLUTION_MAX_COOLDOWN_MS: u64 = 300_000;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicTransportConfig {
  #[serde(default = "default_quic_max_concurrent_streams")]
  pub max_concurrent_bidi_streams: u64,
  #[serde(default = "default_quic_max_concurrent_streams")]
  pub max_concurrent_uni_streams: u64,
  #[serde(default = "default_quic_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default)]
  pub keep_alive_interval_ms: u64,
  #[serde(default = "default_quic_stream_receive_window_bytes")]
  pub stream_receive_window_bytes: u64,
  #[serde(default = "default_quic_receive_window_bytes")]
  pub receive_window_bytes: u64,
  #[serde(default = "default_quic_send_window_bytes")]
  pub send_window_bytes: u64,
  #[serde(default = "default_true")]
  pub send_fairness: bool,
  #[serde(default = "default_quic_datagram_buffer_bytes")]
  pub datagram_receive_buffer_bytes: usize,
  #[serde(default = "default_quic_datagram_buffer_bytes")]
  pub datagram_send_buffer_bytes: usize,
  #[serde(default = "default_quic_max_udp_payload_size")]
  pub max_udp_payload_size: u16,
  #[serde(default = "default_true")]
  pub gso: bool,
  #[serde(default = "default_quic_initial_mtu")]
  pub initial_mtu: u16,
  #[serde(default = "default_quic_min_mtu")]
  pub min_mtu: u16,
  #[serde(default)]
  pub mtu_discovery: QuicMtuDiscoveryConfig,
}

impl Default for QuicTransportConfig {
  fn default() -> Self {
    Self {
      max_concurrent_bidi_streams: default_quic_max_concurrent_streams(),
      max_concurrent_uni_streams: default_quic_max_concurrent_streams(),
      idle_timeout_ms: default_quic_idle_timeout_ms(),
      keep_alive_interval_ms: 0,
      stream_receive_window_bytes: default_quic_stream_receive_window_bytes(),
      receive_window_bytes: default_quic_receive_window_bytes(),
      send_window_bytes: default_quic_send_window_bytes(),
      send_fairness: true,
      datagram_receive_buffer_bytes: default_quic_datagram_buffer_bytes(),
      datagram_send_buffer_bytes: default_quic_datagram_buffer_bytes(),
      max_udp_payload_size: default_quic_max_udp_payload_size(),
      gso: true,
      initial_mtu: default_quic_initial_mtu(),
      min_mtu: default_quic_min_mtu(),
      mtu_discovery: QuicMtuDiscoveryConfig::default(),
    }
  }
}

impl QuicTransportConfig {
  pub fn validate(&self, path: &str) -> anyhow::Result<()> {
    if self.max_concurrent_bidi_streams == 0
      || self.max_concurrent_uni_streams == 0
      || self.idle_timeout_ms == 0
      || self.stream_receive_window_bytes == 0
      || self.receive_window_bytes == 0
      || self.send_window_bytes == 0
      || self.datagram_receive_buffer_bytes == 0
      || self.datagram_send_buffer_bytes == 0
    {
      bail!(
        "{path} numeric values must be greater than 0, except keep_alive_interval_ms = 0 disables keep-alive pings"
      );
    }
    if self.keep_alive_interval_ms > 0 && self.keep_alive_interval_ms >= self.idle_timeout_ms {
      bail!("{path}.keep_alive_interval_ms must be 0 or less than {path}.idle_timeout_ms");
    }
    if self.stream_receive_window_bytes > QUIC_VARINT_MAX {
      bail!("{path}.stream_receive_window_bytes must be at most {QUIC_VARINT_MAX}");
    }
    if self.receive_window_bytes > QUIC_VARINT_MAX {
      bail!("{path}.receive_window_bytes must be at most {QUIC_VARINT_MAX}");
    }
    let max_streams = self
      .max_concurrent_bidi_streams
      .max(self.max_concurrent_uni_streams);
    let max_receive_window_bytes = self.stream_receive_window_bytes.saturating_mul(max_streams);
    if self.receive_window_bytes > max_receive_window_bytes {
      bail!(
        "{path}.receive_window_bytes must be at most {max_receive_window_bytes} based on {path}.stream_receive_window_bytes and the larger concurrent stream limit"
      );
    }
    validate_quic_mtu_value(path, "max_udp_payload_size", self.max_udp_payload_size)?;
    validate_quic_mtu_value(path, "initial_mtu", self.initial_mtu)?;
    validate_quic_mtu_value(path, "min_mtu", self.min_mtu)?;
    if self.min_mtu > self.initial_mtu {
      bail!("{path}.min_mtu must be less than or equal to {path}.initial_mtu");
    }
    self.mtu_discovery.validate(path, self.initial_mtu)?;
    Ok(())
  }
}

fn validate_quic_mtu_value(path: &str, key: &str, value: u16) -> anyhow::Result<()> {
  if !(QUIC_MIN_UDP_PAYLOAD_SIZE..=QUIC_MAX_UDP_PAYLOAD_SIZE).contains(&value) {
    bail!(
      "{path}.{key} must be between {QUIC_MIN_UDP_PAYLOAD_SIZE} and {QUIC_MAX_UDP_PAYLOAD_SIZE}"
    );
  }
  Ok(())
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicMtuDiscoveryConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_quic_mtu_discovery_upper_bound")]
  pub upper_bound: u16,
  #[serde(default = "default_quic_mtu_discovery_interval_ms")]
  pub interval_ms: u64,
  #[serde(default = "default_quic_mtu_discovery_black_hole_cooldown_ms")]
  pub black_hole_cooldown_ms: u64,
  #[serde(default = "default_quic_mtu_discovery_minimum_change")]
  pub minimum_change: u16,
}

impl Default for QuicMtuDiscoveryConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      upper_bound: default_quic_mtu_discovery_upper_bound(),
      interval_ms: default_quic_mtu_discovery_interval_ms(),
      black_hole_cooldown_ms: default_quic_mtu_discovery_black_hole_cooldown_ms(),
      minimum_change: default_quic_mtu_discovery_minimum_change(),
    }
  }
}

impl QuicMtuDiscoveryConfig {
  fn validate(&self, path: &str, initial_mtu: u16) -> anyhow::Result<()> {
    let path = format!("{path}.mtu_discovery");
    validate_quic_mtu_value(&path, "upper_bound", self.upper_bound)?;
    if self.interval_ms == 0 || self.black_hole_cooldown_ms == 0 || self.minimum_change == 0 {
      bail!("{path} numeric values must be greater than 0");
    }
    if self.enabled && self.upper_bound < initial_mtu {
      bail!("{path}.upper_bound must be greater than or equal to the transport initial_mtu");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(crate) struct RawQuicTransportConfig {
  #[serde(default)]
  max_concurrent_bidi_streams: Option<u64>,
  #[serde(default)]
  max_concurrent_uni_streams: Option<u64>,
  #[serde(default)]
  idle_timeout_ms: Option<u64>,
  #[serde(default)]
  keep_alive_interval_ms: Option<u64>,
  #[serde(default)]
  stream_receive_window_bytes: Option<u64>,
  #[serde(default)]
  receive_window_bytes: Option<u64>,
  #[serde(default)]
  send_window_bytes: Option<u64>,
  #[serde(default)]
  send_fairness: Option<bool>,
  #[serde(default)]
  datagram_receive_buffer_bytes: Option<usize>,
  #[serde(default)]
  datagram_send_buffer_bytes: Option<usize>,
  #[serde(default)]
  max_udp_payload_size: Option<u16>,
  #[serde(default)]
  gso: Option<bool>,
  #[serde(default)]
  initial_mtu: Option<u16>,
  #[serde(default)]
  min_mtu: Option<u16>,
  #[serde(default)]
  mtu_discovery: Option<RawQuicMtuDiscoveryConfig>,
}

impl RawQuicTransportConfig {
  pub(crate) fn resolve(&self, base: &QuicTransportConfig) -> QuicTransportConfig {
    let mut resolved = base.clone();
    if let Some(value) = self.max_concurrent_bidi_streams {
      resolved.max_concurrent_bidi_streams = value;
    }
    if let Some(value) = self.max_concurrent_uni_streams {
      resolved.max_concurrent_uni_streams = value;
    }
    if let Some(value) = self.idle_timeout_ms {
      resolved.idle_timeout_ms = value;
    }
    if let Some(value) = self.keep_alive_interval_ms {
      resolved.keep_alive_interval_ms = value;
    }
    if let Some(value) = self.stream_receive_window_bytes {
      resolved.stream_receive_window_bytes = value;
    }
    if let Some(value) = self.receive_window_bytes {
      resolved.receive_window_bytes = value;
    }
    if let Some(value) = self.send_window_bytes {
      resolved.send_window_bytes = value;
    }
    if let Some(value) = self.send_fairness {
      resolved.send_fairness = value;
    }
    if let Some(value) = self.datagram_receive_buffer_bytes {
      resolved.datagram_receive_buffer_bytes = value;
    }
    if let Some(value) = self.datagram_send_buffer_bytes {
      resolved.datagram_send_buffer_bytes = value;
    }
    if let Some(value) = self.max_udp_payload_size {
      resolved.max_udp_payload_size = value;
    }
    if let Some(value) = self.gso {
      resolved.gso = value;
    }
    if let Some(value) = self.initial_mtu {
      resolved.initial_mtu = value;
    }
    if let Some(value) = self.min_mtu {
      resolved.min_mtu = value;
    }
    if let Some(mtu_discovery) = &self.mtu_discovery {
      resolved.mtu_discovery = mtu_discovery.resolve(&base.mtu_discovery);
    }
    resolved
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(super) struct RawQuicMtuDiscoveryConfig {
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub upper_bound: Option<u16>,
  #[serde(default)]
  pub interval_ms: Option<u64>,
  #[serde(default)]
  pub black_hole_cooldown_ms: Option<u64>,
  #[serde(default)]
  pub minimum_change: Option<u16>,
}

impl RawQuicMtuDiscoveryConfig {
  fn resolve(&self, base: &QuicMtuDiscoveryConfig) -> QuicMtuDiscoveryConfig {
    let mut resolved = base.clone();
    if let Some(value) = self.enabled {
      resolved.enabled = value;
    }
    if let Some(value) = self.upper_bound {
      resolved.upper_bound = value;
    }
    if let Some(value) = self.interval_ms {
      resolved.interval_ms = value;
    }
    if let Some(value) = self.black_hole_cooldown_ms {
      resolved.black_hole_cooldown_ms = value;
    }
    if let Some(value) = self.minimum_change {
      resolved.minimum_change = value;
    }
    resolved
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct QuicEndpointConfig {
  #[serde(default)]
  pub transport: QuicTransportConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct QuicUpstreamConfig {
  #[serde(default)]
  pub transport: QuicTransportConfig,
  #[serde(default)]
  pub resolution: QuicUpstreamResolutionConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicUpstreamResolutionConfig {
  #[serde(default = "default_quic_upstream_resolution_max_endpoint_count")]
  pub max_endpoint_count: usize,
  #[serde(default = "default_quic_upstream_resolution_min_ttl_ms")]
  pub min_ttl_ms: u64,
  #[serde(default = "default_quic_upstream_resolution_max_ttl_ms")]
  pub max_ttl_ms: u64,
  #[serde(default = "default_quic_upstream_resolution_negative_ttl_ms")]
  pub negative_ttl_ms: u64,
  #[serde(default = "default_quic_upstream_resolution_address_family_stagger_ms")]
  pub address_family_stagger_ms: u64,
  #[serde(default = "default_quic_upstream_resolution_max_connect_attempts")]
  pub max_connect_attempts: usize,
  #[serde(default = "default_quic_upstream_resolution_cooldown_base_ms")]
  pub cooldown_base_ms: u64,
  #[serde(default = "default_quic_upstream_resolution_cooldown_max_ms")]
  pub cooldown_max_ms: u64,
}

impl Default for QuicUpstreamResolutionConfig {
  fn default() -> Self {
    Self {
      max_endpoint_count: default_quic_upstream_resolution_max_endpoint_count(),
      min_ttl_ms: default_quic_upstream_resolution_min_ttl_ms(),
      max_ttl_ms: default_quic_upstream_resolution_max_ttl_ms(),
      negative_ttl_ms: default_quic_upstream_resolution_negative_ttl_ms(),
      address_family_stagger_ms: default_quic_upstream_resolution_address_family_stagger_ms(),
      max_connect_attempts: default_quic_upstream_resolution_max_connect_attempts(),
      cooldown_base_ms: default_quic_upstream_resolution_cooldown_base_ms(),
      cooldown_max_ms: default_quic_upstream_resolution_cooldown_max_ms(),
    }
  }
}

impl QuicUpstreamResolutionConfig {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    if !(1..=QUIC_UPSTREAM_RESOLUTION_MAX_ENDPOINT_COUNT).contains(&self.max_endpoint_count) {
      bail!(
        "quic.upstream.resolution.max_endpoint_count must be between 1 and {QUIC_UPSTREAM_RESOLUTION_MAX_ENDPOINT_COUNT}"
      );
    }
    if self.min_ttl_ms == 0 || self.min_ttl_ms > QUIC_UPSTREAM_RESOLUTION_MAX_TTL_MS {
      bail!(
        "quic.upstream.resolution.min_ttl_ms must be between 1 and {QUIC_UPSTREAM_RESOLUTION_MAX_TTL_MS}"
      );
    }
    if self.max_ttl_ms == 0 || self.max_ttl_ms > QUIC_UPSTREAM_RESOLUTION_MAX_TTL_MS {
      bail!(
        "quic.upstream.resolution.max_ttl_ms must be between 1 and {QUIC_UPSTREAM_RESOLUTION_MAX_TTL_MS}"
      );
    }
    if self.min_ttl_ms > self.max_ttl_ms {
      bail!(
        "quic.upstream.resolution.min_ttl_ms must be less than or equal to quic.upstream.resolution.max_ttl_ms"
      );
    }
    let maximum_negative_ttl_ms = self
      .max_ttl_ms
      .min(QUIC_UPSTREAM_RESOLUTION_MAX_NEGATIVE_TTL_MS);
    if self.negative_ttl_ms == 0 || self.negative_ttl_ms > maximum_negative_ttl_ms {
      bail!(
        "quic.upstream.resolution.negative_ttl_ms must be between 1 and {maximum_negative_ttl_ms}"
      );
    }
    if self.address_family_stagger_ms < QUIC_UPSTREAM_RESOLUTION_MIN_ADDRESS_FAMILY_STAGGER_MS
      || self.address_family_stagger_ms > QUIC_UPSTREAM_RESOLUTION_MAX_ADDRESS_FAMILY_STAGGER_MS
    {
      bail!(
        "quic.upstream.resolution.address_family_stagger_ms must be between {QUIC_UPSTREAM_RESOLUTION_MIN_ADDRESS_FAMILY_STAGGER_MS} and {QUIC_UPSTREAM_RESOLUTION_MAX_ADDRESS_FAMILY_STAGGER_MS}"
      );
    }
    if !(1..=QUIC_UPSTREAM_RESOLUTION_MAX_CONNECT_ATTEMPTS).contains(&self.max_connect_attempts) {
      bail!(
        "quic.upstream.resolution.max_connect_attempts must be between 1 and {QUIC_UPSTREAM_RESOLUTION_MAX_CONNECT_ATTEMPTS}"
      );
    }
    if self.cooldown_base_ms == 0 {
      bail!("quic.upstream.resolution.cooldown_base_ms must be greater than 0");
    }
    if self.cooldown_max_ms == 0 || self.cooldown_max_ms > QUIC_UPSTREAM_RESOLUTION_MAX_COOLDOWN_MS
    {
      bail!(
        "quic.upstream.resolution.cooldown_max_ms must be between 1 and {QUIC_UPSTREAM_RESOLUTION_MAX_COOLDOWN_MS}"
      );
    }
    if self.cooldown_base_ms > self.cooldown_max_ms {
      bail!(
        "quic.upstream.resolution.cooldown_base_ms must be less than or equal to quic.upstream.resolution.cooldown_max_ms"
      );
    }
    Ok(())
  }

  pub(crate) fn effective_max_connect_attempts(&self) -> usize {
    self.max_connect_attempts.min(self.max_endpoint_count)
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicUpstreamPoolConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_quic_upstream_pool_max_connections")]
  pub max_connections_per_upstream: usize,
  #[serde(default = "default_quic_upstream_pool_max_lifetime_ms")]
  pub max_lifetime_ms: u64,
}

impl Default for QuicUpstreamPoolConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      max_connections_per_upstream: default_quic_upstream_pool_max_connections(),
      max_lifetime_ms: default_quic_upstream_pool_max_lifetime_ms(),
    }
  }
}

fn default_quic_alt_svc_max_age_seconds() -> u64 {
  86_400
}

fn default_quic_max_concurrent_streams() -> u64 {
  100
}

fn default_quic_idle_timeout_ms() -> u64 {
  30_000
}

fn default_quic_datagram_buffer_bytes() -> usize {
  1024 * 1024
}

fn default_quic_stream_receive_window_bytes() -> u64 {
  1_250_000
}

fn default_quic_receive_window_bytes() -> u64 {
  8 * 1024 * 1024
}

fn default_quic_send_window_bytes() -> u64 {
  10_000_000
}

fn default_quic_max_udp_payload_size() -> u16 {
  1472
}

fn default_quic_initial_mtu() -> u16 {
  1200
}

fn default_quic_min_mtu() -> u16 {
  1200
}

fn default_quic_mtu_discovery_upper_bound() -> u16 {
  1452
}

fn default_quic_mtu_discovery_interval_ms() -> u64 {
  600_000
}

fn default_quic_mtu_discovery_black_hole_cooldown_ms() -> u64 {
  60_000
}

fn default_quic_mtu_discovery_minimum_change() -> u16 {
  20
}

fn default_quic_upstream_pool_max_connections() -> usize {
  1
}

fn default_quic_upstream_pool_max_lifetime_ms() -> u64 {
  600_000
}

fn default_quic_upstream_resolution_max_endpoint_count() -> usize {
  16
}

fn default_quic_upstream_resolution_min_ttl_ms() -> u64 {
  1_000
}

fn default_quic_upstream_resolution_max_ttl_ms() -> u64 {
  30_000
}

fn default_quic_upstream_resolution_negative_ttl_ms() -> u64 {
  1_000
}

fn default_quic_upstream_resolution_address_family_stagger_ms() -> u64 {
  250
}

fn default_quic_upstream_resolution_max_connect_attempts() -> usize {
  4
}

fn default_quic_upstream_resolution_cooldown_base_ms() -> u64 {
  1_000
}

fn default_quic_upstream_resolution_cooldown_max_ms() -> u64 {
  30_000
}
