//! Edge TURN relay-family configuration.

use std::net::IpAddr;

use anyhow::bail;
use serde::Deserialize;

use super::TurnRelayPortRange;

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TurnRelayAddressFamily {
  Ipv4,
  Ipv6,
}

impl TurnRelayAddressFamily {
  pub fn from_ip(ip: IpAddr) -> Self {
    match ip {
      IpAddr::V4(_) => Self::Ipv4,
      IpAddr::V6(_) => Self::Ipv6,
    }
  }

  pub fn stun_value(self) -> u8 {
    match self {
      Self::Ipv4 => 0x01,
      Self::Ipv6 => 0x02,
    }
  }

  pub fn from_stun_value(value: u8) -> Option<Self> {
    match value {
      0x01 => Some(Self::Ipv4),
      0x02 => Some(Self::Ipv6),
      _ => None,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnRelayFamilyConfig {
  pub family: TurnRelayAddressFamily,
  pub public_ip: IpAddr,
  pub relay_bind_ip: IpAddr,
  pub relay_port_range: TurnRelayPortRange,
}

impl TurnRelayFamilyConfig {
  pub(super) fn validate(&self, listener_name: &str) -> anyhow::Result<()> {
    if TurnRelayAddressFamily::from_ip(self.public_ip) != self.family {
      bail!(
        "WebRTC TURN listener {} relay family {:?} public_ip must use the same address family",
        listener_name,
        self.family
      );
    }
    if TurnRelayAddressFamily::from_ip(self.relay_bind_ip) != self.family {
      bail!(
        "WebRTC TURN listener {} relay family {:?} relay_bind_ip must use the same address family",
        listener_name,
        self.family
      );
    }
    if self.relay_port_range.start == 0
      || self.relay_port_range.end == 0
      || self.relay_port_range.start > self.relay_port_range.end
    {
      bail!(
        "WebRTC TURN listener {} relay_port_range must have positive start <= end",
        listener_name
      );
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TurnEdgeRelayLimitsConfig {
  #[serde(default = "default_turn_max_proxy_udp_sessions_per_listener")]
  pub max_proxy_udp_sessions_per_listener: usize,
  #[serde(default = "default_turn_max_pending_tcp_connections")]
  pub max_pending_tcp_connections: usize,
  #[serde(default = "default_turn_max_allocations_per_listener")]
  pub max_allocations_per_listener: usize,
  #[serde(default = "default_turn_max_allocations_per_client")]
  pub max_allocations_per_client: usize,
  #[serde(default = "default_turn_max_permissions_per_allocation")]
  pub max_permissions_per_allocation: usize,
  #[serde(default = "default_turn_max_channels_per_allocation")]
  pub max_channels_per_allocation: usize,
  #[serde(default = "default_turn_max_allocation_lifetime_seconds")]
  pub max_allocation_lifetime_seconds: u32,
}

impl Default for TurnEdgeRelayLimitsConfig {
  fn default() -> Self {
    Self {
      max_proxy_udp_sessions_per_listener: default_turn_max_proxy_udp_sessions_per_listener(),
      max_pending_tcp_connections: default_turn_max_pending_tcp_connections(),
      max_allocations_per_listener: default_turn_max_allocations_per_listener(),
      max_allocations_per_client: default_turn_max_allocations_per_client(),
      max_permissions_per_allocation: default_turn_max_permissions_per_allocation(),
      max_channels_per_allocation: default_turn_max_channels_per_allocation(),
      max_allocation_lifetime_seconds: default_turn_max_allocation_lifetime_seconds(),
    }
  }
}

impl TurnEdgeRelayLimitsConfig {
  pub(super) fn validate(&self, listener_name: &str) -> anyhow::Result<()> {
    if self.max_proxy_udp_sessions_per_listener == 0 {
      bail!(
        "WebRTC TURN listener {} limits.max_proxy_udp_sessions_per_listener must be greater than 0",
        listener_name
      );
    }
    if self.max_pending_tcp_connections == 0 {
      bail!(
        "WebRTC TURN listener {} limits.max_pending_tcp_connections must be greater than 0",
        listener_name
      );
    }
    if self.max_allocations_per_listener == 0 {
      bail!(
        "WebRTC TURN listener {} limits.max_allocations_per_listener must be greater than 0",
        listener_name
      );
    }
    if self.max_allocations_per_client == 0 {
      bail!(
        "WebRTC TURN listener {} limits.max_allocations_per_client must be greater than 0",
        listener_name
      );
    }
    if self.max_permissions_per_allocation == 0 {
      bail!(
        "WebRTC TURN listener {} limits.max_permissions_per_allocation must be greater than 0",
        listener_name
      );
    }
    if self.max_channels_per_allocation == 0 {
      bail!(
        "WebRTC TURN listener {} limits.max_channels_per_allocation must be greater than 0",
        listener_name
      );
    }
    if self.max_allocation_lifetime_seconds == 0 {
      bail!(
        "WebRTC TURN listener {} limits.max_allocation_lifetime_seconds must be greater than 0",
        listener_name
      );
    }
    Ok(())
  }
}

fn default_turn_max_proxy_udp_sessions_per_listener() -> usize {
  4096
}

fn default_turn_max_pending_tcp_connections() -> usize {
  1024
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct TurnEdgeRelayPeerPolicyConfig {
  #[serde(default)]
  pub allow_private_peers: bool,
  #[serde(default)]
  pub allow_loopback_peers: bool,
  #[serde(default)]
  pub allow_link_local_peers: bool,
  #[serde(default)]
  pub allow_unspecified_peers: bool,
  #[serde(default)]
  pub allow_multicast_peers: bool,
}

pub(super) fn resolve_relay_families(
  listener_name: &str,
  public_ip: Option<IpAddr>,
  relay_bind_ip: Option<IpAddr>,
  relay_port_range: Option<TurnRelayPortRange>,
  relay_families: Vec<TurnRelayFamilyConfig>,
) -> anyhow::Result<Vec<TurnRelayFamilyConfig>> {
  let legacy_fields = public_ip.is_some() || relay_bind_ip.is_some() || relay_port_range.is_some();
  if !relay_families.is_empty() {
    if legacy_fields {
      bail!(
        "WebRTC TURN listener {} must not mix relay_families with legacy public_ip, relay_bind_ip, or relay_port_range",
        listener_name
      );
    }
    return Ok(relay_families);
  }
  match (public_ip, relay_bind_ip, relay_port_range) {
    (None, None, None) => Ok(Vec::new()),
    (Some(public_ip), Some(relay_bind_ip), Some(relay_port_range)) => {
      Ok(vec![TurnRelayFamilyConfig {
        family: TurnRelayAddressFamily::from_ip(public_ip),
        public_ip,
        relay_bind_ip,
        relay_port_range,
      }])
    }
    _ => bail!(
      "WebRTC TURN listener {} legacy edge relay fields require public_ip, relay_bind_ip, and relay_port_range together",
      listener_name
    ),
  }
}

fn default_turn_max_allocations_per_listener() -> usize {
  4096
}

fn default_turn_max_allocations_per_client() -> usize {
  2
}

fn default_turn_max_permissions_per_allocation() -> usize {
  256
}

fn default_turn_max_channels_per_allocation() -> usize {
  256
}

fn default_turn_max_allocation_lifetime_seconds() -> u32 {
  600
}
