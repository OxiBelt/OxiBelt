//! TURN edge request parsing and relay policy helpers.

use std::net::IpAddr;

use crate::config::{
  TurnEdgeRelayPeerPolicyConfig, TurnRelayAddressFamily, TurnRelayFamilyConfig,
  WebRtcTurnListenerConfig,
};

use super::super::protocol::{
  ATTR_ADDITIONAL_ADDRESS_FAMILY, ATTR_REQUESTED_ADDRESS_FAMILY, StunMessage, attr_bytes,
};
use super::{EdgeSender, relay::send_turn_error};

#[derive(Debug, Clone, Copy)]
pub(super) struct TurnRequestError {
  code: u16,
  reason: &'static str,
}

impl TurnRequestError {
  fn bad_request() -> Self {
    Self {
      code: 400,
      reason: "Bad Request",
    }
  }

  fn address_family_not_supported() -> Self {
    Self {
      code: 440,
      reason: "Address Family not Supported",
    }
  }

  pub(super) async fn send(
    self,
    sender: &EdgeSender,
    request_type: u16,
    transaction_id: [u8; 12],
  ) -> anyhow::Result<()> {
    send_turn_error(sender, request_type, transaction_id, self.code, self.reason).await
  }
}

pub(super) fn address_family_attr(
  message: &StunMessage<'_>,
  kind: u16,
) -> Result<Option<TurnRelayAddressFamily>, TurnRequestError> {
  let Some(value) = attr_bytes(message, kind) else {
    return Ok(None);
  };
  if value.len() != 4 {
    return Err(TurnRequestError::bad_request());
  }
  TurnRelayAddressFamily::from_stun_value(value[0])
    .map(Some)
    .ok_or_else(TurnRequestError::bad_request)
}

pub(super) fn allocate_families(
  config: &WebRtcTurnListenerConfig,
  message: &StunMessage<'_>,
) -> Result<Vec<TurnRelayAddressFamily>, TurnRequestError> {
  let requested = address_family_attr(message, ATTR_REQUESTED_ADDRESS_FAMILY)?;
  let additional = address_family_attr(message, ATTR_ADDITIONAL_ADDRESS_FAMILY)?;
  if requested.is_some() && additional.is_some() {
    return Err(TurnRequestError::bad_request());
  }
  if let Some(family) = requested {
    if relay_family_config(config, family).is_none() {
      return Err(TurnRequestError::address_family_not_supported());
    }
    return Ok(vec![family]);
  }
  if let Some(family) = additional {
    if family != TurnRelayAddressFamily::Ipv6 {
      return Err(TurnRequestError::bad_request());
    }
    if relay_family_config(config, TurnRelayAddressFamily::Ipv4).is_none()
      || relay_family_config(config, TurnRelayAddressFamily::Ipv6).is_none()
    {
      return Err(TurnRequestError::address_family_not_supported());
    }
    return Ok(vec![
      TurnRelayAddressFamily::Ipv4,
      TurnRelayAddressFamily::Ipv6,
    ]);
  }
  if relay_family_config(config, TurnRelayAddressFamily::Ipv4).is_some() {
    Ok(vec![TurnRelayAddressFamily::Ipv4])
  } else {
    Err(TurnRequestError::address_family_not_supported())
  }
}

pub(super) fn relay_family_config(
  config: &WebRtcTurnListenerConfig,
  family: TurnRelayAddressFamily,
) -> Option<&TurnRelayFamilyConfig> {
  config
    .relay_families
    .iter()
    .find(|relay| relay.family == family)
}

pub(super) fn allocation_lifetime(
  config: &WebRtcTurnListenerConfig,
  requested: Option<u32>,
) -> u32 {
  requested
    .unwrap_or(config.limits.max_allocation_lifetime_seconds)
    .min(config.limits.max_allocation_lifetime_seconds)
}

pub(super) fn peer_allowed(ip: IpAddr, policy: &TurnEdgeRelayPeerPolicyConfig) -> bool {
  match ip {
    IpAddr::V4(ip) => {
      if ip.is_private() && !policy.allow_private_peers {
        return false;
      }
      if ip.is_loopback() && !policy.allow_loopback_peers {
        return false;
      }
      if ip.is_link_local() && !policy.allow_link_local_peers {
        return false;
      }
      if ip.is_unspecified() && !policy.allow_unspecified_peers {
        return false;
      }
      if (ip.is_multicast() || ip.is_broadcast()) && !policy.allow_multicast_peers {
        return false;
      }
      true
    }
    IpAddr::V6(ip) => {
      if ip.is_unique_local() && !policy.allow_private_peers {
        return false;
      }
      if ip.is_loopback() && !policy.allow_loopback_peers {
        return false;
      }
      if ip.is_unicast_link_local() && !policy.allow_link_local_peers {
        return false;
      }
      if ip.is_unspecified() && !policy.allow_unspecified_peers {
        return false;
      }
      if ip.is_multicast() && !policy.allow_multicast_peers {
        return false;
      }
      true
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::config::{
    TurnAuthConfig, TurnEdgeRelayLimitsConfig, TurnEdgeRelayPeerPolicyConfig,
    TurnListenerTlsConfig, TurnRelayFamilyConfig, TurnRelayPortRange, WebRtcTurnListenerMode,
  };
  use crate::turn::protocol::{
    ALLOCATE_REQUEST, ATTR_ADDITIONAL_ADDRESS_FAMILY, ATTR_REQUESTED_ADDRESS_FAMILY,
    ATTR_REQUESTED_TRANSPORT, encode_message, parse_stun,
  };

  use super::*;

  #[test]
  fn allocate_families_defaults_to_ipv4_and_accepts_requested_ipv6() {
    let config = edge_relay_config_with_dual_stack();
    let txid = [9u8; 12];
    let default_request_bytes = encode_message(
      ALLOCATE_REQUEST,
      txid,
      &[(ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0])],
    );
    let default_request = parse_stun(&default_request_bytes).expect("request should parse");
    assert_eq!(
      allocate_families(&config, &default_request).expect("default family should resolve"),
      vec![TurnRelayAddressFamily::Ipv4]
    );

    let ipv6_request_bytes = encode_message(
      ALLOCATE_REQUEST,
      txid,
      &[
        (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
        (ATTR_REQUESTED_ADDRESS_FAMILY, vec![0x02, 0, 0, 0]),
      ],
    );
    let ipv6_request = parse_stun(&ipv6_request_bytes).expect("request should parse");
    assert_eq!(
      allocate_families(&config, &ipv6_request).expect("IPv6 family should resolve"),
      vec![TurnRelayAddressFamily::Ipv6]
    );
  }

  #[test]
  fn allocate_families_accepts_additional_dual_stack_request() {
    let config = edge_relay_config_with_dual_stack();
    let request_bytes = encode_message(
      ALLOCATE_REQUEST,
      [10u8; 12],
      &[
        (ATTR_REQUESTED_TRANSPORT, vec![17, 0, 0, 0]),
        (ATTR_ADDITIONAL_ADDRESS_FAMILY, vec![0x02, 0, 0, 0]),
      ],
    );
    let request = parse_stun(&request_bytes).expect("request should parse");

    assert_eq!(
      allocate_families(&config, &request).expect("dual stack request should resolve"),
      vec![TurnRelayAddressFamily::Ipv4, TurnRelayAddressFamily::Ipv6]
    );
  }

  #[test]
  fn peer_policy_denies_private_and_nat66_targets_by_default() {
    let policy = TurnEdgeRelayPeerPolicyConfig::default();

    assert!(!peer_allowed("10.0.0.10".parse().expect("ip"), &policy));
    assert!(!peer_allowed("fc00::10".parse().expect("ip"), &policy));
    assert!(peer_allowed("203.0.113.10".parse().expect("ip"), &policy));
    assert!(peer_allowed("2001:db8::10".parse().expect("ip"), &policy));
  }

  fn edge_relay_config_with_dual_stack() -> WebRtcTurnListenerConfig {
    WebRtcTurnListenerConfig {
      name: "edge-relay".to_string(),
      mode: WebRtcTurnListenerMode::EdgeRelay,
      bind_udp: None,
      bind_tcp: Some("127.0.0.1:0".parse().expect("socket addr")),
      bind_tls: None,
      idle_timeout_ms: 75_000,
      realm: "example.test".to_string(),
      auth: TurnAuthConfig::default(),
      udp_pool: None,
      tcp_pool: None,
      tls_pool: None,
      public_ip: None,
      relay_bind_ip: None,
      relay_port_range: None,
      relay_families: vec![
        TurnRelayFamilyConfig {
          family: TurnRelayAddressFamily::Ipv4,
          public_ip: "203.0.113.10".parse().expect("ip addr"),
          relay_bind_ip: "0.0.0.0".parse().expect("ip addr"),
          relay_port_range: TurnRelayPortRange {
            start: 49152,
            end: 49160,
          },
        },
        TurnRelayFamilyConfig {
          family: TurnRelayAddressFamily::Ipv6,
          public_ip: "2001:db8::10".parse().expect("ip addr"),
          relay_bind_ip: "::".parse().expect("ip addr"),
          relay_port_range: TurnRelayPortRange {
            start: 49152,
            end: 49160,
          },
        },
      ],
      limits: TurnEdgeRelayLimitsConfig::default(),
      peer_policy: TurnEdgeRelayPeerPolicyConfig::default(),
      stream_outbound_queue_capacity: 32,
      tls: TurnListenerTlsConfig::default(),
    }
  }
}
