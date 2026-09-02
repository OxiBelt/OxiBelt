//! TURN edge request parsing and relay policy helpers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::config::{
  TurnEdgeRelayPeerPolicyConfig, TurnRelayAddressFamily, TurnRelayFamilyConfig,
  WebRtcTurnListenerConfig,
};

use super::super::protocol::{
  ATTR_ADDITIONAL_ADDRESS_FAMILY, ATTR_CHANNEL_NUMBER, ATTR_DONT_FRAGMENT, ATTR_EVEN_PORT,
  ATTR_LIFETIME, ATTR_REQUESTED_ADDRESS_FAMILY, ATTR_REQUESTED_TRANSPORT, ATTR_RESERVATION_TOKEN,
  StunMessage, attr_xor_addr, semantic_attributes,
};

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

  pub(super) fn response(self) -> (u16, &'static str) {
    (self.code, self.reason)
  }

  fn address_family_not_supported() -> Self {
    Self {
      code: 440,
      reason: "Address Family not Supported",
    }
  }
}

pub(super) fn address_family_attr(
  message: &StunMessage<'_>,
  kind: u16,
) -> Result<Option<TurnRelayAddressFamily>, TurnRequestError> {
  let Some(value) = singleton_attr(message, kind)? else {
    return Ok(None);
  };
  if value.len() != 4 {
    return Err(TurnRequestError::bad_request());
  }
  TurnRelayAddressFamily::from_stun_value(value[0])
    .map(Some)
    .ok_or_else(TurnRequestError::bad_request)
}

pub(super) fn lifetime_attr(message: &StunMessage<'_>) -> Result<Option<u32>, TurnRequestError> {
  let Some(value) = singleton_attr(message, ATTR_LIFETIME)? else {
    return Ok(None);
  };
  if value.len() != 4 {
    return Err(TurnRequestError::bad_request());
  }
  Ok(Some(u32::from_be_bytes([
    value[0], value[1], value[2], value[3],
  ])))
}

pub(super) fn singleton_xor_addr(
  message: &StunMessage<'_>,
  kind: u16,
) -> Result<Option<SocketAddr>, TurnRequestError> {
  singleton_attr(message, kind)?;
  attr_xor_addr(message, kind).map_err(|_| TurnRequestError::bad_request())
}

pub(super) fn singleton_attr<'a>(
  message: &'a StunMessage<'_>,
  kind: u16,
) -> Result<Option<&'a [u8]>, TurnRequestError> {
  let mut attrs = semantic_attributes(message)
    .iter()
    .filter(|attr| attr.kind == kind);
  let value = attrs.next().map(|attr| attr.value);
  if attrs.next().is_some() {
    return Err(TurnRequestError::bad_request());
  }
  Ok(value)
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
  const DEFAULT_LIFETIME_SECONDS: u32 = 600;
  let maximum = config.limits.max_allocation_lifetime_seconds;
  let default = DEFAULT_LIFETIME_SECONDS.min(maximum);
  match requested {
    Some(requested) if requested > DEFAULT_LIFETIME_SECONDS => requested.min(maximum),
    Some(_) | None => default,
  }
}

pub(super) fn requested_transport(message: &StunMessage<'_>) -> Result<u8, TurnRequestError> {
  let mut attrs = semantic_attributes(message)
    .iter()
    .filter(|attr| attr.kind == ATTR_REQUESTED_TRANSPORT);
  let value = attrs
    .next()
    .ok_or_else(TurnRequestError::bad_request)?
    .value;
  if attrs.next().is_some() || value.len() != 4 {
    return Err(TurnRequestError::bad_request());
  }
  Ok(value[0])
}

pub(super) fn channel_number(message: &StunMessage<'_>) -> Result<u16, TurnRequestError> {
  let mut attrs = semantic_attributes(message)
    .iter()
    .filter(|attr| attr.kind == ATTR_CHANNEL_NUMBER);
  let value = attrs
    .next()
    .ok_or_else(TurnRequestError::bad_request)?
    .value;
  if attrs.next().is_some() || value.len() != 4 {
    return Err(TurnRequestError::bad_request());
  }
  let channel = u16::from_be_bytes([value[0], value[1]]);
  (0x4000..=0x4fff)
    .contains(&channel)
    .then_some(channel)
    .ok_or_else(TurnRequestError::bad_request)
}

pub(super) fn has_tcp_forbidden_allocate_option(message: &StunMessage<'_>) -> bool {
  semantic_attributes(message).iter().any(|attr| {
    matches!(
      attr.kind,
      ATTR_DONT_FRAGMENT | ATTR_EVEN_PORT | ATTR_RESERVATION_TOKEN
    )
  })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum UdpRelayRequest {
  Any,
  Even { reserve_next: bool },
  Reservation([u8; 8]),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) struct UdpAllocateOptions {
  pub(super) dont_fragment: bool,
  pub(super) relay: UdpRelayRequest,
}

pub(super) fn udp_allocate_options(
  message: &StunMessage<'_>,
) -> Result<UdpAllocateOptions, TurnRequestError> {
  let dont_fragment = match singleton_attr(message, ATTR_DONT_FRAGMENT)? {
    Some([]) => true,
    Some(_) => return Err(TurnRequestError::bad_request()),
    None => false,
  };
  if dont_fragment {
    return Ok(UdpAllocateOptions {
      dont_fragment: true,
      relay: UdpRelayRequest::Any,
    });
  }
  let even_port = match singleton_attr(message, ATTR_EVEN_PORT)? {
    Some(value) if value.len() == 1 => Some(value[0] & 0x80 != 0),
    Some(_) => return Err(TurnRequestError::bad_request()),
    None => None,
  };
  let reservation_token = match singleton_attr(message, ATTR_RESERVATION_TOKEN)? {
    Some(value) if value.len() == 8 => {
      let mut token = [0u8; 8];
      token.copy_from_slice(value);
      Some(token)
    }
    Some(_) => return Err(TurnRequestError::bad_request()),
    None => None,
  };
  let requested_family = singleton_attr(message, ATTR_REQUESTED_ADDRESS_FAMILY)?;
  let additional_family = singleton_attr(message, ATTR_ADDITIONAL_ADDRESS_FAMILY)?;

  let relay = if let Some(token) = reservation_token {
    if even_port.is_some() || requested_family.is_some() || additional_family.is_some() {
      return Err(TurnRequestError::bad_request());
    }
    UdpRelayRequest::Reservation(token)
  } else if let Some(reserve_next) = even_port {
    if reserve_next && additional_family.is_some() {
      return Err(TurnRequestError::bad_request());
    }
    UdpRelayRequest::Even { reserve_next }
  } else {
    UdpRelayRequest::Any
  };

  Ok(UdpAllocateOptions {
    dont_fragment,
    relay,
  })
}

pub(super) fn peer_allowed(ip: IpAddr, policy: &TurnEdgeRelayPeerPolicyConfig) -> bool {
  match ip {
    IpAddr::V4(ip) => {
      if ipv4_is_non_public_special_use(ip) && !policy.allow_private_peers {
        return false;
      }
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
      if ip.to_ipv4_mapped().is_some() {
        return false;
      }
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

fn ipv4_is_non_public_special_use(ip: Ipv4Addr) -> bool {
  let value = u32::from(ip);
  ipv4_in_prefix(value, u32::from(Ipv4Addr::new(0, 0, 0, 0)), 8)
    || ipv4_in_prefix(value, u32::from(Ipv4Addr::new(100, 64, 0, 0)), 10)
    || ipv4_in_prefix(value, u32::from(Ipv4Addr::new(192, 0, 0, 0)), 24)
    || ipv4_in_prefix(value, u32::from(Ipv4Addr::new(198, 18, 0, 0)), 15)
    || ipv4_in_prefix(value, u32::from(Ipv4Addr::new(240, 0, 0, 0)), 4)
}

fn ipv4_in_prefix(value: u32, network: u32, prefix_len: u32) -> bool {
  let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
  value & mask == network & mask
}

#[cfg(test)]
mod tests {
  use crate::config::{
    TurnAuthConfig, TurnEdgeRelayLimitsConfig, TurnEdgeRelayPeerPolicyConfig,
    TurnListenerTlsConfig, TurnRelayFamilyConfig, TurnRelayPortRange, WebRtcTurnListenerMode,
  };
  use crate::turn::protocol::{
    ALLOCATE_REQUEST, ATTR_ADDITIONAL_ADDRESS_FAMILY, ATTR_LIFETIME, ATTR_REQUESTED_ADDRESS_FAMILY,
    ATTR_REQUESTED_TRANSPORT, CHANNEL_BIND_REQUEST, encode_message, parse_stun,
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
  fn allocation_lifetime_uses_rfc_default_for_small_or_zero_requests() {
    let mut config = edge_relay_config_with_dual_stack();
    config.limits.max_allocation_lifetime_seconds = 3_600;

    assert_eq!(allocation_lifetime(&config, None), 600);
    assert_eq!(allocation_lifetime(&config, Some(0)), 600);
    assert_eq!(allocation_lifetime(&config, Some(1)), 600);
    assert_eq!(allocation_lifetime(&config, Some(601)), 601);
    assert_eq!(allocation_lifetime(&config, Some(7_200)), 3_600);

    config.limits.max_allocation_lifetime_seconds = 300;
    assert_eq!(allocation_lifetime(&config, None), 300);
    assert_eq!(allocation_lifetime(&config, Some(1)), 300);
    assert_eq!(allocation_lifetime(&config, Some(601)), 300);
  }

  #[test]
  fn requested_transport_requires_one_four_byte_attribute() {
    for attrs in [
      vec![],
      vec![(ATTR_REQUESTED_TRANSPORT, vec![6])],
      vec![
        (ATTR_REQUESTED_TRANSPORT, vec![6, 0, 0, 0]),
        (ATTR_REQUESTED_TRANSPORT, vec![6, 0, 0, 0]),
      ],
    ] {
      let bytes = encode_message(ALLOCATE_REQUEST, [20; 12], &attrs);
      let message = parse_stun(&bytes).expect("structurally valid request");
      assert!(requested_transport(&message).is_err());
    }
    let bytes = encode_message(
      ALLOCATE_REQUEST,
      [21; 12],
      &[(ATTR_REQUESTED_TRANSPORT, vec![6, 0, 0, 0])],
    );
    assert_eq!(
      requested_transport(&parse_stun(&bytes).expect("valid request")).expect("valid transport"),
      6
    );
  }

  #[test]
  fn singleton_allocate_attributes_reject_duplicates_and_invalid_lengths() {
    for attrs in [
      vec![
        (ATTR_LIFETIME, 60u32.to_be_bytes().to_vec()),
        (ATTR_LIFETIME, 60u32.to_be_bytes().to_vec()),
      ],
      vec![(ATTR_LIFETIME, vec![0, 0, 0])],
    ] {
      let bytes = encode_message(ALLOCATE_REQUEST, [25; 12], &attrs);
      assert!(lifetime_attr(&parse_stun(&bytes).unwrap()).is_err());
    }
    let duplicated_family = encode_message(
      ALLOCATE_REQUEST,
      [26; 12],
      &[
        (ATTR_REQUESTED_ADDRESS_FAMILY, vec![1, 0, 0, 0]),
        (ATTR_REQUESTED_ADDRESS_FAMILY, vec![1, 0, 0, 0]),
      ],
    );
    assert!(
      address_family_attr(
        &parse_stun(&duplicated_family).unwrap(),
        ATTR_REQUESTED_ADDRESS_FAMILY,
      )
      .is_err()
    );
  }

  #[test]
  fn channel_number_uses_rfc8656_range_and_tcp_allocate_options_are_detected() {
    for channel in [0x4000u16, 0x4fff] {
      let bytes = encode_message(
        CHANNEL_BIND_REQUEST,
        [22; 12],
        &[(
          ATTR_CHANNEL_NUMBER,
          channel.to_be_bytes().into_iter().chain([0, 0]).collect(),
        )],
      );
      assert_eq!(
        channel_number(&parse_stun(&bytes).expect("valid ChannelBind")).expect("valid channel"),
        channel
      );
    }
    let reserved = encode_message(
      CHANNEL_BIND_REQUEST,
      [23; 12],
      &[(ATTR_CHANNEL_NUMBER, vec![0x50, 0, 0, 0])],
    );
    assert!(channel_number(&parse_stun(&reserved).expect("reserved ChannelBind")).is_err());

    for kind in [ATTR_DONT_FRAGMENT, ATTR_EVEN_PORT, ATTR_RESERVATION_TOKEN] {
      let bytes = encode_message(ALLOCATE_REQUEST, [24; 12], &[(kind, vec![])]);
      assert!(has_tcp_forbidden_allocate_option(
        &parse_stun(&bytes).expect("option request")
      ));
    }
  }

  #[test]
  fn udp_allocate_options_enforce_exact_shapes_and_conflicts() {
    let parse = |attrs: &[(u16, Vec<u8>)]| {
      let bytes = encode_message(ALLOCATE_REQUEST, [27; 12], attrs);
      let message = parse_stun(&bytes).expect("option request");
      udp_allocate_options(&message)
    };

    assert_eq!(
      parse(&[(ATTR_EVEN_PORT, vec![0])]).unwrap().relay,
      UdpRelayRequest::Even {
        reserve_next: false
      }
    );
    assert_eq!(
      parse(&[(ATTR_EVEN_PORT, vec![0x80])]).unwrap().relay,
      UdpRelayRequest::Even { reserve_next: true }
    );
    assert_eq!(
      parse(&[(ATTR_RESERVATION_TOKEN, vec![7; 8])])
        .unwrap()
        .relay,
      UdpRelayRequest::Reservation([7; 8])
    );
    assert!(
      parse(&[(ATTR_DONT_FRAGMENT, Vec::new())])
        .unwrap()
        .dont_fragment
    );

    for attrs in [
      vec![(ATTR_DONT_FRAGMENT, vec![0])],
      vec![(ATTR_EVEN_PORT, Vec::new())],
      vec![(ATTR_RESERVATION_TOKEN, vec![0; 7])],
      vec![(ATTR_EVEN_PORT, vec![0]), (ATTR_EVEN_PORT, vec![0x80])],
      vec![
        (ATTR_RESERVATION_TOKEN, vec![1; 8]),
        (ATTR_EVEN_PORT, vec![0]),
      ],
      vec![
        (ATTR_RESERVATION_TOKEN, vec![1; 8]),
        (ATTR_REQUESTED_ADDRESS_FAMILY, vec![1, 0, 0, 0]),
      ],
      vec![
        (ATTR_EVEN_PORT, vec![0x80]),
        (ATTR_ADDITIONAL_ADDRESS_FAMILY, vec![2, 0, 0, 0]),
      ],
    ] {
      assert!(
        parse(&attrs).is_err(),
        "attributes should be rejected: {attrs:?}"
      );
    }
  }

  #[test]
  fn peer_policy_denies_private_special_use_and_nat66_targets_by_default() {
    let policy = TurnEdgeRelayPeerPolicyConfig::default();

    for peer in [
      "0.0.0.1",
      "10.0.0.10",
      "100.64.0.1",
      "192.0.0.1",
      "198.18.0.1",
      "240.0.0.1",
      "fc00::10",
    ] {
      assert!(
        !peer_allowed(peer.parse().expect("ip"), &policy),
        "special-use peer {peer} must be rejected by default"
      );
    }
    assert!(peer_allowed("203.0.113.10".parse().expect("ip"), &policy));
    assert!(peer_allowed("2001:db8::10".parse().expect("ip"), &policy));
  }

  #[test]
  fn private_peer_opt_in_includes_shared_and_benchmark_networks() {
    let policy = TurnEdgeRelayPeerPolicyConfig {
      allow_private_peers: true,
      ..Default::default()
    };

    assert!(peer_allowed("100.64.0.1".parse().expect("ip"), &policy));
    assert!(peer_allowed("198.18.0.1".parse().expect("ip"), &policy));
  }

  #[test]
  fn peer_policy_denies_ipv4_mapped_ipv6_targets() {
    let policy = TurnEdgeRelayPeerPolicyConfig::default();

    for peer in [
      "::ffff:10.0.0.10",
      "::ffff:127.0.0.1",
      "::ffff:169.254.0.10",
      "::ffff:0.0.0.0",
      "::ffff:224.0.0.1",
      "::ffff:255.255.255.255",
      "::ffff:203.0.113.10",
    ] {
      assert!(
        !peer_allowed(peer.parse().expect("ip"), &policy),
        "IPv4-mapped IPv6 peer {peer} must be rejected"
      );
    }
  }

  fn edge_relay_config_with_dual_stack() -> WebRtcTurnListenerConfig {
    WebRtcTurnListenerConfig {
      name: "edge-relay".to_string(),
      mode: WebRtcTurnListenerMode::EdgeRelay,
      bind_udp: None,
      bind_udp_additional: Vec::new(),
      bind_tcp: Some("127.0.0.1:0".parse().expect("socket addr")),
      bind_tcp_additional: Vec::new(),
      bind_tls: None,
      bind_tls_additional: Vec::new(),
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
