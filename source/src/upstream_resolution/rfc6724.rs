//! RFC 6724 destination ordering using kernel-selected source addresses.

use std::cmp::Ordering;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::UdpSocket;

use super::ResolvedEndpoint;

pub(super) async fn sort_destinations(endpoints: &mut [ResolvedEndpoint]) {
  let mut probes = FuturesUnordered::new();
  for (index, endpoint) in endpoints.iter().enumerate() {
    probes.push(async move {
      let destination = endpoint.socket_addr();
      (index, probe_source(destination).await)
    });
  }
  let mut sources = vec![None; endpoints.len()];
  while let Some((index, source)) = probes.next().await {
    sources[index] = source;
  }
  drop(probes);
  let mut indexed = endpoints
    .iter()
    .cloned()
    .enumerate()
    .map(|(index, endpoint)| {
      let key = DestinationKey::new(endpoint.socket_addr().ip(), sources[index]);
      (index, endpoint, key)
    })
    .collect::<Vec<_>>();
  indexed.sort_by(compare_destination);
  for (slot, (_, endpoint, _)) in endpoints.iter_mut().zip(indexed) {
    *slot = endpoint;
  }
}

async fn probe_source(destination: SocketAddr) -> Option<IpAddr> {
  let bind = if destination.is_ipv4() {
    SocketAddr::from(([0, 0, 0, 0], 0))
  } else {
    SocketAddr::from(([0u16; 8], 0))
  };
  let socket = UdpSocket::bind(bind).await.ok()?;
  socket.connect(destination).await.ok()?;
  Some(socket.local_addr().ok()?.ip())
}

#[derive(Clone, Copy)]
struct DestinationKey {
  usable: bool,
  scope_matches: bool,
  label_matches: bool,
  precedence: u8,
  scope: u8,
  common_prefix: u32,
}

impl DestinationKey {
  fn new(destination: IpAddr, source: Option<IpAddr>) -> Self {
    let destination_v6 = mapped(destination);
    let (precedence, destination_label) = policy(destination_v6);
    let destination_scope = scope(destination);
    let source_policy = source.map(|source| policy(mapped(source)));
    Self {
      usable: source.is_some(),
      scope_matches: source.is_some_and(|source| scope(source) == destination_scope),
      label_matches: source_policy.is_some_and(|(_, label)| label == destination_label),
      precedence,
      scope: destination_scope,
      common_prefix: source
        .map(|source| (mapped(source) ^ destination_v6).leading_zeros())
        .unwrap_or(0),
    }
  }
}

fn compare_destination(
  left: &(usize, ResolvedEndpoint, DestinationKey),
  right: &(usize, ResolvedEndpoint, DestinationKey),
) -> Ordering {
  right
    .2
    .usable
    .cmp(&left.2.usable)
    .then_with(|| right.2.scope_matches.cmp(&left.2.scope_matches))
    .then_with(|| right.2.label_matches.cmp(&left.2.label_matches))
    .then_with(|| right.2.precedence.cmp(&left.2.precedence))
    .then_with(|| left.2.scope.cmp(&right.2.scope))
    .then_with(|| right.2.common_prefix.cmp(&left.2.common_prefix))
    .then_with(|| left.0.cmp(&right.0))
}

fn mapped(address: IpAddr) -> u128 {
  match address {
    IpAddr::V4(address) => u128::from(address.to_ipv6_mapped()),
    IpAddr::V6(address) => u128::from(address),
  }
}

fn policy(address: u128) -> (u8, u8) {
  const LOOPBACK: u128 = 1;
  const MAPPED_MASK: u128 = u128::MAX << 32;
  const MAPPED_PREFIX: u128 = 0xffff << 32;
  if address == LOOPBACK {
    return (50, 0);
  }
  if address & MAPPED_MASK == MAPPED_PREFIX {
    return (35, 4);
  }
  if prefix_matches(
    address,
    u128::from(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0)),
    16,
  ) {
    return (30, 2);
  }
  if prefix_matches(
    address,
    u128::from(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0)),
    32,
  ) {
    return (5, 5);
  }
  if prefix_matches(
    address,
    u128::from(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)),
    7,
  ) {
    return (3, 13);
  }
  if address >> 32 == 0 {
    return (1, 3);
  }
  if prefix_matches(
    address,
    u128::from(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0)),
    10,
  ) {
    return (1, 11);
  }
  if prefix_matches(
    address,
    u128::from(Ipv6Addr::new(0x3ffe, 0, 0, 0, 0, 0, 0, 0)),
    16,
  ) {
    return (1, 12);
  }
  (40, 1)
}

fn prefix_matches(address: u128, prefix: u128, length: u32) -> bool {
  let mask = u128::MAX.checked_shl(128 - length).unwrap_or(0);
  address & mask == prefix & mask
}

fn scope(address: IpAddr) -> u8 {
  match address {
    IpAddr::V4(address) if address.is_loopback() || address.is_link_local() => 2,
    IpAddr::V4(_) => 14,
    IpAddr::V6(address) if address.is_loopback() || address.is_unicast_link_local() => 2,
    IpAddr::V6(address) if site_local(address) => 5,
    IpAddr::V6(_) => 14,
  }
}

fn site_local(address: Ipv6Addr) -> bool {
  let first = address.segments()[0];
  first & 0xffc0 == 0xfec0
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;

  use super::*;

  #[test]
  fn default_policy_table_matches_rfc_6724_precedence_rows() {
    assert_eq!(policy(mapped(IpAddr::V6(Ipv6Addr::LOCALHOST))), (50, 0));
    assert_eq!(policy(mapped(IpAddr::V4(Ipv4Addr::LOCALHOST))), (35, 4));
    assert_eq!(
      policy(mapped(IpAddr::V6("2002::1".parse().unwrap()))),
      (30, 2)
    );
    assert_eq!(
      policy(mapped(IpAddr::V6("fc00::1".parse().unwrap()))),
      (3, 13)
    );
    assert_eq!(
      policy(mapped(IpAddr::V6("2001:db8::1".parse().unwrap()))),
      (40, 1)
    );
  }
}
