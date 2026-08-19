//! Fail-closed RFC7050/RFC6052 PREF64 discovery and synthesis.
//!
//! This module accepts only the two well-known IPv4 embeddings from an
//! absolute DNS-only `AAAA ipv4only.arpa` response. It uses no-send UDP route
//! selection only as a conservative capability gate; route-advertisement
//! validation remains a future route-aware provider responsibility.

use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::{DnsAnswer, DnsQueryType, lookup_dns_absolute_until};

const IPV4ONLY_ARPA: &str = "ipv4only.arpa.";
const MAX_PREF64_AAAA_ANSWERS: usize = 16;
const RFC6052_PREFIX_LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];
const RFC7050_FIRST: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 170);
const RFC7050_SECOND: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 171);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Pref64 {
  prefix: Ipv6Addr,
  prefix_len: u8,
}

impl Pref64 {
  fn new(prefix: Ipv6Addr, prefix_len: u8) -> Option<Self> {
    if !RFC6052_PREFIX_LENGTHS.contains(&prefix_len)
      || prefix.octets()[usize::from(prefix_len / 8)..]
        .iter()
        .any(|byte| *byte != 0)
    {
      return None;
    }
    Some(Self { prefix, prefix_len })
  }

  fn synthesize(self, ipv4: Ipv4Addr) -> Option<Ipv6Addr> {
    let mut octets = self.prefix.octets();
    let ipv4 = ipv4.octets();
    match self.prefix_len {
      32 => octets[4..8].copy_from_slice(&ipv4),
      40 => {
        octets[5..8].copy_from_slice(&ipv4[..3]);
        octets[9] = ipv4[3];
      }
      48 => {
        octets[6..8].copy_from_slice(&ipv4[..2]);
        octets[9..11].copy_from_slice(&ipv4[2..]);
      }
      56 => {
        octets[7] = ipv4[0];
        octets[9..12].copy_from_slice(&ipv4[1..]);
      }
      64 => octets[9..13].copy_from_slice(&ipv4),
      96 => octets[12..16].copy_from_slice(&ipv4),
      _ => return None,
    }
    Some(Ipv6Addr::from(octets))
  }
}

/// Discover a PREF64 only if a no-send UDP route probe can establish an
/// IPv6-only condition conservatively.
pub(crate) async fn discover_pref64_if_ipv6_only(deadline: Instant) -> Option<Pref64> {
  let lookup = lookup_dns_absolute_until(IPV4ONLY_ARPA, DnsQueryType::Aaaa, deadline)
    .await
    .ok()?;
  if lookup.accepted_cname() {
    return None;
  }
  let addresses = lookup
    .answers
    .into_iter()
    .filter_map(|answer| match answer {
      DnsAnswer::Ip(IpAddr::V6(address)) => Some(address),
      _ => None,
    })
    .collect::<Vec<_>>();
  let pref64 = pref64_from_ipv4only_answers(&addresses)?;
  ipv6_only_capability_probe(pref64).await.then_some(pref64)
}

/// Synthesize at most `max_count` IPv6 socket candidates from accepted IPv4
/// candidates. Ports must be the configured port; dynamic DNS metadata never
/// changes this path's egress authority.
pub(crate) async fn synthesize_pref64_ipv4_candidates(
  ipv4_candidates: &[SocketAddr],
  configured_port: u16,
  max_count: usize,
  deadline: Instant,
) -> Vec<SocketAddr> {
  if ipv4_candidates.is_empty() || configured_port == 0 || max_count == 0 {
    return Vec::new();
  }
  let Some(pref64) = discover_pref64_if_ipv6_only(deadline).await else {
    return Vec::new();
  };
  synthesize_candidates(pref64, ipv4_candidates, configured_port, max_count)
}

/// Probe route selection without sending any packets. A UDP `connect` only
/// fixes a peer and asks the OS to select a local route/source address.
///
/// The probe is deliberately stricter than "IPv6 works": IPv4 must fail with
/// `NetworkUnreachable`, while the synthesized RFC7050 destination must pick
/// a non-unspecified IPv6 source. Any bind, permission, route, or address
/// ambiguity fails closed. This does not validate Router Advertisements.
async fn ipv6_only_capability_probe(pref64: Pref64) -> bool {
  let Ok(ipv4_socket) = UdpSocket::bind("0.0.0.0:0").await else {
    return false;
  };
  let ipv4_probe = SocketAddr::new(IpAddr::V4(RFC7050_FIRST), 53);
  match ipv4_socket.connect(ipv4_probe).await {
    Err(error) if ipv4_route_is_unreachable(error.kind()) => {}
    Ok(()) | Err(_) => return false,
  }

  let Some(ipv6) = pref64.synthesize(RFC7050_FIRST) else {
    return false;
  };
  let Ok(ipv6_socket) = UdpSocket::bind("[::]:0").await else {
    return false;
  };
  if ipv6_socket
    .connect(SocketAddr::new(IpAddr::V6(ipv6), 53))
    .await
    .is_err()
  {
    return false;
  }
  ipv6_socket
    .local_addr()
    .is_ok_and(has_non_unspecified_ipv6_source)
}

fn ipv4_route_is_unreachable(kind: ErrorKind) -> bool {
  kind == ErrorKind::NetworkUnreachable
}

fn has_non_unspecified_ipv6_source(address: SocketAddr) -> bool {
  matches!(address, SocketAddr::V6(address) if !address.ip().is_unspecified())
}

fn pref64_from_ipv4only_answers(addresses: &[Ipv6Addr]) -> Option<Pref64> {
  if addresses.len() > MAX_PREF64_AAAA_ANSWERS {
    return None;
  }
  let mut candidates = HashMap::<Pref64, u8>::new();
  for address in addresses {
    for prefix_len in RFC6052_PREFIX_LENGTHS {
      let Some((pref64, embedded)) = pref64_from_rfc7050_answer(*address, prefix_len) else {
        continue;
      };
      let bit = match embedded {
        RFC7050_FIRST => 1,
        RFC7050_SECOND => 2,
        _ => continue,
      };
      let flags = candidates.entry(pref64).or_default();
      *flags |= bit;
    }
  }
  let mut complete = candidates
    .into_iter()
    .filter_map(|(pref64, flags)| (flags == 3).then_some(pref64));
  let pref64 = complete.next()?;
  complete.next().is_none().then_some(pref64)
}

fn pref64_from_rfc7050_answer(address: Ipv6Addr, prefix_len: u8) -> Option<(Pref64, Ipv4Addr)> {
  let octets = address.octets();
  let embedded = match prefix_len {
    32 if octets[8..].iter().all(|byte| *byte == 0) => [octets[4], octets[5], octets[6], octets[7]],
    40 if octets[8] == 0 && octets[10..].iter().all(|byte| *byte == 0) => {
      [octets[5], octets[6], octets[7], octets[9]]
    }
    48 if octets[8] == 0 && octets[11..].iter().all(|byte| *byte == 0) => {
      [octets[6], octets[7], octets[9], octets[10]]
    }
    56 if octets[8] == 0 && octets[12..].iter().all(|byte| *byte == 0) => {
      [octets[7], octets[9], octets[10], octets[11]]
    }
    64 if octets[8] == 0 && octets[13..].iter().all(|byte| *byte == 0) => {
      [octets[9], octets[10], octets[11], octets[12]]
    }
    96 => [octets[12], octets[13], octets[14], octets[15]],
    _ => return None,
  };
  let mut prefix = octets;
  prefix[prefix_len as usize / 8..].fill(0);
  let prefix = Pref64::new(Ipv6Addr::from(prefix), prefix_len)?;
  Some((prefix, Ipv4Addr::from(embedded)))
}

fn synthesize_candidates(
  pref64: Pref64,
  ipv4_candidates: &[SocketAddr],
  configured_port: u16,
  max_count: usize,
) -> Vec<SocketAddr> {
  let mut synthesized = Vec::new();
  let mut seen = HashSet::new();
  for address in ipv4_candidates {
    let SocketAddr::V4(address) = address else {
      continue;
    };
    if address.port() != configured_port {
      continue;
    }
    let Some(ipv6) = pref64.synthesize(*address.ip()) else {
      continue;
    };
    let address = SocketAddr::new(IpAddr::V6(ipv6), configured_port);
    if seen.insert(address) {
      synthesized.push(address);
    }
    if synthesized.len() >= max_count {
      break;
    }
  }
  synthesized
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use futures_util::FutureExt as _;

  use super::*;

  fn rfc7050_answer(prefix: Ipv6Addr, prefix_len: u8, ipv4: Ipv4Addr) -> Ipv6Addr {
    Pref64::new(prefix, prefix_len)
      .expect("supported prefix")
      .synthesize(ipv4)
      .expect("supported embedding")
  }

  #[test]
  fn derives_each_supported_rfc6052_prefix_from_the_rfc7050_pair() {
    for prefix_len in RFC6052_PREFIX_LENGTHS {
      let mut prefix_octets = [0u8; 16];
      let seed = [
        0x20, 0x01, 0x0d, 0xb8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      ];
      let prefix_bytes = usize::from(prefix_len / 8);
      prefix_octets[..prefix_bytes].copy_from_slice(&seed[..prefix_bytes]);
      let prefix = Ipv6Addr::from(prefix_octets);
      let first = rfc7050_answer(prefix, prefix_len, RFC7050_FIRST);
      let second = rfc7050_answer(prefix, prefix_len, RFC7050_SECOND);
      assert_eq!(
        pref64_from_ipv4only_answers(&[first, second]),
        Pref64::new(prefix, prefix_len)
      );
    }
  }

  #[test]
  fn synthesis_skips_the_rfc6052_u_octet_for_non_96_bit_prefixes() {
    let pref64 = Pref64::new("2001:db8:0102::".parse().unwrap(), 48).unwrap();
    assert_eq!(
      pref64
        .synthesize(Ipv4Addr::new(192, 0, 2, 1))
        .unwrap()
        .octets(),
      [
        0x20, 0x01, 0x0d, 0xb8, 0x01, 0x02, 0xc0, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00,
      ]
    );
  }

  #[test]
  fn rejects_missing_ambiguous_or_noncanonical_rfc7050_answers() {
    let prefix = Pref64::new("64:ff9b::".parse().unwrap(), 96).unwrap();
    let first = prefix.synthesize(RFC7050_FIRST).unwrap();
    let second = prefix.synthesize(RFC7050_SECOND).unwrap();
    assert!(pref64_from_ipv4only_answers(&[first]).is_none());
    assert!(pref64_from_ipv4only_answers(&[first, second, first]).is_some());

    let other = Pref64::new("2001:db8::".parse().unwrap(), 96).unwrap();
    let other_first = other.synthesize(RFC7050_FIRST).unwrap();
    let other_second = other.synthesize(RFC7050_SECOND).unwrap();
    assert!(pref64_from_ipv4only_answers(&[first, second, other_first, other_second]).is_none());

    let mut noncanonical = first.octets();
    noncanonical[8] = 1;
    assert!(pref64_from_ipv4only_answers(&[Ipv6Addr::from(noncanonical), second]).is_none());
  }

  #[test]
  fn synthesis_preserves_only_configured_port_and_bounds_output() {
    let pref64 = Pref64::new("64:ff9b::".parse().unwrap(), 96).unwrap();
    let candidates = [
      "192.0.2.1:443".parse().unwrap(),
      "192.0.2.1:443".parse().unwrap(),
      "198.51.100.2:8443".parse().unwrap(),
      "[2001:db8::1]:443".parse().unwrap(),
      "203.0.113.3:443".parse().unwrap(),
    ];
    assert_eq!(
      synthesize_candidates(pref64, &candidates, 443, 1),
      vec!["[64:ff9b::c000:201]:443".parse().unwrap()]
    );
    assert_eq!(
      synthesize_candidates(pref64, &candidates, 443, 16),
      vec![
        "[64:ff9b::c000:201]:443".parse().unwrap(),
        "[64:ff9b::cb00:7103]:443".parse().unwrap(),
      ]
    );
  }

  #[test]
  fn empty_candidates_return_before_pref64_dns_discovery() {
    let deadline = Instant::now()
      .checked_add(Duration::from_secs(1))
      .expect("test deadline");
    assert_eq!(
      synthesize_pref64_ipv4_candidates(&[], 443, 1, deadline).now_or_never(),
      Some(Vec::new())
    );
  }

  #[test]
  fn route_probe_classification_is_fail_closed() {
    assert!(ipv4_route_is_unreachable(ErrorKind::NetworkUnreachable));
    assert!(!ipv4_route_is_unreachable(ErrorKind::PermissionDenied));
    assert!(!has_non_unspecified_ipv6_source(
      "0.0.0.0:0".parse().unwrap()
    ));
    assert!(!has_non_unspecified_ipv6_source("[::]:0".parse().unwrap()));
    assert!(has_non_unspecified_ipv6_source(
      "[2001:db8::1]:0".parse().unwrap()
    ));
  }
}
