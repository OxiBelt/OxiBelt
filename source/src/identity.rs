use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, bail};
use http::HeaderMap;

use crate::config::{RealIpConfig, RealIpHeader};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Cidr {
  network: IpAddr,
  prefix: u8,
}

impl Cidr {
  pub fn parse(raw: &str) -> anyhow::Result<Self> {
    let (ip, prefix) = match raw.split_once('/') {
      Some((ip, prefix)) => {
        let ip: IpAddr = ip
          .parse()
          .with_context(|| format!("invalid CIDR IP address {raw}"))?;
        let prefix: u8 = prefix
          .parse()
          .with_context(|| format!("invalid CIDR prefix {raw}"))?;
        (ip, prefix)
      }
      None => {
        let ip: IpAddr = raw
          .parse()
          .with_context(|| format!("invalid IP address {raw}"))?;
        let prefix = match ip {
          IpAddr::V4(_) => 32,
          IpAddr::V6(_) => 128,
        };
        (ip, prefix)
      }
    };

    match ip {
      IpAddr::V4(ip) if prefix <= 32 => Ok(Self {
        network: IpAddr::V4(mask_v4(ip, prefix)),
        prefix,
      }),
      IpAddr::V6(ip) if prefix <= 128 => Ok(Self {
        network: IpAddr::V6(mask_v6(ip, prefix)),
        prefix,
      }),
      IpAddr::V4(_) => bail!("IPv4 CIDR prefix must be <= 32 in {raw}"),
      IpAddr::V6(_) => bail!("IPv6 CIDR prefix must be <= 128 in {raw}"),
    }
  }

  pub fn contains(&self, ip: IpAddr) -> bool {
    match (self.network, ip) {
      (IpAddr::V4(network), IpAddr::V4(ip)) => mask_v4(ip, self.prefix) == network,
      (IpAddr::V6(network), IpAddr::V6(ip)) => mask_v6(ip, self.prefix) == network,
      _ => false,
    }
  }
}

#[derive(Debug, Clone)]
pub struct TrustedCidrs {
  cidrs: Vec<Cidr>,
}

impl TrustedCidrs {
  pub fn parse(values: &[String]) -> anyhow::Result<Self> {
    Ok(Self {
      cidrs: values
        .iter()
        .map(|value| Cidr::parse(value))
        .collect::<anyhow::Result<_>>()?,
    })
  }

  pub fn contains(&self, ip: IpAddr) -> bool {
    self.cidrs.iter().any(|cidr| cidr.contains(ip))
  }
}

pub fn resolve_client_addr(
  headers: &HeaderMap,
  peer_addr: SocketAddr,
  config: &RealIpConfig,
) -> anyhow::Result<SocketAddr> {
  if !config.enabled {
    return Ok(peer_addr);
  }

  let trusted = TrustedCidrs::parse(&config.trusted_proxies)?;
  let has_forwarded = has_real_ip_header(headers, config.header);
  if !trusted.contains(peer_addr.ip()) {
    if config.fail_on_untrusted_forwarded_headers && has_forwarded {
      bail!("untrusted peer sent forwarded client IP metadata");
    }
    return Ok(peer_addr);
  }

  let candidates = header_candidate_ips(headers, config.header);
  if candidates.is_empty() {
    return Ok(peer_addr);
  }

  let selected = if config.recursive {
    candidates
      .iter()
      .rev()
      .copied()
      .find(|ip| !trusted.contains(*ip))
      .or_else(|| candidates.first().copied())
  } else {
    candidates.first().copied()
  };

  Ok(
    selected
      .map(|ip| SocketAddr::new(ip, peer_addr.port()))
      .unwrap_or(peer_addr),
  )
}

fn has_real_ip_header(headers: &HeaderMap, header: RealIpHeader) -> bool {
  headers.contains_key(header.header_name())
}

fn header_candidate_ips(headers: &HeaderMap, header: RealIpHeader) -> Vec<IpAddr> {
  match header {
    RealIpHeader::XForwardedFor => headers
      .get(header.header_name())
      .and_then(|value| value.to_str().ok())
      .map(parse_csv_ips)
      .unwrap_or_default(),
    RealIpHeader::XRealIp | RealIpHeader::CfConnectingIp => headers
      .get(header.header_name())
      .and_then(|value| value.to_str().ok())
      .and_then(parse_ip_token)
      .into_iter()
      .collect(),
    RealIpHeader::Forwarded => headers
      .get(header.header_name())
      .and_then(|value| value.to_str().ok())
      .map(parse_forwarded_for_ips)
      .unwrap_or_default(),
  }
}

fn parse_csv_ips(raw: &str) -> Vec<IpAddr> {
  raw.split(',').filter_map(parse_ip_token).collect()
}

fn parse_forwarded_for_ips(raw: &str) -> Vec<IpAddr> {
  raw
    .split(',')
    .flat_map(|entry| entry.split(';'))
    .filter_map(|part| {
      let (name, value) = part.trim().split_once('=')?;
      if !name.trim().eq_ignore_ascii_case("for") {
        return None;
      }
      parse_ip_token(value.trim().trim_matches('"'))
    })
    .collect()
}

fn parse_ip_token(raw: &str) -> Option<IpAddr> {
  let token = raw.trim().trim_matches('"');
  if token.is_empty() || token.eq_ignore_ascii_case("unknown") {
    return None;
  }
  if let Ok(ip) = token.parse() {
    return Some(ip);
  }
  if token.starts_with('[') {
    let end = token.find(']')?;
    return token[1..end].parse().ok();
  }
  if let Some((host, port)) = token.rsplit_once(':')
    && !host.contains(':')
    && port.chars().all(|ch| ch.is_ascii_digit())
  {
    return host.parse().ok();
  }
  None
}

fn mask_v4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
  if prefix == 0 {
    return Ipv4Addr::UNSPECIFIED;
  }
  let bits = u32::from(ip);
  Ipv4Addr::from(bits & (!0u32 << (32 - prefix)))
}

fn mask_v6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
  if prefix == 0 {
    return Ipv6Addr::UNSPECIFIED;
  }
  let bits = u128::from(ip);
  Ipv6Addr::from(bits & (!0u128 << (128 - prefix)))
}

#[cfg(test)]
mod tests {
  use http::HeaderValue;

  use super::*;

  #[test]
  fn cidr_matches_ipv4_prefix() {
    let cidr = Cidr::parse("192.0.2.0/24").unwrap();
    assert!(cidr.contains("192.0.2.10".parse().unwrap()));
    assert!(!cidr.contains("192.0.3.10".parse().unwrap()));
  }

  #[test]
  fn x_forwarded_for_recursive_selects_last_untrusted() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "x-forwarded-for",
      HeaderValue::from_static("198.51.100.7, 10.0.0.12"),
    );
    let config = RealIpConfig {
      enabled: true,
      trusted_proxies: vec!["10.0.0.0/8".to_string()],
      ..RealIpConfig::default()
    };
    let addr = resolve_client_addr(&headers, "10.0.0.1:443".parse().unwrap(), &config).unwrap();
    assert_eq!(addr.ip(), "198.51.100.7".parse::<IpAddr>().unwrap());
  }
}
