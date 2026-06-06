use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, anyhow, bail};

use super::iana::AsnRegistry;
use crate::config::ClientIdentityAsnConfig;

#[derive(Debug, Default)]
pub(super) struct AsnDatabase {
  v4: Vec<HashMap<Ipv4Addr, u32>>,
  v6: Vec<HashMap<Ipv6Addr, u32>>,
  pub(super) entries: usize,
}

#[derive(Debug, Clone, Copy)]
struct ParsedPrefix {
  network: IpAddr,
  prefix: u8,
}

impl AsnDatabase {
  pub(super) fn lookup(&self, ip: IpAddr) -> Option<u32> {
    match ip {
      IpAddr::V4(ip) => {
        for prefix in (0..=32).rev() {
          let network = mask_v4(ip, prefix);
          if let Some(asn) = self.v4[prefix as usize].get(&network) {
            return Some(*asn);
          }
        }
        None
      }
      IpAddr::V6(ip) => {
        for prefix in (0..=128).rev() {
          let network = mask_v6(ip, prefix);
          if let Some(asn) = self.v6[prefix as usize].get(&network) {
            return Some(*asn);
          }
        }
        None
      }
    }
  }

  fn insert(&mut self, cidr: ParsedPrefix, asn: u32) -> anyhow::Result<()> {
    match cidr.network {
      IpAddr::V4(ip) => {
        let slot = self
          .v4
          .get_mut(cidr.prefix as usize)
          .ok_or_else(|| anyhow!("asn_database_invalid_ipv4_prefix"))?;
        if slot.insert(ip, asn).is_none() {
          self.entries += 1;
        }
      }
      IpAddr::V6(ip) => {
        let slot = self
          .v6
          .get_mut(cidr.prefix as usize)
          .ok_or_else(|| anyhow!("asn_database_invalid_ipv6_prefix"))?;
        if slot.insert(ip, asn).is_none() {
          self.entries += 1;
        }
      }
    }
    Ok(())
  }
}

pub(super) fn parse_database_bytes(
  config: &ClientIdentityAsnConfig,
  bytes: &[u8],
  registry: Option<&AsnRegistry>,
) -> anyhow::Result<AsnDatabase> {
  if bytes.len() > config.max_database_bytes {
    bail!("asn_database_too_large");
  }
  let text = std::str::from_utf8(bytes).context("asn_database_utf8")?;
  parse_prefix_asn_csv(text, config.max_entries, registry)
}

pub(super) fn parse_prefix_asn_csv(
  text: &str,
  max_entries: usize,
  registry: Option<&AsnRegistry>,
) -> anyhow::Result<AsnDatabase> {
  let mut database = AsnDatabase {
    v4: (0..=32).map(|_| HashMap::new()).collect(),
    v6: (0..=128).map(|_| HashMap::new()).collect(),
    entries: 0,
  };
  let mut seen_data = false;
  for (index, line) in text.lines().enumerate() {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
      continue;
    }
    let Some((prefix, asn)) = line.split_once(',') else {
      bail!("asn_database_line_{}_invalid_shape", index + 1);
    };
    if !seen_data
      && prefix.trim().eq_ignore_ascii_case("prefix")
      && asn.trim().eq_ignore_ascii_case("asn")
    {
      seen_data = true;
      continue;
    }
    seen_data = true;
    let prefix = parse_prefix(prefix.trim())
      .with_context(|| format!("asn_database_line_{}_invalid_prefix", index + 1))?;
    let asn = parse_asn(asn.trim())
      .with_context(|| format!("asn_database_line_{}_invalid_asn", index + 1))?;
    if let Some(registry) = registry {
      registry
        .validate(asn)
        .with_context(|| format!("asn_database_line_{}_unregistered_asn", index + 1))?;
    }
    database.insert(prefix, asn)?;
    if database.entries > max_entries {
      bail!("asn_database_too_many_entries");
    }
  }
  Ok(database)
}

fn parse_prefix(raw: &str) -> anyhow::Result<ParsedPrefix> {
  let (ip, prefix) = raw
    .split_once('/')
    .ok_or_else(|| anyhow!("ASN prefix must use CIDR notation"))?;
  let ip: IpAddr = ip.parse().context("invalid ASN prefix IP")?;
  let prefix: u8 = prefix.parse().context("invalid ASN prefix length")?;
  match ip {
    IpAddr::V4(ip) if prefix <= 32 => Ok(ParsedPrefix {
      network: IpAddr::V4(mask_v4(ip, prefix)),
      prefix,
    }),
    IpAddr::V6(ip) if prefix <= 128 => Ok(ParsedPrefix {
      network: IpAddr::V6(mask_v6(ip, prefix)),
      prefix,
    }),
    IpAddr::V4(_) => bail!("IPv4 ASN prefix length must be <= 32"),
    IpAddr::V6(_) => bail!("IPv6 ASN prefix length must be <= 128"),
  }
}

pub(super) fn parse_asn(raw: &str) -> anyhow::Result<u32> {
  let value = raw
    .strip_prefix("AS")
    .or_else(|| raw.strip_prefix("as"))
    .unwrap_or(raw);
  let asn: u32 = value.parse().context("invalid ASN")?;
  Ok(asn)
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
