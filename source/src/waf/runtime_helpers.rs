use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use anyhow::{Context, anyhow, bail};
use http::header::COOKIE;
use http::{HeaderMap, Uri, Version};

use super::{CompiledPatternSet, WafBodyInput, WafProtocol, WafRequestInput};
use crate::routes::normalize_host;

pub(super) fn request_metadata_has_duplicates(input: WafRequestInput<'_>) -> bool {
  has_duplicate_names(
    input
      .headers
      .iter()
      .map(|(name, _)| name.as_str().to_string()),
  ) || has_duplicate_names(
    url::form_urlencoded::parse(input.uri.query().unwrap_or_default().as_bytes())
      .map(|(name, _)| name.into_owned()),
  ) || has_duplicate_names(
    input
      .headers
      .get_all(COOKIE)
      .iter()
      .filter_map(|value| value.to_str().ok())
      .flat_map(|value| value.split(';'))
      .filter_map(|part| part.trim().split_once('='))
      .map(|(name, _)| name.trim().to_string()),
  )
}

fn has_duplicate_names<I>(names: I) -> bool
where
  I: IntoIterator<Item = String>,
{
  let mut seen = HashSet::new();
  names.into_iter().any(|name| !seen.insert(name))
}

fn content_length(headers: &HeaderMap) -> Option<i64> {
  if headers.contains_key(http::header::TRANSFER_ENCODING) {
    return None;
  }
  let mut values = headers.get_all(http::header::CONTENT_LENGTH).iter();
  let value = values.next()?;
  if values.next().is_some() {
    return None;
  }
  let length = value.to_str().ok()?.trim().parse::<u64>().ok()?;
  if length == 0 {
    return None;
  }
  Some(i64::try_from(length).unwrap_or(i64::MAX))
}

pub(super) fn body_size(headers: &HeaderMap, body: Option<WafBodyInput<'_>>) -> i64 {
  content_length(headers).unwrap_or_else(|| {
    body
      .map(|body| {
        let size = body
          .bytes
          .len()
          .saturating_add(usize::from(body.is_truncated));
        i64::try_from(size).unwrap_or(i64::MAX)
      })
      .unwrap_or(0)
  })
}

pub(super) fn version_string(version: Version) -> String {
  match version {
    Version::HTTP_09 => "0.9",
    Version::HTTP_10 => "1.0",
    Version::HTTP_11 => "1.1",
    Version::HTTP_2 => "2",
    Version::HTTP_3 => "3",
    _ => "unknown",
  }
  .to_string()
}

pub(super) fn pattern_set_matches(
  sets: &HashMap<String, CompiledPatternSet>,
  name: &str,
  text: &str,
) -> anyhow::Result<bool> {
  let set = sets
    .get(name)
    .ok_or_else(|| anyhow!("unknown WAF pattern set {name}"))?;
  Ok(match set {
    CompiledPatternSet::Contains(patterns) => patterns.is_match(text),
    CompiledPatternSet::Regex(patterns) => patterns.is_match(text),
  })
}

pub(super) fn ip_in_cidr(ip: &str, cidr: &str) -> anyhow::Result<bool> {
  let ip: IpAddr = ip.parse().context("invalid IP address")?;
  let (network, prefix) = cidr
    .split_once('/')
    .ok_or_else(|| anyhow!("invalid CIDR literal"))?;
  let network: IpAddr = network.parse().context("invalid CIDR network")?;
  let prefix = prefix.parse::<u32>().context("invalid CIDR prefix")?;

  match (ip, network) {
    (IpAddr::V4(ip), IpAddr::V4(network)) => {
      if prefix > 32 {
        bail!("invalid IPv4 CIDR prefix");
      }
      let mask = if prefix == 0 {
        0
      } else {
        u32::MAX << (32 - prefix)
      };
      Ok((u32::from(ip) & mask) == (u32::from(network) & mask))
    }
    (IpAddr::V6(ip), IpAddr::V6(network)) => {
      if prefix > 128 {
        bail!("invalid IPv6 CIDR prefix");
      }
      let mask = if prefix == 0 {
        0
      } else {
        u128::MAX << (128 - prefix)
      };
      Ok((u128::from(ip) & mask) == (u128::from(network) & mask))
    }
    _ => Ok(false),
  }
}

pub fn request_protocol(headers: &HeaderMap) -> WafProtocol {
  if headers.contains_key(http::header::UPGRADE)
    || headers
      .get(http::header::CONNECTION)
      .and_then(|value| value.to_str().ok())
      .map(|value| {
        value
          .split(',')
          .any(|item| item.trim().eq_ignore_ascii_case("upgrade"))
      })
      .unwrap_or(false)
  {
    WafProtocol::Websocket
  } else {
    WafProtocol::Http
  }
}

pub fn normalized_downstream_host(request_uri: &Uri, headers: &HeaderMap) -> String {
  if let Some(authority) = request_uri.authority() {
    return normalize_host(authority.as_str());
  }

  headers
    .get(http::header::HOST)
    .and_then(|value| value.to_str().ok())
    .map(normalize_host)
    .unwrap_or_default()
}
