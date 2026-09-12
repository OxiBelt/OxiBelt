//! Ordered request-name selection for independently configured Real-IP policies.

use std::net::{IpAddr, SocketAddr};

use http::HeaderMap;

use crate::config::{
  RealIpConfig, normalize_real_ip_host_selector, normalize_real_ip_server_name_selector,
};
use crate::routes::normalize_host_cow;

#[derive(Clone, Debug)]
pub(crate) struct RealIpPolicySelector {
  rules: Vec<CompiledRule>,
}

#[derive(Clone, Debug)]
struct CompiledRule {
  hosts: Vec<NamePattern>,
  server_names: Vec<NamePattern>,
  policy: RealIpConfig,
}

#[derive(Clone, Debug)]
enum NamePattern {
  Exact(String),
  Suffix(String),
  Ip(IpAddr),
}

impl NamePattern {
  fn new(normalized: String, host: bool) -> Self {
    if host && let Ok(ip) = normalized.parse() {
      return Self::Ip(ip);
    }
    match normalized.strip_prefix("*.") {
      Some(suffix) => Self::Suffix(suffix.to_string()),
      None => Self::Exact(normalized),
    }
  }

  fn matches(&self, name: &str) -> bool {
    match self {
      Self::Exact(exact) => exact.eq_ignore_ascii_case(name),
      Self::Suffix(suffix) => name
        .len()
        .checked_sub(suffix.len())
        .and_then(|offset| Some((name.get(..offset)?, name.get(offset..)?)))
        .is_some_and(|(prefix, tail)| {
          prefix.len() > 1 && prefix.ends_with('.') && tail.eq_ignore_ascii_case(suffix)
        }),
      Self::Ip(ip) => name
        .parse::<IpAddr>()
        .is_ok_and(|candidate| candidate == *ip),
    }
  }
}

impl RealIpPolicySelector {
  pub(crate) fn new(config: &RealIpConfig) -> anyhow::Result<Self> {
    crate::config::validate_real_ip_rules(config)?;
    let rules = config
      .rules
      .iter()
      .map(|rule| {
        let hosts = rule
          .hosts
          .iter()
          .map(|name| {
            normalize_real_ip_host_selector(name).map(|name| NamePattern::new(name, true))
          })
          .collect::<anyhow::Result<Vec<_>>>()?;
        let server_names = rule
          .server_names
          .iter()
          .map(|name| {
            normalize_real_ip_server_name_selector(name).map(|name| NamePattern::new(name, false))
          })
          .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(CompiledRule {
          hosts,
          server_names,
          policy: rule.policy(),
        })
      })
      .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Self { rules })
  }

  /// Callers supply validated received authority and transport SNI, before routing or rewriting.
  /// `None` means no downstream TLS SNI; descriptive plaintext metadata must not be supplied.
  pub(crate) fn resolve_client_addr(
    &self,
    headers: &HeaderMap,
    peer_addr: SocketAddr,
    host: &str,
    sni: Option<&str>,
    default: &RealIpConfig,
  ) -> anyhow::Result<SocketAddr> {
    if self.rules.is_empty() {
      return super::resolve_client_addr(headers, peer_addr, default);
    }
    let normalized_host = normalize_host_cow(host);
    let host = normalized_host.trim_end_matches('.');
    let sni = sni.map(|name| name.trim_end_matches('.'));
    let policy = self
      .rules
      .iter()
      .find(|rule| {
        (rule.hosts.is_empty() || rule.hosts.iter().any(|pattern| pattern.matches(host)))
          && (rule.server_names.is_empty()
            || sni.is_some_and(|sni| rule.server_names.iter().any(|pattern| pattern.matches(sni))))
      })
      .map_or(default, |rule| &rule.policy);
    super::resolve_client_addr(headers, peer_addr, policy)
  }
}

#[cfg(test)]
mod tests;
