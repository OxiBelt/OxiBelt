//! Real-IP configuration rules and selector validation.

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::{Context, bail};
use serde::Deserialize;

use super::{RealIpConfig, RealIpHeader, default_true, validate_runtime_identifier};

/// A host- or SNI-scoped Real-IP policy. Rules are evaluated in configuration
/// order by the request identity resolver.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RealIpRuleConfig {
  pub name: String,
  #[serde(default, deserialize_with = "deserialize_nonempty_selector_list")]
  pub hosts: Vec<String>,
  #[serde(default, deserialize_with = "deserialize_nonempty_selector_list")]
  pub server_names: Vec<String>,
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub trusted_proxies: Vec<String>,
  #[serde(default)]
  pub header: RealIpHeader,
  #[serde(default = "default_true")]
  pub recursive: bool,
  #[serde(default)]
  pub fail_on_untrusted_forwarded_headers: bool,
}

impl RealIpRuleConfig {
  /// Returns the rule policy without selectors or further scoped rules.
  pub(crate) fn policy(&self) -> RealIpConfig {
    RealIpConfig {
      enabled: self.enabled,
      trusted_proxies: self.trusted_proxies.clone(),
      header: self.header,
      recursive: self.recursive,
      fail_on_untrusted_forwarded_headers: self.fail_on_untrusted_forwarded_headers,
      rules: Vec::new(),
    }
  }
}

fn deserialize_nonempty_selector_list<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  let values = Vec::<String>::deserialize(deserializer)?;
  if values.is_empty() {
    return Err(serde::de::Error::custom(
      "selector lists must not be explicitly empty",
    ));
  }
  Ok(values)
}

pub(crate) fn validate_real_ip_rules(config: &RealIpConfig) -> anyhow::Result<()> {
  let mut names = HashSet::new();
  for (index, rule) in config.rules.iter().enumerate() {
    let path = format!("proxy.real_ip.rules[{index}]");
    validate_runtime_identifier(&format!("{path}.name"), &rule.name)?;
    if !names.insert(&rule.name) {
      bail!("duplicate Real-IP rule name {}", rule.name);
    }
    if rule.hosts.is_empty() && rule.server_names.is_empty() {
      bail!("{path} must set at least one host or server_names selector");
    }

    let mut hosts = HashSet::new();
    for host in &rule.hosts {
      let normalized = normalize_real_ip_host_selector(host)
        .with_context(|| format!("{path}.hosts contains invalid selector {host}"))?;
      if !hosts.insert(normalized) {
        bail!("{path}.hosts contains duplicate selector {host}");
      }
    }

    let mut server_names = HashSet::new();
    for server_name in &rule.server_names {
      let normalized = normalize_real_ip_server_name_selector(server_name)
        .with_context(|| format!("{path}.server_names contains invalid selector {server_name}"))?;
      if !server_names.insert(normalized) {
        bail!("{path}.server_names contains duplicate selector {server_name}");
      }
    }
  }
  Ok(())
}

pub(crate) fn normalize_real_ip_host_selector(host: &str) -> anyhow::Result<String> {
  if host.trim() != host || host.is_empty() {
    bail!("host selector must not be empty or padded");
  }
  if host.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("host selector {host} contains a control character");
  }
  let normalized = host.trim_end_matches('.').to_ascii_lowercase();
  if normalized == "*" {
    bail!("host selector must not be a bare wildcard");
  }
  let ip_literal = if normalized.starts_with('[') {
    normalized
      .find(']')
      .filter(|end| *end == normalized.len() - 1)
      .map(|end| &normalized[1..end])
  } else {
    Some(normalized.as_str())
  };
  if let Some(ip_literal) = ip_literal
    && let Ok(ip) = ip_literal.parse::<IpAddr>()
  {
    return Ok(ip.to_string());
  }
  normalize_real_ip_dns_selector(&normalized, "host selector")
}

pub(crate) fn normalize_real_ip_server_name_selector(name: &str) -> anyhow::Result<String> {
  if name.trim() != name || name.is_empty() {
    bail!("SNI selector must not be empty or padded");
  }
  if name.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("SNI selector {name} contains a control character");
  }
  let normalized = name.trim_end_matches('.').to_ascii_lowercase();
  if normalized.parse::<IpAddr>().is_ok() {
    bail!("SNI selector {name} must be a DNS name");
  }
  normalize_real_ip_dns_selector(&normalized, "SNI selector")
}

fn normalize_real_ip_dns_selector(value: &str, label: &str) -> anyhow::Result<String> {
  let dns_pattern = value.strip_prefix("*.").unwrap_or(value);
  if dns_pattern.is_empty() || dns_pattern.contains('*') {
    bail!("{label} may only use a leftmost wildcard");
  }
  if dns_pattern
    .split('.')
    .any(|part| part.is_empty() || part.starts_with('-') || part.ends_with('-'))
  {
    bail!("{label} {value} is not a valid DNS pattern");
  }
  if !dns_pattern
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
  {
    bail!("{label} {value} contains invalid characters");
  }
  Ok(value.to_string())
}
