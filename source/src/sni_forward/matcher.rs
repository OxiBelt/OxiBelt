use std::sync::Arc;
use std::time::Duration;

use crate::config::{
  Config, ProxyProtocolEgressMode, SniForwardProtocol, normalize_sni_pattern,
  validate_sni_server_name,
};

#[derive(Debug, Clone)]
pub(crate) struct SniForwardTable {
  enabled: bool,
  default_target: Option<Arc<SniForwardRule>>,
  tcp_rules: PatternSet<Arc<SniForwardRule>>,
  quic_rules: PatternSet<Arc<SniForwardRule>>,
  local_hosts: PatternSet<()>,
}

#[derive(Debug, Clone)]
pub(crate) struct SniForwardRule {
  pub(crate) name: String,
  pub(crate) target: String,
  pub(crate) connect_timeout: Duration,
  pub(crate) idle_timeout: Duration,
  pub(crate) tcp_proxy_protocol_egress: ProxyProtocolEgressMode,
}

#[derive(Debug, Clone)]
pub(crate) enum SniForwardDecision {
  Forward(Arc<SniForwardRule>),
  Local,
  Reject,
}

#[derive(Debug, Clone)]
struct PatternSet<T> {
  exact: Vec<(String, T)>,
  wildcard: Vec<(String, T)>,
}

impl SniForwardTable {
  pub(crate) fn new(config: &Config) -> anyhow::Result<Self> {
    let enabled = config.sni_forward.enabled;
    let default_target = config.sni_forward.default_target.as_ref().map(|target| {
      Arc::new(SniForwardRule {
        name: "default".to_string(),
        target: target.clone(),
        connect_timeout: Duration::from_millis(3_000),
        idle_timeout: Duration::from_millis(config.sni_forward.idle_timeout_ms),
        tcp_proxy_protocol_egress: ProxyProtocolEgressMode::Off,
      })
    });
    let mut table = Self {
      enabled,
      default_target,
      tcp_rules: PatternSet::default(),
      quic_rules: PatternSet::default(),
      local_hosts: PatternSet::default(),
    };

    for rule in &config.sni_forward.rules {
      let entry = Arc::new(SniForwardRule {
        name: rule.name.clone(),
        target: rule.target.clone(),
        connect_timeout: Duration::from_millis(rule.connect_timeout_ms),
        idle_timeout: Duration::from_millis(rule.idle_timeout_ms),
        tcp_proxy_protocol_egress: rule.tcp_proxy_protocol_egress,
      });
      for pattern in &rule.server_names {
        if rule.protocols.contains(&SniForwardProtocol::TcpTls) {
          table.tcp_rules.insert(pattern, entry.clone())?;
        }
        if rule.protocols.contains(&SniForwardProtocol::Quic) {
          table.quic_rules.insert(pattern, entry.clone())?;
        }
      }
    }

    for route in &config.routes {
      for host in &route.hosts {
        let normalized = normalize_sni_pattern(host);
        if normalized == "*" {
          continue;
        }
        if validate_sni_server_name(&normalized).is_ok() {
          table.local_hosts.insert_normalized(normalized, ())?;
        }
      }
    }

    Ok(table)
  }

  pub(crate) fn is_enabled(&self) -> bool {
    self.enabled
  }

  pub(crate) fn decide_tcp_tls(&self, sni: Option<&str>) -> SniForwardDecision {
    self.decide(sni, &self.tcp_rules)
  }

  pub(crate) fn decide_quic(&self, sni: Option<&str>) -> SniForwardDecision {
    self.decide(sni, &self.quic_rules)
  }

  fn decide(
    &self,
    sni: Option<&str>,
    rules: &PatternSet<Arc<SniForwardRule>>,
  ) -> SniForwardDecision {
    if !self.enabled {
      return SniForwardDecision::Local;
    }
    let Some(sni) = sni else {
      return SniForwardDecision::Reject;
    };
    let sni = normalize_sni_pattern(sni);
    if let Some(rule) = rules.matches(&sni) {
      return SniForwardDecision::Forward(rule.clone());
    }
    if self.local_hosts.matches(&sni).is_some() {
      return SniForwardDecision::Local;
    }
    match &self.default_target {
      Some(target) => SniForwardDecision::Forward(target.clone()),
      None => SniForwardDecision::Reject,
    }
  }
}

impl<T> Default for PatternSet<T> {
  fn default() -> Self {
    Self {
      exact: Vec::new(),
      wildcard: Vec::new(),
    }
  }
}

impl<T> PatternSet<T> {
  fn insert(&mut self, pattern: &str, value: T) -> anyhow::Result<()> {
    let normalized = normalize_sni_pattern(pattern);
    self.insert_normalized(normalized, value)
  }

  fn insert_normalized(&mut self, normalized: String, value: T) -> anyhow::Result<()> {
    if let Some(suffix) = normalized.strip_prefix("*.") {
      self.wildcard.push((suffix.to_string(), value));
    } else {
      self.exact.push((normalized, value));
    }
    self
      .wildcard
      .sort_by(|(left, _), (right, _)| right.len().cmp(&left.len()));
    Ok(())
  }

  fn matches(&self, sni: &str) -> Option<&T> {
    if let Some((_, value)) = self.exact.iter().find(|(pattern, _)| pattern == sni) {
      return Some(value);
    }
    self
      .wildcard
      .iter()
      .find(|(suffix, _)| wildcard_matches(sni, suffix))
      .map(|(_, value)| value)
  }
}

fn wildcard_matches(sni: &str, suffix: &str) -> bool {
  sni.len() > suffix.len()
    && sni.ends_with(suffix)
    && sni
      .as_bytes()
      .get(sni.len() - suffix.len() - 1)
      .is_some_and(|byte| *byte == b'.')
}

#[cfg(test)]
mod tests {
  use super::*;

  fn parse_config(extra: &str) -> Config {
    let raw = format!(
      r#"
[listeners]
https_bind = "127.0.0.1:0"
http1 = true
http2 = false
http3 = false

[tls]
cert_chain = "cert.pem"
private_key = "key.pem"

{extra}
"#
    );
    toml::from_str(&raw).expect("config should parse")
  }

  #[test]
  fn wildcard_is_leftmost_only() {
    assert!(wildcard_matches("api.example.com", "example.com"));
    assert!(!wildcard_matches("example.com", "example.com"));
    assert!(!wildcard_matches("badexample.com", "example.com"));
  }

  #[test]
  fn explicit_rule_overrides_local_route_host() {
    let config = parse_config(
      r#"
[sni_forward]
enabled = true

[[sni_forward.rules]]
name = "override"
server_names = ["app.example.com"]
target = "127.0.0.1:9443"
protocols = ["tcp_tls"]

[[routes]]
name = "local"
hosts = ["app.example.com"]
path_prefix = "/"
upstream = "app"
"#,
    );
    let table = SniForwardTable::new(&config).unwrap();

    assert!(matches!(
      table.decide_tcp_tls(Some("app.example.com")),
      SniForwardDecision::Forward(_)
    ));
  }

  #[test]
  fn route_star_does_not_define_local_sni() {
    let config = parse_config(
      r#"
[sni_forward]
enabled = true
default_target = "127.0.0.1:9443"

[[routes]]
name = "catch-all"
hosts = ["*"]
path_prefix = "/"
upstream = "app"
"#,
    );
    let table = SniForwardTable::new(&config).unwrap();

    assert!(matches!(
      table.decide_tcp_tls(Some("unknown.example.com")),
      SniForwardDecision::Forward(_)
    ));
  }
}
