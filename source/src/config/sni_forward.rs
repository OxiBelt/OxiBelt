//! SNI forwarding configuration validation.
//! TCP and QUIC forwarding targets are constrained before listener startup.

use std::collections::HashSet;

use anyhow::{Context, bail};
use serde::Deserialize;

use super::{
  Config, ProxyProtocolEgressMode, default_client_idle_timeout_ms, default_connect_timeout_ms,
  parse_stream_target,
};

const DEFAULT_CLIENT_HELLO_MAX_BYTES: usize = 64 * 1024;
const DEFAULT_QUIC_MAX_SESSIONS: usize = 8192;
const DEFAULT_QUIC_LOCAL_QUEUE_CAPACITY: usize = 1024;
pub(super) const SNI_FORWARD_CONFIG_KEYS: &[&str] = &[
  "client_hello_max_bytes",
  "client_hello_parse_methods",
  "default_target",
  "enabled",
  "idle_timeout_ms",
  "quic_local_queue_capacity",
  "quic_max_sessions",
  "rules",
];
pub(super) const SNI_FORWARD_RULE_KEYS: &[&str] = &[
  "connect_timeout_ms",
  "idle_timeout_ms",
  "name",
  "protocols",
  "server_names",
  "target",
  "tcp_proxy_protocol_egress",
];

impl Config {
  pub fn needs_https_listener(&self) -> bool {
    self.listeners.http1 || self.listeners.http2 || self.sni_forward.has_tcp_tls()
  }

  pub(super) fn validate_sni_forward(&self) -> anyhow::Result<()> {
    self.sni_forward.validate()?;
    let has_explicit_quic_rule = self.sni_forward.enabled
      && self
        .sni_forward
        .rules
        .iter()
        .any(|rule| rule.protocols.contains(&SniForwardProtocol::Quic));
    if has_explicit_quic_rule && !self.listeners.http3 {
      bail!("sni_forward QUIC forwarding requires listeners.http3 = true for same-port demux");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SniForwardConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub default_target: Option<String>,
  #[serde(default = "default_client_hello_max_bytes")]
  pub client_hello_max_bytes: usize,
  #[serde(default = "default_client_hello_parse_methods")]
  pub client_hello_parse_methods: Vec<SniForwardClientHelloParseMethod>,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default = "default_quic_max_sessions")]
  pub quic_max_sessions: usize,
  #[serde(default = "default_quic_local_queue_capacity")]
  pub quic_local_queue_capacity: usize,
  #[serde(default)]
  pub rules: Vec<SniForwardRuleConfig>,
}

impl Default for SniForwardConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      default_target: None,
      client_hello_max_bytes: default_client_hello_max_bytes(),
      client_hello_parse_methods: default_client_hello_parse_methods(),
      idle_timeout_ms: default_client_idle_timeout_ms(),
      quic_max_sessions: default_quic_max_sessions(),
      quic_local_queue_capacity: default_quic_local_queue_capacity(),
      rules: Vec::new(),
    }
  }
}

impl SniForwardConfig {
  pub fn has_tcp_tls(&self) -> bool {
    self.enabled
      && (self.default_target.is_some()
        || self
          .rules
          .iter()
          .any(|rule| rule.protocols.contains(&SniForwardProtocol::TcpTls)))
  }

  pub fn has_quic(&self) -> bool {
    self.enabled
      && (self.default_target.is_some()
        || self
          .rules
          .iter()
          .any(|rule| rule.protocols.contains(&SniForwardProtocol::Quic)))
  }

  pub fn has_any_protocol(&self) -> bool {
    self.has_tcp_tls() || self.has_quic()
  }

  pub fn has_any_target(&self) -> bool {
    self.enabled && (self.default_target.is_some() || !self.rules.is_empty())
  }

  fn validate(&self) -> anyhow::Result<()> {
    if self.client_hello_max_bytes == 0 {
      bail!("sni_forward.client_hello_max_bytes must be greater than 0");
    }
    if self.client_hello_parse_methods.is_empty() {
      bail!("sni_forward.client_hello_parse_methods must include at least one method");
    }
    let mut parse_methods = HashSet::new();
    for method in &self.client_hello_parse_methods {
      if !parse_methods.insert(*method) {
        bail!(
          "duplicate sni_forward.client_hello_parse_methods value: {}",
          method.as_str()
        );
      }
    }
    if self.idle_timeout_ms == 0 {
      bail!("sni_forward.idle_timeout_ms must be greater than 0");
    }
    if self.quic_max_sessions == 0 {
      bail!("sni_forward.quic_max_sessions must be greater than 0");
    }
    if self.quic_local_queue_capacity == 0 {
      bail!("sni_forward.quic_local_queue_capacity must be greater than 0");
    }
    if let Some(target) = &self.default_target {
      validate_sni_forward_target("sni_forward.default_target", target)?;
    }

    let mut names = HashSet::new();
    let mut patterns = HashSet::new();
    for rule in &self.rules {
      rule.validate(&mut names, &mut patterns)?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SniForwardRuleConfig {
  pub name: String,
  pub server_names: Vec<String>,
  pub target: String,
  #[serde(default = "default_sni_forward_protocols")]
  pub protocols: Vec<SniForwardProtocol>,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default)]
  pub tcp_proxy_protocol_egress: ProxyProtocolEgressMode,
}

impl SniForwardRuleConfig {
  fn validate(
    &self,
    names: &mut HashSet<String>,
    patterns: &mut HashSet<String>,
  ) -> anyhow::Result<()> {
    if self.name.trim() != self.name || self.name.is_empty() {
      bail!("sni_forward rule name must not be empty or padded");
    }
    if !names.insert(self.name.clone()) {
      bail!("duplicate sni_forward rule name: {}", self.name);
    }
    if self.server_names.is_empty() {
      bail!(
        "sni_forward rule {} must include at least one server_name",
        self.name
      );
    }
    if self.protocols.is_empty() {
      bail!(
        "sni_forward rule {} protocols must include at least one protocol",
        self.name
      );
    }
    if self.connect_timeout_ms == 0 || self.idle_timeout_ms == 0 {
      bail!(
        "sni_forward rule {} timeout values must be greater than 0",
        self.name
      );
    }
    validate_sni_forward_target(
      &format!("sni_forward rule {} target", self.name),
      &self.target,
    )?;
    for pattern in &self.server_names {
      validate_sni_server_name(pattern)
        .with_context(|| format!("sni_forward rule {} server_names", self.name))?;
      let normalized = normalize_sni_pattern(pattern);
      if !patterns.insert(normalized.clone()) {
        bail!("duplicate sni_forward server_name pattern: {normalized}");
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SniForwardProtocol {
  TcpTls,
  Quic,
}

pub const SNI_FORWARD_PROTOCOL_WIRE_VALUES: &[&str] = &["tcp_tls", "quic"];

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SniForwardClientHelloParseMethod {
  SingleRecord,
  TlsRecordReassembly,
}

impl SniForwardClientHelloParseMethod {
  fn as_str(self) -> &'static str {
    match self {
      Self::SingleRecord => "single_record",
      Self::TlsRecordReassembly => "tls_record_reassembly",
    }
  }
}

pub const SNI_FORWARD_CLIENT_HELLO_PARSE_METHOD_WIRE_VALUES: &[&str] =
  &["single_record", "tls_record_reassembly"];

fn default_client_hello_max_bytes() -> usize {
  DEFAULT_CLIENT_HELLO_MAX_BYTES
}

fn default_quic_max_sessions() -> usize {
  DEFAULT_QUIC_MAX_SESSIONS
}

fn default_quic_local_queue_capacity() -> usize {
  DEFAULT_QUIC_LOCAL_QUEUE_CAPACITY
}

fn default_sni_forward_protocols() -> Vec<SniForwardProtocol> {
  vec![SniForwardProtocol::TcpTls, SniForwardProtocol::Quic]
}

fn default_client_hello_parse_methods() -> Vec<SniForwardClientHelloParseMethod> {
  vec![SniForwardClientHelloParseMethod::SingleRecord]
}

pub(crate) fn normalize_sni_pattern(pattern: &str) -> String {
  pattern.trim_end_matches('.').to_ascii_lowercase()
}

pub(crate) fn validate_sni_server_name(name: &str) -> anyhow::Result<()> {
  if name.trim() != name || name.is_empty() {
    bail!("server name must not be empty or padded");
  }
  if name.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("server name {name} contains a control character");
  }
  if name == "*" {
    bail!("server name {name} is not valid for SNI forwarding");
  }
  let name = name.strip_prefix("*.").unwrap_or(name);
  if name.is_empty() || name.contains('*') {
    bail!("server name may only use a leftmost wildcard");
  }
  if name
    .split('.')
    .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
  {
    bail!("server name {name} is not a valid DNS pattern");
  }
  if !name
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
  {
    bail!("server name {name} contains invalid characters");
  }
  Ok(())
}

fn validate_sni_forward_target(field_name: &str, target: &str) -> anyhow::Result<()> {
  let (host, port) = parse_stream_target(target)
    .with_context(|| format!("{field_name} must be in host:port form"))?;
  if host.trim().is_empty() {
    bail!("{field_name} host must not be empty");
  }
  if port == 0 {
    bail!("{field_name} port must be greater than 0");
  }
  Ok(())
}
