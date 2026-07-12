//! Route configuration validation.
//! Hosts, paths, upstream references, and per-route policy are checked before routing tables build.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::waf::RouteWafConfig;

use super::route_actions::RouteActionsConfig;
use super::{
  BufferingMode, HttpVersion, LimitsConfig, PriorityClass, RetryCondition, RouteIpmConfig,
  RouteStaticFilesConfig, Tls12CipherSuite, Tls13CipherSuite, TlsEarlyDataMode,
  TlsKeyExchangeGroup, TlsVersion, default_hosts, default_path_prefix,
};

mod conflicts;

pub(super) fn validate_route_match_conflicts(routes: &[RouteConfig]) -> anyhow::Result<()> {
  conflicts::validate_route_match_conflicts(routes)
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RouteConfig {
  pub name: String,
  #[serde(default = "default_hosts")]
  pub hosts: Vec<String>,
  #[serde(default = "default_path_prefix")]
  pub path_prefix: String,
  #[serde(default, rename = "match")]
  pub r#match: RouteMatchConfig,
  #[serde(default)]
  pub replace_prefix_with: Option<String>,
  #[serde(default)]
  pub actions: RouteActionsConfig,
  #[serde(default)]
  pub upstream: Option<String>,
  #[serde(default)]
  pub upstream_pool: Option<String>,
  #[serde(default)]
  pub static_root: Option<PathBuf>,
  #[serde(default)]
  pub static_files: RouteStaticFilesConfig,
  #[serde(default)]
  pub upstream_http_version: Option<HttpVersion>,
  #[serde(default)]
  pub generic_http_upgrade: bool,
  #[serde(default)]
  pub connect_tunneling: bool,
  #[serde(default)]
  pub grpc_web: bool,
  #[serde(default)]
  pub external_auth: Option<String>,
  #[serde(default)]
  pub ipm: RouteIpmConfig,
  #[serde(default)]
  pub cache: Option<String>,
  #[serde(default)]
  pub compression: Option<String>,
  #[serde(default)]
  pub security_headers: Option<String>,
  #[serde(default)]
  pub priority_class: PriorityClass,
  #[serde(default)]
  pub buffering: RouteBufferingConfig,
  #[serde(default)]
  pub limits: RouteLimitsConfig,
  #[serde(default)]
  pub timeouts: RouteTimeoutConfig,
  #[serde(default)]
  pub retry: Option<RouteRetryConfig>,
  #[serde(default)]
  pub tls: RouteTlsConfig,
  #[serde(default)]
  pub waf: RouteWafConfig,
}

impl RouteConfig {
  pub fn effective_path_prefix(&self) -> &str {
    self
      .r#match
      .path
      .prefix
      .as_deref()
      .unwrap_or(&self.path_prefix)
  }

  pub fn effective_max_request_body_bytes(&self, limits: &LimitsConfig) -> u64 {
    self
      .limits
      .max_request_body_bytes
      .unwrap_or(limits.max_request_body_bytes)
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteTlsConfig {
  #[serde(default)]
  pub ssl_early_data: Option<TlsEarlyDataMode>,
  #[serde(default)]
  pub min_version: Option<TlsVersion>,
  #[serde(default)]
  pub max_version: Option<TlsVersion>,
  #[serde(default, rename = "1_2")]
  pub tls12: RouteTls12Config,
  #[serde(default, rename = "1_3")]
  pub tls13: RouteTls13Config,
}

impl RouteTlsConfig {
  pub fn has_negotiation_overrides(&self) -> bool {
    self.min_version.is_some()
      || self.max_version.is_some()
      || self.tls12.groups.is_some()
      || self.tls12.key_exchange_groups.is_some()
      || self.tls13.key_exchange_groups.is_some()
      || self.tls13.ciphers.is_some()
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteTls12Config {
  #[serde(default)]
  pub groups: Option<Vec<Tls12CipherSuite>>,
  #[serde(default)]
  pub key_exchange_groups: Option<Vec<TlsKeyExchangeGroup>>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteTls13Config {
  #[serde(default)]
  pub key_exchange_groups: Option<Vec<TlsKeyExchangeGroup>>,
  #[serde(default)]
  pub ciphers: Option<Vec<Tls13CipherSuite>>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteMatchConfig {
  #[serde(default)]
  pub methods: Vec<String>,
  #[serde(default)]
  pub headers: Vec<RouteNamedValueMatchConfig>,
  #[serde(default)]
  pub queries: Vec<RouteNamedValueMatchConfig>,
  #[serde(default)]
  pub path: RoutePathMatchConfig,
  #[serde(default)]
  pub source_cidrs: Vec<String>,
  #[serde(default)]
  pub protocols: Vec<String>,
  #[serde(default)]
  pub priority: i32,
  #[serde(default)]
  pub terminal: bool,
  #[serde(default)]
  pub tls: RouteTlsMatchConfig,
}

impl RouteMatchConfig {
  pub fn has_additional_conditions(&self) -> bool {
    !self.methods.is_empty()
      || !self.headers.is_empty()
      || !self.queries.is_empty()
      || self.path.exact.is_some()
      || self.path.regex.is_some()
      || !self.source_cidrs.is_empty()
      || !self.protocols.is_empty()
      || self.tls.client_cert.has_conditions()
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RoutePathMatchConfig {
  #[serde(default)]
  pub exact: Option<String>,
  #[serde(default)]
  pub prefix: Option<String>,
  #[serde(default)]
  pub regex: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteNamedValueMatchConfig {
  pub name: String,
  #[serde(flatten)]
  pub value: RouteValueMatchConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteValueMatchConfig {
  #[serde(default)]
  pub present: Option<bool>,
  #[serde(default)]
  pub exact: Option<String>,
  #[serde(default)]
  pub prefix: Option<String>,
  #[serde(default)]
  pub suffix: Option<String>,
  #[serde(default)]
  pub contains: Option<String>,
  #[serde(default)]
  pub regex: Option<String>,
}

impl RouteValueMatchConfig {
  pub fn has_conditions(&self) -> bool {
    self.present.is_some()
      || self.exact.is_some()
      || self.prefix.is_some()
      || self.suffix.is_some()
      || self.contains.is_some()
      || self.regex.is_some()
  }

  pub fn condition_count(&self) -> usize {
    usize::from(self.present.is_some())
      + usize::from(self.exact.is_some())
      + usize::from(self.prefix.is_some())
      + usize::from(self.suffix.is_some())
      + usize::from(self.contains.is_some())
      + usize::from(self.regex.is_some())
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteTlsMatchConfig {
  #[serde(default)]
  pub client_cert: RouteClientCertMatchConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteClientCertMatchConfig {
  #[serde(default)]
  pub present: Option<bool>,
  #[serde(default)]
  pub fingerprint_sha256: RouteValueMatchConfig,
  #[serde(default)]
  pub subject_cn: RouteValueMatchConfig,
  #[serde(default)]
  pub san_dns: RouteValueMatchConfig,
  #[serde(default)]
  pub san_ip: RouteValueMatchConfig,
}

impl RouteClientCertMatchConfig {
  pub fn has_conditions(&self) -> bool {
    self.present.is_some()
      || self.fingerprint_sha256.has_conditions()
      || self.subject_cn.has_conditions()
      || self.san_dns.has_conditions()
      || self.san_ip.has_conditions()
  }
}

pub(super) fn validate_route_path_value(
  route_name: &str,
  field_name: &str,
  value: &str,
) -> anyhow::Result<()> {
  if !value.starts_with('/') {
    bail!("route {route_name} {field_name} must start with '/'");
  }
  if value
    .bytes()
    .any(|byte| byte.is_ascii_control() || matches!(byte, b'\\' | b'?' | b'#'))
  {
    bail!(
      "route {route_name} {field_name} must not contain control characters, backslashes, queries, or fragments"
    );
  }

  for segment in value.split('/') {
    if matches!(segment, "." | "..") {
      bail!("route {route_name} {field_name} must not contain dot segments");
    }
  }

  let lower = value.to_ascii_lowercase();
  if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
    bail!("route {route_name} {field_name} must not contain encoded dot or slash separators");
  }

  Ok(())
}

pub(super) fn validate_route_match_config(route: &RouteConfig) -> anyhow::Result<()> {
  let route_name = &route.name;
  let mut hosts = HashSet::new();
  for host in &route.hosts {
    let normalized = validate_route_host_pattern(route_name, host)?;
    if !hosts.insert(normalized) {
      bail!("route {route_name} hosts contains duplicate {host}");
    }
  }

  let path = &route.r#match.path;
  if let Some(prefix) = &path.prefix {
    validate_route_path_value(route_name, "match.path.prefix", prefix)?;
    if route.path_prefix != "/" && route.path_prefix != *prefix {
      bail!("route {route_name} match.path.prefix must match path_prefix when both are configured");
    }
  }
  if let Some(exact) = &path.exact {
    validate_route_path_value(route_name, "match.path.exact", exact)?;
  }
  if let Some(regex) = &path.regex {
    validate_route_regex(route_name, "match.path.regex", regex)?;
  }

  let mut methods = HashSet::new();
  for method in &route.r#match.methods {
    if method.trim() != method || method.is_empty() {
      bail!("route {route_name} match.methods must not contain empty or padded values");
    }
    http::Method::from_bytes(method.as_bytes()).with_context(|| {
      format!("route {route_name} match.methods contains invalid method {method}")
    })?;
    if !methods.insert(method.as_str()) {
      bail!("route {route_name} match.methods contains duplicate {method}");
    }
  }

  for matcher in &route.r#match.headers {
    validate_named_value_match(route_name, "match.headers", matcher, true)?;
  }
  for matcher in &route.r#match.queries {
    validate_named_value_match(route_name, "match.queries", matcher, false)?;
  }

  let mut cidrs = HashSet::new();
  for cidr in &route.r#match.source_cidrs {
    let parsed = crate::identity::Cidr::parse(cidr).with_context(|| {
      format!("route {route_name} match.source_cidrs contains invalid CIDR {cidr}")
    })?;
    let canonical = parsed.canonical();
    if !cidrs.insert(canonical.clone()) {
      bail!("route {route_name} match.source_cidrs contains duplicate {canonical}");
    }
  }

  let mut protocols = HashSet::new();
  for protocol in &route.r#match.protocols {
    match protocol.as_str() {
      "http" | "http1" | "http2" | "http3" | "websocket" | "webtransport" => {}
      _ => bail!("route {route_name} match.protocols contains unsupported protocol {protocol}"),
    }
    if !protocols.insert(protocol.as_str()) {
      bail!("route {route_name} match.protocols contains duplicate {protocol}");
    }
  }

  let client_cert = &route.r#match.tls.client_cert;
  validate_optional_value_match(
    route_name,
    "match.tls.client_cert.fingerprint_sha256",
    &client_cert.fingerprint_sha256,
  )?;
  validate_optional_value_match(
    route_name,
    "match.tls.client_cert.subject_cn",
    &client_cert.subject_cn,
  )?;
  validate_optional_value_match(
    route_name,
    "match.tls.client_cert.san_dns",
    &client_cert.san_dns,
  )?;
  validate_optional_value_match(
    route_name,
    "match.tls.client_cert.san_ip",
    &client_cert.san_ip,
  )?;

  Ok(())
}

fn validate_route_host_pattern(route_name: &str, host: &str) -> anyhow::Result<String> {
  if host.trim() != host || host.is_empty() {
    bail!("route {route_name} hosts entries must not be empty or padded");
  }
  if host.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("route {route_name} hosts entry {host} contains a control character");
  }
  let normalized = host.trim_end_matches('.').to_ascii_lowercase();
  if normalized == "*" {
    return Ok(normalized);
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
  let dns_pattern = normalized.strip_prefix("*.").unwrap_or(&normalized);
  if dns_pattern.is_empty() || dns_pattern.contains('*') {
    bail!("route {route_name} hosts entry {host} may only use a leftmost wildcard");
  }
  if dns_pattern
    .split('.')
    .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
  {
    bail!("route {route_name} hosts entry {host} is not a valid DNS pattern");
  }
  if !dns_pattern
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
  {
    bail!("route {route_name} hosts entry {host} contains invalid characters");
  }
  Ok(normalized)
}

fn validate_named_value_match(
  route_name: &str,
  field_name: &str,
  matcher: &RouteNamedValueMatchConfig,
  header_name: bool,
) -> anyhow::Result<()> {
  if matcher.name.trim() != matcher.name || matcher.name.is_empty() {
    bail!("route {route_name} {field_name}.name must not be empty or padded");
  }
  if header_name {
    http::header::HeaderName::from_bytes(matcher.name.as_bytes()).with_context(|| {
      format!(
        "route {route_name} {field_name} contains invalid header name {}",
        matcher.name
      )
    })?;
  } else if matcher.name.bytes().any(|byte| byte.is_ascii_control()) {
    bail!(
      "route {route_name} {field_name} query name {} contains a control character",
      matcher.name
    );
  }
  validate_required_value_match(route_name, field_name, &matcher.value)
}

fn validate_required_value_match(
  route_name: &str,
  field_name: &str,
  matcher: &RouteValueMatchConfig,
) -> anyhow::Result<()> {
  if matcher.condition_count() != 1 {
    bail!("route {route_name} {field_name} entries must set exactly one value matcher");
  }
  validate_value_match_regex(route_name, field_name, matcher)
}

fn validate_optional_value_match(
  route_name: &str,
  field_name: &str,
  matcher: &RouteValueMatchConfig,
) -> anyhow::Result<()> {
  if matcher.condition_count() > 1 {
    bail!("route {route_name} {field_name} must set at most one value matcher");
  }
  validate_value_match_regex(route_name, field_name, matcher)
}

fn validate_value_match_regex(
  route_name: &str,
  field_name: &str,
  matcher: &RouteValueMatchConfig,
) -> anyhow::Result<()> {
  if let Some(regex) = &matcher.regex {
    validate_route_regex(route_name, field_name, regex)?;
  }
  Ok(())
}

fn validate_route_regex(route_name: &str, field_name: &str, regex: &str) -> anyhow::Result<()> {
  if regex.is_empty() {
    bail!("route {route_name} {field_name} must not be empty");
  }
  regex::Regex::new(regex)
    .with_context(|| format!("route {route_name} {field_name} contains invalid regex"))?;
  Ok(())
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteBufferingConfig {
  #[serde(default)]
  pub request: Option<BufferingMode>,
  #[serde(default)]
  pub response: Option<BufferingMode>,
  #[serde(default)]
  pub max_memory_body_bytes: Option<usize>,
  #[serde(default)]
  pub max_temp_file_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteLimitsConfig {
  #[serde(default)]
  pub max_request_body_bytes: Option<u64>,
}

impl RouteLimitsConfig {
  pub(super) fn validate(&self, route_name: &str) -> anyhow::Result<()> {
    if self.max_request_body_bytes == Some(0) {
      bail!("route {route_name} limits.max_request_body_bytes must be greater than 0");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteTimeoutConfig {
  #[serde(default)]
  pub client_body_timeout_ms: Option<u64>,
  #[serde(default)]
  pub response_send_timeout_ms: Option<u64>,
  #[serde(default)]
  pub websocket_idle_timeout_ms: Option<u64>,
  #[serde(default)]
  pub webtransport_idle_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_connect_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_request_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_first_byte_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_read_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_send_timeout_ms: Option<u64>,
}

impl RouteTimeoutConfig {
  pub(super) fn validate(&self, route_name: &str) -> anyhow::Result<()> {
    for (field, value) in [
      ("client_body_timeout_ms", self.client_body_timeout_ms),
      ("response_send_timeout_ms", self.response_send_timeout_ms),
      ("websocket_idle_timeout_ms", self.websocket_idle_timeout_ms),
      (
        "webtransport_idle_timeout_ms",
        self.webtransport_idle_timeout_ms,
      ),
      (
        "upstream_connect_timeout_ms",
        self.upstream_connect_timeout_ms,
      ),
      (
        "upstream_request_timeout_ms",
        self.upstream_request_timeout_ms,
      ),
      (
        "upstream_first_byte_timeout_ms",
        self.upstream_first_byte_timeout_ms,
      ),
      ("upstream_read_timeout_ms", self.upstream_read_timeout_ms),
      ("upstream_send_timeout_ms", self.upstream_send_timeout_ms),
    ] {
      if value == Some(0) {
        bail!("route {route_name} timeouts.{field} must be greater than 0");
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteRetryConfig {
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub tries: Option<usize>,
  #[serde(default)]
  pub total_budget_ms: Option<u64>,
  #[serde(default)]
  pub per_attempt_timeout_ms: Option<u64>,
  #[serde(default)]
  pub on: Option<Vec<RetryCondition>>,
  #[serde(default)]
  pub retry_non_idempotent: Option<bool>,
  #[serde(default)]
  pub backoff_base_ms: Option<u64>,
  #[serde(default)]
  pub backoff_max_ms: Option<u64>,
  #[serde(default)]
  pub jitter: Option<bool>,
  #[serde(default)]
  pub reselect_pool_on_retry: Option<bool>,
  #[serde(default)]
  pub exclude_failed_pool_upstreams: Option<bool>,
  #[serde(default)]
  pub report_passive_health: Option<bool>,
}

impl RouteRetryConfig {
  pub(super) fn validate(&self, route_name: &str) -> anyhow::Result<()> {
    if self.tries == Some(0) {
      bail!("route {route_name} retry.tries must be greater than 0");
    }
    for (field, value) in [
      ("total_budget_ms", self.total_budget_ms),
      ("per_attempt_timeout_ms", self.per_attempt_timeout_ms),
    ] {
      if value == Some(0) {
        bail!("route {route_name} retry.{field} must be greater than 0");
      }
    }
    if let (Some(base), Some(max)) = (self.backoff_base_ms, self.backoff_max_ms)
      && max > 0
      && base > max
    {
      bail!(
        "route {route_name} retry.backoff_max_ms must be 0 or greater than or equal to retry.backoff_base_ms"
      );
    }
    Ok(())
  }
}
