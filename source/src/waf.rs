use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use http::header::{COOKIE, HeaderName, HeaderValue, SET_COOKIE, USER_AGENT};
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use regex::{Regex, RegexBuilder};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::{Config, resolve_existing_local_config_file_path_with_logical};
use crate::routes::normalize_host;
use crate::shared_state::SharedState;

mod person_proof;

use person_proof::{
  PersonProofEngine, PersonProofPolicy, PersonProofRequestStatus, PersonProofState,
};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub mode: WafMode,
  #[serde(default)]
  pub fail_policy: WafFailPolicy,
  #[serde(default)]
  pub duplicate_metadata_policy: WafDuplicateMetadataPolicy,
  #[serde(default)]
  pub limits: WafLimits,
  #[serde(default)]
  pub rules: Vec<WafRuleConfig>,
  #[serde(default)]
  pub pattern_sets: Vec<WafPatternSetConfig>,
}

impl Default for WafConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: WafMode::Enforcing,
      fail_policy: WafFailPolicy::Closed,
      duplicate_metadata_policy: WafDuplicateMetadataPolicy::FailClosed,
      limits: WafLimits::default(),
      rules: Vec::new(),
      pattern_sets: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteWafConfig {
  #[serde(default)]
  pub rules: Vec<WafRuleConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
  #[default]
  Enforcing,
  Monitor,
}

impl WafMode {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Enforcing => "enforcing",
      Self::Monitor => "monitor",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafFailPolicy {
  #[default]
  Closed,
  Open,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafDuplicateMetadataPolicy {
  #[default]
  FailClosed,
  NullOnDuplicate,
  RejectRequest,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafLimits {
  #[serde(default = "default_max_rule_runtime_ms")]
  pub max_rule_runtime_ms: u64,
  #[serde(default = "default_max_total_waf_runtime_ms")]
  pub max_total_waf_runtime_ms: u64,
  #[serde(default = "default_max_expression_steps")]
  pub max_expression_steps: usize,
  #[serde(default = "default_max_memory_bytes")]
  pub max_memory_bytes: usize,
  #[serde(default = "default_max_string_bytes")]
  pub max_string_bytes: usize,
  #[serde(default = "default_max_body_inspection_bytes")]
  pub max_body_inspection_bytes: usize,
  #[serde(default = "default_max_header_count")]
  pub max_header_count: usize,
  #[serde(default = "default_max_header_value_bytes")]
  pub max_header_value_bytes: usize,
  #[serde(default = "default_max_mutations")]
  pub max_mutations: usize,
  #[serde(default = "default_max_regex_runtime_ms")]
  pub max_regex_runtime_ms: u64,
  #[serde(default = "default_max_helper_items")]
  pub max_helper_items: usize,
  #[serde(default = "default_max_helper_pattern_count")]
  pub max_helper_pattern_count: usize,
  #[serde(default = "default_max_helper_result_bytes")]
  pub max_helper_result_bytes: usize,
  #[serde(default = "default_max_person_proof_reuse_tokens")]
  pub max_person_proof_reuse_tokens: usize,
}

impl Default for WafLimits {
  fn default() -> Self {
    Self {
      max_rule_runtime_ms: default_max_rule_runtime_ms(),
      max_total_waf_runtime_ms: default_max_total_waf_runtime_ms(),
      max_expression_steps: default_max_expression_steps(),
      max_memory_bytes: default_max_memory_bytes(),
      max_string_bytes: default_max_string_bytes(),
      max_body_inspection_bytes: default_max_body_inspection_bytes(),
      max_header_count: default_max_header_count(),
      max_header_value_bytes: default_max_header_value_bytes(),
      max_mutations: default_max_mutations(),
      max_regex_runtime_ms: default_max_regex_runtime_ms(),
      max_helper_items: default_max_helper_items(),
      max_helper_pattern_count: default_max_helper_pattern_count(),
      max_helper_result_bytes: default_max_helper_result_bytes(),
      max_person_proof_reuse_tokens: default_max_person_proof_reuse_tokens(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafRuleConfig {
  pub name: String,
  #[serde(default)]
  pub id: Option<String>,
  #[serde(default)]
  pub tags: Vec<String>,
  #[serde(default)]
  pub mode: Option<WafMode>,
  pub phase: WafPhase,
  pub priority: i64,
  #[serde(default)]
  pub when: Option<String>,
  #[serde(default)]
  pub path: Option<PathBuf>,
  #[serde(default)]
  pub actions: Vec<WafActionConfig>,
  #[serde(skip)]
  pub loaded_from_path: Option<PathBuf>,
  #[serde(skip)]
  pub loaded_from_logical_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafPhase {
  Request,
  Response,
}

impl WafPhase {
  fn as_str(self) -> &'static str {
    match self {
      Self::Request => "request",
      Self::Response => "response",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WafActionConfig {
  Reject {
    status: u16,
    #[serde(default)]
    body: Option<String>,
  },
  ContinueResponse,
  ReplaceResponse {
    status: u16,
    #[serde(default)]
    body: Option<String>,
  },
  RejectResponse {
    status: u16,
    #[serde(default)]
    body: Option<String>,
  },
  EmitAccessLog {
    #[serde(default = "default_access_log_field_configs")]
    fields: Vec<AccessLogFieldConfig>,
  },
  RouteToPool {
    pool: String,
  },
  RouteToUpstream {
    upstream: String,
  },
  SetLoadBalancingPolicy {
    policy: String,
  },
  SetRequestHeader {
    name: String,
    value: String,
  },
  RemoveRequestHeader {
    name: String,
  },
  SetResponseHeader {
    name: String,
    value: String,
  },
  RemoveResponseHeader {
    name: String,
  },
  SetTag {
    key: String,
    value: String,
  },
  RequirePersonProof {
    #[serde(default)]
    algorithm: PersonProofAlgorithm,
    #[serde(default = "default_person_proof_difficulty")]
    difficulty: u8,
    #[serde(
      rename = "token_validity_seconds",
      default = "default_person_proof_token_validity_seconds",
      alias = "ttl_seconds",
      alias = "token_ttl_seconds"
    )]
    ttl_seconds: u64,
    #[serde(default = "default_person_proof_cookie")]
    cookie: String,
    #[serde(default = "default_person_proof_token_bindings")]
    token_bindings: Vec<PersonProofTokenBinding>,
    #[serde(default = "default_person_proof_direct_peer_ipv4_prefix_bits")]
    direct_peer_ipv4_prefix_bits: u8,
    #[serde(default = "default_person_proof_direct_peer_ipv6_prefix_bits")]
    direct_peer_ipv6_prefix_bits: u8,
    #[serde(default)]
    tcp_max_hop: Option<u8>,
    #[serde(default)]
    single_use: bool,
    #[serde(default)]
    success_tag: Option<String>,
    #[serde(default = "default_person_proof_status")]
    status: u16,
  },
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct AccessLogFieldConfig {
  pub name: String,
  #[serde(alias = "expression")]
  pub value: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PersonProofAlgorithm {
  #[default]
  PowSha256V1,
}

impl PersonProofAlgorithm {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::PowSha256V1 => "pow_sha256_v1",
    }
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PersonProofTokenBinding {
  UserAgent,
  TlsFingerprint,
  Route,
  #[serde(alias = "peer_ip_prefix")]
  DirectPeerIpNetworkPrefix,
  TcpMaxHop,
}

impl PersonProofTokenBinding {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::UserAgent => "user_agent",
      Self::TlsFingerprint => "tls_fingerprint",
      Self::Route => "route",
      Self::DirectPeerIpNetworkPrefix => "direct_peer_ip_network_prefix",
      Self::TcpMaxHop => "tcp_max_hop",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafPatternSetConfig {
  pub name: String,
  pub kind: WafPatternSetKind,
  pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafPatternSetKind {
  Contains,
  Regex,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalRuleFile {
  pub when: String,
  #[serde(default)]
  pub actions: Vec<WafActionConfig>,
}

impl WafConfig {
  pub fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<()> {
    for rule in &mut self.rules {
      resolve_rule_path(rule, base_dir)?;
    }
    Ok(())
  }

  pub fn load_external_rules(&mut self) -> anyhow::Result<()> {
    for rule in &mut self.rules {
      load_external_rule(rule)?;
    }
    Ok(())
  }

  pub fn loaded_rule_paths(&self) -> Vec<PathBuf> {
    self
      .rules
      .iter()
      .filter_map(|rule| {
        rule
          .loaded_from_logical_path
          .clone()
          .or_else(|| rule.loaded_from_path.clone())
      })
      .collect()
  }
}

impl RouteWafConfig {
  pub fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<()> {
    for rule in &mut self.rules {
      resolve_rule_path(rule, base_dir)?;
    }
    Ok(())
  }

  pub fn load_external_rules(&mut self) -> anyhow::Result<()> {
    for rule in &mut self.rules {
      load_external_rule(rule)?;
    }
    Ok(())
  }

  pub fn loaded_rule_paths(&self) -> Vec<PathBuf> {
    self
      .rules
      .iter()
      .filter_map(|rule| {
        rule
          .loaded_from_logical_path
          .clone()
          .or_else(|| rule.loaded_from_path.clone())
      })
      .collect()
  }
}

fn resolve_rule_path(rule: &mut WafRuleConfig, base_dir: &Path) -> anyhow::Result<()> {
  rule.path = rule
    .path
    .take()
    .map(|path| {
      let (resolved, logical) =
        resolve_existing_local_config_file_path_with_logical("WAF rule path", base_dir, &path)?;
      rule.loaded_from_logical_path = Some(logical);
      Ok::<PathBuf, anyhow::Error>(resolved)
    })
    .transpose()?;
  Ok(())
}

fn load_external_rule(rule: &mut WafRuleConfig) -> anyhow::Result<()> {
  let Some(path) = rule.path.take() else {
    return Ok(());
  };

  if rule.when.is_some() {
    bail!(
      "WAF rule {} must specify exactly one of when or path",
      rule.name
    );
  }

  let raw = std::fs::read_to_string(&path)
    .with_context(|| format!("failed to read WAF rule file {}", path.display()))?;
  let external: ExternalRuleFile = toml::from_str(&raw)
    .with_context(|| format!("failed to parse WAF rule file {}", path.display()))?;

  rule.when = Some(external.when);
  rule.actions = external.actions;
  rule.loaded_from_path = Some(path);
  Ok(())
}

pub fn validate_config(config: &Config) -> anyhow::Result<()> {
  if config.waf.limits.max_person_proof_reuse_tokens == 0 {
    bail!("waf.limits.max_person_proof_reuse_tokens must be greater than 0");
  }

  let upstream_names = config
    .upstreams
    .iter()
    .map(|upstream| upstream.name.as_str())
    .collect::<HashSet<_>>();
  let pool_names = config
    .upstream_pools
    .iter()
    .map(|pool| pool.name.as_str())
    .collect::<HashSet<_>>();
  validate_scope(
    "global WAF",
    &config.waf.rules,
    &config.waf.pattern_sets,
    &config.waf.limits,
    &upstream_names,
    &pool_names,
  )?;

  for route in &config.routes {
    validate_scope(
      &format!("route {} WAF", route.name),
      &route.waf.rules,
      &config.waf.pattern_sets,
      &config.waf.limits,
      &upstream_names,
      &pool_names,
    )?;
  }
  validate_unique_rule_ids(config)?;

  Ok(())
}

fn validate_unique_rule_ids(config: &Config) -> anyhow::Result<()> {
  let mut ids = HashMap::new();
  for rule in &config.waf.rules {
    remember_rule_id(&mut ids, "global WAF", rule)?;
  }
  for route in &config.routes {
    for rule in &route.waf.rules {
      remember_rule_id(&mut ids, &format!("route {} WAF", route.name), rule)?;
    }
  }
  Ok(())
}

fn remember_rule_id(
  ids: &mut HashMap<String, String>,
  scope: &str,
  rule: &WafRuleConfig,
) -> anyhow::Result<()> {
  let Some(id) = rule.id.as_deref().filter(|id| !id.is_empty()) else {
    return Ok(());
  };
  let label = format!("{scope} rule {}", rule.name);
  if let Some(previous) = ids.insert(id.to_string(), label.clone()) {
    bail!("duplicate WAF rule id {id} in {label}; already used by {previous}");
  }
  Ok(())
}

fn validate_scope(
  scope: &str,
  rules: &[WafRuleConfig],
  pattern_sets: &[WafPatternSetConfig],
  limits: &WafLimits,
  upstream_names: &HashSet<&str>,
  pool_names: &HashSet<&str>,
) -> anyhow::Result<()> {
  validate_pattern_sets(pattern_sets, limits)?;

  let mut names = HashSet::new();
  for rule in rules {
    if rule.name.trim().is_empty() {
      bail!("{scope} rule name must not be empty");
    }
    if !names.insert(rule.name.as_str()) {
      bail!("{scope} contains duplicate WAF rule name {}", rule.name);
    }
    if rule.priority < 0 {
      bail!("WAF rule {} priority must not be negative", rule.name);
    }
    validate_rule_metadata(rule)?;
    if rule.path.is_some() {
      bail!(
        "WAF rule {} external path was not loaded; use Config::load for rule files",
        rule.name
      );
    }
    if rule.when.is_none() {
      bail!(
        "WAF rule {} must specify exactly one of when or path",
        rule.name
      );
    }
    if rule.actions.is_empty() {
      bail!("WAF rule {} must define at least one action", rule.name);
    }

    let expression = rule.when.as_deref().unwrap_or_default();
    let ast = Parser::new(expression)
      .parse()
      .with_context(|| format!("failed to parse WAF rule {} expression", rule.name))?;
    ast
      .validate_for_phase(rule.phase)
      .with_context(|| format!("invalid WAF rule {} expression", rule.name))?;

    validate_actions(rule, upstream_names, pool_names, limits)?;
  }

  Ok(())
}

fn validate_rule_metadata(rule: &WafRuleConfig) -> anyhow::Result<()> {
  if let Some(id) = rule.id.as_deref()
    && !is_valid_rule_label(id)
  {
    bail!("WAF rule {} id must match [A-Za-z0-9-]{{0,32}}", rule.name);
  }

  let mut tags = HashSet::new();
  for tag in &rule.tags {
    if !is_valid_rule_label(tag) {
      bail!("WAF rule {} tag must match [A-Za-z0-9-]{{0,32}}", rule.name);
    }
    if !tags.insert(tag.as_str()) {
      bail!("WAF rule {} contains duplicate tag {}", rule.name, tag);
    }
  }

  Ok(())
}

fn validate_pattern_sets(
  pattern_sets: &[WafPatternSetConfig],
  limits: &WafLimits,
) -> anyhow::Result<()> {
  let mut names = HashSet::new();
  for set in pattern_sets {
    if set.name.trim().is_empty() {
      bail!("WAF pattern set name must not be empty");
    }
    if !names.insert(set.name.as_str()) {
      bail!("duplicate WAF pattern set name {}", set.name);
    }
    if set.patterns.len() > limits.max_helper_pattern_count {
      bail!(
        "WAF pattern set {} exceeds max_helper_pattern_count",
        set.name
      );
    }
    for pattern in &set.patterns {
      if pattern.len() > limits.max_string_bytes {
        bail!("WAF pattern set {} contains an oversized pattern", set.name);
      }
      if set.kind == WafPatternSetKind::Regex {
        Regex::new(pattern).with_context(|| {
          format!(
            "WAF pattern set {} contains an invalid regex pattern",
            set.name
          )
        })?;
      }
    }
  }
  Ok(())
}

fn validate_actions(
  rule: &WafRuleConfig,
  upstream_names: &HashSet<&str>,
  pool_names: &HashSet<&str>,
  limits: &WafLimits,
) -> anyhow::Result<()> {
  let mut mutations = 0usize;
  for action in &rule.actions {
    match action {
      WafActionConfig::Reject { status, .. } => {
        require_phase(rule, WafPhase::Request, "reject")?;
        validate_status(*status, &rule.name)?;
      }
      WafActionConfig::ContinueResponse => {
        require_phase(rule, WafPhase::Response, "continue_response")?;
      }
      WafActionConfig::ReplaceResponse { status, .. }
      | WafActionConfig::RejectResponse { status, .. } => {
        require_phase(rule, WafPhase::Response, "response terminal action")?;
        validate_status(*status, &rule.name)?;
      }
      WafActionConfig::EmitAccessLog { fields } => {
        require_phase(rule, WafPhase::Response, "emit_access_log")?;
        validate_access_log_field_configs(
          &format!("WAF rule {} emit_access_log", rule.name),
          fields,
        )?;
      }
      WafActionConfig::RouteToUpstream { upstream } => {
        require_phase(rule, WafPhase::Request, "route_to_upstream")?;
        if !upstream_names.contains(upstream.as_str()) {
          bail!(
            "WAF rule {} route_to_upstream references unknown upstream {}",
            rule.name,
            upstream
          );
        }
        mutations += 1;
      }
      WafActionConfig::RouteToPool { pool } => {
        require_phase(rule, WafPhase::Request, "route_to_pool")?;
        if !pool_names.contains(pool.as_str()) {
          bail!(
            "WAF rule {} route_to_pool references unknown upstream pool {}",
            rule.name,
            pool
          );
        }
        mutations += 1;
      }
      WafActionConfig::SetLoadBalancingPolicy { policy } => {
        require_phase(rule, WafPhase::Request, "set_load_balancing_policy")?;
        if !matches!(
          policy.as_str(),
          "round_robin" | "least_conn" | "least_connections" | "random" | "hash" | "ip_hash"
        ) {
          bail!(
            "WAF rule {} set_load_balancing_policy uses unsupported policy {}",
            rule.name,
            policy
          );
        }
        mutations += 1;
      }
      WafActionConfig::SetRequestHeader { name, value } => {
        require_phase(rule, WafPhase::Request, "set_request_header")?;
        validate_header(name, value)?;
        mutations += 1;
      }
      WafActionConfig::RemoveRequestHeader { name } => {
        require_phase(rule, WafPhase::Request, "remove_request_header")?;
        validate_header_name(name)?;
        mutations += 1;
      }
      WafActionConfig::SetResponseHeader { name, value } => {
        require_phase(rule, WafPhase::Response, "set_response_header")?;
        validate_header(name, value)?;
        mutations += 1;
      }
      WafActionConfig::RemoveResponseHeader { name } => {
        require_phase(rule, WafPhase::Response, "remove_response_header")?;
        validate_header_name(name)?;
        mutations += 1;
      }
      WafActionConfig::SetTag { key, value } => {
        require_phase(rule, WafPhase::Request, "set_tag")?;
        if key.is_empty() || !is_valid_rule_label(key) || value.len() > 1024 {
          bail!("WAF rule {} set_tag exceeds tag size limits", rule.name);
        }
        mutations += 1;
      }
      WafActionConfig::RequirePersonProof { status, .. } => {
        require_phase(rule, WafPhase::Request, "require_person_proof")?;
        validate_status(*status, &rule.name)?;
        validate_person_proof_settings(&rule.name, action)?;
      }
    }
  }

  if mutations > limits.max_mutations {
    bail!("WAF rule {} exceeds max_mutations", rule.name);
  }

  Ok(())
}

fn require_phase(rule: &WafRuleConfig, expected: WafPhase, action: &str) -> anyhow::Result<()> {
  if rule.phase != expected {
    bail!(
      "WAF rule {} action {action} is not valid in {:?} phase",
      rule.name,
      rule.phase
    );
  }
  Ok(())
}

fn validate_status(status: u16, rule_name: &str) -> anyhow::Result<()> {
  StatusCode::from_u16(status)
    .with_context(|| format!("WAF rule {rule_name} has invalid HTTP status {status}"))?;
  Ok(())
}

fn validate_header(name: &str, value: &str) -> anyhow::Result<()> {
  validate_header_name(name)?;
  HeaderValue::from_str(value).context("invalid WAF header value")?;
  Ok(())
}

fn validate_header_name(name: &str) -> anyhow::Result<()> {
  HeaderName::from_bytes(name.as_bytes()).context("invalid WAF header name")?;
  Ok(())
}

pub fn validate_access_log_field_configs(
  label: &str,
  fields: &[AccessLogFieldConfig],
) -> anyhow::Result<()> {
  if fields.is_empty() {
    bail!("{label} must define at least one field");
  }

  let mut names = HashSet::new();
  for field in fields {
    validate_access_log_field_name(label, &field.name)?;
    if matches!(field.name.as_str(), "event" | "timestamp_unix_ms") {
      bail!("{label} field {} uses a reserved field name", field.name);
    }
    if !names.insert(field.name.as_str()) {
      bail!("{label} contains duplicate field {}", field.name);
    }
    let expression = Parser::new(&field.value)
      .parse()
      .with_context(|| format!("failed to parse {label} field {}", field.name))?;
    expression
      .validate_for_phase(WafPhase::Response)
      .with_context(|| format!("invalid {label} field {}", field.name))?;
    if expression.requires_request_body_inspection() {
      bail!(
        "{label} field {} cannot read request body bytes",
        field.name
      );
    }
  }

  Ok(())
}

fn validate_access_log_field_name(label: &str, field_name: &str) -> anyhow::Result<()> {
  if field_name.is_empty()
    || field_name.len() > 64
    || !field_name
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
  {
    bail!("{label} field names must match [A-Za-z0-9_.-]{{1,64}}");
  }
  Ok(())
}

fn validate_person_proof_settings(rule_name: &str, action: &WafActionConfig) -> anyhow::Result<()> {
  let WafActionConfig::RequirePersonProof {
    difficulty,
    ttl_seconds,
    cookie,
    token_bindings,
    direct_peer_ipv4_prefix_bits,
    direct_peer_ipv6_prefix_bits,
    tcp_max_hop,
    success_tag,
    ..
  } = action
  else {
    unreachable!("validate_person_proof_settings requires require_person_proof action");
  };

  if !(1..=30).contains(difficulty) {
    bail!("WAF rule {rule_name} require_person_proof difficulty must be between 1 and 30");
  }
  if !(1..=86_400).contains(ttl_seconds) {
    bail!(
      "WAF rule {rule_name} require_person_proof token_validity_seconds must be between 1 and 86400"
    );
  }
  if !is_valid_cookie_name(cookie) {
    bail!("WAF rule {rule_name} require_person_proof cookie must be a safe cookie name");
  }
  if token_bindings.is_empty() {
    bail!("WAF rule {rule_name} require_person_proof token_bindings must not be empty");
  }
  let mut seen_bindings = HashSet::new();
  for binding in token_bindings {
    if !seen_bindings.insert(*binding) {
      bail!(
        "WAF rule {rule_name} require_person_proof token_bindings contains duplicate {}",
        binding.as_str()
      );
    }
    if *binding == PersonProofTokenBinding::TcpMaxHop && tcp_max_hop.is_none() {
      bail!(
        "WAF rule {rule_name} require_person_proof token binding tcp_max_hop requires tcp_max_hop"
      );
    }
  }
  if *direct_peer_ipv4_prefix_bits > 32 {
    bail!(
      "WAF rule {rule_name} require_person_proof direct_peer_ipv4_prefix_bits must be between 0 and 32"
    );
  }
  if *direct_peer_ipv6_prefix_bits > 128 {
    bail!(
      "WAF rule {rule_name} require_person_proof direct_peer_ipv6_prefix_bits must be between 0 and 128"
    );
  }
  if let Some(tag) = success_tag
    && (tag.is_empty() || !is_valid_rule_label(tag))
  {
    bail!("WAF rule {rule_name} require_person_proof success_tag exceeds tag size limits");
  }
  Ok(())
}

fn is_valid_rule_label(value: &str) -> bool {
  value.len() <= 32
    && value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_valid_cookie_name(name: &str) -> bool {
  !name.is_empty()
    && name.len() <= 64
    && !name.starts_with('$')
    && name
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[derive(Clone)]
pub struct WafEngine {
  enabled: bool,
  mode: WafMode,
  fail_policy: WafFailPolicy,
  duplicate_metadata_policy: WafDuplicateMetadataPolicy,
  limits: WafLimits,
  pattern_sets: HashMap<String, CompiledPatternSet>,
  global_rules: Vec<CompiledRule>,
  route_rules: HashMap<String, Vec<CompiledRule>>,
  person_proof: PersonProofEngine,
  person_proof_tcp_max_hop: Option<u8>,
}

impl WafEngine {
  pub fn new(config: &Config) -> anyhow::Result<Self> {
    Self::new_with_previous(config, None, None)
  }

  pub fn new_with_previous(
    config: &Config,
    previous: Option<&Self>,
    shared_state: Option<std::sync::Arc<SharedState>>,
  ) -> anyhow::Result<Self> {
    validate_config(config)?;

    let previous_counters = previous
      .map(WafEngine::active_hit_counters)
      .unwrap_or_default();
    let pattern_sets = compile_pattern_sets(&config.waf.pattern_sets, &config.waf.limits)?;
    let global_rules = compile_rules(
      &config.waf.rules,
      WafRuleScope::global(),
      config.waf.mode,
      &previous_counters,
    )?;
    let mut route_rules = HashMap::new();
    for route in &config.routes {
      route_rules.insert(
        route.name.clone(),
        compile_rules(
          &route.waf.rules,
          WafRuleScope::route(&route.name),
          config.waf.mode,
          &previous_counters,
        )?,
      );
    }
    let person_proof_policies = global_rules
      .iter()
      .chain(route_rules.values().flat_map(|rules| rules.iter()))
      .flat_map(|rule| rule.person_proof_policies.iter().cloned())
      .collect::<Vec<_>>();
    let person_proof = PersonProofEngine::from_policies_with_previous(
      person_proof_policies,
      config.waf.limits.max_person_proof_reuse_tokens,
      previous.map(|waf| &waf.person_proof),
      shared_state,
    )?;
    let person_proof_tcp_max_hop = if config.waf.enabled {
      person_proof.tcp_max_hop()
    } else {
      None
    };

    Ok(Self {
      enabled: config.waf.enabled,
      mode: config.waf.mode,
      fail_policy: config.waf.fail_policy,
      duplicate_metadata_policy: config.waf.duplicate_metadata_policy,
      limits: config.waf.limits.clone(),
      pattern_sets,
      global_rules,
      route_rules,
      person_proof,
      person_proof_tcp_max_hop,
    })
  }

  pub fn person_proof_tcp_max_hop(&self) -> Option<u8> {
    self.person_proof_tcp_max_hop
  }

  pub fn enabled(&self) -> bool {
    self.enabled
  }

  pub fn rule_hit_snapshots(&self) -> Vec<WafRuleHitSnapshot> {
    let mut snapshots = self
      .global_rules
      .iter()
      .chain(self.route_rules.values().flat_map(|rules| rules.iter()))
      .map(CompiledRule::hit_snapshot)
      .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| {
      left
        .scope
        .cmp(&right.scope)
        .then_with(|| left.route.cmp(&right.route))
        .then_with(|| left.phase.cmp(&right.phase))
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| left.id.cmp(&right.id))
        .then_with(|| left.effective_mode.cmp(&right.effective_mode))
    });
    snapshots
  }

  pub fn has_response_rules(&self, route_name: &str) -> bool {
    self.enabled
      && (self
        .global_rules
        .iter()
        .any(|rule| rule.phase == WafPhase::Response)
        || self
          .route_rules
          .get(route_name)
          .map(|rules| rules.iter().any(|rule| rule.phase == WafPhase::Response))
          .unwrap_or(false))
  }

  pub fn requires_request_body_inspection(&self, route_name: &str) -> bool {
    self.enabled
      && self
        .rules_for(route_name, WafPhase::Request)
        .iter()
        .any(|rule| rule.requires_request_body_inspection)
  }

  pub fn evaluate_request(&self, input: WafRequestInput<'_>) -> RequestWafDecision {
    if !self.enabled {
      return RequestWafDecision::default();
    }

    if self.duplicate_metadata_policy == WafDuplicateMetadataPolicy::RejectRequest
      && request_metadata_has_duplicates(input)
    {
      return RequestWafDecision {
        terminal: Some(WafTerminalResponse::new(
          StatusCode::BAD_REQUEST,
          "duplicate request metadata".to_string(),
        )),
        ..RequestWafDecision::default()
      };
    }

    match self.evaluate_request_inner(input) {
      Ok(decision) => decision,
      Err(error) => match self.fail_policy {
        WafFailPolicy::Open => {
          warn!(error = %error, "WAF request evaluation failed open");
          RequestWafDecision::default()
        }
        WafFailPolicy::Closed => {
          warn!(error = %error, "WAF request evaluation failed closed");
          RequestWafDecision {
            terminal: Some(WafTerminalResponse::new(
              StatusCode::FORBIDDEN,
              "WAF evaluation failed".to_string(),
            )),
            ..RequestWafDecision::default()
          }
        }
      },
    }
  }

  pub fn evaluate_response(&self, input: WafResponseInput<'_>) -> ResponseWafDecision {
    if !self.enabled {
      return ResponseWafDecision::default();
    }

    match self.evaluate_response_inner(input) {
      Ok(decision) => decision,
      Err(error) => match self.fail_policy {
        WafFailPolicy::Open => {
          warn!(error = %error, "WAF response evaluation failed open");
          ResponseWafDecision::default()
        }
        WafFailPolicy::Closed => {
          warn!(error = %error, "WAF response evaluation failed closed");
          ResponseWafDecision {
            terminal: Some(WafTerminalResponse::new(
              StatusCode::FORBIDDEN,
              "WAF evaluation failed".to_string(),
            )),
            ..ResponseWafDecision::default()
          }
        }
      },
    }
  }

  pub fn build_system_access_log(
    &self,
    fields: &CompiledAccessLogFields,
    input: WafResponseInput<'_>,
  ) -> anyhow::Result<AccessLogRecord> {
    let mut tx = TransactionBudget::new(&self.limits);
    let person_proof = self.person_proof.evaluate_request(input.request);
    let ctx = EvalContext {
      phase: WafPhase::Response,
      mode: self.mode,
      rule_name: "",
      rule_id: None,
      rule_tags: &[],
      request: input.request,
      response: Some(input),
      person_proof: &person_proof,
      pattern_sets: &self.pattern_sets,
      limits: &self.limits,
      duplicate_metadata_policy: self.duplicate_metadata_policy,
    };
    AccessLogRecord::from_fields(&fields.fields, &ctx, &mut tx, "system")
  }

  fn evaluate_request_inner(
    &self,
    input: WafRequestInput<'_>,
  ) -> anyhow::Result<RequestWafDecision> {
    let mut decision = RequestWafDecision::default();
    let mut active_tags = input.tags.to_owned();
    let person_proof = self.person_proof.evaluate_request(input);
    if person_proof.rate_limited {
      return Ok(person_proof_rate_limited_decision());
    }
    if let Some(tag) = self.person_proof.success_tag_for(&person_proof) {
      record_request_tag(
        &mut decision,
        &mut active_tags,
        tag.to_string(),
        "valid".to_string(),
      );
    }
    if let Some(mutation) = self.person_proof.clearance_cookie_mutation(&person_proof)? {
      decision.response_header_mutations.push(mutation);
    }

    let mut tx = TransactionBudget::new(&self.limits);
    for rule in self.rules_for(input.route_name, WafPhase::Request) {
      tx.check_total()?;
      let rule_person_proof = self.person_proof_status_for_rule(&person_proof, rule);
      let matched = {
        let request = WafRequestInput {
          tags: &active_tags,
          ..input
        };
        let ctx = EvalContext {
          phase: WafPhase::Request,
          mode: rule.mode,
          rule_name: "",
          rule_id: None,
          rule_tags: &[],
          request,
          response: None,
          person_proof: &rule_person_proof,
          pattern_sets: &self.pattern_sets,
          limits: &self.limits,
          duplicate_metadata_policy: self.duplicate_metadata_policy,
        };
        self.evaluate_rule(rule, &ctx, &mut tx)?
      };
      if !matched {
        continue;
      }
      rule.record_hit();
      debug!(
        rule = %rule.name,
        rule_id = rule.id.as_deref().unwrap_or_default(),
        internal_rule_id = %rule.internal_id,
        mode = rule.mode.as_str(),
        phase = "request",
        "WAF rule matched"
      );
      if rule.mode == WafMode::Monitor {
        continue;
      }
      let previous_tag_count = decision.tags.len();
      {
        let request = WafRequestInput {
          tags: &active_tags,
          ..input
        };
        apply_request_actions(rule, request, &self.person_proof, &mut decision, &mut tx)?;
      }
      for (key, value) in &decision.tags[previous_tag_count..] {
        active_tags.insert(key.clone(), value.clone());
      }
      if decision.terminal.is_some() {
        return Ok(decision);
      }
    }

    Ok(decision)
  }

  fn evaluate_response_inner(
    &self,
    input: WafResponseInput<'_>,
  ) -> anyhow::Result<ResponseWafDecision> {
    let mut decision = ResponseWafDecision::default();
    let person_proof = self.person_proof.evaluate_request(input.request);
    let mut tx = TransactionBudget::new(&self.limits);

    for rule in self.rules_for(input.request.route_name, WafPhase::Response) {
      tx.check_total()?;
      let ctx = EvalContext {
        phase: WafPhase::Response,
        mode: rule.mode,
        rule_name: "",
        rule_id: None,
        rule_tags: &[],
        request: input.request,
        response: Some(input),
        person_proof: &person_proof,
        pattern_sets: &self.pattern_sets,
        limits: &self.limits,
        duplicate_metadata_policy: self.duplicate_metadata_policy,
      };
      let matched = self.evaluate_rule(rule, &ctx, &mut tx)?;
      if !matched {
        continue;
      }
      rule.record_hit();
      debug!(
        rule = %rule.name,
        rule_id = rule.id.as_deref().unwrap_or_default(),
        internal_rule_id = %rule.internal_id,
        mode = rule.mode.as_str(),
        phase = "response",
        "WAF rule matched"
      );
      if rule.mode == WafMode::Monitor {
        continue;
      }
      apply_response_actions(rule, &ctx, input, &mut decision, &mut tx)?;
      if decision.terminal.is_some() {
        return Ok(decision);
      }
    }

    Ok(decision)
  }

  fn active_hit_counters(&self) -> HashMap<WafRuleHitKey, Arc<AtomicU64>> {
    self
      .global_rules
      .iter()
      .chain(self.route_rules.values().flat_map(|rules| rules.iter()))
      .map(|rule| (rule.hit_key.clone(), rule.hit_counter.clone()))
      .collect()
  }

  fn evaluate_rule(
    &self,
    rule: &CompiledRule,
    ctx: &EvalContext<'_>,
    tx: &mut TransactionBudget,
  ) -> anyhow::Result<bool> {
    tx.start_rule();
    let rule_ctx = EvalContext {
      rule_name: &rule.name,
      rule_id: rule.id.as_deref(),
      rule_tags: &rule.tags,
      ..*ctx
    };
    let value = rule.expression.eval(&rule_ctx, tx)?;
    value
      .as_bool()
      .with_context(|| format!("WAF rule {} expression did not evaluate to Bool", rule.name))
  }

  fn rules_for(&self, route_name: &str, phase: WafPhase) -> Vec<&CompiledRule> {
    let mut rules = self
      .global_rules
      .iter()
      .chain(
        self
          .route_rules
          .get(route_name)
          .into_iter()
          .flat_map(|rules| rules.iter()),
      )
      .filter(|rule| rule.phase == phase)
      .collect::<Vec<_>>();
    rules.sort_by(|left, right| {
      left
        .priority
        .cmp(&right.priority)
        .then_with(|| left.name.cmp(&right.name))
    });
    rules
  }

  fn person_proof_status_for_rule(
    &self,
    global_status: &PersonProofRequestStatus,
    rule: &CompiledRule,
  ) -> PersonProofRequestStatus {
    if rule.person_proof_policies.is_empty() {
      return global_status.clone();
    }
    if let Some(policy_key) = global_status.policy_key.as_deref()
      && rule
        .person_proof_policies
        .iter()
        .any(|policy| policy.key == policy_key)
    {
      return global_status.clone();
    }
    PersonProofRequestStatus::default()
  }
}

fn compile_pattern_sets(
  configs: &[WafPatternSetConfig],
  limits: &WafLimits,
) -> anyhow::Result<HashMap<String, CompiledPatternSet>> {
  validate_pattern_sets(configs, limits)?;
  let mut sets = HashMap::new();
  for config in configs {
    let compiled = match config.kind {
      WafPatternSetKind::Contains => CompiledPatternSet::Contains(config.patterns.clone()),
      WafPatternSetKind::Regex => {
        let patterns = config
          .patterns
          .iter()
          .map(|pattern| Regex::new(pattern))
          .collect::<Result<Vec<_>, _>>()
          .with_context(|| format!("failed to compile WAF pattern set {}", config.name))?;
        CompiledPatternSet::Regex(patterns)
      }
    };
    sets.insert(config.name.clone(), compiled);
  }
  Ok(sets)
}

fn compile_rules(
  configs: &[WafRuleConfig],
  scope: WafRuleScope,
  default_mode: WafMode,
  previous_counters: &HashMap<WafRuleHitKey, Arc<AtomicU64>>,
) -> anyhow::Result<Vec<CompiledRule>> {
  configs
    .iter()
    .map(|rule| {
      let expression = Parser::new(rule.when.as_deref().unwrap_or_default())
        .parse()
        .with_context(|| format!("failed to compile WAF rule {}", rule.name))?;
      let actions = compile_actions(rule, scope.person_proof_scope())
        .with_context(|| format!("failed to compile WAF rule {} actions", rule.name))?;
      let person_proof_policies = actions
        .iter()
        .filter_map(|action| match action {
          CompiledAction::RequirePersonProof(policy) => Some(policy.clone()),
          _ => None,
        })
        .collect();
      let mode = rule.mode.unwrap_or(default_mode);
      let hit_key = WafRuleHitKey {
        scope: scope.label.to_string(),
        route: scope.route.clone(),
        phase: rule.phase,
        name: rule.name.clone(),
        id: rule.id.clone().filter(|id| !id.is_empty()),
        mode,
      };
      let hit_counter = previous_counters.get(&hit_key).cloned().unwrap_or_default();
      Ok(CompiledRule {
        name: rule.name.clone(),
        id: rule.id.clone().filter(|id| !id.is_empty()),
        tags: rule.tags.clone(),
        scope: scope.label.to_string(),
        route: scope.route.clone(),
        internal_id: new_internal_rule_id()?,
        phase: rule.phase,
        priority: rule.priority,
        mode,
        hit_key,
        hit_counter,
        requires_request_body_inspection: rule.phase == WafPhase::Request
          && expression.requires_request_body_inspection(),
        expression,
        actions,
        person_proof_policies,
      })
    })
    .collect()
}

#[derive(Clone)]
struct WafRuleScope {
  label: &'static str,
  route: Option<String>,
  person_proof_scope: String,
}

impl WafRuleScope {
  fn global() -> Self {
    Self {
      label: "global",
      route: None,
      person_proof_scope: "global".to_string(),
    }
  }

  fn route(route_name: &str) -> Self {
    Self {
      label: "route",
      route: Some(route_name.to_string()),
      person_proof_scope: format!("route:{route_name}"),
    }
  }

  fn person_proof_scope(&self) -> &str {
    &self.person_proof_scope
  }
}

fn compile_actions(rule: &WafRuleConfig, scope: &str) -> anyhow::Result<Vec<CompiledAction>> {
  rule
    .actions
    .iter()
    .enumerate()
    .map(|(action_index, action)| match action {
      WafActionConfig::EmitAccessLog { fields } => Ok(CompiledAction::EmitAccessLog {
        fields: fields
          .iter()
          .map(|field| {
            Ok(CompiledAccessLogField {
              name: field.name.clone(),
              expression: Parser::new(&field.value).parse().with_context(|| {
                format!("failed to compile emit_access_log field {}", field.name)
              })?,
            })
          })
          .collect::<anyhow::Result<Vec<_>>>()?,
      }),
      WafActionConfig::RequirePersonProof { .. } => Ok(CompiledAction::RequirePersonProof(
        person_proof_policy_from_action(rule, scope, action_index, action),
      )),
      action => Ok(CompiledAction::Config(action.clone())),
    })
    .collect()
}

#[derive(Clone)]
pub struct CompiledAccessLogFields {
  fields: Vec<CompiledAccessLogField>,
}

pub fn compile_access_log_fields(
  label: &str,
  fields: &[AccessLogFieldConfig],
) -> anyhow::Result<CompiledAccessLogFields> {
  validate_access_log_field_configs(label, fields)?;
  let fields = fields
    .iter()
    .map(|field| {
      Ok(CompiledAccessLogField {
        name: field.name.clone(),
        expression: Parser::new(&field.value)
          .parse()
          .with_context(|| format!("failed to compile {label} field {}", field.name))?,
      })
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok(CompiledAccessLogFields { fields })
}

fn person_proof_policy_from_action(
  rule: &WafRuleConfig,
  scope: &str,
  action_index: usize,
  action: &WafActionConfig,
) -> PersonProofPolicy {
  let WafActionConfig::RequirePersonProof {
    algorithm,
    difficulty,
    ttl_seconds,
    cookie,
    token_bindings,
    direct_peer_ipv4_prefix_bits,
    direct_peer_ipv6_prefix_bits,
    tcp_max_hop,
    single_use,
    success_tag,
    status,
  } = action
  else {
    unreachable!("person_proof_policy_from_action requires require_person_proof action");
  };
  let rule_key = rule
    .id
    .as_deref()
    .filter(|id| !id.is_empty())
    .unwrap_or(&rule.name);
  PersonProofPolicy {
    key: format!("{scope}:{rule_key}:{action_index}"),
    algorithm: *algorithm,
    difficulty: *difficulty,
    ttl_seconds: *ttl_seconds,
    cookie: cookie.clone(),
    token_bindings: token_bindings.clone(),
    direct_peer_ipv4_prefix_bits: *direct_peer_ipv4_prefix_bits,
    direct_peer_ipv6_prefix_bits: *direct_peer_ipv6_prefix_bits,
    tcp_max_hop: *tcp_max_hop,
    single_use: *single_use,
    success_tag: success_tag.clone(),
    status: *status,
  }
}

fn new_internal_rule_id() -> anyhow::Result<String> {
  new_uuid_like_id("WAF internal rule id")
}

pub fn new_access_log_id() -> String {
  new_uuid_like_id("access log id").unwrap_or_else(|_| format!("fallback-{}", current_unix_ms()))
}

fn new_uuid_like_id(label: &str) -> anyhow::Result<String> {
  let mut bytes = [0u8; 16];
  SystemRandom::new()
    .fill(&mut bytes)
    .map_err(|_| anyhow!("failed to generate {label}"))?;
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  Ok(format!(
    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
    bytes[0],
    bytes[1],
    bytes[2],
    bytes[3],
    bytes[4],
    bytes[5],
    bytes[6],
    bytes[7],
    bytes[8],
    bytes[9],
    bytes[10],
    bytes[11],
    bytes[12],
    bytes[13],
    bytes[14],
    bytes[15]
  ))
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct WafRuleHitKey {
  scope: String,
  route: Option<String>,
  phase: WafPhase,
  name: String,
  id: Option<String>,
  mode: WafMode,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct WafRuleHitSnapshot {
  pub scope: String,
  pub route: Option<String>,
  pub phase: String,
  pub name: String,
  pub id: Option<String>,
  pub effective_mode: String,
  pub hits: u64,
}

#[derive(Clone)]
struct CompiledRule {
  name: String,
  id: Option<String>,
  tags: Vec<String>,
  scope: String,
  route: Option<String>,
  internal_id: String,
  phase: WafPhase,
  priority: i64,
  mode: WafMode,
  hit_key: WafRuleHitKey,
  hit_counter: Arc<AtomicU64>,
  requires_request_body_inspection: bool,
  expression: Expr,
  actions: Vec<CompiledAction>,
  person_proof_policies: Vec<PersonProofPolicy>,
}

impl CompiledRule {
  fn record_hit(&self) {
    self.hit_counter.fetch_add(1, Ordering::Relaxed);
  }

  fn hit_snapshot(&self) -> WafRuleHitSnapshot {
    WafRuleHitSnapshot {
      scope: self.scope.clone(),
      route: self.route.clone(),
      phase: self.phase.as_str().to_string(),
      name: self.name.clone(),
      id: self.id.clone(),
      effective_mode: self.mode.as_str().to_string(),
      hits: self.hit_counter.load(Ordering::Relaxed),
    }
  }
}

#[derive(Clone)]
enum CompiledAction {
  Config(WafActionConfig),
  RequirePersonProof(PersonProofPolicy),
  EmitAccessLog { fields: Vec<CompiledAccessLogField> },
}

#[derive(Clone)]
struct CompiledAccessLogField {
  name: String,
  expression: Expr,
}

#[derive(Clone)]
enum CompiledPatternSet {
  Contains(Vec<String>),
  Regex(Vec<Regex>),
}

#[derive(Debug, Clone, Copy)]
pub struct WafRequestInput<'a> {
  pub request_id: &'a str,
  pub transaction_id: &'a str,
  pub received_at_unix_ms: u64,
  pub method: &'a Method,
  pub uri: &'a Uri,
  pub version: Version,
  pub headers: &'a HeaderMap,
  pub body: Option<WafBodyInput<'a>>,
  pub peer_addr: std::net::SocketAddr,
  pub downstream_host: &'a str,
  pub downstream_scheme: &'a str,
  pub route_name: &'a str,
  pub tcp_max_hop: Option<u8>,
  pub tls: &'a WafTlsMetadata,
  pub protocol: WafProtocol,
  pub transport_network: WafTransportNetwork,
  pub tags: &'a HashMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
pub struct WafBodyInput<'a> {
  pub bytes: &'a [u8],
  pub is_truncated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct WafTlsMetadata {
  pub enabled: bool,
  pub version: Option<String>,
  pub cipher_suite: Option<String>,
  pub sni: Option<String>,
  pub alpn: Option<String>,
  pub fingerprint: Option<String>,
  pub fingerprint_scheme: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum WafProtocol {
  Http,
  Websocket,
  Webrtc,
  Webtransport,
}

impl WafProtocol {
  fn as_str(self) -> &'static str {
    match self {
      Self::Http => "http",
      Self::Websocket => "websocket",
      Self::Webrtc => "webrtc",
      Self::Webtransport => "webtransport",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafTransportNetwork {
  Tcp,
  Udp,
}

impl WafTransportNetwork {
  fn as_str(self) -> &'static str {
    match self {
      Self::Tcp => "tcp",
      Self::Udp => "udp",
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub struct WafResponseInput<'a> {
  pub request: WafRequestInput<'a>,
  pub response_id: &'a str,
  pub received_at_unix_ms: u64,
  pub version: Version,
  pub status: StatusCode,
  pub headers: &'a HeaderMap,
  pub upstream_name: &'a str,
  pub upstream_pool: Option<&'a str>,
  pub upstream_scheme: &'a str,
  pub upstream_connect_time_ms: Option<u64>,
  pub upstream_first_byte_time_ms: Option<u64>,
  pub upstream_error: Option<WafUpstreamError<'a>>,
}

#[derive(Debug, Clone, Copy)]
pub struct WafUpstreamError<'a> {
  pub code: &'a str,
  pub message: &'a str,
}

#[derive(Debug, Default)]
pub struct RequestWafDecision {
  pub terminal: Option<WafTerminalResponse>,
  pub request_header_mutations: Vec<HeaderMutation>,
  pub response_header_mutations: Vec<HeaderMutation>,
  pub tags: Vec<(String, String)>,
  pub upstream_override: Option<String>,
  pub upstream_pool_override: Option<String>,
  pub load_balancing_policy: Option<String>,
}

#[derive(Debug, Default)]
pub struct ResponseWafDecision {
  pub terminal: Option<WafTerminalResponse>,
  pub response_header_mutations: Vec<HeaderMutation>,
  pub access_logs: Vec<AccessLogRecord>,
}

fn record_request_tag(
  decision: &mut RequestWafDecision,
  active_tags: &mut HashMap<String, String>,
  key: String,
  value: String,
) {
  active_tags.insert(key.clone(), value.clone());
  decision.tags.push((key, value));
}

fn person_proof_rate_limited_decision() -> RequestWafDecision {
  RequestWafDecision {
    terminal: Some(WafTerminalResponse::new(
      StatusCode::TOO_MANY_REQUESTS,
      "person proof token capacity exhausted".to_string(),
    )),
    ..RequestWafDecision::default()
  }
}

#[derive(Debug)]
pub struct WafTerminalResponse {
  pub status: StatusCode,
  pub body: String,
  pub headers: Vec<HeaderMutation>,
}

impl WafTerminalResponse {
  pub(super) fn new(status: StatusCode, body: String) -> Self {
    Self {
      status,
      body,
      headers: Vec::new(),
    }
  }
}

#[derive(Debug, Clone)]
pub enum HeaderMutation {
  Set {
    name: HeaderName,
    value: HeaderValue,
  },
  Append {
    name: HeaderName,
    value: HeaderValue,
  },
  Remove {
    name: HeaderName,
  },
}

fn apply_request_actions(
  rule: &CompiledRule,
  input: WafRequestInput<'_>,
  person_proof: &PersonProofEngine,
  decision: &mut RequestWafDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<()> {
  for action in &rule.actions {
    tx.count_mutation()?;
    match action {
      CompiledAction::Config(WafActionConfig::Reject { status, body }) => {
        decision.terminal = Some(WafTerminalResponse::new(
          StatusCode::from_u16(*status)?,
          body.clone().unwrap_or_else(|| "Blocked by WAF".to_string()),
        ));
        return Ok(());
      }
      CompiledAction::Config(WafActionConfig::SetRequestHeader { name, value }) => {
        decision.request_header_mutations.push(HeaderMutation::Set {
          name: HeaderName::from_bytes(name.as_bytes())?,
          value: HeaderValue::from_str(value)?,
        });
      }
      CompiledAction::Config(WafActionConfig::RemoveRequestHeader { name }) => {
        decision
          .request_header_mutations
          .push(HeaderMutation::Remove {
            name: HeaderName::from_bytes(name.as_bytes())?,
          });
      }
      CompiledAction::Config(WafActionConfig::SetTag { key, value }) => {
        decision.tags.push((key.clone(), value.clone()));
      }
      CompiledAction::Config(WafActionConfig::RouteToUpstream { upstream }) => {
        decision.upstream_override = Some(upstream.clone());
      }
      CompiledAction::Config(WafActionConfig::RouteToPool { pool }) => {
        decision.upstream_pool_override = Some(pool.clone());
      }
      CompiledAction::Config(WafActionConfig::SetLoadBalancingPolicy { policy }) => {
        decision.load_balancing_policy = Some(policy.clone());
      }
      CompiledAction::RequirePersonProof(policy) => {
        decision.terminal = Some(person_proof.issue_challenge(input, policy.clone())?);
        return Ok(());
      }
      CompiledAction::Config(WafActionConfig::ContinueResponse)
      | CompiledAction::Config(WafActionConfig::ReplaceResponse { .. })
      | CompiledAction::Config(WafActionConfig::RejectResponse { .. })
      | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. })
      | CompiledAction::Config(WafActionConfig::SetResponseHeader { .. })
      | CompiledAction::Config(WafActionConfig::RemoveResponseHeader { .. })
      | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
      | CompiledAction::EmitAccessLog { .. } => {
        bail!("invalid request-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(())
}

fn apply_response_actions(
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  input: WafResponseInput<'_>,
  decision: &mut ResponseWafDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<()> {
  for action in &rule.actions {
    tx.count_mutation()?;
    match action {
      CompiledAction::Config(WafActionConfig::ContinueResponse) => return Ok(()),
      CompiledAction::Config(WafActionConfig::ReplaceResponse { status, body })
      | CompiledAction::Config(WafActionConfig::RejectResponse { status, body }) => {
        decision.terminal = Some(WafTerminalResponse::new(
          StatusCode::from_u16(*status)?,
          body.clone().unwrap_or_else(|| "Blocked by WAF".to_string()),
        ));
        return Ok(());
      }
      CompiledAction::Config(WafActionConfig::SetResponseHeader { name, value }) => {
        decision
          .response_header_mutations
          .push(HeaderMutation::Set {
            name: HeaderName::from_bytes(name.as_bytes())?,
            value: HeaderValue::from_str(value)?,
          });
      }
      CompiledAction::Config(WafActionConfig::RemoveResponseHeader { name }) => {
        decision
          .response_header_mutations
          .push(HeaderMutation::Remove {
            name: HeaderName::from_bytes(name.as_bytes())?,
          });
      }
      CompiledAction::EmitAccessLog { fields } => {
        let action_ctx = EvalContext {
          rule_name: &rule.name,
          rule_id: rule.id.as_deref(),
          rule_tags: &rule.tags,
          response: Some(input),
          ..*ctx
        };
        decision.access_logs.push(AccessLogRecord::from_fields(
          fields,
          &action_ctx,
          tx,
          "waf",
        )?);
      }
      CompiledAction::Config(WafActionConfig::Reject { .. })
      | CompiledAction::Config(WafActionConfig::RouteToPool { .. })
      | CompiledAction::Config(WafActionConfig::RouteToUpstream { .. })
      | CompiledAction::Config(WafActionConfig::SetLoadBalancingPolicy { .. })
      | CompiledAction::Config(WafActionConfig::SetRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::RemoveRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::SetTag { .. })
      | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
      | CompiledAction::RequirePersonProof(_)
      | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. }) => {
        bail!("invalid response-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccessLogRecord {
  timestamp_unix_ms: u64,
  fields: Vec<AccessLogFieldValue>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AccessLogFieldValue {
  name: String,
  value: AccessLogJsonValue,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum AccessLogJsonValue {
  Bool(bool),
  Int(i64),
  String(String),
  Array(Vec<AccessLogJsonValue>),
  Object(Vec<(String, AccessLogJsonValue)>),
  Null,
}

impl AccessLogRecord {
  pub const EVENT: &'static str = "oxibelt.access";

  fn from_fields(
    fields: &[CompiledAccessLogField],
    ctx: &EvalContext<'_>,
    tx: &mut TransactionBudget,
    scope: &str,
  ) -> anyhow::Result<Self> {
    let values = fields
      .iter()
      .map(|field| {
        let value = field
          .expression
          .eval(ctx, tx)
          .with_context(|| format!("failed to evaluate emit_access_log field {}", field.name))?;
        Ok(AccessLogFieldValue {
          name: field.name.clone(),
          value: AccessLogJsonValue::from_value(value, ctx)?,
        })
      })
      .collect::<anyhow::Result<Vec<_>>>()?;
    let mut values = values;
    if !values.iter().any(|field| field.name == "scope") {
      values.insert(
        0,
        AccessLogFieldValue {
          name: "scope".to_string(),
          value: AccessLogJsonValue::String(scope.to_string()),
        },
      );
    }

    Ok(Self {
      timestamp_unix_ms: current_unix_ms(),
      fields: values,
    })
  }

  pub fn timestamp_unix_ms(&self) -> u64 {
    self.timestamp_unix_ms
  }

  pub fn to_json_line(&self) -> String {
    let mut out = String::new();
    out.push('{');
    let mut first = true;

    push_json_string_field(&mut out, &mut first, "event", Self::EVENT);
    push_json_u64_field(
      &mut out,
      &mut first,
      "timestamp_unix_ms",
      self.timestamp_unix_ms,
    );
    for field in &self.fields {
      push_json_value_field(&mut out, &mut first, &field.name, &field.value);
    }

    out.push('}');
    out
  }

  pub fn emit_stdout(&self) {
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = writeln!(stdout, "{}", self.to_json_line()) {
      warn!(error = %error, "failed to write OxiRule access log to stdout");
    }
  }
}

impl AccessLogJsonValue {
  fn from_value(value: Value, ctx: &EvalContext<'_>) -> anyhow::Result<Self> {
    match value {
      Value::Bool(value) => Ok(Self::Bool(value)),
      Value::Int(value) => Ok(Self::Int(value)),
      Value::String(value) => Ok(Self::String(truncate_log_string(
        &value,
        ctx.limits.max_helper_result_bytes,
      ))),
      Value::StringList(list) => Ok(Self::bounded_string_list(list, ctx.limits)),
      Value::Object(object) => Self::from_object(object, ctx),
      Value::Null => Ok(Self::Null),
      Value::Bytes(_) => bail!("emit_access_log fields cannot write raw Bytes"),
    }
  }

  fn bounded_string_list(list: BoundedStringList, limits: &WafLimits) -> Self {
    Self::Object(vec![
      (
        "values".to_string(),
        Self::Array(
          list
            .values
            .into_iter()
            .map(|value| Self::String(truncate_log_string(&value, limits.max_helper_result_bytes)))
            .collect(),
        ),
      ),
      ("is_truncated".to_string(), Self::Bool(list.is_truncated)),
    ])
  }

  fn from_object(object: ObjectRef, ctx: &EvalContext<'_>) -> anyhow::Result<Self> {
    match object {
      ObjectRef::RequestHeaders => Ok(header_map_json(ctx.request.headers, ctx.limits)),
      ObjectRef::ResponseHeaders => Ok(header_map_json(
        ctx.response.context("missing response context")?.headers,
        ctx.limits,
      )),
      ObjectRef::RequestQueryParams => Ok(pair_map_json(
        query_pairs(ctx.request.uri, ctx.limits),
        ctx.limits,
      )),
      ObjectRef::RequestCookies => Ok(pair_map_json(
        cookie_pairs(ctx.request.headers, ctx.limits),
        ctx.limits,
      )),
      ObjectRef::RequestTags => Ok(string_map_json(ctx.request.tags, ctx.limits)),
      ObjectRef::ContextRuleTags => Ok(Self::Array(
        ctx
          .rule_tags
          .iter()
          .take(ctx.limits.max_helper_items)
          .map(|tag| Self::String(truncate_log_string(tag, ctx.limits.max_helper_result_bytes)))
          .collect(),
      )),
      ObjectRef::RequestHttp => object_members_json(
        object,
        &[
          "Version", "Method", "Scheme", "Host", "Path", "Query", "Uri",
        ],
        ctx,
      ),
      ObjectRef::RequestClient => object_members_json(
        object,
        &[
          "Kind",
          "Ip",
          "Port",
          "SourceAddress",
          "UserAgent",
          "GeoCountry",
          "Asn",
        ],
        ctx,
      ),
      ObjectRef::RequestTransport => object_members_json(
        object,
        &["Network", "RemoteIp", "RemotePort", "IsEncrypted"],
        ctx,
      ),
      ObjectRef::RequestTransportTcp => {
        object_members_json(object, &["Sni", "Alpn", "MaxHop", "Mss", "RttMs"], ctx)
      }
      ObjectRef::RequestTransportUdp => object_members_json(
        object,
        &["DatagramSize", "QuicDetected", "ConnectionId"],
        ctx,
      ),
      ObjectRef::RequestTls | ObjectRef::ResponseTls => object_members_json(
        object,
        &[
          "Enabled",
          "Version",
          "CipherSuite",
          "Sni",
          "Alpn",
          "Fingerprint",
          "FingerprintScheme",
          "ClientCertificatePresent",
        ],
        ctx,
      ),
      ObjectRef::RequestBody | ObjectRef::ResponseBody => {
        object_members_json(object, &["Size", "IsTruncated", "Text"], ctx)
      }
      ObjectRef::RequestClientPersonProof => object_members_json(
        object,
        &[
          "State",
          "Method",
          "Difficulty",
          "IssuedAtUnixMs",
          "ExpiresAtUnixMs",
        ],
        ctx,
      ),
      ObjectRef::RequestClientAgent => object_members_json(
        object,
        &["Verified", "Kind", "Provider", "Model", "AuthMethod"],
        ctx,
      ),
      ObjectRef::RequestClientBot => object_members_json(
        object,
        &["Disposition", "Malicious", "Score", "Reason"],
        ctx,
      ),
      ObjectRef::ResponseHttp => object_members_json(object, &["Version", "Status", "Reason"], ctx),
      ObjectRef::ResponseTransport => object_members_json(object, &["Network", "IsEncrypted"], ctx),
      ObjectRef::ResponseUpstream => object_members_json(
        object,
        &[
          "Name",
          "Pool",
          "Scheme",
          "ConnectTimeMs",
          "FirstByteTimeMs",
          "Error",
        ],
        ctx,
      ),
      ObjectRef::ResponseUpstreamError => object_members_json(object, &["Code", "Message"], ctx),
      ObjectRef::ResponseCookies => Ok(header_cookie_json(
        ctx.response.context("missing response context")?.headers,
        ctx.limits,
      )),
      ObjectRef::ResponseTags => Ok(Self::Object(Vec::new())),
      ObjectRef::RequestTokenBindings => object_members_json(
        object,
        &[
          "UserAgent",
          "TlsFingerprint",
          "Route",
          "DirectPeerIpNetworkPrefix",
          "TcpMaxHop",
        ],
        ctx,
      ),
      ObjectRef::Context | ObjectRef::Request | ObjectRef::Response => {
        bail!("top-level OxiRule objects cannot be written as access-log fields")
      }
    }
  }
}

fn object_members_json(
  object: ObjectRef,
  fields: &[&str],
  ctx: &EvalContext<'_>,
) -> anyhow::Result<AccessLogJsonValue> {
  let mut values = Vec::new();
  for field in fields {
    let value = eval_member(Value::Object(object), field, ctx)?;
    values.push((
      field.to_ascii_lowercase(),
      AccessLogJsonValue::from_value(value, ctx)?,
    ));
  }
  Ok(AccessLogJsonValue::Object(values))
}

fn header_map_json(headers: &HeaderMap, limits: &WafLimits) -> AccessLogJsonValue {
  let mut fields: BTreeMap<String, Vec<AccessLogJsonValue>> = BTreeMap::new();
  for (name, value) in headers.iter().take(limits.max_helper_items) {
    let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
    fields
      .entry(name.as_str().to_ascii_lowercase())
      .or_default()
      .push(AccessLogJsonValue::String(truncate_log_string(
        &value,
        limits.max_header_value_bytes,
      )));
  }
  AccessLogJsonValue::Object(collapse_json_map(fields))
}

fn pair_map_json(pairs: Vec<(String, String)>, limits: &WafLimits) -> AccessLogJsonValue {
  let mut fields: BTreeMap<String, Vec<AccessLogJsonValue>> = BTreeMap::new();
  for (name, value) in pairs.into_iter().take(limits.max_helper_items) {
    fields
      .entry(truncate_log_string(&name, limits.max_helper_result_bytes))
      .or_default()
      .push(AccessLogJsonValue::String(truncate_log_string(
        &value,
        limits.max_helper_result_bytes,
      )));
  }
  AccessLogJsonValue::Object(collapse_json_map(fields))
}

fn string_map_json(values: &HashMap<String, String>, limits: &WafLimits) -> AccessLogJsonValue {
  let mut fields = values
    .iter()
    .take(limits.max_helper_items)
    .map(|(name, value)| {
      (
        truncate_log_string(name, limits.max_helper_result_bytes),
        AccessLogJsonValue::String(truncate_log_string(value, limits.max_helper_result_bytes)),
      )
    })
    .collect::<Vec<_>>();
  fields.sort_by(|left, right| left.0.cmp(&right.0));
  AccessLogJsonValue::Object(fields)
}

fn collapse_json_map(
  fields: BTreeMap<String, Vec<AccessLogJsonValue>>,
) -> Vec<(String, AccessLogJsonValue)> {
  fields
    .into_iter()
    .map(|(name, mut values)| {
      let value = if values.len() == 1 {
        values.pop().expect("single value is present")
      } else {
        AccessLogJsonValue::Array(values)
      };
      (name, value)
    })
    .collect()
}

fn query_pairs(uri: &Uri, limits: &WafLimits) -> Vec<(String, String)> {
  url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
    .take(limits.max_helper_items)
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect()
}

fn cookie_pairs(headers: &HeaderMap, limits: &WafLimits) -> Vec<(String, String)> {
  headers
    .get_all(COOKIE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(';'))
    .filter_map(|part| part.trim().split_once('='))
    .take(limits.max_helper_items)
    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
    .collect()
}

fn header_cookie_json(headers: &HeaderMap, limits: &WafLimits) -> AccessLogJsonValue {
  AccessLogJsonValue::bounded_string_list(
    bounded_string_list(
      headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| truncate_to_bytes(value, limits.max_header_value_bytes)),
      limits,
    ),
    limits,
  )
}

pub fn current_unix_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
    .unwrap_or_default()
}

fn truncate_log_string(value: &str, max_bytes: usize) -> String {
  if value.len() <= max_bytes {
    return value.to_string();
  }

  let mut end = 0usize;
  for (index, character) in value.char_indices() {
    let next = index + character.len_utf8();
    if next > max_bytes {
      break;
    }
    end = next;
  }
  value[..end].to_string()
}

fn push_json_field_name(out: &mut String, first: &mut bool, name: &str) {
  if *first {
    *first = false;
  } else {
    out.push(',');
  }
  push_json_string(out, name);
  out.push(':');
}

fn push_json_string_field(out: &mut String, first: &mut bool, name: &str, value: &str) {
  push_json_field_name(out, first, name);
  push_json_string(out, value);
}

fn push_json_value_field(
  out: &mut String,
  first: &mut bool,
  name: &str,
  value: &AccessLogJsonValue,
) {
  push_json_field_name(out, first, name);
  match value {
    AccessLogJsonValue::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
    AccessLogJsonValue::Int(value) => {
      let _ = write!(out, "{value}");
    }
    AccessLogJsonValue::String(value) => push_json_string(out, value),
    AccessLogJsonValue::Array(values) => {
      out.push('[');
      let mut first = true;
      for value in values {
        if first {
          first = false;
        } else {
          out.push(',');
        }
        push_json_value(out, value);
      }
      out.push(']');
    }
    AccessLogJsonValue::Object(fields) => {
      out.push('{');
      let mut first = true;
      for (name, value) in fields {
        push_json_value_field(out, &mut first, name, value);
      }
      out.push('}');
    }
    AccessLogJsonValue::Null => out.push_str("null"),
  }
}

fn push_json_value(out: &mut String, value: &AccessLogJsonValue) {
  match value {
    AccessLogJsonValue::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
    AccessLogJsonValue::Int(value) => {
      let _ = write!(out, "{value}");
    }
    AccessLogJsonValue::String(value) => push_json_string(out, value),
    AccessLogJsonValue::Array(values) => {
      out.push('[');
      let mut first = true;
      for value in values {
        if first {
          first = false;
        } else {
          out.push(',');
        }
        push_json_value(out, value);
      }
      out.push(']');
    }
    AccessLogJsonValue::Object(fields) => {
      out.push('{');
      let mut first = true;
      for (name, value) in fields {
        push_json_value_field(out, &mut first, name, value);
      }
      out.push('}');
    }
    AccessLogJsonValue::Null => out.push_str("null"),
  }
}

fn push_json_u64_field(out: &mut String, first: &mut bool, name: &str, value: u64) {
  push_json_field_name(out, first, name);
  let _ = write!(out, "{value}");
}

fn push_json_string(out: &mut String, value: &str) {
  out.push('"');
  for character in value.chars() {
    match character {
      '"' => out.push_str("\\\""),
      '\\' => out.push_str("\\\\"),
      '\u{08}' => out.push_str("\\b"),
      '\u{0c}' => out.push_str("\\f"),
      '\n' => out.push_str("\\n"),
      '\r' => out.push_str("\\r"),
      '\t' => out.push_str("\\t"),
      character if character <= '\u{1f}' => {
        let _ = write!(out, "\\u{:04x}", character as u32);
      }
      character => out.push(character),
    }
  }
  out.push('"');
}

pub fn apply_header_mutations(headers: &mut HeaderMap, mutations: &[HeaderMutation]) {
  for mutation in mutations {
    match mutation {
      HeaderMutation::Set { name, value } => {
        headers.insert(name, value.clone());
      }
      HeaderMutation::Append { name, value } => {
        headers.append(name, value.clone());
      }
      HeaderMutation::Remove { name } => {
        headers.remove(name);
      }
    }
  }
}

struct TransactionBudget<'a> {
  limits: &'a WafLimits,
  started_at: Instant,
  rule_started_at: Instant,
  steps: usize,
  mutations: usize,
}

impl<'a> TransactionBudget<'a> {
  fn new(limits: &'a WafLimits) -> Self {
    let now = Instant::now();
    Self {
      limits,
      started_at: now,
      rule_started_at: now,
      steps: 0,
      mutations: 0,
    }
  }

  fn start_rule(&mut self) {
    self.rule_started_at = Instant::now();
    self.steps = 0;
  }

  fn step(&mut self) -> anyhow::Result<()> {
    self.steps += 1;
    if self.steps > self.limits.max_expression_steps {
      bail!("WAF expression step budget exceeded");
    }
    self.check_total()?;
    if self.rule_started_at.elapsed() > Duration::from_millis(self.limits.max_rule_runtime_ms) {
      bail!("WAF rule runtime budget exceeded");
    }
    Ok(())
  }

  fn check_total(&self) -> anyhow::Result<()> {
    if self.started_at.elapsed() > Duration::from_millis(self.limits.max_total_waf_runtime_ms) {
      bail!("WAF total runtime budget exceeded");
    }
    Ok(())
  }

  fn count_mutation(&mut self) -> anyhow::Result<()> {
    self.mutations += 1;
    if self.mutations > self.limits.max_mutations {
      bail!("WAF mutation budget exceeded");
    }
    Ok(())
  }
}

#[derive(Clone, Copy)]
struct EvalContext<'a> {
  phase: WafPhase,
  mode: WafMode,
  rule_name: &'a str,
  rule_id: Option<&'a str>,
  rule_tags: &'a [String],
  request: WafRequestInput<'a>,
  response: Option<WafResponseInput<'a>>,
  person_proof: &'a PersonProofRequestStatus,
  pattern_sets: &'a HashMap<String, CompiledPatternSet>,
  limits: &'a WafLimits,
  duplicate_metadata_policy: WafDuplicateMetadataPolicy,
}

#[derive(Debug, Clone)]
enum Expr {
  Bool(bool),
  Null,
  Int(i64),
  String(String),
  Ident(String),
  Member(Box<Expr>, String),
  Call(Box<Expr>, String, Vec<Expr>),
  UnaryNot(Box<Expr>),
  Binary(Box<Expr>, BinaryOp, Box<Expr>),
}

#[derive(Debug, Clone, Copy)]
enum BinaryOp {
  Eq,
  Ne,
  Lt,
  Le,
  Gt,
  Ge,
  And,
  Or,
  Add,
}

impl Expr {
  fn validate_for_phase(&self, phase: WafPhase) -> anyhow::Result<()> {
    if phase == WafPhase::Request && self.references_ident("Response") {
      bail!("Response is unavailable in request-phase rules");
    }
    Ok(())
  }

  fn references_ident(&self, name: &str) -> bool {
    match self {
      Self::Ident(ident) => ident == name,
      Self::Member(receiver, _) | Self::UnaryNot(receiver) => receiver.references_ident(name),
      Self::Call(receiver, _, args) => {
        receiver.references_ident(name) || args.iter().any(|arg| arg.references_ident(name))
      }
      Self::Binary(left, _, right) => left.references_ident(name) || right.references_ident(name),
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) => false,
    }
  }

  fn requires_request_body_inspection(&self) -> bool {
    match self {
      Self::Member(receiver, field) => {
        receiver.requires_request_body_inspection()
          || (matches!(field.as_str(), "Bytes" | "IsTruncated") && receiver.is_request_body_expr())
      }
      Self::Call(receiver, method, args) => {
        receiver.requires_request_body_inspection()
          || args.iter().any(Self::requires_request_body_inspection)
          || (receiver.is_request_body_expr() && body_content_method(method))
          || (receiver.is_request_body_bytes_expr() && bytes_content_method(method))
      }
      Self::UnaryNot(expr) => expr.requires_request_body_inspection(),
      Self::Binary(left, _, right) => {
        left.requires_request_body_inspection() || right.requires_request_body_inspection()
      }
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) | Self::Ident(_) => false,
    }
  }

  fn is_request_body_expr(&self) -> bool {
    match self {
      Self::Member(receiver, field) if field == "Body" => {
        receiver.is_request_expr() || receiver.is_request_http_expr()
      }
      _ => false,
    }
  }

  fn is_request_body_bytes_expr(&self) -> bool {
    matches!(self, Self::Member(receiver, field) if field == "Bytes" && receiver.is_request_body_expr())
  }

  fn is_request_expr(&self) -> bool {
    matches!(self, Self::Ident(name) if name == "Request")
  }

  fn is_request_http_expr(&self) -> bool {
    matches!(self, Self::Member(receiver, field) if field == "Http" && receiver.is_request_expr())
  }

  fn eval(&self, ctx: &EvalContext<'_>, tx: &mut TransactionBudget) -> anyhow::Result<Value> {
    tx.step()?;
    match self {
      Self::Bool(value) => Ok(Value::Bool(*value)),
      Self::Null => Ok(Value::Null),
      Self::Int(value) => Ok(Value::Int(*value)),
      Self::String(value) => Ok(Value::String(value.clone())),
      Self::Ident(name) => eval_ident(name, ctx),
      Self::Member(receiver, field) => {
        let value = receiver.eval(ctx, tx)?;
        eval_member(value, field, ctx)
      }
      Self::Call(receiver, method, args) => {
        let value = receiver.eval(ctx, tx)?;
        let values = args
          .iter()
          .map(|arg| arg.eval(ctx, tx))
          .collect::<anyhow::Result<Vec<_>>>()?;
        eval_call(value, method, &values, ctx, tx)
      }
      Self::UnaryNot(expr) => Ok(Value::Bool(!expr.eval(ctx, tx)?.as_bool()?)),
      Self::Binary(left, op, right) => eval_binary(left, *op, right, ctx, tx),
    }
  }
}

#[derive(Debug, Clone)]
enum Value {
  Bool(bool),
  Int(i64),
  String(String),
  Bytes(Vec<u8>),
  StringList(BoundedStringList),
  Null,
  Object(ObjectRef),
}

#[derive(Debug, Clone)]
struct BoundedStringList {
  values: Vec<String>,
  is_truncated: bool,
}

impl Value {
  fn as_bool(&self) -> anyhow::Result<bool> {
    match self {
      Self::Bool(value) => Ok(*value),
      _ => bail!("expected Bool, got {:?}", self),
    }
  }

  fn as_string(&self) -> anyhow::Result<&str> {
    match self {
      Self::String(value) => Ok(value),
      _ => bail!("expected String, got {:?}", self),
    }
  }

  fn is_null(&self) -> bool {
    matches!(self, Self::Null)
  }
}

#[derive(Debug, Clone, Copy)]
enum ObjectRef {
  Context,
  ContextRuleTags,
  Request,
  RequestClient,
  RequestClientPersonProof,
  RequestClientAgent,
  RequestClientBot,
  RequestTransport,
  RequestTransportTcp,
  RequestTransportUdp,
  RequestHttp,
  RequestHeaders,
  RequestQueryParams,
  RequestCookies,
  RequestBody,
  RequestTags,
  RequestTls,
  RequestTokenBindings,
  Response,
  ResponseHttp,
  ResponseHeaders,
  ResponseCookies,
  ResponseBody,
  ResponseTags,
  ResponseTls,
  ResponseTransport,
  ResponseUpstream,
  ResponseUpstreamError,
}

fn eval_ident(name: &str, ctx: &EvalContext<'_>) -> anyhow::Result<Value> {
  match name {
    "Context" => Ok(Value::Object(ObjectRef::Context)),
    "Request" => Ok(Value::Object(ObjectRef::Request)),
    "Response" if ctx.phase == WafPhase::Response => Ok(Value::Object(ObjectRef::Response)),
    "Response" => bail!("Response is unavailable in request phase"),
    _ => bail!("unknown identifier {name}"),
  }
}

fn eval_member(value: Value, field: &str, ctx: &EvalContext<'_>) -> anyhow::Result<Value> {
  if let Value::StringList(list) = value {
    return eval_string_list_member(list, field);
  }

  let object = match value {
    Value::Object(object) => object,
    Value::Null => bail!("attempted to access {field} on null"),
    _ => bail!("cannot access member {field} on {:?}", value),
  };

  match (object, field) {
    (ObjectRef::Context, "Phase") => Ok(Value::String(ctx.phase.as_str().to_string())),
    (ObjectRef::Context, "RuleName") => Ok(Value::String(ctx.rule_name.to_string())),
    (ObjectRef::Context, "RuleId") => Ok(
      ctx
        .rule_id
        .map(|id| Value::String(id.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::Context, "RuleTags") => Ok(Value::Object(ObjectRef::ContextRuleTags)),
    (ObjectRef::Context, "RouteName") => Ok(if ctx.request.route_name.is_empty() {
      Value::Null
    } else {
      Value::String(ctx.request.route_name.to_string())
    }),
    (ObjectRef::Context, "TransactionId") => {
      Ok(Value::String(ctx.request.transaction_id.to_string()))
    }
    (ObjectRef::Context, "Mode") => Ok(Value::String(ctx.mode.as_str().to_string())),
    (ObjectRef::Request, "Id") => Ok(Value::String(ctx.request.request_id.to_string())),
    (ObjectRef::Request, "ReceivedAtUnixMs") => Ok(Value::Int(
      i64::try_from(ctx.request.received_at_unix_ms).unwrap_or(i64::MAX),
    )),
    (ObjectRef::Request, "Protocol") => {
      Ok(Value::String(ctx.request.protocol.as_str().to_string()))
    }
    (ObjectRef::Request, "Client") => Ok(Value::Object(ObjectRef::RequestClient)),
    (ObjectRef::Request, "Transport") => Ok(Value::Object(ObjectRef::RequestTransport)),
    (ObjectRef::Request, "Http") => Ok(Value::Object(ObjectRef::RequestHttp)),
    (ObjectRef::Request, "Headers") => Ok(Value::Object(ObjectRef::RequestHeaders)),
    (ObjectRef::Request, "QueryParams") => Ok(Value::Object(ObjectRef::RequestQueryParams)),
    (ObjectRef::Request, "Cookies") => Ok(Value::Object(ObjectRef::RequestCookies)),
    (ObjectRef::Request, "Body") => Ok(Value::Object(ObjectRef::RequestBody)),
    (ObjectRef::Request, "Tags") => Ok(Value::Object(ObjectRef::RequestTags)),
    (ObjectRef::Request, "Tls") => Ok(Value::Object(ObjectRef::RequestTls)),
    (ObjectRef::Request, "TokenBindings") => Ok(Value::Object(ObjectRef::RequestTokenBindings)),
    (ObjectRef::RequestClient, "Kind") => Ok(Value::String(
      if ctx.person_proof.state == PersonProofState::Valid {
        "person"
      } else {
        "unknown"
      }
      .to_string(),
    )),
    (ObjectRef::RequestClient, "Ip") => Ok(Value::String(ctx.request.peer_addr.ip().to_string())),
    (ObjectRef::RequestClient, "Port") => Ok(Value::Int(ctx.request.peer_addr.port().into())),
    (ObjectRef::RequestClient, "SourceAddress") => {
      Ok(Value::String(ctx.request.peer_addr.to_string()))
    }
    (ObjectRef::RequestClient, "UserAgent") => header_single(ctx.request.headers, USER_AGENT, ctx),
    (ObjectRef::RequestClient, "PersonProof") => {
      Ok(Value::Object(ObjectRef::RequestClientPersonProof))
    }
    (ObjectRef::RequestClient, "Agent") => Ok(Value::Object(ObjectRef::RequestClientAgent)),
    (ObjectRef::RequestClient, "Bot") => Ok(Value::Object(ObjectRef::RequestClientBot)),
    (ObjectRef::RequestClient, "GeoCountry") | (ObjectRef::RequestClient, "Asn") => Ok(Value::Null),
    (ObjectRef::RequestClientPersonProof, "State") => {
      Ok(Value::String(ctx.person_proof.state.as_str().to_string()))
    }
    (ObjectRef::RequestClientPersonProof, "Method") => Ok(
      ctx
        .person_proof
        .method
        .map(|method| Value::String(method.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientPersonProof, "Difficulty") => Ok(
      ctx
        .person_proof
        .difficulty
        .map(|difficulty| Value::Int(difficulty.into()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientPersonProof, "IssuedAtUnixMs") => Ok(
      ctx
        .person_proof
        .issued_at_unix_ms
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientPersonProof, "ExpiresAtUnixMs") => Ok(
      ctx
        .person_proof
        .expires_at_unix_ms
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientAgent, "Verified") => Ok(Value::Bool(false)),
    (ObjectRef::RequestClientAgent, "Kind")
    | (ObjectRef::RequestClientAgent, "Provider")
    | (ObjectRef::RequestClientAgent, "Model")
    | (ObjectRef::RequestClientAgent, "AuthMethod") => Ok(Value::Null),
    (ObjectRef::RequestClientBot, "Disposition") => Ok(Value::String("unknown".to_string())),
    (ObjectRef::RequestClientBot, "Malicious") => Ok(Value::Null),
    (ObjectRef::RequestClientBot, "Score") => Ok(Value::Int(0)),
    (ObjectRef::RequestClientBot, "Reason") => Ok(Value::Null),
    (ObjectRef::RequestTransport, "Network") => Ok(Value::String(
      ctx.request.transport_network.as_str().to_string(),
    )),
    (ObjectRef::RequestTransport, "RemoteIp") => {
      Ok(Value::String(ctx.request.peer_addr.ip().to_string()))
    }
    (ObjectRef::RequestTransport, "RemotePort") => {
      Ok(Value::Int(ctx.request.peer_addr.port().into()))
    }
    (ObjectRef::RequestTransport, "IsEncrypted") => Ok(Value::Bool(true)),
    (ObjectRef::RequestTransport, "Tcp") => {
      if ctx.request.transport_network == WafTransportNetwork::Tcp {
        Ok(Value::Object(ObjectRef::RequestTransportTcp))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::RequestTransport, "Udp") => {
      if ctx.request.transport_network == WafTransportNetwork::Udp {
        Ok(Value::Object(ObjectRef::RequestTransportUdp))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::RequestTransportTcp, "State") => Ok(Value::String("accepted".to_string())),
    (ObjectRef::RequestTransportTcp, "TlsDetected") => Ok(Value::Bool(true)),
    (ObjectRef::RequestTransportTcp, "MaxHop") => Ok(
      ctx
        .request
        .tcp_max_hop
        .map(|max_hop| Value::Int(i64::from(max_hop)))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportTcp, "Sni") => Ok(
      ctx
        .request
        .tls
        .sni
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportTcp, "Alpn") => Ok(
      ctx
        .request
        .tls
        .alpn
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportTcp, "Mss") | (ObjectRef::RequestTransportTcp, "RttMs") => {
      Ok(Value::Null)
    }
    (ObjectRef::RequestTransportUdp, "DatagramSize")
    | (ObjectRef::RequestTransportUdp, "FlowId")
    | (ObjectRef::RequestTransportUdp, "ConnectionId") => Ok(Value::Null),
    (ObjectRef::RequestTransportUdp, "QuicDetected") => Ok(Value::Bool(true)),
    (ObjectRef::RequestHttp, "Version") => Ok(Value::String(version_string(ctx.request.version))),
    (ObjectRef::RequestHttp, "Method") => {
      Ok(Value::String(ctx.request.method.as_str().to_string()))
    }
    (ObjectRef::RequestHttp, "Scheme") => {
      Ok(Value::String(ctx.request.downstream_scheme.to_string()))
    }
    (ObjectRef::RequestHttp, "Host") => Ok(Value::String(ctx.request.downstream_host.to_string())),
    (ObjectRef::RequestHttp, "Path") => Ok(Value::String(ctx.request.uri.path().to_string())),
    (ObjectRef::RequestHttp, "Query") => Ok(Value::String(
      ctx.request.uri.query().unwrap_or_default().to_string(),
    )),
    (ObjectRef::RequestHttp, "Uri") => Ok(Value::String(ctx.request.uri.to_string())),
    (ObjectRef::RequestHttp, "Body") => Ok(Value::Object(ObjectRef::RequestBody)),
    (ObjectRef::RequestBody, "Size") => {
      Ok(Value::Int(body_size(ctx.request.headers, ctx.request.body)))
    }
    (ObjectRef::RequestBody, "IsTruncated") => Ok(Value::Bool(
      ctx
        .request
        .body
        .map(|body| body.is_truncated)
        .unwrap_or(false),
    )),
    (ObjectRef::RequestBody, "Bytes") => Ok(
      ctx
        .request
        .body
        .map(|body| Value::Bytes(body.bytes.to_vec()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestBody, "Text") => Ok(Value::Null),
    (ObjectRef::RequestTls, "Enabled") => Ok(Value::Bool(ctx.request.tls.enabled)),
    (ObjectRef::RequestTls, "Version") => Ok(
      ctx
        .request
        .tls
        .version
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTls, "CipherSuite") => Ok(
      ctx
        .request
        .tls
        .cipher_suite
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTls, "Sni") => Ok(
      ctx
        .request
        .tls
        .sni
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTls, "Alpn") => Ok(
      ctx
        .request
        .tls
        .alpn
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTls, "Fingerprint") => Ok(
      ctx
        .request
        .tls
        .fingerprint
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTls, "FingerprintScheme") => Ok(
      ctx
        .request
        .tls
        .fingerprint_scheme
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTls, "ClientCertificatePresent") => Ok(Value::Bool(false)),
    (ObjectRef::RequestTokenBindings, "UserAgent") => Ok(Value::String(
      request_token_binding_value(ctx.request, PersonProofTokenBinding::UserAgent),
    )),
    (ObjectRef::RequestTokenBindings, "TlsFingerprint") => Ok(Value::String(
      request_token_binding_value(ctx.request, PersonProofTokenBinding::TlsFingerprint),
    )),
    (ObjectRef::RequestTokenBindings, "Route") => Ok(Value::String(request_token_binding_value(
      ctx.request,
      PersonProofTokenBinding::Route,
    ))),
    (ObjectRef::RequestTokenBindings, "DirectPeerIpNetworkPrefix") => {
      Ok(Value::String(request_token_binding_value(
        ctx.request,
        PersonProofTokenBinding::DirectPeerIpNetworkPrefix,
      )))
    }
    (ObjectRef::RequestTokenBindings, "TcpMaxHop") => Ok(Value::String(
      request_token_binding_value(ctx.request, PersonProofTokenBinding::TcpMaxHop),
    )),
    (ObjectRef::Response, "Id") => Ok(Value::String(
      ctx
        .response
        .context("missing response context")?
        .response_id
        .to_string(),
    )),
    (ObjectRef::Response, "ReceivedAtUnixMs") => Ok(Value::Int(
      i64::try_from(
        ctx
          .response
          .context("missing response context")?
          .received_at_unix_ms,
      )
      .unwrap_or(i64::MAX),
    )),
    (ObjectRef::Response, "Protocol") => Ok(Value::String(
      ctx
        .response
        .context("missing response context")?
        .request
        .protocol
        .as_str()
        .to_string(),
    )),
    (ObjectRef::Response, "Http") => Ok(Value::Object(ObjectRef::ResponseHttp)),
    (ObjectRef::Response, "Headers") => Ok(Value::Object(ObjectRef::ResponseHeaders)),
    (ObjectRef::Response, "Cookies") => Ok(Value::Object(ObjectRef::ResponseCookies)),
    (ObjectRef::Response, "Body") => Ok(Value::Object(ObjectRef::ResponseBody)),
    (ObjectRef::Response, "Tags") => Ok(Value::Object(ObjectRef::ResponseTags)),
    (ObjectRef::Response, "Tls") => Ok(Value::Object(ObjectRef::ResponseTls)),
    (ObjectRef::Response, "Transport") => Ok(Value::Object(ObjectRef::ResponseTransport)),
    (ObjectRef::Response, "Upstream") => Ok(Value::Object(ObjectRef::ResponseUpstream)),
    (ObjectRef::ResponseHttp, "Version") => Ok(Value::String(version_string(
      ctx.response.context("missing response context")?.version,
    ))),
    (ObjectRef::ResponseHttp, "Status") => Ok(Value::Int(
      ctx
        .response
        .context("missing response context")?
        .status
        .as_u16()
        .into(),
    )),
    (ObjectRef::ResponseHttp, "Reason") => Ok(
      ctx
        .response
        .context("missing response context")?
        .status
        .canonical_reason()
        .map(|reason| Value::String(reason.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseHttp, "Body") => Ok(Value::Object(ObjectRef::ResponseBody)),
    (ObjectRef::ResponseBody, "Size") => Ok(Value::Int(content_length(
      ctx.response.context("missing response context")?.headers,
    ))),
    (ObjectRef::ResponseBody, "IsTruncated") => Ok(Value::Bool(false)),
    (ObjectRef::ResponseBody, "Text") | (ObjectRef::ResponseBody, "Bytes") => Ok(Value::Null),
    (ObjectRef::ResponseUpstream, "Name") => {
      let upstream_name = ctx
        .response
        .context("missing response context")?
        .upstream_name;
      Ok(if upstream_name.is_empty() {
        Value::Null
      } else {
        Value::String(upstream_name.to_string())
      })
    }
    (ObjectRef::ResponseUpstream, "Pool") => Ok(
      ctx
        .response
        .context("missing response context")?
        .upstream_pool
        .map(|pool| Value::String(pool.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseUpstream, "Scheme") => {
      let upstream_scheme = ctx
        .response
        .context("missing response context")?
        .upstream_scheme;
      Ok(if upstream_scheme.is_empty() {
        Value::Null
      } else {
        Value::String(upstream_scheme.to_string())
      })
    }
    (ObjectRef::ResponseUpstream, "ConnectTimeMs") => Ok(
      ctx
        .response
        .context("missing response context")?
        .upstream_connect_time_ms
        .and_then(|value| i64::try_from(value).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseUpstream, "FirstByteTimeMs") => Ok(
      ctx
        .response
        .context("missing response context")?
        .upstream_first_byte_time_ms
        .and_then(|value| i64::try_from(value).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseUpstream, "Error") => {
      if ctx
        .response
        .context("missing response context")?
        .upstream_error
        .is_some()
      {
        Ok(Value::Object(ObjectRef::ResponseUpstreamError))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::ResponseUpstreamError, "Code") => Ok(Value::String(
      ctx
        .response
        .context("missing response context")?
        .upstream_error
        .context("missing upstream error")?
        .code
        .to_string(),
    )),
    (ObjectRef::ResponseUpstreamError, "Message") => Ok(Value::String(
      ctx
        .response
        .context("missing response context")?
        .upstream_error
        .context("missing upstream error")?
        .message
        .chars()
        .take(ctx.limits.max_helper_result_bytes)
        .collect(),
    )),
    (ObjectRef::ResponseTls, "Enabled") => Ok(Value::Bool(false)),
    (ObjectRef::ResponseTls, "Version")
    | (ObjectRef::ResponseTls, "CipherSuite")
    | (ObjectRef::ResponseTls, "Sni")
    | (ObjectRef::ResponseTls, "Alpn")
    | (ObjectRef::ResponseTls, "Fingerprint")
    | (ObjectRef::ResponseTls, "FingerprintScheme") => Ok(Value::Null),
    (ObjectRef::ResponseTls, "ClientCertificatePresent") => Ok(Value::Bool(false)),
    (ObjectRef::ResponseTransport, "Network") => Ok(Value::String("tcp".to_string())),
    (ObjectRef::ResponseTransport, "IsEncrypted") => Ok(Value::Bool(false)),
    (ObjectRef::ResponseTags, _) => Ok(Value::Null),
    _ => bail!("unknown WAF object property {:?}.{field}", object),
  }
}

fn eval_call(
  value: Value,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
  tx: &mut TransactionBudget,
) -> anyhow::Result<Value> {
  match value {
    Value::String(text) => eval_string_call(&text, method, args, ctx, tx),
    Value::Bytes(bytes) => eval_bytes_call(&bytes, method, args),
    Value::StringList(list) => eval_string_list_call(&list, method, args, ctx),
    Value::Object(ObjectRef::ContextRuleTags) => eval_rule_tag_call(ctx.rule_tags, method, args),
    Value::Object(ObjectRef::RequestHeaders) => {
      eval_header_call(ctx.request.headers, method, args, ctx)
    }
    Value::Object(ObjectRef::ResponseHeaders) => eval_header_call(
      ctx.response.context("missing response context")?.headers,
      method,
      args,
      ctx,
    ),
    Value::Object(ObjectRef::RequestQueryParams) => eval_query_call(ctx, method, args),
    Value::Object(ObjectRef::RequestCookies) => eval_cookie_call(ctx, method, args),
    Value::Object(ObjectRef::RequestTags) => eval_tag_call(ctx.request.tags, method, args, ctx),
    Value::Object(ObjectRef::RequestTokenBindings) => eval_token_binding_call(ctx, method, args),
    Value::Object(ObjectRef::RequestBody) => eval_body_call(ctx.request.body, method, args),
    Value::Object(ObjectRef::ResponseBody) => eval_body_call(None, method, args),
    _ => bail!("method {method} is not available on {:?}", value),
  }
}

fn eval_string_call(
  text: &str,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
  _tx: &mut TransactionBudget,
) -> anyhow::Result<Value> {
  match method {
    "contains" => Ok(Value::Bool(text.contains(expect_string_arg(args, 0)?))),
    "startsWith" => Ok(Value::Bool(text.starts_with(expect_string_arg(args, 0)?))),
    "endsWith" => Ok(Value::Bool(text.ends_with(expect_string_arg(args, 0)?))),
    "matches" => {
      let regex = Regex::new(expect_string_arg(args, 0)?)?;
      Ok(Value::Bool(regex.is_match(text)))
    }
    "lowerAscii" => Ok(Value::String(text.to_ascii_lowercase())),
    "upperAscii" => Ok(Value::String(text.to_ascii_uppercase())),
    "size" => Ok(Value::Int(text.len() as i64)),
    "inCidr" => Ok(Value::Bool(ip_in_cidr(text, expect_string_arg(args, 0)?)?)),
    "containsAny" => Ok(Value::Bool(pattern_set_matches(
      ctx.pattern_sets,
      expect_string_arg(args, 0)?,
      text,
    )?)),
    "matchesAny" => Ok(Value::Bool(pattern_set_matches(
      ctx.pattern_sets,
      expect_string_arg(args, 0)?,
      text,
    )?)),
    _ => bail!("unknown String method {method}"),
  }
}

fn eval_bytes_call(bytes: &[u8], method: &str, args: &[Value]) -> anyhow::Result<Value> {
  match method {
    "size" => Ok(Value::Int(bytes.len() as i64)),
    "isFormat" | "isBinaryFormat" | "matchesFormat" => Ok(Value::Bool(bytes_match_format(
      bytes,
      expect_string_arg(args, 0)?,
    ))),
    _ => bail!("unknown Bytes method {method}"),
  }
}

fn eval_header_call(
  headers: &HeaderMap,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(headers.len() as i64)),
    "has" => Ok(Value::Bool(
      header_name(expect_string_arg(args, 0)?)
        .map(|name| headers.contains_key(name))
        .unwrap_or(false),
    )),
    "get" => Ok(header_single(
      headers,
      header_name(expect_string_arg(args, 0)?)?,
      ctx,
    )?),
    "getAll" => Ok(Value::StringList(bounded_string_list(
      headers
        .get_all(header_name(expect_string_arg(args, 0)?)?)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| truncate_to_bytes(value, ctx.limits.max_header_value_bytes)),
      ctx.limits,
    ))),
    "anyNameMatches" => {
      let regex = header_name_regex(expect_string_arg(args, 0)?)?;
      Ok(Value::Bool(
        headers
          .keys()
          .take(ctx.limits.max_helper_items)
          .any(|name| regex.is_match(name.as_str())),
      ))
    }
    "anyValueContains" => {
      let needle = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        headers
          .values()
          .take(ctx.limits.max_helper_items)
          .filter_map(|value| value.to_str().ok())
          .any(|value| value.contains(needle)),
      ))
    }
    "anyValueMatches" => {
      let regex = Regex::new(expect_string_arg(args, 0)?)?;
      Ok(Value::Bool(
        headers
          .values()
          .take(ctx.limits.max_helper_items)
          .filter_map(|value| value.to_str().ok())
          .any(|value| regex.is_match(value)),
      ))
    }
    "anyEntryMatches" => {
      let name_regex = header_name_regex(expect_string_arg(args, 0)?)?;
      let value_regex = Regex::new(expect_string_arg(args, 1)?)?;
      Ok(Value::Bool(
        headers
          .iter()
          .take(ctx.limits.max_helper_items)
          .filter_map(|(name, value)| value.to_str().ok().map(|value| (name, value)))
          .any(|(name, value)| name_regex.is_match(name.as_str()) && value_regex.is_match(value)),
      ))
    }
    "allEntriesMatch" => {
      let name_regex = header_name_regex(expect_string_arg(args, 0)?)?;
      let value_regex = Regex::new(expect_string_arg(args, 1)?)?;
      Ok(Value::Bool(
        headers
          .iter()
          .take(ctx.limits.max_helper_items)
          .filter_map(|(name, value)| value.to_str().ok().map(|value| (name, value)))
          .all(|(name, value)| name_regex.is_match(name.as_str()) && value_regex.is_match(value)),
      ))
    }
    _ => bail!("unknown HeaderMap method {method}"),
  }
}

fn header_name_regex(pattern: &str) -> anyhow::Result<Regex> {
  Ok(RegexBuilder::new(pattern).case_insensitive(true).build()?)
}

fn eval_query_call(ctx: &EvalContext<'_>, method: &str, args: &[Value]) -> anyhow::Result<Value> {
  let query = ctx.request.uri.query().unwrap_or_default();
  let pairs = url::form_urlencoded::parse(query.as_bytes())
    .take(ctx.limits.max_helper_items)
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect::<Vec<_>>();
  eval_pair_map_call(&pairs, method, args, ctx)
}

fn eval_cookie_call(ctx: &EvalContext<'_>, method: &str, args: &[Value]) -> anyhow::Result<Value> {
  let pairs = ctx
    .request
    .headers
    .get_all(COOKIE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(';'))
    .filter_map(|part| part.trim().split_once('='))
    .take(ctx.limits.max_helper_items)
    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
    .collect::<Vec<_>>();
  eval_pair_map_call(&pairs, method, args, ctx)
}

fn eval_tag_call(
  tags: &HashMap<String, String>,
  method: &str,
  args: &[Value],
  _ctx: &EvalContext<'_>,
) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(tags.len() as i64)),
    "has" => Ok(Value::Bool(tags.contains_key(expect_string_arg(args, 0)?))),
    "get" => Ok(
      tags
        .get(expect_string_arg(args, 0)?)
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    "anyKeyMatches" => {
      let regex = Regex::new(expect_string_arg(args, 0)?)?;
      Ok(Value::Bool(tags.keys().any(|key| regex.is_match(key))))
    }
    "anyValueContains" => {
      let needle = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        tags.values().any(|value| value.contains(needle)),
      ))
    }
    "anyEntryMatches" => {
      let key_regex = Regex::new(expect_string_arg(args, 0)?)?;
      let value_regex = Regex::new(expect_string_arg(args, 1)?)?;
      Ok(Value::Bool(tags.iter().any(|(key, value)| {
        key_regex.is_match(key) && value_regex.is_match(value)
      })))
    }
    _ => bail!("unknown TagMap method {method}"),
  }
}

fn eval_rule_tag_call(tags: &[String], method: &str, args: &[Value]) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(tags.len() as i64)),
    "has" => {
      let expected = expect_string_arg(args, 0)?;
      Ok(Value::Bool(tags.iter().any(|tag| tag == expected)))
    }
    "anyMatches" => {
      let regex = Regex::new(expect_string_arg(args, 0)?)?;
      Ok(Value::Bool(tags.iter().any(|tag| regex.is_match(tag))))
    }
    _ => bail!("unknown RuleTagSet method {method}"),
  }
}

fn eval_string_list_member(list: BoundedStringList, field: &str) -> anyhow::Result<Value> {
  match field {
    "Count" => Ok(Value::Int(list.values.len() as i64)),
    "IsTruncated" => Ok(Value::Bool(list.is_truncated)),
    "First" => Ok(
      list
        .values
        .first()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    _ => bail!("unknown BoundedStringList property {field}"),
  }
}

fn eval_string_list_call(
  list: &BoundedStringList,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
) -> anyhow::Result<Value> {
  match method {
    "contains" => {
      let expected = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        list.values.iter().any(|value| value == expected),
      ))
    }
    "containsAny" => {
      let pattern_set = expect_string_arg(args, 0)?;
      for value in &list.values {
        if pattern_set_matches(ctx.pattern_sets, pattern_set, value)? {
          return Ok(Value::Bool(true));
        }
      }
      Ok(Value::Bool(false))
    }
    "matchesAny" => {
      let pattern_set = expect_string_arg(args, 0)?;
      for value in &list.values {
        if pattern_set_matches(ctx.pattern_sets, pattern_set, value)? {
          return Ok(Value::Bool(true));
        }
      }
      Ok(Value::Bool(false))
    }
    _ => bail!("unknown BoundedStringList method {method}"),
  }
}

fn eval_token_binding_call(
  ctx: &EvalContext<'_>,
  method: &str,
  args: &[Value],
) -> anyhow::Result<Value> {
  match method {
    "directPeerIpNetworkPrefix" => {
      let ipv4_prefix_bits = expect_u8_arg(args, 0, 32, "IPv4 prefix bits")?;
      let ipv6_prefix_bits = expect_u8_arg(args, 1, 128, "IPv6 prefix bits")?;
      Ok(Value::String(person_proof::direct_peer_ip_network_prefix(
        ctx.request.peer_addr.ip(),
        ipv4_prefix_bits,
        ipv6_prefix_bits,
      )))
    }
    "tcpMaxHop" => {
      let configured = expect_u8_arg(args, 0, 255, "configured TCP max-hop")?;
      Ok(Value::String(person_proof::tcp_max_hop_binding_value(
        Some(configured),
        ctx.request.tcp_max_hop,
      )))
    }
    _ => bail!("unknown PersonProofTokenBindings method {method}"),
  }
}

fn request_token_binding_value(
  input: WafRequestInput<'_>,
  binding: PersonProofTokenBinding,
) -> String {
  match binding {
    PersonProofTokenBinding::UserAgent => input
      .headers
      .get(USER_AGENT)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default()
      .to_string(),
    PersonProofTokenBinding::TlsFingerprint => input
      .tls
      .fingerprint
      .as_deref()
      .unwrap_or("unavailable")
      .to_string(),
    PersonProofTokenBinding::Route => input.route_name.to_string(),
    PersonProofTokenBinding::DirectPeerIpNetworkPrefix => {
      person_proof::direct_peer_ip_network_prefix(
        input.peer_addr.ip(),
        default_person_proof_direct_peer_ipv4_prefix_bits(),
        default_person_proof_direct_peer_ipv6_prefix_bits(),
      )
    }
    PersonProofTokenBinding::TcpMaxHop => {
      person_proof::tcp_max_hop_binding_value(None, input.tcp_max_hop)
    }
  }
}

fn eval_pair_map_call(
  pairs: &[(String, String)],
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(pairs.len() as i64)),
    "has" => {
      let name = expect_string_arg(args, 0)?;
      Ok(Value::Bool(pairs.iter().any(|(key, _)| key == name)))
    }
    "get" => {
      let name = expect_string_arg(args, 0)?;
      single_pair_value(pairs, name, ctx.duplicate_metadata_policy)
    }
    "getAll" => {
      let name = expect_string_arg(args, 0)?;
      Ok(Value::StringList(bounded_string_list(
        pairs
          .iter()
          .filter(|(key, _)| key == name)
          .map(|(_, value)| value.clone()),
        ctx.limits,
      )))
    }
    "anyNameMatches" => {
      let regex = Regex::new(expect_string_arg(args, 0)?)?;
      Ok(Value::Bool(
        pairs.iter().any(|(key, _)| regex.is_match(key)),
      ))
    }
    "anyValueContains" => {
      let needle = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        pairs.iter().any(|(_, value)| value.contains(needle)),
      ))
    }
    "anyValueMatches" => {
      let regex = Regex::new(expect_string_arg(args, 0)?)?;
      Ok(Value::Bool(
        pairs.iter().any(|(_, value)| regex.is_match(value)),
      ))
    }
    "anyEntryMatches" => {
      let key_regex = Regex::new(expect_string_arg(args, 0)?)?;
      let value_regex = Regex::new(expect_string_arg(args, 1)?)?;
      Ok(Value::Bool(pairs.iter().any(|(key, value)| {
        key_regex.is_match(key) && value_regex.is_match(value)
      })))
    }
    _ => bail!("unknown bounded map method {method}"),
  }
}

fn eval_body_call(
  body: Option<WafBodyInput<'_>>,
  method: &str,
  args: &[Value],
) -> anyhow::Result<Value> {
  match method {
    "isFormat" | "isBinaryFormat" | "matchesFormat" => {
      let format = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        body
          .map(|body| bytes_match_format(body.bytes, format))
          .unwrap_or(false),
      ))
    }
    "contains" | "matches" | "containsAny" | "matchesAny" | "scan" => bail!(
      "body content inspection is reserved for a streaming-safe WAF body buffer implementation"
    ),
    _ => bail!("unknown BodyView method {method}"),
  }
}

fn body_content_method(method: &str) -> bool {
  matches!(method, "isFormat" | "isBinaryFormat" | "matchesFormat")
}

fn bytes_content_method(method: &str) -> bool {
  matches!(
    method,
    "isFormat" | "isBinaryFormat" | "matchesFormat" | "size"
  )
}

fn eval_binary(
  left: &Expr,
  op: BinaryOp,
  right: &Expr,
  ctx: &EvalContext<'_>,
  tx: &mut TransactionBudget,
) -> anyhow::Result<Value> {
  match op {
    BinaryOp::And => {
      let left_value = left.eval(ctx, tx)?.as_bool()?;
      if !left_value {
        return Ok(Value::Bool(false));
      }
      Ok(Value::Bool(right.eval(ctx, tx)?.as_bool()?))
    }
    BinaryOp::Or => {
      let left_value = left.eval(ctx, tx)?.as_bool()?;
      if left_value {
        return Ok(Value::Bool(true));
      }
      Ok(Value::Bool(right.eval(ctx, tx)?.as_bool()?))
    }
    BinaryOp::Add => {
      let left_value = left.eval(ctx, tx)?;
      let right_value = right.eval(ctx, tx)?;
      Ok(Value::String(format!(
        "{}{}",
        left_value.as_string()?,
        right_value.as_string()?
      )))
    }
    BinaryOp::Eq | BinaryOp::Ne => {
      let left_value = left.eval(ctx, tx)?;
      let right_value = right.eval(ctx, tx)?;
      let equal = values_equal(&left_value, &right_value)?;
      Ok(Value::Bool(matches!(op, BinaryOp::Eq) == equal))
    }
    BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
      let left_value = left.eval(ctx, tx)?;
      let right_value = right.eval(ctx, tx)?;
      let result = match (&left_value, &right_value) {
        (Value::Int(left), Value::Int(right)) => match op {
          BinaryOp::Lt => left < right,
          BinaryOp::Le => left <= right,
          BinaryOp::Gt => left > right,
          BinaryOp::Ge => left >= right,
          _ => unreachable!(),
        },
        (Value::String(left), Value::String(right)) => match op {
          BinaryOp::Lt => left < right,
          BinaryOp::Le => left <= right,
          BinaryOp::Gt => left > right,
          BinaryOp::Ge => left >= right,
          _ => unreachable!(),
        },
        _ => bail!("ordered comparison requires matching Int or String values"),
      };
      Ok(Value::Bool(result))
    }
  }
}

fn values_equal(left: &Value, right: &Value) -> anyhow::Result<bool> {
  match (left, right) {
    (Value::Bool(left), Value::Bool(right)) => Ok(left == right),
    (Value::Int(left), Value::Int(right)) => Ok(left == right),
    (Value::String(left), Value::String(right)) => Ok(left == right),
    (Value::Bytes(left), Value::Bytes(right)) => Ok(left == right),
    (Value::StringList(left), Value::StringList(right)) => {
      Ok(left.values == right.values && left.is_truncated == right.is_truncated)
    }
    (Value::Null, Value::Null) => Ok(true),
    (Value::Null, other) | (other, Value::Null) => Ok(other.is_null()),
    (Value::Object(_), Value::Object(_)) => Ok(true),
    _ => Ok(false),
  }
}

fn expect_string_arg(args: &[Value], index: usize) -> anyhow::Result<&str> {
  args
    .get(index)
    .ok_or_else(|| anyhow!("missing string argument {index}"))?
    .as_string()
}

fn expect_int_arg(args: &[Value], index: usize) -> anyhow::Result<i64> {
  match args
    .get(index)
    .ok_or_else(|| anyhow!("missing integer argument {index}"))?
  {
    Value::Int(value) => Ok(*value),
    value => bail!("expected Int argument {index}, got {:?}", value),
  }
}

fn expect_u8_arg(args: &[Value], index: usize, max: i64, label: &str) -> anyhow::Result<u8> {
  let value = expect_int_arg(args, index)?;
  if !(0..=max).contains(&value) {
    bail!("{label} must be between 0 and {max}");
  }
  Ok(value as u8)
}

fn header_name(name: &str) -> anyhow::Result<HeaderName> {
  HeaderName::from_bytes(name.as_bytes()).context("invalid header name")
}

fn header_single(
  headers: &HeaderMap,
  name: HeaderName,
  ctx: &EvalContext<'_>,
) -> anyhow::Result<Value> {
  let values = headers
    .get_all(name)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .collect::<Vec<_>>();
  single_string_value(
    values
      .into_iter()
      .map(|value| truncate_to_bytes(value, ctx.limits.max_header_value_bytes)),
    ctx.duplicate_metadata_policy,
  )
}

fn single_pair_value(
  pairs: &[(String, String)],
  name: &str,
  policy: WafDuplicateMetadataPolicy,
) -> anyhow::Result<Value> {
  single_string_value(
    pairs
      .iter()
      .filter(|(key, _)| key == name)
      .map(|(_, value)| value.clone()),
    policy,
  )
}

fn single_string_value<I>(values: I, policy: WafDuplicateMetadataPolicy) -> anyhow::Result<Value>
where
  I: IntoIterator<Item = String>,
{
  let mut values = values.into_iter();
  let Some(first) = values.next() else {
    return Ok(Value::Null);
  };
  if values.next().is_some() {
    return match policy {
      WafDuplicateMetadataPolicy::FailClosed | WafDuplicateMetadataPolicy::RejectRequest => {
        bail!("duplicate request metadata value")
      }
      WafDuplicateMetadataPolicy::NullOnDuplicate => Ok(Value::Null),
    };
  }
  Ok(Value::String(first))
}

fn bounded_string_list<I>(values: I, limits: &WafLimits) -> BoundedStringList
where
  I: IntoIterator<Item = String>,
{
  let mut result = Vec::new();
  let mut total_bytes = 0usize;
  let mut is_truncated = false;
  for value in values {
    if result.len() >= limits.max_helper_items {
      is_truncated = true;
      break;
    }
    let next_total = total_bytes.saturating_add(value.len());
    if next_total > limits.max_helper_result_bytes {
      is_truncated = true;
      break;
    }
    total_bytes = next_total;
    result.push(value);
  }
  BoundedStringList {
    values: result,
    is_truncated,
  }
}

fn truncate_to_bytes(value: &str, max_bytes: usize) -> String {
  if value.len() <= max_bytes {
    return value.to_string();
  }
  let mut end = max_bytes;
  while !value.is_char_boundary(end) {
    end = end.saturating_sub(1);
  }
  value[..end].to_string()
}

fn request_metadata_has_duplicates(input: WafRequestInput<'_>) -> bool {
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

fn content_length(headers: &HeaderMap) -> i64 {
  headers
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<i64>().ok())
    .unwrap_or(0)
}

fn body_size(headers: &HeaderMap, body: Option<WafBodyInput<'_>>) -> i64 {
  let size = content_length(headers);
  if size > 0 {
    size
  } else {
    body.map(|body| body.bytes.len() as i64).unwrap_or(0)
  }
}

fn version_string(version: Version) -> String {
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

fn bytes_match_format(bytes: &[u8], format: &str) -> bool {
  match normalize_binary_format(format).as_str() {
    "7z" | "7zip" | "application/x-7z-compressed" => bytes.starts_with(b"\x37\x7a\xbc\xaf\x27\x1c"),
    "alac" | "audio/alac" => is_alac(bytes),
    "apng" | "image/apng" => is_apng(bytes),
    "av1" | "video/av1" => is_av1(bytes),
    "avif" | "image/avif" => is_isobmff_with_brand(bytes, &[b"avif", b"avis"]),
    "bzip2" | "bz2" | "application/x-bzip2" => bytes.starts_with(b"BZh"),
    "dirac" | "video/dirac" => bytes.starts_with(b"BBCD"),
    "djvu" | "djv" | "image/vnd.djvu" => bytes.starts_with(b"AT&TFORM"),
    "dvi" | "application/x-dvi" => bytes.starts_with(b"\xf7\x02"),
    "elf" | "linux-exe" | "linux-executable" | "application/x-elf" => bytes.starts_with(b"\x7fELF"),
    "epub" | "application/epub+zip" => is_zip_with(bytes, b"application/epub+zip"),
    "exe"
    | "pe"
    | "pe32"
    | "portable-executable"
    | "windows-exe"
    | "windows-executable"
    | "application/x-msdownload"
    | "application/vnd.microsoft.portable-executable" => is_pe_executable(bytes),
    "exr" | "openexr" | "image/x-exr" => bytes.starts_with(b"\x76\x2f\x31\x01"),
    "flac" | "audio/flac" => bytes.starts_with(b"fLaC"),
    "flif" | "image/flif" => bytes.starts_with(b"FLIF"),
    "gbr" | "gimp-brush" | "image/x-gimp-gbr" => is_gbr(bytes),
    "gif" | "image/gif" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
    "glb" | "gltf-binary" | "model/gltf-binary" => bytes.starts_with(b"glTF"),
    "gzip" | "gz" | "application/gzip" | "application/x-gzip" => bytes.starts_with(b"\x1f\x8b\x08"),
    "hdf" | "hdf4" | "application/x-hdf" => {
      bytes.starts_with(b"\x0e\x03\x13\x01") || is_hdf5(bytes)
    }
    "hdf5" | "h5" | "application/x-hdf5" => is_hdf5(bytes),
    "jpeg" | "jpg" | "image/jpeg" => bytes.starts_with(b"\xff\xd8\xff"),
    "jpeg-2000" | "jpeg2000" | "jp2" | "j2k" | "image/jp2" => is_jpeg_2000(bytes),
    "jpeg-xl" | "jpegxl" | "jxl" | "image/jxl" => is_jpeg_xl(bytes),
    "lzip" | "application/x-lzip" => bytes.starts_with(b"LZIP"),
    "maff" | "application/x-maff" => is_zip_with(bytes, b"index.rdf"),
    "matroska" | "mkv" | "video/x-matroska" => is_ebml_doctype(bytes, b"matroska"),
    "mng" | "video/x-mng" => bytes.starts_with(b"\x8aMNG\r\n\x1a\n"),
    "mp3" | "audio/mpeg" => is_mp3(bytes),
    "musepack" | "mpc" | "audio/x-musepack" => {
      bytes.starts_with(b"MPCK") || bytes.starts_with(b"MP+")
    }
    "netcdf" | "nc" | "application/x-netcdf" => is_netcdf(bytes),
    "odf" | "odt" | "ods" | "odp" | "odg" | "opendocument" => {
      is_zip_with(bytes, b"application/vnd.oasis.opendocument")
    }
    "ogg" | "application/ogg" | "audio/ogg" | "video/ogg" => is_ogg(bytes),
    "ooxml" | "office-open-xml" | "docx" | "xlsx" | "pptx" => is_ooxml(bytes),
    "openraster" | "ora" | "image/openraster" => is_zip_with(bytes, b"application/x-openraster"),
    "openxps" | "oxps" | "xps" | "application/oxps" | "application/vnd.ms-xpsdocument" => {
      is_openxps(bytes)
    }
    "opus" | "audio/opus" => is_ogg_with(bytes, b"OpusHead"),
    "pdf" | "pdf-a" | "pdf-e" | "pdf-raster" | "pdf-ua" | "pdf-x" | "application/pdf" => {
      bytes.starts_with(b"%PDF-")
    }
    "png" | "image/png" => is_png(bytes),
    "qoi" | "image/qoi" => bytes.starts_with(b"qoif"),
    "speex" | "audio/speex" => is_ogg_with(bytes, b"Speex   "),
    "tar" | "application/x-tar" => is_tar(bytes),
    "theora" | "video/theora" => is_ogg_with(bytes, b"\x80theora"),
    "vorbis" | "audio/vorbis" => is_ogg_with(bytes, b"\x01vorbis"),
    "wavpack" | "wv" | "audio/wavpack" => bytes.starts_with(b"wvpk"),
    "webp" | "image/webp" => is_webp(bytes),
    "zip" | "application/zip" | "application/x-zip-compressed" => is_zip(bytes),
    "webm" | "video/webm" | "audio/webm" => is_ebml_doctype(bytes, b"webm"),
    "woff" | "font/woff" => bytes.starts_with(b"wOFF"),
    "woff2" | "font/woff2" => bytes.starts_with(b"wOF2"),
    "xcf" | "image/x-xcf" => bytes.starts_with(b"gimp xcf "),
    "xz" | "application/x-xz" => bytes.starts_with(b"\xfd7zXZ\x00"),
    "zim" | "application/x-zim" => bytes.starts_with(b"ZIM\x04"),
    _ => false,
  }
}

fn normalize_binary_format(format: &str) -> String {
  format.trim().to_ascii_lowercase().replace(['_', ' '], "-")
}

fn is_zip(bytes: &[u8]) -> bool {
  bytes.starts_with(b"PK\x03\x04")
    || bytes.starts_with(b"PK\x05\x06")
    || bytes.starts_with(b"PK\x07\x08")
}

fn is_png(bytes: &[u8]) -> bool {
  bytes.starts_with(b"\x89PNG\r\n\x1a\n")
}

fn is_apng(bytes: &[u8]) -> bool {
  is_png(bytes) && png_contains_chunk(bytes, b"acTL")
}

fn png_contains_chunk(bytes: &[u8], chunk_type: &[u8; 4]) -> bool {
  let mut offset = 8usize;
  while offset + 8 <= bytes.len() {
    let length = u32::from_be_bytes([
      bytes[offset],
      bytes[offset + 1],
      bytes[offset + 2],
      bytes[offset + 3],
    ]) as usize;
    if &bytes[offset + 4..offset + 8] == chunk_type {
      return true;
    }
    let Some(next) = offset
      .checked_add(8)
      .and_then(|offset| offset.checked_add(length))
      .and_then(|offset| offset.checked_add(4))
    else {
      return false;
    };
    if next <= offset {
      return false;
    }
    offset = next;
  }
  false
}

fn is_webp(bytes: &[u8]) -> bool {
  bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP"
}

fn is_gbr(bytes: &[u8]) -> bool {
  bytes.len() >= 24 && &bytes[20..24] == b"GIMP"
}

fn is_jpeg_2000(bytes: &[u8]) -> bool {
  bytes.starts_with(b"\x00\x00\x00\x0cjP  \r\n\x87\n") || bytes.starts_with(b"\xff\x4f\xff\x51")
}

fn is_jpeg_xl(bytes: &[u8]) -> bool {
  bytes.starts_with(b"\xff\x0a") || is_isobmff_with_brand(bytes, &[b"jxl "])
}

fn is_isobmff_with_brand(bytes: &[u8], brands: &[&[u8; 4]]) -> bool {
  if bytes.len() < 12 || &bytes[4..8] != b"ftyp" {
    return false;
  }
  if brands.iter().any(|brand| &bytes[8..12] == brand.as_slice()) {
    return true;
  }

  let box_size = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
  let limit = if box_size >= 16 && box_size <= bytes.len() {
    box_size
  } else {
    bytes.len().min(256)
  };
  if limit <= 16 {
    return false;
  }
  bytes[16..limit]
    .chunks_exact(4)
    .any(|brand| brands.iter().any(|expected| brand == expected.as_slice()))
}

fn is_alac(bytes: &[u8]) -> bool {
  bytes.len() >= 12 && &bytes[4..8] == b"ftyp" && byte_contains(bytes, b"alac")
}

fn is_av1(bytes: &[u8]) -> bool {
  (bytes.len() >= 12 && bytes.starts_with(b"DKIF") && &bytes[8..12] == b"AV01")
    || is_isobmff_with_brand(bytes, &[b"av01"])
}

fn is_ogg(bytes: &[u8]) -> bool {
  bytes.starts_with(b"OggS")
}

fn is_ogg_with(bytes: &[u8], marker: &[u8]) -> bool {
  is_ogg(bytes) && byte_contains(bytes, marker)
}

fn is_mp3(bytes: &[u8]) -> bool {
  bytes.starts_with(b"ID3") || (bytes.len() >= 2 && bytes[0] == 0xff && (bytes[1] & 0xe0) == 0xe0)
}

fn is_tar(bytes: &[u8]) -> bool {
  bytes.len() >= 263 && (&bytes[257..263] == b"ustar\0" || &bytes[257..263] == b"ustar ")
}

fn is_ooxml(bytes: &[u8]) -> bool {
  is_zip(bytes)
    && byte_contains(bytes, b"[Content_Types].xml")
    && (byte_contains(bytes, b"word/")
      || byte_contains(bytes, b"xl/")
      || byte_contains(bytes, b"ppt/"))
}

fn is_openxps(bytes: &[u8]) -> bool {
  is_zip(bytes)
    && (byte_contains(bytes, b"FixedDocumentSequence.fdseq")
      || byte_contains(bytes, b"application/vnd.ms-package.xps")
      || byte_contains(bytes, b"schemas.microsoft.com/xps/"))
}

fn is_zip_with(bytes: &[u8], marker: &[u8]) -> bool {
  is_zip(bytes) && byte_contains(bytes, marker)
}

fn is_hdf5(bytes: &[u8]) -> bool {
  bytes.starts_with(b"\x89HDF\r\n\x1a\n")
}

fn is_netcdf(bytes: &[u8]) -> bool {
  bytes.starts_with(b"CDF\x01") || bytes.starts_with(b"CDF\x02") || bytes.starts_with(b"CDF\x05")
}

fn is_pe_executable(bytes: &[u8]) -> bool {
  if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
    return false;
  }
  let pe_offset = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
  pe_offset + 4 <= bytes.len() && &bytes[pe_offset..pe_offset + 4] == b"PE\0\0"
}

fn is_ebml_doctype(bytes: &[u8], expected_doctype: &[u8]) -> bool {
  if !bytes.starts_with(b"\x1a\x45\xdf\xa3") {
    return false;
  }

  let limit = bytes.len().min(4096);
  let header = &bytes[..limit];
  let Some(position) = header.windows(2).position(|window| window == b"\x42\x82") else {
    return false;
  };
  let Some((size_len, doc_type_len)) = parse_ebml_vint(&header[position + 2..]) else {
    return false;
  };
  let start = position + 2 + size_len;
  let end = start + doc_type_len;
  end <= header.len() && &header[start..end] == expected_doctype
}

fn byte_contains(bytes: &[u8], needle: &[u8]) -> bool {
  !needle.is_empty()
    && bytes.len() >= needle.len()
    && bytes.windows(needle.len()).any(|window| window == needle)
}

fn parse_ebml_vint(bytes: &[u8]) -> Option<(usize, usize)> {
  let first = *bytes.first()?;
  for width in 1..=8 {
    let marker = 1u8 << (8 - width);
    if first & marker == 0 {
      continue;
    }
    if bytes.len() < width {
      return None;
    }
    let mut value = u64::from(first & !marker);
    for byte in &bytes[1..width] {
      value = (value << 8) | u64::from(*byte);
    }
    return usize::try_from(value).ok().map(|value| (width, value));
  }
  None
}

#[cfg(test)]
mod tests {
  use super::bytes_match_format;

  #[test]
  fn binary_format_helper_matches_attachment_formats_with_stable_signatures() {
    let pe = {
      let mut bytes = vec![0u8; 0x84];
      bytes[0..2].copy_from_slice(b"MZ");
      bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
      bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
      bytes
    };
    let tar = {
      let mut bytes = vec![0u8; 512];
      bytes[257..263].copy_from_slice(b"ustar\0");
      bytes
    };

    let cases: &[(&str, &[u8])] = &[
      ("7z", b"\x37\x7a\xbc\xaf\x27\x1c\x00\x04"),
      ("alac", b"\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00alac"),
      (
        "apng",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00acTL\x00\x00\x00\x00",
      ),
      ("av1", b"DKIF\x00\x00\x00\x00AV01"),
      ("avif", b"\x00\x00\x00\x18ftypavif\x00\x00\x00\x00mif1"),
      ("bzip2", b"BZh9"),
      ("dirac", b"BBCD"),
      ("djvu", b"AT&TFORM"),
      ("dvi", b"\xf7\x02"),
      ("elf", b"\x7fELF\x02\x01\x01"),
      ("epub", b"PK\x03\x04mimetypeapplication/epub+zip"),
      ("exr", b"\x76\x2f\x31\x01"),
      ("flac", b"fLaC"),
      ("flif", b"FLIF"),
      (
        "gbr",
        b"\x00\x00\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04GIMP",
      ),
      ("gif", b"GIF89a"),
      ("glb", b"glTF\x02\x00\x00\x00"),
      ("gzip", b"\x1f\x8b\x08"),
      ("hdf4", b"\x0e\x03\x13\x01"),
      ("hdf5", b"\x89HDF\r\n\x1a\n"),
      ("jpeg", b"\xff\xd8\xff\xe0"),
      ("jpeg-2000", b"\x00\x00\x00\x0cjP  \r\n\x87\n"),
      ("jpeg-xl", b"\xff\x0a"),
      ("lzip", b"LZIP"),
      ("maff", b"PK\x03\x04index.rdf"),
      ("mkv", b"\x1a\x45\xdf\xa3\x9f\x42\x82\x88matroska"),
      ("mng", b"\x8aMNG\r\n\x1a\n"),
      ("mp3", b"ID3\x04\x00"),
      ("musepack", b"MPCK"),
      ("netcdf", b"CDF\x01"),
      (
        "odf",
        b"PK\x03\x04mimetypeapplication/vnd.oasis.opendocument.text",
      ),
      ("ogg", b"OggS"),
      ("ooxml", b"PK\x03\x04[Content_Types].xmlword/document.xml"),
      ("openraster", b"PK\x03\x04mimetypeapplication/x-openraster"),
      ("openxps", b"PK\x03\x04FixedDocumentSequence.fdseq"),
      ("opus", b"OggS\x00OpusHead"),
      ("pdf", b"%PDF-1.7"),
      ("png", b"\x89PNG\r\n\x1a\n"),
      ("qoi", b"qoif"),
      ("speex", b"OggS\x00Speex   "),
      ("theora", b"OggS\x00\x80theora"),
      ("vorbis", b"OggS\x00\x01vorbis"),
      ("wavpack", b"wvpk"),
      ("webm", b"\x1a\x45\xdf\xa3\x9f\x42\x82\x84webm"),
      ("webp", b"RIFF\x00\x00\x00\x00WEBP"),
      ("woff", b"wOFF"),
      ("woff2", b"wOF2"),
      ("xcf", b"gimp xcf "),
      ("xz", b"\xfd7zXZ\x00"),
      ("zim", b"ZIM\x04"),
      ("zip", b"PK\x03\x04"),
    ];

    for (format, bytes) in cases {
      assert!(
        bytes_match_format(bytes, format),
        "expected {format} to match"
      );
    }
    assert!(bytes_match_format(&pe, "windows-exe"));
    assert!(bytes_match_format(&tar, "tar"));
  }

  #[test]
  fn binary_format_helper_leaves_text_and_filesystem_like_formats_unmatched() {
    assert!(!bytes_match_format(b"<svg></svg>", "svg"));
    assert!(!bytes_match_format(b"key: value\n", "yaml"));
    assert!(!bytes_match_format(b"LUKS\xba\xbe", "luks"));
    assert!(!bytes_match_format(b"OBJ text", "obj"));
  }

  #[test]
  fn binary_format_helper_rejects_short_isobmff_without_panicking() {
    for len in 12..=15 {
      let mut bytes = vec![0u8; len];
      bytes[4..8].copy_from_slice(b"ftyp");
      bytes[8..12].copy_from_slice(b"nope");

      assert!(!bytes_match_format(&bytes, "avif"));
      assert!(!bytes_match_format(&bytes, "jpeg-xl"));
      assert!(!bytes_match_format(&bytes, "av1"));
    }
  }
}

fn pattern_set_matches(
  sets: &HashMap<String, CompiledPatternSet>,
  name: &str,
  text: &str,
) -> anyhow::Result<bool> {
  let set = sets
    .get(name)
    .ok_or_else(|| anyhow!("unknown WAF pattern set {name}"))?;
  match set {
    CompiledPatternSet::Contains(patterns) => {
      Ok(patterns.iter().any(|pattern| text.contains(pattern)))
    }
    CompiledPatternSet::Regex(patterns) => {
      Ok(patterns.iter().any(|pattern| pattern.is_match(text)))
    }
  }
}

fn ip_in_cidr(ip: &str, cidr: &str) -> anyhow::Result<bool> {
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

#[derive(Debug, Clone, PartialEq)]
enum Token {
  Ident(String),
  String(String),
  Int(i64),
  True,
  False,
  Null,
  Dot,
  Comma,
  LParen,
  RParen,
  Bang,
  EqEq,
  Ne,
  Lt,
  Le,
  Gt,
  Ge,
  AndAnd,
  OrOr,
  Plus,
  Invalid(char),
  Eof,
}

struct Parser {
  tokens: Vec<Token>,
  position: usize,
}

impl Parser {
  fn new(input: &str) -> Self {
    Self {
      tokens: tokenize(input),
      position: 0,
    }
  }

  fn parse(mut self) -> anyhow::Result<Expr> {
    let expr = self.parse_or()?;
    if !matches!(self.peek(), Token::Eof) {
      bail!("unexpected token {:?}", self.peek());
    }
    Ok(expr)
  }

  fn parse_or(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_and()?;
    while self.consume(&Token::OrOr) {
      let right = self.parse_and()?;
      expr = Expr::Binary(Box::new(expr), BinaryOp::Or, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_and(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_equality()?;
    while self.consume(&Token::AndAnd) {
      let right = self.parse_equality()?;
      expr = Expr::Binary(Box::new(expr), BinaryOp::And, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_equality(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_comparison()?;
    loop {
      let op = if self.consume(&Token::EqEq) {
        Some(BinaryOp::Eq)
      } else if self.consume(&Token::Ne) {
        Some(BinaryOp::Ne)
      } else {
        None
      };
      let Some(op) = op else {
        break;
      };
      let right = self.parse_comparison()?;
      expr = Expr::Binary(Box::new(expr), op, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_comparison(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_additive()?;
    loop {
      let op = if self.consume(&Token::Lt) {
        Some(BinaryOp::Lt)
      } else if self.consume(&Token::Le) {
        Some(BinaryOp::Le)
      } else if self.consume(&Token::Gt) {
        Some(BinaryOp::Gt)
      } else if self.consume(&Token::Ge) {
        Some(BinaryOp::Ge)
      } else {
        None
      };
      let Some(op) = op else {
        break;
      };
      let right = self.parse_additive()?;
      expr = Expr::Binary(Box::new(expr), op, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_additive(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_unary()?;
    while self.consume(&Token::Plus) {
      let right = self.parse_unary()?;
      expr = Expr::Binary(Box::new(expr), BinaryOp::Add, Box::new(right));
    }
    Ok(expr)
  }

  fn parse_unary(&mut self) -> anyhow::Result<Expr> {
    if self.consume(&Token::Bang) {
      return Ok(Expr::UnaryNot(Box::new(self.parse_unary()?)));
    }
    self.parse_postfix()
  }

  fn parse_postfix(&mut self) -> anyhow::Result<Expr> {
    let mut expr = self.parse_primary()?;
    while self.consume(&Token::Dot) {
      let field = self.expect_ident()?;
      if self.consume(&Token::LParen) {
        let args = self.parse_args()?;
        expr = Expr::Call(Box::new(expr), field, args);
      } else {
        expr = Expr::Member(Box::new(expr), field);
      }
    }
    Ok(expr)
  }

  fn parse_primary(&mut self) -> anyhow::Result<Expr> {
    match self.advance() {
      Token::True => Ok(Expr::Bool(true)),
      Token::False => Ok(Expr::Bool(false)),
      Token::Null => Ok(Expr::Null),
      Token::Int(value) => Ok(Expr::Int(value)),
      Token::String(value) => Ok(Expr::String(value)),
      Token::Ident(value) => {
        validate_identifier(&value)?;
        Ok(Expr::Ident(value))
      }
      Token::LParen => {
        let expr = self.parse_or()?;
        self.expect(Token::RParen)?;
        Ok(expr)
      }
      token => bail!("unexpected token {:?}", token),
    }
  }

  fn parse_args(&mut self) -> anyhow::Result<Vec<Expr>> {
    let mut args = Vec::new();
    if self.consume(&Token::RParen) {
      return Ok(args);
    }
    loop {
      args.push(self.parse_or()?);
      if self.consume(&Token::RParen) {
        break;
      }
      self.expect(Token::Comma)?;
    }
    Ok(args)
  }

  fn expect_ident(&mut self) -> anyhow::Result<String> {
    match self.advance() {
      Token::Ident(value) => {
        validate_identifier(&value)?;
        Ok(value)
      }
      token => bail!("expected identifier, got {:?}", token),
    }
  }

  fn expect(&mut self, expected: Token) -> anyhow::Result<()> {
    let token = self.advance();
    if token == expected {
      Ok(())
    } else {
      bail!("expected {:?}, got {:?}", expected, token)
    }
  }

  fn consume(&mut self, expected: &Token) -> bool {
    if self.peek() == expected {
      self.position += 1;
      true
    } else {
      false
    }
  }

  fn advance(&mut self) -> Token {
    let token = self.peek().clone();
    if !matches!(token, Token::Eof) {
      self.position += 1;
    }
    token
  }

  fn peek(&self) -> &Token {
    self.tokens.get(self.position).unwrap_or(&Token::Eof)
  }
}

fn tokenize(input: &str) -> Vec<Token> {
  let mut chars = input.chars().peekable();
  let mut tokens = Vec::new();

  while let Some(ch) = chars.next() {
    match ch {
      ch if ch.is_whitespace() => {}
      '\'' => {
        let mut value = String::new();
        while let Some(next) = chars.next() {
          match next {
            '\\' => {
              if let Some(escaped) = chars.next() {
                value.push(escaped);
              }
            }
            '\'' => break,
            other => value.push(other),
          }
        }
        tokens.push(Token::String(value));
      }
      '0'..='9' => {
        let mut value = ch.to_string();
        while let Some(next) = chars.peek() {
          if next.is_ascii_digit() {
            value.push(chars.next().unwrap());
          } else {
            break;
          }
        }
        tokens.push(Token::Int(value.parse().unwrap_or_default()));
      }
      'A'..='Z' | 'a'..='z' | '_' => {
        let mut value = ch.to_string();
        while let Some(next) = chars.peek() {
          if next.is_ascii_alphanumeric() || *next == '_' {
            value.push(chars.next().unwrap());
          } else {
            break;
          }
        }
        tokens.push(match value.as_str() {
          "true" => Token::True,
          "false" => Token::False,
          "null" => Token::Null,
          _ => Token::Ident(value),
        });
      }
      '.' => tokens.push(Token::Dot),
      ',' => tokens.push(Token::Comma),
      '(' => tokens.push(Token::LParen),
      ')' => tokens.push(Token::RParen),
      '+' => tokens.push(Token::Plus),
      '!' if chars.peek() == Some(&'=') => {
        chars.next();
        tokens.push(Token::Ne);
      }
      '!' => tokens.push(Token::Bang),
      '=' if chars.peek() == Some(&'=') => {
        chars.next();
        tokens.push(Token::EqEq);
      }
      '<' if chars.peek() == Some(&'=') => {
        chars.next();
        tokens.push(Token::Le);
      }
      '<' => tokens.push(Token::Lt),
      '>' if chars.peek() == Some(&'=') => {
        chars.next();
        tokens.push(Token::Ge);
      }
      '>' => tokens.push(Token::Gt),
      '&' if chars.peek() == Some(&'&') => {
        chars.next();
        tokens.push(Token::AndAnd);
      }
      '|' if chars.peek() == Some(&'|') => {
        chars.next();
        tokens.push(Token::OrOr);
      }
      _ => tokens.push(Token::Invalid(ch)),
    }
  }

  tokens.push(Token::Eof);
  tokens
}

fn validate_identifier(identifier: &str) -> anyhow::Result<()> {
  match identifier {
    "if" | "else" | "for" | "while" | "do" | "switch" | "let" | "const" | "function" | "import"
    | "export" | "new" | "try" | "catch" | "throw" | "await" | "return" => {
      bail!("forbidden OxiRule construct {identifier}")
    }
    _ => Ok(()),
  }
}

fn default_access_log_field_configs() -> Vec<AccessLogFieldConfig> {
  [
    ("request_id", "Request.Id"),
    ("response_id", "Response.Id"),
    ("transaction_id", "Context.TransactionId"),
    ("method", "Request.Http.Method"),
    ("uri", "Request.Http.Uri"),
    ("path", "Request.Http.Path"),
    ("query", "Request.Http.Query"),
    ("request_version", "Request.Http.Version"),
    ("host", "Request.Http.Host"),
    ("user_agent", "Request.Headers.getAll('User-Agent')"),
    ("client_ip", "Request.Client.Ip"),
    ("client_port", "Request.Client.Port"),
    ("protocol", "Request.Protocol"),
    ("transport", "Request.Transport.Network"),
    ("tls", "Request.Tls.Enabled"),
    ("route", "Context.RouteName"),
    ("status", "Response.Http.Status"),
    ("reason", "Response.Http.Reason"),
    ("response_body_bytes", "Response.Body.Size"),
    ("upstream", "Response.Upstream.Name"),
    ("upstream_pool", "Response.Upstream.Pool"),
    ("upstream_scheme", "Response.Upstream.Scheme"),
    (
      "upstream_connect_time_ms",
      "Response.Upstream.ConnectTimeMs",
    ),
    (
      "upstream_first_byte_time_ms",
      "Response.Upstream.FirstByteTimeMs",
    ),
    ("waf_rule", "Context.RuleName"),
    ("waf_rule_id", "Context.RuleId"),
    ("request_received_at_unix_ms", "Request.ReceivedAtUnixMs"),
    ("response_received_at_unix_ms", "Response.ReceivedAtUnixMs"),
  ]
  .into_iter()
  .map(|(name, value)| AccessLogFieldConfig {
    name: name.to_string(),
    value: value.to_string(),
  })
  .collect()
}

fn default_max_rule_runtime_ms() -> u64 {
  5
}

fn default_max_total_waf_runtime_ms() -> u64 {
  20
}

fn default_max_expression_steps() -> usize {
  2_000
}

fn default_max_memory_bytes() -> usize {
  262_144
}

fn default_max_string_bytes() -> usize {
  8_192
}

fn default_max_body_inspection_bytes() -> usize {
  1_048_576
}

fn default_max_header_count() -> usize {
  128
}

fn default_max_header_value_bytes() -> usize {
  8_192
}

fn default_max_mutations() -> usize {
  32
}

fn default_max_regex_runtime_ms() -> u64 {
  2
}

fn default_max_helper_items() -> usize {
  128
}

fn default_max_helper_pattern_count() -> usize {
  32
}

fn default_max_helper_result_bytes() -> usize {
  8_192
}

fn default_max_person_proof_reuse_tokens() -> usize {
  4_096
}

fn default_person_proof_difficulty() -> u8 {
  18
}

fn default_person_proof_token_validity_seconds() -> u64 {
  300
}

fn default_person_proof_cookie() -> String {
  "__oxibelt_person_proof".to_string()
}

fn default_person_proof_token_bindings() -> Vec<PersonProofTokenBinding> {
  vec![
    PersonProofTokenBinding::UserAgent,
    PersonProofTokenBinding::Route,
    PersonProofTokenBinding::DirectPeerIpNetworkPrefix,
  ]
}

fn default_person_proof_direct_peer_ipv4_prefix_bits() -> u8 {
  24
}

fn default_person_proof_direct_peer_ipv6_prefix_bits() -> u8 {
  56
}

fn default_person_proof_status() -> u16 {
  403
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
