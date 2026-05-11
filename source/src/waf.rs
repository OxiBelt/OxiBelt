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

use crate::config::{
  Config, LimitMode, RateLimitKey, resolve_existing_local_config_file_path_with_logical,
};
use crate::dynamic_policy::DynamicPolicyContext;
use crate::limits::{LimitState, RateLimitCheck, RateLimitContext};
use crate::routes::normalize_host;
use crate::shared_state::SharedState;

mod binary_format;
mod body_scan;
mod crs;
mod defaults;
mod expression;
mod functions;
pub(crate) mod normalization;
mod person_proof;

use binary_format::bytes_match_format;
pub use crs::{CrsCompatibilityMatrix, compatibility_matrix as crs_compatibility_matrix};
use crs::{CrsDecision, CrsEngine, WafCrsConfig, validate_crs_config};
use defaults::*;
use expression::Parser;
pub use functions::WafFunctionConfig;
use functions::{
  FunctionCallRef, FunctionKey, FunctionMap, compile_global_functions, compile_route_functions,
  function_body_route_functions, resolve_function, validate_function_arity,
};
use normalization::{
  normalize_cookie_pairs, normalize_header_pairs, normalize_query_pairs, normalized_http_path,
  normalized_http_query, normalized_http_uri,
};
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
  pub crs: WafCrsConfig,
  #[serde(default)]
  pub functions: Vec<WafFunctionConfig>,
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
      crs: WafCrsConfig::default(),
      functions: Vec::new(),
      rules: Vec::new(),
      pattern_sets: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteWafConfig {
  #[serde(default)]
  pub functions: Vec<WafFunctionConfig>,
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
  Stream,
}

impl WafPhase {
  fn as_str(self) -> &'static str {
    match self {
      Self::Request => "request",
      Self::Response => "response",
      Self::Stream => "stream",
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
  RateLimit {
    name: String,
    #[serde(default)]
    key: RateLimitKey,
    #[serde(default)]
    token_header: Option<String>,
    rate: String,
    #[serde(default)]
    burst: u32,
    #[serde(default = "crate::limits::default_rate_limit_max_buckets")]
    max_buckets: usize,
    #[serde(default = "default_waf_rate_limit_status")]
    status: u16,
    #[serde(default)]
    body: Option<String>,
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
  CloseStream {
    #[serde(default = "default_websocket_close_code")]
    websocket_code: u16,
    #[serde(default = "default_webtransport_close_code")]
    webtransport_code: u32,
    #[serde(default = "default_stream_close_reason")]
    reason: String,
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
#[serde(deny_unknown_fields)]
struct ExternalRuleFile {
  pub when: String,
  #[serde(default)]
  pub actions: Vec<WafActionConfig>,
}

impl WafConfig {
  pub fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<()> {
    self.crs.resolve_relative_paths(base_dir)?;
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
    let mut paths = self
      .rules
      .iter()
      .filter_map(|rule| {
        rule
          .loaded_from_logical_path
          .clone()
          .or_else(|| rule.loaded_from_path.clone())
      })
      .collect::<Vec<_>>();
    paths.extend(self.crs.loaded_paths());
    paths
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
  if config.waf.crs.enabled {
    validate_crs_config(&config.waf.crs)?;
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
  let global_functions = compile_global_functions(&config.waf.functions)?;
  let global_validation = WafValidationContext {
    pattern_sets: &config.waf.pattern_sets,
    global_functions: &global_functions,
    route_functions: None,
    limits: &config.waf.limits,
    upstream_names: &upstream_names,
    pool_names: &pool_names,
  };
  validate_scope("global WAF", &config.waf.rules, &global_validation)?;

  for route in &config.routes {
    let route_functions = compile_route_functions(
      &format!("route {} WAF", route.name),
      &route.waf.functions,
      &global_functions,
    )?;
    let route_validation = WafValidationContext {
      pattern_sets: &config.waf.pattern_sets,
      global_functions: &global_functions,
      route_functions: Some(&route_functions),
      limits: &config.waf.limits,
      upstream_names: &upstream_names,
      pool_names: &pool_names,
    };
    validate_scope(
      &format!("route {} WAF", route.name),
      &route.waf.rules,
      &route_validation,
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

struct WafValidationContext<'a> {
  pattern_sets: &'a [WafPatternSetConfig],
  global_functions: &'a FunctionMap,
  route_functions: Option<&'a FunctionMap>,
  limits: &'a WafLimits,
  upstream_names: &'a HashSet<&'a str>,
  pool_names: &'a HashSet<&'a str>,
}

fn validate_scope(
  scope: &str,
  rules: &[WafRuleConfig],
  ctx: &WafValidationContext<'_>,
) -> anyhow::Result<()> {
  validate_pattern_sets(ctx.pattern_sets, ctx.limits)?;

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
      .validate_for_phase_with_functions(rule.phase, ctx.global_functions, ctx.route_functions)
      .with_context(|| format!("invalid WAF rule {} expression", rule.name))?;

    validate_actions(
      rule,
      ctx.upstream_names,
      ctx.pool_names,
      ctx.limits,
      ctx.global_functions,
      ctx.route_functions,
    )?;
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
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
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
        validate_access_log_field_configs_with_functions(
          &format!("WAF rule {} emit_access_log", rule.name),
          fields,
          global_functions,
          route_functions,
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
      WafActionConfig::RateLimit {
        name,
        key,
        token_header,
        rate,
        max_buckets,
        status,
        ..
      } => {
        require_phase(rule, WafPhase::Request, "rate_limit")?;
        if name.trim().is_empty() {
          bail!("WAF rule {} rate_limit name must not be empty", rule.name);
        }
        crate::limits::parse_rate(rate)
          .with_context(|| format!("invalid WAF rule {} rate_limit rate", rule.name))?;
        if *max_buckets == 0 {
          bail!(
            "WAF rule {} rate_limit max_buckets must be greater than 0",
            rule.name
          );
        }
        validate_status(*status, &rule.name)?;
        if let Some(token_header) = token_header {
          if !key.uses_access_token() {
            bail!(
              "WAF rule {} rate_limit token_header requires an access_token key",
              rule.name
            );
          }
          validate_header_name(token_header)?;
        }
        mutations += 1;
      }
      WafActionConfig::RequirePersonProof { status, .. } => {
        require_phase(rule, WafPhase::Request, "require_person_proof")?;
        validate_status(*status, &rule.name)?;
        validate_person_proof_settings(&rule.name, action)?;
      }
      WafActionConfig::CloseStream {
        websocket_code,
        webtransport_code: _,
        reason,
      } => {
        require_phase(rule, WafPhase::Stream, "close_stream")?;
        validate_websocket_close_code(*websocket_code, &rule.name)?;
        if reason.len() > 123 {
          bail!(
            "WAF rule {} close_stream reason exceeds 123 bytes",
            rule.name
          );
        }
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

fn validate_websocket_close_code(code: u16, rule_name: &str) -> anyhow::Result<()> {
  if code < 1000 || matches!(code, 1004..=1006) || (1016..3000).contains(&code) || code >= 5000 {
    bail!("WAF rule {rule_name} has invalid WebSocket close code {code}");
  }
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
  let empty_functions = FunctionMap::new();
  validate_access_log_field_configs_with_functions(label, fields, &empty_functions, None)
}

fn validate_access_log_field_configs_with_functions(
  label: &str,
  fields: &[AccessLogFieldConfig],
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
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
      .validate_for_phase_with_functions(WafPhase::Response, global_functions, route_functions)
      .with_context(|| format!("invalid {label} field {}", field.name))?;
    if expression.requires_request_body_inspection_with_functions(global_functions, route_functions)
    {
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
  global_functions: Arc<FunctionMap>,
  global_rules: Vec<CompiledRule>,
  route_rules: HashMap<String, Vec<CompiledRule>>,
  crs: CrsEngine,
  rate_limits: Arc<LimitState>,
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
    Self::new_with_previous_and_limits(config, previous, shared_state, None)
  }

  pub fn new_with_previous_and_limits(
    config: &Config,
    previous: Option<&Self>,
    shared_state: Option<std::sync::Arc<SharedState>>,
    rate_limits: Option<Arc<LimitState>>,
  ) -> anyhow::Result<Self> {
    validate_config(config)?;

    let previous_counters = previous
      .map(WafEngine::active_hit_counters)
      .unwrap_or_default();
    let previous_crs_counters = previous
      .map(|engine| engine.crs.active_hit_counters())
      .unwrap_or_default();
    let rate_limits = rate_limits.unwrap_or_else(|| LimitState::new(shared_state.clone()));
    let pattern_sets = compile_pattern_sets(&config.waf.pattern_sets, &config.waf.limits)?;
    let global_functions = Arc::new(compile_global_functions(&config.waf.functions)?);
    let crs = CrsEngine::compile(&config.waf.crs, &previous_crs_counters)?;
    let global_rules = compile_rules(
      &config.waf.rules,
      WafRuleScope::global(),
      config.waf.mode,
      &previous_counters,
      global_functions.clone(),
      None,
    )?;
    let mut route_rules = HashMap::new();
    for route in &config.routes {
      let functions = Arc::new(compile_route_functions(
        &format!("route {} WAF", route.name),
        &route.waf.functions,
        global_functions.as_ref(),
      )?);
      route_rules.insert(
        route.name.clone(),
        compile_rules(
          &route.waf.rules,
          WafRuleScope::route(&route.name),
          config.waf.mode,
          &previous_counters,
          global_functions.clone(),
          Some(functions.clone()),
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
      global_functions,
      global_rules,
      route_rules,
      crs,
      rate_limits,
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
    snapshots.extend(self.crs.rule_hit_snapshots());
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
      && (self.crs.enabled()
        || self
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
      && (self.crs.requires_request_body_inspection()
        || self
          .rules_for(route_name, WafPhase::Request)
          .iter()
          .any(|rule| rule.requires_request_body_inspection))
  }

  pub fn requires_response_body_inspection(&self, route_name: &str) -> bool {
    self.enabled
      && (self.crs.requires_response_body_inspection()
        || self
          .rules_for(route_name, WafPhase::Response)
          .iter()
          .any(|rule| rule.requires_response_body_inspection()))
  }

  pub fn requires_stream_inspection(&self, route_name: &str) -> bool {
    self.enabled && !self.rules_for(route_name, WafPhase::Stream).is_empty()
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

  pub fn evaluate_stream(&self, input: WafStreamInput<'_>) -> WafStreamDecision {
    if !self.enabled {
      return WafStreamDecision::default();
    }

    match self.evaluate_stream_inner(input) {
      Ok(decision) => decision,
      Err(error) => match self.fail_policy {
        WafFailPolicy::Open => {
          warn!(error = %error, "WAF stream evaluation failed open");
          WafStreamDecision::default()
        }
        WafFailPolicy::Closed => {
          warn!(error = %error, "WAF stream evaluation failed closed");
          WafStreamDecision {
            close: Some(WafStreamClose::default()),
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
    let empty_functions = FunctionMap::new();
    let ctx = EvalContext {
      phase: WafPhase::Response,
      mode: self.mode,
      rule_name: "",
      rule_id: None,
      rule_tags: &[],
      request: input.request,
      response: Some(input),
      stream: None,
      person_proof: &person_proof,
      pattern_sets: &self.pattern_sets,
      global_functions: &empty_functions,
      route_functions: None,
      locals: &[],
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
          stream: None,
          person_proof: &rule_person_proof,
          pattern_sets: &self.pattern_sets,
          global_functions: self.global_functions.as_ref(),
          route_functions: None,
          locals: &[],
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
        apply_request_actions(
          rule,
          request,
          &self.person_proof,
          &self.rate_limits,
          &mut decision,
          &mut tx,
        )?;
      }
      for (key, value) in &decision.tags[previous_tag_count..] {
        active_tags.insert(key.clone(), value.clone());
      }
      if decision.terminal.is_some() {
        return Ok(decision);
      }
    }

    let request = WafRequestInput {
      tags: &active_tags,
      ..input
    };
    apply_crs_request_decision(self.crs.evaluate_request(request)?, &mut decision);
    if decision.terminal.is_some() {
      return Ok(decision);
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
        stream: None,
        person_proof: &person_proof,
        pattern_sets: &self.pattern_sets,
        global_functions: self.global_functions.as_ref(),
        route_functions: None,
        locals: &[],
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

    apply_crs_response_decision(self.crs.evaluate_response(input)?, &mut decision);
    if decision.terminal.is_some() {
      return Ok(decision);
    }

    Ok(decision)
  }

  fn evaluate_stream_inner(&self, input: WafStreamInput<'_>) -> anyhow::Result<WafStreamDecision> {
    let mut decision = WafStreamDecision::default();
    let person_proof = self.person_proof.evaluate_request(input.request);
    let mut tx = TransactionBudget::new(&self.limits);

    for rule in self.rules_for(input.request.route_name, WafPhase::Stream) {
      tx.check_total()?;
      let ctx = EvalContext {
        phase: WafPhase::Stream,
        mode: rule.mode,
        rule_name: "",
        rule_id: None,
        rule_tags: &[],
        request: input.request,
        response: None,
        stream: Some(input),
        person_proof: &person_proof,
        pattern_sets: &self.pattern_sets,
        global_functions: self.global_functions.as_ref(),
        route_functions: None,
        locals: &[],
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
        phase = "stream",
        "WAF rule matched"
      );
      if rule.mode == WafMode::Monitor {
        continue;
      }
      apply_stream_actions(rule, &mut decision, &mut tx)?;
      if decision.close.is_some() {
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
      global_functions: rule.global_functions.as_ref(),
      route_functions: rule.route_functions.as_deref(),
      locals: &[],
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
  global_functions: Arc<FunctionMap>,
  route_functions: Option<Arc<FunctionMap>>,
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
          && expression.requires_request_body_inspection_with_functions(
            global_functions.as_ref(),
            route_functions.as_deref(),
          ),
        expression,
        global_functions: global_functions.clone(),
        route_functions: route_functions.clone(),
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
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<String>,
  pub effective_mode: String,
  pub hits: u64,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub tuned_hits: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub latest_inbound_anomaly_score: Option<i64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub latest_outbound_anomaly_score: Option<i64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub latest_inbound_blocking_score: Option<i64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub latest_outbound_blocking_score: Option<i64>,
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
  global_functions: Arc<FunctionMap>,
  route_functions: Option<Arc<FunctionMap>>,
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
      tags: self.tags.clone(),
      effective_mode: self.mode.as_str().to_string(),
      hits: self.hit_counter.load(Ordering::Relaxed),
      tuned_hits: None,
      latest_inbound_anomaly_score: None,
      latest_outbound_anomaly_score: None,
      latest_inbound_blocking_score: None,
      latest_outbound_blocking_score: None,
    }
  }

  fn requires_response_body_inspection(&self) -> bool {
    self.phase == WafPhase::Response
      && self
        .expression
        .requires_response_body_inspection_with_functions(
          self.global_functions.as_ref(),
          self.route_functions.as_deref(),
        )
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
  pub dynamic_policy: &'a DynamicPolicyContext,
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
  pub body: Option<WafBodyInput<'a>>,
  pub upstream_name: &'a str,
  pub upstream_pool: Option<&'a str>,
  pub upstream_scheme: &'a str,
  pub upstream_connect_time_ms: Option<u64>,
  pub upstream_first_byte_time_ms: Option<u64>,
  pub upstream_error: Option<WafUpstreamError<'a>>,
}

#[derive(Debug, Clone, Copy)]
pub struct WafStreamInput<'a> {
  pub request: WafRequestInput<'a>,
  pub protocol: WafStreamProtocol,
  pub direction: WafStreamDirection,
  pub unit: WafStreamUnit,
  pub payload: WafBodyInput<'a>,
  pub websocket: Option<WafWebSocketStreamMetadata<'a>>,
  pub webtransport: Option<WafWebTransportStreamMetadata>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafStreamProtocol {
  Websocket,
  Webtransport,
}

impl WafStreamProtocol {
  fn as_str(self) -> &'static str {
    match self {
      Self::Websocket => "websocket",
      Self::Webtransport => "webtransport",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafStreamDirection {
  DownstreamToUpstream,
  UpstreamToDownstream,
}

impl WafStreamDirection {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::DownstreamToUpstream => "downstream_to_upstream",
      Self::UpstreamToDownstream => "upstream_to_downstream",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafStreamUnit {
  WebsocketFrame,
  WebsocketMessage,
  WebtransportStreamChunk,
  WebtransportDatagram,
}

impl WafStreamUnit {
  fn as_str(self) -> &'static str {
    match self {
      Self::WebsocketFrame => "websocket_frame",
      Self::WebsocketMessage => "websocket_message",
      Self::WebtransportStreamChunk => "webtransport_stream_chunk",
      Self::WebtransportDatagram => "webtransport_datagram",
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub struct WafWebSocketStreamMetadata<'a> {
  pub opcode: &'a str,
  pub fin: bool,
  pub is_control: bool,
  pub message_opcode: Option<&'a str>,
  pub frame_payload_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct WafWebTransportStreamMetadata {
  pub stream_kind: Option<WafWebTransportStreamKind>,
  pub stream_id: Option<u64>,
  pub datagram_size: Option<usize>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafWebTransportStreamKind {
  Bidi,
  Uni,
}

impl WafWebTransportStreamKind {
  fn as_str(self) -> &'static str {
    match self {
      Self::Bidi => "bidi",
      Self::Uni => "uni",
    }
  }
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

#[derive(Debug, Clone, Default)]
pub struct WafStreamDecision {
  pub close: Option<WafStreamClose>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WafStreamClose {
  pub websocket_code: u16,
  pub webtransport_code: u32,
  pub reason: String,
}

impl Default for WafStreamClose {
  fn default() -> Self {
    Self {
      websocket_code: default_websocket_close_code(),
      webtransport_code: default_webtransport_close_code(),
      reason: default_stream_close_reason(),
    }
  }
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

fn apply_crs_request_decision(crs: CrsDecision, decision: &mut RequestWafDecision) {
  if decision.terminal.is_none() {
    decision.terminal = crs.terminal;
  }
}

fn apply_crs_response_decision(crs: CrsDecision, decision: &mut ResponseWafDecision) {
  if decision.terminal.is_none() {
    decision.terminal = crs.terminal;
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
  rate_limits: &LimitState,
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
      CompiledAction::Config(WafActionConfig::RateLimit {
        name,
        key,
        token_header,
        rate,
        burst,
        max_buckets,
        status,
        body,
      }) => {
        let context = RateLimitContext::route(
          input.peer_addr.ip(),
          input.route_name,
          input.uri.path(),
          input.headers,
        );
        let check = RateLimitCheck {
          name,
          key: *key,
          token_header: token_header.as_deref(),
          rate,
          burst: *burst,
          max_buckets: *max_buckets,
          mode: LimitMode::Enforcing,
          status: *status,
        };
        if let Some(status) = rate_limits.check_rate_limit(context, check) {
          decision.terminal = Some(WafTerminalResponse::new(
            status,
            body
              .clone()
              .unwrap_or_else(|| "rate limit exceeded".to_string()),
          ));
          return Ok(());
        }
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
      | CompiledAction::Config(WafActionConfig::CloseStream { .. })
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
          global_functions: rule.global_functions.as_ref(),
          route_functions: rule.route_functions.as_deref(),
          locals: &[],
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
      | CompiledAction::Config(WafActionConfig::RateLimit { .. })
      | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
      | CompiledAction::Config(WafActionConfig::CloseStream { .. })
      | CompiledAction::RequirePersonProof(_)
      | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. }) => {
        bail!("invalid response-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(())
}

fn apply_stream_actions(
  rule: &CompiledRule,
  decision: &mut WafStreamDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<()> {
  let Some(action) = rule.actions.first() else {
    return Ok(());
  };

  tx.count_mutation()?;
  match action {
    CompiledAction::Config(WafActionConfig::CloseStream {
      websocket_code,
      webtransport_code,
      reason,
    }) => {
      decision.close = Some(WafStreamClose {
        websocket_code: *websocket_code,
        webtransport_code: *webtransport_code,
        reason: reason.clone(),
      });
    }
    CompiledAction::Config(WafActionConfig::Reject { .. })
    | CompiledAction::Config(WafActionConfig::ContinueResponse)
    | CompiledAction::Config(WafActionConfig::ReplaceResponse { .. })
    | CompiledAction::Config(WafActionConfig::RejectResponse { .. })
    | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. })
    | CompiledAction::Config(WafActionConfig::RouteToPool { .. })
    | CompiledAction::Config(WafActionConfig::RouteToUpstream { .. })
    | CompiledAction::Config(WafActionConfig::SetLoadBalancingPolicy { .. })
    | CompiledAction::Config(WafActionConfig::SetRequestHeader { .. })
    | CompiledAction::Config(WafActionConfig::RemoveRequestHeader { .. })
    | CompiledAction::Config(WafActionConfig::SetResponseHeader { .. })
    | CompiledAction::Config(WafActionConfig::RemoveResponseHeader { .. })
    | CompiledAction::Config(WafActionConfig::SetTag { .. })
    | CompiledAction::Config(WafActionConfig::RateLimit { .. })
    | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
    | CompiledAction::RequirePersonProof(_)
    | CompiledAction::EmitAccessLog { .. } => {
      bail!("invalid stream-phase WAF action in rule {}", rule.name);
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
      Value::BodyScanResult(result) => Ok(Self::Object(vec![
        ("matched".to_string(), Self::Bool(result.matched)),
        (
          "pattern".to_string(),
          result.pattern.map(Self::String).unwrap_or(Self::Null),
        ),
        (
          "offset".to_string(),
          result
            .offset
            .map(|offset| Self::Int(offset as i64))
            .unwrap_or(Self::Null),
        ),
        (
          "match".to_string(),
          result.matched_text.map(Self::String).unwrap_or(Self::Null),
        ),
        ("is_truncated".to_string(), Self::Bool(result.is_truncated)),
      ])),
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
      ObjectRef::RequestNormalized => {
        object_members_json(object, &["Http", "Headers", "QueryParams", "Cookies"], ctx)
      }
      ObjectRef::RequestNormalizedHttp => {
        object_members_json(object, &["Path", "Query", "Uri"], ctx)
      }
      ObjectRef::RequestNormalizedHeaders => Ok(pair_map_json(
        normalize_header_pairs(ctx.request.headers),
        ctx.limits,
      )),
      ObjectRef::RequestNormalizedQueryParams => Ok(pair_map_json(
        normalize_query_pairs(ctx.request.uri),
        ctx.limits,
      )),
      ObjectRef::RequestNormalizedCookies => Ok(pair_map_json(
        normalize_cookie_pairs(ctx.request.headers),
        ctx.limits,
      )),
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
      ObjectRef::StreamPayload => {
        object_members_json(object, &["Size", "IsTruncated", "Text"], ctx)
      }
      ObjectRef::StreamWebSocket => object_members_json(
        object,
        &[
          "Opcode",
          "Fin",
          "IsControl",
          "MessageOpcode",
          "FramePayloadSize",
        ],
        ctx,
      ),
      ObjectRef::StreamWebTransport => {
        object_members_json(object, &["StreamKind", "StreamId", "DatagramSize"], ctx)
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
      ObjectRef::DynamicPolicy => {
        object_members_json(object, &["Matched", "Action", "Name", "Reason"], ctx)
      }
      ObjectRef::Context | ObjectRef::Request | ObjectRef::Response | ObjectRef::Stream => {
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
  stream: Option<WafStreamInput<'a>>,
  person_proof: &'a PersonProofRequestStatus,
  pattern_sets: &'a HashMap<String, CompiledPatternSet>,
  global_functions: &'a FunctionMap,
  route_functions: Option<&'a FunctionMap>,
  locals: &'a [(&'a str, &'a Value)],
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
  FunctionCall(String, Vec<Expr>),
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
    if phase == WafPhase::Stream {
      if self.references_ident("Response") {
        bail!("Response is unavailable in stream-phase rules");
      }
      if self.references_request_body_object() {
        bail!("Request.Body is unavailable in stream-phase rules");
      }
    } else if self.references_ident("Stream") {
      bail!("Stream is available only in stream-phase rules");
    }
    Ok(())
  }

  fn validate_for_phase_with_functions(
    &self,
    phase: WafPhase,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
  ) -> anyhow::Result<()> {
    self.validate_for_phase(phase)?;
    self.validate_called_functions_for_phase(
      phase,
      global_functions,
      route_functions,
      &mut HashSet::new(),
    )
  }

  fn validate_called_functions_for_phase(
    &self,
    phase: WafPhase,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    active: &mut HashSet<FunctionKey>,
  ) -> anyhow::Result<()> {
    for call in self.function_calls() {
      let function = resolve_function(call.name, global_functions, route_functions)
        .ok_or_else(|| anyhow!("unknown OxiRule function {}", call.name))?;
      validate_function_arity(function, call.args_len)?;
      let key = FunctionKey::from(function);
      if active.insert(key.clone()) {
        let body_route_functions = function_body_route_functions(function, route_functions);
        function.expression.validate_for_phase(phase)?;
        function.expression.validate_called_functions_for_phase(
          phase,
          global_functions,
          body_route_functions,
          active,
        )?;
        active.remove(&key);
      }
    }
    Ok(())
  }

  fn references_ident(&self, name: &str) -> bool {
    match self {
      Self::Ident(ident) => ident == name,
      Self::FunctionCall(_, args) => args.iter().any(|arg| arg.references_ident(name)),
      Self::Member(receiver, _) | Self::UnaryNot(receiver) => receiver.references_ident(name),
      Self::Call(receiver, _, args) => {
        receiver.references_ident(name) || args.iter().any(|arg| arg.references_ident(name))
      }
      Self::Binary(left, _, right) => left.references_ident(name) || right.references_ident(name),
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) => false,
    }
  }

  fn references_request_body_object(&self) -> bool {
    match self {
      Self::Member(receiver, field) => {
        (field == "Body" && (receiver.is_request_expr() || receiver.is_request_http_expr()))
          || receiver.references_request_body_object()
      }
      Self::Call(receiver, _, args) => {
        receiver.references_request_body_object()
          || args.iter().any(Self::references_request_body_object)
      }
      Self::FunctionCall(_, args) => args.iter().any(Self::references_request_body_object),
      Self::UnaryNot(expr) => expr.references_request_body_object(),
      Self::Binary(left, _, right) => {
        left.references_request_body_object() || right.references_request_body_object()
      }
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) | Self::Ident(_) => false,
    }
  }

  fn requires_request_body_inspection(&self) -> bool {
    match self {
      Self::Member(receiver, field) => {
        receiver.requires_request_body_inspection()
          || (matches!(field.as_str(), "Bytes" | "Text" | "IsTruncated")
            && receiver.is_request_body_expr())
      }
      Self::Call(receiver, method, args) => {
        receiver.requires_request_body_inspection()
          || args.iter().any(Self::requires_request_body_inspection)
          || (receiver.is_request_body_expr() && body_content_method(method))
          || (receiver.is_request_body_bytes_expr() && bytes_content_method(method))
      }
      Self::FunctionCall(_, args) => args.iter().any(Self::requires_request_body_inspection),
      Self::UnaryNot(expr) => expr.requires_request_body_inspection(),
      Self::Binary(left, _, right) => {
        left.requires_request_body_inspection() || right.requires_request_body_inspection()
      }
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) | Self::Ident(_) => false,
    }
  }

  fn requires_response_body_inspection(&self) -> bool {
    match self {
      Self::Member(receiver, field) => {
        receiver.requires_response_body_inspection()
          || (matches!(field.as_str(), "Bytes" | "Text" | "IsTruncated")
            && receiver.is_response_body_expr())
      }
      Self::Call(receiver, method, args) => {
        receiver.requires_response_body_inspection()
          || args.iter().any(Self::requires_response_body_inspection)
          || (receiver.is_response_body_expr() && body_content_method(method))
          || (receiver.is_response_body_bytes_expr() && bytes_content_method(method))
      }
      Self::FunctionCall(_, args) => args.iter().any(Self::requires_response_body_inspection),
      Self::UnaryNot(expr) => expr.requires_response_body_inspection(),
      Self::Binary(left, _, right) => {
        left.requires_response_body_inspection() || right.requires_response_body_inspection()
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

  fn is_response_body_expr(&self) -> bool {
    match self {
      Self::Member(receiver, field) if field == "Body" => {
        receiver.is_response_expr() || receiver.is_response_http_expr()
      }
      _ => false,
    }
  }

  fn is_response_body_bytes_expr(&self) -> bool {
    matches!(self, Self::Member(receiver, field) if field == "Bytes" && receiver.is_response_body_expr())
  }

  fn is_request_expr(&self) -> bool {
    matches!(self, Self::Ident(name) if name == "Request")
  }

  fn is_response_expr(&self) -> bool {
    matches!(self, Self::Ident(name) if name == "Response")
  }

  fn is_request_http_expr(&self) -> bool {
    matches!(self, Self::Member(receiver, field) if field == "Http" && receiver.is_request_expr())
  }

  fn is_response_http_expr(&self) -> bool {
    matches!(self, Self::Member(receiver, field) if field == "Http" && receiver.is_response_expr())
  }

  fn requires_request_body_inspection_with_functions(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
  ) -> bool {
    self.requires_request_body_inspection_with_functions_inner(
      global_functions,
      route_functions,
      &mut HashSet::new(),
    )
  }

  fn requires_request_body_inspection_with_functions_inner(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    active: &mut HashSet<FunctionKey>,
  ) -> bool {
    if self.requires_request_body_inspection() {
      return true;
    }
    self.function_calls().into_iter().any(|call| {
      let Some(function) = resolve_function(call.name, global_functions, route_functions) else {
        return false;
      };
      let key = FunctionKey::from(function);
      if !active.insert(key.clone()) {
        return false;
      }
      let body_route_functions = function_body_route_functions(function, route_functions);
      let result = function
        .expression
        .requires_request_body_inspection_with_functions_inner(
          global_functions,
          body_route_functions,
          active,
        );
      active.remove(&key);
      result
    })
  }

  fn requires_response_body_inspection_with_functions(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
  ) -> bool {
    self.requires_response_body_inspection_with_functions_inner(
      global_functions,
      route_functions,
      &mut HashSet::new(),
    )
  }

  fn requires_response_body_inspection_with_functions_inner(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    active: &mut HashSet<FunctionKey>,
  ) -> bool {
    if self.requires_response_body_inspection() {
      return true;
    }
    self.function_calls().into_iter().any(|call| {
      let Some(function) = resolve_function(call.name, global_functions, route_functions) else {
        return false;
      };
      let key = FunctionKey::from(function);
      if !active.insert(key.clone()) {
        return false;
      }
      let body_route_functions = function_body_route_functions(function, route_functions);
      let result = function
        .expression
        .requires_response_body_inspection_with_functions_inner(
          global_functions,
          body_route_functions,
          active,
        );
      active.remove(&key);
      result
    })
  }

  fn function_calls(&self) -> Vec<FunctionCallRef<'_>> {
    let mut calls = Vec::new();
    self.collect_function_calls(&mut calls);
    calls
  }

  fn collect_function_calls<'a>(&'a self, calls: &mut Vec<FunctionCallRef<'a>>) {
    match self {
      Self::FunctionCall(name, args) => {
        calls.push(FunctionCallRef {
          name,
          args_len: args.len(),
        });
        for arg in args {
          arg.collect_function_calls(calls);
        }
      }
      Self::Member(receiver, _) | Self::UnaryNot(receiver) => {
        receiver.collect_function_calls(calls)
      }
      Self::Call(receiver, _, args) => {
        receiver.collect_function_calls(calls);
        for arg in args {
          arg.collect_function_calls(calls);
        }
      }
      Self::Binary(left, _, right) => {
        left.collect_function_calls(calls);
        right.collect_function_calls(calls);
      }
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) | Self::Ident(_) => {}
    }
  }

  fn eval(&self, ctx: &EvalContext<'_>, tx: &mut TransactionBudget) -> anyhow::Result<Value> {
    tx.step()?;
    match self {
      Self::Bool(value) => Ok(Value::Bool(*value)),
      Self::Null => Ok(Value::Null),
      Self::Int(value) => Ok(Value::Int(*value)),
      Self::String(value) => Ok(Value::String(value.clone())),
      Self::Ident(name) => eval_ident(name, ctx),
      Self::FunctionCall(name, args) => {
        let values = args
          .iter()
          .map(|arg| arg.eval(ctx, tx))
          .collect::<anyhow::Result<Vec<_>>>()?;
        eval_function_call(name, &values, ctx, tx)
      }
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
  BodyScanResult(body_scan::BodyScanResult),
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
  RequestNormalized,
  RequestNormalizedHttp,
  RequestNormalizedHeaders,
  RequestNormalizedQueryParams,
  RequestNormalizedCookies,
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
  DynamicPolicy,
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
  Stream,
  StreamPayload,
  StreamWebSocket,
  StreamWebTransport,
}

fn eval_ident(name: &str, ctx: &EvalContext<'_>) -> anyhow::Result<Value> {
  if let Some((_, value)) = ctx
    .locals
    .iter()
    .find(|(local_name, _)| *local_name == name)
  {
    return Ok((*value).clone());
  }
  match name {
    "Context" => Ok(Value::Object(ObjectRef::Context)),
    "Request" => Ok(Value::Object(ObjectRef::Request)),
    "DynamicPolicy" => Ok(Value::Object(ObjectRef::DynamicPolicy)),
    "Response" if ctx.phase == WafPhase::Response => Ok(Value::Object(ObjectRef::Response)),
    "Response" => bail!("Response is unavailable in this phase"),
    "Stream" if ctx.phase == WafPhase::Stream => Ok(Value::Object(ObjectRef::Stream)),
    "Stream" => bail!("Stream is available only in stream phase"),
    _ => bail!("unknown identifier {name}"),
  }
}

fn eval_function_call(
  name: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
  tx: &mut TransactionBudget,
) -> anyhow::Result<Value> {
  let function = resolve_function(name, ctx.global_functions, ctx.route_functions)
    .ok_or_else(|| anyhow!("unknown OxiRule function {name}"))?;
  validate_function_arity(function, args.len())?;
  let locals = function
    .params
    .iter()
    .zip(args.iter())
    .map(|(param, value)| (param.as_str(), value))
    .collect::<Vec<_>>();
  let child_ctx = EvalContext {
    route_functions: function_body_route_functions(function, ctx.route_functions),
    locals: &locals,
    ..*ctx
  };
  function.expression.eval(&child_ctx, tx)
}

fn eval_member(value: Value, field: &str, ctx: &EvalContext<'_>) -> anyhow::Result<Value> {
  if let Value::StringList(list) = value {
    return eval_string_list_member(list, field);
  }
  if let Value::BodyScanResult(result) = value {
    return eval_body_scan_result_member(result, field);
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
    (ObjectRef::DynamicPolicy, "Matched") => Ok(Value::Bool(ctx.request.dynamic_policy.matched)),
    (ObjectRef::DynamicPolicy, "Action") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.action))
    }
    (ObjectRef::DynamicPolicy, "Name") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.name))
    }
    (ObjectRef::DynamicPolicy, "Reason") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.reason))
    }
    (ObjectRef::DynamicPolicy, "Code") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.code))
    }
    (ObjectRef::DynamicPolicy, "Mode") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.mode))
    }
    (ObjectRef::DynamicPolicy, "Source") => {
      Ok(optional_string_value(&ctx.request.dynamic_policy.source))
    }
    (ObjectRef::Stream, "Protocol") => Ok(Value::String(
      ctx
        .stream
        .context("missing stream context")?
        .protocol
        .as_str()
        .to_string(),
    )),
    (ObjectRef::Stream, "Direction") => Ok(Value::String(
      ctx
        .stream
        .context("missing stream context")?
        .direction
        .as_str()
        .to_string(),
    )),
    (ObjectRef::Stream, "Unit") => Ok(Value::String(
      ctx
        .stream
        .context("missing stream context")?
        .unit
        .as_str()
        .to_string(),
    )),
    (ObjectRef::Stream, "Payload") => Ok(Value::Object(ObjectRef::StreamPayload)),
    (ObjectRef::Stream, "WebSocket") => {
      if ctx
        .stream
        .context("missing stream context")?
        .websocket
        .is_some()
      {
        Ok(Value::Object(ObjectRef::StreamWebSocket))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::Stream, "WebTransport") => {
      if ctx
        .stream
        .context("missing stream context")?
        .webtransport
        .is_some()
      {
        Ok(Value::Object(ObjectRef::StreamWebTransport))
      } else {
        Ok(Value::Null)
      }
    }
    (ObjectRef::StreamPayload, "Size") => Ok(Value::Int(
      ctx
        .stream
        .context("missing stream context")?
        .payload
        .bytes
        .len() as i64,
    )),
    (ObjectRef::StreamPayload, "IsTruncated") => Ok(Value::Bool(
      ctx
        .stream
        .context("missing stream context")?
        .payload
        .is_truncated,
    )),
    (ObjectRef::StreamPayload, "Bytes") => Ok(Value::Bytes(
      ctx
        .stream
        .context("missing stream context")?
        .payload
        .bytes
        .to_vec(),
    )),
    (ObjectRef::StreamPayload, "Text") => Ok(Value::String(body_scan::body_text(
      ctx.stream.context("missing stream context")?.payload.bytes,
    ))),
    (ObjectRef::StreamWebSocket, "Opcode") => Ok(Value::String(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .opcode
        .to_string(),
    )),
    (ObjectRef::StreamWebSocket, "Fin") => Ok(Value::Bool(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .fin,
    )),
    (ObjectRef::StreamWebSocket, "IsControl") => Ok(Value::Bool(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .is_control,
    )),
    (ObjectRef::StreamWebSocket, "MessageOpcode") => Ok(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .message_opcode
        .map(|opcode| Value::String(opcode.to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::StreamWebSocket, "FramePayloadSize") => Ok(Value::Int(
      ctx
        .stream
        .and_then(|stream| stream.websocket)
        .context("missing WebSocket stream context")?
        .frame_payload_size as i64,
    )),
    (ObjectRef::StreamWebTransport, "StreamKind") => Ok(
      ctx
        .stream
        .and_then(|stream| stream.webtransport)
        .context("missing WebTransport stream context")?
        .stream_kind
        .map(|kind| Value::String(kind.as_str().to_string()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::StreamWebTransport, "StreamId") => Ok(
      ctx
        .stream
        .and_then(|stream| stream.webtransport)
        .context("missing WebTransport stream context")?
        .stream_id
        .and_then(|id| i64::try_from(id).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::StreamWebTransport, "DatagramSize") => Ok(
      ctx
        .stream
        .and_then(|stream| stream.webtransport)
        .context("missing WebTransport stream context")?
        .datagram_size
        .map(|size| Value::Int(size as i64))
        .unwrap_or(Value::Null),
    ),
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
    (ObjectRef::Request, "Normalized") => Ok(Value::Object(ObjectRef::RequestNormalized)),
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
    (ObjectRef::RequestNormalized, "Http") => Ok(Value::Object(ObjectRef::RequestNormalizedHttp)),
    (ObjectRef::RequestNormalized, "Headers") => {
      Ok(Value::Object(ObjectRef::RequestNormalizedHeaders))
    }
    (ObjectRef::RequestNormalized, "QueryParams") => {
      Ok(Value::Object(ObjectRef::RequestNormalizedQueryParams))
    }
    (ObjectRef::RequestNormalized, "Cookies") => {
      Ok(Value::Object(ObjectRef::RequestNormalizedCookies))
    }
    (ObjectRef::RequestNormalizedHttp, "Path") => {
      Ok(Value::String(normalized_http_path(ctx.request.uri)))
    }
    (ObjectRef::RequestNormalizedHttp, "Query") => {
      Ok(Value::String(normalized_http_query(ctx.request.uri)))
    }
    (ObjectRef::RequestNormalizedHttp, "Uri") => {
      Ok(Value::String(normalized_http_uri(ctx.request.uri)))
    }
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
    (ObjectRef::RequestBody, "Text") => Ok(
      ctx
        .request
        .body
        .map(|body| Value::String(body_scan::body_text(body.bytes)))
        .unwrap_or(Value::Null),
    ),
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
    (ObjectRef::ResponseBody, "Size") => {
      let response = ctx.response.context("missing response context")?;
      Ok(Value::Int(
        response
          .body
          .map(|body| body.bytes.len() as i64)
          .unwrap_or_else(|| content_length(response.headers)),
      ))
    }
    (ObjectRef::ResponseBody, "IsTruncated") => Ok(Value::Bool(
      ctx
        .response
        .and_then(|response| response.body)
        .map(|body| body.is_truncated)
        .unwrap_or(false),
    )),
    (ObjectRef::ResponseBody, "Text") => Ok(
      ctx
        .response
        .and_then(|response| response.body)
        .map(|body| Value::String(body_scan::body_text(body.bytes)))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::ResponseBody, "Bytes") => Ok(
      ctx
        .response
        .and_then(|response| response.body)
        .map(|body| Value::Bytes(body.bytes.to_vec()))
        .unwrap_or(Value::Null),
    ),
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

fn optional_string_value(value: &Option<String>) -> Value {
  value
    .as_ref()
    .map(|value| Value::String(value.clone()))
    .unwrap_or(Value::Null)
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
    Value::Object(ObjectRef::RequestNormalizedHeaders) => eval_pair_map_call(
      &normalize_header_pairs(ctx.request.headers),
      method,
      args,
      ctx,
    ),
    Value::Object(ObjectRef::ResponseHeaders) => eval_header_call(
      ctx.response.context("missing response context")?.headers,
      method,
      args,
      ctx,
    ),
    Value::Object(ObjectRef::RequestQueryParams) => eval_query_call(ctx, method, args),
    Value::Object(ObjectRef::RequestNormalizedQueryParams) => {
      eval_pair_map_call(&normalize_query_pairs(ctx.request.uri), method, args, ctx)
    }
    Value::Object(ObjectRef::RequestCookies) => eval_cookie_call(ctx, method, args),
    Value::Object(ObjectRef::RequestNormalizedCookies) => eval_pair_map_call(
      &normalize_cookie_pairs(ctx.request.headers),
      method,
      args,
      ctx,
    ),
    Value::Object(ObjectRef::RequestTags) => eval_tag_call(ctx.request.tags, method, args, ctx),
    Value::Object(ObjectRef::RequestTokenBindings) => eval_token_binding_call(ctx, method, args),
    Value::Object(ObjectRef::RequestBody) => eval_body_call(ctx.request.body, method, args, ctx),
    Value::Object(ObjectRef::ResponseBody) => eval_body_call(
      ctx.response.and_then(|response| response.body),
      method,
      args,
      ctx,
    ),
    Value::Object(ObjectRef::StreamPayload) => {
      eval_body_call(ctx.stream.map(|stream| stream.payload), method, args, ctx)
    }
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

fn eval_body_scan_result_member(
  result: body_scan::BodyScanResult,
  field: &str,
) -> anyhow::Result<Value> {
  match field {
    "Matched" => Ok(Value::Bool(result.matched)),
    "Pattern" => Ok(result.pattern.map(Value::String).unwrap_or(Value::Null)),
    "Offset" => Ok(
      result
        .offset
        .map(|offset| Value::Int(offset as i64))
        .unwrap_or(Value::Null),
    ),
    "Match" => Ok(
      result
        .matched_text
        .map(Value::String)
        .unwrap_or(Value::Null),
    ),
    "IsTruncated" => Ok(Value::Bool(result.is_truncated)),
    _ => bail!("unknown BodyScanResult property {field}"),
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
  ctx: &EvalContext<'_>,
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
    "contains" => Ok(Value::Bool(if let Some(body) = body {
      body_scan::contains(body.bytes, expect_string_arg(args, 0)?)
    } else {
      false
    })),
    "matches" => Ok(Value::Bool(
      body
        .map(|body| body_scan::matches(body.bytes, expect_string_arg(args, 0)?))
        .transpose()?
        .unwrap_or(false),
    )),
    "containsAny" | "matchesAny" => {
      let pattern_set_name = expect_string_arg(args, 0)?;
      let Some(body) = body else {
        return Ok(Value::Bool(false));
      };
      let pattern_set = ctx
        .pattern_sets
        .get(pattern_set_name)
        .ok_or_else(|| anyhow!("unknown WAF pattern set {pattern_set_name}"))?;
      Ok(Value::Bool(
        body_scan::scan_pattern_set(body.bytes, body.is_truncated, pattern_set).matched,
      ))
    }
    "scan" => {
      let pattern_set_name = expect_string_arg(args, 0)?;
      let Some(body) = body else {
        return Ok(Value::BodyScanResult(body_scan::BodyScanResult::no_match(
          false,
        )));
      };
      let pattern_set = ctx
        .pattern_sets
        .get(pattern_set_name)
        .ok_or_else(|| anyhow!("unknown WAF pattern set {pattern_set_name}"))?;
      Ok(Value::BodyScanResult(body_scan::scan_pattern_set(
        body.bytes,
        body.is_truncated,
        pattern_set,
      )))
    }
    _ => bail!("unknown BodyView method {method}"),
  }
}

fn body_content_method(method: &str) -> bool {
  matches!(
    method,
    "isFormat"
      | "isBinaryFormat"
      | "matchesFormat"
      | "contains"
      | "matches"
      | "containsAny"
      | "matchesAny"
      | "scan"
  )
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

#[cfg(test)]
mod tests;

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
