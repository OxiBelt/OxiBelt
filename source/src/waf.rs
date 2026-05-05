use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use http::header::{COOKIE, HeaderName, HeaderValue, USER_AGENT};
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::config::{Config, resolve_existing_local_config_file_path};
use crate::routes::normalize_host;

mod person_proof;

use person_proof::{PersonProofEngine, PersonProofRequestStatus, PersonProofState};

#[derive(Debug, Clone, Deserialize)]
pub struct WafConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub mode: WafMode,
  #[serde(default)]
  pub fail_policy: WafFailPolicy,
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
      limits: WafLimits::default(),
      rules: Vec::new(),
      pattern_sets: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RouteWafConfig {
  #[serde(default)]
  pub rules: Vec<WafRuleConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
  #[default]
  Enforcing,
  Monitor,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafFailPolicy {
  #[default]
  Closed,
  Open,
}

#[derive(Debug, Clone, Deserialize)]
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
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WafRuleConfig {
  pub name: String,
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
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafPhase {
  Request,
  Response,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
}

fn resolve_rule_path(rule: &mut WafRuleConfig, base_dir: &Path) -> anyhow::Result<()> {
  rule.path = rule
    .path
    .take()
    .map(|path| resolve_existing_local_config_file_path("WAF rule path", base_dir, &path))
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
  let upstream_names = config
    .upstreams
    .iter()
    .map(|upstream| upstream.name.as_str())
    .collect::<HashSet<_>>();
  validate_scope(
    "global WAF",
    &config.waf.rules,
    &config.waf.pattern_sets,
    &config.waf.limits,
    &upstream_names,
  )?;

  for route in &config.routes {
    validate_scope(
      &format!("route {} WAF", route.name),
      &route.waf.rules,
      &config.waf.pattern_sets,
      &config.waf.limits,
      &upstream_names,
    )?;
  }

  Ok(())
}

fn validate_scope(
  scope: &str,
  rules: &[WafRuleConfig],
  pattern_sets: &[WafPatternSetConfig],
  limits: &WafLimits,
  upstream_names: &HashSet<&str>,
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

    validate_actions(rule, upstream_names, limits)?;
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
      WafActionConfig::RouteToPool { .. } => {
        bail!(
          "WAF rule {} uses route_to_pool, but upstream pools are not implemented in this build",
          rule.name
        );
      }
      WafActionConfig::SetLoadBalancingPolicy { .. } => {
        bail!(
          "WAF rule {} uses set_load_balancing_policy, but load-balancing policies are not implemented in this build",
          rule.name
        );
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
        if key.len() > 128 || value.len() > 1024 {
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
    && (tag.is_empty() || tag.len() > 128)
  {
    bail!("WAF rule {rule_name} require_person_proof success_tag exceeds tag size limits");
  }
  Ok(())
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
  limits: WafLimits,
  pattern_sets: HashMap<String, CompiledPatternSet>,
  global_rules: Vec<CompiledRule>,
  route_rules: HashMap<String, Vec<CompiledRule>>,
  person_proof: PersonProofEngine,
  person_proof_tcp_max_hop: Option<u8>,
}

impl WafEngine {
  pub fn new(config: &Config) -> anyhow::Result<Self> {
    validate_config(config)?;

    let pattern_sets = compile_pattern_sets(&config.waf.pattern_sets, &config.waf.limits)?;
    let global_rules = compile_rules(&config.waf.rules)?;
    let mut route_rules = HashMap::new();
    for route in &config.routes {
      route_rules.insert(route.name.clone(), compile_rules(&route.waf.rules)?);
    }
    let person_proof = PersonProofEngine::from_config(config)?;
    let person_proof_tcp_max_hop = if config.waf.enabled {
      person_proof.tcp_max_hop()
    } else {
      None
    };

    Ok(Self {
      enabled: config.waf.enabled,
      mode: config.waf.mode,
      fail_policy: config.waf.fail_policy,
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

  pub fn evaluate_request(&self, input: WafRequestInput<'_>) -> RequestWafDecision {
    if !self.enabled {
      return RequestWafDecision::default();
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

  fn evaluate_request_inner(
    &self,
    input: WafRequestInput<'_>,
  ) -> anyhow::Result<RequestWafDecision> {
    let mut tx = TransactionBudget::new(&self.limits);
    let mut decision = RequestWafDecision::default();
    let person_proof = self.person_proof.evaluate_request(input);
    if let Some(tag) = self.person_proof.success_tag_for(&person_proof) {
      decision.tags.push((tag.to_string(), "valid".to_string()));
    }
    if let Some(mutation) = self.person_proof.clearance_cookie_mutation(&person_proof)? {
      decision.response_header_mutations.push(mutation);
    }
    let ctx = EvalContext {
      phase: WafPhase::Request,
      mode: self.mode,
      rule_name: "",
      request: input,
      response: None,
      person_proof: &person_proof,
      pattern_sets: &self.pattern_sets,
      limits: &self.limits,
    };

    for rule in self.rules_for(input.route_name, WafPhase::Request) {
      tx.check_total()?;
      let matched = self.evaluate_rule(rule, &ctx, &mut tx)?;
      if !matched {
        continue;
      }
      debug!(rule = %rule.name, phase = "request", "WAF rule matched");
      if self.mode == WafMode::Monitor {
        continue;
      }
      apply_request_actions(rule, input, &self.person_proof, &mut decision, &mut tx)?;
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
    let mut tx = TransactionBudget::new(&self.limits);
    let mut decision = ResponseWafDecision::default();
    let person_proof = self.person_proof.evaluate_request(input.request);
    let ctx = EvalContext {
      phase: WafPhase::Response,
      mode: self.mode,
      rule_name: "",
      request: input.request,
      response: Some(input),
      person_proof: &person_proof,
      pattern_sets: &self.pattern_sets,
      limits: &self.limits,
    };

    for rule in self.rules_for(input.request.route_name, WafPhase::Response) {
      tx.check_total()?;
      let matched = self.evaluate_rule(rule, &ctx, &mut tx)?;
      if !matched {
        continue;
      }
      debug!(rule = %rule.name, phase = "response", "WAF rule matched");
      if self.mode == WafMode::Monitor {
        continue;
      }
      apply_response_actions(rule, &mut decision, &mut tx)?;
      if decision.terminal.is_some() {
        return Ok(decision);
      }
    }

    Ok(decision)
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

fn compile_rules(configs: &[WafRuleConfig]) -> anyhow::Result<Vec<CompiledRule>> {
  configs
    .iter()
    .map(|rule| {
      let expression = Parser::new(rule.when.as_deref().unwrap_or_default())
        .parse()
        .with_context(|| format!("failed to compile WAF rule {}", rule.name))?;
      Ok(CompiledRule {
        name: rule.name.clone(),
        phase: rule.phase,
        priority: rule.priority,
        expression,
        actions: rule.actions.clone(),
      })
    })
    .collect()
}

#[derive(Clone)]
struct CompiledRule {
  name: String,
  phase: WafPhase,
  priority: i64,
  expression: Expr,
  actions: Vec<WafActionConfig>,
}

#[derive(Clone)]
enum CompiledPatternSet {
  Contains(Vec<String>),
  Regex(Vec<Regex>),
}

#[derive(Debug, Clone, Copy)]
pub struct WafRequestInput<'a> {
  pub method: &'a Method,
  pub uri: &'a Uri,
  pub version: Version,
  pub headers: &'a HeaderMap,
  pub peer_addr: std::net::SocketAddr,
  pub downstream_host: &'a str,
  pub route_name: &'a str,
  pub tcp_max_hop: Option<u8>,
  pub tls: &'a WafTlsMetadata,
  pub protocol: WafProtocol,
  pub transport_network: WafTransportNetwork,
  pub tags: &'a HashMap<String, String>,
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
  pub status: StatusCode,
  pub headers: &'a HeaderMap,
  pub upstream_name: &'a str,
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
}

#[derive(Debug, Default)]
pub struct ResponseWafDecision {
  pub terminal: Option<WafTerminalResponse>,
  pub response_header_mutations: Vec<HeaderMutation>,
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
      WafActionConfig::Reject { status, body } => {
        decision.terminal = Some(WafTerminalResponse::new(
          StatusCode::from_u16(*status)?,
          body.clone().unwrap_or_else(|| "Blocked by WAF".to_string()),
        ));
        return Ok(());
      }
      WafActionConfig::SetRequestHeader { name, value } => {
        decision.request_header_mutations.push(HeaderMutation::Set {
          name: HeaderName::from_bytes(name.as_bytes())?,
          value: HeaderValue::from_str(value)?,
        });
      }
      WafActionConfig::RemoveRequestHeader { name } => {
        decision
          .request_header_mutations
          .push(HeaderMutation::Remove {
            name: HeaderName::from_bytes(name.as_bytes())?,
          });
      }
      WafActionConfig::SetTag { key, value } => {
        decision.tags.push((key.clone(), value.clone()));
      }
      WafActionConfig::RouteToUpstream { upstream } => {
        decision.upstream_override = Some(upstream.clone());
      }
      WafActionConfig::RequirePersonProof {
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
      } => {
        decision.terminal = Some(person_proof.issue_challenge(
          input,
          person_proof::PersonProofPolicy {
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
          },
        )?);
        return Ok(());
      }
      WafActionConfig::RouteToPool { .. }
      | WafActionConfig::SetLoadBalancingPolicy { .. }
      | WafActionConfig::ContinueResponse
      | WafActionConfig::ReplaceResponse { .. }
      | WafActionConfig::RejectResponse { .. }
      | WafActionConfig::SetResponseHeader { .. }
      | WafActionConfig::RemoveResponseHeader { .. } => {
        bail!("invalid request-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(())
}

fn apply_response_actions(
  rule: &CompiledRule,
  decision: &mut ResponseWafDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<()> {
  for action in &rule.actions {
    tx.count_mutation()?;
    match action {
      WafActionConfig::ContinueResponse => return Ok(()),
      WafActionConfig::ReplaceResponse { status, body }
      | WafActionConfig::RejectResponse { status, body } => {
        decision.terminal = Some(WafTerminalResponse::new(
          StatusCode::from_u16(*status)?,
          body.clone().unwrap_or_else(|| "Blocked by WAF".to_string()),
        ));
        return Ok(());
      }
      WafActionConfig::SetResponseHeader { name, value } => {
        decision
          .response_header_mutations
          .push(HeaderMutation::Set {
            name: HeaderName::from_bytes(name.as_bytes())?,
            value: HeaderValue::from_str(value)?,
          });
      }
      WafActionConfig::RemoveResponseHeader { name } => {
        decision
          .response_header_mutations
          .push(HeaderMutation::Remove {
            name: HeaderName::from_bytes(name.as_bytes())?,
          });
      }
      WafActionConfig::Reject { .. }
      | WafActionConfig::RouteToPool { .. }
      | WafActionConfig::RouteToUpstream { .. }
      | WafActionConfig::SetLoadBalancingPolicy { .. }
      | WafActionConfig::SetRequestHeader { .. }
      | WafActionConfig::RemoveRequestHeader { .. }
      | WafActionConfig::SetTag { .. }
      | WafActionConfig::RequirePersonProof { .. } => {
        bail!("invalid response-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(())
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
  request: WafRequestInput<'a>,
  response: Option<WafResponseInput<'a>>,
  person_proof: &'a PersonProofRequestStatus,
  pattern_sets: &'a HashMap<String, CompiledPatternSet>,
  limits: &'a WafLimits,
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
  Null,
  Object(ObjectRef),
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
  let object = match value {
    Value::Object(object) => object,
    Value::Null => bail!("attempted to access {field} on null"),
    _ => bail!("cannot access member {field} on {:?}", value),
  };

  match (object, field) {
    (ObjectRef::Context, "Phase") => Ok(Value::String(match ctx.phase {
      WafPhase::Request => "request".to_string(),
      WafPhase::Response => "response".to_string(),
    })),
    (ObjectRef::Context, "RuleName") => Ok(Value::String(ctx.rule_name.to_string())),
    (ObjectRef::Context, "RouteName") => Ok(Value::String(ctx.request.route_name.to_string())),
    (ObjectRef::Context, "TransactionId") => Ok(Value::String(String::new())),
    (ObjectRef::Context, "Mode") => Ok(Value::String(match ctx.mode {
      WafMode::Enforcing => "enforcing".to_string(),
      WafMode::Monitor => "monitor".to_string(),
    })),
    (ObjectRef::Request, "Id") => Ok(Value::String(String::new())),
    (ObjectRef::Request, "ReceivedAtUnixMs") => Ok(Value::Int(0)),
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
    (ObjectRef::RequestClient, "UserAgent") => header_single(ctx.request.headers, USER_AGENT),
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
    (ObjectRef::RequestHttp, "Scheme") => Ok(Value::String("https".to_string())),
    (ObjectRef::RequestHttp, "Host") => Ok(Value::String(ctx.request.downstream_host.to_string())),
    (ObjectRef::RequestHttp, "Path") => Ok(Value::String(ctx.request.uri.path().to_string())),
    (ObjectRef::RequestHttp, "Query") => Ok(Value::String(
      ctx.request.uri.query().unwrap_or_default().to_string(),
    )),
    (ObjectRef::RequestHttp, "Uri") => Ok(Value::String(ctx.request.uri.to_string())),
    (ObjectRef::RequestHttp, "Body") => Ok(Value::Object(ObjectRef::RequestBody)),
    (ObjectRef::RequestBody, "Size") => Ok(Value::Int(content_length(ctx.request.headers))),
    (ObjectRef::RequestBody, "IsTruncated") => Ok(Value::Bool(false)),
    (ObjectRef::RequestBody, "Text") | (ObjectRef::RequestBody, "Bytes") => Ok(Value::Null),
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
    (ObjectRef::Response, "Id") => Ok(Value::String(String::new())),
    (ObjectRef::Response, "ReceivedAtUnixMs") => Ok(Value::Int(0)),
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
    (ObjectRef::ResponseHttp, "Version") => Ok(Value::String("1.1".to_string())),
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
    (ObjectRef::ResponseUpstream, "Name") => Ok(Value::String(
      ctx
        .response
        .context("missing response context")?
        .upstream_name
        .to_string(),
    )),
    (ObjectRef::ResponseUpstream, "Pool") => Ok(Value::String(String::new())),
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
    Value::Object(ObjectRef::RequestBody) | Value::Object(ObjectRef::ResponseBody) => {
      eval_body_call(method)
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
    )?),
    "anyNameMatches" => {
      let regex = Regex::new(expect_string_arg(args, 0)?)?;
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
      let name_regex = Regex::new(expect_string_arg(args, 0)?)?;
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
      let name_regex = Regex::new(expect_string_arg(args, 0)?)?;
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

fn eval_query_call(ctx: &EvalContext<'_>, method: &str, args: &[Value]) -> anyhow::Result<Value> {
  let query = ctx.request.uri.query().unwrap_or_default();
  let pairs = url::form_urlencoded::parse(query.as_bytes())
    .take(ctx.limits.max_helper_items)
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect::<Vec<_>>();
  eval_pair_map_call(&pairs, method, args)
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
  eval_pair_map_call(&pairs, method, args)
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
) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(pairs.len() as i64)),
    "has" => {
      let name = expect_string_arg(args, 0)?;
      Ok(Value::Bool(pairs.iter().any(|(key, _)| key == name)))
    }
    "get" => {
      let name = expect_string_arg(args, 0)?;
      Ok(
        pairs
          .iter()
          .find(|(key, _)| key == name)
          .map(|(_, value)| Value::String(value.clone()))
          .unwrap_or(Value::Null),
      )
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

fn eval_body_call(method: &str) -> anyhow::Result<Value> {
  match method {
    "contains" | "matches" | "containsAny" | "matchesAny" | "scan" => bail!(
      "body content inspection is reserved for a streaming-safe WAF body buffer implementation"
    ),
    _ => bail!("unknown BodyView method {method}"),
  }
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

fn header_single(headers: &HeaderMap, name: HeaderName) -> anyhow::Result<Value> {
  Ok(
    headers
      .get(name)
      .and_then(|value| value.to_str().ok())
      .map(|value| Value::String(value.to_string()))
      .unwrap_or(Value::Null),
  )
}

fn content_length(headers: &HeaderMap) -> i64 {
  headers
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<i64>().ok())
    .unwrap_or(0)
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
