//! WAF configuration, compilation, and evaluation for inspected requests, responses, and streams.
use anyhow::{Context, anyhow, bail};
use http::header::{HeaderName, HeaderValue, USER_AGENT};
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use online_dsl_forge::{
  BinaryOp as ForgeBinaryOp, CompiledRegexCache as ForgeCompiledRegexCache,
  RegexFlavor as ForgeRegexFlavor, UnaryOp as ForgeUnaryOp, VerifiedExprKindRef,
  VerifiedExpression,
};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use crate::config::{
  AccessTokenRateLimitSource, Config, LimitMode, MitigationFailurePolicy, RateLimitIdentityPart,
  RateLimitKey, resolve_existing_local_config_file_path_with_logical,
};
use crate::dynamic_policy::DynamicPolicyContext;
use crate::limits::{LimitState, RateLimitCheck, RateLimitContext};
use crate::mitigation::MitigationSink;
use crate::shared_state::SharedState;

mod access_log_record;
mod async_evaluation;
mod binary_format;
mod body_cache;
mod body_eval;
mod body_scan;
mod crs;
mod defaults;
mod devtools;
mod expression;
mod external_files;
mod functions;
mod http_body_compression;
mod lb_policy_compat;
mod malicious_intelligence_score;
pub mod metadata;
mod mitigation_action;
pub(crate) mod normalization;
mod object_model;
mod pattern_set;
mod person_proof;
mod person_proof_admin;
mod person_proof_api;
mod person_proof_config;
mod person_proof_dynamic;
mod person_proof_policy;
mod person_proof_request;
mod person_proof_reuse;
mod person_proof_v2;
mod plan;
mod request_header_mutation;
mod rule_groups;
mod rulepacks;
mod runtime_helpers;

use access_log_record::AccessLogJsonValue;
pub use access_log_record::AccessLogRecord;
use binary_format::bytes_match_format;
use body_cache::{BodyTextCaches, BodyTextSlot};
use body_eval::eval_body_call;
pub use crs::{CrsCompatibilityMatrix, compatibility_matrix as crs_compatibility_matrix};
use crs::{CrsDecision, CrsEngine, WafCrsConfig, validate_crs_config};
use defaults::*;
pub use devtools::*;
use expression::{Expr, Parser};
pub use functions::WafFunctionConfig;
use functions::{FunctionMap, compile_global_functions, compile_route_functions};
pub(crate) use http_body_compression::route_http_body_compression_transform_enabled;
use http_body_compression::validate_http_body_compression_config;
pub use http_body_compression::{
  RouteWafHttpBodyCompressionConfig, RouteWafHttpBodyCompressionMode, WafHttpBodyCompressionConfig,
  WafHttpBodyCompressionMode, WafHttpBodyEncoding,
};
use malicious_intelligence_score as mi_score;
pub use metadata::{WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork};
pub use mitigation_action::MitigationIntent;
use mitigation_action::{
  CompiledMitigationAction, apply_mitigation_http_action, apply_mitigation_stream_action,
  compile_mitigation_action, validate_mitigation_action,
};
use normalization::{
  normalize_cookie_pairs, normalize_header_pairs, normalize_query_pairs, normalized_http_path,
  normalized_http_query, normalized_http_uri,
};
use object_model::{eval_request_cookie_call, eval_response_cookie_call};
pub(crate) use pattern_set::CompiledPatternSet;
use pattern_set::{compile_pattern_sets, validate_pattern_sets};
pub use person_proof::PersonProofIssuedClearance;
use person_proof::{
  PersonProofEngine, PersonProofPolicy, PersonProofRequestStatus, PersonProofState,
};
pub use person_proof_admin::{
  PersonProofAdminClearancePage, PersonProofAdminRevokeResult, PersonProofAdminStatus,
};
pub use person_proof_api::{
  PERSON_PROOF_API_VERSION, PersonProofApiPathRole, PersonProofSessionDocument,
};
pub use person_proof_config::{
  PersonProofClearanceConfig, PersonProofClearanceCookieConfig, PersonProofClearanceIssueTarget,
  PersonProofClearanceLocalStorageConfig, PersonProofClearanceSameSite,
  PersonProofClearanceSourceConfig, PersonProofMode, PersonProofThirdPartyProvider,
  WafPersonProofConfig,
};
use person_proof_policy::PersonProofPolicyState;
pub use person_proof_request::{EvaluatedPersonProofRequest, PersonProofRequestSnapshot};
pub use person_proof_v2::PersonProofProviderChallenge;
pub use plan::BodyNeed;
use plan::{WafRoutePlan, phase_plan};
use rule_groups::{RuleGroupScope, resolve_rule, validate_rule_group_scope};
pub use rule_groups::{WafConditionMerge, WafRuleGroupConfig};
pub use rulepacks::{
  RULEPACK_FILE_SUFFIX, RulepackActionSelector, RulepackBinding, RulepackBindingKind,
  RulepackDiscovery, RulepackException, RulepackInputMetadata, RulepackModeOverride,
  RulepackOverride, RulepackOverrideSelector, RulepackProfile, RulepackReferencedFile,
  RulepackReferencedFileKind, RulepackRenderOptions, RulepackSourceProvenance, RulepackVariable,
  WafRulepackSummary, inspect_rulepack, inspect_rulepack_inputs, referenced_rulepack_files,
  render_rulepack_for_install, validate_rulepack_exception_list, validate_rulepack_manifest,
  validate_rulepack_overrides,
};
use runtime_helpers::{
  body_size, ip_in_cidr, pattern_set_matches, request_metadata_has_duplicates, version_string,
};
pub use runtime_helpers::{normalized_downstream_host, request_protocol};

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
  pub http_body_compression: WafHttpBodyCompressionConfig,
  #[serde(default)]
  pub limits: WafLimits,
  #[serde(default)]
  pub crs: WafCrsConfig,
  #[serde(default)]
  pub person_proof: WafPersonProofConfig,
  #[serde(default)]
  pub functions: Vec<WafFunctionConfig>,
  #[serde(default)]
  pub rulepack_files: Vec<PathBuf>,
  #[serde(default)]
  pub rule_group_files: Vec<PathBuf>,
  #[serde(default)]
  pub rule_groups: Vec<WafRuleGroupConfig>,
  #[serde(default)]
  pub rules: Vec<WafRuleConfig>,
  #[serde(default)]
  pub pattern_sets: Vec<WafPatternSetConfig>,
  #[serde(skip)]
  rulepack_base_dir: Option<PathBuf>,
  #[serde(skip)]
  rulepack_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  rulepack_files_logical: Vec<PathBuf>,
  #[serde(skip)]
  loaded_rulepacks: Vec<WafRulepackSummary>,
  #[serde(skip)]
  rule_group_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  rule_group_files_logical: Vec<PathBuf>,
}

impl Default for WafConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: WafMode::Enforcing,
      fail_policy: WafFailPolicy::Closed,
      duplicate_metadata_policy: WafDuplicateMetadataPolicy::FailClosed,
      http_body_compression: WafHttpBodyCompressionConfig::default(),
      limits: WafLimits::default(),
      crs: WafCrsConfig::default(),
      person_proof: WafPersonProofConfig::default(),
      functions: Vec::new(),
      rulepack_files: Vec::new(),
      rule_group_files: Vec::new(),
      rule_groups: Vec::new(),
      rules: Vec::new(),
      pattern_sets: Vec::new(),
      rulepack_base_dir: None,
      rulepack_files_resolved: Vec::new(),
      rulepack_files_logical: Vec::new(),
      loaded_rulepacks: Vec::new(),
      rule_group_files_resolved: Vec::new(),
      rule_group_files_logical: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteWafConfig {
  #[serde(default)]
  pub http_body_compression: RouteWafHttpBodyCompressionConfig,
  #[serde(default)]
  pub functions: Vec<WafFunctionConfig>,
  #[serde(default)]
  pub rulepack_files: Vec<PathBuf>,
  #[serde(default)]
  pub rule_group_files: Vec<PathBuf>,
  #[serde(default)]
  pub rule_groups: Vec<WafRuleGroupConfig>,
  #[serde(default)]
  pub rules: Vec<WafRuleConfig>,
  #[serde(skip)]
  rulepack_base_dir: Option<PathBuf>,
  #[serde(skip)]
  rulepack_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  rulepack_files_logical: Vec<PathBuf>,
  #[serde(skip)]
  loaded_rulepacks: Vec<WafRulepackSummary>,
  #[serde(skip)]
  rule_group_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  rule_group_files_logical: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
  pub merge_condition_as: WafConditionMerge,
  #[serde(default)]
  pub path: Option<PathBuf>,
  #[serde(default)]
  pub groups: Vec<String>,
  #[serde(default)]
  pub actions: Vec<WafActionConfig>,
  #[serde(skip)]
  pub local_rule_groups: Vec<WafRuleGroupConfig>,
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
    #[serde(default)]
    priority: i64,
    status: u16,
    #[serde(default)]
    body: Option<String>,
  },
  SilentClose {
    #[serde(default)]
    priority: i64,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    websocket_code: Option<u16>,
    #[serde(default)]
    webtransport_code: Option<u32>,
    #[serde(default)]
    reason: Option<String>,
  },
  ContinueResponse {
    #[serde(default)]
    priority: i64,
  },
  ReplaceResponse {
    #[serde(default)]
    priority: i64,
    status: u16,
    #[serde(default)]
    body: Option<String>,
  },
  RejectResponse {
    #[serde(default)]
    priority: i64,
    status: u16,
    #[serde(default)]
    body: Option<String>,
  },
  EmitAccessLog {
    #[serde(default)]
    priority: i64,
    #[serde(default = "default_access_log_field_configs")]
    fields: Vec<AccessLogFieldConfig>,
  },
  EmitMitigation {
    #[serde(default)]
    priority: i64,
    intent: MitigationIntent,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    target_prefix: Option<String>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    dedupe_window_ms: Option<u64>,
    #[serde(default)]
    min_count: Option<u64>,
    #[serde(default)]
    failure_policy: Option<MitigationFailurePolicy>,
    #[serde(default = "default_mitigation_fail_status")]
    fail_closed_status: u16,
    #[serde(default)]
    fail_closed_body: Option<String>,
    #[serde(default = "default_websocket_close_code")]
    fail_closed_websocket_code: u16,
    #[serde(default = "default_webtransport_close_code")]
    fail_closed_webtransport_code: u32,
    #[serde(default = "default_stream_close_reason")]
    fail_closed_stream_reason: String,
    #[serde(default)]
    fields: Vec<AccessLogFieldConfig>,
  },
  RouteToPool {
    #[serde(default)]
    priority: i64,
    pool: String,
  },
  RouteToUpstream {
    #[serde(default)]
    priority: i64,
    upstream: String,
  },
  SetLoadBalancingPolicy {
    #[serde(default)]
    priority: i64,
    policy: String,
  },
  SetRequestHeader {
    #[serde(default)]
    priority: i64,
    name: String,
    value: String,
  },
  RemoveRequestHeader {
    #[serde(default)]
    priority: i64,
    name: String,
  },
  SetResponseHeader {
    #[serde(default)]
    priority: i64,
    name: String,
    value: String,
  },
  RemoveResponseHeader {
    #[serde(default)]
    priority: i64,
    name: String,
  },
  SetTag {
    #[serde(default)]
    priority: i64,
    key: String,
    value: String,
  },
  RateLimit {
    #[serde(default)]
    priority: i64,
    name: String,
    #[serde(default)]
    key: RateLimitKey,
    #[serde(default = "crate::limits::default_rate_limit_ipv4_prefix_bits")]
    ipv4_prefix_bits: u8,
    #[serde(default = "crate::limits::default_rate_limit_ipv6_prefix_bits")]
    ipv6_prefix_bits: u8,
    #[serde(default)]
    identity_parts: Vec<RateLimitIdentityPart>,
    #[serde(default)]
    token_bindings: Vec<PersonProofTokenBinding>,
    #[serde(default)]
    token_header: Option<String>,
    #[serde(default)]
    access_token_source: Option<AccessTokenRateLimitSource>,
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
  WeighPersonProof {
    #[serde(default)]
    priority: i64,
    weight: i64,
  },
  AllowPersonProof {
    #[serde(default)]
    priority: i64,
  },
  RequirePersonProof {
    #[serde(default)]
    priority: i64,
    #[serde(default)]
    person_proof_mode: PersonProofMode,
    #[serde(default = "default_person_proof_difficulty")]
    difficulty: u8,
    #[serde(
      rename = "token_validity_seconds",
      default = "default_person_proof_token_validity_seconds",
      alias = "ttl_seconds",
      alias = "token_ttl_seconds"
    )]
    ttl_seconds: u64,
    #[serde(default)]
    cookie: Option<String>,
    #[serde(default)]
    clearance: Box<PersonProofClearanceConfig>,
    #[serde(default = "default_person_proof_token_bindings")]
    token_bindings: Vec<PersonProofTokenBinding>,
    #[serde(default = "default_person_proof_direct_peer_ipv4_prefix_bits")]
    direct_peer_ipv4_prefix_bits: u8,
    #[serde(default = "default_person_proof_direct_peer_ipv6_prefix_bits")]
    direct_peer_ipv6_prefix_bits: u8,
    #[serde(default)]
    tcp_max_hop: Option<u8>,
    #[serde(default = "default_person_proof_single_use")]
    single_use: bool,
    #[serde(default)]
    success_tag: Option<String>,
    #[serde(default = "default_person_proof_status")]
    status: u16,
    #[serde(default)]
    custom_frontend_url: Option<String>,
    #[serde(default = "default_person_proof_challenge_redirect_status")]
    challenge_redirect_status: u16,
    #[serde(default)]
    session_path: Option<String>,
    #[serde(default)]
    verify_path: Option<String>,
    #[serde(default)]
    openapi_path: Option<String>,
    #[serde(default)]
    third_party_provider: Option<PersonProofThirdPartyProvider>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    provider_metadata: Box<serde_json::Value>,
    #[serde(default)]
    proof_kind: Option<Box<str>>,
    #[serde(default)]
    proof_challenge_kind: Option<Box<str>>,
    #[serde(default)]
    proof_label: Option<Box<str>>,
    #[serde(default)]
    site_key: Option<String>,
    #[serde(default)]
    secret_env: Option<String>,
    #[serde(default)]
    provider_endpoint: Option<Box<url::Url>>,
    #[serde(default = "default_person_proof_provider_timeout_ms")]
    provider_timeout_ms: u64,
    #[serde(default)]
    provider_fail_policy: PersonProofProviderFailPolicy,
    #[serde(default = "default_person_proof_provider_max_response_body_bytes")]
    provider_max_response_body_bytes: usize,
    #[serde(default = "default_true")]
    send_remote_ip: bool,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    challenge_url: Option<String>,
  },
  CloseStream {
    #[serde(default)]
    priority: i64,
    #[serde(default = "default_websocket_close_code")]
    websocket_code: u16,
    #[serde(default = "default_webtransport_close_code")]
    webtransport_code: u32,
    #[serde(default = "default_stream_close_reason")]
    reason: String,
  },
}

impl WafActionConfig {
  pub(super) fn priority(&self) -> i64 {
    match self {
      Self::Reject { priority, .. }
      | Self::SilentClose { priority, .. }
      | Self::ContinueResponse { priority }
      | Self::ReplaceResponse { priority, .. }
      | Self::RejectResponse { priority, .. }
      | Self::EmitAccessLog { priority, .. }
      | Self::EmitMitigation { priority, .. }
      | Self::RouteToPool { priority, .. }
      | Self::RouteToUpstream { priority, .. }
      | Self::SetLoadBalancingPolicy { priority, .. }
      | Self::SetRequestHeader { priority, .. }
      | Self::RemoveRequestHeader { priority, .. }
      | Self::SetResponseHeader { priority, .. }
      | Self::RemoveResponseHeader { priority, .. }
      | Self::SetTag { priority, .. }
      | Self::RateLimit { priority, .. }
      | Self::WeighPersonProof { priority, .. }
      | Self::AllowPersonProof { priority }
      | Self::RequirePersonProof { priority, .. }
      | Self::CloseStream { priority, .. } => *priority,
    }
  }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct AccessLogFieldConfig {
  pub name: String,
  #[serde(alias = "expression")]
  pub value: String,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PersonProofProviderFailPolicy {
  #[default]
  Closed,
  Open,
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
  #[serde(default)]
  pub when: Option<String>,
  #[serde(default)]
  pub merge_condition_as: WafConditionMerge,
  #[serde(default)]
  pub groups: Vec<String>,
  #[serde(default)]
  pub rule_groups: Vec<WafRuleGroupConfig>,
  #[serde(default)]
  pub actions: Vec<WafActionConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalRuleGroupFile {
  #[serde(default)]
  rule_groups: Vec<WafRuleGroupConfig>,
}

fn resolve_rule_group_file_paths(
  field_name: &str,
  base_dir: &Path,
  paths: &[PathBuf],
) -> anyhow::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
  if paths.is_empty() {
    return Ok((Vec::new(), Vec::new()));
  }
  let canonical_base = base_dir
    .canonicalize()
    .with_context(|| format!("failed to resolve OxiRule directory {}", base_dir.display()))?;
  let mut resolved = Vec::new();
  let mut logical = Vec::new();
  for path in paths {
    if path_has_glob_pattern(path)? {
      let pattern_path = crate::config::resolve_local_config_file_path(field_name, base_dir, path)?;
      let pattern = pattern_path.to_str().ok_or_else(|| {
        anyhow!(
          "{field_name} entry is not valid UTF-8: {}",
          pattern_path.display()
        )
      })?;
      let mut matched = Vec::new();
      for candidate in glob::glob(pattern)
        .with_context(|| format!("invalid {field_name} glob {}", path.display()))?
      {
        let candidate = candidate
          .with_context(|| format!("failed to expand {field_name} glob {}", path.display()))?;
        if candidate.is_file() {
          let canonical = crate::config::canonicalize_existing_file(field_name, &candidate)?;
          if !canonical.starts_with(&canonical_base) {
            bail!("{field_name} entries must stay within the OxiRule directory");
          }
          matched.push((canonical, candidate));
        }
      }
      matched.sort_by(|left, right| left.0.cmp(&right.0));
      for (canonical, candidate) in matched {
        resolved.push(canonical);
        logical.push(candidate);
      }
    } else {
      let (canonical, candidate) =
        resolve_existing_local_config_file_path_with_logical(field_name, base_dir, path)?;
      resolved.push(canonical);
      logical.push(candidate);
    }
  }
  Ok((resolved, logical))
}

fn path_has_glob_pattern(path: &Path) -> anyhow::Result<bool> {
  let value = path.to_str().ok_or_else(|| {
    anyhow!(
      "OxiRule group file path is not valid UTF-8: {}",
      path.display()
    )
  })?;
  Ok(value.chars().any(|ch| matches!(ch, '*' | '?' | '[')))
}

fn load_external_rule_groups(
  scope: &str,
  paths: &[PathBuf],
) -> anyhow::Result<Vec<WafRuleGroupConfig>> {
  let mut groups = Vec::new();
  for path in paths {
    let raw = std::fs::read_to_string(path)
      .with_context(|| format!("failed to read OxiRule group file {}", path.display()))?;
    let external: ExternalRuleGroupFile = toml::from_str(&raw)
      .with_context(|| format!("failed to parse OxiRule group file {}", path.display()))?;
    if external.rule_groups.is_empty() {
      bail!(
        "{scope} OxiRule group file {} must contain at least one [[rule_groups]] entry",
        path.display()
      );
    }
    groups.extend(external.rule_groups);
  }
  Ok(groups)
}

pub fn validate_external_rule_group_file(raw: &str) -> anyhow::Result<()> {
  let external: ExternalRuleGroupFile =
    toml::from_str(raw).context("failed to parse OxiRule group file")?;
  if external.rule_groups.is_empty() {
    bail!("OxiRule group file must contain at least one [[rule_groups]] entry");
  }
  validate_rule_group_scope("OxiRule group file", &external.rule_groups)
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

  if rule.when.is_some()
    || rule.merge_condition_as != WafConditionMerge::And
    || !rule.groups.is_empty()
    || !rule.actions.is_empty()
  {
    bail!(
      "WAF rule {} external path cannot be combined with inline when, merge_condition_as, groups, or actions",
      rule.name
    );
  }

  let raw = std::fs::read_to_string(&path)
    .with_context(|| format!("failed to read WAF rule file {}", path.display()))?;
  let external: ExternalRuleFile = toml::from_str(&raw)
    .with_context(|| format!("failed to parse WAF rule file {}", path.display()))?;

  rule.when = external.when;
  rule.merge_condition_as = external.merge_condition_as;
  rule.groups = external.groups;
  rule.local_rule_groups = external.rule_groups;
  rule.actions = external.actions;
  rule.loaded_from_path = Some(path);
  Ok(())
}

pub fn validate_config(config: &Config) -> anyhow::Result<()> {
  validate_http_body_compression_config(config)?;
  if config.waf.limits.max_person_proof_reuse_tokens == 0 {
    bail!("waf.limits.max_person_proof_reuse_tokens must be greater than 0");
  }
  if has_emit_mitigation_actions(config) && !config.database.mitigation.enabled {
    bail!("emit_mitigation actions require database.mitigation.enabled = true");
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
  validate_rule_group_scope("global WAF", &config.waf.rule_groups)?;
  let global_validation = WafValidationContext {
    pattern_sets: &config.waf.pattern_sets,
    global_rule_groups: &config.waf.rule_groups,
    route_rule_groups: None,
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
    validate_rule_group_scope(&format!("route {} WAF", route.name), &route.waf.rule_groups)?;
    let route_validation = WafValidationContext {
      pattern_sets: &config.waf.pattern_sets,
      global_rule_groups: &config.waf.rule_groups,
      route_rule_groups: Some(&route.waf.rule_groups),
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
  person_proof_config::validate_api_paths(config)?;

  Ok(())
}

fn has_emit_mitigation_actions(config: &Config) -> bool {
  fn action_is_mitigation(action: &WafActionConfig) -> bool {
    matches!(action, WafActionConfig::EmitMitigation { .. })
  }
  fn rule_has_mitigation(rule: &WafRuleConfig) -> bool {
    rule.actions.iter().any(action_is_mitigation)
      || rule
        .local_rule_groups
        .iter()
        .any(|group| group.actions.iter().any(action_is_mitigation))
  }

  config.waf.rules.iter().any(rule_has_mitigation)
    || config
      .routes
      .iter()
      .any(|route| route.waf.rules.iter().any(rule_has_mitigation))
    || config
      .waf
      .rule_groups
      .iter()
      .any(|group| group.actions.iter().any(action_is_mitigation))
    || config.routes.iter().any(|route| {
      route
        .waf
        .rule_groups
        .iter()
        .any(|group| group.actions.iter().any(action_is_mitigation))
    })
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
  global_rule_groups: &'a [WafRuleGroupConfig],
  route_rule_groups: Option<&'a [WafRuleGroupConfig]>,
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
    validate_rule_group_scope(
      &format!("{scope} rule {} external file", rule.name),
      &rule.local_rule_groups,
    )?;
    if let Some(expression) = rule.when.as_deref() {
      Parser::new(expression)
        .parse()
        .with_context(|| format!("failed to parse WAF rule {} expression", rule.name))?;
    }
    let resolved = resolve_rule(
      scope,
      rule,
      RuleGroupScope {
        global: ctx.global_rule_groups,
        route: ctx.route_rule_groups,
      },
    )?;
    let expression = resolved.when.as_str();
    let ast = Parser::new(expression)
      .parse()
      .with_context(|| format!("failed to parse WAF rule {} expression", rule.name))?;
    ast
      .validate_for_phase_with_functions(rule.phase, ctx.global_functions, ctx.route_functions)
      .with_context(|| format!("invalid WAF rule {} expression", rule.name))?;

    validate_actions(
      rule,
      &resolved.actions,
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

fn validate_actions(
  rule: &WafRuleConfig,
  actions: &[WafActionConfig],
  upstream_names: &HashSet<&str>,
  pool_names: &HashSet<&str>,
  limits: &WafLimits,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<()> {
  let mut mutations = 0usize;
  for action in actions {
    if action.priority() < 0 {
      bail!(
        "WAF rule {} action priority must not be negative",
        rule.name
      );
    }
    match action {
      WafActionConfig::Reject { status, .. } => {
        require_phase(rule, WafPhase::Request, "reject")?;
        validate_status(*status, &rule.name)?;
      }
      WafActionConfig::SilentClose {
        status,
        body,
        websocket_code,
        webtransport_code,
        reason,
        ..
      } => {
        if status.is_some()
          || body.is_some()
          || websocket_code.is_some()
          || webtransport_code.is_some()
          || reason.is_some()
        {
          bail!("WAF rule {} silent_close supports only priority", rule.name);
        }
      }
      WafActionConfig::ContinueResponse { .. } => {
        require_phase(rule, WafPhase::Response, "continue_response")?;
      }
      WafActionConfig::ReplaceResponse { status, .. }
      | WafActionConfig::RejectResponse { status, .. } => {
        require_phase(rule, WafPhase::Response, "response terminal action")?;
        validate_status(*status, &rule.name)?;
      }
      WafActionConfig::EmitAccessLog { fields, .. } => {
        require_phase(rule, WafPhase::Response, "emit_access_log")?;
        validate_access_log_field_configs_with_functions(
          &format!("WAF rule {} emit_access_log", rule.name),
          fields,
          global_functions,
          route_functions,
        )?;
      }
      WafActionConfig::EmitMitigation { .. } => {
        validate_mitigation_action(rule, action, global_functions, route_functions)?;
        mutations += 1;
      }
      WafActionConfig::RouteToUpstream { upstream, .. } => {
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
      WafActionConfig::RouteToPool { pool, .. } => {
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
      WafActionConfig::SetLoadBalancingPolicy { policy, .. } => {
        require_phase(rule, WafPhase::Request, "set_load_balancing_policy")?;
        if !matches!(
          policy.as_str(),
          "power_of_two_choices"
            | "weighted_least_conn"
            | "rendezvous_hash"
            | "rendezvous_ip_hash"
            | "ewma"
            | "least_time"
        ) {
          bail!(
            "WAF rule {} set_load_balancing_policy uses unsupported policy {}",
            rule.name,
            policy
          );
        }
        mutations += 1;
      }
      WafActionConfig::SetRequestHeader { name, value, .. } => {
        require_phase(rule, WafPhase::Request, "set_request_header")?;
        request_header_mutation::validate(
          rule.name.as_str(),
          "set_request_header",
          name,
          Some(value),
        )?;
        mutations += 1;
      }
      WafActionConfig::RemoveRequestHeader { name, .. } => {
        require_phase(rule, WafPhase::Request, "remove_request_header")?;
        request_header_mutation::validate(rule.name.as_str(), "remove_request_header", name, None)?;
        mutations += 1;
      }
      WafActionConfig::SetResponseHeader { name, value, .. } => {
        require_phase(rule, WafPhase::Response, "set_response_header")?;
        validate_header(name, value)?;
        mutations += 1;
      }
      WafActionConfig::RemoveResponseHeader { name, .. } => {
        require_phase(rule, WafPhase::Response, "remove_response_header")?;
        validate_header_name(name)?;
        mutations += 1;
      }
      WafActionConfig::SetTag { key, value, .. } => {
        require_phase(rule, WafPhase::Request, "set_tag")?;
        if key.is_empty() || !is_valid_rule_label(key) || value.len() > 1024 {
          bail!("WAF rule {} set_tag exceeds tag size limits", rule.name);
        }
        mutations += 1;
      }
      WafActionConfig::RateLimit {
        name,
        key,
        ipv4_prefix_bits,
        ipv6_prefix_bits,
        identity_parts,
        token_bindings,
        token_header,
        access_token_source,
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
          validate_header_name(token_header)?;
        }
        crate::config::validate_rate_limit_identity_config(
          crate::config::RateLimitIdentityValidation {
            label: "WAF rule rate_limit",
            name,
            key: *key,
            ipv4_prefix_bits: *ipv4_prefix_bits,
            ipv6_prefix_bits: *ipv6_prefix_bits,
            identity_parts,
            token_bindings,
            token_header: token_header.as_deref(),
            access_token_source: *access_token_source,
            waf_context: true,
          },
        )?;
        mutations += 1;
      }
      WafActionConfig::WeighPersonProof { weight, .. } => {
        require_phase(rule, WafPhase::Request, "weigh_person_proof")?;
        if !(-1_000_000..=1_000_000).contains(weight) {
          bail!(
            "WAF rule {} weigh_person_proof weight must be between -1000000 and 1000000",
            rule.name
          );
        }
        mutations += 1;
      }
      WafActionConfig::AllowPersonProof { .. } => {
        require_phase(rule, WafPhase::Request, "allow_person_proof")?;
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
        ..
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
    let expression = expression
      .analyze_for_phase_with_functions(WafPhase::Response, global_functions, route_functions)
      .with_context(|| format!("invalid {label} field {}", field.name))?;
    if expression
      .request_body_need_with_functions(global_functions, route_functions)
      .requires_prefix()
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
    person_proof_mode,
    difficulty,
    ttl_seconds,
    cookie,
    clearance,
    token_bindings,
    direct_peer_ipv4_prefix_bits,
    direct_peer_ipv6_prefix_bits,
    tcp_max_hop,
    success_tag,
    custom_frontend_url,
    challenge_redirect_status,
    session_path,
    verify_path,
    openapi_path,
    third_party_provider,
    provider,
    proof_kind,
    proof_challenge_kind,
    proof_label,
    site_key,
    secret_env,
    provider_endpoint,
    provider_timeout_ms,
    provider_max_response_body_bytes,
    method,
    algorithm,
    challenge_url,
    ..
  } = action
  else {
    unreachable!("validate_person_proof_settings requires require_person_proof action");
  };

  if method.is_some() {
    bail!(
      "WAF rule {rule_name} require_person_proof method is no longer supported; use person_proof_mode instead"
    );
  }
  if algorithm.is_some() {
    bail!(
      "WAF rule {rule_name} require_person_proof algorithm is no longer supported; use person_proof_mode instead"
    );
  }
  if challenge_url.is_some() {
    bail!(
      "WAF rule {rule_name} require_person_proof challenge_url is no longer supported; use custom_frontend_url instead"
    );
  }
  if person_proof_mode.uses_pow() && !(1..=30).contains(difficulty) {
    bail!("WAF rule {rule_name} require_person_proof difficulty must be between 1 and 30");
  }
  if !(1..=86_400).contains(ttl_seconds) {
    bail!(
      "WAF rule {rule_name} require_person_proof token_validity_seconds must be between 1 and 86400"
    );
  }
  if cookie.is_some() {
    bail!(
      "WAF rule {rule_name} require_person_proof cookie is no longer supported; use clearance.cookie.key and clearance.sources instead"
    );
  }
  person_proof_config::validate_clearance_settings(rule_name, clearance)?;
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
  person_proof_config::validate_redirect_settings(
    rule_name,
    *person_proof_mode,
    custom_frontend_url.as_deref(),
    *challenge_redirect_status,
    session_path.as_deref(),
    verify_path.as_deref(),
    openapi_path.as_deref(),
    *third_party_provider,
    provider.as_deref(),
    proof_kind.as_deref(),
    proof_challenge_kind.as_deref(),
    proof_label.as_deref(),
    site_key.as_deref(),
    secret_env.as_deref(),
    provider_endpoint.as_deref(),
    *provider_timeout_ms,
    *provider_max_response_body_bytes,
  )?;
  Ok(())
}

fn is_valid_rule_label(value: &str) -> bool {
  value.len() <= 32
    && value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
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
  default_route_plan: WafRoutePlan,
  route_plans: HashMap<String, WafRoutePlan>,
  crs: CrsEngine,
  rate_limits: Arc<LimitState>,
  mitigation: MitigationSink,
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
    Self::new_with_previous_limits_and_mitigation(
      config,
      previous,
      shared_state,
      None,
      previous
        .map(|waf| waf.mitigation.clone())
        .unwrap_or_else(MitigationSink::disabled),
    )
  }

  pub fn new_with_previous_and_limits(
    config: &Config,
    previous: Option<&Self>,
    shared_state: Option<std::sync::Arc<SharedState>>,
    rate_limits: Option<Arc<LimitState>>,
  ) -> anyhow::Result<Self> {
    Self::new_with_previous_limits_and_mitigation(
      config,
      previous,
      shared_state,
      rate_limits,
      previous
        .map(|waf| waf.mitigation.clone())
        .unwrap_or_else(MitigationSink::disabled),
    )
  }

  pub fn new_with_previous_limits_and_mitigation(
    config: &Config,
    previous: Option<&Self>,
    shared_state: Option<std::sync::Arc<SharedState>>,
    rate_limits: Option<Arc<LimitState>>,
    mitigation: MitigationSink,
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
      RuleGroupScope {
        global: &config.waf.rule_groups,
        route: None,
      },
      WafRuleScope::global(),
      config.waf.mode,
      &previous_counters,
      global_functions.clone(),
      None,
      &config.waf.person_proof,
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
          RuleGroupScope {
            global: &config.waf.rule_groups,
            route: Some(&route.waf.rule_groups),
          },
          WafRuleScope::route(&route.name),
          config.waf.mode,
          &previous_counters,
          global_functions.clone(),
          Some(functions.clone()),
          &config.waf.person_proof,
        )?,
      );
    }
    let mut person_proof_policies = global_rules
      .iter()
      .chain(route_rules.values().flat_map(|rules| rules.iter()))
      .flat_map(|rule| rule.person_proof_policies.iter().cloned())
      .collect::<Vec<_>>();
    if config.dynamic_policy.enabled {
      person_proof_policies.push(person_proof_dynamic::policy(&config.waf.person_proof));
    }
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
    let (default_route_plan, route_plans) =
      build_route_plans(config, &global_rules, &route_rules, &crs);

    Ok(Self {
      enabled: config.waf.enabled,
      mode: config.waf.mode,
      fail_policy: config.waf.fail_policy,
      duplicate_metadata_policy: config.waf.duplicate_metadata_policy,
      limits: config.waf.limits.clone(),
      pattern_sets,
      global_rules,
      route_rules,
      default_route_plan,
      route_plans,
      crs,
      rate_limits,
      mitigation,
      person_proof,
      person_proof_tcp_max_hop,
    })
  }

  pub async fn new_with_previous_limits_and_mitigation_async(
    config: &Config,
    previous: Option<&Self>,
    shared_state: Option<std::sync::Arc<SharedState>>,
    rate_limits: Option<Arc<LimitState>>,
    mitigation: MitigationSink,
  ) -> anyhow::Result<Self> {
    let mut engine = Self::new_with_previous_limits_and_mitigation(
      config,
      previous,
      shared_state,
      rate_limits,
      mitigation,
    )?;
    engine.person_proof.load_shared_secret().await?;
    Ok(engine)
  }

  pub fn person_proof_tcp_max_hop(&self) -> Option<u8> {
    self.person_proof_tcp_max_hop
  }

  pub fn person_proof_admin_status(&self) -> anyhow::Result<PersonProofAdminStatus> {
    self.person_proof.admin_status()
  }

  pub async fn person_proof_admin_status_async(&self) -> anyhow::Result<PersonProofAdminStatus> {
    self.person_proof.admin_status_async().await
  }

  pub fn person_proof_admin_clearances(
    &self,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofAdminClearancePage> {
    self.person_proof.admin_list_clearances(limit, cursor)
  }

  pub async fn person_proof_admin_clearances_async(
    &self,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofAdminClearancePage> {
    self
      .person_proof
      .admin_list_clearances_async(limit, cursor)
      .await
  }

  pub fn person_proof_admin_revoke_clearance(
    &self,
    hash: &str,
    ttl_seconds: Option<u64>,
  ) -> anyhow::Result<PersonProofAdminRevokeResult> {
    self.person_proof.admin_revoke_clearance(hash, ttl_seconds)
  }

  pub async fn person_proof_admin_revoke_clearance_async(
    &self,
    hash: &str,
    ttl_seconds: Option<u64>,
  ) -> anyhow::Result<PersonProofAdminRevokeResult> {
    self
      .person_proof
      .admin_revoke_clearance_async(hash, ttl_seconds)
      .await
  }

  pub async fn person_proof_admin_revoke_clearance_with_idempotency_async(
    &self,
    hash: &str,
    ttl_seconds: Option<u64>,
    idempotency_key: Option<&str>,
  ) -> anyhow::Result<PersonProofAdminRevokeResult> {
    self
      .person_proof
      .admin_revoke_clearance_with_idempotency_async(hash, ttl_seconds, idempotency_key)
      .await
  }

  pub fn normalize_person_proof_admin_clearance_hash(hash: &str) -> anyhow::Result<String> {
    PersonProofEngine::normalize_admin_clearance_hash(hash)
  }

  pub fn enabled(&self) -> bool {
    self.enabled
  }

  pub(crate) fn route_plan(&self, route_name: &str) -> &WafRoutePlan {
    if self.enabled {
      self
        .route_plans
        .get(route_name)
        .unwrap_or(&self.default_route_plan)
    } else {
      &self.default_route_plan
    }
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

  pub fn rule_cost_snapshots(&self) -> Vec<WafRuleCostSnapshot> {
    let mut snapshots = self
      .global_rules
      .iter()
      .chain(self.route_rules.values().flat_map(|rules| rules.iter()))
      .map(CompiledRule::cost_snapshot)
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
    self.route_plan(route_name).response().enabled()
  }
  pub fn has_request_rules(&self, route_name: &str) -> bool {
    self.route_plan(route_name).request().enabled()
  }
  pub fn person_proof_api_path_role(&self, path: &str) -> Option<PersonProofApiPathRole> {
    person_proof_api::api_path_role(&self.person_proof, path)
  }
  pub fn has_person_proof_api_path(&self, path: &str) -> bool {
    self.person_proof_api_path_role(path).is_some()
  }
  pub fn has_person_proof_api_paths(&self) -> bool {
    !self.person_proof.policies.is_empty()
  }
  pub fn has_person_proof_verify_path(&self, path: &str) -> bool {
    self.person_proof_api_path_role(path) == Some(PersonProofApiPathRole::Verify)
  }
  pub fn person_proof_session_document(
    &self,
    input: WafRequestInput<'_>,
    session_path: &str,
    session: &str,
  ) -> anyhow::Result<Option<PersonProofSessionDocument>> {
    person_proof_api::session_document(&self.person_proof, input, session_path, session)
  }

  pub fn person_proof_openapi_document(&self, openapi_path: &str) -> Option<String> {
    person_proof_api::openapi_document(&self.person_proof, openapi_path)
  }

  pub fn begin_person_proof_session_challenge(
    &self,
    input: WafRequestInput<'_>,
    verify_path: &str,
    session: &str,
  ) -> anyhow::Result<Option<PersonProofProviderChallenge>> {
    person_proof_api::begin_session_challenge(&self.person_proof, input, verify_path, session)
  }

  pub fn begin_person_proof_provider_challenge(
    &self,
    input: WafRequestInput<'_>,
    verify_path: &str,
    challenge: &str,
  ) -> anyhow::Result<Option<PersonProofProviderChallenge>> {
    person_proof_v2::begin_provider_challenge(&self.person_proof, input, verify_path, challenge)
  }

  pub fn complete_person_proof_provider_challenge(
    &self,
    input: WafRequestInput<'_>,
    challenge: PersonProofProviderChallenge,
  ) -> anyhow::Result<PersonProofIssuedClearance> {
    person_proof_v2::complete_provider_challenge(&self.person_proof, input, challenge)
  }

  pub async fn complete_person_proof_provider_challenge_async(
    &self,
    input: WafRequestInput<'_>,
    challenge: PersonProofProviderChallenge,
  ) -> anyhow::Result<PersonProofIssuedClearance> {
    person_proof_v2::complete_provider_challenge_async(&self.person_proof, input, challenge).await
  }

  pub fn requires_request_body_inspection(&self, route_name: &str) -> bool {
    self
      .route_plan(route_name)
      .request_body_need()
      .requires_prefix()
  }

  pub fn requires_response_body_inspection(&self, route_name: &str) -> bool {
    self
      .route_plan(route_name)
      .response()
      .body_need()
      .requires_prefix()
  }

  pub fn request_body_need(&self, route_name: &str) -> BodyNeed {
    self.route_plan(route_name).request_body_need()
  }

  pub fn response_body_need(&self, route_name: &str) -> BodyNeed {
    self.route_plan(route_name).response().body_need()
  }

  pub fn plain_proxy_fast_path_safe(&self, route_name: &str) -> bool {
    self.route_plan(route_name).plain_proxy_fast_path_safe()
  }

  pub fn static_sendfile_fast_path_safe(&self, route_name: &str) -> bool {
    self.route_plan(route_name).static_sendfile_fast_path_safe()
  }

  pub fn requires_stream_inspection(&self, route_name: &str) -> bool {
    self.route_plan(route_name).stream().enabled()
  }

  pub fn evaluate_response(&self, input: WafResponseInput<'_>) -> ResponseWafDecision {
    if !self.enabled
      || !self
        .route_plan(input.request.route_name)
        .response()
        .enabled()
    {
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
            terminal: Some(WafHttpTerminal::response(
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
    if !self.enabled || !self.route_plan(input.request.route_name).stream().enabled() {
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
            ..WafStreamDecision::default()
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
    let person_proof = self.person_proof.evaluate_request(input.request);
    self.build_system_access_log_with_person_proof(fields, input, &person_proof)
  }

  fn build_system_access_log_with_person_proof(
    &self,
    fields: &CompiledAccessLogFields,
    input: WafResponseInput<'_>,
    person_proof: &PersonProofRequestStatus,
  ) -> anyhow::Result<AccessLogRecord> {
    let mut tx = TransactionBudget::new(&self.limits);
    let body_text_caches = BodyTextCaches::default();
    let ctx = EvalContext {
      phase: WafPhase::Response,
      mode: self.mode,
      rule_name: "",
      rule_id: None,
      rule_tags: &[],
      request: input.request,
      response: Some(input),
      stream: None,
      person_proof,
      pattern_sets: &self.pattern_sets,
      regex_cache: None,
      locals: &[],
      limits: &self.limits,
      duplicate_metadata_policy: self.duplicate_metadata_policy,
      body_text_caches: &body_text_caches,
    };
    AccessLogRecord::from_fields(&fields.fields, &ctx, &mut tx, "system")
  }

  fn evaluate_request_inner(
    &self,
    input: WafRequestInput<'_>,
    evaluated_person_proof: Option<&PersonProofRequestStatus>,
    suppress_clearance_mutation: bool,
  ) -> anyhow::Result<RequestWafDecision> {
    let mut decision = RequestWafDecision::default();
    let mut active_tags = input.tags.to_owned();
    let person_proof = evaluated_person_proof
      .cloned()
      .unwrap_or_else(|| self.person_proof.evaluate_request(input));
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
    if !suppress_clearance_mutation
      && let Some(mutation) = self
        .person_proof
        .clearance_response_mutation(&person_proof)?
    {
      decision.response_header_mutations.push(mutation);
    }

    let mut active_person_proof = PersonProofPolicyState::default();
    let mut tx = TransactionBudget::new(&self.limits);
    let body_text_caches = BodyTextCaches::default();
    for rule in self.route_plan(input.route_name).request().rules() {
      tx.check_total()?;
      let mut rule_person_proof = self.person_proof_status_for_rule(&person_proof, rule);
      active_person_proof.apply_to(&mut rule_person_proof);
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
          regex_cache: None,
          locals: &[],
          limits: &self.limits,
          duplicate_metadata_policy: self.duplicate_metadata_policy,
          body_text_caches: &body_text_caches,
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
        let action_ctx = EvalContext {
          phase: WafPhase::Request,
          mode: rule.mode,
          rule_name: &rule.name,
          rule_id: rule.id.as_deref(),
          rule_tags: &rule.tags,
          request,
          response: None,
          stream: None,
          person_proof: &rule_person_proof,
          pattern_sets: &self.pattern_sets,
          regex_cache: Some(&rule.regex_cache),
          locals: &[],
          limits: &self.limits,
          duplicate_metadata_policy: self.duplicate_metadata_policy,
          body_text_caches: &body_text_caches,
        };
        active_person_proof = apply_request_actions(
          rule,
          RequestActionContext {
            input: request,
            eval: &action_ctx,
            person_proof: &self.person_proof,
            rate_limits: &self.rate_limits,
            mitigation: &self.mitigation,
          },
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
    let person_proof = self.person_proof.evaluate_request(input.request);
    self.evaluate_response_inner_with_person_proof(input, &person_proof)
  }

  fn evaluate_response_inner_with_person_proof(
    &self,
    input: WafResponseInput<'_>,
    person_proof: &PersonProofRequestStatus,
  ) -> anyhow::Result<ResponseWafDecision> {
    let mut decision = ResponseWafDecision::default();
    let mut tx = TransactionBudget::new(&self.limits);
    let body_text_caches = BodyTextCaches::default();

    for rule in self.route_plan(input.request.route_name).response().rules() {
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
        person_proof,
        pattern_sets: &self.pattern_sets,
        regex_cache: None,
        locals: &[],
        limits: &self.limits,
        duplicate_metadata_policy: self.duplicate_metadata_policy,
        body_text_caches: &body_text_caches,
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
      apply_response_actions(rule, &ctx, input, &self.mitigation, &mut decision, &mut tx)?;
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
    let person_proof = self.person_proof.evaluate_request(input.request);
    self.evaluate_stream_inner_with_person_proof(input, &person_proof)
  }

  fn evaluate_stream_inner_with_person_proof(
    &self,
    input: WafStreamInput<'_>,
    person_proof: &PersonProofRequestStatus,
  ) -> anyhow::Result<WafStreamDecision> {
    let mut decision = WafStreamDecision::default();
    let mut tx = TransactionBudget::new(&self.limits);
    let body_text_caches = BodyTextCaches::default();

    for rule in self.route_plan(input.request.route_name).stream().rules() {
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
        person_proof,
        pattern_sets: &self.pattern_sets,
        regex_cache: None,
        locals: &[],
        limits: &self.limits,
        duplicate_metadata_policy: self.duplicate_metadata_policy,
        body_text_caches: &body_text_caches,
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
      apply_stream_actions(rule, &ctx, input, &self.mitigation, &mut decision, &mut tx)?;
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
      regex_cache: Some(&rule.regex_cache),
      locals: &[],
      ..*ctx
    };
    let started_at = Instant::now();
    let value = rule.expression.eval(&rule_ctx, tx);
    rule.record_eval(started_at.elapsed());
    let value = value?;
    value
      .as_bool()
      .with_context(|| format!("WAF rule {} expression did not evaluate to Bool", rule.name))
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

#[allow(clippy::too_many_arguments)]
fn compile_rules(
  configs: &[WafRuleConfig],
  groups: RuleGroupScope<'_>,
  scope: WafRuleScope,
  default_mode: WafMode,
  previous_counters: &HashMap<WafRuleHitKey, Arc<AtomicU64>>,
  global_functions: Arc<FunctionMap>,
  route_functions: Option<Arc<FunctionMap>>,
  person_proof_defaults: &WafPersonProofConfig,
) -> anyhow::Result<Vec<CompiledRule>> {
  configs
    .iter()
    .map(|rule| {
      let resolved = resolve_rule(scope.label, rule, groups)
        .with_context(|| format!("failed to resolve WAF rule {} groups", rule.name))?;
      let expression = Parser::new(&resolved.when)
        .parse()
        .and_then(|expression| {
          expression.analyze_for_phase_with_functions(
            rule.phase,
            global_functions.as_ref(),
            route_functions.as_deref(),
          )
        })
        .with_context(|| format!("failed to compile WAF rule {}", rule.name))?;
      let actions = compile_actions(
        rule,
        &resolved.actions,
        scope.person_proof_scope(),
        person_proof_defaults,
        global_functions.as_ref(),
        route_functions.as_deref(),
      )
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
      let request_body_need = expression
        .request_body_need_with_functions(global_functions.as_ref(), route_functions.as_deref());
      let response_body_need = expression
        .response_body_need_with_functions(global_functions.as_ref(), route_functions.as_deref());
      let regex_cache = CompiledRegexCache::from_rule_expression(
        &expression,
        global_functions.as_ref(),
        route_functions.as_deref(),
      );
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
        eval_counter: Arc::new(AtomicU64::new(0)),
        eval_duration_ns: Arc::new(AtomicU64::new(0)),
        request_body_need,
        response_body_need,
        regex_cache,
        expression,
        actions,
        person_proof_policies,
      })
    })
    .collect()
}

fn build_route_plans(
  config: &Config,
  global_rules: &[CompiledRule],
  route_rules: &HashMap<String, Vec<CompiledRule>>,
  crs: &CrsEngine,
) -> (WafRoutePlan, HashMap<String, WafRoutePlan>) {
  let reject_duplicate_metadata =
    config.waf.duplicate_metadata_policy == WafDuplicateMetadataPolicy::RejectRequest;
  let build = |rules: &[CompiledRule]| {
    if !config.waf.enabled {
      return WafRoutePlan::disabled();
    }
    WafRoutePlan::new(
      phase_plan(
        global_rules,
        rules,
        WafPhase::Request,
        crs.has_request_rules() || reject_duplicate_metadata,
        if crs.requires_request_body_inspection() {
          BodyNeed::PrefixBytes
        } else {
          BodyNeed::None
        },
      ),
      phase_plan(
        global_rules,
        rules,
        WafPhase::Response,
        crs.has_response_rules(),
        if crs.requires_response_body_inspection() {
          BodyNeed::PrefixBytes
        } else {
          BodyNeed::None
        },
      ),
      phase_plan(global_rules, rules, WafPhase::Stream, false, BodyNeed::None),
    )
  };
  let default_route_plan = build(&[]);
  let route_plans = config
    .routes
    .iter()
    .map(|route| {
      (
        route.name.clone(),
        build(
          route_rules
            .get(&route.name)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        ),
      )
    })
    .collect();
  (default_route_plan, route_plans)
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

fn compile_actions(
  rule: &WafRuleConfig,
  actions: &[WafActionConfig],
  scope: &str,
  person_proof_defaults: &WafPersonProofConfig,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<Vec<CompiledAction>> {
  actions
    .iter()
    .enumerate()
    .map(|(action_index, action)| match action {
      WafActionConfig::EmitAccessLog { fields, .. } => Ok(CompiledAction::EmitAccessLog {
        fields: fields
          .iter()
          .map(|field| {
            Ok(CompiledAccessLogField {
              name: field.name.clone(),
              expression: Parser::new(&field.value)
                .parse()
                .and_then(|expression| {
                  expression.analyze_for_phase_with_functions(
                    WafPhase::Response,
                    global_functions,
                    route_functions,
                  )
                })
                .with_context(|| {
                  format!("failed to compile emit_access_log field {}", field.name)
                })?,
            })
          })
          .collect::<anyhow::Result<Vec<_>>>()?,
      }),
      WafActionConfig::RequirePersonProof { .. } => Ok(CompiledAction::RequirePersonProof(
        person_proof_policy::from_action(rule, scope, action_index, action, person_proof_defaults),
      )),
      WafActionConfig::EmitMitigation { .. } => Ok(CompiledAction::EmitMitigation(
        compile_mitigation_action(rule, action, global_functions, route_functions)?,
      )),
      WafActionConfig::SetRequestHeader { name, value, .. } if rule.phase == WafPhase::Request => {
        request_header_mutation::validate(
          rule.name.as_str(),
          "set_request_header",
          name,
          Some(value),
        )?;
        Ok(CompiledAction::Config(action.clone()))
      }
      WafActionConfig::RemoveRequestHeader { name, .. } if rule.phase == WafPhase::Request => {
        request_header_mutation::validate(rule.name.as_str(), "remove_request_header", name, None)?;
        Ok(CompiledAction::Config(action.clone()))
      }
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
  let empty_functions = FunctionMap::new();
  let fields = fields
    .iter()
    .map(|field| {
      Ok(CompiledAccessLogField {
        name: field.name.clone(),
        expression: Parser::new(&field.value)
          .parse()
          .and_then(|expression| {
            expression.analyze_for_phase_with_functions(WafPhase::Response, &empty_functions, None)
          })
          .with_context(|| format!("failed to compile {label} field {}", field.name))?,
      })
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok(CompiledAccessLogFields { fields })
}

fn new_internal_rule_id() -> anyhow::Result<String> {
  new_uuid_like_id("WAF internal rule id")
}

pub fn new_access_log_id() -> String {
  new_uuid_like_id("access log id").unwrap_or_else(|_| format!("fallback-{}", current_unix_ms()))
}

fn new_uuid_like_id(label: &str) -> anyhow::Result<String> {
  let mut bytes = [0u8; 16];
  crate::crypto::random_fill(&mut bytes).map_err(|_| anyhow!("failed to generate {label}"))?;
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct WafRuleCostSnapshot {
  pub scope: String,
  pub route: Option<String>,
  pub phase: String,
  pub name: String,
  pub id: Option<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<String>,
  pub effective_mode: String,
  pub evaluations: u64,
  pub total_duration_ns: u64,
  pub average_duration_ns: u64,
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
  eval_counter: Arc<AtomicU64>,
  eval_duration_ns: Arc<AtomicU64>,
  request_body_need: BodyNeed,
  response_body_need: BodyNeed,
  regex_cache: CompiledRegexCache,
  expression: Expr,
  actions: Vec<CompiledAction>,
  person_proof_policies: Vec<PersonProofPolicy>,
}

impl CompiledRule {
  fn record_hit(&self) {
    self.hit_counter.fetch_add(1, Ordering::Relaxed);
  }

  fn record_eval(&self, duration: Duration) {
    self.eval_counter.fetch_add(1, Ordering::Relaxed);
    self.eval_duration_ns.fetch_add(
      duration.as_nanos().min(u128::from(u64::MAX)) as u64,
      Ordering::Relaxed,
    );
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

  fn cost_snapshot(&self) -> WafRuleCostSnapshot {
    let evaluations = self.eval_counter.load(Ordering::Relaxed);
    let total_duration_ns = self.eval_duration_ns.load(Ordering::Relaxed);
    WafRuleCostSnapshot {
      scope: self.scope.clone(),
      route: self.route.clone(),
      phase: self.phase.as_str().to_string(),
      name: self.name.clone(),
      id: self.id.clone(),
      tags: self.tags.clone(),
      effective_mode: self.mode.as_str().to_string(),
      evaluations,
      total_duration_ns,
      average_duration_ns: total_duration_ns.checked_div(evaluations).unwrap_or(0),
    }
  }
}

#[derive(Clone)]
enum CompiledAction {
  Config(WafActionConfig),
  RequirePersonProof(PersonProofPolicy),
  EmitAccessLog { fields: Vec<CompiledAccessLogField> },
  EmitMitigation(CompiledMitigationAction),
}

#[derive(Clone)]
struct CompiledAccessLogField {
  name: String,
  expression: Expr,
}

#[derive(Clone, Default)]
struct CompiledRegexCache {
  inner: ForgeCompiledRegexCache,
}

impl CompiledRegexCache {
  fn from_rule_expression(
    expression: &Expr,
    _global_functions: &FunctionMap,
    _route_functions: Option<&FunctionMap>,
  ) -> Self {
    let inner = match expression.verified_program() {
      Ok(program) => program.regex_cache().clone(),
      Err(_) => ForgeCompiledRegexCache::default(),
    };
    Self { inner }
  }

  fn get(&self, flavor: RegexFlavor, pattern: &str) -> Option<&Regex> {
    self.inner.get(forge_regex_flavor(flavor), pattern)
  }
}

#[derive(Clone, Copy)]
enum RegexFlavor {
  Default,
  HeaderName,
}

fn forge_regex_flavor(flavor: RegexFlavor) -> ForgeRegexFlavor {
  match flavor {
    RegexFlavor::Default => ForgeRegexFlavor::Default,
    RegexFlavor::HeaderName => ForgeRegexFlavor::HeaderName,
  }
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
  pub client_asn: Option<u32>,
  pub downstream_host: &'a str,
  pub downstream_scheme: &'a str,
  pub route_name: &'a str,
  pub tcp_max_hop: Option<u8>,
  pub tls: &'a WafTlsMetadata,
  pub protocol: WafProtocol,
  pub transport_network: WafTransportNetwork,
  pub transport_metadata: WafTransportMetadataInput<'a>,
  pub tags: &'a HashMap<String, String>,
  pub dynamic_policy: &'a DynamicPolicyContext,
}

#[derive(Debug, Clone, Copy)]
pub struct WafBodyInput<'a> {
  pub bytes: &'a [u8],
  pub is_truncated: bool,
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
  pub terminal: Option<WafHttpTerminal>,
  pub request_header_mutations: Vec<HeaderMutation>,
  pub response_header_mutations: Vec<HeaderMutation>,
  pub tags: Vec<(String, String)>,
  pub upstream_override: Option<String>,
  pub upstream_pool_override: Option<String>,
  pub load_balancing_policy: Option<String>,
}

#[derive(Debug, Default)]
pub struct ResponseWafDecision {
  pub terminal: Option<WafHttpTerminal>,
  pub response_header_mutations: Vec<HeaderMutation>,
  pub access_logs: Vec<AccessLogRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct WafStreamDecision {
  pub close: Option<WafStreamClose>,
  pub silent_close: bool,
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
    terminal: Some(WafHttpTerminal::response(
      StatusCode::TOO_MANY_REQUESTS,
      "person proof token capacity exhausted".to_string(),
    )),
    ..RequestWafDecision::default()
  }
}

fn apply_crs_request_decision(crs: CrsDecision, decision: &mut RequestWafDecision) {
  if decision.terminal.is_none() {
    decision.terminal = crs.terminal.map(Into::into);
  }
}

fn apply_crs_response_decision(crs: CrsDecision, decision: &mut ResponseWafDecision) {
  if decision.terminal.is_none() {
    decision.terminal = crs.terminal.map(Into::into);
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

#[derive(Debug)]
pub enum WafHttpTerminal {
  Response(WafTerminalResponse),
  SilentClose,
}

impl WafHttpTerminal {
  pub(super) fn response(status: StatusCode, body: String) -> Self {
    Self::Response(WafTerminalResponse::new(status, body))
  }

  pub fn is_silent_close(&self) -> bool {
    matches!(self, Self::SilentClose)
  }

  pub fn into_response(self) -> Option<WafTerminalResponse> {
    match self {
      Self::Response(response) => Some(response),
      Self::SilentClose => None,
    }
  }
}

impl Deref for WafHttpTerminal {
  type Target = WafTerminalResponse;

  fn deref(&self) -> &Self::Target {
    match self {
      Self::Response(response) => response,
      Self::SilentClose => panic!("silent_close WAF terminal has no HTTP response"),
    }
  }
}

impl From<WafTerminalResponse> for WafHttpTerminal {
  fn from(response: WafTerminalResponse) -> Self {
    Self::Response(response)
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

struct RequestActionContext<'a, 'ctx> {
  input: WafRequestInput<'a>,
  eval: &'ctx EvalContext<'a>,
  person_proof: &'ctx PersonProofEngine,
  rate_limits: &'ctx LimitState,
  mitigation: &'ctx MitigationSink,
}

fn apply_request_actions(
  rule: &CompiledRule,
  action_ctx: RequestActionContext<'_, '_>,
  decision: &mut RequestWafDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<PersonProofPolicyState> {
  let input = action_ctx.input;
  let ctx = action_ctx.eval;
  let person_proof = action_ctx.person_proof;
  let rate_limits = action_ctx.rate_limits;
  let mitigation = action_ctx.mitigation;
  let mut person_proof_policy = PersonProofPolicyState::from_status(ctx.person_proof);
  for action in &rule.actions {
    tx.count_mutation()?;
    match action {
      CompiledAction::Config(WafActionConfig::Reject { status, body, .. }) => {
        decision.terminal = Some(WafHttpTerminal::response(
          StatusCode::from_u16(*status)?,
          body.clone().unwrap_or_else(|| "Blocked by WAF".to_string()),
        ));
        return Ok(person_proof_policy);
      }
      CompiledAction::Config(WafActionConfig::SilentClose { .. }) => {
        decision.terminal = Some(WafHttpTerminal::SilentClose);
        return Ok(person_proof_policy);
      }
      CompiledAction::Config(WafActionConfig::SetRequestHeader { name, value, .. }) => {
        let name = HeaderName::from_bytes(name.as_bytes())?;
        request_header_mutation::ensure_allowed(&rule.name, "set_request_header", &name)?;
        decision.request_header_mutations.push(HeaderMutation::Set {
          name,
          value: HeaderValue::from_str(value)?,
        });
      }
      CompiledAction::Config(WafActionConfig::RemoveRequestHeader { name, .. }) => {
        let name = HeaderName::from_bytes(name.as_bytes())?;
        request_header_mutation::ensure_allowed(&rule.name, "remove_request_header", &name)?;
        decision
          .request_header_mutations
          .push(HeaderMutation::Remove { name });
      }
      CompiledAction::Config(WafActionConfig::SetTag { key, value, .. }) => {
        decision.tags.push((key.clone(), value.clone()));
      }
      CompiledAction::Config(WafActionConfig::RouteToUpstream { upstream, .. }) => {
        decision.upstream_override = Some(upstream.clone());
      }
      CompiledAction::Config(WafActionConfig::RouteToPool { pool, .. }) => {
        decision.upstream_pool_override = Some(pool.clone());
      }
      CompiledAction::Config(WafActionConfig::SetLoadBalancingPolicy { policy, .. }) => {
        decision.load_balancing_policy = Some(policy.clone());
      }
      CompiledAction::Config(WafActionConfig::RateLimit {
        name,
        key,
        ipv4_prefix_bits,
        ipv6_prefix_bits,
        identity_parts,
        token_bindings,
        token_header,
        access_token_source,
        rate,
        burst,
        max_buckets,
        status,
        body,
        ..
      }) => {
        let context = RateLimitContext::route(
          input.peer_addr.ip(),
          input.route_name,
          input.uri.path(),
          input.headers,
        )
        .with_tls_fingerprint(input.tls.fingerprint.as_deref())
        .with_client_asn(input.client_asn)
        .with_tcp_max_hop(input.tcp_max_hop)
        .with_person_proof_clearance_hash(ctx.person_proof.clearance_hash.as_deref());
        let check = RateLimitCheck {
          name,
          key: *key,
          token_header: token_header.as_deref(),
          access_token_source: *access_token_source,
          ipv4_prefix_bits: *ipv4_prefix_bits,
          ipv6_prefix_bits: *ipv6_prefix_bits,
          identity_parts,
          token_bindings,
          rate,
          burst: *burst,
          max_buckets: *max_buckets,
          mode: LimitMode::Enforcing,
          status: *status,
        };
        if let Some(status) = rate_limits.check_rate_limit_local(context, check) {
          decision.terminal = Some(WafHttpTerminal::response(
            status,
            body
              .clone()
              .unwrap_or_else(|| "rate limit exceeded".to_string()),
          ));
          return Ok(person_proof_policy);
        }
      }
      CompiledAction::Config(WafActionConfig::WeighPersonProof { weight, .. }) => {
        person_proof_policy.add_weight(*weight);
      }
      CompiledAction::Config(WafActionConfig::AllowPersonProof { .. }) => {
        person_proof_policy.allow();
      }
      CompiledAction::RequirePersonProof(policy) => {
        if person_proof_policy.challenge_suppressed(ctx.person_proof) {
          continue;
        }
        decision.terminal = Some(person_proof.issue_challenge(input, policy.clone())?.into());
        return Ok(person_proof_policy);
      }
      CompiledAction::EmitMitigation(action) => {
        if let Some(terminal) =
          apply_mitigation_http_action(action, rule, ctx, None, mitigation, tx)?
        {
          decision.terminal = Some(terminal.into());
          return Ok(person_proof_policy);
        }
      }
      CompiledAction::Config(WafActionConfig::ContinueResponse { .. })
      | CompiledAction::Config(WafActionConfig::ReplaceResponse { .. })
      | CompiledAction::Config(WafActionConfig::RejectResponse { .. })
      | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. })
      | CompiledAction::Config(WafActionConfig::EmitMitigation { .. })
      | CompiledAction::Config(WafActionConfig::SetResponseHeader { .. })
      | CompiledAction::Config(WafActionConfig::RemoveResponseHeader { .. })
      | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
      | CompiledAction::Config(WafActionConfig::CloseStream { .. })
      | CompiledAction::EmitAccessLog { .. } => {
        bail!("invalid request-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(person_proof_policy)
}

fn apply_response_actions(
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  input: WafResponseInput<'_>,
  mitigation: &MitigationSink,
  decision: &mut ResponseWafDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<()> {
  for action in &rule.actions {
    tx.count_mutation()?;
    match action {
      CompiledAction::Config(WafActionConfig::ContinueResponse { .. }) => return Ok(()),
      CompiledAction::Config(WafActionConfig::SilentClose { .. }) => {
        decision.terminal = Some(WafHttpTerminal::SilentClose);
        return Ok(());
      }
      CompiledAction::Config(WafActionConfig::ReplaceResponse { status, body, .. })
      | CompiledAction::Config(WafActionConfig::RejectResponse { status, body, .. }) => {
        decision.terminal = Some(WafHttpTerminal::response(
          StatusCode::from_u16(*status)?,
          body.clone().unwrap_or_else(|| "Blocked by WAF".to_string()),
        ));
        return Ok(());
      }
      CompiledAction::Config(WafActionConfig::SetResponseHeader { name, value, .. }) => {
        decision
          .response_header_mutations
          .push(HeaderMutation::Set {
            name: HeaderName::from_bytes(name.as_bytes())?,
            value: HeaderValue::from_str(value)?,
          });
      }
      CompiledAction::Config(WafActionConfig::RemoveResponseHeader { name, .. }) => {
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
      CompiledAction::EmitMitigation(action) => {
        if let Some(terminal) =
          apply_mitigation_http_action(action, rule, ctx, Some(input), mitigation, tx)?
        {
          decision.terminal = Some(terminal.into());
          return Ok(());
        }
      }
      CompiledAction::Config(WafActionConfig::Reject { .. })
      | CompiledAction::Config(WafActionConfig::RouteToPool { .. })
      | CompiledAction::Config(WafActionConfig::RouteToUpstream { .. })
      | CompiledAction::Config(WafActionConfig::SetLoadBalancingPolicy { .. })
      | CompiledAction::Config(WafActionConfig::SetRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::RemoveRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::SetTag { .. })
      | CompiledAction::Config(WafActionConfig::RateLimit { .. })
      | CompiledAction::Config(WafActionConfig::WeighPersonProof { .. })
      | CompiledAction::Config(WafActionConfig::AllowPersonProof { .. })
      | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
      | CompiledAction::Config(WafActionConfig::CloseStream { .. })
      | CompiledAction::RequirePersonProof(_)
      | CompiledAction::Config(WafActionConfig::EmitMitigation { .. })
      | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. }) => {
        bail!("invalid response-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(())
}

fn apply_stream_actions(
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  input: WafStreamInput<'_>,
  mitigation: &MitigationSink,
  decision: &mut WafStreamDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<()> {
  for action in &rule.actions {
    tx.count_mutation()?;
    match action {
      CompiledAction::Config(WafActionConfig::CloseStream {
        websocket_code,
        webtransport_code,
        reason,
        ..
      }) => {
        decision.close = Some(WafStreamClose {
          websocket_code: *websocket_code,
          webtransport_code: *webtransport_code,
          reason: reason.clone(),
        });
        return Ok(());
      }
      CompiledAction::Config(WafActionConfig::SilentClose { .. }) => {
        decision.silent_close = true;
        return Ok(());
      }
      CompiledAction::EmitMitigation(action) => {
        if let Some(close) =
          apply_mitigation_stream_action(action, rule, ctx, input, mitigation, tx)?
        {
          decision.close = Some(close);
          return Ok(());
        }
      }
      CompiledAction::Config(WafActionConfig::Reject { .. })
      | CompiledAction::Config(WafActionConfig::ContinueResponse { .. })
      | CompiledAction::Config(WafActionConfig::ReplaceResponse { .. })
      | CompiledAction::Config(WafActionConfig::RejectResponse { .. })
      | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. })
      | CompiledAction::Config(WafActionConfig::EmitMitigation { .. })
      | CompiledAction::Config(WafActionConfig::RouteToPool { .. })
      | CompiledAction::Config(WafActionConfig::RouteToUpstream { .. })
      | CompiledAction::Config(WafActionConfig::SetLoadBalancingPolicy { .. })
      | CompiledAction::Config(WafActionConfig::SetRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::RemoveRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::SetResponseHeader { .. })
      | CompiledAction::Config(WafActionConfig::RemoveResponseHeader { .. })
      | CompiledAction::Config(WafActionConfig::SetTag { .. })
      | CompiledAction::Config(WafActionConfig::RateLimit { .. })
      | CompiledAction::Config(WafActionConfig::WeighPersonProof { .. })
      | CompiledAction::Config(WafActionConfig::AllowPersonProof { .. })
      | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
      | CompiledAction::RequirePersonProof(_)
      | CompiledAction::EmitAccessLog { .. } => {
        bail!("invalid stream-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(())
}

pub fn current_unix_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
    .unwrap_or_default()
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
  regex_cache: Option<&'a CompiledRegexCache>,
  locals: &'a [(&'a str, &'a Value)],
  limits: &'a WafLimits,
  duplicate_metadata_policy: WafDuplicateMetadataPolicy,
  body_text_caches: &'a BodyTextCaches,
}

impl Expr {
  fn eval(&self, ctx: &EvalContext<'_>, tx: &mut TransactionBudget) -> anyhow::Result<Value> {
    self.eval_verified(self.verified_root()?, ctx, tx)
  }

  fn eval_verified(
    &self,
    expression: &VerifiedExpression,
    ctx: &EvalContext<'_>,
    tx: &mut TransactionBudget,
  ) -> anyhow::Result<Value> {
    tx.step()?;
    match expression.kind() {
      VerifiedExprKindRef::Null => Ok(Value::Null),
      VerifiedExprKindRef::Bool(value) => Ok(Value::Bool(value)),
      VerifiedExprKindRef::Int(value) => Ok(Value::Int(value)),
      VerifiedExprKindRef::Float(_) => bail!("OxiRule V1 does not support float values"),
      VerifiedExprKindRef::String(value) => Ok(Value::String(value.to_string())),
      VerifiedExprKindRef::Array(_) => bail!("OxiRule V1 does not support array values"),
      VerifiedExprKindRef::Identifier(name) => eval_ident(name, ctx),
      VerifiedExprKindRef::Member { receiver, name } => {
        let value = self.eval_verified(receiver, ctx, tx)?;
        eval_member(value, name, ctx)
      }
      VerifiedExprKindRef::FunctionCall { name, .. } => {
        bail!("unknown OxiRule function {name}")
      }
      VerifiedExprKindRef::ExpressionFunctionCall {
        params, args, body, ..
      } => {
        let values = args
          .iter()
          .map(|arg| self.eval_verified(arg, ctx, tx))
          .collect::<anyhow::Result<Vec<_>>>()?;
        let locals = params
          .iter()
          .zip(values.iter())
          .map(|(param, value)| (param.as_str(), value))
          .collect::<Vec<_>>();
        let child_ctx = EvalContext {
          locals: &locals,
          ..*ctx
        };
        self.eval_verified(body, &child_ctx, tx)
      }
      VerifiedExprKindRef::MethodCall {
        receiver,
        name,
        args,
      } => {
        let value = self.eval_verified(receiver, ctx, tx)?;
        let regex_args = CachedRegexArgs::for_verified_args(args, ctx.regex_cache);
        let values = args
          .iter()
          .map(|arg| self.eval_verified(arg, ctx, tx))
          .collect::<anyhow::Result<Vec<_>>>()?;
        eval_call(value, name, &values, ctx, tx, regex_args)
      }
      VerifiedExprKindRef::Unary { op, expr } => match op {
        ForgeUnaryOp::Not => Ok(Value::Bool(!self.eval_verified(expr, ctx, tx)?.as_bool()?)),
        ForgeUnaryOp::Neg => bail!("OxiRule V1 does not support unary numeric negation"),
      },
      VerifiedExprKindRef::Binary { left, op, right } => {
        eval_verified_binary(self, left, op, right, ctx, tx)
      }
    }
  }
}

fn eval_verified_binary(
  owner: &Expr,
  left: &VerifiedExpression,
  op: ForgeBinaryOp,
  right: &VerifiedExpression,
  ctx: &EvalContext<'_>,
  tx: &mut TransactionBudget,
) -> anyhow::Result<Value> {
  match op {
    ForgeBinaryOp::And => {
      let left_value = owner.eval_verified(left, ctx, tx)?.as_bool()?;
      if !left_value {
        return Ok(Value::Bool(false));
      }
      Ok(Value::Bool(owner.eval_verified(right, ctx, tx)?.as_bool()?))
    }
    ForgeBinaryOp::Or => {
      let left_value = owner.eval_verified(left, ctx, tx)?.as_bool()?;
      if left_value {
        return Ok(Value::Bool(true));
      }
      Ok(Value::Bool(owner.eval_verified(right, ctx, tx)?.as_bool()?))
    }
    ForgeBinaryOp::Add => {
      let left_value = owner.eval_verified(left, ctx, tx)?;
      let right_value = owner.eval_verified(right, ctx, tx)?;
      Ok(Value::String(format!(
        "{}{}",
        left_value.as_string()?,
        right_value.as_string()?
      )))
    }
    ForgeBinaryOp::Eq | ForgeBinaryOp::Ne => {
      let left_value = owner.eval_verified(left, ctx, tx)?;
      let right_value = owner.eval_verified(right, ctx, tx)?;
      let equal = values_equal(&left_value, &right_value)?;
      Ok(Value::Bool(matches!(op, ForgeBinaryOp::Eq) == equal))
    }
    ForgeBinaryOp::Lt | ForgeBinaryOp::Le | ForgeBinaryOp::Gt | ForgeBinaryOp::Ge => {
      let left_value = owner.eval_verified(left, ctx, tx)?;
      let right_value = owner.eval_verified(right, ctx, tx)?;
      let result = match (&left_value, &right_value) {
        (Value::Int(left), Value::Int(right)) => match op {
          ForgeBinaryOp::Lt => left < right,
          ForgeBinaryOp::Le => left <= right,
          ForgeBinaryOp::Gt => left > right,
          ForgeBinaryOp::Ge => left >= right,
          _ => unreachable!(),
        },
        (Value::String(left), Value::String(right)) => match op {
          ForgeBinaryOp::Lt => left < right,
          ForgeBinaryOp::Le => left <= right,
          ForgeBinaryOp::Gt => left > right,
          ForgeBinaryOp::Ge => left >= right,
          _ => unreachable!(),
        },
        _ => bail!("ordered comparison requires matching Int or String values"),
      };
      Ok(Value::Bool(result))
    }
    ForgeBinaryOp::Sub | ForgeBinaryOp::Mul | ForgeBinaryOp::Div | ForgeBinaryOp::Rem => {
      bail!("OxiRule V1 does not support operator {}", op.as_str())
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

#[derive(Clone, Copy, Default)]
struct CachedRegexArgs<'a> {
  default: [Option<&'a Regex>; 2],
  header_name: [Option<&'a Regex>; 2],
}

impl<'a> CachedRegexArgs<'a> {
  fn for_verified_args(args: &[VerifiedExpression], cache: Option<&'a CompiledRegexCache>) -> Self {
    let Some(cache) = cache else {
      return Self::default();
    };
    let mut regex_args = Self::default();
    for (index, arg) in args.iter().enumerate().take(regex_args.default.len()) {
      if let Some(pattern) = expression::verified_string_literal(arg) {
        regex_args.default[index] = cache.get(RegexFlavor::Default, pattern);
        regex_args.header_name[index] = cache.get(RegexFlavor::HeaderName, pattern);
      }
    }
    regex_args
  }

  fn get(self, flavor: RegexFlavor, index: usize) -> Option<&'a Regex> {
    match flavor {
      RegexFlavor::Default => self.default.get(index).copied().flatten(),
      RegexFlavor::HeaderName => self.header_name.get(index).copied().flatten(),
    }
  }
}

enum RegexSource<'a> {
  Borrowed(&'a Regex),
  Owned(Regex),
}

impl RegexSource<'_> {
  fn is_match(&self, value: &str) -> bool {
    match self {
      Self::Borrowed(regex) => regex.is_match(value),
      Self::Owned(regex) => regex.is_match(value),
    }
  }
}

fn regex_arg<'a>(
  args: &[Value],
  index: usize,
  cached: Option<&'a Regex>,
) -> anyhow::Result<RegexSource<'a>> {
  if let Some(regex) = cached {
    return Ok(RegexSource::Borrowed(regex));
  }
  Ok(RegexSource::Owned(Regex::new(expect_string_arg(
    args, index,
  )?)?))
}

fn header_name_regex_arg<'a>(
  args: &[Value],
  index: usize,
  cached: Option<&'a Regex>,
) -> anyhow::Result<RegexSource<'a>> {
  if let Some(regex) = cached {
    return Ok(RegexSource::Borrowed(regex));
  }
  Ok(RegexSource::Owned(header_name_regex(expect_string_arg(
    args, index,
  )?)?))
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
    (ObjectRef::StreamPayload, "Text") => {
      let body = ctx.stream.context("missing stream context")?.payload;
      Ok(Value::String(
        ctx
          .body_text_caches
          .text(BodyTextSlot::Stream, body)
          .to_string(),
      ))
    }
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
    (ObjectRef::RequestClient, "GeoCountry") => Ok(Value::Null),
    (ObjectRef::RequestClient, "Asn") => Ok(
      ctx
        .request
        .client_asn
        .map(|asn| Value::Int(asn.into()))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientPersonProof, "State") => {
      Ok(Value::String(ctx.person_proof.state.as_str().to_string()))
    }
    (ObjectRef::RequestClientPersonProof, "Mode") => Ok(
      ctx
        .person_proof
        .mode
        .map(|mode| Value::String(mode.to_string()))
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
    (ObjectRef::RequestClientPersonProof, "Weight") => Ok(Value::Int(ctx.person_proof.weight)),
    (ObjectRef::RequestClientPersonProof, "Allowed") => Ok(Value::Bool(ctx.person_proof.allowed)),
    (ObjectRef::RequestClientAgent, "Verified") => Ok(Value::Bool(false)),
    (ObjectRef::RequestClientAgent, "Kind")
    | (ObjectRef::RequestClientAgent, "Provider")
    | (ObjectRef::RequestClientAgent, "Model")
    | (ObjectRef::RequestClientAgent, "AuthMethod") => Ok(Value::Null),
    (ObjectRef::RequestClientBot, "Disposition") => Ok(Value::String(
      mi_score::request_bot_assessment(ctx.request)
        .disposition
        .to_string(),
    )),
    (ObjectRef::RequestClientBot, "Malicious") => Ok(
      mi_score::request_bot_assessment(ctx.request)
        .malicious
        .map(Value::Bool)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestClientBot, "Score") => Ok(Value::Int(
      mi_score::request_bot_assessment(ctx.request).score,
    )),
    (ObjectRef::RequestClientBot, "Reason") => Ok(
      mi_score::request_bot_assessment(ctx.request)
        .reason
        .map(Value::String)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransport, "Network") => Ok(Value::String(
      ctx.request.transport_network.as_str().to_string(),
    )),
    (ObjectRef::RequestTransport, "RemoteIp") => {
      Ok(Value::String(ctx.request.peer_addr.ip().to_string()))
    }
    (ObjectRef::RequestTransport, "RemotePort") => {
      Ok(Value::Int(ctx.request.peer_addr.port().into()))
    }
    (ObjectRef::RequestTransport, "IsEncrypted") => Ok(Value::Bool(ctx.request.tls.enabled)),
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
    (ObjectRef::RequestTransportTcp, "Mss") => Ok(
      ctx
        .request
        .transport_metadata
        .tcp_mss
        .map(|mss| Value::Int(i64::from(mss)))
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportTcp, "RttMs") => Ok(
      ctx
        .request
        .transport_metadata
        .tcp_rtt_ms
        .and_then(|rtt| i64::try_from(rtt).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportUdp, "DatagramSize") => Ok(
      ctx
        .request
        .transport_metadata
        .udp_datagram_size
        .and_then(|size| i64::try_from(size).ok())
        .map(Value::Int)
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTransportUdp, "FlowId") => Ok(Value::Null),
    (ObjectRef::RequestTransportUdp, "ConnectionId") => Ok(
      ctx
        .request
        .transport_metadata
        .udp_connection_id
        .map(|id| Value::String(id.to_string()))
        .unwrap_or(Value::Null),
    ),
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
        .map(|body| {
          Value::String(
            ctx
              .body_text_caches
              .text(BodyTextSlot::Request, body)
              .to_string(),
          )
        })
        .unwrap_or(Value::Null),
    ),
    (ObjectRef::RequestTls, field) => object_model::eval_request_tls_member(ctx, field),
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
      Ok(Value::Int(body_size(response.headers, response.body)))
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
        .map(|body| {
          Value::String(
            ctx
              .body_text_caches
              .text(BodyTextSlot::Response, body)
              .to_string(),
          )
        })
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
    (ObjectRef::ResponseTransport, field) => {
      object_model::eval_response_transport_member(ctx, field)
    }
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
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match value {
    Value::String(text) => eval_string_call(&text, method, args, ctx, tx, regex_args),
    Value::Bytes(bytes) => eval_bytes_call(&bytes, method, args),
    Value::StringList(list) => eval_string_list_call(&list, method, args, ctx),
    Value::Object(ObjectRef::ContextRuleTags) => {
      eval_rule_tag_call(ctx.rule_tags, method, args, regex_args)
    }
    Value::Object(ObjectRef::RequestHeaders) => {
      eval_header_call(ctx.request.headers, method, args, ctx, regex_args)
    }
    Value::Object(ObjectRef::RequestNormalizedHeaders) => eval_pair_map_call(
      &normalize_header_pairs(ctx.request.headers),
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::ResponseHeaders) => eval_header_call(
      ctx.response.context("missing response context")?.headers,
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::RequestQueryParams) => eval_query_call(ctx, method, args, regex_args),
    Value::Object(ObjectRef::RequestNormalizedQueryParams) => eval_pair_map_call(
      &normalize_query_pairs(ctx.request.uri),
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::RequestCookies) => {
      eval_request_cookie_call(ctx, method, args, regex_args)
    }
    Value::Object(ObjectRef::ResponseCookies) => {
      eval_response_cookie_call(ctx, method, args, regex_args)
    }
    Value::Object(ObjectRef::RequestNormalizedCookies) => eval_pair_map_call(
      &normalize_cookie_pairs(ctx.request.headers),
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::RequestTags) => {
      eval_tag_call(ctx.request.tags, method, args, ctx, regex_args)
    }
    Value::Object(ObjectRef::ResponseTags) => eval_tag_call(
      ctx
        .response
        .context("missing response context")?
        .request
        .tags,
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::RequestTokenBindings) => eval_token_binding_call(ctx, method, args),
    Value::Object(ObjectRef::RequestBody) => eval_body_call(
      ctx.request.body,
      BodyTextSlot::Request,
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::ResponseBody) => eval_body_call(
      ctx.response.and_then(|response| response.body),
      BodyTextSlot::Response,
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::StreamPayload) => eval_body_call(
      ctx.stream.map(|stream| stream.payload),
      BodyTextSlot::Stream,
      method,
      args,
      ctx,
      regex_args,
    ),
    _ => bail!("method {method} is not available on {:?}", value),
  }
}

fn eval_string_call(
  text: &str,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
  _tx: &mut TransactionBudget,
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match method {
    "contains" => Ok(Value::Bool(text.contains(expect_string_arg(args, 0)?))),
    "startsWith" => Ok(Value::Bool(text.starts_with(expect_string_arg(args, 0)?))),
    "endsWith" => Ok(Value::Bool(text.ends_with(expect_string_arg(args, 0)?))),
    "matches" => {
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
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
    "anomalyScore" => Ok(Value::Int(mi_score::anomaly_score(
      text,
      expect_string_arg(args, 0)?,
    )?)),
    "malformedScore" => Ok(Value::Int(mi_score::malformed_score(
      text,
      expect_string_arg(args, 0)?,
    )?)),
    "promptInjectionScore" => Ok(Value::Int(mi_score::prompt_injection_score(text))),
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
  regex_args: CachedRegexArgs<'_>,
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
      let regex = header_name_regex_arg(args, 0, regex_args.get(RegexFlavor::HeaderName, 0))?;
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
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      Ok(Value::Bool(
        headers
          .values()
          .take(ctx.limits.max_helper_items)
          .filter_map(|value| value.to_str().ok())
          .any(|value| regex.is_match(value)),
      ))
    }
    "anyEntryMatches" => {
      let name_regex = header_name_regex_arg(args, 0, regex_args.get(RegexFlavor::HeaderName, 0))?;
      let value_regex = regex_arg(args, 1, regex_args.get(RegexFlavor::Default, 1))?;
      Ok(Value::Bool(
        headers
          .iter()
          .take(ctx.limits.max_helper_items)
          .filter_map(|(name, value)| value.to_str().ok().map(|value| (name, value)))
          .any(|(name, value)| name_regex.is_match(name.as_str()) && value_regex.is_match(value)),
      ))
    }
    "allEntriesMatch" => {
      let name_regex = header_name_regex_arg(args, 0, regex_args.get(RegexFlavor::HeaderName, 0))?;
      let value_regex = regex_arg(args, 1, regex_args.get(RegexFlavor::Default, 1))?;
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

fn eval_query_call(
  ctx: &EvalContext<'_>,
  method: &str,
  args: &[Value],
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  let query = ctx.request.uri.query().unwrap_or_default();
  let pairs = url::form_urlencoded::parse(query.as_bytes())
    .take(ctx.limits.max_helper_items)
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect::<Vec<_>>();
  eval_pair_map_call(&pairs, method, args, ctx, regex_args)
}

fn eval_tag_call(
  tags: &HashMap<String, String>,
  method: &str,
  args: &[Value],
  _ctx: &EvalContext<'_>,
  regex_args: CachedRegexArgs<'_>,
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
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      Ok(Value::Bool(tags.keys().any(|key| regex.is_match(key))))
    }
    "anyValueContains" => {
      let needle = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        tags.values().any(|value| value.contains(needle)),
      ))
    }
    "anyEntryMatches" => {
      let key_regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      let value_regex = regex_arg(args, 1, regex_args.get(RegexFlavor::Default, 1))?;
      Ok(Value::Bool(tags.iter().any(|(key, value)| {
        key_regex.is_match(key) && value_regex.is_match(value)
      })))
    }
    _ => bail!("unknown TagMap method {method}"),
  }
}

fn eval_rule_tag_call(
  tags: &[String],
  method: &str,
  args: &[Value],
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(tags.len() as i64)),
    "has" => {
      let expected = expect_string_arg(args, 0)?;
      Ok(Value::Bool(tags.iter().any(|tag| tag == expected)))
    }
    "anyMatches" => {
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
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
  regex_args: CachedRegexArgs<'_>,
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
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
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
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      Ok(Value::Bool(
        pairs.iter().any(|(_, value)| regex.is_match(value)),
      ))
    }
    "anyEntryMatches" => {
      let key_regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      let value_regex = regex_arg(args, 1, regex_args.get(RegexFlavor::Default, 1))?;
      Ok(Value::Bool(pairs.iter().any(|(key, value)| {
        key_regex.is_match(key) && value_regex.is_match(value)
      })))
    }
    _ => bail!("unknown bounded map method {method}"),
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

#[cfg(test)]
mod tests;
