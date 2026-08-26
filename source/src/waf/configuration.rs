//! WAF schema, typed actions, phases, and limits.

use super::*;

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
  pub(super) rulepack_base_dir: Option<PathBuf>,
  #[serde(skip)]
  pub(super) rulepack_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  pub(super) rulepack_files_logical: Vec<PathBuf>,
  #[serde(skip)]
  pub(super) loaded_rulepacks: Vec<WafRulepackSummary>,
  #[serde(skip)]
  pub(super) rule_group_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  pub(super) rule_group_files_logical: Vec<PathBuf>,
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
  pub(super) rulepack_base_dir: Option<PathBuf>,
  #[serde(skip)]
  pub(super) rulepack_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  pub(super) rulepack_files_logical: Vec<PathBuf>,
  #[serde(skip)]
  pub(super) loaded_rulepacks: Vec<WafRulepackSummary>,
  #[serde(skip)]
  pub(super) rule_group_files_resolved: Vec<PathBuf>,
  #[serde(skip)]
  pub(super) rule_group_files_logical: Vec<PathBuf>,
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
  #[serde(default = "default_max_advanced_regex_subject_bytes")]
  pub max_advanced_regex_subject_bytes: usize,
  #[serde(default = "default_max_advanced_regex_backtracks")]
  pub max_advanced_regex_backtracks: usize,
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
      max_advanced_regex_subject_bytes: default_max_advanced_regex_subject_bytes(),
      max_advanced_regex_backtracks: default_max_advanced_regex_backtracks(),
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

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WafPhase {
  Request,
  Response,
  Stream,
}

impl WafPhase {
  pub(super) fn as_str(self) -> &'static str {
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
pub(super) struct ExternalRuleFile {
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
pub(super) struct ExternalRuleGroupFile {
  #[serde(default)]
  pub(super) rule_groups: Vec<WafRuleGroupConfig>,
}
