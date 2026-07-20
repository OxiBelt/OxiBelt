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
use std::path::PathBuf;
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
mod action_execution;
mod async_evaluation;
mod binary_format;
mod body_cache;
mod body_eval;
mod body_scan;
mod compiler;
mod configuration;
mod crs;
mod defaults;
mod devtools;
mod engine;
mod evaluator_calls;
mod evaluator_core;
mod evaluator_helpers;
mod evaluator_member;
mod evaluator_values;
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
mod phase_runtime;
mod plan;
mod request_header_mutation;
mod rule_groups;
mod rulepacks;
mod runtime_helpers;
mod runtime_types;
mod validation;

use access_log_record::AccessLogJsonValue;
pub use access_log_record::AccessLogRecord;
use action_execution::*;
pub use action_execution::{apply_header_mutations, current_unix_ms};
use binary_format::bytes_match_format;
use body_cache::{BodyTextCaches, BodyTextSlot};
use body_eval::eval_body_call;
use compiler::*;
pub use compiler::{
  CompiledAccessLogFields, WafRuleCostSnapshot, WafRuleHitSnapshot, compile_access_log_fields,
  new_access_log_id,
};
pub use configuration::*;
pub use crs::{CrsCompatibilityMatrix, compatibility_matrix as crs_compatibility_matrix};
use crs::{CrsDecision, CrsEngine, WafCrsConfig, validate_crs_config};
use defaults::*;
pub use devtools::*;
use evaluator_calls::*;
use evaluator_core::*;
use evaluator_helpers::*;
use evaluator_member::*;
use evaluator_values::*;
use expression::{Expr, Parser};
pub use external_files::validate_external_rule_group_file;
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
pub use runtime_types::*;
use validation::{
  is_valid_rule_label, validate_access_log_field_name, validate_status,
  validate_websocket_close_code,
};
pub use validation::{validate_access_log_field_configs, validate_config};

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

#[cfg(test)]
mod tests;
