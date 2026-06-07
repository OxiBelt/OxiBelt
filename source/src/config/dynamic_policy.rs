//! Dynamic policy configuration validation.
//! Signature and refresh settings are checked before policy records are loaded.

use std::collections::HashSet;

use anyhow::{Context, bail};
use base64::Engine;
use serde::Deserialize;

use super::RateLimitIdentityPart;
use crate::dynamic_policy::MAX_DYNAMIC_POLICY_BODY_BYTES;
use crate::waf::PersonProofTokenBinding;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DynamicPolicyConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub backend: Option<String>,
  #[serde(default = "default_dynamic_policy_refresh_interval_ms")]
  pub refresh_interval_ms: u64,
  #[serde(default = "default_dynamic_policy_max_policies")]
  pub max_policies: usize,
  #[serde(default)]
  pub fail_policy: DynamicPolicyFailPolicy,
  #[serde(default = "default_dynamic_policy_status")]
  pub default_status: u16,
  #[serde(default = "default_dynamic_policy_body")]
  pub default_body: String,
  #[serde(default)]
  pub matching: DynamicPolicyMatchingConfig,
  #[serde(default)]
  pub automation_api: DynamicPolicyAutomationApiConfig,
}

impl Default for DynamicPolicyConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      backend: None,
      refresh_interval_ms: default_dynamic_policy_refresh_interval_ms(),
      max_policies: default_dynamic_policy_max_policies(),
      fail_policy: DynamicPolicyFailPolicy::default(),
      default_status: default_dynamic_policy_status(),
      default_body: default_dynamic_policy_body(),
      matching: DynamicPolicyMatchingConfig::default(),
      automation_api: DynamicPolicyAutomationApiConfig::default(),
    }
  }
}

impl DynamicPolicyConfig {
  pub(crate) fn validate_basic(&self) -> anyhow::Result<()> {
    if self.refresh_interval_ms == 0 {
      bail!("dynamic_policy.refresh_interval_ms must be greater than 0");
    }
    if self.max_policies == 0 {
      bail!("dynamic_policy.max_policies must be greater than 0");
    }
    http::StatusCode::from_u16(self.default_status)
      .context("dynamic_policy.default_status is not a valid HTTP status")?;
    if self.default_body.len() > MAX_DYNAMIC_POLICY_BODY_BYTES {
      bail!(
        "dynamic_policy.default_body must be at most {} bytes",
        MAX_DYNAMIC_POLICY_BODY_BYTES
      );
    }
    self.matching.validate()?;
    self.automation_api.validate(self.max_policies)
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DynamicPolicyFailPolicy {
  #[default]
  UseLastGood,
  FailClosedOnStartup,
  DisabledOnError,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DynamicPolicyMatchingConfig {
  #[serde(default = "default_true")]
  pub trust_route_name: bool,
  #[serde(default = "default_true")]
  pub normalize_path: bool,
  #[serde(default = "crate::limits::default_rate_limit_ipv4_prefix_bits")]
  pub ipv4_prefix_bits: u8,
  #[serde(default = "crate::limits::default_rate_limit_ipv6_prefix_bits")]
  pub ipv6_prefix_bits: u8,
  #[serde(default = "default_dynamic_policy_token_bindings")]
  pub token_bindings: Vec<PersonProofTokenBinding>,
  #[serde(default = "default_dynamic_policy_composite_identity_parts")]
  pub composite_identity_parts: Vec<RateLimitIdentityPart>,
}

impl Default for DynamicPolicyMatchingConfig {
  fn default() -> Self {
    Self {
      trust_route_name: true,
      normalize_path: true,
      ipv4_prefix_bits: crate::limits::default_rate_limit_ipv4_prefix_bits(),
      ipv6_prefix_bits: crate::limits::default_rate_limit_ipv6_prefix_bits(),
      token_bindings: default_dynamic_policy_token_bindings(),
      composite_identity_parts: default_dynamic_policy_composite_identity_parts(),
    }
  }
}

impl DynamicPolicyMatchingConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.ipv4_prefix_bits > 32 {
      bail!("dynamic_policy.matching.ipv4_prefix_bits must be between 0 and 32");
    }
    if self.ipv6_prefix_bits > 128 {
      bail!("dynamic_policy.matching.ipv6_prefix_bits must be between 0 and 128");
    }
    if self.token_bindings.is_empty() {
      bail!("dynamic_policy.matching.token_bindings must not be empty");
    }
    let mut seen_bindings = HashSet::new();
    for binding in &self.token_bindings {
      if !seen_bindings.insert(*binding) {
        bail!(
          "dynamic_policy.matching.token_bindings contains duplicate {}",
          binding.as_str()
        );
      }
    }
    if self.composite_identity_parts.is_empty() {
      bail!("dynamic_policy.matching.composite_identity_parts must not be empty");
    }
    let mut seen_parts = HashSet::new();
    for part in &self.composite_identity_parts {
      if !seen_parts.insert(*part) {
        bail!("dynamic_policy.matching.composite_identity_parts contains duplicate {part:?}");
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DynamicPolicyAutomationApiConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub require_ttl: bool,
  #[serde(default = "default_dynamic_policy_signature_key_env")]
  pub signature_key_env: String,
  #[serde(default)]
  pub default_source_quota: Option<usize>,
  #[serde(default)]
  pub source_quotas: Vec<DynamicPolicySourceQuotaConfig>,
}

impl Default for DynamicPolicyAutomationApiConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      require_ttl: true,
      signature_key_env: default_dynamic_policy_signature_key_env(),
      default_source_quota: None,
      source_quotas: Vec::new(),
    }
  }
}

impl DynamicPolicyAutomationApiConfig {
  fn validate(&self, max_policies: usize) -> anyhow::Result<()> {
    if self.signature_key_env.trim().is_empty() {
      bail!("dynamic_policy.automation_api.signature_key_env must not be empty");
    }
    if let Some(quota) = self.default_source_quota
      && quota == 0
    {
      bail!("dynamic_policy.automation_api.default_source_quota must be greater than 0");
    }
    if let Some(quota) = self.default_source_quota
      && quota > max_policies
    {
      bail!(
        "dynamic_policy.automation_api.default_source_quota must be less than or equal to dynamic_policy.max_policies"
      );
    }
    let mut sources = std::collections::HashSet::new();
    for quota in &self.source_quotas {
      if quota.source.trim().is_empty() {
        bail!("dynamic_policy.automation_api.source_quotas.source must not be empty");
      }
      if !sources.insert(quota.source.as_str()) {
        bail!(
          "duplicate dynamic_policy.automation_api.source_quotas source {}",
          quota.source
        );
      }
      if quota.max_active_policies == 0 || quota.max_active_policies > max_policies {
        bail!(
          "dynamic_policy.automation_api.source_quotas {} max_active_policies must be between 1 and dynamic_policy.max_policies",
          quota.source
        );
      }
    }
    Ok(())
  }

  pub(crate) fn validate_signature_key_env(&self) -> anyhow::Result<()> {
    let raw = std::env::var(&self.signature_key_env).with_context(|| {
      format!(
        "failed to read dynamic_policy.automation_api.signature_key_env {}",
        self.signature_key_env
      )
    })?;
    let bytes = base64::engine::general_purpose::STANDARD
      .decode(raw.trim())
      .context("dynamic_policy.automation_api.signature_key_env must contain base64")?;
    if bytes.len() != 32 {
      bail!("dynamic_policy.automation_api.signature_key_env must contain exactly 32 bytes");
    }
    Ok(())
  }

  pub fn quota_for_source(&self, source: &str, max_policies: usize) -> usize {
    self
      .source_quotas
      .iter()
      .find(|quota| quota.source == source)
      .map(|quota| quota.max_active_policies)
      .or(self.default_source_quota)
      .unwrap_or(max_policies)
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DynamicPolicySourceQuotaConfig {
  pub source: String,
  pub max_active_policies: usize,
}

fn default_true() -> bool {
  true
}

fn default_dynamic_policy_token_bindings() -> Vec<PersonProofTokenBinding> {
  vec![
    PersonProofTokenBinding::UserAgent,
    PersonProofTokenBinding::TlsFingerprint,
    PersonProofTokenBinding::Route,
    PersonProofTokenBinding::DirectPeerIpNetworkPrefix,
  ]
}

fn default_dynamic_policy_composite_identity_parts() -> Vec<RateLimitIdentityPart> {
  vec![
    RateLimitIdentityPart::ClientIpPrefix,
    RateLimitIdentityPart::UserAgent,
    RateLimitIdentityPart::TlsFingerprint,
    RateLimitIdentityPart::Asn,
  ]
}

fn default_dynamic_policy_refresh_interval_ms() -> u64 {
  2_000
}

fn default_dynamic_policy_max_policies() -> usize {
  10_000
}

fn default_dynamic_policy_status() -> u16 {
  429
}

fn default_dynamic_policy_body() -> String {
  "Blocked by dynamic policy".to_string()
}

fn default_dynamic_policy_signature_key_env() -> String {
  "OXIBELT_DYNAMIC_POLICY_HMAC_KEY".to_string()
}
