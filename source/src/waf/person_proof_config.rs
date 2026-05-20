use std::collections::HashMap;

use anyhow::{Context, bail};
use http::HeaderName;
use serde::Deserialize;

use crate::config::Config;

use super::defaults::{
  default_cookie_path, default_person_proof_cookie, default_person_proof_local_storage_key,
  default_person_proof_local_storage_request_header, default_person_proof_openapi_path,
  default_person_proof_session_path, default_person_proof_verify_path, default_true,
};
use super::{WafActionConfig, WafRuleConfig, WafRuleGroupConfig};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafPersonProofConfig {
  #[serde(default = "default_person_proof_session_path")]
  pub session_path: String,
  #[serde(default = "default_person_proof_verify_path")]
  pub verify_path: String,
  #[serde(default = "default_person_proof_openapi_path")]
  pub openapi_path: String,
}

impl Default for WafPersonProofConfig {
  fn default() -> Self {
    Self {
      session_path: default_person_proof_session_path(),
      verify_path: default_person_proof_verify_path(),
      openapi_path: default_person_proof_openapi_path(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PersonProofMode {
  #[default]
  BuiltIn,
  OpenApi,
  ThirdPartyProvider,
  CustomProvider,
}

impl PersonProofMode {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::BuiltIn => "built_in",
      Self::OpenApi => "openapi",
      Self::ThirdPartyProvider => "third_party_provider",
      Self::CustomProvider => "custom_provider",
    }
  }

  pub(crate) fn uses_pow(self) -> bool {
    matches!(self, Self::BuiltIn | Self::OpenApi)
  }

  pub(crate) fn uses_provider(self) -> bool {
    matches!(self, Self::ThirdPartyProvider | Self::CustomProvider)
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PersonProofThirdPartyProvider {
  Turnstile,
  #[serde(rename = "hcaptcha")]
  HCaptcha,
  FriendlyCaptchaV2,
}

impl PersonProofThirdPartyProvider {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Turnstile => "turnstile",
      Self::HCaptcha => "hcaptcha",
      Self::FriendlyCaptchaV2 => "friendly_captcha_v2",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PersonProofClearanceConfig {
  #[serde(default)]
  pub issue_to: PersonProofClearanceIssueTarget,
  #[serde(default)]
  pub sources: Vec<PersonProofClearanceSourceConfig>,
  #[serde(default)]
  pub cookie: PersonProofClearanceCookieConfig,
  #[serde(default)]
  pub local_storage: PersonProofClearanceLocalStorageConfig,
}

impl Default for PersonProofClearanceConfig {
  fn default() -> Self {
    Self {
      issue_to: PersonProofClearanceIssueTarget::Cookie,
      sources: Vec::new(),
      cookie: PersonProofClearanceCookieConfig::default(),
      local_storage: PersonProofClearanceLocalStorageConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PersonProofClearanceIssueTarget {
  #[default]
  Cookie,
  LocalStorage,
  ResponseJson,
}

impl PersonProofClearanceIssueTarget {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Cookie => "cookie",
      Self::LocalStorage => "local_storage",
      Self::ResponseJson => "response_json",
    }
  }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PersonProofClearanceSourceConfig {
  Cookie { key: String },
  AuthorizationBearer,
  Header { key: String },
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct PersonProofClearanceCookieConfig {
  #[serde(default = "default_person_proof_cookie")]
  pub key: String,
  #[serde(default = "default_cookie_path")]
  pub path: String,
  #[serde(default)]
  pub same_site: PersonProofClearanceSameSite,
  #[serde(default = "default_true")]
  pub secure: bool,
  #[serde(default = "default_true")]
  pub http_only: bool,
}

impl Default for PersonProofClearanceCookieConfig {
  fn default() -> Self {
    Self {
      key: default_person_proof_cookie(),
      path: default_cookie_path(),
      same_site: PersonProofClearanceSameSite::default(),
      secure: true,
      http_only: true,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PersonProofClearanceSameSite {
  Strict,
  #[default]
  Lax,
  None,
}

impl PersonProofClearanceSameSite {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Strict => "Strict",
      Self::Lax => "Lax",
      Self::None => "None",
    }
  }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct PersonProofClearanceLocalStorageConfig {
  #[serde(default = "default_person_proof_local_storage_key")]
  pub key: String,
  #[serde(default = "default_person_proof_local_storage_request_header")]
  pub request_header: String,
}

impl Default for PersonProofClearanceLocalStorageConfig {
  fn default() -> Self {
    Self {
      key: default_person_proof_local_storage_key(),
      request_header: default_person_proof_local_storage_request_header(),
    }
  }
}

pub(super) fn validate_api_paths(config: &Config) -> anyhow::Result<()> {
  validate_global_paths(&config.waf.person_proof)?;
  let mut paths = HashMap::new();
  remember_scope_api_paths(
    &mut paths,
    "global WAF",
    &config.waf.person_proof,
    &config.waf.rules,
  )?;
  remember_group_api_paths(
    &mut paths,
    "global WAF",
    &config.waf.person_proof,
    &config.waf.rule_groups,
  )?;
  for route in &config.routes {
    remember_scope_api_paths(
      &mut paths,
      &format!("route {} WAF", route.name),
      &config.waf.person_proof,
      &route.waf.rules,
    )?;
    remember_group_api_paths(
      &mut paths,
      &format!("route {} WAF", route.name),
      &config.waf.person_proof,
      &route.waf.rule_groups,
    )?;
  }
  Ok(())
}

pub(super) fn validate_clearance_settings(
  rule_name: &str,
  clearance: &PersonProofClearanceConfig,
) -> anyhow::Result<()> {
  if !is_valid_cookie_name(&clearance.cookie.key) {
    bail!(
      "WAF rule {rule_name} require_person_proof clearance.cookie.key must be a safe cookie name"
    );
  }
  if !is_valid_cookie_path(&clearance.cookie.path) {
    bail!(
      "WAF rule {rule_name} require_person_proof clearance.cookie.path must be a safe cookie path"
    );
  }
  if !is_valid_local_storage_key(&clearance.local_storage.key) {
    bail!(
      "WAF rule {rule_name} require_person_proof clearance.local_storage.key must not be empty or contain control characters"
    );
  }
  validate_header_name(&clearance.local_storage.request_header).with_context(|| {
    format!(
      "WAF rule {rule_name} require_person_proof clearance.local_storage.request_header is invalid"
    )
  })?;
  if clearance.sources.is_empty()
    && clearance.issue_to == PersonProofClearanceIssueTarget::ResponseJson
  {
    bail!(
      "WAF rule {rule_name} require_person_proof clearance.sources must not be empty when issue_to is response_json"
    );
  }
  for source in &clearance.sources {
    match source {
      PersonProofClearanceSourceConfig::Cookie { key } => {
        if !is_valid_cookie_name(key) {
          bail!(
            "WAF rule {rule_name} require_person_proof clearance source cookie key must be a safe cookie name"
          );
        }
      }
      PersonProofClearanceSourceConfig::AuthorizationBearer => {}
      PersonProofClearanceSourceConfig::Header { key } => {
        validate_header_name(key).with_context(|| {
          format!(
            "WAF rule {rule_name} require_person_proof clearance source header key is invalid"
          )
        })?;
      }
    }
  }
  Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_redirect_settings(
  rule_name: &str,
  person_proof_mode: PersonProofMode,
  custom_frontend_url: Option<&str>,
  challenge_redirect_status: u16,
  session_path: Option<&str>,
  verify_path: Option<&str>,
  openapi_path: Option<&str>,
  third_party_provider: Option<PersonProofThirdPartyProvider>,
  provider: Option<&str>,
  site_key: Option<&str>,
  secret_env: Option<&str>,
  provider_endpoint: Option<&url::Url>,
  provider_timeout_ms: u64,
  provider_max_response_body_bytes: usize,
) -> anyhow::Result<()> {
  if let Some(custom_frontend_url) = custom_frontend_url
    && !is_origin_relative_url(custom_frontend_url, true)
  {
    bail!("WAF rule {rule_name} require_person_proof custom_frontend_url must be origin-relative");
  }
  if !matches!(challenge_redirect_status, 301 | 302 | 303 | 307 | 308) {
    bail!(
      "WAF rule {rule_name} require_person_proof challenge_redirect_status must be 301, 302, 303, 307, or 308"
    );
  }
  if let Some(verify_path) = verify_path
    && !is_origin_relative_url(verify_path, false)
  {
    bail!("WAF rule {rule_name} require_person_proof verify_path must be an origin-relative path");
  }
  if let Some(session_path) = session_path
    && !is_origin_relative_url(session_path, false)
  {
    bail!("WAF rule {rule_name} require_person_proof session_path must be an origin-relative path");
  }
  if let Some(openapi_path) = openapi_path
    && !is_origin_relative_url(openapi_path, false)
  {
    bail!("WAF rule {rule_name} require_person_proof openapi_path must be an origin-relative path");
  }
  if let Some(provider) = provider
    && provider.trim().is_empty()
  {
    bail!("WAF rule {rule_name} require_person_proof provider must not be empty");
  }
  match person_proof_mode {
    PersonProofMode::BuiltIn => {
      if custom_frontend_url.is_some() {
        bail!(
          "WAF rule {rule_name} require_person_proof custom_frontend_url is not allowed for built_in mode"
        );
      }
      if third_party_provider.is_some() {
        bail!(
          "WAF rule {rule_name} require_person_proof third_party_provider is only valid for third_party_provider mode"
        );
      }
    }
    PersonProofMode::OpenApi => {
      if custom_frontend_url.is_none() {
        bail!(
          "WAF rule {rule_name} require_person_proof custom_frontend_url is required for openapi mode"
        );
      }
      if third_party_provider.is_some() {
        bail!(
          "WAF rule {rule_name} require_person_proof third_party_provider is only valid for third_party_provider mode"
        );
      }
    }
    PersonProofMode::ThirdPartyProvider => {
      if custom_frontend_url.is_none() {
        bail!(
          "WAF rule {rule_name} require_person_proof custom_frontend_url is required for third_party_provider mode"
        );
      }
      if third_party_provider.is_none() {
        bail!(
          "WAF rule {rule_name} require_person_proof third_party_provider is required for third_party_provider mode"
        );
      }
      if provider.is_some() {
        bail!(
          "WAF rule {rule_name} require_person_proof provider is only valid for custom_provider mode"
        );
      }
      validate_non_empty(
        rule_name,
        "site_key",
        site_key,
        "is required for third_party_provider mode",
      )?;
      validate_non_empty(
        rule_name,
        "secret_env",
        secret_env,
        "is required for third_party_provider mode",
      )?;
    }
    PersonProofMode::CustomProvider => {
      if custom_frontend_url.is_none() {
        bail!(
          "WAF rule {rule_name} require_person_proof custom_frontend_url is required for custom_provider mode"
        );
      }
      if third_party_provider.is_some() {
        bail!(
          "WAF rule {rule_name} require_person_proof third_party_provider is only valid for third_party_provider mode"
        );
      }
      if provider_endpoint.is_none() {
        bail!(
          "WAF rule {rule_name} require_person_proof provider_endpoint is required for custom_provider mode"
        );
      }
    }
  }
  if let Some(endpoint) = provider_endpoint
    && endpoint.scheme() != "http"
    && endpoint.scheme() != "https"
  {
    bail!(
      "WAF rule {rule_name} require_person_proof provider_endpoint must use http:// or https://"
    );
  }
  if provider_timeout_ms == 0 {
    bail!("WAF rule {rule_name} require_person_proof provider_timeout_ms must be greater than 0");
  }
  if provider_max_response_body_bytes == 0 {
    bail!(
      "WAF rule {rule_name} require_person_proof provider_max_response_body_bytes must be greater than 0"
    );
  }
  Ok(())
}

fn validate_global_paths(defaults: &WafPersonProofConfig) -> anyhow::Result<()> {
  for (field, value) in [
    (
      "waf.person_proof.session_path",
      defaults.session_path.as_str(),
    ),
    (
      "waf.person_proof.verify_path",
      defaults.verify_path.as_str(),
    ),
    (
      "waf.person_proof.openapi_path",
      defaults.openapi_path.as_str(),
    ),
  ] {
    if !is_origin_relative_url(value, false) {
      bail!("{field} must be an origin-relative path");
    }
  }
  if defaults.session_path == defaults.verify_path
    || defaults.session_path == defaults.openapi_path
    || defaults.verify_path == defaults.openapi_path
  {
    bail!("waf.person_proof API paths must be distinct");
  }
  Ok(())
}

fn remember_scope_api_paths(
  paths: &mut HashMap<String, ApiPathUse>,
  scope: &str,
  defaults: &WafPersonProofConfig,
  rules: &[WafRuleConfig],
) -> anyhow::Result<()> {
  for rule in rules {
    remember_action_api_paths(
      paths,
      &format!("{scope} rule {}", rule.name),
      defaults,
      &rule.actions,
    )?;
    remember_group_api_paths(
      paths,
      &format!("{scope} rule {}", rule.name),
      defaults,
      &rule.local_rule_groups,
    )?;
  }
  Ok(())
}

fn remember_group_api_paths(
  paths: &mut HashMap<String, ApiPathUse>,
  scope: &str,
  defaults: &WafPersonProofConfig,
  groups: &[WafRuleGroupConfig],
) -> anyhow::Result<()> {
  for group in groups {
    remember_action_api_paths(
      paths,
      &format!("{scope} group {}", group.name),
      defaults,
      &group.actions,
    )?;
  }
  Ok(())
}

fn remember_action_api_paths(
  paths: &mut HashMap<String, ApiPathUse>,
  label: &str,
  defaults: &WafPersonProofConfig,
  actions: &[WafActionConfig],
) -> anyhow::Result<()> {
  for action in actions {
    let WafActionConfig::RequirePersonProof {
      session_path,
      verify_path,
      openapi_path,
      ..
    } = action
    else {
      continue;
    };
    remember_api_path(
      paths,
      label,
      "session",
      session_path,
      &defaults.session_path,
    )?;
    remember_api_path(paths, label, "verify", verify_path, &defaults.verify_path)?;
    remember_api_path(
      paths,
      label,
      "openapi",
      openapi_path,
      &defaults.openapi_path,
    )?;
  }
  Ok(())
}

fn remember_api_path(
  paths: &mut HashMap<String, ApiPathUse>,
  label: &str,
  role: &'static str,
  configured: &Option<String>,
  fallback: &str,
) -> anyhow::Result<()> {
  let value = configured.as_deref().unwrap_or(fallback);
  let explicit = configured.is_some();
  if let Some(previous) = paths.get(value) {
    if previous.role != role {
      bail!(
        "duplicate require_person_proof API path {value} in {label}; already used as {} by {}",
        previous.role,
        previous.label
      );
    }
    if previous.explicit && explicit {
      bail!(
        "duplicate require_person_proof {role}_path {value} in {label}; already used by {}",
        previous.label
      );
    }
    return Ok(());
  }
  paths.insert(
    value.to_string(),
    ApiPathUse {
      role,
      label: label.to_string(),
      explicit,
    },
  );
  Ok(())
}

struct ApiPathUse {
  role: &'static str,
  label: String,
  explicit: bool,
}

fn validate_non_empty(
  rule_name: &str,
  field: &str,
  value: Option<&str>,
  missing_message: &str,
) -> anyhow::Result<()> {
  match value {
    Some(value) if !value.trim().is_empty() => Ok(()),
    Some(_) => bail!("WAF rule {rule_name} require_person_proof {field} must not be empty"),
    None => bail!("WAF rule {rule_name} require_person_proof {field} {missing_message}"),
  }
}

fn validate_header_name(name: &str) -> anyhow::Result<()> {
  HeaderName::from_bytes(name.as_bytes()).context("invalid WAF header name")?;
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

fn is_valid_cookie_path(path: &str) -> bool {
  !path.is_empty()
    && path.starts_with('/')
    && path
      .bytes()
      .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && byte != b';')
}

fn is_valid_local_storage_key(key: &str) -> bool {
  !key.is_empty() && key.len() <= 256 && key.chars().all(|character| !character.is_control())
}

fn is_origin_relative_url(value: &str, allow_query: bool) -> bool {
  value.starts_with('/')
    && !value.starts_with("//")
    && !value.contains('#')
    && (allow_query || !value.contains('?'))
    && value.bytes().all(|byte| byte.is_ascii())
}
