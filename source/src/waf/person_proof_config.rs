use std::collections::HashMap;

use anyhow::bail;
use serde::Deserialize;

use crate::config::Config;

use super::defaults::{
  default_person_proof_openapi_path, default_person_proof_session_path,
  default_person_proof_verify_path,
};
use super::{PersonProofAlgorithm, WafActionConfig, WafRuleConfig, WafRuleGroupConfig};

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

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_redirect_settings(
  rule_name: &str,
  method: PersonProofAlgorithm,
  challenge_url: Option<&str>,
  challenge_redirect_status: u16,
  session_path: Option<&str>,
  verify_path: Option<&str>,
  openapi_path: Option<&str>,
  provider: Option<&str>,
  site_key: Option<&str>,
  secret_env: Option<&str>,
  provider_endpoint: Option<&url::Url>,
  provider_timeout_ms: u64,
  provider_max_response_body_bytes: usize,
) -> anyhow::Result<()> {
  if let Some(challenge_url) = challenge_url
    && !is_origin_relative_url(challenge_url, true)
  {
    bail!("WAF rule {rule_name} require_person_proof challenge_url must be origin-relative");
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
  if method.is_provider() {
    if challenge_url.is_none() {
      bail!(
        "WAF rule {rule_name} require_person_proof challenge_url is required for external providers"
      );
    }
    if method == PersonProofAlgorithm::CustomHttp {
      if provider_endpoint.is_none() {
        bail!(
          "WAF rule {rule_name} require_person_proof provider_endpoint is required for custom_http"
        );
      }
    } else {
      validate_non_empty(
        rule_name,
        "site_key",
        site_key,
        "is required for external providers",
      )?;
      validate_non_empty(
        rule_name,
        "secret_env",
        secret_env,
        "is required for external providers",
      )?;
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

fn is_origin_relative_url(value: &str, allow_query: bool) -> bool {
  value.starts_with('/')
    && !value.starts_with("//")
    && !value.contains('#')
    && (allow_query || !value.contains('?'))
    && value.bytes().all(|byte| byte.is_ascii())
}
