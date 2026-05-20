use std::collections::HashMap;

use anyhow::bail;

use crate::config::Config;

use super::{PersonProofAlgorithm, WafActionConfig, WafRuleConfig, WafRuleGroupConfig};

pub(super) fn validate_unique_verify_paths(config: &Config) -> anyhow::Result<()> {
  let mut paths = HashMap::new();
  remember_scope_verify_paths(&mut paths, "global WAF", &config.waf.rules)?;
  remember_group_verify_paths(&mut paths, "global WAF", &config.waf.rule_groups)?;
  for route in &config.routes {
    remember_scope_verify_paths(
      &mut paths,
      &format!("route {} WAF", route.name),
      &route.waf.rules,
    )?;
    remember_group_verify_paths(
      &mut paths,
      &format!("route {} WAF", route.name),
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
  verify_path: Option<&str>,
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
  if method.is_provider() {
    if challenge_url.is_none() {
      bail!(
        "WAF rule {rule_name} require_person_proof challenge_url is required for external providers"
      );
    }
    if verify_path.is_none() {
      bail!(
        "WAF rule {rule_name} require_person_proof verify_path is required for external providers"
      );
    }
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

fn remember_scope_verify_paths(
  paths: &mut HashMap<String, String>,
  scope: &str,
  rules: &[WafRuleConfig],
) -> anyhow::Result<()> {
  for rule in rules {
    remember_action_verify_paths(paths, &format!("{scope} rule {}", rule.name), &rule.actions)?;
    remember_group_verify_paths(
      paths,
      &format!("{scope} rule {}", rule.name),
      &rule.local_rule_groups,
    )?;
  }
  Ok(())
}

fn remember_group_verify_paths(
  paths: &mut HashMap<String, String>,
  scope: &str,
  groups: &[WafRuleGroupConfig],
) -> anyhow::Result<()> {
  for group in groups {
    remember_action_verify_paths(
      paths,
      &format!("{scope} group {}", group.name),
      &group.actions,
    )?;
  }
  Ok(())
}

fn remember_action_verify_paths(
  paths: &mut HashMap<String, String>,
  label: &str,
  actions: &[WafActionConfig],
) -> anyhow::Result<()> {
  for action in actions {
    let WafActionConfig::RequirePersonProof {
      method,
      verify_path: Some(verify_path),
      ..
    } = action
    else {
      continue;
    };
    if !method.is_provider() {
      continue;
    }
    if let Some(previous) = paths.insert(verify_path.clone(), label.to_string()) {
      bail!(
        "duplicate require_person_proof verify_path {verify_path} in {label}; already used by {previous}"
      );
    }
  }
  Ok(())
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
