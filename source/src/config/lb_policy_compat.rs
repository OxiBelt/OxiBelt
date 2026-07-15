//! Explicit load-balancing policy compatibility helpers for nginx/Caddy migration UX.
//! Canonical OxiBelt wire values remain the default; compatibility only runs by opt-in.

use anyhow::bail;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LbPolicyCompatProfile {
  #[default]
  Strict,
  Nginx,
  Caddy,
}

impl LbPolicyCompatProfile {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Strict => "strict",
      Self::Nginx => "nginx",
      Self::Caddy => "caddy",
    }
  }

  pub fn is_compat(self) -> bool {
    !matches!(self, Self::Strict)
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LbPolicyCompatDiagnosticKind {
  Converted,
  Unsupported,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct LbPolicyCompatDiagnostic {
  pub kind: LbPolicyCompatDiagnosticKind,
  pub path: String,
  pub profile: &'static str,
  pub original: String,
  pub replacement: Option<&'static str>,
  pub message: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct LbPolicyCompatReport {
  pub profile: &'static str,
  pub converted_toml: String,
  pub diagnostics: Vec<LbPolicyCompatDiagnostic>,
}

pub fn normalize_toml_from_config(
  value: &mut toml::Value,
) -> anyhow::Result<Vec<LbPolicyCompatDiagnostic>> {
  let profile = profile_from_config(value)?;
  Ok(normalize_toml_with_profile(value, profile))
}

pub fn normalize_toml_with_profile(
  value: &mut toml::Value,
  profile: LbPolicyCompatProfile,
) -> Vec<LbPolicyCompatDiagnostic> {
  let mut diagnostics = Vec::new();
  if !profile.is_compat() {
    return diagnostics;
  }

  normalize_pool_arrays(value, "upstream_pools", profile, &mut diagnostics);
  normalize_pool_arrays(value, "turn_upstream_pools", profile, &mut diagnostics);
  normalize_waf_value(value, profile, &mut diagnostics);
  diagnostics
}

pub fn normalize_policy_string(
  path: impl Into<String>,
  policy: &mut String,
  profile: LbPolicyCompatProfile,
  diagnostics: &mut Vec<LbPolicyCompatDiagnostic>,
) {
  if !profile.is_compat() {
    return;
  }
  match compatibility_decision(policy.as_str()) {
    Some(CompatibilityDecision::Convert(replacement)) => {
      let original = std::mem::replace(policy, replacement.to_string());
      diagnostics.push(LbPolicyCompatDiagnostic {
        kind: LbPolicyCompatDiagnosticKind::Converted,
        path: path.into(),
        profile: profile.as_str(),
        original: original.clone(),
        replacement: Some(replacement),
        message: format!("{original} is converted to canonical OxiBelt policy {replacement}"),
      });
    }
    Some(CompatibilityDecision::Unsupported) => {
      diagnostics.push(unsupported_diagnostic(
        path.into(),
        profile,
        policy.as_str(),
      ));
    }
    None => {}
  }
}

pub fn ensure_supported(diagnostics: &[LbPolicyCompatDiagnostic]) -> anyhow::Result<()> {
  let unsupported = diagnostics
    .iter()
    .filter(|diagnostic| diagnostic.kind == LbPolicyCompatDiagnosticKind::Unsupported)
    .collect::<Vec<_>>();
  if unsupported.is_empty() {
    return Ok(());
  }

  let details = unsupported
    .into_iter()
    .map(|diagnostic| {
      format!(
        "{} uses unsupported {} policy {}",
        diagnostic.path, diagnostic.profile, diagnostic.original
      )
    })
    .collect::<Vec<_>>()
    .join("; ");
  bail!(
    "unsupported load-balancing compatibility policy; choose an OxiBelt canonical policy instead: {details}"
  );
}

fn profile_from_config(value: &toml::Value) -> anyhow::Result<LbPolicyCompatProfile> {
  let Some(raw) = value
    .get("config")
    .and_then(|config| config.get("lb_policy_compat_profile"))
  else {
    return Ok(LbPolicyCompatProfile::Strict);
  };
  let Some(raw) = raw.as_str() else {
    bail!("config.lb_policy_compat_profile must be a string");
  };
  match raw {
    "strict" => Ok(LbPolicyCompatProfile::Strict),
    "nginx" => Ok(LbPolicyCompatProfile::Nginx),
    "caddy" => Ok(LbPolicyCompatProfile::Caddy),
    _ => {
      bail!("unsupported config.lb_policy_compat_profile {raw}; expected strict, nginx, or caddy")
    }
  }
}

fn normalize_pool_arrays(
  value: &mut toml::Value,
  array_name: &str,
  profile: LbPolicyCompatProfile,
  diagnostics: &mut Vec<LbPolicyCompatDiagnostic>,
) {
  let Some(pools) = value
    .get_mut(array_name)
    .and_then(toml::Value::as_array_mut)
  else {
    return;
  };
  for (index, pool) in pools.iter_mut().enumerate() {
    normalize_table_string(
      pool,
      "algorithm",
      format!("{array_name}[{index}].algorithm"),
      profile,
      diagnostics,
    );
    if array_name == "upstream_pools"
      && let Some(sticky_cookie) = pool.get_mut("sticky_cookie")
    {
      normalize_table_string(
        sticky_cookie,
        "fallback_algorithm",
        format!("{array_name}[{index}].sticky_cookie.fallback_algorithm"),
        profile,
        diagnostics,
      );
    }
  }
}

fn normalize_waf_value(
  value: &mut toml::Value,
  profile: LbPolicyCompatProfile,
  diagnostics: &mut Vec<LbPolicyCompatDiagnostic>,
) {
  if let Some(waf) = value.get_mut("waf") {
    normalize_waf_scope(waf, "waf", profile, diagnostics);
  }
  let Some(routes) = value.get_mut("routes").and_then(toml::Value::as_array_mut) else {
    return;
  };
  for (route_index, route) in routes.iter_mut().enumerate() {
    if let Some(waf) = route.get_mut("waf") {
      normalize_waf_scope(
        waf,
        &format!("routes[{route_index}].waf"),
        profile,
        diagnostics,
      );
    }
  }
}

fn normalize_waf_scope(
  value: &mut toml::Value,
  path: &str,
  profile: LbPolicyCompatProfile,
  diagnostics: &mut Vec<LbPolicyCompatDiagnostic>,
) {
  normalize_waf_rules(value, path, "rules", profile, diagnostics);
  normalize_waf_rule_groups(value, path, "rule_groups", profile, diagnostics);
}

fn normalize_waf_rules(
  value: &mut toml::Value,
  path: &str,
  field: &str,
  profile: LbPolicyCompatProfile,
  diagnostics: &mut Vec<LbPolicyCompatDiagnostic>,
) {
  let Some(rules) = value.get_mut(field).and_then(toml::Value::as_array_mut) else {
    return;
  };
  for (rule_index, rule) in rules.iter_mut().enumerate() {
    normalize_waf_actions(
      rule,
      &format!("{path}.{field}[{rule_index}]"),
      profile,
      diagnostics,
    );
    normalize_waf_rule_groups(
      rule,
      &format!("{path}.{field}[{rule_index}]"),
      "local_rule_groups",
      profile,
      diagnostics,
    );
  }
}

fn normalize_waf_rule_groups(
  value: &mut toml::Value,
  path: &str,
  field: &str,
  profile: LbPolicyCompatProfile,
  diagnostics: &mut Vec<LbPolicyCompatDiagnostic>,
) {
  let Some(groups) = value.get_mut(field).and_then(toml::Value::as_array_mut) else {
    return;
  };
  for (group_index, group) in groups.iter_mut().enumerate() {
    normalize_waf_actions(
      group,
      &format!("{path}.{field}[{group_index}]"),
      profile,
      diagnostics,
    );
  }
}

fn normalize_waf_actions(
  value: &mut toml::Value,
  path: &str,
  profile: LbPolicyCompatProfile,
  diagnostics: &mut Vec<LbPolicyCompatDiagnostic>,
) {
  let Some(actions) = value.get_mut("actions").and_then(toml::Value::as_array_mut) else {
    return;
  };
  for (action_index, action) in actions.iter_mut().enumerate() {
    if action.get("type").and_then(toml::Value::as_str) != Some("set_load_balancing_policy") {
      continue;
    }
    normalize_table_string(
      action,
      "policy",
      format!("{path}.actions[{action_index}].policy"),
      profile,
      diagnostics,
    );
  }
}

fn normalize_table_string(
  value: &mut toml::Value,
  field: &str,
  path: String,
  profile: LbPolicyCompatProfile,
  diagnostics: &mut Vec<LbPolicyCompatDiagnostic>,
) {
  let Some(raw) = value.get_mut(field).and_then(|value| value.as_str()) else {
    return;
  };
  match compatibility_decision(raw) {
    Some(CompatibilityDecision::Convert(replacement)) => {
      let original = raw.to_string();
      if let Some(value) = value.get_mut(field) {
        *value = toml::Value::String(replacement.to_string());
      }
      diagnostics.push(LbPolicyCompatDiagnostic {
        kind: LbPolicyCompatDiagnosticKind::Converted,
        path,
        profile: profile.as_str(),
        original: original.clone(),
        replacement: Some(replacement),
        message: format!("{original} is converted to canonical OxiBelt policy {replacement}"),
      });
    }
    Some(CompatibilityDecision::Unsupported) => {
      diagnostics.push(unsupported_diagnostic(path, profile, raw));
    }
    None => {}
  }
}

fn unsupported_diagnostic(
  path: String,
  profile: LbPolicyCompatProfile,
  original: &str,
) -> LbPolicyCompatDiagnostic {
  LbPolicyCompatDiagnostic {
    kind: LbPolicyCompatDiagnosticKind::Unsupported,
    path,
    profile: profile.as_str(),
    original: original.to_string(),
    replacement: None,
    message: format!(
      "{original} does not have an exact OxiBelt equivalent; choose a canonical policy explicitly"
    ),
  }
}

fn compatibility_decision(raw: &str) -> Option<CompatibilityDecision> {
  match raw {
    "least_conn" | "least_connections" => {
      Some(CompatibilityDecision::Convert("weighted_least_conn"))
    }
    "ip_hash" => Some(CompatibilityDecision::Convert("rendezvous_ip_hash")),
    "round_robin" | "random" | "hash" => Some(CompatibilityDecision::Unsupported),
    _ => None,
  }
}

enum CompatibilityDecision {
  Convert(&'static str),
  Unsupported,
}
