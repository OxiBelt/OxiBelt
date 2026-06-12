use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RulepackInputMetadata {
  pub summary: super::WafRulepackSummary,
  pub variables: Vec<RulepackVariable>,
  pub bindings: Vec<RulepackBinding>,
  pub profiles: Vec<RulepackProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RulepackVariable {
  pub name: String,
  #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
  pub value_type: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub default: Option<String>,
  #[serde(default)]
  pub required: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub description: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub prompt: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RulepackBinding {
  pub name: String,
  pub kind: RulepackBindingKind,
  pub bind_as: String,
  #[serde(default)]
  pub required: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub description: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub prompt: Option<String>,
  #[serde(default)]
  pub discovery: RulepackDiscovery,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RulepackProfile {
  pub name: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub mode: Option<super::WafMode>,
  #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
  pub values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RulepackBindingKind {
  Route,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RulepackDiscovery {
  #[serde(default)]
  pub name_any: Vec<String>,
  #[serde(default)]
  pub host_contains_any: Vec<String>,
  #[serde(default)]
  pub upstream_contains_any: Vec<String>,
  #[serde(default)]
  pub path_prefix_any: Vec<String>,
}

pub(super) fn validate_rulepack_inputs(
  source: &str,
  variables: &[RulepackVariable],
  bindings: &[RulepackBinding],
  profiles: &[RulepackProfile],
) -> anyhow::Result<()> {
  let mut variable_names = HashSet::new();
  for variable in variables {
    super::validate_label(source, "variables.name", &variable.name)?;
    validate_variable_type(source, variable)?;
    validate_optional_human_text(
      source,
      "variables.description",
      variable.description.as_deref(),
    )?;
    validate_optional_human_text(source, "variables.prompt", variable.prompt.as_deref())?;
    if let Some(default) = &variable.default {
      validate_variable_value(source, variable, default)?;
    }
    if !variable_names.insert(variable.name.clone()) {
      bail!("{source} contains duplicate variable {}", variable.name);
    }
  }

  let mut binding_names = HashSet::new();
  let mut binding_targets = HashSet::new();
  for binding in bindings {
    super::validate_label(source, "bindings.name", &binding.name)?;
    super::validate_label(source, "bindings.bind_as", &binding.bind_as)?;
    if variable_names.contains(&binding.bind_as) {
      bail!(
        "{source} binding {} bind_as {} conflicts with a declared variable; route and other environment objects must use [[bindings]], while [[variables]] is only for scalar values",
        binding.name,
        binding.bind_as
      );
    }
    if !binding_targets.insert(binding.bind_as.clone()) {
      bail!(
        "{source} contains duplicate binding render target {}",
        binding.bind_as
      );
    }
    if !binding_names.insert(binding.name.clone()) {
      bail!("{source} contains duplicate binding {}", binding.name);
    }
    if variable_names.contains(&binding.name) {
      bail!(
        "{source} binding {} conflicts with a declared variable; use distinct names for --bind and --var inputs",
        binding.name,
      );
    }
    validate_optional_human_text(
      source,
      "bindings.description",
      binding.description.as_deref(),
    )?;
    validate_optional_human_text(source, "bindings.prompt", binding.prompt.as_deref())?;
    validate_discovery(source, "bindings.discovery", &binding.discovery)?;
  }

  let mut profile_names = HashSet::new();
  for profile in profiles {
    super::validate_label(source, "profiles.name", &profile.name)?;
    if !profile_names.insert(profile.name.clone()) {
      bail!("{source} contains duplicate profile {}", profile.name);
    }
    for (name, value) in &profile.values {
      let variable = variables.iter().find(|variable| variable.name == *name);
      let Some(variable) = variable else {
        bail!(
          "{source} profile {} sets unknown variable {name}",
          profile.name
        );
      };
      validate_variable_value(source, variable, value)?;
    }
  }

  Ok(())
}

pub(super) fn reject_legacy_variable_discovery(
  value: &toml::Value,
  source: &str,
) -> anyhow::Result<()> {
  for variable in value
    .get("variables")
    .and_then(toml::Value::as_array)
    .into_iter()
    .flatten()
  {
    let Some(table) = variable.as_table() else {
      continue;
    };
    let name = table
      .get("name")
      .and_then(toml::Value::as_str)
      .unwrap_or("<unknown>");
    if table.contains_key("discovery") {
      bail!(
        "{source} variable {name} uses [variables.discovery]; route and other environment objects must be declared with explicit [[bindings]] and bind_as"
      );
    }
  }
  Ok(())
}

pub(super) fn validate_variable_value(
  source: &str,
  variable: &RulepackVariable,
  value: &str,
) -> anyhow::Result<()> {
  match variable.value_type.as_deref() {
    Some("cidr") => {
      crate::identity::Cidr::parse(value)
        .with_context(|| format!("{source} variable {} must be a valid CIDR", variable.name))?;
    }
    Some("rate") => {
      crate::limits::parse_rate(value)
        .with_context(|| format!("{source} variable {} must be a valid rate", variable.name))?;
    }
    Some("string") | None => {}
    Some("route") => bail!(
      "{source} variable {} uses type = \"route\"; route objects must be declared with [[bindings]] and bind_as",
      variable.name
    ),
    Some(other) => bail!(
      "{source} variable {} uses unsupported type {}; supported types are string, cidr, and rate",
      variable.name,
      other
    ),
  }
  Ok(())
}

fn validate_variable_type(source: &str, variable: &RulepackVariable) -> anyhow::Result<()> {
  let Some(value_type) = &variable.value_type else {
    return Ok(());
  };
  super::validate_label(source, "variables.type", value_type)?;
  match value_type.as_str() {
    "string" | "cidr" | "rate" => Ok(()),
    "route" => bail!(
      "{source} variable {} uses type = \"route\"; route objects must be declared with [[bindings]] and bind_as",
      variable.name
    ),
    _ => bail!(
      "{source} variable {} uses unsupported type {}; supported types are string, cidr, and rate",
      variable.name,
      value_type
    ),
  }
}

fn validate_optional_human_text(
  source: &str,
  field: &str,
  value: Option<&str>,
) -> anyhow::Result<()> {
  if let Some(value) = value {
    validate_human_text(source, field, value)?;
  }
  Ok(())
}

fn validate_human_text(source: &str, field: &str, value: &str) -> anyhow::Result<()> {
  super::validate_non_empty(source, field, value)?;
  if value.len() > 512 || value.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("{source} {field} must be 1 to 512 printable bytes");
  }
  Ok(())
}

fn validate_discovery(
  source: &str,
  field: &str,
  discovery: &RulepackDiscovery,
) -> anyhow::Result<()> {
  for token in discovery
    .name_any
    .iter()
    .chain(discovery.host_contains_any.iter())
    .chain(discovery.upstream_contains_any.iter())
  {
    validate_discovery_token(source, field, token)?;
  }
  for prefix in &discovery.path_prefix_any {
    validate_human_text(source, &format!("{field}.path_prefix_any"), prefix)?;
    if !prefix.starts_with('/') {
      bail!("{source} {field}.path_prefix_any values must start with '/'");
    }
  }
  Ok(())
}

fn validate_discovery_token(source: &str, field: &str, value: &str) -> anyhow::Result<()> {
  validate_human_text(source, &format!("{field} token"), value)?;
  if value
    .bytes()
    .any(|byte| matches!(byte, b'/' | b'\\' | b'?' | b'#'))
  {
    bail!("{source} {field} tokens must not contain path or URL separators");
  }
  Ok(())
}
