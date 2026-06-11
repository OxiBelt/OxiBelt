use std::collections::HashSet;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RulepackInputMetadata {
  pub summary: super::WafRulepackSummary,
  pub variables: Vec<RulepackVariable>,
  pub bindings: Vec<RulepackBinding>,
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
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub discovery: Option<RulepackDiscovery>,
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
) -> anyhow::Result<()> {
  let mut variable_names = HashSet::new();
  let mut variables_with_discovery = HashSet::new();
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
    if let Some(discovery) = &variable.discovery {
      if variable.value_type.as_deref() != Some("route") {
        bail!(
          "{source} variable {} discovery requires type = \"route\"",
          variable.name
        );
      }
      validate_discovery(source, "variables.discovery", discovery)?;
      variables_with_discovery.insert(variable.name.clone());
    }
    if !variable_names.insert(variable.name.clone()) {
      bail!("{source} contains duplicate variable {}", variable.name);
    }
  }

  let mut binding_names = HashSet::new();
  for binding in bindings {
    super::validate_label(source, "bindings.name", &binding.name)?;
    super::validate_label(source, "bindings.bind_as", &binding.bind_as)?;
    if !variable_names.contains(&binding.bind_as) {
      bail!(
        "{source} binding {} bind_as references undeclared variable {}",
        binding.name,
        binding.bind_as
      );
    }
    if variables_with_discovery.contains(&binding.bind_as) {
      bail!(
        "{source} binding {} targets variable {} that already declares variables.discovery; choose either [variables.discovery] or [[bindings]]",
        binding.name,
        binding.bind_as
      );
    }
    validate_optional_human_text(
      source,
      "bindings.description",
      binding.description.as_deref(),
    )?;
    validate_optional_human_text(source, "bindings.prompt", binding.prompt.as_deref())?;
    validate_discovery(source, "bindings.discovery", &binding.discovery)?;
    if !binding_names.insert(binding.name.clone()) {
      bail!("{source} contains duplicate binding {}", binding.name);
    }
  }

  let mut effective_binding_names = binding_names;
  for variable in variables
    .iter()
    .filter(|variable| variable.discovery.is_some())
  {
    if !effective_binding_names.insert(variable.name.clone()) {
      bail!(
        "{source} contains duplicate effective binding {}",
        variable.name
      );
    }
  }

  Ok(())
}

pub(super) fn effective_bindings(
  variables: &[RulepackVariable],
  bindings: &[RulepackBinding],
) -> Vec<RulepackBinding> {
  let mut effective = bindings.to_vec();
  for variable in variables {
    if let Some(discovery) = &variable.discovery {
      effective.push(RulepackBinding {
        name: variable.name.clone(),
        kind: RulepackBindingKind::Route,
        bind_as: variable.name.clone(),
        required: variable.required,
        description: variable.description.clone(),
        prompt: variable.prompt.clone(),
        discovery: discovery.clone(),
      });
    }
  }
  effective
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
    Some("route") | Some("string") | None => {}
    Some(other) => bail!(
      "{source} variable {} uses unsupported type {}; supported types are string, route, cidr, and rate",
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
    "string" | "route" | "cidr" | "rate" => Ok(()),
    _ => bail!(
      "{source} variable {} uses unsupported type {}; supported types are string, route, cidr, and rate",
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
