use std::collections::HashSet;

use anyhow::bail;
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
  schema_version: u32,
  source: &str,
  variables: &[RulepackVariable],
  bindings: &[RulepackBinding],
) -> anyhow::Result<()> {
  if schema_version == 1 && !bindings.is_empty() {
    bail!("{source} schema_version 1 does not support [[bindings]]");
  }

  let mut variable_names = HashSet::new();
  for variable in variables {
    super::validate_label(source, "variables.name", &variable.name)?;
    if schema_version == 1
      && (variable.value_type.is_some()
        || variable.description.is_some()
        || variable.prompt.is_some())
    {
      bail!("{source} schema_version 1 does not support variable metadata fields");
    }
    if let Some(value_type) = &variable.value_type {
      super::validate_label(source, "variables.type", value_type)?;
    }
    validate_optional_human_text(
      source,
      "variables.description",
      variable.description.as_deref(),
    )?;
    validate_optional_human_text(source, "variables.prompt", variable.prompt.as_deref())?;
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
    validate_optional_human_text(
      source,
      "bindings.description",
      binding.description.as_deref(),
    )?;
    validate_optional_human_text(source, "bindings.prompt", binding.prompt.as_deref())?;
    validate_discovery(source, &binding.discovery)?;
    if !binding_names.insert(binding.name.clone()) {
      bail!("{source} contains duplicate binding {}", binding.name);
    }
  }

  Ok(())
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

fn validate_discovery(source: &str, discovery: &RulepackDiscovery) -> anyhow::Result<()> {
  for token in discovery
    .name_any
    .iter()
    .chain(discovery.host_contains_any.iter())
    .chain(discovery.upstream_contains_any.iter())
  {
    validate_discovery_token(source, token)?;
  }
  for prefix in &discovery.path_prefix_any {
    validate_human_text(source, "bindings.discovery.path_prefix_any", prefix)?;
    if !prefix.starts_with('/') {
      bail!("{source} bindings.discovery.path_prefix_any values must start with '/'");
    }
  }
  Ok(())
}

fn validate_discovery_token(source: &str, value: &str) -> anyhow::Result<()> {
  validate_human_text(source, "bindings.discovery token", value)?;
  if value
    .bytes()
    .any(|byte| matches!(byte, b'/' | b'\\' | b'?' | b'#'))
  {
    bail!("{source} bindings.discovery tokens must not contain path or URL separators");
  }
  Ok(())
}
