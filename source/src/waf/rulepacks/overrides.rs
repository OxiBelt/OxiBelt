use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::waf::WafMode;

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RulepackOverride {
  pub selector: RulepackOverrideSelector,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub action: Option<RulepackActionSelector>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub mode: Option<WafMode>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub priority: Option<i64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub enabled: Option<bool>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub rate: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub burst: Option<u32>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub status: Option<u16>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub body: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RulepackOverrideSelector {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub rulepack: Option<String>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub rule_id: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub rule_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RulepackActionSelector {
  #[serde(rename = "type")]
  pub action_type: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub name: Option<String>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum OverrideScope {
  Manifest,
  Local,
}

struct OrderedOverride<'a> {
  scope: OverrideScope,
  index: usize,
  item: &'a RulepackOverride,
}

pub fn validate_rulepack_overrides(
  source: &str,
  rulepack_name: &str,
  overrides: &[RulepackOverride],
) -> anyhow::Result<()> {
  for override_item in overrides {
    validate_override(source, rulepack_name, override_item)?;
  }
  Ok(())
}

pub(super) fn apply_overrides(
  value: &mut toml::Value,
  source: &str,
  rulepack_name: &str,
  manifest_overrides: &[RulepackOverride],
  local_overrides: &[RulepackOverride],
) -> anyhow::Result<()> {
  let overrides = ordered_overrides(manifest_overrides, local_overrides);
  if overrides.is_empty() {
    return Ok(());
  }
  let Some(rules) = value.get_mut("rules").and_then(toml::Value::as_array_mut) else {
    bail!("{source} overrides require at least one [[rules]] entry");
  };
  let mut match_counts = vec![0usize; overrides.len()];
  let mut rendered_rules = Vec::with_capacity(rules.len());
  for rule_value in rules.iter() {
    let Some(original_rule) = rule_value.as_table() else {
      bail!("{source} rules entries must be tables");
    };
    let mut rendered_rule = toml::Value::Table(original_rule.clone());
    let mut enabled = true;
    for (position, ordered) in overrides.iter().enumerate() {
      if !selector_matches_rule(rulepack_name, &ordered.item.selector, original_rule) {
        continue;
      }
      match_counts[position] += 1;
      apply_override_to_rule(source, ordered.item, &mut rendered_rule, &mut enabled)?;
    }
    if enabled {
      rendered_rules.push(rendered_rule);
    }
  }
  for (position, count) in match_counts.into_iter().enumerate() {
    if count == 0 {
      let ordered = &overrides[position];
      bail!(
        "{source} {} override {} did not match any rule",
        scope_name(ordered.scope),
        ordered.index + 1
      );
    }
  }
  *rules = rendered_rules;
  Ok(())
}

fn ordered_overrides<'a>(
  manifest_overrides: &'a [RulepackOverride],
  local_overrides: &'a [RulepackOverride],
) -> Vec<OrderedOverride<'a>> {
  let mut overrides = Vec::with_capacity(manifest_overrides.len() + local_overrides.len());
  for (index, item) in manifest_overrides.iter().enumerate() {
    overrides.push(OrderedOverride {
      scope: OverrideScope::Manifest,
      index,
      item,
    });
  }
  for (index, item) in local_overrides.iter().enumerate() {
    overrides.push(OrderedOverride {
      scope: OverrideScope::Local,
      index,
      item,
    });
  }
  overrides.sort_by_key(|ordered| {
    (
      ordered.scope,
      selector_precedence(&ordered.item.selector),
      ordered.index,
    )
  });
  overrides
}

fn validate_override(
  source: &str,
  rulepack_name: &str,
  override_item: &RulepackOverride,
) -> anyhow::Result<()> {
  validate_selector(source, rulepack_name, &override_item.selector)?;
  let has_rule_field = override_item.mode.is_some()
    || override_item.priority.is_some()
    || override_item.enabled.is_some();
  let has_action_field = override_item.rate.is_some()
    || override_item.burst.is_some()
    || override_item.status.is_some()
    || override_item.body.is_some();
  if !has_rule_field && !has_action_field {
    bail!("{source} override must set at least one supported field");
  }
  if override_item.action.is_some() && !has_action_field {
    bail!("{source} override action selector requires an action field");
  }
  if has_action_field {
    let Some(action) = &override_item.action else {
      bail!("{source} action fields require an action selector");
    };
    validate_action_selector(source, action)?;
    validate_action_fields(source, override_item, action)?;
  }
  if let Some(rate) = &override_item.rate {
    crate::limits::parse_rate(rate)
      .with_context(|| format!("{source} override rate must be valid"))?;
  }
  if let Some(status) = override_item.status {
    http::StatusCode::from_u16(status)
      .with_context(|| format!("{source} override status {status} is invalid"))?;
  }
  Ok(())
}

fn validate_selector(
  source: &str,
  rulepack_name: &str,
  selector: &RulepackOverrideSelector,
) -> anyhow::Result<()> {
  let mut kinds = 0;
  if let Some(value) = &selector.rulepack {
    kinds += 1;
    super::validate_label(source, "overrides.selector.rulepack", value)?;
    if value != rulepack_name {
      bail!("{source} override selector rulepack {value} does not match rulepack {rulepack_name}");
    }
  }
  if !selector.tags.is_empty() {
    kinds += 1;
    for tag in &selector.tags {
      super::validate_label(source, "overrides.selector.tags", tag)?;
    }
  }
  if let Some(value) = &selector.rule_id {
    kinds += 1;
    super::validate_label(source, "overrides.selector.rule_id", value)?;
  }
  if let Some(value) = &selector.rule_name {
    kinds += 1;
    super::validate_label(source, "overrides.selector.rule_name", value)?;
  }
  if kinds != 1 {
    bail!("{source} override selector must set exactly one selector kind");
  }
  Ok(())
}

fn validate_action_selector(source: &str, action: &RulepackActionSelector) -> anyhow::Result<()> {
  super::validate_label(source, "overrides.action.type", &action.action_type)?;
  if let Some(name) = &action.name {
    super::validate_label(source, "overrides.action.name", name)?;
  }
  match action.action_type.as_str() {
    "rate_limit" | "reject" | "replace_response" | "reject_response" => {}
    other => bail!("{source} override action type {other} is not supported"),
  }
  if action.action_type == "rate_limit" && action.name.is_none() {
    bail!("{source} rate_limit action overrides require action.name");
  }
  Ok(())
}

fn validate_action_fields(
  source: &str,
  override_item: &RulepackOverride,
  action: &RulepackActionSelector,
) -> anyhow::Result<()> {
  if (override_item.rate.is_some() || override_item.burst.is_some())
    && action.action_type != "rate_limit"
  {
    bail!("{source} rate and burst overrides are only supported for rate_limit actions");
  }
  if (override_item.status.is_some() || override_item.body.is_some())
    && !matches!(
      action.action_type.as_str(),
      "rate_limit" | "reject" | "replace_response" | "reject_response"
    )
  {
    bail!("{source} status and body overrides are not supported for this action");
  }
  Ok(())
}

fn selector_precedence(selector: &RulepackOverrideSelector) -> usize {
  if selector.rulepack.is_some() {
    0
  } else if !selector.tags.is_empty() {
    1
  } else {
    2
  }
}

fn selector_matches_rule(
  rulepack_name: &str,
  selector: &RulepackOverrideSelector,
  rule: &toml::value::Table,
) -> bool {
  if selector.rulepack.as_deref() == Some(rulepack_name) {
    return true;
  }
  if !selector.tags.is_empty()
    && rule
      .get("tags")
      .and_then(toml::Value::as_array)
      .is_some_and(|tags| {
        tags.iter().any(|tag| {
          tag
            .as_str()
            .is_some_and(|tag| selector.tags.iter().any(|wanted| wanted == tag))
        })
      })
  {
    return true;
  }
  if let Some(rule_id) = &selector.rule_id
    && rule.get("id").and_then(toml::Value::as_str) == Some(rule_id)
  {
    return true;
  }
  if let Some(rule_name) = &selector.rule_name
    && rule.get("name").and_then(toml::Value::as_str) == Some(rule_name)
  {
    return true;
  }
  false
}

fn apply_override_to_rule(
  source: &str,
  override_item: &RulepackOverride,
  rule: &mut toml::Value,
  enabled: &mut bool,
) -> anyhow::Result<()> {
  let Some(table) = rule.as_table_mut() else {
    bail!("{source} rules entries must be tables");
  };
  if let Some(value) = override_item.enabled {
    *enabled = value;
  }
  if let Some(mode) = override_item.mode {
    table.insert(
      "mode".to_string(),
      toml::Value::String(mode.as_str().to_string()),
    );
  }
  if let Some(priority) = override_item.priority {
    table.insert("priority".to_string(), toml::Value::Integer(priority));
  }
  if override_item.action.is_some() {
    if table.get("path").is_some() {
      let name = table
        .get("name")
        .and_then(toml::Value::as_str)
        .unwrap_or("<unknown>");
      bail!("{source} rule {name} uses path; action overrides require inline content");
    }
    let Some(content) = table.get("content").and_then(toml::Value::as_str) else {
      bail!("{source} action overrides require inline rule content");
    };
    let content = apply_override_to_content(source, content, override_item)?;
    table.insert("content".to_string(), toml::Value::String(content));
  }
  Ok(())
}

fn apply_override_to_content(
  source: &str,
  content: &str,
  override_item: &RulepackOverride,
) -> anyhow::Result<String> {
  let action = override_item
    .action
    .as_ref()
    .ok_or_else(|| anyhow::anyhow!("{source} action override is missing its selector"))?;
  let mut value: toml::Value =
    toml::from_str(content).with_context(|| format!("failed to parse {source} rule content"))?;
  let actions = value
    .get_mut("actions")
    .and_then(toml::Value::as_array_mut)
    .with_context(|| format!("{source} action override found no [[actions]] entries"))?;
  let mut matches = Vec::new();
  for (index, action_value) in actions.iter().enumerate() {
    let Some(table) = action_value.as_table() else {
      bail!("{source} action entries must be tables");
    };
    if action_matches_selector(table, action) {
      matches.push(index);
    }
  }
  if matches.len() != 1 {
    bail!(
      "{source} action override for {} matched {} actions; expected exactly one",
      action.action_type,
      matches.len()
    );
  }
  let Some(table) = actions[matches[0]].as_table_mut() else {
    bail!("{source} matching action must be a table");
  };
  if let Some(rate) = &override_item.rate {
    table.insert("rate".to_string(), toml::Value::String(rate.clone()));
  }
  if let Some(burst) = override_item.burst {
    table.insert("burst".to_string(), toml::Value::Integer(i64::from(burst)));
  }
  if let Some(status) = override_item.status {
    table.insert(
      "status".to_string(),
      toml::Value::Integer(i64::from(status)),
    );
  }
  if let Some(body) = &override_item.body {
    table.insert("body".to_string(), toml::Value::String(body.clone()));
  }
  toml::to_string_pretty(&value).context("failed to render overridden rule content")
}

fn action_matches_selector(table: &toml::value::Table, selector: &RulepackActionSelector) -> bool {
  if table.get("type").and_then(toml::Value::as_str) != Some(selector.action_type.as_str()) {
    return false;
  }
  match selector.name.as_deref() {
    Some(name) => table.get("name").and_then(toml::Value::as_str) == Some(name),
    None => true,
  }
}

fn scope_name(scope: OverrideScope) -> &'static str {
  match scope {
    OverrideScope::Manifest => "manifest",
    OverrideScope::Local => "local",
  }
}
