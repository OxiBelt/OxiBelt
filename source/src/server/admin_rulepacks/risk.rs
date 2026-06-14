use std::collections::BTreeSet;

use anyhow::Context;

use crate::config::Config;
use crate::waf::{
  OxiRuleCandidate, OxiRuleDevtoolsCheckRequest, OxiRuleGroupCandidate, cost_oxirule,
};

use super::{
  AdminRulepackCandidateSet, AdminRulepackPrepared, AdminRulepackRisk, AdminRulepackRuleCandidate,
  parse_waf_mode, parse_waf_phase,
};

pub(super) fn candidate_set(rendered_manifest: &str) -> anyhow::Result<AdminRulepackCandidateSet> {
  let value: toml::Value =
    toml::from_str(rendered_manifest).context("rendered rulepack manifest was not TOML")?;
  let rules = value
    .get("rules")
    .and_then(toml::Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(toml::Value::as_table)
    .map(rule_candidate_from_table)
    .collect::<anyhow::Result<Vec<_>>>()?;
  let groups = value
    .get("group_files")
    .and_then(toml::Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(toml::Value::as_table)
    .map(group_candidate_from_table)
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok(AdminRulepackCandidateSet { rules, groups })
}

fn rule_candidate_from_table(
  table: &toml::map::Map<String, toml::Value>,
) -> anyhow::Result<AdminRulepackRuleCandidate> {
  let name = table
    .get("name")
    .and_then(toml::Value::as_str)
    .unwrap_or("unnamed-rule")
    .to_string();
  let content = table
    .get("content")
    .and_then(toml::Value::as_str)
    .with_context(|| format!("rendered rulepack rule {name} does not include embedded content"))?
    .to_string();
  let body = OxiRuleCandidate {
    content: content.clone(),
    name: Some(name.clone()),
    id: table
      .get("id")
      .and_then(toml::Value::as_str)
      .map(str::to_string),
    tags: table
      .get("tags")
      .and_then(toml::Value::as_array)
      .into_iter()
      .flatten()
      .filter_map(toml::Value::as_str)
      .map(str::to_string)
      .collect(),
    mode: table
      .get("mode")
      .and_then(toml::Value::as_str)
      .map(parse_waf_mode)
      .transpose()
      .with_context(|| format!("rendered rulepack rule {name} has invalid mode"))?,
    phase: table
      .get("phase")
      .and_then(toml::Value::as_str)
      .map(parse_waf_phase)
      .transpose()
      .with_context(|| format!("rendered rulepack rule {name} has invalid phase"))?,
    priority: table.get("priority").and_then(toml::Value::as_integer),
    route: None,
  };
  Ok(AdminRulepackRuleCandidate {
    name,
    content,
    body,
  })
}

fn group_candidate_from_table(
  table: &toml::map::Map<String, toml::Value>,
) -> anyhow::Result<OxiRuleGroupCandidate> {
  Ok(OxiRuleGroupCandidate {
    content: table
      .get("content")
      .and_then(toml::Value::as_str)
      .context("rendered rulepack group file does not include embedded content")?
      .to_string(),
    route: None,
    name: table
      .get("name")
      .and_then(toml::Value::as_str)
      .map(str::to_string),
  })
}

pub(super) fn static_risk(candidates: &AdminRulepackCandidateSet) -> AdminRulepackRisk {
  let mut terminal_actions = BTreeSet::new();
  let mut body_inspection = false;
  let mut response_inspection = false;
  for candidate in &candidates.rules {
    body_inspection |= candidate.content.contains("Request.Body");
    response_inspection |= candidate.content.contains("Response.Body");
    for action in terminal_actions_for_content(&candidate.content) {
      terminal_actions.insert(action);
    }
  }
  let estimated_cost = if body_inspection || response_inspection {
    "medium"
  } else {
    "low"
  };
  AdminRulepackRisk {
    terminal_actions: terminal_actions.into_iter().collect(),
    body_inspection,
    response_inspection,
    estimated_cost,
  }
}

pub(super) fn augment_risk_with_cost(
  config: &Config,
  prepared: &AdminRulepackPrepared,
  risk: &mut AdminRulepackRisk,
  cost_warnings: &mut Vec<String>,
  warnings: &mut Vec<String>,
) {
  for candidate in &prepared.candidates.rules {
    let report = cost_oxirule(
      config,
      OxiRuleDevtoolsCheckRequest {
        rule: Some(candidate.body.clone()),
        groups: prepared.candidates.groups.clone(),
        include_active_rules: false,
      },
    );
    if !report.ok {
      warnings.push(format!("cost probe for rule {} failed", candidate.name));
      continue;
    }
    if let Some(body_need) = report.body_need {
      if body_need.request_body != "none" {
        risk.body_inspection = true;
      }
      if body_need.response_body != "none" {
        risk.response_inspection = true;
      }
    }
    for warning in report.cost_warnings {
      if !cost_warnings.iter().any(|existing| existing == &warning) {
        cost_warnings.push(warning);
      }
    }
  }
  if risk.body_inspection || risk.response_inspection || !cost_warnings.is_empty() {
    risk.estimated_cost = "medium";
  }
}

fn terminal_actions_for_content(content: &str) -> Vec<String> {
  let Ok(value) = toml::from_str::<toml::Value>(content) else {
    return Vec::new();
  };
  value
    .get("actions")
    .and_then(toml::Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(toml::Value::as_table)
    .filter_map(|action| action.get("type").and_then(toml::Value::as_str))
    .filter(|action_type| {
      matches!(
        *action_type,
        "reject" | "rate_limit" | "replace_response" | "reject_response" | "challenge"
      )
    })
    .map(str::to_string)
    .collect()
}

pub(super) fn unknown_risk() -> AdminRulepackRisk {
  AdminRulepackRisk {
    terminal_actions: Vec::new(),
    body_inspection: false,
    response_inspection: false,
    estimated_cost: "unknown",
  }
}
