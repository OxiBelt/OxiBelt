//! Candidate generation and scrubbing for OxiRule devtools.
//! Candidate-only data is sanitized before it is surfaced outside the scanner.

use anyhow::{Context, anyhow, bail};

use crate::config::Config;

use super::super::{
  ExternalRuleFile, ExternalRuleGroupFile, WafPhase, WafRuleConfig, WafRuleGroupConfig,
};
use super::types::{OxiRuleCandidate, OxiRuleGroupCandidate};

const DEFAULT_CANDIDATE_RULE_NAME: &str = "candidate";
const DEFAULT_CANDIDATE_PRIORITY: i64 = 100;
const DEFAULT_ROUTE_NAME: &str = "default";

pub(super) struct CandidateConfig {
  pub config: Config,
  pub route_name: String,
}

pub(super) fn candidate_config(
  base: &Config,
  rule: Option<&OxiRuleCandidate>,
  groups: &[OxiRuleGroupCandidate],
  include_active_rules: bool,
) -> anyhow::Result<CandidateConfig> {
  let mut config = base.clone();
  config.waf.enabled = true;
  if !include_active_rules {
    config.waf.rule_groups.clear();
    config.waf.rules.clear();
    config.waf.crs.enabled = false;
    for route in &mut config.routes {
      route.waf.rule_groups.clear();
      route.waf.rules.clear();
    }
  }

  for group in groups {
    let parsed = parse_group_candidate(group)?;
    if let Some(route_name) = &group.route {
      let route = config
        .routes
        .iter_mut()
        .find(|route| route.name == *route_name)
        .ok_or_else(|| anyhow!("unknown route {route_name} for OxiRule group candidate"))?;
      route.waf.rule_groups.extend(parsed);
    } else {
      config.waf.rule_groups.extend(parsed);
    }
  }

  let route_name = rule
    .and_then(|rule| rule.route.clone())
    .or_else(|| config.routes.first().map(|route| route.name.clone()))
    .unwrap_or_else(|| DEFAULT_ROUTE_NAME.to_string());

  if let Some(rule_candidate) = rule {
    let parsed = parse_rule_candidate(rule_candidate)?;
    if let Some(route_name) = &rule_candidate.route {
      let route = config
        .routes
        .iter_mut()
        .find(|route| route.name == *route_name)
        .ok_or_else(|| anyhow!("unknown route {route_name} for OxiRule candidate"))?;
      route.waf.rules.push(parsed);
    } else {
      config.waf.rules.push(parsed);
    }
  }

  Ok(CandidateConfig { config, route_name })
}

pub fn oxirule_rule_resource_name(request: &OxiRuleCandidate) -> String {
  format!("oxirule/{}", request.name.as_deref().unwrap_or("inline"))
}

pub fn oxirule_group_resource_names(groups: &[OxiRuleGroupCandidate]) -> Vec<String> {
  if groups.is_empty() {
    return Vec::new();
  }
  groups
    .iter()
    .enumerate()
    .map(|(index, group)| {
      format!(
        "oxirule-group/{}",
        group
          .name
          .as_deref()
          .map(str::to_string)
          .unwrap_or_else(|| format!("inline-{}", index + 1))
      )
    })
    .collect()
}

fn parse_rule_candidate(candidate: &OxiRuleCandidate) -> anyhow::Result<WafRuleConfig> {
  let mut rule = match toml::from_str::<WafRuleConfig>(&candidate.content) {
    Ok(rule) => rule,
    Err(_) => {
      let external: ExternalRuleFile = toml::from_str(&candidate.content)
        .context("failed to parse OxiRule candidate as rule body")?;
      WafRuleConfig {
        name: candidate
          .name
          .clone()
          .unwrap_or_else(|| DEFAULT_CANDIDATE_RULE_NAME.to_string()),
        id: candidate.id.clone(),
        tags: candidate.tags.clone(),
        mode: candidate.mode,
        phase: candidate.phase.unwrap_or(WafPhase::Request),
        priority: candidate.priority.unwrap_or(DEFAULT_CANDIDATE_PRIORITY),
        when: external.when,
        merge_condition_as: external.merge_condition_as,
        path: None,
        groups: external.groups,
        actions: external.actions,
        local_rule_groups: external.rule_groups,
        loaded_from_path: None,
        loaded_from_logical_path: None,
      }
    }
  };
  if let Some(name) = &candidate.name {
    rule.name = name.clone();
  }
  if let Some(id) = &candidate.id {
    rule.id = Some(id.clone());
  }
  if !candidate.tags.is_empty() {
    rule.tags = candidate.tags.clone();
  }
  if let Some(mode) = candidate.mode {
    rule.mode = Some(mode);
  }
  if let Some(phase) = candidate.phase {
    rule.phase = phase;
  }
  if let Some(priority) = candidate.priority {
    rule.priority = priority;
  }
  rule.path = None;
  Ok(rule)
}

fn parse_group_candidate(
  candidate: &OxiRuleGroupCandidate,
) -> anyhow::Result<Vec<WafRuleGroupConfig>> {
  if let Ok(group) = toml::from_str::<WafRuleGroupConfig>(&candidate.content) {
    return Ok(vec![group]);
  }
  let external: ExternalRuleGroupFile =
    toml::from_str(&candidate.content).context("failed to parse OxiRule group candidate")?;
  if external.rule_groups.is_empty() {
    bail!("OxiRule group candidate must contain at least one group");
  }
  Ok(external.rule_groups)
}
