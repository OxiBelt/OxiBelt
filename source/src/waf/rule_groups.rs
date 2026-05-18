use std::collections::HashSet;

use anyhow::{Context, bail};
use serde::Deserialize;

use super::{Parser, WafActionConfig, WafRuleConfig, is_valid_rule_label};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafRuleGroupConfig {
  pub name: String,
  #[serde(default)]
  pub when: Option<String>,
  #[serde(default)]
  pub merge_condition_as: WafConditionMerge,
  #[serde(default)]
  pub actions: Vec<WafActionConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafConditionMerge {
  #[default]
  And,
  Or,
  Override,
}

#[derive(Clone, Copy)]
pub(super) struct RuleGroupScope<'a> {
  pub(super) global: &'a [WafRuleGroupConfig],
  pub(super) route: Option<&'a [WafRuleGroupConfig]>,
}

pub(super) struct ResolvedRule {
  pub(super) when: String,
  pub(super) actions: Vec<WafActionConfig>,
}

pub(super) fn validate_rule_group_scope(
  scope: &str,
  groups: &[WafRuleGroupConfig],
) -> anyhow::Result<()> {
  let mut names = HashSet::new();
  for group in groups {
    if group.name.trim().is_empty() || !is_valid_rule_label(&group.name) {
      bail!("{scope} rule group name must match [A-Za-z0-9-]{{1,32}}");
    }
    if !names.insert(group.name.as_str()) {
      bail!("{scope} contains duplicate WAF rule group {}", group.name);
    }
    if group.when.is_none() && group.actions.is_empty() {
      bail!(
        "{scope} rule group {} must define at least one of when or actions",
        group.name
      );
    }
    if group.when.is_none() && group.merge_condition_as == WafConditionMerge::Override {
      bail!(
        "{scope} rule group {} merge_condition_as override requires when",
        group.name
      );
    }
    if let Some(expression) = group.when.as_deref() {
      Parser::new(expression).parse().with_context(|| {
        format!(
          "failed to parse {scope} rule group {} expression",
          group.name
        )
      })?;
    }
    for action in &group.actions {
      if action.priority() < 0 {
        bail!(
          "{scope} rule group {} action priority must not be negative",
          group.name
        );
      }
    }
  }
  Ok(())
}

pub(super) fn resolve_rule<'a>(
  scope: &str,
  rule: &'a WafRuleConfig,
  groups: RuleGroupScope<'a>,
) -> anyhow::Result<ResolvedRule> {
  let mut seen_groups = HashSet::new();
  let mut condition = ConditionAccumulator::default();
  let mut actions = Vec::new();
  let mut order = 0usize;

  for group_name in &rule.groups {
    if !seen_groups.insert(group_name.as_str()) {
      bail!(
        "{scope} rule {} references duplicate rule group {}",
        rule.name,
        group_name
      );
    }
    let group = find_group(rule, group_name, &groups)?;
    condition.push(
      &format!("rule group {group_name}"),
      group.when.as_deref(),
      group.merge_condition_as,
    )?;
    collect_actions(&mut actions, &mut order, &group.actions);
  }

  condition.push(
    &format!("rule {}", rule.name),
    rule.when.as_deref(),
    rule.merge_condition_as,
  )?;
  collect_actions(&mut actions, &mut order, &rule.actions);
  actions.sort_by(|left, right| {
    left
      .action
      .priority()
      .cmp(&right.action.priority())
      .then_with(|| left.order.cmp(&right.order))
  });

  let when = condition.finish(scope, &rule.name)?;
  if actions.is_empty() {
    bail!("{scope} rule {} must define at least one action", rule.name);
  }

  Ok(ResolvedRule {
    when,
    actions: actions.into_iter().map(|action| action.action).collect(),
  })
}

fn find_group<'a>(
  rule: &'a WafRuleConfig,
  name: &str,
  groups: &RuleGroupScope<'a>,
) -> anyhow::Result<&'a WafRuleGroupConfig> {
  rule
    .local_rule_groups
    .iter()
    .find(|group| group.name == name)
    .or_else(|| {
      groups
        .route
        .and_then(|route_groups| route_groups.iter().find(|group| group.name == name))
    })
    .or_else(|| groups.global.iter().find(|group| group.name == name))
    .ok_or_else(|| {
      anyhow::anyhow!(
        "WAF rule {} references unknown rule group {}",
        rule.name,
        name
      )
    })
}

fn collect_actions(
  actions: &mut Vec<OrderedAction>,
  order: &mut usize,
  source_actions: &[WafActionConfig],
) {
  actions.extend(source_actions.iter().cloned().map(|action| {
    let ordered = OrderedAction {
      order: *order,
      action,
    };
    *order += 1;
    ordered
  }));
}

struct OrderedAction {
  order: usize,
  action: WafActionConfig,
}

#[derive(Default)]
struct ConditionAccumulator {
  value: Option<String>,
  override_value: Option<String>,
}

impl ConditionAccumulator {
  fn push(
    &mut self,
    label: &str,
    when: Option<&str>,
    merge: WafConditionMerge,
  ) -> anyhow::Result<()> {
    let Some(when) = when else {
      if merge == WafConditionMerge::Override {
        bail!("{label} merge_condition_as override requires when");
      }
      return Ok(());
    };

    if merge == WafConditionMerge::Override {
      if self.override_value.is_some() {
        bail!("multiple OxiRule condition overrides are not allowed");
      }
      self.override_value = Some(when.to_string());
      return Ok(());
    }

    self.value = Some(match self.value.take() {
      Some(previous) => match merge {
        WafConditionMerge::And => format!("({previous}) && ({when})"),
        WafConditionMerge::Or => format!("({previous}) || ({when})"),
        WafConditionMerge::Override => unreachable!("override was handled above"),
      },
      None => when.to_string(),
    });
    Ok(())
  }

  fn finish(self, scope: &str, rule_name: &str) -> anyhow::Result<String> {
    if let Some(override_value) = self.override_value {
      return Ok(override_value);
    }
    self
      .value
      .ok_or_else(|| anyhow::anyhow!("{scope} rule {rule_name} must define an effective condition"))
  }
}
