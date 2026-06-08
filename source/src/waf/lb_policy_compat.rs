//! WAF action normalization for explicit load-balancing compatibility profiles.

use crate::config::{
  LbPolicyCompatDiagnostic, LbPolicyCompatProfile,
  normalize_policy_string as normalize_lb_policy_string,
};

use super::{RouteWafConfig, WafActionConfig, WafConfig, WafRuleConfig, WafRuleGroupConfig};

impl WafConfig {
  pub(crate) fn normalize_lb_policy_compat(
    &mut self,
    profile: LbPolicyCompatProfile,
    path: String,
  ) -> Vec<LbPolicyCompatDiagnostic> {
    normalize_waf_lb_policy_compat(
      &mut self.rules,
      &mut self.rule_groups,
      profile,
      path.as_str(),
    )
  }
}

impl RouteWafConfig {
  pub(crate) fn normalize_lb_policy_compat(
    &mut self,
    profile: LbPolicyCompatProfile,
    path: String,
  ) -> Vec<LbPolicyCompatDiagnostic> {
    normalize_waf_lb_policy_compat(
      &mut self.rules,
      &mut self.rule_groups,
      profile,
      path.as_str(),
    )
  }
}

fn normalize_waf_lb_policy_compat(
  rules: &mut [WafRuleConfig],
  groups: &mut [WafRuleGroupConfig],
  profile: LbPolicyCompatProfile,
  path: &str,
) -> Vec<LbPolicyCompatDiagnostic> {
  let mut diagnostics = Vec::new();
  for (group_index, group) in groups.iter_mut().enumerate() {
    normalize_waf_actions(
      &mut group.actions,
      &format!("{path}.rule_groups[{group_index}]"),
      profile,
      &mut diagnostics,
    );
  }
  for (rule_index, rule) in rules.iter_mut().enumerate() {
    let rule_path = format!("{path}.rules[{rule_index}]");
    normalize_waf_actions(&mut rule.actions, &rule_path, profile, &mut diagnostics);
    for (group_index, group) in rule.local_rule_groups.iter_mut().enumerate() {
      normalize_waf_actions(
        &mut group.actions,
        &format!("{rule_path}.rule_groups[{group_index}]"),
        profile,
        &mut diagnostics,
      );
    }
  }
  diagnostics
}

fn normalize_waf_actions(
  actions: &mut [WafActionConfig],
  path: &str,
  profile: LbPolicyCompatProfile,
  diagnostics: &mut Vec<LbPolicyCompatDiagnostic>,
) {
  for (action_index, action) in actions.iter_mut().enumerate() {
    let WafActionConfig::SetLoadBalancingPolicy { policy, .. } = action else {
      continue;
    };
    normalize_lb_policy_string(
      format!("{path}.actions[{action_index}].policy"),
      policy,
      profile,
      diagnostics,
    );
  }
}
