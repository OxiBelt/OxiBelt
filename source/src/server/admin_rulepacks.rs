//! Admin rulepack endpoints.
//! Rulepack inspection and rendering are exposed through the same admin authorization boundary.

use crate::config::Config;

pub(super) fn active_rulepack_summaries(config: &Config) -> Vec<crate::waf::WafRulepackSummary> {
  config
    .waf
    .rulepack_summaries()
    .iter()
    .cloned()
    .chain(
      config
        .routes
        .iter()
        .flat_map(|route| route.waf.rulepack_summaries().iter().cloned()),
    )
    .collect()
}
