use std::collections::BTreeMap;

use oxibelt::waf::{
  RulepackModeOverride, RulepackRenderOptions, RulepackSourceProvenance, WafMode,
};

use crate::cli::RulepackModeArg;

pub(crate) fn render_options(
  variables: BTreeMap<String, String>,
  local_overrides: Vec<oxibelt::waf::RulepackOverride>,
  local_exceptions: Vec<oxibelt::waf::RulepackException>,
  mode: Option<RulepackModeArg>,
  force_mode: bool,
  source_commit: Option<String>,
  source_provenance: Option<RulepackSourceProvenance>,
) -> RulepackRenderOptions {
  RulepackRenderOptions {
    variables,
    local_overrides,
    local_exceptions,
    mode_override: mode.map(|mode| RulepackModeOverride {
      mode: mode_arg(mode),
      force: force_mode,
    }),
    source_commit,
    source_provenance,
    pin_variables: false,
  }
}

pub(crate) fn render_text(raw: &str, variables: &BTreeMap<String, String>) -> String {
  let mut rendered = raw.to_string();
  for (name, value) in variables {
    rendered = rendered.replace(&format!("{{{{{name}}}}}"), value);
  }
  rendered
}

fn mode_arg(mode: RulepackModeArg) -> WafMode {
  match mode {
    RulepackModeArg::Monitor => WafMode::Monitor,
    RulepackModeArg::Enforcing => WafMode::Enforcing,
  }
}
