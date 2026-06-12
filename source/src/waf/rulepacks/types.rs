use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

use super::{RulepackException, RulepackOverride, RulepackSourceProvenance, WafRulepackSummary};
use crate::waf::WafMode;

#[derive(Debug, Clone, Copy)]
pub struct RulepackModeOverride {
  pub mode: WafMode,
  pub force: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RulepackRenderOptions {
  pub variables: BTreeMap<String, String>,
  pub local_overrides: Vec<RulepackOverride>,
  pub local_exceptions: Vec<RulepackException>,
  pub mode_override: Option<RulepackModeOverride>,
  pub source_commit: Option<String>,
  pub source_provenance: Option<RulepackSourceProvenance>,
  pub pin_variables: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RulepackInspection {
  pub summary: WafRulepackSummary,
  pub rendered: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RulepackReferencedFile {
  pub kind: RulepackReferencedFileKind,
  pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RulepackReferencedFileKind {
  Rule,
  Group,
}
