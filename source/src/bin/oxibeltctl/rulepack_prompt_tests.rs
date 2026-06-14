use super::*;
use crate::rulepack_fit::{RouteCandidate, RouteCandidateSet, RulepackFitReport};

struct ScriptedPrompt {
  terminal: bool,
  answers: Vec<String>,
  lines: Vec<String>,
}

impl ScriptedPrompt {
  fn new(answers: &[&str]) -> Self {
    Self {
      terminal: true,
      answers: answers
        .iter()
        .rev()
        .map(|answer| (*answer).to_string())
        .collect(),
      lines: Vec::new(),
    }
  }
}

impl InteractivePrompt for ScriptedPrompt {
  fn is_terminal(&self) -> bool {
    self.terminal
  }

  fn write_line(&mut self, line: &str) -> anyhow::Result<()> {
    self.lines.push(line.to_string());
    Ok(())
  }

  fn prompt(&mut self, message: &str) -> anyhow::Result<String> {
    self.lines.push(message.to_string());
    self
      .answers
      .pop()
      .ok_or_else(|| anyhow::anyhow!("missing scripted answer"))
  }
}

fn evaluation() -> RulepackFitEvaluation {
  let inputs = oxibelt::waf::inspect_rulepack_inputs(
    r#"[rulepack]
schema_version = 2
name = "vaultwarden-hardening"
version = "0.1.0"

[[variables]]
name = "admin_cidr"
type = "cidr"
required = true
prompt = "Trusted CIDR."

[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"
required = true
prompt = "Select Vaultwarden route."

[[rules]]
name = "admin-guard"
phase = "request"
priority = 100
content = "when = \"true\"\n"
"#,
    "test rulepack",
  )
  .expect("inputs");
  let report = RulepackFitReport {
    rulepack: "vaultwarden-hardening".to_string(),
    required_bindings: vec!["app_route".to_string()],
    missing_bindings: vec!["app_route".to_string()],
    route_candidates: vec![RouteCandidateSet {
      binding: "app_route".to_string(),
      candidates: vec![RouteCandidate {
        name: "mmsecretvault".to_string(),
        score: 85,
        reason: vec!["route name contains vault".to_string()],
        hosts: vec!["vault.example.com".to_string()],
        path_prefix: "/".to_string(),
        upstream: Some("vaultwarden-origin".to_string()),
      }],
    }],
    missing_variables: vec!["admin_cidr".to_string()],
    resolved_bindings: BTreeMap::new(),
    warnings: Vec::new(),
    suggested_command: "oxibeltctl rulepack apply ...".to_string(),
  };
  RulepackFitEvaluation { inputs, report }
}

#[test]
fn scripted_prompt_collects_binding_and_required_variable() {
  let evaluation = evaluation();
  let mut vars = BTreeMap::new();
  let mut binds = BTreeMap::new();
  let mut prompt = ScriptedPrompt::new(&["1", "10.0.0.0/8", "yes"]);

  complete_interactive_from_evaluation(
    &evaluation,
    &mut vars,
    &mut binds,
    RulepackModeArg::Monitor,
    true,
    &mut prompt,
  )
  .expect("interactive inputs");

  assert_eq!(
    binds.get("app_route").map(String::as_str),
    Some("mmsecretvault")
  );
  assert_eq!(
    vars.get("admin_cidr").map(String::as_str),
    Some("10.0.0.0/8")
  );
}

#[test]
fn scripted_prompt_rejects_non_terminal() {
  let evaluation = evaluation();
  let mut vars = BTreeMap::new();
  let mut binds = BTreeMap::new();
  let mut prompt = ScriptedPrompt::new(&[]);
  prompt.terminal = false;

  let error = complete_interactive_from_evaluation(
    &evaluation,
    &mut vars,
    &mut binds,
    RulepackModeArg::Monitor,
    true,
    &mut prompt,
  )
  .expect_err("non-terminal should fail");

  assert!(error.to_string().contains("interactive terminal"));
}

#[test]
fn scripted_prompt_skips_prefilled_inputs() {
  let evaluation = evaluation();
  let mut vars = BTreeMap::from([("admin_cidr".to_string(), "10.0.0.0/8".to_string())]);
  let mut binds = BTreeMap::from([("app_route".to_string(), "mmsecretvault".to_string())]);
  let mut prompt = ScriptedPrompt::new(&["yes"]);

  complete_interactive_from_evaluation(
    &evaluation,
    &mut vars,
    &mut binds,
    RulepackModeArg::Monitor,
    true,
    &mut prompt,
  )
  .expect("prefilled interactive inputs");

  assert_eq!(
    prompt.lines.last().map(String::as_str),
    Some("Apply rulepack now? [y/N]")
  );
  assert_eq!(
    binds.get("app_route").map(String::as_str),
    Some("mmsecretvault")
  );
  assert_eq!(
    vars.get("admin_cidr").map(String::as_str),
    Some("10.0.0.0/8")
  );
}

#[test]
fn scripted_prompt_can_cancel_before_apply() {
  let evaluation = evaluation();
  let mut vars = BTreeMap::new();
  let mut binds = BTreeMap::new();
  let mut prompt = ScriptedPrompt::new(&["1", "10.0.0.0/8", "no"]);

  let error = complete_interactive_from_evaluation(
    &evaluation,
    &mut vars,
    &mut binds,
    RulepackModeArg::Monitor,
    true,
    &mut prompt,
  )
  .expect_err("decline should cancel");

  assert!(error.to_string().contains("cancelled"));
}

#[test]
fn scripted_prompt_can_skip_apply_confirmation_for_dry_run() {
  let evaluation = evaluation();
  let mut vars = BTreeMap::from([("admin_cidr".to_string(), "10.0.0.0/8".to_string())]);
  let mut binds = BTreeMap::from([("app_route".to_string(), "mmsecretvault".to_string())]);
  let mut prompt = ScriptedPrompt::new(&[]);

  complete_interactive_from_evaluation(
    &evaluation,
    &mut vars,
    &mut binds,
    RulepackModeArg::Monitor,
    false,
    &mut prompt,
  )
  .expect("dry-run interactive inputs");

  assert!(
    !prompt
      .lines
      .iter()
      .any(|line| line.contains("Apply rulepack now?"))
  );
}
