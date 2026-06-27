//! Devtools summary projection for generated rule candidates.

use super::super::{
  BodyNeed, BodyTextCaches, CompiledAction, EvalContext, HeaderMutation, PersonProofRequestStatus,
  RequestWafDecision, ResponseWafDecision, TransactionBudget, WafActionConfig, WafEngine,
  WafHttpTerminal, WafPhase, WafStreamClose, WafStreamDecision, WafTerminalResponse,
};
use super::fixture::{BuiltFixture, header_value_to_string};
use super::types::{
  OxiRuleActionSummary, OxiRuleBodyNeedSummary, OxiRuleDevtoolsReport, OxiRuleExpectedOutcome,
  OxiRuleExplainStep, OxiRuleMatchedRule, OxiRuleMutationSummary, OxiRuleStreamCloseSummary,
  OxiRuleTagSummary, OxiRuleTerminalSummary,
};

pub(super) fn explain_steps(
  engine: &WafEngine,
  fixture: &BuiltFixture,
  phase: WafPhase,
  report: &mut OxiRuleDevtoolsReport,
) -> Vec<OxiRuleExplainStep> {
  let mut tx = TransactionBudget::new(&engine.limits);
  let person_proof = PersonProofRequestStatus::default();
  let body_text_caches = BodyTextCaches::default();
  let request = fixture.request_input();
  let response = (phase == WafPhase::Response).then(|| fixture.response_input());
  let stream = (phase == WafPhase::Stream).then(|| fixture.stream_input());
  let ctx = EvalContext {
    phase,
    mode: engine.mode,
    rule_name: "",
    rule_id: None,
    rule_tags: &[],
    request,
    response,
    stream,
    person_proof: &person_proof,
    pattern_sets: &engine.pattern_sets,
    regex_cache: None,
    locals: &[],
    limits: &engine.limits,
    duplicate_metadata_policy: engine.duplicate_metadata_policy,
    body_text_caches: &body_text_caches,
  };
  let rules = match phase {
    WafPhase::Request => engine.route_plan(fixture.route_name()).request().rules(),
    WafPhase::Response => engine.route_plan(fixture.route_name()).response().rules(),
    WafPhase::Stream => engine.route_plan(fixture.route_name()).stream().rules(),
  };
  rules
    .iter()
    .map(|rule| match engine.evaluate_rule(rule, &ctx, &mut tx) {
      Ok(matched) => OxiRuleExplainStep {
        phase: phase.as_str().to_string(),
        rule: rule.name.clone(),
        matched,
        error: None,
        actions: rule.actions.iter().map(action_label).collect(),
      },
      Err(error) => {
        report.push_error("oxirule.explain.eval", error.to_string());
        OxiRuleExplainStep {
          phase: phase.as_str().to_string(),
          rule: rule.name.clone(),
          matched: false,
          error: Some(error.to_string()),
          actions: rule.actions.iter().map(action_label).collect(),
        }
      }
    })
    .collect()
}

pub(super) fn summarize_request_decision(
  report: &mut OxiRuleDevtoolsReport,
  decision: RequestWafDecision,
) {
  if let Some(terminal) = decision.terminal {
    summarize_http_terminal(report, "terminal", terminal);
  }
  append_mutations(
    &mut report.mutations,
    "request_header",
    decision.request_header_mutations,
  );
  append_mutations(
    &mut report.mutations,
    "response_header",
    decision.response_header_mutations,
  );
  if let Some(upstream) = decision.upstream_override {
    report.actions.push(OxiRuleActionSummary {
      action: "route_to_upstream".to_string(),
      target: Some(upstream),
    });
  }
  if let Some(pool) = decision.upstream_pool_override {
    report.actions.push(OxiRuleActionSummary {
      action: "route_to_pool".to_string(),
      target: Some(pool),
    });
  }
  if let Some(policy) = decision.load_balancing_policy {
    report.actions.push(OxiRuleActionSummary {
      action: "set_load_balancing_policy".to_string(),
      target: Some(policy),
    });
  }
  report.tags.extend(
    decision
      .tags
      .into_iter()
      .map(|(key, value)| OxiRuleTagSummary { key, value }),
  );
}

pub(super) fn summarize_response_decision(
  report: &mut OxiRuleDevtoolsReport,
  decision: ResponseWafDecision,
) {
  if let Some(terminal) = decision.terminal {
    summarize_http_terminal(report, "response_terminal", terminal);
  }
  append_mutations(
    &mut report.mutations,
    "response_header",
    decision.response_header_mutations,
  );
  for access_log in decision.access_logs {
    report.actions.push(OxiRuleActionSummary {
      action: "emit_access_log".to_string(),
      target: Some(access_log.to_json_line()),
    });
  }
}

pub(super) fn summarize_stream_decision(
  report: &mut OxiRuleDevtoolsReport,
  decision: WafStreamDecision,
) {
  if let Some(close) = decision.close {
    report.actions.push(OxiRuleActionSummary {
      action: "close_stream".to_string(),
      target: Some(close.reason.clone()),
    });
    report.stream_close = Some(stream_close_summary(close));
  }
  if decision.silent_close {
    report.actions.push(OxiRuleActionSummary {
      action: "silent_close".to_string(),
      target: None,
    });
  }
}

pub(super) fn matched_rules(engine: &WafEngine) -> Vec<OxiRuleMatchedRule> {
  engine
    .rule_hit_snapshots()
    .into_iter()
    .filter(|snapshot| snapshot.hits > 0)
    .map(|snapshot| OxiRuleMatchedRule {
      scope: snapshot.scope,
      route: snapshot.route,
      phase: snapshot.phase,
      name: snapshot.name,
      id: snapshot.id,
      tags: snapshot.tags,
      effective_mode: snapshot.effective_mode,
    })
    .collect()
}

pub(super) fn body_need_summary(
  engine: &WafEngine,
  route_name: &str,
  phase: WafPhase,
) -> OxiRuleBodyNeedSummary {
  let plan = engine.route_plan(route_name);
  OxiRuleBodyNeedSummary {
    phase: phase.as_str().to_string(),
    request_body: body_need_str(plan.request_body_need()).to_string(),
    response_body: body_need_str(plan.response().body_need()).to_string(),
  }
}

pub(super) fn cost_warnings(engine: &WafEngine, route_name: &str) -> Vec<String> {
  let mut warnings = Vec::new();
  let plan = engine.route_plan(route_name);
  if plan.request_body_need().requires_prefix() {
    warnings.push("request body prefix inspection is required".to_string());
  }
  if plan.response().body_need().requires_prefix() {
    warnings.push("response body prefix inspection is required".to_string());
  }
  let rules = engine
    .global_rules
    .iter()
    .chain(engine.route_rules.values().flat_map(|rules| rules.iter()))
    .count();
  if rules > 32 {
    warnings.push(format!(
      "{rules} OxiRule rules are in the candidate evaluation set"
    ));
  }
  warnings
}

pub(super) fn apply_expectations(
  report: &mut OxiRuleDevtoolsReport,
  expected: Option<&OxiRuleExpectedOutcome>,
) {
  let Some(expected) = expected else {
    return;
  };
  for rule in &expected.matched_rules {
    if !report
      .matched_rules
      .iter()
      .any(|matched| matched.name == *rule)
    {
      report.push_error(
        "oxirule.expect.matched_rule",
        format!("expected rule {rule} to match"),
      );
    }
  }
  if let Some(status) = expected.terminal_status {
    let actual = report.terminal.as_ref().map(|terminal| terminal.status);
    if actual != Some(status) {
      report.push_error(
        "oxirule.expect.terminal_status",
        format!("expected terminal status {status}, got {actual:?}"),
      );
    }
  }
  if let Some(stream_close) = expected.stream_close
    && report.stream_close.is_some() != stream_close
  {
    report.push_error(
      "oxirule.expect.stream_close",
      format!("expected stream_close = {stream_close}"),
    );
  }
}

fn terminal_summary(terminal: WafTerminalResponse) -> OxiRuleTerminalSummary {
  OxiRuleTerminalSummary {
    status: terminal.status.as_u16(),
    body: terminal.body,
    headers: terminal
      .headers
      .into_iter()
      .map(|header| mutation_summary("response_header", header))
      .collect(),
  }
}

fn summarize_http_terminal(
  report: &mut OxiRuleDevtoolsReport,
  action: &str,
  terminal: WafHttpTerminal,
) {
  match terminal {
    WafHttpTerminal::Response(terminal) => {
      report.actions.push(OxiRuleActionSummary {
        action: action.to_string(),
        target: Some(terminal.status.as_u16().to_string()),
      });
      report.terminal = Some(terminal_summary(terminal));
    }
    WafHttpTerminal::SilentClose => {
      report.actions.push(OxiRuleActionSummary {
        action: "silent_close".to_string(),
        target: None,
      });
    }
  }
}

fn stream_close_summary(close: WafStreamClose) -> OxiRuleStreamCloseSummary {
  OxiRuleStreamCloseSummary {
    websocket_code: close.websocket_code,
    webtransport_code: close.webtransport_code,
    reason: close.reason,
  }
}

fn append_mutations(
  out: &mut Vec<OxiRuleMutationSummary>,
  prefix: &str,
  mutations: Vec<HeaderMutation>,
) {
  out.extend(
    mutations
      .into_iter()
      .map(|mutation| mutation_summary(prefix, mutation)),
  );
}

fn mutation_summary(prefix: &str, mutation: HeaderMutation) -> OxiRuleMutationSummary {
  match mutation {
    HeaderMutation::Set { name, value } => OxiRuleMutationSummary {
      op: format!("{prefix}.set"),
      name: name.as_str().to_string(),
      value: Some(header_value_to_string(&value)),
    },
    HeaderMutation::Append { name, value } => OxiRuleMutationSummary {
      op: format!("{prefix}.append"),
      name: name.as_str().to_string(),
      value: Some(header_value_to_string(&value)),
    },
    HeaderMutation::Remove { name } => OxiRuleMutationSummary {
      op: format!("{prefix}.remove"),
      name: name.as_str().to_string(),
      value: None,
    },
  }
}

fn body_need_str(need: BodyNeed) -> &'static str {
  match need {
    BodyNeed::None => "none",
    BodyNeed::SizeOnly => "size_only",
    BodyNeed::PrefixBytes => "prefix_bytes",
  }
}

fn action_label(action: &CompiledAction) -> String {
  match action {
    CompiledAction::Config(config) => action_config_label(config).to_string(),
    CompiledAction::RequirePersonProof(_) => "require_person_proof".to_string(),
    CompiledAction::EmitAccessLog { .. } => "emit_access_log".to_string(),
    CompiledAction::EmitMitigation(_) => "emit_mitigation".to_string(),
  }
}

fn action_config_label(action: &WafActionConfig) -> &'static str {
  match action {
    WafActionConfig::Reject { .. } => "reject",
    WafActionConfig::SilentClose { .. } => "silent_close",
    WafActionConfig::ContinueResponse { .. } => "continue_response",
    WafActionConfig::ReplaceResponse { .. } => "replace_response",
    WafActionConfig::RejectResponse { .. } => "reject_response",
    WafActionConfig::EmitAccessLog { .. } => "emit_access_log",
    WafActionConfig::EmitMitigation { .. } => "emit_mitigation",
    WafActionConfig::RouteToPool { .. } => "route_to_pool",
    WafActionConfig::RouteToUpstream { .. } => "route_to_upstream",
    WafActionConfig::SetLoadBalancingPolicy { .. } => "set_load_balancing_policy",
    WafActionConfig::SetRequestHeader { .. } => "set_request_header",
    WafActionConfig::RemoveRequestHeader { .. } => "remove_request_header",
    WafActionConfig::SetResponseHeader { .. } => "set_response_header",
    WafActionConfig::RemoveResponseHeader { .. } => "remove_response_header",
    WafActionConfig::SetTag { .. } => "set_tag",
    WafActionConfig::RateLimit { .. } => "rate_limit",
    WafActionConfig::WeighPersonProof { .. } => "weigh_person_proof",
    WafActionConfig::AllowPersonProof { .. } => "allow_person_proof",
    WafActionConfig::RequirePersonProof { .. } => "require_person_proof",
    WafActionConfig::CloseStream { .. } => "close_stream",
  }
}
