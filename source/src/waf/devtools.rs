mod candidate;
mod fixture;
mod summary;
mod templates;
mod types;

use crate::config::Config;

use super::{WafEngine, WafPhase};
use candidate::candidate_config;
pub use candidate::{oxirule_group_resource_names, oxirule_rule_resource_name};
use fixture::{BuiltFixture, fixture_from_access_log_value};
use summary::{
  apply_expectations, body_need_summary, cost_warnings, explain_steps, matched_rules,
  summarize_request_decision, summarize_response_decision, summarize_stream_decision,
};
pub use templates::{list_oxirule_templates, plan_false_positive, render_oxirule_template};
pub use types::*;

pub fn check_oxirule(
  config: &Config,
  request: OxiRuleDevtoolsCheckRequest,
) -> OxiRuleDevtoolsReport {
  let mut report = OxiRuleDevtoolsReport::ok();
  match candidate_config(
    config,
    request.rule.as_ref(),
    &request.groups,
    request.include_active_rules,
  ) {
    Ok(candidate) => match WafEngine::new(&candidate.config) {
      Ok(engine) => {
        report.body_need = Some(body_need_summary(
          &engine,
          &candidate.route_name,
          WafPhase::Request,
        ));
        report.cost_warnings = cost_warnings(&engine, &candidate.route_name);
      }
      Err(error) => report.push_error("oxirule.compile", error.to_string()),
    },
    Err(error) => report.push_error("oxirule.prepare", error.to_string()),
  }
  report
}

pub fn cost_oxirule(
  config: &Config,
  request: OxiRuleDevtoolsCheckRequest,
) -> OxiRuleDevtoolsReport {
  let mut report = check_oxirule(config, request);
  if report.ok && report.cost_warnings.is_empty() {
    report.push_warning(
      "oxirule.cost.no_runtime_samples",
      "no runtime fixture was provided; cost is a static estimate",
    );
  }
  report
}

pub fn test_oxirule(config: &Config, request: OxiRuleDevtoolsEvalRequest) -> OxiRuleDevtoolsReport {
  evaluate_oxirule(config, request, false)
}

pub fn explain_oxirule(
  config: &Config,
  request: OxiRuleDevtoolsEvalRequest,
) -> OxiRuleDevtoolsReport {
  evaluate_oxirule(config, request, true)
}

pub fn replay_oxirule(
  config: &Config,
  request: OxiRuleDevtoolsReplayRequest,
) -> OxiRuleDevtoolsReport {
  let mut report = OxiRuleDevtoolsReport::ok();
  let mut saw_line = false;
  for (line_index, raw_line) in request.input.lines().enumerate() {
    let line_number = line_index + 1;
    let line = raw_line.trim();
    if line.is_empty() {
      continue;
    }
    saw_line = true;
    let fixture = match serde_json::from_str::<OxiRuleFixture>(line).or_else(|_| {
      serde_json::from_str::<serde_json::Value>(line).map(fixture_from_access_log_value)
    }) {
      Ok(fixture) => fixture,
      Err(error) => {
        report.ok = false;
        report.replay_results.push(OxiRuleReplayResult {
          line: line_number,
          ok: false,
          matched_rules: Vec::new(),
          terminal: None,
          stream_close: None,
          diagnostics: vec![OxiRuleDiagnostic {
            severity: "error",
            code: "oxirule.replay.parse",
            message: error.to_string(),
          }],
        });
        continue;
      }
    };
    let eval_request = OxiRuleDevtoolsEvalRequest {
      rule: request.rule.clone(),
      groups: request.groups.clone(),
      include_active_rules: request.include_active_rules,
      fixture,
      expected: None,
    };
    let line_report = test_oxirule(config, eval_request);
    if !line_report.ok {
      report.ok = false;
    }
    report.replay_results.push(OxiRuleReplayResult {
      line: line_number,
      ok: line_report.ok,
      matched_rules: line_report.matched_rules,
      terminal: line_report.terminal,
      stream_close: line_report.stream_close,
      diagnostics: line_report.diagnostics,
    });
  }
  if !saw_line {
    report.push_error(
      "oxirule.replay.empty",
      "replay input must contain at least one JSON line",
    );
  }
  report
}

fn evaluate_oxirule(
  config: &Config,
  request: OxiRuleDevtoolsEvalRequest,
  explain: bool,
) -> OxiRuleDevtoolsReport {
  let mut report = OxiRuleDevtoolsReport::ok();
  let candidate = match candidate_config(
    config,
    Some(&request.rule),
    &request.groups,
    request.include_active_rules,
  ) {
    Ok(candidate) => candidate,
    Err(error) => {
      report.push_error("oxirule.prepare", error.to_string());
      return report;
    }
  };
  let engine = match WafEngine::new(&candidate.config) {
    Ok(engine) => engine,
    Err(error) => {
      report.push_error("oxirule.compile", error.to_string());
      return report;
    }
  };
  let fixture = match BuiltFixture::new(&candidate.config, &candidate.route_name, request.fixture) {
    Ok(fixture) => fixture,
    Err(error) => {
      report.push_error("oxirule.fixture", error.to_string());
      return report;
    }
  };
  let phase = fixture.phase();
  report.body_need = Some(body_need_summary(&engine, fixture.route_name(), phase));
  if explain {
    report.explain_steps = explain_steps(&engine, &fixture, phase, &mut report);
  }

  match phase {
    WafPhase::Request => {
      let decision = engine.evaluate_request(fixture.request_input());
      summarize_request_decision(&mut report, decision);
    }
    WafPhase::Response => {
      let response = fixture.response_input();
      let decision = engine.evaluate_response(response);
      summarize_response_decision(&mut report, decision);
    }
    WafPhase::Stream => {
      let stream = fixture.stream_input();
      let decision = engine.evaluate_stream(stream);
      summarize_stream_decision(&mut report, decision);
    }
  }

  report.matched_rules = matched_rules(&engine);
  report.cost_warnings = cost_warnings(&engine, fixture.route_name());
  apply_expectations(&mut report, request.expected.as_ref());
  report
}
