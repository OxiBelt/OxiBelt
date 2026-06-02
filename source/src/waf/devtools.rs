mod candidate;
mod fixture;
mod summary;
mod templates;
mod types;

use crate::config::Config;

use super::{WafEngine, WafMode, WafPhase, body_scan, malicious_intelligence_score};
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

pub fn analyze_oxirule(config: &Config, request: OxiRuleAnalyzeRequest) -> OxiRuleDevtoolsReport {
  let mut report = OxiRuleDevtoolsReport::ok();
  let fallback_route = config
    .routes
    .first()
    .map(|route| route.name.as_str())
    .unwrap_or("default");
  let fixture = match BuiltFixture::new(config, fallback_route, request.fixture) {
    Ok(fixture) => fixture,
    Err(error) => {
      report.push_error("oxirule.fixture", error.to_string());
      return report;
    }
  };
  let profiles = request.profiles;
  let request_input = fixture.request_input();

  push_risk(
    &mut report,
    &profiles,
    "request.uri",
    "uri",
    &request_input.uri.to_string(),
    false,
  );
  push_risk(
    &mut report,
    &profiles,
    "request.path",
    "path",
    request_input.uri.path(),
    false,
  );
  push_risk(
    &mut report,
    &profiles,
    "request.query",
    "query",
    request_input.uri.query().unwrap_or_default(),
    false,
  );
  if let Some(user_agent) = request_input
    .headers
    .get(http::header::USER_AGENT)
    .and_then(|value| value.to_str().ok())
  {
    push_risk(
      &mut report,
      &profiles,
      "request.headers.user_agent",
      "header",
      user_agent,
      false,
    );
  }
  for (name, value) in request_input.headers.iter().take(16) {
    if let Ok(value) = value.to_str() {
      push_risk(
        &mut report,
        &profiles,
        &format!("request.headers.{name}"),
        "header",
        value,
        false,
      );
    }
  }
  if let Some(body) = request_input.body {
    let text = body_scan::body_text(body.bytes);
    push_body_risk(
      &mut report,
      &profiles,
      "request.body",
      "payload",
      body,
      &text,
    );
  }

  match fixture.phase() {
    WafPhase::Response => {
      let response = fixture.response_input();
      if let Some(body) = response.body {
        let text = body_scan::body_text(body.bytes);
        push_body_risk(
          &mut report,
          &profiles,
          "response.body",
          "payload",
          body,
          &text,
        );
      }
    }
    WafPhase::Stream => {
      let stream = fixture.stream_input();
      let text = body_scan::body_text(stream.payload.bytes);
      push_body_risk(
        &mut report,
        &profiles,
        "stream.payload",
        "payload",
        stream.payload,
        &text,
      );
    }
    WafPhase::Request => {}
  }

  let bot = malicious_intelligence_score::request_bot_assessment(request_input);
  report.bot = Some(OxiRuleBotRiskSummary {
    score: bot.score,
    disposition: bot.disposition,
    malicious: bot.malicious,
    reason: bot.reason,
  });
  report
}

pub fn plan_oxirule_hardening(request: OxiRuleHardeningPlanRequest) -> OxiRuleDevtoolsReport {
  let mut report = OxiRuleDevtoolsReport::ok();
  let mode = request.mode.unwrap_or(WafMode::Monitor);
  let route_condition = request
    .route
    .as_ref()
    .map(|route| {
      format!(
        "Context.RouteName == '{}' && ",
        route.replace('\\', "\\\\").replace('\'', "\\'")
      )
    })
    .unwrap_or_default();
  let threats = if request.threats.is_empty() {
    vec![
      "prompt_injection".to_string(),
      "malformed_payload".to_string(),
      "suspicious_automation".to_string(),
    ]
  } else {
    request.threats
  };
  report.suggestions = threats
    .iter()
    .map(|threat| format!("include local heuristic coverage for {threat}"))
    .collect();
  report.toml_patch = Some(format!(
    r#"# groups/malicious-intelligence-local-risk.oxirule-group.toml
[[rule_groups]]
name = "malicious-intelligence-local-risk"
when = """
{route_condition}(
  Request.Http.Uri.anomalyScore('uri') >= 60 ||
  Request.Http.Path.malformedScore('path') >= 35 ||
  Request.Http.Query.promptInjectionScore() >= 35 ||
  Request.Headers.anyValueMatches('(?i)(headless|python-requests|curl|sqlmap|nikto)') ||
  Request.Client.Bot.Score >= 70
)
"""

[[rule_groups.actions]]
priority = 10
type = "weigh_person_proof"
weight = 50

# rules/malicious-intelligence-local-hardening.oxirule.toml
groups = ["malicious-intelligence-local-risk"]
when = """
Request.Client.PersonProof.State != 'valid' &&
Request.Client.Bot.Disposition != 'normal'
"""
merge_condition_as = "and"

[[actions]]
priority = 20
type = "require_person_proof"
person_proof_mode = "built_in"
difficulty = 20
token_validity_seconds = 180
single_use = true
success_tag = "MaliciousIntelligenceRiskCleared"
status = 403

# rules/malicious-intelligence-malformed-payload.oxirule.toml
# Recommended rule entry mode: {mode}
when = """
{route_condition}(
  Request.Body.malformedScore('payload') >= 55 ||
  Request.Body.promptInjectionScore() >= 55
)
"""

[[actions]]
type = "reject"
status = 403
body = "Blocked by OxiRule"
"#,
    mode = mode.as_str()
  ));
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

fn push_risk(
  report: &mut OxiRuleDevtoolsReport,
  profiles: &[String],
  target: &str,
  profile: &str,
  text: &str,
  truncated: bool,
) {
  if !profiles.is_empty() && !profiles.iter().any(|candidate| candidate == profile) {
    return;
  }
  let anomaly_score = match malicious_intelligence_score::anomaly_score(text, profile) {
    Ok(score) => score,
    Err(error) => {
      report.push_error("oxirule.analyze.profile", error.to_string());
      return;
    }
  };
  let malformed_score = match malicious_intelligence_score::malformed_score(text, profile) {
    Ok(score) => score,
    Err(error) => {
      report.push_error("oxirule.analyze.profile", error.to_string());
      return;
    }
  };
  report.risk.push(OxiRuleRiskSummary {
    target: target.to_string(),
    profile: profile.to_string(),
    anomaly_score,
    malformed_score,
    prompt_injection_score: malicious_intelligence_score::prompt_injection_score(text),
    truncated,
  });
}

fn push_body_risk(
  report: &mut OxiRuleDevtoolsReport,
  profiles: &[String],
  target: &str,
  profile: &str,
  body: super::WafBodyInput<'_>,
  text: &str,
) {
  if !profiles.is_empty() && !profiles.iter().any(|candidate| candidate == profile) {
    return;
  }
  let anomaly_score =
    match malicious_intelligence_score::body_anomaly_score(Some(body), Some(text), profile) {
      Ok(score) => score,
      Err(error) => {
        report.push_error("oxirule.analyze.profile", error.to_string());
        return;
      }
    };
  let malformed_score =
    match malicious_intelligence_score::body_malformed_score(Some(body), Some(text), profile) {
      Ok(score) => score,
      Err(error) => {
        report.push_error("oxirule.analyze.profile", error.to_string());
        return;
      }
    };
  report.risk.push(OxiRuleRiskSummary {
    target: target.to_string(),
    profile: profile.to_string(),
    anomaly_score,
    malformed_score,
    prompt_injection_score: malicious_intelligence_score::body_prompt_injection_score(
      Some(body),
      Some(text),
    ),
    truncated: body.is_truncated,
  });
}
