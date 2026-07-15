use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::AdminClient;
use serde::Serialize;
use serde_json::{Value, json};

use super::PreparedRulepackApply;

#[derive(Debug, Default, Serialize)]
pub(crate) struct RulepackRisk {
  terminal_actions: Vec<String>,
  body_inspection: bool,
  response_inspection: bool,
  estimated_cost: &'static str,
  cost_warnings: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  fixture_results: Vec<RulepackProbeResult>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  replay_results: Vec<RulepackProbeResult>,
}

impl RulepackRisk {
  pub(super) fn unknown() -> Self {
    Self {
      estimated_cost: "unknown",
      ..Self::default()
    }
  }
}

#[derive(Debug, Serialize)]
struct RulepackProbeResult {
  rule: String,
  ok: bool,
  report: Value,
}

#[derive(Debug)]
struct RulepackCandidateSet {
  rules: Vec<RenderedRuleCandidate>,
  groups: Vec<Value>,
}

#[derive(Debug)]
struct RenderedRuleCandidate {
  name: String,
  body: Value,
  content: String,
}

pub(super) fn risk_for_prepared(prepared: &PreparedRulepackApply) -> anyhow::Result<RulepackRisk> {
  let candidates = rendered_candidates(prepared)?;
  let mut terminal_actions = BTreeSet::new();
  let mut body_inspection = false;
  let mut response_inspection = false;
  for candidate in &candidates.rules {
    body_inspection |= candidate.content.contains("Request.Body");
    response_inspection |= candidate.content.contains("Response.Body");
    for action in terminal_actions_for_content(&candidate.content) {
      terminal_actions.insert(action);
    }
  }
  let mut risk = RulepackRisk {
    terminal_actions: terminal_actions.into_iter().collect(),
    body_inspection,
    response_inspection,
    estimated_cost: "low",
    ..RulepackRisk::default()
  };
  if risk.body_inspection || risk.response_inspection {
    risk.estimated_cost = "medium";
  }
  Ok(risk)
}

pub(super) async fn augment_risk_with_devtools(
  client: &AdminClient,
  prepared: &PreparedRulepackApply,
  risk: &mut RulepackRisk,
  fixture: Option<&Path>,
  replay: Option<&Path>,
  warnings: &mut Vec<String>,
) -> anyhow::Result<()> {
  let candidates = rendered_candidates(prepared)?;
  for candidate in &candidates.rules {
    let body = json!({
      "rule": candidate.body.clone(),
      "groups": candidates.groups.clone(),
      "include_active_rules": false,
    });
    match post_devtool(client, "/admin/v1/waf/oxirule/cost", body).await {
      Ok(report) => merge_cost_report(risk, &report),
      Err(error) => warnings.push(format!(
        "cost probe for rule {} was not available: {error:#}",
        candidate.name
      )),
    }
  }
  if let Some(path) = fixture {
    let fixture = read_json_file(path)?;
    for candidate in &candidates.rules {
      let body = json!({
        "rule": candidate.body.clone(),
        "groups": candidates.groups.clone(),
        "include_active_rules": false,
        "fixture": fixture.clone(),
      });
      match post_devtool(client, "/admin/v1/waf/oxirule/test", body).await {
        Ok(report) => risk.fixture_results.push(RulepackProbeResult {
          rule: candidate.name.clone(),
          ok: report.get("ok").and_then(Value::as_bool).unwrap_or(false),
          report,
        }),
        Err(error) => warnings.push(format!(
          "fixture probe for rule {} was not available: {error:#}",
          candidate.name
        )),
      }
    }
  }
  if let Some(path) = replay {
    let input = std::fs::read_to_string(path)
      .with_context(|| format!("failed to read {}", path.display()))?;
    for candidate in &candidates.rules {
      let body = json!({
        "rule": candidate.body.clone(),
        "groups": candidates.groups.clone(),
        "include_active_rules": false,
        "input": input.clone(),
      });
      match post_devtool(client, "/admin/v1/waf/oxirule/replay", body).await {
        Ok(report) => risk.replay_results.push(RulepackProbeResult {
          rule: candidate.name.clone(),
          ok: report.get("ok").and_then(Value::as_bool).unwrap_or(false),
          report,
        }),
        Err(error) => warnings.push(format!(
          "replay probe for rule {} was not available: {error:#}",
          candidate.name
        )),
      }
    }
  }
  if !risk.cost_warnings.is_empty() {
    risk.estimated_cost = "medium";
  }
  Ok(())
}

fn merge_cost_report(risk: &mut RulepackRisk, report: &Value) {
  if let Some(body_need) = report.get("body_need").and_then(Value::as_object) {
    if body_need
      .get("request_body")
      .and_then(Value::as_str)
      .is_some_and(|need| need != "none")
    {
      risk.body_inspection = true;
    }
    if body_need
      .get("response_body")
      .and_then(Value::as_str)
      .is_some_and(|need| need != "none")
    {
      risk.response_inspection = true;
    }
  }
  if let Some(warnings) = report.get("cost_warnings").and_then(Value::as_array) {
    for warning in warnings {
      if let Some(warning) = warning.as_str()
        && !risk
          .cost_warnings
          .iter()
          .any(|existing| existing == warning)
      {
        risk.cost_warnings.push(warning.to_string());
      }
    }
  }
}

async fn post_devtool(client: &AdminClient, endpoint: &str, body: Value) -> anyhow::Result<Value> {
  let response = client
    .request_json(Method::POST, endpoint, Some(body), None)
    .await?;
  if !response.status.is_success() {
    bail!("Admin devtool request failed with {}", response.status);
  }
  serde_json::from_slice(&response.body).context("Admin devtool response was not JSON")
}

fn rendered_candidates(prepared: &PreparedRulepackApply) -> anyhow::Result<RulepackCandidateSet> {
  let value: toml::Value = toml::from_str(&prepared.rendered_manifest)
    .context("rendered rulepack manifest was not TOML")?;
  let rules = value
    .get("rules")
    .and_then(toml::Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(toml::Value::as_table)
    .map(|table| rule_candidate_from_table(table, &prepared.rendered_rule_files))
    .collect::<anyhow::Result<Vec<_>>>()?;
  let groups = value
    .get("group_files")
    .and_then(toml::Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(toml::Value::as_table)
    .map(|table| group_candidate_from_table(table, &prepared.rendered_group_files))
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok(RulepackCandidateSet { rules, groups })
}

fn rule_candidate_from_table(
  table: &toml::map::Map<String, toml::Value>,
  rendered_files: &BTreeMap<String, String>,
) -> anyhow::Result<RenderedRuleCandidate> {
  let name = table
    .get("name")
    .and_then(toml::Value::as_str)
    .unwrap_or("unnamed-rule")
    .to_string();
  let content = content_or_path(table, rendered_files)
    .with_context(|| format!("rendered rulepack rule {name} does not include content"))?;
  let mut candidate = serde_json::Map::new();
  candidate.insert("content".to_string(), json!(content));
  insert_str(table, &mut candidate, "name");
  insert_str(table, &mut candidate, "id");
  insert_str(table, &mut candidate, "phase");
  insert_str(table, &mut candidate, "mode");
  if let Some(priority) = table.get("priority").and_then(toml::Value::as_integer) {
    candidate.insert("priority".to_string(), json!(priority));
  }
  if let Some(tags) = table.get("tags").and_then(toml::Value::as_array) {
    candidate.insert(
      "tags".to_string(),
      Value::Array(
        tags
          .iter()
          .filter_map(toml::Value::as_str)
          .map(|tag| json!(tag))
          .collect(),
      ),
    );
  }
  Ok(RenderedRuleCandidate {
    name,
    body: Value::Object(candidate),
    content,
  })
}

fn group_candidate_from_table(
  table: &toml::map::Map<String, toml::Value>,
  rendered_files: &BTreeMap<String, String>,
) -> anyhow::Result<Value> {
  let content = content_or_path(table, rendered_files)
    .context("rendered rulepack group does not include content")?;
  let mut candidate = serde_json::Map::new();
  candidate.insert("content".to_string(), json!(content));
  insert_str(table, &mut candidate, "name");
  Ok(Value::Object(candidate))
}

fn content_or_path(
  table: &toml::map::Map<String, toml::Value>,
  rendered_files: &BTreeMap<String, String>,
) -> Option<String> {
  table
    .get("content")
    .and_then(toml::Value::as_str)
    .map(str::to_string)
    .or_else(|| {
      table
        .get("path")
        .and_then(toml::Value::as_str)
        .and_then(|path| rendered_files.get(path).cloned())
    })
}

fn insert_str(
  table: &toml::map::Map<String, toml::Value>,
  candidate: &mut serde_json::Map<String, Value>,
  key: &str,
) {
  if let Some(value) = table.get(key).and_then(toml::Value::as_str) {
    candidate.insert(key.to_string(), json!(value));
  }
}

pub(super) fn terminal_actions_for_content(content: &str) -> Vec<String> {
  let Ok(value) = toml::from_str::<toml::Value>(content) else {
    return Vec::new();
  };
  value
    .get("actions")
    .and_then(toml::Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(toml::Value::as_table)
    .filter_map(|action| action.get("type").and_then(toml::Value::as_str))
    .filter(|action_type| {
      matches!(
        *action_type,
        "reject"
          | "silent_close"
          | "rate_limit"
          | "replace_response"
          | "reject_response"
          | "challenge"
      )
    })
    .map(str::to_string)
    .collect()
}

fn read_json_file(path: &Path) -> anyhow::Result<Value> {
  let raw =
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
  serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}
