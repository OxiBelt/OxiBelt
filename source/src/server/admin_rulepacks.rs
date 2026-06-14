//! Admin rulepack endpoints.
//! Rulepack inspection and rendering are exposed through the same admin authorization boundary.

use std::collections::{BTreeMap, BTreeSet};

use ::http::{Response, StatusCode};
use anyhow::{Context, bail};
use hyper::body::Incoming;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::Config;
use crate::identity::Cidr;
use crate::limits::parse_rate;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::waf::{
  OxiRuleCandidate, OxiRuleGroupCandidate, RULEPACK_FILE_SUFFIX, RulepackBindingKind,
  RulepackException, RulepackInputMetadata, RulepackModeOverride, RulepackOverride,
  RulepackRenderOptions, RulepackSourceProvenance, WafMode, WafPhase, WafRulepackSummary,
  inspect_rulepack, inspect_rulepack_inputs, referenced_rulepack_files,
  render_rulepack_for_install, validate_rulepack_exception_list, validate_rulepack_overrides,
};

use super::admin;
use super::admin_auth::AdminAuthorization;
use super::admin_body::collect_admin_json;

#[path = "admin_rulepacks/risk.rs"]
mod risk;
#[path = "admin_rulepacks/route_fit.rs"]
mod route_fit;
use risk::{augment_risk_with_cost, candidate_set, static_risk, unknown_risk};
use route_fit::{route_candidates, route_warnings};
#[cfg(test)]
#[path = "admin_rulepacks/tests.rs"]
mod tests;

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

pub(super) async fn plan_response(
  request: hyper::Request<Incoming>,
  config: &Config,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
) -> Response<ProxyBody> {
  if *method != ::http::Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  let body = match collect_admin_json::<AdminRulepackPlanRequest>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  if let Some(response) = plan_permission_denial(&body, authorization) {
    return response;
  }
  match plan_rulepack(config, body) {
    Ok(report) => admin::json_response(StatusCode::OK, &report),
    Err(error) => admin::json_response(
      StatusCode::BAD_REQUEST,
      &json!({ "ok": false, "error": error.to_string() }),
    ),
  }
}

fn plan_permission_denial(
  body: &AdminRulepackPlanRequest,
  authorization: &AdminAuthorization<'_>,
) -> Option<Response<ProxyBody>> {
  if !authorization.is_allowed("waf:PlanOxiRulePack", "oxirule-rulepack/plan") {
    return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }
  if body.include_route_candidates
    && !authorization.is_allowed("config:ReadRouteInventory", "route-inventory/current")
  {
    return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }
  if body.include_diff && !authorization.is_allowed("waf:ListOxiRulePacks", "*") {
    return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }
  if body.include_cost && !authorization.is_allowed("waf:EstimateOxiRuleCost", "oxirule/*") {
    return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }
  None
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminRulepackPlanRequest {
  manifest: String,
  #[serde(default)]
  source: Option<AdminRulepackPlanSource>,
  #[serde(default)]
  values: BTreeMap<String, String>,
  #[serde(default)]
  bindings: BTreeMap<String, String>,
  #[serde(default)]
  rule_overrides: Vec<RulepackOverride>,
  #[serde(default)]
  exceptions: Vec<RulepackException>,
  #[serde(default)]
  profile: Option<String>,
  #[serde(default)]
  mode: Option<WafMode>,
  #[serde(default)]
  force_mode: bool,
  #[serde(default)]
  include_route_candidates: bool,
  #[serde(default)]
  include_diff: bool,
  #[serde(default)]
  include_cost: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminRulepackPlanSource {
  url: String,
  sha256: String,
  #[serde(default)]
  openpgp_signature_url: Option<String>,
  #[serde(default)]
  openpgp_signer_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminRulepackPlanReport {
  ok: bool,
  rulepack: String,
  required_inputs: Vec<AdminRulepackRequiredInput>,
  route_candidates: Vec<AdminRulepackRouteCandidateSet>,
  #[serde(skip_serializing_if = "Option::is_none")]
  rendered_manifest: Option<String>,
  install_plan: AdminRulepackInstallPlan,
  #[serde(skip_serializing_if = "Option::is_none")]
  diff: Option<AdminRulepackDiff>,
  risk: AdminRulepackRisk,
  cost_warnings: Vec<String>,
  warnings: Vec<String>,
  permission_hints: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct AdminRulepackRequiredInput {
  name: String,
  #[serde(rename = "type")]
  input_type: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  prompt: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  description: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminRulepackRouteCandidateSet {
  binding: String,
  candidates: Vec<AdminRulepackRouteCandidate>,
}

#[derive(Debug, Serialize)]
struct AdminRulepackRouteCandidate {
  name: String,
  score: i64,
  reason: Vec<String>,
  hosts: Vec<String>,
  path_prefix: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  upstream: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminRulepackInstallPlan {
  ready: bool,
  will_put: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  will_reload: Option<&'static str>,
  mode: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  profile: Option<String>,
  bindings: BTreeMap<String, String>,
  values_count: usize,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_url: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_sha256: Option<String>,
  endpoint: &'static str,
}

#[derive(Debug, Serialize)]
struct AdminRulepackDiff {
  added_rules: i64,
  changed_rules: i64,
  deleted_rules: i64,
  basis: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  active_version: Option<String>,
  planned_version: String,
}

#[derive(Debug, Serialize)]
struct AdminRulepackRisk {
  terminal_actions: Vec<String>,
  body_inspection: bool,
  response_inspection: bool,
  estimated_cost: &'static str,
}

#[derive(Debug)]
struct AdminRulepackPrepared {
  name: String,
  summary: WafRulepackSummary,
  rendered_manifest: String,
  values: BTreeMap<String, String>,
  bindings: BTreeMap<String, String>,
  selected_profile: Option<String>,
  mode: WafMode,
  force_mode: bool,
  candidates: AdminRulepackCandidateSet,
}

#[derive(Debug)]
struct AdminRulepackCandidateSet {
  rules: Vec<AdminRulepackRuleCandidate>,
  groups: Vec<OxiRuleGroupCandidate>,
}

#[derive(Debug)]
struct AdminRulepackRuleCandidate {
  name: String,
  content: String,
  body: OxiRuleCandidate,
}

#[derive(Debug)]
struct RouteInventory {
  name: String,
  hosts: Vec<String>,
  path_prefix: String,
  upstream: Option<String>,
  upstream_text: Vec<String>,
}

struct ResolvedPlanInputs {
  values: BTreeMap<String, String>,
  bindings: BTreeMap<String, String>,
  render_vars: BTreeMap<String, String>,
  selected_profile: Option<String>,
  mode: WafMode,
}

fn plan_rulepack(
  config: &Config,
  request: AdminRulepackPlanRequest,
) -> anyhow::Result<AdminRulepackPlanReport> {
  let source = "Admin rulepack plan manifest";
  let include_route_candidates = request.include_route_candidates;
  let include_diff = request.include_diff;
  let include_cost = request.include_cost;
  let inputs = inspect_rulepack_inputs(&request.manifest, source)?;
  let resolved = resolve_plan_inputs(&inputs, &request)?;
  let route_candidates = if include_route_candidates {
    route_candidates(config, &inputs)
  } else {
    Vec::new()
  };
  let required_inputs = required_inputs(&inputs, &resolved.values, &resolved.bindings);
  let mut warnings = route_warnings(&inputs, &route_candidates);
  if !required_inputs.is_empty() {
    warnings.push("rulepack plan is incomplete until required inputs are supplied".to_string());
    return Ok(AdminRulepackPlanReport {
      ok: false,
      rulepack: inputs.summary.name,
      required_inputs,
      route_candidates,
      rendered_manifest: None,
      install_plan: incomplete_install_plan(&request, &resolved),
      diff: None,
      risk: unknown_risk(),
      cost_warnings: Vec::new(),
      warnings,
      permission_hints: permission_hints(),
    });
  }

  let raw_manifest = request.manifest.clone();
  let prepared = prepare_rulepack(&raw_manifest, request, resolved)?;
  let active = if include_diff {
    active_rulepack_summaries(config)
      .into_iter()
      .find(|summary| summary.name == prepared.name)
  } else {
    None
  };
  let diff = if include_diff {
    Some(diff_for_summary(&prepared.summary, active.as_ref()))
  } else {
    None
  };
  warnings.extend(install_warnings(&prepared, active.as_ref()));
  let mut risk = static_risk(&prepared.candidates);
  let mut cost_warnings = Vec::new();
  if prepared.candidates.rules.is_empty() && prepared.summary.group_files > 0 {
    warnings.push("rulepack contains only group files; rule risk is empty".to_string());
  }
  if prepared.summary.rules > 32 {
    risk.estimated_cost = "medium";
  }
  if include_cost {
    augment_risk_with_cost(
      config,
      &prepared,
      &mut risk,
      &mut cost_warnings,
      &mut warnings,
    );
  }

  Ok(AdminRulepackPlanReport {
    ok: true,
    rulepack: prepared.name.clone(),
    required_inputs: Vec::new(),
    route_candidates,
    rendered_manifest: Some(prepared.rendered_manifest.clone()),
    install_plan: complete_install_plan(&prepared),
    diff,
    risk,
    cost_warnings,
    warnings,
    permission_hints: permission_hints(),
  })
}

fn resolve_plan_inputs(
  inputs: &RulepackInputMetadata,
  request: &AdminRulepackPlanRequest,
) -> anyhow::Result<ResolvedPlanInputs> {
  validate_rulepack_overrides(
    "Admin rulepack plan manifest",
    &inputs.summary.name,
    &request.rule_overrides,
  )?;
  validate_rulepack_exception_list("Admin rulepack plan manifest", &request.exceptions)?;
  let profile = request
    .profile
    .as_deref()
    .map(|name| {
      inputs
        .profiles
        .iter()
        .find(|profile| profile.name == name)
        .with_context(|| {
          format!(
            "rulepack {} does not declare profile {name}",
            inputs.summary.name
          )
        })
    })
    .transpose()?;
  let mut values = profile
    .map(|profile| profile.values.clone())
    .unwrap_or_default();
  values.extend(request.values.clone());

  validate_value_keys(inputs, &values)?;
  validate_binding_keys(inputs, &request.bindings)?;
  let mut render_vars = values.clone();
  for binding in &inputs.bindings {
    if let Some(value) = request.bindings.get(&binding.name) {
      if let Some(existing) = render_vars.get(&binding.bind_as)
        && existing != value
      {
        bail!(
          "binding {} conflicts with variable {}",
          binding.name,
          binding.bind_as
        );
      }
      render_vars.insert(binding.bind_as.clone(), value.clone());
    }
  }
  validate_render_values(inputs, &values)?;
  Ok(ResolvedPlanInputs {
    values,
    bindings: request.bindings.clone(),
    render_vars,
    selected_profile: request.profile.clone(),
    mode: request
      .mode
      .or_else(|| profile.and_then(|profile| profile.mode))
      .unwrap_or(WafMode::Monitor),
  })
}

fn validate_value_keys(
  inputs: &RulepackInputMetadata,
  values: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
  let variables = inputs
    .variables
    .iter()
    .map(|variable| variable.name.as_str())
    .collect::<BTreeSet<_>>();
  for key in values.keys() {
    if !variables.contains(key.as_str()) {
      bail!(
        "rulepack {} does not declare variable {key}",
        inputs.summary.name
      );
    }
  }
  Ok(())
}

fn validate_binding_keys(
  inputs: &RulepackInputMetadata,
  bindings: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
  let declared = inputs
    .bindings
    .iter()
    .map(|binding| binding.name.as_str())
    .collect::<BTreeSet<_>>();
  for key in bindings.keys() {
    if !declared.contains(key.as_str()) {
      bail!(
        "rulepack {} does not declare binding {key}",
        inputs.summary.name
      );
    }
  }
  Ok(())
}

fn validate_render_values(
  inputs: &RulepackInputMetadata,
  values: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
  for variable in &inputs.variables {
    let Some(value) = values.get(&variable.name) else {
      continue;
    };
    match variable.value_type.as_deref() {
      Some("cidr") => {
        Cidr::parse(value).with_context(|| {
          format!(
            "rulepack {} variable {} must be a valid CIDR",
            inputs.summary.name, variable.name
          )
        })?;
      }
      Some("rate") => {
        parse_rate(value).with_context(|| {
          format!(
            "rulepack {} variable {} must be a valid rate",
            inputs.summary.name, variable.name
          )
        })?;
      }
      Some("string") | None => {}
      Some(other) => bail!(
        "rulepack {} variable {} uses unsupported type {}",
        inputs.summary.name,
        variable.name,
        other
      ),
    }
  }
  Ok(())
}

fn required_inputs(
  inputs: &RulepackInputMetadata,
  values: &BTreeMap<String, String>,
  bindings: &BTreeMap<String, String>,
) -> Vec<AdminRulepackRequiredInput> {
  inputs
    .bindings
    .iter()
    .filter(|binding| binding.required && !bindings.contains_key(&binding.name))
    .map(|binding| AdminRulepackRequiredInput {
      name: binding.name.clone(),
      input_type: binding_kind_name(binding.kind).to_string(),
      prompt: binding.prompt.clone(),
      description: binding.description.clone(),
    })
    .chain(
      inputs
        .variables
        .iter()
        .filter(|variable| {
          variable.required && variable.default.is_none() && !values.contains_key(&variable.name)
        })
        .map(|variable| AdminRulepackRequiredInput {
          name: variable.name.clone(),
          input_type: variable
            .value_type
            .clone()
            .unwrap_or_else(|| "string".to_string()),
          prompt: variable.prompt.clone(),
          description: variable.description.clone(),
        }),
    )
    .collect()
}

fn prepare_rulepack(
  raw: &str,
  request: AdminRulepackPlanRequest,
  resolved: ResolvedPlanInputs,
) -> anyhow::Result<AdminRulepackPrepared> {
  let source = "Admin rulepack plan manifest";
  let source_provenance = request
    .source
    .as_ref()
    .map(|source| RulepackSourceProvenance {
      source_url: source.url.clone(),
      source_sha256: source.sha256.clone(),
      source_openpgp_signature_url: source.openpgp_signature_url.clone(),
      source_openpgp_signer_fingerprint: source.openpgp_signer_fingerprint.clone(),
    });
  let options = RulepackRenderOptions {
    variables: resolved.render_vars,
    local_overrides: request.rule_overrides,
    local_exceptions: request.exceptions,
    mode_override: Some(RulepackModeOverride {
      mode: resolved.mode,
      force: request.force_mode,
    }),
    source_commit: None,
    source_provenance,
    pin_variables: false,
  };
  if !referenced_rulepack_files(raw, source, options.clone())?.is_empty() {
    bail!("Admin rulepack plan requires embedded rule and group content");
  }
  let rendered_manifest = render_rulepack_for_install(raw, source, options)?;
  let inspection = inspect_rulepack(&rendered_manifest, source, RulepackRenderOptions::default())?;
  let candidates = candidate_set(&rendered_manifest)?;
  Ok(AdminRulepackPrepared {
    name: inspection.summary.name.clone(),
    summary: inspection.summary,
    rendered_manifest,
    values: resolved.values,
    bindings: resolved.bindings,
    selected_profile: resolved.selected_profile,
    mode: resolved.mode,
    force_mode: request.force_mode,
    candidates,
  })
}

fn incomplete_install_plan(
  request: &AdminRulepackPlanRequest,
  resolved: &ResolvedPlanInputs,
) -> AdminRulepackInstallPlan {
  AdminRulepackInstallPlan {
    ready: false,
    will_put: Vec::new(),
    will_reload: None,
    mode: mode_name(resolved.mode),
    profile: resolved.selected_profile.clone(),
    bindings: resolved.bindings.clone(),
    values_count: resolved.values.len(),
    source_url: request.source.as_ref().map(|source| source.url.clone()),
    source_sha256: request.source.as_ref().map(|source| source.sha256.clone()),
    endpoint: "/admin/v1/files/sync",
  }
}

fn complete_install_plan(prepared: &AdminRulepackPrepared) -> AdminRulepackInstallPlan {
  AdminRulepackInstallPlan {
    ready: true,
    will_put: vec![
      installed_rulepack_path(&prepared.name),
      installed_rulepack_lock_path(&prepared.name),
    ],
    will_reload: Some("oxirule"),
    mode: mode_name(prepared.mode),
    profile: prepared.selected_profile.clone(),
    bindings: prepared.bindings.clone(),
    values_count: prepared.values.len(),
    source_url: prepared.summary.source_url.clone(),
    source_sha256: prepared.summary.source_sha256.clone(),
    endpoint: "/admin/v1/files/sync",
  }
}

fn diff_for_summary(
  planned: &WafRulepackSummary,
  active: Option<&WafRulepackSummary>,
) -> AdminRulepackDiff {
  let Some(active) = active else {
    return AdminRulepackDiff {
      added_rules: planned.rules as i64,
      changed_rules: 0,
      deleted_rules: 0,
      basis: "new_install",
      active_version: None,
      planned_version: planned.version.clone(),
    };
  };
  let changed_rules = if active.version == planned.version && active.rules == planned.rules {
    0
  } else {
    active.rules.min(planned.rules) as i64
  };
  AdminRulepackDiff {
    added_rules: planned.rules.saturating_sub(active.rules) as i64,
    changed_rules,
    deleted_rules: active.rules.saturating_sub(planned.rules) as i64,
    basis: "active_summary",
    active_version: Some(active.version.clone()),
    planned_version: planned.version.clone(),
  }
}

fn install_warnings(
  prepared: &AdminRulepackPrepared,
  active: Option<&WafRulepackSummary>,
) -> Vec<String> {
  let mut warnings = Vec::new();
  if !prepared.bindings.is_empty() {
    warnings.push(
      "rulepack is installed globally; rendered route conditions should limit execution to selected bindings"
        .to_string(),
    );
  }
  if prepared.mode == WafMode::Monitor {
    warnings
      .push("WAF mode is monitor; terminal actions will not block until enforcing".to_string());
  }
  if prepared.force_mode {
    warnings.push("force_mode pins every rendered rule to the effective mode".to_string());
  }
  if active.is_some() {
    warnings.push("existing active rulepack with the same name will be replaced".to_string());
  }
  warnings
}

fn installed_rulepack_path(name: &str) -> String {
  format!("rulepacks/{name}{RULEPACK_FILE_SUFFIX}")
}

fn installed_rulepack_lock_path(name: &str) -> String {
  format!("rulepacks/{name}.install.toml")
}

fn permission_hints() -> Vec<&'static str> {
  vec!["waf:PutOxiRulePack", "waf:ReloadOxiRule"]
}

fn binding_kind_name(kind: RulepackBindingKind) -> &'static str {
  match kind {
    RulepackBindingKind::Route => "route",
  }
}

fn parse_waf_mode(value: &str) -> anyhow::Result<WafMode> {
  match value {
    "monitor" => Ok(WafMode::Monitor),
    "enforcing" => Ok(WafMode::Enforcing),
    other => bail!("unsupported mode {other}"),
  }
}

fn parse_waf_phase(value: &str) -> anyhow::Result<WafPhase> {
  match value {
    "request" => Ok(WafPhase::Request),
    "response" => Ok(WafPhase::Response),
    "stream" => Ok(WafPhase::Stream),
    other => bail!("unsupported phase {other}"),
  }
}

fn mode_name(mode: WafMode) -> &'static str {
  match mode {
    WafMode::Monitor => "monitor",
    WafMode::Enforcing => "enforcing",
  }
}
