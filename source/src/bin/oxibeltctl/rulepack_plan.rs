#[path = "rulepack_plan_risk.rs"]
mod risk;

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, bail};
use http::{Method, StatusCode};
use oxibelt::admin_client::AdminClient;
use oxibelt::waf::{
  RulepackReferencedFileKind, RulepackRenderOptions, WafRulepackSummary, inspect_rulepack,
  referenced_rulepack_files, render_rulepack_for_install,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::{
  OutputFormat, RulepackApplyArgs, RulepackDiffArgs, RulepackModeArg, RulepackPlanArgs,
  RulepackSourceArgs,
};
use crate::rulepack::LoadedRulepackSource;
use crate::rulepack_install::{
  RulepackInstallLockInput, installed_rulepack_lock_path, installed_rulepack_path,
  render_install_lock,
};
use crate::rulepack_prompt::InteractiveApplyRequest;
use crate::rulepack_render::{render_options, render_text};
use risk::{RulepackRisk, augment_risk_with_devtools, risk_for_prepared};

#[derive(Debug)]
pub(crate) struct PreparedRulepackApply {
  pub(crate) name: String,
  pub(crate) request_body: Value,
  summary: WafRulepackSummary,
  source_label: String,
  git_commit: Option<String>,
  selected_profile: Option<String>,
  effective_mode: RulepackModeArg,
  force_mode: bool,
  bindings: BTreeMap<String, String>,
  values: BTreeMap<String, String>,
  rendered_manifest: String,
  rendered_rule_files: BTreeMap<String, String>,
  rendered_group_files: BTreeMap<String, String>,
  will_put: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RulepackPreinstallReport {
  rulepack: String,
  view: &'static str,
  install_plan: RulepackInstallPlan,
  diff: Option<RulepackDiff>,
  risk: RulepackRisk,
  warnings: Vec<String>,
  route_candidates: Vec<crate::rulepack_fit::RouteCandidateSet>,
  missing_bindings: Vec<String>,
  missing_variables: Vec<String>,
  suggested_command: String,
}

#[derive(Debug, Serialize)]
struct RulepackInstallPlan {
  ready: bool,
  will_put: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  will_reload: Option<&'static str>,
  mode: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  profile: Option<String>,
  bindings: BTreeMap<String, String>,
  values_count: usize,
  source: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_commit: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_url: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_sha256: Option<String>,
  endpoint: &'static str,
}

#[derive(Debug, Serialize)]
struct RulepackDiff {
  added_rules: i64,
  #[serde(skip_serializing_if = "Option::is_none")]
  changed_rules: Option<i64>,
  deleted_rules: i64,
  basis: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  active_version: Option<String>,
  planned_version: String,
}

#[derive(Debug)]
struct RulepackReportContext<'a> {
  source: &'a RulepackSourceArgs,
  values: Option<&'a Path>,
  vars: &'a [String],
  binds: &'a [String],
  profile: Option<&'a str>,
  mode: Option<RulepackModeArg>,
  force_mode: bool,
  fixture: Option<&'a Path>,
  replay: Option<&'a Path>,
  view: &'static str,
}

#[derive(Debug)]
struct ActiveRulepackSummary {
  version: Option<String>,
  rules: usize,
}

struct RulepackPrepareInputs<'a> {
  selected_profile: Option<&'a str>,
  effective_mode: RulepackModeArg,
  force_mode: bool,
  vars: &'a BTreeMap<String, String>,
  binds: &'a BTreeMap<String, String>,
  rule_overrides: &'a [oxibelt::waf::RulepackOverride],
  exceptions: &'a [oxibelt::waf::RulepackException],
}

pub(crate) async fn print_plan(
  client: &AdminClient,
  args: &RulepackPlanArgs,
  output: OutputFormat,
) -> anyhow::Result<()> {
  let report = build_report(
    client,
    RulepackReportContext {
      source: &args.source,
      values: args.values.as_deref(),
      vars: &args.vars,
      binds: &args.binds,
      profile: args.profile.as_deref(),
      mode: args.mode,
      force_mode: args.force_mode,
      fixture: None,
      replay: None,
      view: "plan",
    },
  )
  .await?;
  print_report(&report, output)
}

pub(crate) async fn print_diff(
  client: &AdminClient,
  args: &RulepackDiffArgs,
  output: OutputFormat,
) -> anyhow::Result<()> {
  let report = build_report(
    client,
    RulepackReportContext {
      source: &args.source,
      values: args.values.as_deref(),
      vars: &args.vars,
      binds: &args.binds,
      profile: args.profile.as_deref(),
      mode: args.mode,
      force_mode: args.force_mode,
      fixture: None,
      replay: None,
      view: "diff",
    },
  )
  .await?;
  print_report(&report, output)
}

pub(crate) async fn print_apply_dry_run(
  client: &AdminClient,
  args: &RulepackApplyArgs,
  output: OutputFormat,
) -> anyhow::Result<()> {
  if !args.interactive {
    let report = build_report(
      client,
      RulepackReportContext {
        source: &args.source,
        values: args.values.as_deref(),
        vars: &args.vars,
        binds: &args.binds,
        profile: args.profile.as_deref(),
        mode: args.mode,
        force_mode: args.force_mode,
        fixture: args.fixture.as_deref(),
        replay: args.replay.as_deref(),
        view: "apply_dry_run",
      },
    )
    .await?;
    return print_report(&report, output);
  }
  let prepared = prepare_rulepack_apply(client, args, false).await?;
  let report = build_report_from_prepared(
    client,
    &prepared,
    None,
    Vec::new(),
    args.fixture.as_deref(),
    args.replay.as_deref(),
    "apply_dry_run",
  )
  .await?;
  print_report(&report, output)
}

pub(crate) async fn prepare_rulepack_apply(
  client: &AdminClient,
  args: &RulepackApplyArgs,
  confirm_interactive_apply: bool,
) -> anyhow::Result<PreparedRulepackApply> {
  let loaded = crate::rulepack::load_rulepack_source(&args.source, client.timeout(), true).await?;
  let cli_vars = crate::rulepack_fit::parse_key_values(&args.vars, "--var")?;
  let cli_binds = crate::rulepack_fit::parse_key_values(&args.binds, "--bind")?;
  let resolved = crate::rulepack_values::resolve_rulepack_inputs(
    crate::rulepack_values::RulepackResolveRequest {
      raw: &loaded.manifest,
      source: &loaded.source_label,
      values_file: args.values.as_deref(),
      cli_vars: &cli_vars,
      cli_binds: &cli_binds,
      cli_profile: args.profile.as_deref(),
      cli_mode: args.mode,
      cli_force_mode: args.force_mode,
      default_mode: Some(RulepackModeArg::Monitor),
    },
  )?;
  let mut vars = resolved.vars.clone();
  let mut binds = resolved.binds.clone();
  let effective_mode = resolved.mode.unwrap_or(RulepackModeArg::Monitor);
  if args.interactive {
    crate::rulepack_prompt::complete_interactive_apply(
      client,
      InteractiveApplyRequest {
        loaded: &loaded,
        source_args: &args.source,
        vars: &mut vars,
        binds: &mut binds,
        mode: effective_mode,
        force_mode: resolved.force_mode,
        confirm_apply: confirm_interactive_apply,
      },
    )
    .await?;
  }
  prepare_loaded_rulepack(
    &loaded,
    RulepackPrepareInputs {
      selected_profile: resolved.selected_profile.as_deref(),
      effective_mode,
      force_mode: resolved.force_mode,
      vars: &vars,
      binds: &binds,
      rule_overrides: &resolved.rule_overrides,
      exceptions: &resolved.exceptions,
    },
  )
}

async fn build_report(
  client: &AdminClient,
  context: RulepackReportContext<'_>,
) -> anyhow::Result<RulepackPreinstallReport> {
  let loaded =
    crate::rulepack::load_rulepack_source(context.source, client.timeout(), true).await?;
  let cli_vars = crate::rulepack_fit::parse_key_values(context.vars, "--var")?;
  let cli_binds = crate::rulepack_fit::parse_key_values(context.binds, "--bind")?;
  let resolved = crate::rulepack_values::resolve_rulepack_inputs(
    crate::rulepack_values::RulepackResolveRequest {
      raw: &loaded.manifest,
      source: &loaded.source_label,
      values_file: context.values,
      cli_vars: &cli_vars,
      cli_binds: &cli_binds,
      cli_profile: context.profile,
      cli_mode: context.mode,
      cli_force_mode: context.force_mode,
      default_mode: Some(RulepackModeArg::Monitor),
    },
  )?;
  let evaluation = crate::rulepack_fit::evaluate_fit(
    client,
    &loaded,
    context.source,
    crate::rulepack_fit::RulepackFitOptions {
      vars: &resolved.vars,
      binds: &resolved.binds,
      command_vars: &cli_vars,
      command_binds: &cli_binds,
      values_file: resolved.values_file.as_deref(),
      profile_arg: context.profile,
      mode: resolved.mode,
      force_mode: resolved.force_mode,
    },
  )
  .await?;
  if !evaluation.report.missing_bindings.is_empty()
    || !evaluation.report.missing_variables.is_empty()
  {
    let mut warnings = evaluation.report.warnings.clone();
    warnings.push("rulepack plan is incomplete until required inputs are supplied".to_string());
    return Ok(incomplete_report(
      context.view,
      &loaded,
      resolved.mode.unwrap_or(RulepackModeArg::Monitor),
      resolved.selected_profile,
      &resolved.binds,
      warnings,
      evaluation.report,
    ));
  }
  let prepared = prepare_loaded_rulepack(
    &loaded,
    RulepackPrepareInputs {
      selected_profile: resolved.selected_profile.as_deref(),
      effective_mode: resolved.mode.unwrap_or(RulepackModeArg::Monitor),
      force_mode: resolved.force_mode,
      vars: &resolved.vars,
      binds: &resolved.binds,
      rule_overrides: &resolved.rule_overrides,
      exceptions: &resolved.exceptions,
    },
  )?;
  build_report_from_prepared(
    client,
    &prepared,
    Some(evaluation.report),
    Vec::new(),
    context.fixture,
    context.replay,
    context.view,
  )
  .await
}

fn prepare_loaded_rulepack(
  loaded: &LoadedRulepackSource,
  inputs: RulepackPrepareInputs<'_>,
) -> anyhow::Result<PreparedRulepackApply> {
  let render_vars = crate::rulepack_fit::resolve_render_variables(
    &loaded.manifest,
    &loaded.source_label,
    inputs.vars,
    inputs.binds,
    true,
  )?;
  let options = render_options(
    render_vars.clone(),
    inputs.rule_overrides.to_vec(),
    inputs.exceptions.to_vec(),
    Some(inputs.effective_mode),
    inputs.force_mode,
    loaded.git_commit.clone(),
    loaded.source_provenance.clone(),
  );
  let rendered_manifest =
    render_rulepack_for_install(&loaded.manifest, &loaded.source_label, options.clone())?;
  let inspection = inspect_rulepack(
    &rendered_manifest,
    &loaded.source_label,
    RulepackRenderOptions::default(),
  )?;
  let name = inspection.summary.name.clone();
  let mut operations = Vec::new();
  let mut rendered_rule_files = BTreeMap::new();
  let mut rendered_group_files = BTreeMap::new();
  for referenced in referenced_rulepack_files(&loaded.manifest, &loaded.source_label, options)? {
    let Some(base_dir) = loaded.base_dir.as_deref() else {
      bail!("remote single-file rulepacks must embed rule and group content");
    };
    let path = crate::rulepack::resolve_existing_local_source_file(base_dir, &referenced.path)?;
    let raw = std::fs::read_to_string(&path)
      .with_context(|| format!("failed to read referenced rulepack file {}", path.display()))?;
    let rendered = render_text(&raw, &render_vars);
    let root = match referenced.kind {
      RulepackReferencedFileKind::Rule => {
        rendered_rule_files.insert(
          referenced.path.to_string_lossy().to_string(),
          rendered.clone(),
        );
        "oxirule"
      }
      RulepackReferencedFileKind::Group => {
        rendered_group_files.insert(
          referenced.path.to_string_lossy().to_string(),
          rendered.clone(),
        );
        "oxirule_group"
      }
    };
    operations.push(json!({
      "op": "put",
      "root": root,
      "path": referenced.path.to_string_lossy(),
      "content": rendered,
    }));
  }
  let installed_path = installed_rulepack_path(&name)?;
  operations.push(json!({
    "op": "put",
    "root": "oxirule_rulepack",
    "path": installed_path,
    "content": rendered_manifest,
  }));
  let input_metadata =
    oxibelt::waf::inspect_rulepack_inputs(&loaded.manifest, &loaded.source_label)?;
  let lock_values = input_metadata
    .variables
    .iter()
    .filter_map(|variable| {
      render_vars
        .get(&variable.name)
        .map(|value| (variable.name.clone(), value.clone()))
    })
    .collect::<BTreeMap<_, _>>();
  let lock_path = installed_rulepack_lock_path(&name)?;
  operations.push(json!({
    "op": "put",
    "root": "oxirule_rulepack_install",
    "path": lock_path,
    "content": render_install_lock(RulepackInstallLockInput {
      name: &name,
      version: &inspection.summary.version,
      source: &loaded.source_label,
      source_commit: loaded.git_commit.as_deref(),
      source_provenance: loaded.source_provenance.as_ref(),
      selected_profile: inputs.selected_profile,
      effective_mode: inputs.effective_mode,
      force_mode: inputs.force_mode,
      bindings: inputs.binds,
      values: &lock_values,
      rule_overrides: inputs.rule_overrides,
      exceptions: inputs.exceptions,
    })?,
  }));
  let will_put = operations
    .iter()
    .filter(|operation| operation.get("op").and_then(Value::as_str) == Some("put"))
    .filter_map(|operation| {
      operation
        .get("path")
        .and_then(Value::as_str)
        .map(str::to_string)
    })
    .collect::<Vec<_>>();
  Ok(PreparedRulepackApply {
    name,
    request_body: json!({ "apply": "oxirule", "operations": operations }),
    summary: inspection.summary,
    source_label: loaded.source_label.clone(),
    git_commit: loaded.git_commit.clone(),
    selected_profile: inputs.selected_profile.map(str::to_string),
    effective_mode: inputs.effective_mode,
    force_mode: inputs.force_mode,
    bindings: inputs.binds.clone(),
    values: lock_values,
    rendered_manifest,
    rendered_rule_files,
    rendered_group_files,
    will_put,
  })
}

async fn build_report_from_prepared(
  client: &AdminClient,
  prepared: &PreparedRulepackApply,
  fit_report: Option<crate::rulepack_fit::RulepackFitReport>,
  mut warnings: Vec<String>,
  fixture: Option<&Path>,
  replay: Option<&Path>,
  view: &'static str,
) -> anyhow::Result<RulepackPreinstallReport> {
  let active = match active_rulepack_summary(client, &prepared.name).await {
    Ok(active) => active,
    Err(error) => {
      warnings.push(format!("active rulepack diff unavailable: {error:#}"));
      None
    }
  };
  let diff = Some(diff_for_summary(
    &prepared.summary,
    active.as_ref(),
    &mut warnings,
  ));
  warnings.extend(install_warnings(prepared, active.as_ref()));
  let mut risk = risk_for_prepared(prepared)?;
  augment_risk_with_devtools(client, prepared, &mut risk, fixture, replay, &mut warnings).await?;
  let fit_report = fit_report.unwrap_or_else(|| empty_fit_report(&prepared.name));
  Ok(RulepackPreinstallReport {
    rulepack: prepared.name.clone(),
    view,
    install_plan: complete_install_plan(prepared),
    diff,
    risk,
    warnings,
    route_candidates: fit_report.route_candidates,
    missing_bindings: fit_report.missing_bindings,
    missing_variables: fit_report.missing_variables,
    suggested_command: fit_report.suggested_command,
  })
}

fn incomplete_report(
  view: &'static str,
  loaded: &LoadedRulepackSource,
  mode: RulepackModeArg,
  selected_profile: Option<String>,
  bindings: &BTreeMap<String, String>,
  warnings: Vec<String>,
  fit_report: crate::rulepack_fit::RulepackFitReport,
) -> RulepackPreinstallReport {
  RulepackPreinstallReport {
    rulepack: fit_report.rulepack.clone(),
    view,
    install_plan: RulepackInstallPlan {
      ready: false,
      will_put: Vec::new(),
      will_reload: None,
      mode: mode_name(mode),
      profile: selected_profile,
      bindings: bindings.clone(),
      values_count: 0,
      source: loaded.source_label.clone(),
      source_commit: loaded.git_commit.clone(),
      source_url: loaded
        .source_provenance
        .as_ref()
        .map(|provenance| provenance.source_url.clone()),
      source_sha256: loaded
        .source_provenance
        .as_ref()
        .map(|provenance| provenance.source_sha256.clone()),
      endpoint: "/admin/v1/files/sync",
    },
    diff: None,
    risk: RulepackRisk::unknown(),
    warnings,
    route_candidates: fit_report.route_candidates,
    missing_bindings: fit_report.missing_bindings,
    missing_variables: fit_report.missing_variables,
    suggested_command: fit_report.suggested_command,
  }
}

fn complete_install_plan(prepared: &PreparedRulepackApply) -> RulepackInstallPlan {
  RulepackInstallPlan {
    ready: true,
    will_put: prepared.will_put.clone(),
    will_reload: Some("oxirule"),
    mode: mode_name(prepared.effective_mode),
    profile: prepared.selected_profile.clone(),
    bindings: prepared.bindings.clone(),
    values_count: prepared.values.len(),
    source: prepared.source_label.clone(),
    source_commit: prepared.git_commit.clone(),
    source_url: prepared.summary.source_url.clone(),
    source_sha256: prepared.summary.source_sha256.clone(),
    endpoint: "/admin/v1/files/sync",
  }
}

fn diff_for_summary(
  planned: &WafRulepackSummary,
  active: Option<&ActiveRulepackSummary>,
  warnings: &mut Vec<String>,
) -> RulepackDiff {
  let Some(active) = active else {
    return RulepackDiff {
      added_rules: planned.rules as i64,
      changed_rules: Some(0),
      deleted_rules: 0,
      basis: "new_install",
      active_version: None,
      planned_version: planned.version.clone(),
    };
  };
  warnings.push(
    "content-level changed-rule diff requires a future Admin manifest-read or rulepack-plan endpoint"
      .to_string(),
  );
  RulepackDiff {
    added_rules: planned.rules.saturating_sub(active.rules) as i64,
    changed_rules: None,
    deleted_rules: active.rules.saturating_sub(planned.rules) as i64,
    basis: "active_summary",
    active_version: active.version.clone(),
    planned_version: planned.version.clone(),
  }
}

fn install_warnings(
  prepared: &PreparedRulepackApply,
  active: Option<&ActiveRulepackSummary>,
) -> Vec<String> {
  let mut warnings = Vec::new();
  if !prepared.bindings.is_empty() {
    warnings.push(
      "rulepack is installed globally; rendered route conditions should limit execution to selected bindings"
        .to_string(),
    );
  }
  if prepared.effective_mode == RulepackModeArg::Monitor {
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

async fn active_rulepack_summary(
  client: &AdminClient,
  name: &str,
) -> anyhow::Result<Option<ActiveRulepackSummary>> {
  let response = client
    .request_json(Method::GET, "/admin/v1/waf/rulepacks", None, None)
    .await?;
  if response.status == StatusCode::FORBIDDEN {
    bail!("Admin request failed with {}", response.status);
  }
  if !response.status.is_success() {
    bail!("failed to fetch active rulepacks: {}", response.status);
  }
  let value: Value =
    serde_json::from_slice(&response.body).context("rulepack list response was not JSON")?;
  Ok(
    value
      .get("rulepacks")
      .and_then(Value::as_array)
      .into_iter()
      .flatten()
      .find(|entry| entry.get("name").and_then(Value::as_str) == Some(name))
      .map(|entry| ActiveRulepackSummary {
        version: entry
          .get("version")
          .and_then(Value::as_str)
          .map(str::to_string),
        rules: entry.get("rules").and_then(Value::as_u64).unwrap_or(0) as usize,
      }),
  )
}

fn empty_fit_report(name: &str) -> crate::rulepack_fit::RulepackFitReport {
  crate::rulepack_fit::RulepackFitReport {
    rulepack: name.to_string(),
    required_bindings: Vec::new(),
    missing_bindings: Vec::new(),
    route_candidates: Vec::new(),
    missing_variables: Vec::new(),
    resolved_bindings: BTreeMap::new(),
    warnings: Vec::new(),
    suggested_command: String::new(),
  }
}

fn print_report(report: &RulepackPreinstallReport, output: OutputFormat) -> anyhow::Result<()> {
  match output {
    OutputFormat::PrettyJson => println!("{}", serde_json::to_string_pretty(report)?),
    OutputFormat::Json => println!("{}", serde_json::to_string(report)?),
  }
  Ok(())
}

fn mode_name(mode: RulepackModeArg) -> &'static str {
  match mode {
    RulepackModeArg::Monitor => "monitor",
    RulepackModeArg::Enforcing => "enforcing",
  }
}

#[cfg(test)]
#[path = "rulepack_plan_tests.rs"]
mod tests;
