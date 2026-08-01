use std::path::Path;

use anyhow::Context;
use http::Method;
use oxibelt::activation_plan::{ConfigActivationReport, PlanningBasis};
use oxibelt::admin_client::AdminResponse;
use oxibelt::config::load_native_config_document;
use serde_json::{Value, json};

use crate::cli::{Command, ConfigPlanOutputFormat, ConfigSubcommand};
use crate::plan::{PermissionHint, RequestPlan, ResponseFilter};

pub(crate) enum ConfigPlanDispatch {
  NotRequested,
  Complete(i32),
  Online(PreparedOnlinePlan),
}

pub(crate) struct PreparedOnlinePlan {
  candidate_toml: String,
  format: ConfigPlanOutputFormat,
}

pub(crate) fn prepare_if_requested(command: &Command) -> anyhow::Result<ConfigPlanDispatch> {
  let Command::Config(config) = command else {
    return Ok(ConfigPlanDispatch::NotRequested);
  };
  let ConfigSubcommand::Plan(args) = &config.command else {
    return Ok(ConfigPlanDispatch::NotRequested);
  };

  if let Some(current) = args.current.as_deref() {
    let report = match plan_offline(current, &args.candidate) {
      Ok(report) => report,
      Err(_error) => {
        eprintln!("current or candidate configuration could not be loaded or validated");
        ConfigActivationReport::invalid_configuration(PlanningBasis::OfflineConfig)
      }
    };
    let exit_code = if report.is_success() { 0 } else { 1 };
    let value = serde_json::to_value(&report)?;
    print_report(&value, args.format)?;
    return Ok(ConfigPlanDispatch::Complete(exit_code));
  }

  let candidate = match load_native_config_document(&args.candidate) {
    Ok(candidate) => candidate,
    Err(_error) => {
      eprintln!("candidate configuration could not be loaded or validated");
      let report = ConfigActivationReport::invalid_configuration(PlanningBasis::OnlineActive);
      let value = serde_json::to_value(report)?;
      print_report(&value, args.format)?;
      return Ok(ConfigPlanDispatch::Complete(1));
    }
  };
  let candidate_toml = toml::to_string(&candidate.value)
    .context("failed to serialize the merged candidate configuration")?;
  Ok(ConfigPlanDispatch::Online(PreparedOnlinePlan {
    candidate_toml,
    format: args.format,
  }))
}

fn plan_offline(current: &Path, candidate: &Path) -> anyhow::Result<ConfigActivationReport> {
  oxibelt::activation_plan::plan_config_files(current, candidate)
}

impl PreparedOnlinePlan {
  pub(crate) fn request_plan(&self) -> RequestPlan {
    RequestPlan {
      method: Method::POST,
      endpoint: "/admin/v1/config/diff".to_string(),
      body: Some(json!({
        "format": "toml",
        "config": self.candidate_toml,
      })),
      if_match: None,
      permission: PermissionHint::new("config:DiffSecrets", "*"),
      filter: ResponseFilter::None,
    }
  }

  pub(crate) fn finish(self, response: &AdminResponse) -> anyhow::Result<i32> {
    let value = serde_json::from_slice::<Value>(&response.body)
      .context("Admin configuration plan response was not JSON")?;
    print_report(&value, self.format)?;
    if response.status.is_success() {
      Ok(report_exit_code(&value))
    } else {
      Ok(1)
    }
  }
}

fn print_report(value: &Value, format: ConfigPlanOutputFormat) -> anyhow::Result<()> {
  let rendered = render_report(value, format)?;
  if rendered.ends_with('\n') {
    print!("{rendered}");
  } else {
    println!("{rendered}");
  }
  Ok(())
}

fn render_report(value: &Value, format: ConfigPlanOutputFormat) -> anyhow::Result<String> {
  match format {
    ConfigPlanOutputFormat::Json => serde_json::to_string_pretty(value).map_err(Into::into),
    ConfigPlanOutputFormat::Text => Ok(render_text_report(value)),
  }
}

fn render_text_report(value: &Value) -> String {
  if let Some(error) = value.get("error") {
    return render_error(error);
  }

  let report = activation_report(value);
  let plan = report.get("activation_plan").unwrap_or(report);
  let mut rendered = String::from("Configuration activation plan\n");
  push_scalar(
    &mut rendered,
    report,
    "activation_plan_schema_version",
    "schema version",
  );
  push_scalar(
    &mut rendered,
    report,
    "native_schema_epoch",
    "native schema epoch",
  );
  push_scalar(&mut rendered, report, "basis", "basis");
  push_scalar(&mut rendered, report, "ok", "valid");
  push_scalar(
    &mut rendered,
    plan,
    "minimum_required_operation",
    "minimum required operation",
  );
  push_scalar(
    &mut rendered,
    plan,
    "selected_operation",
    "selected operation",
  );
  push_scalar(
    &mut rendered,
    plan,
    "can_apply_in_process",
    "can apply in process",
  );
  push_scalar(&mut rendered, plan, "conditional", "conditional");

  let changes = report
    .get("changes")
    .or_else(|| value.get("changes"))
    .and_then(Value::as_array);
  match changes {
    Some(changes) => {
      rendered.push_str(&format!("changes: {}\n", changes.len()));
      for change in changes {
        render_change(&mut rendered, change);
      }
    }
    None => rendered.push_str("changes: unavailable\n"),
  }

  render_string_array(&mut rendered, plan, "reason_codes", "reason codes");
  render_prerequisites(&mut rendered, plan);
  rendered
}

fn render_error(error: &Value) -> String {
  let mut rendered = String::from("Configuration activation plan failed\n");
  push_scalar(&mut rendered, error, "code", "code");
  push_scalar(&mut rendered, error, "message", "message");
  rendered
}

fn push_scalar(rendered: &mut String, object: &Value, key: &str, label: &str) {
  let Some(value) = object.get(key) else {
    return;
  };
  let scalar = match value {
    Value::String(value) => value.clone(),
    Value::Bool(value) => value.to_string(),
    Value::Number(value) => value.to_string(),
    Value::Null | Value::Array(_) | Value::Object(_) => return,
  };
  rendered.push_str(label);
  rendered.push_str(": ");
  rendered.push_str(&scalar);
  rendered.push('\n');
}

fn render_change(rendered: &mut String, change: &Value) {
  let path = string_field(change, "path").unwrap_or("<unknown>");
  let operation = string_field(change, "op").unwrap_or("change");
  rendered.push_str("- ");
  rendered.push_str(path);
  rendered.push_str(": ");
  rendered.push_str(operation);
  for (key, label) in [
    ("native_activation", "native"),
    ("metadata_provenance", "metadata"),
    ("resolved_operation", "resolved"),
    ("reason_code", "reason"),
    ("rollback", "rollback"),
  ] {
    if let Some(value) = string_field(change, key) {
      rendered.push_str("; ");
      rendered.push_str(label);
      rendered.push('=');
      rendered.push_str(value);
    }
  }
  for (key, label) in [
    ("secret", "secret"),
    ("conditional", "conditional"),
    ("prerequisite_missing", "prerequisite_missing"),
    ("long_connections_affected", "long_connections_affected"),
  ] {
    if let Some(value) = change.get(key).and_then(Value::as_bool) {
      rendered.push_str("; ");
      rendered.push_str(label);
      rendered.push('=');
      rendered.push_str(if value { "true" } else { "false" });
    }
  }
  if let Some(prerequisites) = change
    .get("missing_prerequisites")
    .and_then(Value::as_array)
  {
    for prerequisite in prerequisites.iter().filter_map(Value::as_str) {
      rendered.push_str("; missing=");
      rendered.push_str(prerequisite);
    }
  }
  rendered.push('\n');
}

fn render_prerequisites(rendered: &mut String, plan: &Value) {
  let Some(prerequisites) = plan.get("prerequisites").and_then(Value::as_array) else {
    return;
  };
  rendered.push_str(&format!("prerequisites: {}\n", prerequisites.len()));
  for prerequisite in prerequisites {
    let name = prerequisite
      .as_str()
      .or_else(|| string_field(prerequisite, "name"))
      .or_else(|| string_field(prerequisite, "prerequisite"));
    let Some(name) = name else {
      continue;
    };
    rendered.push_str("- ");
    rendered.push_str(name);
    if let Some(availability) = string_field(prerequisite, "availability") {
      rendered.push_str(": ");
      rendered.push_str(availability);
    }
    rendered.push('\n');
  }
}

fn render_string_array(rendered: &mut String, object: &Value, key: &str, label: &str) {
  let Some(values) = object.get(key).and_then(Value::as_array) else {
    return;
  };
  rendered.push_str(&format!("{label}: {}\n", values.len()));
  for value in values.iter().filter_map(Value::as_str) {
    rendered.push_str("- ");
    rendered.push_str(value);
    rendered.push('\n');
  }
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
  value.get(key).and_then(Value::as_str)
}

fn activation_report(value: &Value) -> &Value {
  let Some(nested) = value.get("activation_plan") else {
    return value;
  };
  if nested.get("activation_plan_schema_version").is_some() {
    nested
  } else {
    value
  }
}

fn report_exit_code(value: &Value) -> i32 {
  let report = activation_report(value);
  let plan = report.get("activation_plan").unwrap_or(report);
  if value.get("ok").and_then(Value::as_bool) == Some(false)
    || report.get("ok").and_then(Value::as_bool) == Some(false)
    || plan.get("ok").and_then(Value::as_bool) == Some(false)
  {
    return 1;
  }
  let selected = plan
    .get("selected_operation")
    .and_then(Value::as_str)
    .unwrap_or_default();
  if matches!(
    selected,
    "invalid_or_unsupported" | "blocked_by_confinement"
  ) {
    1
  } else {
    0
  }
}

#[cfg(test)]
mod tests {
  use clap::Parser;

  use super::*;
  use crate::cli::{Cli, ConfigCommand};

  #[test]
  fn cli_requires_exactly_one_planning_source() {
    let missing = Cli::try_parse_from([
      "oxibeltctl",
      "config",
      "plan",
      "--candidate",
      "candidate.toml",
    ]);
    assert!(missing.is_err());

    let conflicting = Cli::try_parse_from([
      "oxibeltctl",
      "config",
      "plan",
      "--current",
      "current.toml",
      "--online",
      "--candidate",
      "candidate.toml",
    ]);
    assert!(conflicting.is_err());
  }

  #[test]
  fn cli_parses_offline_and_online_plans() {
    let offline = Cli::try_parse_from([
      "oxibeltctl",
      "config",
      "plan",
      "--current",
      "current.toml",
      "--candidate",
      "candidate.toml",
      "--format",
      "json",
    ])
    .expect("offline plan should parse");
    let Command::Config(ConfigCommand {
      command: ConfigSubcommand::Plan(offline),
    }) = offline.command
    else {
      panic!("expected config plan command");
    };
    assert_eq!(offline.current.as_deref(), Some(Path::new("current.toml")));
    assert!(!offline.online);
    assert_eq!(offline.format, ConfigPlanOutputFormat::Json);

    let online = Cli::try_parse_from([
      "oxibeltctl",
      "config",
      "plan",
      "--online",
      "--candidate",
      "candidate.toml",
    ])
    .expect("online plan should parse");
    let Command::Config(ConfigCommand {
      command: ConfigSubcommand::Plan(online),
    }) = online.command
    else {
      panic!("expected config plan command");
    };
    assert!(online.current.is_none());
    assert!(online.online);
    assert_eq!(online.format, ConfigPlanOutputFormat::Text);
  }

  #[test]
  fn text_report_has_stable_activation_summary() {
    let value = json!({
      "changes": [{
        "path": "waf.mode",
        "op": "change",
        "native_activation": "oxi_rule_reload",
        "resolved_operation": "oxi_rule_reload",
        "reason_code": "oxirule_changed",
        "secret": false,
        "conditional": false
      }],
      "activation_plan_schema_version": 1,
      "native_schema_epoch": 1,
      "basis": "online_active",
      "ok": true,
      "activation_plan": {
        "minimum_required_operation": "oxi_rule_reload",
        "selected_operation": "oxi_rule_reload",
        "can_apply_in_process": true,
        "conditional": false,
        "reason_codes": ["oxirule_changed"],
        "prerequisites": []
      }
    });
    assert_eq!(
      render_text_report(&value),
      "Configuration activation plan\n\
schema version: 1\n\
native schema epoch: 1\n\
basis: online_active\n\
valid: true\n\
minimum required operation: oxi_rule_reload\n\
selected operation: oxi_rule_reload\n\
can apply in process: true\n\
conditional: false\n\
changes: 1\n\
- waf.mode: change; native=oxi_rule_reload; resolved=oxi_rule_reload; reason=oxirule_changed; secret=false; conditional=false\n\
reason codes: 1\n\
- oxirule_changed\n\
prerequisites: 0\n"
    );
  }

  #[test]
  fn terminal_plans_exit_unsuccessfully() {
    assert_eq!(
      report_exit_code(&json!({"ok": true, "selected_operation": "process_restart"})),
      0
    );
    assert_eq!(
      report_exit_code(&json!({"ok": false, "selected_operation": "invalid_or_unsupported"})),
      1
    );
    assert_eq!(
      report_exit_code(&json!({"ok": true, "selected_operation": "blocked_by_confinement"})),
      1
    );
    assert_eq!(
      report_exit_code(&json!({
        "changes": [],
        "activation_plan": {
          "activation_plan_schema_version": 1,
          "native_schema_epoch": 1,
          "ok": false,
          "basis": "online_active",
          "changes": [],
          "activation_plan": {
            "selected_operation": "invalid_or_unsupported"
          }
        }
      })),
      1
    );
  }

  #[test]
  fn online_request_never_carries_mutation_authority() {
    let prepared = PreparedOnlinePlan {
      candidate_toml: "workers = 4\n".to_string(),
      format: ConfigPlanOutputFormat::Json,
    };
    let request = prepared.request_plan();
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.endpoint, "/admin/v1/config/diff");
    assert_eq!(request.permission.action, "config:DiffSecrets");
    assert!(request.if_match.is_none());
  }
}
