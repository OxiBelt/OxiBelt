use http::Method;
use oxibelt::admin_client::AdminResponse;
use oxibelt::config::{load_native_config_document, validate_native_config};
use serde_json::{Value, json};

use crate::cli::{Command, ConfigSubcommand, OutputFormat};
use crate::config_output::{
  NATIVE_SCHEMA_EPOCH, REPORT_SCHEMA_VERSION, error_report, print_serializable, report_ok,
};
use crate::plan::{PermissionHint, RequestPlan};

pub(crate) enum ValidationDispatch {
  NotRequested,
  Complete(i32),
  Remote(PreparedValidation),
}

pub(crate) struct PreparedValidation {
  local_report: Value,
  merged_toml: String,
}

pub(crate) fn prepare_if_requested(
  command: &Command,
  format: OutputFormat,
) -> anyhow::Result<ValidationDispatch> {
  let Command::Config(config) = command else {
    return Ok(ValidationDispatch::NotRequested);
  };
  let ConfigSubcommand::Validate(args) = &config.command else {
    return Ok(ValidationDispatch::NotRequested);
  };

  let local_report = serde_json::to_value(validate_native_config(&args.file))?;
  if !report_ok(&local_report) || args.local_only {
    let ok = report_ok(&local_report);
    print_serializable(&combined_report(local_report, None, ok), format)?;
    return Ok(ValidationDispatch::Complete(if ok { 0 } else { 1 }));
  }

  let document = match load_native_config_document(&args.file) {
    Ok(document) => document,
    Err(_error) => {
      let admin = error_report(
        "validate",
        "merge",
        "configuration changed or could not be merged after local validation",
      );
      print_serializable(&combined_report(local_report, Some(admin), false), format)?;
      return Ok(ValidationDispatch::Complete(1));
    }
  };
  let merged_toml = toml::to_string(&document.value)?;
  Ok(ValidationDispatch::Remote(PreparedValidation {
    local_report,
    merged_toml,
  }))
}

impl PreparedValidation {
  pub(crate) fn request_plan(&self) -> RequestPlan {
    RequestPlan {
      method: Method::POST,
      endpoint: "/admin/v1/config/validate".to_string(),
      body: Some(json!({ "format": "toml", "config": self.merged_toml })),
      if_match: None,
      permission: PermissionHint::new("config:Validate", "*"),
      filter: crate::plan::ResponseFilter::None,
    }
  }

  pub(crate) fn finish(
    self,
    response: &AdminResponse,
    format: OutputFormat,
  ) -> anyhow::Result<i32> {
    let admin_report = match serde_json::from_slice::<Value>(&response.body) {
      Ok(value) => admin_config_report(value),
      Err(error) => error_report(
        "validate",
        "admin_response",
        &format!("Admin validation response was not JSON: {error}"),
      ),
    };
    let ok = response.status.is_success() && report_ok(&admin_report);
    print_serializable(
      &combined_report(self.local_report, Some(admin_report), ok),
      format,
    )?;
    Ok(if ok { 0 } else { 1 })
  }
}

fn admin_config_report(value: Value) -> Value {
  value
    .pointer("/error/details/config_report")
    .cloned()
    .unwrap_or(value)
}

fn combined_report(local: Value, admin: Option<Value>, ok: bool) -> Value {
  json!({
    "report_schema_version": REPORT_SCHEMA_VERSION,
    "operation": "validate",
    "native_schema_epoch": NATIVE_SCHEMA_EPOCH,
    "ok": ok,
    "local_validation": local,
    "admin_validation": admin,
  })
}

#[cfg(test)]
mod tests {
  use clap::Parser;

  use super::*;
  use crate::cli::{Cli, ConfigCommand};

  #[test]
  fn validate_accepts_local_only_after_the_file() {
    let cli = Cli::try_parse_from([
      "oxibeltctl",
      "config",
      "validate",
      "config.toml",
      "--local-only",
    ])
    .expect("validate command should parse");
    let Command::Config(ConfigCommand {
      command: ConfigSubcommand::Validate(args),
    }) = cli.command
    else {
      panic!("expected validate command");
    };
    assert_eq!(args.file, std::path::PathBuf::from("config.toml"));
    assert!(args.local_only);
  }

  #[test]
  fn combined_report_keeps_local_and_admin_results_separate() {
    let report = combined_report(json!({"ok": true}), Some(json!({"ok": false})), false);
    assert_eq!(report["operation"], "validate");
    assert_eq!(report["local_validation"]["ok"], true);
    assert_eq!(report["admin_validation"]["ok"], false);
    assert_eq!(report["ok"], false);
  }

  #[test]
  fn extracts_config_report_from_the_global_admin_error_envelope() {
    let wire = json!({
      "error": {
        "code": "invalid_configuration",
        "message": "invalid",
        "details": {"config_report": {"ok": false, "diagnostics": []}}
      },
      "request_id": "request-1"
    });
    let report = admin_config_report(wire);
    assert_eq!(report["ok"], false);
    assert!(report["diagnostics"].is_array());
  }
}
