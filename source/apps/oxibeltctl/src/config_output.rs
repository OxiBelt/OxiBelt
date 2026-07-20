use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::OutputFormat;

pub(crate) const REPORT_SCHEMA_VERSION: u32 = 1;
pub(crate) const NATIVE_SCHEMA_EPOCH: u32 = 1;

pub(crate) fn print_serializable<T: Serialize>(
  value: &T,
  format: OutputFormat,
) -> anyhow::Result<()> {
  match format {
    OutputFormat::PrettyJson => println!("{}", serde_json::to_string_pretty(value)?),
    OutputFormat::Json => println!("{}", serde_json::to_string(value)?),
  }
  Ok(())
}

pub(crate) fn report_ok(value: &Value) -> bool {
  value.get("ok").and_then(Value::as_bool).unwrap_or(false)
}

pub(crate) fn error_report(operation: &str, stage: &str, message: &str) -> Value {
  json!({
    "report_schema_version": REPORT_SCHEMA_VERSION,
    "operation": operation,
    "native_schema_epoch": NATIVE_SCHEMA_EPOCH,
    "ok": false,
    "diagnostics": [{
      "code": format!("config.{operation}.{stage}_failed"),
      "severity": "fatal",
      "stage": stage,
      "field_path": "$",
      "source": null,
      "message": message,
      "suggestions": [],
      "replacement": null,
    }]
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn error_reports_have_a_stable_envelope() {
    let report = error_report("migrate", "write", "failed");
    assert_eq!(report["report_schema_version"], 1);
    assert_eq!(report["native_schema_epoch"], 1);
    assert_eq!(report["operation"], "migrate");
    assert_eq!(report["diagnostics"][0]["severity"], "fatal");
    assert!(!report_ok(&report));
  }
}
