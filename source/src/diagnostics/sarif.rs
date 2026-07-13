//! SARIF serialization for the public doctor report.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::{DiagnosticReport, DiagnosticSeverity};

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

pub(super) fn format_sarif(report: &DiagnosticReport) -> Value {
  let mut emitted_rules = BTreeSet::new();
  let rules = report
    .findings
    .iter()
    .filter(|finding| emitted_rules.insert(finding.code.clone()))
    .map(|finding| {
      json!({
        "id": finding.code,
        "name": finding.id,
        "shortDescription": { "text": finding.message },
        "help": { "text": finding.remediation },
        "properties": {
          "diagnosticId": finding.id,
          "category": finding.category,
        },
      })
    })
    .collect::<Vec<_>>();
  let results = report
    .findings
    .iter()
    .map(|finding| {
      json!({
        "ruleId": finding.code,
        "level": sarif_level(finding.severity),
        "message": { "text": finding.message },
        "properties": {
          "diagnosticId": finding.id,
          "category": finding.category,
          "target": finding.target,
          "remediation": finding.remediation,
        },
      })
    })
    .collect::<Vec<_>>();

  json!({
    "$schema": SARIF_SCHEMA,
    "version": "2.1.0",
    "runs": [{
      "tool": {
        "driver": {
          "name": "oxibeltctl doctor",
          "informationUri": "https://github.com/OxiBelt/OxiBelt",
          "rules": rules,
        },
      },
      "properties": {
        "diagnosticSchemaVersion": report.schema_version,
        "profile": report.profile,
        "ok": report.ok,
      },
      "results": results,
    }],
  })
}

fn sarif_level(severity: DiagnosticSeverity) -> &'static str {
  match severity {
    DiagnosticSeverity::Critical | DiagnosticSeverity::Error => "error",
    DiagnosticSeverity::Warning => "warning",
    DiagnosticSeverity::Info => "note",
  }
}
