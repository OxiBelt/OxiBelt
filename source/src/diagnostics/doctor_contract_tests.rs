use super::{
  DiagnosticReport, DiagnosticSeverity, checks, format_natural_language, format_sarif, tls_checks,
};
use crate::config::Config;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[test]
fn public_report_contract_has_codes_schema_natural_language_and_sarif() {
  let mut report = DiagnosticReport::new();
  report.push(
    DiagnosticSeverity::Error,
    "admin.public_without_mtls",
    "admin",
    "admin.tls.client_auth",
    "Admin API is reachable outside loopback without mTLS.",
    "Require mTLS.",
  );
  let report = report.finish();

  let json = serde_json::to_value(&report).expect("report should serialize");
  assert_eq!(json["schema_version"], 1);
  assert_eq!(json["findings"][0]["code"], "ADM-001");
  assert_eq!(json["findings"][0]["id"], "admin.public_without_mtls");
  assert!(
    format_natural_language(&report)
      .contains("ERROR ADM-001: Admin API is reachable outside loopback without mTLS.")
  );

  let sarif = format_sarif(&report);
  assert_eq!(sarif["version"], "2.1.0");
  assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "ADM-001");
  assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
  assert_eq!(
    sarif["runs"][0]["results"][0]["properties"]["diagnosticId"],
    "admin.public_without_mtls"
  );
}

#[test]
fn older_remote_report_normalizes_missing_schema_and_code() {
  let mut report: DiagnosticReport = serde_json::from_value(serde_json::json!({
    "ok": false,
    "profile": "production",
    "summary": { "critical": 0, "error": 1, "warning": 0, "info": 0 },
    "findings": [{
      "id": "real_ip.no_trusted_proxies",
      "severity": "error",
      "category": "identity",
      "target": "proxy.real_ip.trusted_proxies",
      "message": "unsafe",
      "remediation": "fix it"
    }],
    "probes": []
  }))
  .expect("older report should deserialize");
  report.normalize();
  assert_eq!(report.schema_version, 1);
  assert_eq!(report.findings[0].code, "PROXY-002");
}

#[test]
fn required_local_security_checks_emit_fixed_codes() {
  let temp_dir = common::TempDir::new("diagnostics-required-codes");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "diagnostics-required-codes");
  let mut config: Config = toml::from_str(&common::minimal_config_toml(&cert_path, &key_path))
    .expect("config should parse");
  config.admin.enabled = true;
  config.admin.bind = "0.0.0.0:9092".parse().expect("socket address");
  config.admin.tls.enabled = true;
  config.proxy.real_ip.enabled = true;
  config.listeners.http3 = true;
  config.waf.enabled = true;
  config.waf.http_body_compression.mode = crate::waf::WafHttpBodyCompressionMode::Transform;
  config.waf.http_body_compression.max_decoded_body_bytes = 2_048;
  config.limits.max_request_body_bytes = 1_024;

  let mut report = DiagnosticReport::new();
  checks::diagnose_admin(&config, &mut report);
  checks::diagnose_real_ip(&config, &mut report);
  checks::diagnose_waf(&config, &mut report);
  tls_checks::diagnose_tls(&config, &mut report);
  let report = report.finish();
  for code in ["ADM-001", "AUD-003", "PROXY-002", "TLS-013", "WAF-021"] {
    assert!(
      report.findings.iter().any(|finding| finding.code == code),
      "missing {code}: {:#?}",
      report.findings
    );
  }

  let raw = format!(
    r#"
{}

[shared_state]
enabled = true

[[shared_state.backends]]
name = "redis-remote"
kind = "redis"
connection_url = "redis://redis.example.test:6379/0"
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );
  let redis_config: Config = toml::from_str(&raw).expect("Redis config should parse");
  let mut report = DiagnosticReport::new();
  checks::diagnose_shared_state(&redis_config, &mut report);
  let report = report.finish();
  assert!(
    report
      .findings
      .iter()
      .any(|finding| finding.code == "STATE-008"),
    "missing STATE-008: {:#?}",
    report.findings
  );
}
