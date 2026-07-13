//! Diagnostics entrypoints for local checks, probes, and support bundle assembly.
//! Diagnostic output must describe runtime state without leaking credentials or private material.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use anyhow::bail;
use serde::{Deserialize, Serialize};

use crate::config::Config;

mod checks;
mod deployment;
mod discovery_probe;
mod probes;
mod rules;
mod sarif;
mod support_bundle;
mod system;
mod tls_checks;
mod upstream_probe;

#[cfg(test)]
mod doctor_contract_tests;

pub use deployment::{
  KubernetesDoctorOptions, diagnose_helm_chart, diagnose_kubernetes, diagnose_rendered_directory,
};
pub use support_bundle::{
  RuntimeSnapshot, SupportBundle, build_runtime_snapshot, build_support_bundle,
};

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalProbeKind {
  SharedState,
  IpmStore,
  RemoteSigner,
  Upstream,
  All,
}

impl ExternalProbeKind {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::SharedState => "shared_state",
      Self::IpmStore => "ipm_store",
      Self::RemoteSigner => "remote_signer",
      Self::Upstream => "upstream",
      Self::All => "all",
    }
  }
}

impl fmt::Display for ExternalProbeKind {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

impl FromStr for ExternalProbeKind {
  type Err = anyhow::Error;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "shared_state" => Ok(Self::SharedState),
      "ipm_store" => Ok(Self::IpmStore),
      "remote_signer" => Ok(Self::RemoteSigner),
      "upstream" => Ok(Self::Upstream),
      "all" => Ok(Self::All),
      _ => bail!(
        "unsupported doctor external probe {value}; expected shared_state, ipm_store, remote_signer, upstream, or all"
      ),
    }
  }
}

#[derive(Debug, Clone, Default)]
pub struct DoctorOptions {
  pub external_probes: Vec<ExternalProbeKind>,
  // Kept as a compatibility name. Redis ACL secret files are also treated as
  // secret-backed probe inputs and require this opt-in.
  pub allow_secret_env_probes: bool,
}

impl DoctorOptions {
  pub fn with_secret_env_probes(mut self) -> Self {
    self.allow_secret_env_probes = true;
    self
  }

  pub fn expanded_external_probes(&self) -> Vec<ExternalProbeKind> {
    let mut probes = Vec::new();
    let requested_all = self.external_probes.contains(&ExternalProbeKind::All);
    for probe in [
      ExternalProbeKind::SharedState,
      ExternalProbeKind::IpmStore,
      ExternalProbeKind::RemoteSigner,
      ExternalProbeKind::Upstream,
    ] {
      if requested_all || self.external_probes.contains(&probe) {
        probes.push(probe);
      }
    }
    probes
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DoctorFailOn {
  Critical,
  Error,
  Warning,
}

impl FromStr for DoctorFailOn {
  type Err = anyhow::Error;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "critical" => Ok(Self::Critical),
      "error" => Ok(Self::Error),
      "warning" => Ok(Self::Warning),
      _ => bail!("unsupported doctor fail threshold {value}; expected critical, error, or warning"),
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DoctorOutputFormat {
  Text,
  Json,
  Sarif,
}

impl FromStr for DoctorOutputFormat {
  type Err = anyhow::Error;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "text" => Ok(Self::Text),
      "json" => Ok(Self::Json),
      "sarif" => Ok(Self::Sarif),
      _ => bail!("unsupported doctor format {value}; expected text, json, or sarif"),
    }
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
  Critical,
  Error,
  Warning,
  Info,
}

impl DiagnosticSeverity {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Critical => "critical",
      Self::Error => "error",
      Self::Warning => "warning",
      Self::Info => "info",
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DiagnosticSummary {
  pub critical: usize,
  pub error: usize,
  pub warning: usize,
  pub info: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiagnosticFinding {
  /// Stable public rule code. The dotted `id` remains a compatibility alias.
  #[serde(default)]
  pub code: String,
  pub id: String,
  pub severity: DiagnosticSeverity,
  pub category: String,
  pub target: String,
  pub message: String,
  pub remediation: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiagnosticProbe {
  pub kind: String,
  pub target: String,
  pub status: String,
  pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiagnosticReport {
  #[serde(default = "diagnostic_schema_version")]
  pub schema_version: u32,
  pub ok: bool,
  pub profile: String,
  pub summary: DiagnosticSummary,
  pub findings: Vec<DiagnosticFinding>,
  pub probes: Vec<DiagnosticProbe>,
}

impl DiagnosticReport {
  pub(crate) fn new() -> Self {
    Self {
      schema_version: diagnostic_schema_version(),
      ok: true,
      profile: "production".to_string(),
      summary: DiagnosticSummary::default(),
      findings: Vec::new(),
      probes: Vec::new(),
    }
  }

  pub(crate) fn push(
    &mut self,
    severity: DiagnosticSeverity,
    id: &str,
    category: &str,
    target: impl Into<String>,
    message: impl Into<String>,
    remediation: impl Into<String>,
  ) {
    self.findings.push(DiagnosticFinding {
      code: rules::code_for(id),
      id: id.to_string(),
      severity,
      category: category.to_string(),
      target: target.into(),
      message: message.into(),
      remediation: remediation.into(),
    });
  }

  pub(crate) fn probe(
    &mut self,
    kind: &str,
    target: impl Into<String>,
    status: &str,
    message: impl Into<String>,
  ) {
    self.probes.push(DiagnosticProbe {
      kind: kind.to_string(),
      target: target.into(),
      status: status.to_string(),
      message: message.into(),
    });
  }

  /// Normalizes a report received from a local or older remote doctor.
  ///
  /// Older Admin endpoints did not serialize `schema_version` or finding
  /// codes. Filling those additive fields here keeps JSON, text, and SARIF
  /// output usable during rolling upgrades.
  pub fn normalize(&mut self) {
    if self.schema_version == 0 {
      self.schema_version = diagnostic_schema_version();
    }
    for finding in &mut self.findings {
      if finding.code.is_empty() {
        finding.code = rules::code_for(&finding.id);
      }
    }
    let mut summary = DiagnosticSummary::default();
    for finding in &self.findings {
      match finding.severity {
        DiagnosticSeverity::Critical => summary.critical += 1,
        DiagnosticSeverity::Error => summary.error += 1,
        DiagnosticSeverity::Warning => summary.warning += 1,
        DiagnosticSeverity::Info => summary.info += 1,
      }
    }
    self.ok = summary.critical == 0 && summary.error == 0;
    self.summary = summary;
  }

  pub(crate) fn finish(mut self) -> Self {
    self.normalize();
    self
  }

  pub fn fails_on(&self, threshold: DoctorFailOn) -> bool {
    match threshold {
      DoctorFailOn::Critical => self.summary.critical > 0,
      DoctorFailOn::Error => self.summary.critical > 0 || self.summary.error > 0,
      DoctorFailOn::Warning => {
        self.summary.critical > 0 || self.summary.error > 0 || self.summary.warning > 0
      }
    }
  }

  pub(crate) fn merge(&mut self, other: Self) {
    self.findings.extend(other.findings);
    self.probes.extend(other.probes);
    self.schema_version = diagnostic_schema_version();
    self.profile = "production".to_string();
  }
}

const fn diagnostic_schema_version() -> u32 {
  1
}

/// Combines independently collected doctor reports into one normalized report.
pub fn combine_reports(reports: impl IntoIterator<Item = DiagnosticReport>) -> DiagnosticReport {
  let mut combined = DiagnosticReport::new();
  for report in reports {
    combined.merge(report);
  }
  combined.finish()
}

pub async fn diagnose_config_path(path: &Path, options: &DoctorOptions) -> DiagnosticReport {
  match Config::load(path) {
    Ok(config) => diagnose_config(config, options).await,
    Err(error) => invalid_config_report(error),
  }
}

pub async fn diagnose_admin_inline_toml(
  raw: &str,
  active: &Config,
  options: &DoctorOptions,
) -> DiagnosticReport {
  match load_admin_inline_config(raw, active) {
    Ok(config) => diagnose_config(config, options).await,
    Err(report) => report,
  }
}

pub async fn diagnose_config(config: Config, options: &DoctorOptions) -> DiagnosticReport {
  if let Err(report) = validate_config_for_diagnostics(&config) {
    return report;
  }

  diagnose_valid_config(config, options).await
}

pub(crate) fn load_admin_inline_config(
  raw: &str,
  active: &Config,
) -> Result<Config, DiagnosticReport> {
  Config::load_admin_inline_toml(raw, active).map_err(invalid_config_report)
}

pub(crate) fn validate_config_for_diagnostics(config: &Config) -> Result<(), DiagnosticReport> {
  config.validate().map_err(validation_config_report)
}

pub(crate) fn external_probe_target_resources(
  config: &Config,
  options: &DoctorOptions,
) -> Vec<String> {
  probes::external_probe_target_resources(config, options)
}

async fn diagnose_valid_config(config: Config, options: &DoctorOptions) -> DiagnosticReport {
  let mut report = DiagnosticReport::new();
  checks::diagnose_admin(&config, &mut report);
  checks::diagnose_ipm(&config, &mut report);
  checks::diagnose_ops_listeners(&config, &mut report);
  checks::diagnose_real_ip(&config, &mut report);
  checks::diagnose_waf(&config, &mut report);
  checks::diagnose_shared_state(&config, &mut report);
  checks::diagnose_cache(&config, &mut report);
  checks::diagnose_upgrades(&config, &mut report);
  checks::diagnose_remote_signer_local(&config, &mut report);
  checks::diagnose_deploy_hygiene(&config, &mut report);
  system::diagnose_system(&config, &mut report);
  tls_checks::diagnose_tls(&config, &mut report);
  probes::run_external_probes(&config, options, &mut report).await;
  report.finish()
}

pub fn format_text(report: &DiagnosticReport) -> String {
  let mut report = report.clone();
  report.normalize();
  let mut out = String::new();
  out.push_str(&format!(
    "OxiBelt production doctor (schema v{})\n",
    report.schema_version
  ));
  out.push_str(&format!(
    "status: {}\n",
    if report.ok { "ok" } else { "not ok" }
  ));
  out.push_str(&format!(
    "findings: critical={} error={} warning={} info={}\n",
    report.summary.critical, report.summary.error, report.summary.warning, report.summary.info
  ));
  for finding in &report.findings {
    out.push_str(&format!(
      "\n{} {}: {}\n",
      finding.severity.as_str().to_ascii_uppercase(),
      finding.code,
      finding.message
    ));
    out.push_str(&format!("id: {} ({})\n", finding.id, finding.category));
    out.push_str(&format!("target: {}\n", finding.target));
    out.push_str(&format!("message: {}\n", finding.message));
    out.push_str(&format!("remediation: {}\n", finding.remediation));
  }
  if !report.probes.is_empty() {
    out.push_str("\nprobes:\n");
    for probe in &report.probes {
      out.push_str(&format!(
        "- [{}] {} {}: {}\n",
        probe.status, probe.kind, probe.target, probe.message
      ));
    }
  }
  out
}

/// Serializes the diagnostics report as a SARIF 2.1.0 document.
pub fn format_sarif(report: &DiagnosticReport) -> serde_json::Value {
  let mut report = report.clone();
  report.normalize();
  sarif::format_sarif(&report)
}

fn invalid_config_report(error: anyhow::Error) -> DiagnosticReport {
  let mut report = DiagnosticReport::new();
  report.push(
    DiagnosticSeverity::Critical,
    "config.invalid",
    "config",
    "config",
    format!("configuration could not be loaded: {error}"),
    "Fix the TOML configuration and rerun doctor before deploying.",
  );
  report.finish()
}

fn validation_config_report(error: anyhow::Error) -> DiagnosticReport {
  let mut report = DiagnosticReport::new();
  report.push(
    DiagnosticSeverity::Critical,
    "config.invalid",
    "config",
    "config",
    format!("configuration failed validation: {error}"),
    "Fix the TOML configuration and rerun doctor before deploying.",
  );
  report.finish()
}

#[cfg(test)]
mod tests {
  use super::*;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[tokio::test]
  async fn report_summary_marks_errors_not_ok() {
    let temp_dir = common::TempDir::new("diagnostics-summary");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "diagnostics-summary");
    let raw = format!(
      r#"
{}

[metrics]
enabled = true
bind = "0.0.0.0:9090"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let report = diagnose_config(config, &DoctorOptions::default()).await;

    assert!(!report.ok);
    assert!(report.summary.error > 0);
    assert!(
      report
        .findings
        .iter()
        .any(|finding| finding.id == "metrics.public_bind")
    );
  }

  #[test]
  fn external_probe_target_resources_strip_credentials_and_normalize_hosts() {
    let temp_dir = common::TempDir::new("diagnostics-probe-targets");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "diagnostics-probe-targets");
    let raw = format!(
      r#"
{}

[shared_state]
enabled = true

[[shared_state.backends]]
name = "redis-main"
kind = "redis"
connection_url = "redis://user:secret@[::1]/0?ignored=yes"

[[shared_state.backends]]
name = "pg-main"
kind = "postgres"
connection_url = "postgres://user:secret@Db.Example.TEST/db?sslmode=disable"

[ipm]
enabled = true
backend = "pg-main"

[tls.remote_signer]
enabled = true
socket_path = "/run/oxibelt/signer.sock"
key_id = "deploy-key"
token_env = "OXIBELT_UNUSED_REMOTE_SIGNER_TOKEN"

[[upstreams]]
name = "upper"
origin = "https://Example.TEST/private?token=secret"

[[upstream_pools]]
name = "pool"

[[upstream_pools.servers]]
id = "v6"
origin = "http://[::1]"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let options = DoctorOptions {
      external_probes: vec![ExternalProbeKind::All],
      allow_secret_env_probes: true,
    };
    let resources = external_probe_target_resources(&config, &options);

    for expected in [
      "probe/shared_state/tcp/[::1]:6379",
      "probe/shared_state/tcp/db.example.test:5432",
      "probe/ipm_store/tcp/db.example.test:5432",
      "probe/remote_signer/unix//run/oxibelt/signer.sock",
      "probe/upstream/tcp/example.test:443",
      "probe/upstream/tcp/[::1]:80",
    ] {
      assert!(
        resources.iter().any(|resource| resource == expected),
        "missing target resource {expected}: {resources:#?}"
      );
    }
    assert!(
      resources
        .iter()
        .all(|resource| !resource.contains("secret") && !resource.contains("token=")),
      "target resources should not include credentials or query strings: {resources:#?}"
    );
  }

  #[test]
  fn external_probe_target_resources_skip_secret_env_candidate_targets() {
    let temp_dir = common::TempDir::new("diagnostics-secret-env-targets");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "diagnostics-secret-env-targets");
    let raw = format!(
      r#"
{}

[shared_state]
enabled = true

[[shared_state.backends]]
name = "redis-env"
kind = "redis"
connection_url_env = "PATH"

[[upstream_pools]]
name = "secret-discovery"

[[upstream_pools.discovery]]
provider = "consul"
endpoint = "http://Token-Probe.Example:8500"
service = "api"
token_env = "PATH"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let options = DoctorOptions {
      external_probes: vec![ExternalProbeKind::All],
      allow_secret_env_probes: false,
    };
    let resources = external_probe_target_resources(&config, &options);

    assert!(
      resources
        .iter()
        .all(|resource| !resource.contains("token-probe.example")),
      "candidate probe target resources must not include token_env discovery endpoints: {resources:#?}"
    );
    assert!(
      resources
        .iter()
        .all(|resource| !resource.starts_with("probe/shared_state/tcp/")),
      "candidate probe target resources must not resolve connection_url_env backends: {resources:#?}"
    );

    let active_options = options.with_secret_env_probes();
    let active_resources = external_probe_target_resources(&config, &active_options);
    assert!(
      active_resources
        .iter()
        .any(|resource| resource == "probe/upstream/tcp/token-probe.example:8500"),
      "active-config probes should still expose authorized token_env discovery targets: {active_resources:#?}"
    );
  }

  #[test]
  fn external_probe_target_resources_skip_redis_acl_file_candidate_targets() {
    let temp_dir = common::TempDir::new("diagnostics-redis-acl-file-targets");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "diagnostics-redis-acl-file-targets");
    let raw = format!(
      r#"
{}

[shared_state]
enabled = true

[[shared_state.backends]]
name = "redis-acl"
kind = "redis"
connection_url = "rediss://redis.example.test:6380/0"

[shared_state.backends.redis_auth]
password_file = "redis/redis-acl/password"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let options = DoctorOptions {
      external_probes: vec![ExternalProbeKind::SharedState],
      allow_secret_env_probes: false,
    };

    assert!(
      external_probe_target_resources(&config, &options).is_empty(),
      "candidate diagnostics must not use Redis ACL files"
    );
    assert!(
      external_probe_target_resources(&config, &options.with_secret_env_probes())
        .iter()
        .any(|resource| resource == "probe/shared_state/tcp/redis.example.test:6380")
    );
  }

  #[tokio::test]
  async fn candidate_discovery_probe_skips_token_env_without_reading_secret() {
    let temp_dir = common::TempDir::new("diagnostics-secret-env-discovery");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "diagnostics-secret-env-discovery");
    let raw = format!(
      r#"
{}

[[upstream_pools]]
name = "secret-discovery"

[[upstream_pools.discovery]]
provider = "kubernetes"
endpoint = "http://Token-Probe.Example:8080"
namespace = "default"
service = "api"
port = 8080
token_env = "PATH"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let options = DoctorOptions {
      external_probes: vec![ExternalProbeKind::Upstream],
      allow_secret_env_probes: false,
    };
    let mut report = DiagnosticReport::new();

    discovery_probe::probe_discovery(&config, &options, &mut report).await;

    assert!(
      report.probes.iter().any(|probe| {
        probe.kind == "upstream"
          && probe.status == "skipped"
          && probe.message.contains("disabled for candidate diagnostics")
      }),
      "candidate discovery probe should be skipped instead of reading token_env: {:#?}",
      report.probes
    );
  }

  #[tokio::test]
  async fn cache_key_and_waf_monitor_findings_are_reported() {
    let temp_dir = common::TempDir::new("diagnostics-cache-waf");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "diagnostics-cache-waf");
    let raw = format!(
      r#"
{}

[cache]
enabled = true
cache_key = "{{uri}}"
bypass_request_headers = ["Proxy-Authorization"]

[waf]
enabled = true
mode = "monitor"
"#,
      common::minimal_config_toml(&cert_path, &key_path)
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    let report = diagnose_config(config, &DoctorOptions::default()).await;

    for id in [
      "cache.key_missing_host",
      "cache.secret_headers_not_bypassed",
      "waf.monitor_mode",
    ] {
      assert!(
        report.findings.iter().any(|finding| finding.id == id),
        "missing finding {id}: {:#?}",
        report.findings
      );
    }
  }
}
