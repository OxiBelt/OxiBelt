use std::time::Duration;

use clap::Parser;
use http::Method;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, DEFAULT_ADMIN_URL};
use oxibelt::diagnostics::{DoctorFailOn, DoctorOutputFormat, ExternalProbeKind};
use serde_json::json;
use url::Url;

use super::cli::{Cli, Command, DoctorArgs};
use super::plan::plan_command;

#[test]
fn current_doctor_includes_external_probe_query() {
  let command = Command::Doctor(DoctorArgs {
    config: None,
    candidate: None,
    helm_rendered: None,
    helm_chart: None,
    helm_values: Vec::new(),
    helm_release: "oxibelt-doctor".to_string(),
    helm_namespace: "default".to_string(),
    kubernetes: false,
    kube_context: None,
    kube_namespace: None,
    all_namespaces: false,
    kube_selector: None,
    format: DoctorOutputFormat::NaturalLanguage,
    fail_on: DoctorFailOn::Error,
    external_probes: vec![ExternalProbeKind::SharedState, ExternalProbeKind::Upstream],
  });
  let plan = plan(&command);

  assert_eq!(plan.method, Method::GET);
  assert_eq!(
    plan.endpoint,
    "/admin/v1/diagnostics/preflight?external_probe=shared_state&external_probe=upstream"
  );
  assert_eq!(plan.permission.action, "diagnostics:ReadPreflight");
  assert_eq!(plan.permission.resources, vec!["preflight/current"]);
}

#[test]
fn candidate_doctor_posts_toml() {
  let candidate = tempfile::Builder::new()
    .prefix("oxibeltctl-doctor-")
    .suffix(".toml")
    .tempfile()
    .expect("candidate config file should be created");
  std::fs::write(
    candidate.path(),
    "[listeners]\nhttps_bind = \"127.0.0.1:8443\"\n",
  )
  .expect("candidate should be written");
  let command = Command::Doctor(DoctorArgs {
    config: None,
    candidate: Some(candidate.path().to_path_buf()),
    helm_rendered: None,
    helm_chart: None,
    helm_values: Vec::new(),
    helm_release: "oxibelt-doctor".to_string(),
    helm_namespace: "default".to_string(),
    kubernetes: false,
    kube_context: None,
    kube_namespace: None,
    all_namespaces: false,
    kube_selector: None,
    format: DoctorOutputFormat::Json,
    fail_on: DoctorFailOn::Warning,
    external_probes: vec![ExternalProbeKind::RemoteSigner],
  });
  let plan = plan(&command);

  assert_eq!(plan.method, Method::POST);
  assert_eq!(plan.endpoint, "/admin/v1/diagnostics/preflight");
  assert_eq!(
    plan.body,
    Some(json!({
      "format": "toml",
      "config": "[listeners]\nhttps_bind = \"127.0.0.1:8443\"\n",
      "external_probes": ["remote_signer"],
    }))
  );
}

#[test]
fn local_doctor_cli_conflicts_with_candidate_and_parses_options() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "doctor",
    "--config",
    "source/config/oxibelt.toml",
    "--format",
    "json",
    "--fail-on",
    "warning",
    "--external-probe",
    "all",
  ])
  .expect("local doctor should parse");
  let Command::Doctor(args) = parsed.command else {
    panic!("expected doctor command");
  };
  assert!(args.config.is_some());
  assert_eq!(args.format, DoctorOutputFormat::Json);
  assert_eq!(args.fail_on, DoctorFailOn::Warning);
  assert_eq!(args.external_probes, vec![ExternalProbeKind::All]);

  let conflict = Cli::try_parse_from([
    "oxibeltctl",
    "doctor",
    "--config",
    "active.toml",
    "--candidate",
    "candidate.toml",
  ]);
  assert!(conflict.is_err(), "doctor config and candidate conflict");
}

#[test]
fn doctor_defaults_to_natural_language_and_rejects_legacy_text() {
  let default = Cli::try_parse_from(["oxibeltctl", "doctor"])
    .expect("doctor should use the natural-language format by default");
  let Command::Doctor(args) = default.command else {
    panic!("expected doctor command");
  };
  assert_eq!(args.format, DoctorOutputFormat::NaturalLanguage);

  let explicit = Cli::try_parse_from(["oxibeltctl", "doctor", "--format", "natural-language"])
    .expect("doctor should accept the natural-language format");
  let Command::Doctor(args) = explicit.command else {
    panic!("expected doctor command");
  };
  assert_eq!(args.format, DoctorOutputFormat::NaturalLanguage);

  let legacy = Cli::try_parse_from(["oxibeltctl", "doctor", "--format", "text"])
    .expect_err("doctor must reject the legacy text format");
  assert!(
    legacy
      .to_string()
      .contains("expected natural-language, json, or sarif"),
    "legacy format error should list the supported doctor formats: {legacy}"
  );
}

#[test]
fn doctor_parses_local_deployment_sources_and_sarif() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "doctor",
    "--config",
    "source/config/oxibelt.toml",
    "--helm-chart",
    "deploy/helm/oxibelt",
    "--helm-values",
    "values-production.yaml",
    "--helm-release",
    "oxibelt",
    "--helm-namespace",
    "edge",
    "--format",
    "sarif",
  ])
  .expect("config plus one local Helm source should parse");
  let Command::Doctor(args) = parsed.command else {
    panic!("expected doctor command");
  };
  assert!(args.config.is_some());
  assert!(args.helm_chart.is_some());
  assert_eq!(args.helm_values.len(), 1);
  assert_eq!(args.helm_release, "oxibelt");
  assert_eq!(args.helm_namespace, "edge");
  assert_eq!(args.format, DoctorOutputFormat::Sarif);

  let conflicting_sources = Cli::try_parse_from([
    "oxibeltctl",
    "doctor",
    "--helm-rendered",
    "rendered",
    "--kubernetes",
  ]);
  assert!(
    conflicting_sources.is_err(),
    "doctor must reject multiple deployment sources"
  );

  let missing_live_source =
    Cli::try_parse_from(["oxibeltctl", "doctor", "--kube-namespace", "edge"]);
  assert!(
    missing_live_source.is_err(),
    "Kubernetes flags require --kubernetes"
  );
}

fn plan(command: &Command) -> super::plan::RequestPlan {
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  runtime
    .block_on(plan_command(&dummy_client(), command))
    .expect("plan")
}

fn dummy_client() -> AdminClient {
  oxibelt::tls::install_default_provider().expect("provider");
  let options = AdminClientOptions::new(
    Url::parse(DEFAULT_ADMIN_URL).expect("url"),
    "test-token".to_string(),
    Duration::from_secs(1),
  );
  AdminClient::new(options).expect("client")
}
