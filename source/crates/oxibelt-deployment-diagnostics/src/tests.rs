use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use oxibelt::diagnostics::DiagnosticReport;

use super::{
  MAX_MANIFEST_DOCUMENTS, Manifest,
  checks::{diagnose_manifests, is_digest_pinned},
  diagnose_gateway_resources, diagnose_rendered_directory, diagnose_server_version,
  helm_template_command,
  manifest::{
    append_yaml_manifests, contains_command_credential, validate_chart_tree,
    validate_helm_identifier,
  },
};

fn manifests(raw: &str) -> Vec<Manifest> {
  let mut manifests = Vec::new();
  append_yaml_manifests(&mut manifests, "fixture", "default", raw).expect("manifest fixture");
  manifests
}

fn has_code(report: &DiagnosticReport, code: &str) -> bool {
  report.findings.iter().any(|finding| finding.code == code)
}

#[test]
fn controller_and_immutable_target_with_digest_are_safe_except_mutable_images() {
  let raw = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oxibelt
  annotations:
    oxibelt.dev/immutable-config-rollout: "true"
    oxibelt.dev/effective-version: "0.7.0"
spec:
  replicas: 2
  template:
    metadata:
      annotations:
        oxibelt.dev/immutable-config-rollout: "true"
        oxibelt.dev/config-revision: config-v1
        oxibelt.dev/config-digest: deadbeef
        oxibelt.dev/effective-version: "0.7.0"
    spec:
      containers:
      - name: oxibelt
        image: ghcr.io/oxibelt/oxibelt@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        command: ["/usr/local/bin/oxibelt"]
        args: ["--config=/etc/oxibelt/config/oxibelt.toml"]
        env:
        - name: OXIBELT_CONFIG_ROLLOUT_MODE
          value: kubernetes_immutable
        - name: OXIBELT_CONFIG_REVISION
          valueFrom: {fieldRef: {fieldPath: "metadata.annotations['oxibelt.dev/config-revision']"}}
        - name: OXIBELT_CONFIG_DIGEST
          valueFrom: {fieldRef: {fieldPath: "metadata.annotations['oxibelt.dev/config-digest']"}}
        - name: OXIBELT_CONFIG_REVISION_FILE
          value: /etc/oxibelt/config/conf.d/gateway-api.generated.toml
        - name: OXIBELT_INSTANCE_ID
          valueFrom: {fieldRef: {fieldPath: metadata.uid}}
        readinessProbe: {httpGet: {path: /readyz, port: 8080}}
        volumeMounts:
        - name: config
          mountPath: /etc/oxibelt/config
          readOnly: true
      volumes:
      - name: config
        configMap: {name: oxibelt-config}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: controller}
spec:
  template:
    metadata:
      annotations:
        oxibelt.dev/effective-version: "0.7.0"
    spec:
      containers:
      - name: controller
        image: ghcr.io/oxibelt/controller@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
        command: ["/usr/local/bin/oxibelt-gateway-controller"]
        args:
        - run
        - --rollout-target-namespace=default
        - --rollout-target-kind=deployment
        - --rollout-target-name=oxibelt
        - --rollout-target-container-name=oxibelt
        - --rollout-volume-name=gateway-config
        - --compatibility-mode=exact
"#;
  let report = diagnose_manifests(manifests(raw));
  assert!(!has_code(&report, "K8S-004"), "{:#?}", report.findings);
  assert!(!has_code(&report, "K8S-005"), "{:#?}", report.findings);
  assert!(!has_code(&report, "K8S-009"), "{:#?}", report.findings);
  assert!(!has_code(&report, "REL-012"), "{:#?}", report.findings);
}

#[test]
fn detects_controller_data_plane_version_skew() {
  let raw = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oxibelt
  annotations:
    oxibelt.dev/immutable-config-rollout: "true"
spec:
  template:
    metadata:
      annotations:
        oxibelt.dev/immutable-config-rollout: "true"
        oxibelt.dev/effective-version: "0.6.5"
    spec:
      containers:
      - name: oxibelt
        command: ["/usr/local/bin/oxibelt"]
        args: ["--config=/etc/oxibelt/config/oxibelt.toml"]
        volumeMounts:
        - {name: config, mountPath: /etc/oxibelt/config, readOnly: true}
      volumes:
      - name: config
        configMap: {name: oxibelt-config}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: controller}
spec:
  template:
    metadata:
      annotations:
        oxibelt.dev/effective-version: "0.7.0"
    spec:
      containers:
      - name: controller
        command: ["/usr/local/bin/oxibelt-gateway-controller"]
        args:
        - run
        - --rollout-target-namespace=default
        - --rollout-target-kind=deployment
        - --rollout-target-name=oxibelt
        - --compatibility-mode=exact
"#;
  let report = diagnose_manifests(manifests(raw));

  assert!(has_code(&report, "K8S-009"), "{:#?}", report.findings);
}

#[test]
fn diagnoses_unsupported_kubernetes_minors_and_missing_gateway_apis() {
  let mut report = DiagnosticReport::new();
  diagnose_server_version(&mut report, "v1.33.9", "1", "33");
  diagnose_gateway_resources(&mut report, &BTreeSet::new());
  let report = report.finish();

  assert!(has_code(&report, "K8S-006"), "{:#?}", report.findings);
  assert!(has_code(&report, "K8S-007"), "{:#?}", report.findings);
}

#[test]
fn diagnoses_kubernetes_minors_above_the_qualified_range() {
  let mut report = DiagnosticReport::new();
  diagnose_server_version(&mut report, "v1.38.0", "1", "38");
  let report = report.finish();

  assert!(has_code(&report, "K8S-006"), "{:#?}", report.findings);
}

#[test]
fn accepts_qualified_kubernetes_minors_and_complete_gateway_api_v1() {
  let mut report = DiagnosticReport::new();
  diagnose_server_version(&mut report, "v1.37.0", "1", "37+");
  let served = super::REQUIRED_GATEWAY_API_V1_RESOURCES
    .iter()
    .map(|resource| (*resource).to_string())
    .collect::<BTreeSet<_>>();
  diagnose_gateway_resources(&mut report, &served);
  let report = report.finish();

  assert!(!has_code(&report, "K8S-006"), "{:#?}", report.findings);
  assert!(!has_code(&report, "K8S-007"), "{:#?}", report.findings);
}

#[test]
fn rejects_non_kubernetes_major_even_with_a_qualified_minor() {
  let mut report = DiagnosticReport::new();
  diagnose_server_version(&mut report, "v2.36.0", "2", "36");
  let report = report.finish();

  assert!(has_code(&report, "K8S-006"), "{:#?}", report.findings);
}

#[test]
fn detects_missing_cluster_acknowledgement_and_mutable_image() {
  let raw = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oxibelt
  annotations: {oxibelt.dev/immutable-config-rollout: "true"}
spec:
  replicas: 3
  template:
    metadata:
      annotations: {oxibelt.dev/immutable-config-rollout: "true"}
    spec:
      containers:
      - name: oxibelt
        image: ghcr.io/oxibelt/oxibelt:latest
        command: ["/usr/local/bin/oxibelt"]
"#;
  let report = diagnose_manifests(manifests(raw));
  assert!(has_code(&report, "K8S-005"), "{:#?}", report.findings);
  assert!(has_code(&report, "REL-012"), "{:#?}", report.findings);
}

#[test]
fn rejects_command_based_kubeconfig_credentials() {
  let value = serde_json::json!({
    "users": [{"name": "unsafe", "user": {"exec": {"command": "credential-helper"}}}]
  });
  assert!(contains_command_credential(&value));
  assert!(contains_command_credential(&serde_json::json!({
    "users": [{"name": "unsafe", "user": {"auth-provider": {"name": "legacy"}}}]
  })));
}

#[test]
fn rejects_symlinked_rendered_input_and_chart_members() {
  let directory = tempfile::tempdir().expect("temporary directory");
  let manifest = directory.path().join("outside.yaml");
  fs::write(&manifest, "apiVersion: v1\nkind: ConfigMap\n").expect("manifest fixture");
  symlink(&manifest, directory.path().join("linked.yaml")).expect("manifest symlink");
  assert!(diagnose_rendered_directory(directory.path()).is_err());

  let chart = directory.path().join("chart");
  fs::create_dir(&chart).expect("chart directory");
  fs::write(
    chart.join("Chart.yaml"),
    "apiVersion: v2\nname: fixture\nversion: 0.1.0\n",
  )
  .expect("chart metadata");
  symlink(&manifest, chart.join("linked-template.yaml")).expect("chart symlink");
  assert!(validate_chart_tree(&chart).is_err());
}

#[test]
fn supports_list_envelopes() {
  let raw = r#"
apiVersion: v1
kind: List
items:
- apiVersion: apps/v1
  kind: Deployment
  metadata: {name: oxibelt}
  spec:
    template:
      spec:
        containers:
        - name: oxibelt
          image: ghcr.io/oxibelt/oxibelt:latest
          command: ["/usr/local/bin/oxibelt"]
"#;
  let report = diagnose_manifests(manifests(raw));
  assert!(has_code(&report, "REL-012"), "{:#?}", report.findings);
}

#[test]
fn rejects_list_envelopes_that_exceed_the_document_bound() {
  let item = "- apiVersion: v1\n  kind: ConfigMap\n";
  let raw = format!(
    "apiVersion: v1\nkind: List\nitems:\n{}",
    item.repeat(MAX_MANIFEST_DOCUMENTS + 1)
  );
  let mut output = Vec::new();
  assert!(append_yaml_manifests(&mut output, "fixture", "default", &raw).is_err());
}

#[test]
fn validates_digest_shape() {
  assert!(is_digest_pinned(
    "registry.example/oxibelt@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  ));
  assert!(!is_digest_pinned("registry.example/oxibelt:latest"));
  assert!(!is_digest_pinned("registry.example/oxibelt@sha256:ABC"));
}

#[test]
fn helm_identifiers_are_not_shell_arguments() {
  assert!(validate_helm_identifier("release", "oxibelt").is_ok());
  assert!(validate_helm_identifier("release", "$(unsafe)").is_err());
}

#[test]
fn helm_template_command_terminates_options_before_positionals() {
  let values = [
    PathBuf::from("values-production.yaml"),
    PathBuf::from("--post-renderer=/tmp/unsafe-values"),
  ];
  let command = helm_template_command(
    Path::new("--post-renderer=/tmp/unsafe-chart"),
    &values,
    "oxibelt-doctor",
    "default",
  );
  let args = command
    .as_std()
    .get_args()
    .map(|argument| argument.to_str().expect("ASCII Helm argument"))
    .collect::<Vec<_>>();

  assert_eq!(
    args,
    vec![
      "template",
      "--namespace",
      "default",
      "--dry-run=client",
      "--no-hooks",
      "--disable-openapi-validation",
      "--values",
      "values-production.yaml",
      "--values",
      "--post-renderer=/tmp/unsafe-values",
      "--",
      "oxibelt-doctor",
      "--post-renderer=/tmp/unsafe-chart",
    ]
  );
}
