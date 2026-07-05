use std::fs;
use std::path::PathBuf;

use serde_json::Value;

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate should live under the repository root")
    .to_path_buf()
}

fn read_repo(path: &str) -> String {
  let full_path = repo_root().join(path);
  fs::read_to_string(&full_path)
    .unwrap_or_else(|error| panic!("failed to read {}: {error}", full_path.display()))
}

fn read_yaml(path: &str) -> Value {
  serde_saphyr::from_str(&read_repo(path))
    .unwrap_or_else(|error| panic!("{path} should parse as YAML: {error}"))
}

#[test]
fn data_plane_chart_metadata_and_values_are_valid() {
  let chart = read_yaml("deploy/helm/oxibelt/Chart.yaml");
  assert_eq!(chart["apiVersion"], "v2");
  assert_eq!(chart["name"], "oxibelt");
  assert_eq!(chart["type"], "application");
  assert_eq!(chart["version"], "0.0.0");
  assert_eq!(chart["appVersion"], "0.0.0");

  let values = read_yaml("deploy/helm/oxibelt/values.yaml");
  assert_eq!(values["workload"]["kind"], "Deployment");
  assert_eq!(values["service"]["type"], "LoadBalancer");
  assert_eq!(values["service"]["ports"]["http3"]["targetPort"], 8443);
  assert_eq!(values["tls"]["secretName"], "oxibelt-tls");
  assert_eq!(values["securityContext"]["readOnlyRootFilesystem"], true);
  assert_eq!(values["podSecurityContext"]["runAsNonRoot"], true);

  let schema: Value = serde_json::from_str(&read_repo("deploy/helm/oxibelt/values.schema.json"))
    .expect("values.schema.json should parse as JSON");
  assert_eq!(
    schema["properties"]["workload"]["properties"]["kind"]["enum"][0],
    "Deployment"
  );
  assert_eq!(
    schema["properties"]["workload"]["properties"]["kind"]["enum"][1],
    "DaemonSet"
  );
}

#[test]
fn data_plane_chart_templates_cover_production_runtime_contracts() {
  let expected = [
    "templates/_helpers.tpl",
    "templates/serviceaccount.yaml",
    "templates/rbac.yaml",
    "templates/configmap.yaml",
    "templates/deployment.yaml",
    "templates/daemonset.yaml",
    "templates/service.yaml",
    "templates/admin-service.yaml",
    "templates/metrics-service.yaml",
    "templates/pdb.yaml",
    "templates/hpa.yaml",
  ];
  for file in expected {
    assert!(
      repo_root().join("deploy/helm/oxibelt").join(file).exists(),
      "data-plane chart should include {file}"
    );
  }

  let deployment = read_repo("deploy/helm/oxibelt/templates/deployment.yaml");
  for needle in [
    "kind: Deployment",
    "securityContext",
    "readinessProbe",
    "livenessProbe",
    "startupProbe",
    "secretName: {{ required \"tls.secretName is required when tls.enabled=true\"",
    "emptyDir: {}",
    "OXIBELT_ADMIN_TOKEN",
  ] {
    assert!(
      deployment.contains(needle),
      "deployment template should contain {needle}"
    );
  }

  let service = read_repo("deploy/helm/oxibelt/templates/service.yaml");
  assert!(service.contains("protocol: TCP"));
  assert!(service.contains("protocol: UDP"));
  assert!(service.contains("targetPort: http3"));

  let pdb = read_repo("deploy/helm/oxibelt/templates/pdb.yaml");
  assert!(pdb.contains("kind: PodDisruptionBudget"));

  let hpa = read_repo("deploy/helm/oxibelt/templates/hpa.yaml");
  assert!(hpa.contains("apiVersion: autoscaling/v2"));
  assert!(hpa.contains("kind: HorizontalPodAutoscaler"));

  let metrics = read_repo("deploy/helm/oxibelt/templates/metrics-service.yaml");
  assert!(metrics.contains("targetPort: metrics"));

  let rbac = read_repo("deploy/helm/oxibelt/templates/rbac.yaml");
  assert!(rbac.contains("endpointslices"));
  assert!(rbac.contains("verbs: [\"get\", \"list\", \"watch\"]"));
}

#[test]
fn gateway_controller_chart_exposes_controller_runtime_options() {
  let chart = read_yaml("deploy/helm/oxibelt-gateway-controller/Chart.yaml");
  assert_eq!(chart["apiVersion"], "v2");
  assert_eq!(chart["name"], "oxibelt-gateway-controller");
  assert_eq!(chart["type"], "application");
  assert_eq!(chart["version"], "0.0.0");
  assert_eq!(chart["appVersion"], "0.0.0");

  let values = read_yaml("deploy/helm/oxibelt-gateway-controller/values.yaml");
  assert_eq!(values["controllerName"], "oxibelt.dev/gateway-controller");
  assert_eq!(values["backendResolution"], "cluster_dns");
  assert_eq!(values["securityContext"]["readOnlyRootFilesystem"], true);
  assert_eq!(values["podSecurityContext"]["runAsNonRoot"], true);
  assert!(values["resources"].is_object());

  let schema: Value = serde_json::from_str(&read_repo(
    "deploy/helm/oxibelt-gateway-controller/values.schema.json",
  ))
  .expect("gateway controller values schema should parse");
  assert_eq!(
    schema["properties"]["backendResolution"]["enum"][1],
    "endpoint_slice_watch"
  );

  let deployment = read_repo("deploy/helm/oxibelt-gateway-controller/templates/deployment.yaml");
  assert!(deployment.contains("--backend-resolution={{ .Values.backendResolution }}"));
  assert!(deployment.contains("--status-service={{ .Values.statusService }}"));
  assert!(deployment.contains("securityContext"));
  assert!(deployment.contains("startupProbe"));

  let rbac = read_repo("deploy/helm/oxibelt-gateway-controller/templates/rbac.yaml");
  assert!(rbac.contains("gatewayclasses"));
  assert!(rbac.contains("services"));
}
