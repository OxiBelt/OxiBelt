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
  assert_eq!(values["workload"]["deployment"]["maxUnavailable"], 0);
  assert_eq!(values["workload"]["deployment"]["maxSurge"], 1);
  assert_eq!(values["workload"]["daemonSet"]["maxUnavailable"], 1);
  assert_eq!(values["service"]["type"], "LoadBalancer");
  assert_eq!(values["service"]["ports"]["http3"]["targetPort"], 8443);
  assert_eq!(values["tls"]["secretName"], "oxibelt-tls");
  assert!(values["config"]["inline"].as_str().is_some_and(|inline| {
    inline.contains("[runtime.accept]\nreuse_port = true")
      && inline.contains("[quic.socket]\nreuse_port = true")
  }));
  assert_eq!(values["admin"]["bindAddress"], "127.0.0.1");
  assert_eq!(values["admin"]["service"]["type"], "ClusterIP");
  assert_eq!(
    values["admin"]["mtls"]["enforcement"],
    "required_non_loopback"
  );
  assert_eq!(values["configRollout"]["mode"], "helm_immutable");
  assert_eq!(
    values["configRollout"]["managedConfigPath"],
    "conf.d/gateway-api.generated.toml"
  );
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
  assert_eq!(
    schema["properties"]["configRollout"]["properties"]["mode"]["enum"][1],
    "kubernetes_immutable"
  );
  assert_eq!(
    schema["properties"]["configRollout"]["properties"]["managedConfigPath"]["pattern"],
    "^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)+\\.toml$"
  );
  assert_eq!(
    schema["properties"]["config"]["properties"]["key"]["not"]["const"],
    "gateway-config-directory"
  );
  assert_eq!(
    schema["properties"]["config"]["properties"]["key"]["pattern"],
    "^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$"
  );
  assert_eq!(
    schema["allOf"][0]["then"]["properties"]["config"]["properties"]["existingConfigMapDigest"]["pattern"],
    "^[a-f0-9]{64}$"
  );
  assert_eq!(
    schema["properties"]["admin"]["properties"]["bindAddress"]["enum"][3],
    "::"
  );
  assert_eq!(
    schema["properties"]["admin"]["properties"]["mtls"]["properties"]["enforcement"]["enum"][1],
    "required_external"
  );
  assert_eq!(
    schema["properties"]["admin"]["properties"]["mtls"]["properties"]["verifyDepth"]["maximum"],
    255
  );

  let admin_mtls_example = read_yaml("deploy/helm/oxibelt/examples/admin-mtls-values.yaml");
  assert_eq!(admin_mtls_example["admin"]["service"]["type"], "ClusterIP");
  assert_eq!(admin_mtls_example["admin"]["tls"]["enabled"], true);
  assert_eq!(admin_mtls_example["admin"]["mtls"]["enabled"], true);
  assert_eq!(
    admin_mtls_example["admin"]["tls"]["serverNames"][0],
    "oxibelt-admin.oxibelt.svc.cluster.local"
  );
}

#[test]
fn data_plane_chart_templates_cover_production_runtime_contracts() {
  let expected = [
    "templates/_helpers.tpl",
    "templates/NOTES.txt",
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
    "name: {{ required \"tls.secretName is required when tls.enabled=true\"",
    "projected:",
    "defaultMode: 288",
    "admin-server/tls.crt",
    "admin-client-ca/ca.crt",
    "emptyDir: {}",
    "OXIBELT_ADMIN_TOKEN",
    "maxUnavailable: {{ .Values.workload.deployment.maxUnavailable }}",
    "maxSurge: {{ .Values.workload.deployment.maxSurge }}",
    "checksum/oxibelt-config",
    "OXIBELT_CONFIG_ROLLOUT_MODE",
    "OXIBELT_CONFIG_REVISION",
    "OXIBELT_CONFIG_DIGEST",
    "OXIBELT_CONFIG_REVISION_FILE",
    "OXIBELT_INSTANCE_ID",
    "oxibelt.dev/immutable-config-rollout",
    "{{- if not .Values.config.existingConfigMap }}\n        oxibelt.dev/config-revision: {{ include \"oxibelt.configMapName\" . | quote }}",
    "oxibelt.dev/config-digest: {{ \"\" | sha256sum | quote }}",
    "gateway-config-directory",
    "command: [\"/usr/local/bin/oxibelt\"]",
    "oxibelt.validateAdmin",
  ] {
    assert!(
      deployment.contains(needle),
      "deployment template should contain {needle}"
    );
  }
  assert!(
    !deployment.contains("- name: gateway-config"),
    "the data chart must leave the controller-owned ConfigMap volume and mount absent"
  );
  assert_eq!(
    deployment
      .matches("oxibelt.dev/immutable-config-rollout")
      .count(),
    2,
    "Deployment must opt in at both workload and Pod-template metadata"
  );
  assert!(deployment.contains(
    "{{ if eq .Values.configRollout.mode \"kubernetes_immutable\" }}\n          - key: gateway-config-directory"
  ));
  assert_eq!(
    deployment
      .matches("- key: gateway-config-directory")
      .count(),
    2,
    "Deployment must retain the compatibility sentinel and project the exact managed placeholder"
  );
  assert!(deployment.contains("path: {{ .Values.configRollout.managedConfigPath | quote }}"));

  let daemonset = read_repo("deploy/helm/oxibelt/templates/daemonset.yaml");
  for needle in [
    "minReadySeconds: {{ .Values.workload.daemonSet.minReadySeconds }}",
    "maxUnavailable: {{ .Values.workload.daemonSet.maxUnavailable }}",
    "checksum/oxibelt-config",
    "OXIBELT_CONFIG_ROLLOUT_MODE",
    "{{- if not .Values.config.existingConfigMap }}\n        oxibelt.dev/config-revision: {{ include \"oxibelt.configMapName\" . | quote }}",
    "oxibelt.dev/config-digest: {{ \"\" | sha256sum | quote }}",
    "gateway-config-directory",
    "command: [\"/usr/local/bin/oxibelt\"]",
    "oxibelt.validateAdmin",
    "projected:",
    "defaultMode: 288",
    "admin-server/tls.crt",
    "admin-client-ca/ca.crt",
  ] {
    assert!(
      daemonset.contains(needle),
      "DaemonSet template should contain {needle}"
    );
  }
  assert_eq!(
    daemonset
      .matches("oxibelt.dev/immutable-config-rollout")
      .count(),
    2,
    "DaemonSet must opt in at both workload and Pod-template metadata"
  );
  assert!(daemonset.contains(
    "{{ if eq .Values.configRollout.mode \"kubernetes_immutable\" }}\n          - key: gateway-config-directory"
  ));
  assert_eq!(
    daemonset.matches("- key: gateway-config-directory").count(),
    2,
    "DaemonSet must retain the compatibility sentinel and project the exact managed placeholder"
  );
  assert!(daemonset.contains("path: {{ .Values.configRollout.managedConfigPath | quote }}"));

  let configmap = read_repo("deploy/helm/oxibelt/templates/configmap.yaml");
  for needle in [
    "immutable: true",
    "helm.sh/resource-policy: keep",
    "oxibelt.dev/config-digest",
    "gateway-config-directory",
    "gateway-config-directory: \"\"",
    "oxibelt.validateAdmin",
  ] {
    assert!(
      configmap.contains(needle),
      "ConfigMap template should contain {needle}"
    );
  }

  let helpers = read_repo("deploy/helm/oxibelt/templates/_helpers.tpl");
  for needle in [
    "oxibelt.generatedConfigDigest",
    "oxibelt-helm-config-v1",
    "sha256sum",
    "existingConfigMapDigest",
    "oxiruleConfigMapDigest",
    "validateBaseConfigKey",
    "nested relative TOML path",
    "validateWorkloadRollout",
    "progressDeadlineSeconds must be greater than",
    "oxibelt.validateAdmin",
    "required_non_loopback",
    "admin.insecureDevelopmentMode.enabled",
    "oxibelt.adminConfig",
    "admin-server/tls.crt",
  ] {
    assert!(
      helpers.contains(needle),
      "data chart helper should contain {needle}"
    );
  }

  let notes = read_repo("deploy/helm/oxibelt/templates/NOTES.txt");
  assert!(notes.contains("WARNING: the Admin Service is externally exposed without mTLS."));
  assert!(notes.contains("admin.mtls.enforcement"));

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
  assert_eq!(values["rollout"]["target"]["kind"], "deployment");
  assert_eq!(values["rollout"]["target"]["name"], "oxibelt");
  assert_eq!(values["rollout"]["volumeName"], "gateway-config");
  assert_eq!(values["rollout"]["timeoutSeconds"], 300);
  assert!(values["rollout"].get("retainedRevisions").is_none());
  assert!(values.get("admin").is_none());
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
  assert_eq!(
    schema["properties"]["rollout"]["properties"]["target"]["properties"]["kind"]["enum"][1],
    "daemonset"
  );
  assert_eq!(
    schema["properties"]["managedConfigPath"]["pattern"],
    "^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)+\\.toml$"
  );
  assert!(
    schema["properties"]["rollout"]["properties"]
      .get("retainedRevisions")
      .is_none()
  );

  let deployment = read_repo("deploy/helm/oxibelt-gateway-controller/templates/deployment.yaml");
  assert!(deployment.contains("--backend-resolution={{ .Values.backendResolution }}"));
  assert!(deployment.contains("--status-service={{ .Values.statusService }}"));
  assert!(deployment.contains("strategy:\n    type: Recreate"));
  assert!(deployment.contains("validateManagedConfigPath"));
  let rollout_arguments = [
    "--rollout-target-namespace=",
    "--rollout-target-kind=",
    "--rollout-target-name=",
    "--rollout-target-container-name=",
    "--rollout-volume-name=",
    "--rollout-timeout-seconds=",
    "--rollout-config-map-prefix=",
  ];
  for needle in rollout_arguments {
    assert!(
      deployment.contains(needle),
      "controller deployment should contain {needle}"
    );
  }
  let run_position = deployment
    .find("- \"run\"")
    .expect("controller deployment should invoke the run subcommand");
  for needle in rollout_arguments {
    let argument_position = deployment
      .find(needle)
      .expect("controller deployment should contain every rollout argument");
    assert!(
      run_position < argument_position,
      "controller subcommand `run` must precede {needle}"
    );
  }
  assert!(!deployment.contains("--admin-"));
  assert!(!deployment.contains("admin-token"));
  assert!(deployment.contains("securityContext"));
  assert!(deployment.contains("startupProbe"));

  let rbac = read_repo("deploy/helm/oxibelt-gateway-controller/templates/rbac.yaml");
  assert!(rbac.contains("gatewayclasses"));
  assert!(rbac.contains("services"));
  assert!(rbac.contains("kind: Role"));
  let rollout_role = rbac
    .split("kind: Role\n")
    .nth(1)
    .and_then(|section| section.split("\n---").next())
    .expect("target-namespace rollout Role should be present");
  assert!(rollout_role.contains("resources: [\"configmaps\"]\n  verbs: [\"get\", \"create\"]"));
  assert!(rollout_role.contains("resources: [\"pods\"]\n  verbs: [\"list\"]"));
  assert!(rollout_role.contains("resources: [\"replicasets\"]\n  verbs: [\"list\"]"));
  assert!(rollout_role.contains("{{- if eq $targetKind \"deployment\" }}"));
  assert!(rollout_role.contains("resourceNames:"));
  assert!(rollout_role.contains("verbs: [\"get\", \"patch\"]"));
  assert!(!rollout_role.contains("watch"));
  assert!(!rollout_role.contains("delete"));
  assert!(!rbac.contains("secrets"));
}
