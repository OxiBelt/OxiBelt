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
  assert_eq!(values["image"]["digest"], "");
  assert_eq!(values["replicaCount"], 2);
  assert_eq!(values["workload"]["kind"], "Deployment");
  assert_eq!(values["workload"]["deployment"]["maxUnavailable"], 0);
  assert_eq!(values["workload"]["deployment"]["maxSurge"], 1);
  assert_eq!(values["workload"]["daemonSet"]["maxUnavailable"], 1);
  assert_eq!(values["workload"]["daemonSet"]["maxSurge"], 0);
  assert_eq!(values["service"]["type"], "LoadBalancer");
  assert!(values["service"]["additionalPorts"].is_array());
  assert_eq!(
    values["service"]["additionalPorts"]
      .as_array()
      .unwrap()
      .len(),
    0
  );
  assert_eq!(values["service"]["ports"]["http3"]["targetPort"], 8443);
  assert_eq!(values["operationalProfile"]["name"], "");
  assert_eq!(values["operationalProfile"]["version"], 1);
  assert_eq!(values["operationalProfile"]["wafMode"], "enforcing");
  assert_eq!(values["tls"]["secretName"], "oxibelt-tls");
  assert!(values["tls"]["serverNames"].is_array());
  assert_eq!(values["quic"]["hostKeySecretName"], "");
  assert_eq!(values["quic"]["hostKeySecretKey"], "quic-host-key.b64");
  assert_eq!(values["lifecycle"]["terminationGracePeriodSeconds"], 0);
  assert_eq!(values["lifecycle"]["preStop"]["enabled"], false);
  assert_eq!(values["lifecycle"]["preStop"]["drainSeconds"], 300);
  assert_eq!(values["autoscaling"]["enabled"], false);
  assert_eq!(values["autoscaling"]["minReplicas"], 2);
  assert_eq!(values["autoscaling"]["maxReplicas"], 10);
  assert_eq!(values["autoscaling"]["activeRequests"]["enabled"], false);
  assert_eq!(
    values["autoscaling"]["activeRequests"]["targetAverageValue"],
    24
  );
  assert_eq!(
    values["autoscaling"]["scaleDown"]["stabilizationWindowSeconds"],
    300
  );
  assert_eq!(values["autoscaling"]["scaleDown"]["periodSeconds"], 300);
  assert_eq!(values["podDistribution"]["enabled"], false);
  assert_eq!(values["podDistribution"]["nodeSpread"]["maxSkew"], 1);
  assert_eq!(values["podDistribution"]["nodeSpread"]["minDomains"], 2);
  assert_eq!(
    values["podDistribution"]["nodeSpread"]["whenUnsatisfiable"],
    "DoNotSchedule"
  );
  assert_eq!(
    values["podDistribution"]["zoneSpread"]["whenUnsatisfiable"],
    "ScheduleAnyway"
  );
  assert_eq!(
    values["podDistribution"]["podAntiAffinity"]["enabled"],
    true
  );
  assert_eq!(values["podDistribution"]["podAntiAffinity"]["weight"], 100);
  assert_eq!(values["podDisruptionBudget"]["enabled"], true);
  assert_eq!(values["podDisruptionBudget"]["minAvailable"], 1);
  assert!(values["podDisruptionBudget"]["maxUnavailable"].is_null());
  assert_eq!(
    values["podDisruptionBudget"]["unhealthyPodEvictionPolicy"],
    ""
  );
  assert_eq!(
    values["serviceAccount"]["automountServiceAccountToken"],
    false
  );
  assert_eq!(
    values["kubernetesDiscovery"]["serviceAccountToken"]["enabled"],
    false
  );
  assert_eq!(
    values["kubernetesDiscovery"]["serviceAccountToken"]["expirationSeconds"],
    3600
  );
  assert_eq!(values["kubernetesDiscovery"]["rbac"]["create"], false);
  assert!(values["kubernetesDiscovery"]["rbac"]["namespaces"].is_array());
  assert!(values["sharedState"]["redisSecretProjections"].is_array());
  assert_eq!(values["networkPolicy"]["enabled"], false);
  assert_eq!(
    values["networkPolicy"]["ingress"]["public"]["allowAll"],
    false
  );
  assert!(values["networkPolicy"]["egress"]["destinations"].is_array());
  assert_eq!(values["networkPolicy"]["cilium"]["enabled"], false);
  assert!(values["networkPolicy"]["cilium"]["fqdnDestinations"].is_array());
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
    schema["properties"]["image"]["properties"]["digest"]["pattern"],
    "^$|^sha256:[0-9a-f]{64}$"
  );
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
    schema["properties"]["sharedState"]["properties"]["redisSecretProjections"]["items"]["properties"]
      ["items"]["items"]["properties"]["path"]["pattern"],
    "^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$"
  );
  assert_eq!(
    schema["allOf"][0]["then"]["properties"]["config"]["properties"]["existingConfigMapDigest"]["pattern"],
    "^[a-f0-9]{64}$"
  );
  assert_eq!(
    schema["allOf"][5]["if"]["properties"]["config"]["properties"]["create"]["const"],
    false
  );
  assert_eq!(
    schema["allOf"][5]["then"]["properties"]["config"]["properties"]["existingConfigMap"]["minLength"],
    1
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
  assert_eq!(
    schema["properties"]["operationalProfile"]["properties"]["name"]["enum"][1],
    "edge-secure-medium"
  );
  assert_eq!(
    schema["properties"]["operationalProfile"]["properties"]["wafMode"]["enum"][1],
    "monitor"
  );
  assert_eq!(
    schema["properties"]["lifecycle"]["properties"]["preStop"]["properties"]["drainSeconds"]["maximum"],
    86400
  );
  assert_eq!(
    schema["properties"]["autoscaling"]["properties"]["activeRequests"]["properties"]["targetAverageValue"]
      ["minimum"],
    1
  );
  assert_eq!(
    schema["properties"]["autoscaling"]["properties"]["scaleDown"]["properties"]["stabilizationWindowSeconds"]
      ["maximum"],
    3600
  );
  assert_eq!(
    schema["properties"]["autoscaling"]["properties"]["scaleDown"]["properties"]["periodSeconds"]["maximum"],
    1800
  );
  assert_eq!(
    schema["properties"]["podDistribution"]["properties"]["nodeSpread"]["properties"]["minDomains"]
      ["minimum"],
    1
  );
  assert_eq!(
    schema["properties"]["podDistribution"]["properties"]["zoneSpread"]["properties"]["whenUnsatisfiable"]
      ["enum"][1],
    "ScheduleAnyway"
  );
  assert_eq!(
    schema["properties"]["podDisruptionBudget"]["properties"]["maxUnavailable"]["anyOf"][1]["type"],
    "null"
  );
  assert_eq!(
    schema["properties"]["podDisruptionBudget"]["properties"]["unhealthyPodEvictionPolicy"]["enum"]
      [2],
    "AlwaysAllow"
  );
  assert_eq!(
    schema["properties"]["quic"]["properties"]["hostKeySecretKey"]["pattern"],
    "^[A-Za-z0-9._-]+$"
  );
  assert_eq!(
    schema["properties"]["networkPolicy"]["properties"]["enabled"]["type"],
    "boolean"
  );
  assert_eq!(
    schema["properties"]["service"]["properties"]["additionalPorts"]["maxItems"],
    32
  );
  assert_eq!(
    schema["definitions"]["additionalServicePort"]["properties"]["targetPort"]["minimum"],
    1024
  );
  assert_eq!(
    schema["properties"]["serviceAccount"]["properties"]["automountServiceAccountToken"]["const"],
    false
  );
  assert_eq!(
    schema["properties"]["kubernetesDiscovery"]["properties"]["serviceAccountToken"]["properties"]
      ["expirationSeconds"]["minimum"],
    600
  );
  assert_eq!(
    schema["properties"]["kubernetesDiscovery"]["properties"]["serviceAccountToken"]["properties"]
      ["expirationSeconds"]["maximum"],
    3600
  );
  assert_eq!(
    schema["properties"]["kubernetesDiscovery"]["properties"]["rbac"]["properties"]["namespaces"]["uniqueItems"],
    true
  );
  assert_eq!(
    schema["definitions"]["networkPolicyPeer"]["oneOf"]
      .as_array()
      .unwrap()
      .len(),
    2
  );
  assert_eq!(
    schema["definitions"]["ciliumFqdnDestination"]["properties"]["matchNames"]["items"]["pattern"],
    "^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
  );

  let admin_mtls_example = read_yaml("deploy/helm/oxibelt/examples/admin-mtls-values.yaml");
  assert_eq!(admin_mtls_example["admin"]["service"]["type"], "ClusterIP");
  assert_eq!(admin_mtls_example["admin"]["tls"]["enabled"], true);
  assert_eq!(admin_mtls_example["admin"]["mtls"]["enabled"], true);
  assert_eq!(
    admin_mtls_example["admin"]["tls"]["serverNames"][0],
    "oxibelt-admin.oxibelt.svc.cluster.local"
  );

  let edge_secure_medium_example =
    read_yaml("deploy/helm/oxibelt/examples/edge-secure-medium-v1-values.yaml");
  assert_eq!(
    edge_secure_medium_example["operationalProfile"]["name"],
    "edge-secure-medium"
  );
  assert_eq!(
    edge_secure_medium_example["operationalProfile"]["version"],
    1
  );
  assert_eq!(
    edge_secure_medium_example["tls"]["serverNames"][0],
    "edge.example.test"
  );
  assert_eq!(
    edge_secure_medium_example["quic"]["hostKeySecretKey"],
    "quic-host-key.b64"
  );
  assert_eq!(
    edge_secure_medium_example["lifecycle"]["terminationGracePeriodSeconds"],
    360
  );
  assert_eq!(
    edge_secure_medium_example["lifecycle"]["preStop"]["enabled"],
    true
  );
  assert_eq!(
    edge_secure_medium_example["lifecycle"]["preStop"]["drainSeconds"],
    300
  );
  assert_eq!(edge_secure_medium_example["replicaCount"], 3);
  assert_eq!(edge_secure_medium_example["autoscaling"]["minReplicas"], 3);
  assert_eq!(
    edge_secure_medium_example["workload"]["daemonSet"]["maxUnavailable"],
    0
  );
  assert_eq!(
    edge_secure_medium_example["workload"]["daemonSet"]["maxSurge"],
    1
  );
  assert_eq!(
    edge_secure_medium_example["podDistribution"]["enabled"],
    true
  );
  assert_eq!(
    edge_secure_medium_example["podDistribution"]["nodeSpread"]["whenUnsatisfiable"],
    "DoNotSchedule"
  );
  assert_eq!(
    edge_secure_medium_example["podDistribution"]["zoneSpread"]["whenUnsatisfiable"],
    "ScheduleAnyway"
  );
  assert_eq!(
    edge_secure_medium_example["podDistribution"]["podAntiAffinity"]["weight"],
    100
  );
  assert!(edge_secure_medium_example["podDisruptionBudget"]["minAvailable"].is_null());
  assert_eq!(
    edge_secure_medium_example["podDisruptionBudget"]["maxUnavailable"],
    1
  );
  assert_eq!(
    edge_secure_medium_example["podDisruptionBudget"]["unhealthyPodEvictionPolicy"],
    "AlwaysAllow"
  );
  assert_eq!(
    edge_secure_medium_example["admin"]["service"]["enabled"],
    false
  );
  assert_eq!(edge_secure_medium_example["networkPolicy"]["enabled"], true);
  assert_eq!(
    edge_secure_medium_example["networkPolicy"]["ingress"]["public"]["allowAll"],
    true
  );
  assert_eq!(
    edge_secure_medium_example["networkPolicy"]["ingress"]["metrics"]["from"][0]["namespaceSelector"]
      ["matchLabels"]["kubernetes.io/metadata.name"],
    "monitoring"
  );
  assert_eq!(
    edge_secure_medium_example["networkPolicy"]["cilium"]["enabled"],
    false
  );

  let edge_secure_medium_autoscaling_example =
    read_yaml("deploy/helm/oxibelt/examples/edge-secure-medium-v1-autoscaling-values.yaml");
  assert_eq!(
    edge_secure_medium_autoscaling_example["autoscaling"]["enabled"],
    true
  );
  assert_eq!(
    edge_secure_medium_autoscaling_example["autoscaling"]["minReplicas"],
    3
  );
  assert_eq!(
    edge_secure_medium_autoscaling_example["autoscaling"]["activeRequests"]["enabled"],
    true
  );
  assert_eq!(
    edge_secure_medium_autoscaling_example["autoscaling"]["activeRequests"]["targetAverageValue"],
    24
  );
  assert_eq!(
    edge_secure_medium_autoscaling_example["autoscaling"]["scaleDown"]["stabilizationWindowSeconds"],
    300
  );
  assert_eq!(
    edge_secure_medium_autoscaling_example["autoscaling"]["scaleDown"]["periodSeconds"],
    360
  );
}

#[test]
fn data_plane_chart_templates_cover_production_runtime_contracts() {
  assert!(
    repo_root()
      .join("tests/scripts/check-helm-image-digest.sh")
      .is_file(),
    "the Helm image digest renderer check should be present"
  );
  assert!(
    repo_root()
      .join("tests/scripts/check-helm-edge-secure-medium-profile.sh")
      .is_file(),
    "the edge-secure-medium Helm renderer check should be present"
  );
  assert!(
    repo_root()
      .join("tests/scripts/check-helm-network-policy.sh")
      .is_file(),
    "the NetworkPolicy Helm renderer check should be present"
  );
  assert!(
    repo_root()
      .join("tests/scripts/check-helm-service-account-token.sh")
      .is_file(),
    "the ServiceAccount token Helm renderer check should be present"
  );
  assert!(
    repo_root()
      .join("tests/scripts/check-helm-pod-lifecycle.sh")
      .is_file(),
    "the Pod lifecycle Helm renderer check should be present"
  );
  assert!(
    repo_root()
      .join("tests/scripts/check-helm-autoscaling.sh")
      .is_file(),
    "the autoscaling Helm renderer check should be present"
  );
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
    "templates/networkpolicy.yaml",
    "templates/ciliumnetworkpolicy.yaml",
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
    "sharedState.redisSecretProjections",
    "redis/%s/%s",
    "quic.hostKeySecretName",
    "path: quic-host-key.b64",
    "terminationGracePeriodSeconds",
    "topologySpreadConstraints:",
    "lifecycle:",
    "- {{ include \"oxibelt.imageExecutable\" . }}",
    "- __lifecycle-prestop",
    "- --wait-seconds",
    "oxibelt.deploymentAffinity",
    "oxibelt.cacheVolumeEnabled",
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
    "{{- if and .Values.config.create (not .Values.config.existingConfigMap) }}\n        oxibelt.dev/config-revision: {{ include \"oxibelt.configMapName\" . | quote }}",
    "oxibelt.dev/config-digest: {{ \"\" | sha256sum | quote }}",
    "gateway-config-directory",
    "command: [{{ include \"oxibelt.imageExecutable\" . | quote }}]",
    "oxibelt.validateAdmin",
    "oxibelt.validateKubernetesServiceAccount",
    "automountServiceAccountToken: false",
    "oxibelt.kubernetesApiAccessEnabled",
    "name: kube-api-access",
    "serviceAccountToken:",
    "expirationSeconds: {{ .Values.kubernetesDiscovery.serviceAccountToken.expirationSeconds }}",
    "name: kube-root-ca.crt",
    "image: {{ include \"oxibelt.image\" . | quote }}",
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
    "maxUnavailable: {{ int .Values.workload.daemonSet.maxUnavailable }}",
    "maxSurge: {{ int .Values.workload.daemonSet.maxSurge }}",
    "checksum/oxibelt-config",
    "OXIBELT_CONFIG_ROLLOUT_MODE",
    "{{- if and .Values.config.create (not .Values.config.existingConfigMap) }}\n        oxibelt.dev/config-revision: {{ include \"oxibelt.configMapName\" . | quote }}",
    "oxibelt.dev/config-digest: {{ \"\" | sha256sum | quote }}",
    "gateway-config-directory",
    "command: [{{ include \"oxibelt.imageExecutable\" . | quote }}]",
    "oxibelt.validateAdmin",
    "projected:",
    "defaultMode: 288",
    "admin-server/tls.crt",
    "admin-client-ca/ca.crt",
    "sharedState.redisSecretProjections",
    "redis/%s/%s",
    "quic.hostKeySecretName",
    "path: quic-host-key.b64",
    "terminationGracePeriodSeconds",
    "lifecycle:",
    "- {{ include \"oxibelt.imageExecutable\" . }}",
    "- __lifecycle-prestop",
    "- --wait-seconds",
    "oxibelt.validateKubernetesServiceAccount",
    "automountServiceAccountToken: false",
    "oxibelt.kubernetesApiAccessEnabled",
    "name: kube-api-access",
    "serviceAccountToken:",
    "expirationSeconds: {{ .Values.kubernetesDiscovery.serviceAccountToken.expirationSeconds }}",
    "name: kube-root-ca.crt",
    "image: {{ include \"oxibelt.image\" . | quote }}",
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
    "oxibelt.validateOperationalProfile",
  ] {
    assert!(
      configmap.contains(needle),
      "ConfigMap template should contain {needle}"
    );
  }

  let helpers = read_repo("deploy/helm/oxibelt/templates/_helpers.tpl");
  for needle in [
    "oxibelt.image",
    "image.digest must be an empty string or a lower-case sha256 digest",
    "oxibelt.generatedConfigDigest",
    "oxibelt-helm-config-v1",
    "sha256sum",
    "config.existingConfigMap is required when config.create=false",
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
    "validateRedisSecretProjections",
    "sharedState.redisSecretProjections[].items[].path",
    "oxibelt.operationalProfileConfig",
    "oxibelt.operationalProfileWafConfig",
    "oxibelt.validateOperationalProfile",
    "quic.hostKeySecretName",
    "lifecycle.terminationGracePeriodSeconds",
    "oxibelt.validateLifecycle",
    "lifecycle.preStop.drainSeconds",
    "oxibelt.validateAutoscaling",
    "autoscaling.activeRequests.enabled=true requires autoscaling.enabled=true",
    "autoscaling.activeRequests.enabled=true requires metrics.enabled=true",
    "autoscaling.activeRequests.enabled=true requires operationalProfile.name=edge-secure-medium",
    "autoscaling.scaleDown.stabilizationWindowSeconds",
    "autoscaling.scaleDown.periodSeconds",
    "oxibelt.validatePodDistribution",
    "podDistribution.podAntiAffinity.enabled cannot be combined",
    "oxibelt.validatePodDisruptionBudget",
    "podDisruptionBudget requires exactly one of minAvailable or maxUnavailable",
    "oxibelt.deploymentAffinity",
    "oxibelt.validateNetworkPolicy",
    "oxibelt.validateAdditionalServicePorts",
    "service.additionalPorts[].targetPort must be an unprivileged numeric port",
    "networkPolicy.cilium.enabled requires networkPolicy.enabled=true",
    "kubernetes-api egress destination",
    "oxibelt.ciliumSelectorLabels",
    "oxibelt.kubernetesApiAccessEnabled",
    "oxibelt.validateKubernetesServiceAccount",
    "kubernetesDiscovery.serviceAccountToken.enabled",
    "kubernetesDiscovery.rbac.namespaces",
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
  assert!(service.contains("range $port := .Values.service.additionalPorts"));
  assert!(service.contains("targetPort: {{ $port.targetPort }}"));
  assert!(deployment.contains("containerPort: {{ $port.targetPort }}"));
  assert!(daemonset.contains("containerPort: {{ $port.targetPort }}"));

  let pdb = read_repo("deploy/helm/oxibelt/templates/pdb.yaml");
  assert!(pdb.contains("kind: PodDisruptionBudget"));
  assert!(pdb.contains("maxUnavailable"));
  assert!(pdb.contains("unhealthyPodEvictionPolicy"));

  let hpa = read_repo("deploy/helm/oxibelt/templates/hpa.yaml");
  assert!(hpa.contains("apiVersion: autoscaling/v2"));
  assert!(hpa.contains("kind: HorizontalPodAutoscaler"));
  assert!(hpa.contains("oxibelt.validateAutoscaling"));
  assert!(hpa.contains("name: oxibelt_active_http_requests"));
  assert!(hpa.contains("type: AverageValue"));
  assert!(hpa.contains("selectPolicy: Min"));

  let metrics = read_repo("deploy/helm/oxibelt/templates/metrics-service.yaml");
  assert!(metrics.contains("targetPort: metrics"));

  let rbac = read_repo("deploy/helm/oxibelt/templates/rbac.yaml");
  assert!(rbac.contains("endpointslices"));
  assert!(rbac.contains("kind: Role"));
  assert!(rbac.contains("kind: RoleBinding"));
  assert!(rbac.contains("verbs: [\"list\", \"watch\"]"));
  assert!(rbac.contains("resources: [\"endpoints\"]\n  verbs: [\"get\"]"));
  assert!(rbac.contains("kubernetesDiscovery.rbac.namespaces"));
  assert!(!rbac.contains("kind: ClusterRole"));
  assert!(!rbac.contains("resources: [\"endpoints\", \"services\"]"));

  let network_policy = read_repo("deploy/helm/oxibelt/templates/networkpolicy.yaml");
  for needle in [
    "kind: NetworkPolicy",
    "public-ingress",
    "metrics-ingress",
    "admin-ingress",
    "port\" \"http\"",
    "port\" \"http3\"",
    ".Values.service.additionalPorts",
    "networkPolicy.egress.destinations",
    "policyTypes",
  ] {
    assert!(
      network_policy.contains(needle),
      "NetworkPolicy template should contain {needle}"
    );
  }

  let cilium_network_policy = read_repo("deploy/helm/oxibelt/templates/ciliumnetworkpolicy.yaml");
  for needle in [
    "kind: CiliumNetworkPolicy",
    "toFQDNs",
    "fqdn-egress",
    "matchPattern: \"*\"",
    "oxibelt.ciliumSelectorLabels",
    "networkPolicy.cilium.enabled",
  ] {
    assert!(
      cilium_network_policy.contains(needle),
      "Cilium NetworkPolicy template should contain {needle}"
    );
  }
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
  assert_eq!(values["image"]["digest"], "");
  assert_eq!(values["replicaCount"], 2);
  assert_eq!(values["leaderElection"]["leaseName"], "");
  assert_eq!(values["leaderElection"]["leaseDurationSeconds"], 15);
  assert_eq!(values["leaderElection"]["renewDeadlineSeconds"], 10);
  assert_eq!(values["leaderElection"]["retryPeriodSeconds"], 2);
  assert_eq!(values["podDisruptionBudget"]["enabled"], true);
  assert_eq!(values["podDisruptionBudget"]["minAvailable"], 1);
  assert_eq!(values["podAntiAffinity"]["enabled"], true);
  assert_eq!(values["controllerName"], "oxibelt.dev/gateway-controller");
  assert_eq!(values["backendResolution"], "cluster_dns");
  assert_eq!(values["l4"]["bindAddress"], "0.0.0.0");
  assert_eq!(values["l4"]["connectTimeoutMs"], 3000);
  assert_eq!(values["l4"]["idleTimeoutMs"], 75000);
  assert_eq!(values["l4"]["udp"]["flowState"], "disabled");
  assert_eq!(values["l4"]["udp"]["maxFlows"], 3072);
  assert_eq!(values["l4"]["udp"]["newFlowRate"], "200r/s");
  assert_eq!(values["l4"]["udp"]["batch"], "auto");
  assert_eq!(values["l4"]["udp"]["batchSize"], 16);
  assert_eq!(values["rollout"]["target"]["kind"], "deployment");
  assert_eq!(values["rollout"]["target"]["name"], "oxibelt");
  assert_eq!(values["rollout"]["volumeName"], "gateway-config");
  assert_eq!(values["rollout"]["timeoutSeconds"], 300);
  assert!(values["rollout"].get("retainedRevisions").is_none());
  assert!(values.get("admin").is_none());
  assert_eq!(values["watchNamespace"], "");
  assert_eq!(values["watchAllNamespaces"], false);
  assert!(values["statusAddresses"].is_array());
  assert_eq!(values["statusAddresses"].as_array().unwrap().len(), 0);
  assert_eq!(
    values["serviceAccount"]["automountServiceAccountToken"],
    false
  );
  assert_eq!(
    values["serviceAccount"]["tokenProjection"]["expirationSeconds"],
    3600
  );
  assert_eq!(values["securityContext"]["readOnlyRootFilesystem"], true);
  assert_eq!(values["podSecurityContext"]["runAsNonRoot"], true);
  assert_eq!(values["podSecurityContext"]["fsGroup"], 10001);
  assert!(values["resources"].is_object());

  let schema: Value = serde_json::from_str(&read_repo(
    "deploy/helm/oxibelt-gateway-controller/values.schema.json",
  ))
  .expect("gateway controller values schema should parse");
  assert_eq!(
    schema["properties"]["image"]["properties"]["digest"]["pattern"],
    "^$|^sha256:[0-9a-f]{64}$"
  );
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
  assert_eq!(
    schema["properties"]["watchAllNamespaces"]["type"],
    "boolean"
  );
  assert_eq!(schema["properties"]["statusAddresses"]["maxItems"], 16);
  assert_eq!(schema["properties"]["statusAddresses"]["uniqueItems"], true);
  assert_eq!(
    schema["properties"]["l4"]["properties"]["udp"]["properties"]["flowState"]["enum"][1],
    "shared_required"
  );
  assert_eq!(
    schema["properties"]["l4"]["properties"]["udp"]["properties"]["maxFlows"]["maximum"],
    1048576
  );
  assert_eq!(
    schema["properties"]["serviceAccount"]["properties"]["automountServiceAccountToken"]["const"],
    false
  );
  assert_eq!(
    schema["properties"]["serviceAccount"]["properties"]["tokenProjection"]["properties"]["expirationSeconds"]
      ["maximum"],
    3600
  );
  assert_eq!(schema["properties"]["replicaCount"]["minimum"], 1);
  assert_eq!(
    schema["properties"]["leaderElection"]["properties"]["leaseDurationSeconds"]["minimum"],
    10
  );
  assert_eq!(
    schema["properties"]["podAntiAffinity"]["properties"]["weight"]["maximum"],
    100
  );

  let deployment = read_repo("deploy/helm/oxibelt-gateway-controller/templates/deployment.yaml");
  assert!(
    deployment.contains("image: {{ include \"oxibelt-gateway-controller.image\" . | quote }}")
  );
  let helpers = read_repo("deploy/helm/oxibelt-gateway-controller/templates/_helpers.tpl");
  assert!(helpers.contains("oxibelt-gateway-controller.image"));
  assert!(helpers.contains("image.digest must be an empty string or a lower-case sha256 digest"));
  assert!(deployment.contains("--backend-resolution={{ .Values.backendResolution }}"));
  assert!(deployment.contains("--status-service={{ .Values.statusService }}"));
  assert!(deployment.contains("range $address := .Values.statusAddresses"));
  assert!(deployment.contains("--status-address={{ $address }}"));
  for argument in [
    "--l4-bind-address=",
    "--l4-connect-timeout-ms=",
    "--l4-idle-timeout-ms=",
    "--udp-flow-state=",
    "--udp-max-flows=",
    "--udp-new-flow-rate=",
    "--udp-new-flow-burst=",
    "--udp-datagram-rate=",
    "--udp-datagram-burst=",
    "--udp-batch=",
    "--udp-batch-size=",
  ] {
    assert!(
      deployment.contains(argument),
      "controller deployment should contain {argument}"
    );
  }
  assert!(deployment.contains("replicas: {{ .Values.replicaCount }}"));
  assert!(deployment.contains("strategy:\n    type: RollingUpdate"));
  assert!(deployment.contains("maxUnavailable: 0"));
  assert!(deployment.contains("maxSurge: 1"));
  assert!(!deployment.contains("type: Recreate"));
  assert!(deployment.contains("validateManagedConfigPath"));
  assert!(deployment.contains("validateSecurity"));
  assert!(deployment.contains("automountServiceAccountToken: false"));
  assert!(deployment.contains("--watch-namespace={{ $watchNamespace }}"));
  assert!(deployment.contains("if not .Values.watchAllNamespaces"));
  assert!(deployment.contains("name: kube-api-access"));
  assert!(deployment.contains("serviceAccountToken:"));
  assert!(
    deployment.contains(
      "expirationSeconds: {{ .Values.serviceAccount.tokenProjection.expirationSeconds }}"
    )
  );
  assert!(deployment.contains("name: kube-root-ca.crt"));
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
  assert!(deployment.contains("--leader-election-namespace={{ .Release.Namespace }}"));
  assert!(deployment.contains("--leader-election-lease-name="));
  assert!(deployment.contains("--leader-election-lease-duration-seconds="));
  assert!(deployment.contains("--leader-election-renew-deadline-seconds="));
  assert!(deployment.contains("--leader-election-retry-period-seconds="));
  assert!(deployment.contains("fieldPath: metadata.name"));
  assert!(deployment.contains("fieldPath: metadata.uid"));
  assert!(deployment.contains("preferredDuringSchedulingIgnoredDuringExecution"));

  let rbac = read_repo("deploy/helm/oxibelt-gateway-controller/templates/rbac.yaml");
  assert!(rbac.contains("gatewayclasses"));
  assert!(rbac.contains("services"));
  assert!(rbac.contains("udproutes"));
  assert!(rbac.contains("backendtlspolicies"));
  assert!(rbac.contains("udproutes/status"));
  assert!(rbac.contains("backendtlspolicies/status"));
  assert!(rbac.contains("watchAllNamespaces"));
  assert!(rbac.contains("-cluster"));
  assert!(rbac.contains("-watch"));
  assert!(rbac.contains("resourceNames:"));
  assert!(rbac.contains("resources: [\"namespaces\"]"));
  assert!(rbac.contains("verbs: [\"list\"]"));
  assert!(rbac.contains("verbs: [\"patch\"]"));
  assert!(rbac.contains("kind: Role"));
  let rollout_role = rbac
    .split("name: {{ include \"oxibelt-gateway-controller.name\" . }}-rollout")
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
  assert!(!rbac.contains("verbs: [\"get\", \"list\", \"watch\"]"));
  assert!(!rbac.contains("verbs: [\"get\", \"patch\", \"update\"]"));
  assert!(!rbac.contains("secrets"));
  assert_eq!(
    rbac
      .matches("resources: [\"configmaps\"]\n  verbs: [\"get\"]")
      .count(),
    2,
    "each namespaced and cluster-wide watch mode should grant ConfigMap get without list"
  );

  let leader_role = rbac
    .split("name: {{ include \"oxibelt-gateway-controller.name\" . }}-leader-election")
    .nth(1)
    .and_then(|section| section.split("\n---").next())
    .expect("release-namespace leader-election Role should be present");
  assert!(leader_role.contains("apiGroups: [\"coordination.k8s.io\"]"));
  assert!(leader_role.contains("resources: [\"leases\"]"));
  assert!(leader_role.contains("resourceNames:"));
  assert!(leader_role.contains("verbs: [\"get\", \"watch\", \"patch\"]"));
  assert!(!leader_role.contains("create"));
  assert!(!leader_role.contains("delete"));

  let lease = read_repo("deploy/helm/oxibelt-gateway-controller/templates/lease.yaml");
  assert!(lease.contains("apiVersion: coordination.k8s.io/v1"));
  assert!(lease.contains("kind: Lease"));
  assert!(!lease.contains("spec:"));

  let pdb = read_repo("deploy/helm/oxibelt-gateway-controller/templates/pdb.yaml");
  assert!(pdb.contains("apiVersion: policy/v1"));
  assert!(pdb.contains("kind: PodDisruptionBudget"));
  assert!(pdb.contains("minAvailable: {{ .Values.podDisruptionBudget.minAvailable }}"));
}
