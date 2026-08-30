use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

const FEATURE_IDS: [&str; 15] = [
  "gateway-controller",
  "gateway-api-httproute",
  "gateway-api-grpcroute",
  "gateway-api-tlsroute",
  "gateway-api-tcproute",
  "gateway-api-udproute",
  "gateway-api-backendtlspolicy",
  "gateway-api-weighted-discovery",
  "gateway-api-standard-filters-backend-tls",
  "gateway-api-route-policy",
  "gateway-controller-multi-target",
  "gateway-controller-explain",
  "supply-chain-admission-bundle",
  "helm-data-plane",
  "helm-gateway-controller",
];

const REQUIRED_GATES: [&str; 25] = [
  "policy-contract",
  "unsupported-combination-diagnostics",
  "clean-lifecycle",
  "leader-election-failover",
  "api-outage-recovery",
  "watch-reconnect-compaction",
  "stale-object-convergence",
  "partial-rollout-recovery",
  "network-partition",
  "configmap-propagation",
  "secret-rotation",
  "multi-node",
  "pod-security-restricted",
  "live-supply-chain-admission",
  "network-policy-cnis",
  "previous-minor-interop",
  "long-duration-soak",
  "native-amd64",
  "native-arm64",
  "native-riscv64",
  "gateway-conformance-http",
  "gateway-conformance-grpc",
  "gateway-conformance-tls",
  "gateway-conformance-tcp",
  "gateway-conformance-udp",
];

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate should live below the repository root")
    .to_path_buf()
}

fn read_repo(path: &str) -> String {
  fs::read_to_string(repo_root().join(path))
    .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
}

fn policy() -> Value {
  serde_json::from_str(&read_repo(
    "devops/config/kubernetes-feature-graduation.json",
  ))
  .expect("Kubernetes graduation policy should be valid JSON")
}

fn strings(value: &Value) -> BTreeSet<&str> {
  value
    .as_array()
    .expect("value should be an array")
    .iter()
    .map(|item| item.as_str().expect("array item should be a string"))
    .collect()
}

fn feature_statuses() -> BTreeMap<String, String> {
  read_repo("docs/FeatureStatus.md")
    .lines()
    .filter_map(|line| {
      let mut fields = line.split('|').map(str::trim);
      let _empty = fields.next()?;
      let id = fields.next()?.strip_prefix('`')?.strip_suffix('`')?;
      let status = fields.next()?.strip_prefix('`')?.strip_suffix('`')?;
      Some((id.to_string(), status.to_string()))
    })
    .collect()
}

#[test]
fn graduation_registry_covers_the_complete_support_contract() {
  let policy = policy();
  assert_eq!(policy["schemaVersion"], 2);
  assert_eq!(policy["policyVersion"], 4);
  assert_eq!(policy["lifecycleAuthority"], "docs/FeatureStatus.md");
  assert_eq!(policy["repository"], "OxiBelt/OxiBelt");
  assert_eq!(policy["targetVersion"], "0.8.1");
  assert_eq!(
    policy["supportContract"]["kubernetes"]["range"],
    ">=1.34.0-0 <1.37.0-0"
  );
  assert_eq!(
    strings(&policy["supportContract"]["helm"]["versions"]),
    BTreeSet::from(["3.21.4", "4.2.4"])
  );
  assert_eq!(policy["supportContract"]["gatewayApi"]["version"], "v1.6.1");
  assert_eq!(
    policy["supportContract"]["gatewayApi"]["standardInstallSha256"],
    "24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73"
  );
  assert_eq!(
    policy["supportContract"]["controllerDataPlaneSkew"]["defaultMode"],
    "exact"
  );
  assert_eq!(
    policy["supportContract"]["controllerDataPlaneSkew"]["maximumRollingHours"],
    24
  );
  assert_eq!(
    policy["supportContract"]["podSecurity"]["standard"],
    "restricted"
  );

  let minors = policy["supportContract"]["kubernetes"]["minors"]
    .as_array()
    .expect("Kubernetes minors should be an array");
  let minor_versions = minors
    .iter()
    .map(|minor| {
      (
        minor["minor"].as_str().expect("minor should be a string"),
        minor["ciVersion"]
          .as_str()
          .expect("CI version should be a string"),
        minor["kindNodeImage"]
          .as_str()
          .expect("Kind image should be a string"),
      )
    })
    .collect::<Vec<_>>();
  assert_eq!(
    minor_versions,
    [
      (
        "1.34",
        "v1.34.11",
        "kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d"
      ),
      (
        "1.35",
        "v1.35.8",
        "kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"
      ),
      (
        "1.36",
        "v1.36.4",
        "kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"
      ),
    ]
  );

  let gate_ids = policy["gates"]
    .as_array()
    .expect("gates should be an array")
    .iter()
    .map(|gate| gate["id"].as_str().expect("gate id should be a string"))
    .collect::<BTreeSet<_>>();
  assert_eq!(gate_ids, BTreeSet::from(REQUIRED_GATES));

  let cadence_ids = policy["cadences"]
    .as_array()
    .expect("cadences should be an array")
    .iter()
    .map(|cadence| {
      cadence["id"]
        .as_str()
        .expect("cadence id should be a string")
    })
    .collect::<BTreeSet<_>>();
  assert_eq!(
    cadence_ids,
    BTreeSet::from(["nightly", "pull_request", "release_candidate", "stable"])
  );
}

#[test]
fn lifecycle_policy_uses_detached_feature_scoped_evidence() {
  let policy = policy();
  let status_rows = feature_statuses();
  let gates = policy["gates"]
    .as_array()
    .expect("gates should be an array");
  for gate in gates {
    assert_eq!(gate["mandatory"], true);
    assert!(
      gate.get("status").is_none(),
      "gate state must be detached from the shared descriptor"
    );
    assert!(
      gate.get("evidenceReceipts").is_none(),
      "receipt paths must be detached from the shared descriptor"
    );
  }
  let features = policy["features"]
    .as_array()
    .expect("features should be an array");
  assert_eq!(
    features
      .iter()
      .map(|feature| feature["id"]
        .as_str()
        .expect("feature id should be a string"))
      .collect::<BTreeSet<_>>(),
    BTreeSet::from(FEATURE_IDS)
  );

  for feature in features {
    let id = feature["id"]
      .as_str()
      .expect("feature id should be a string");
    let status = feature["status"]
      .as_str()
      .expect("feature status should be a string");
    assert_eq!(
      status_rows.get(id).map(String::as_str),
      Some(status),
      "policy and docs/FeatureStatus.md must agree for {id}"
    );
    assert_eq!(status, "experimental");
    assert_eq!(feature["lastValidatedVersion"], "unvalidated");
    let platforms = strings(&feature["qualifiedPlatforms"]);
    if id == "supply-chain-admission-bundle" {
      assert_eq!(platforms, BTreeSet::from(["linux/amd64", "linux/arm64"]));
      assert!(!strings(&feature["gateIds"]).contains("native-riscv64"));
      assert!(!strings(&feature["blockerIds"]).contains("native-riscv64-cluster-runner"));
      let required_artifacts = feature["requiredArtifacts"]
        .as_array()
        .expect("required artifacts should be an array")
        .iter()
        .map(|artifact| {
          format!(
            "{}|{}|{}",
            artifact["name"]
              .as_str()
              .expect("artifact name should be a string"),
            artifact["kind"]
              .as_str()
              .expect("artifact kind should be a string"),
            artifact["repository"]
              .as_str()
              .expect("artifact repository should be a string")
          )
        })
        .collect::<BTreeSet<_>>();
      assert_eq!(
        required_artifacts,
        BTreeSet::from([
          "chart-gateway-controller|helm-chart|ghcr.io/oxibelt/charts/oxibelt-gateway-controller"
            .to_string(),
          "chart-oxibelt|helm-chart|ghcr.io/oxibelt/charts/oxibelt".to_string(),
          "image-controller|oci-image|ghcr.io/oxibelt/oxibelt-gateway-controller".to_string(),
          "image-dataplane-strict|oci-image|ghcr.io/oxibelt/oxibelt-dataplane-strict".to_string(),
          "image-dataplane|oci-image|ghcr.io/oxibelt/oxibelt-dataplane".to_string(),
          "image-keysigner|oci-image|ghcr.io/oxibelt/oxibelt-keysigner".to_string(),
          "image-standalone|oci-image|ghcr.io/oxibelt/oxibelt".to_string(),
          "image-tools|oci-image|ghcr.io/oxibelt/oxibelt-tools".to_string(),
        ])
      );
    } else {
      assert_eq!(
        platforms,
        BTreeSet::from(["linux/amd64", "linux/arm64", "linux/riscv64"])
      );
      assert!(strings(&feature["gateIds"]).contains("native-riscv64"));
      assert!(strings(&feature["blockerIds"]).contains("native-riscv64-cluster-runner"));
      assert!(
        feature["requiredArtifacts"]
          .as_array()
          .expect("required artifacts should be an array")
          .is_empty(),
        "only the supply-chain row should bind the release artifact inventory"
      );
    }
  }

  let evidence_schema: Value = serde_json::from_str(&read_repo(
    "devops/config/kubernetes-feature-graduation-evidence.schema.json",
  ))
  .expect("Kubernetes evidence schema should be valid JSON");
  let required = strings(&evidence_schema["required"]);
  for field in [
    "featureId",
    "phase",
    "sourceRef",
    "sourceRevision",
    "qualifiedPlatforms",
    "workflow",
    "reportHashes",
    "logHashes",
    "gateResults",
    "result",
  ] {
    assert!(
      required.contains(field),
      "receipt schema should require {field}"
    );
  }
  assert_eq!(
    strings(&evidence_schema["properties"]["gateResults"]["items"]["required"]),
    BTreeSet::from(["id", "platformResults"])
  );
  assert_eq!(
    strings(
      &evidence_schema["properties"]["gateResults"]["items"]["properties"]["platformResults"]["items"]
        ["required"],
    ),
    BTreeSet::from(["jobId", "platform", "reportName", "reportSha256", "result",])
  );
}

#[test]
fn charts_workflows_and_harnesses_expose_the_same_experimental_policy() {
  let controller_chart = read_repo("deploy/helm/oxibelt-gateway-controller/Chart.yaml");
  let data_chart = read_repo("deploy/helm/oxibelt/Chart.yaml");
  for chart in [&controller_chart, &data_chart] {
    assert!(chart.contains("oxibelt.dev/feature-status: experimental"));
    assert!(chart.contains("oxibelt.dev/kubernetes-support-policy: \"1\""));
  }
  assert!(controller_chart.contains("kubeVersion: \">=1.34.0-0 <1.37.0-0\""));

  let controller_deployment =
    read_repo("deploy/helm/oxibelt-gateway-controller/templates/deployment.yaml");
  let data_deployment = read_repo("deploy/helm/oxibelt/templates/deployment.yaml");
  let controller_helpers =
    read_repo("deploy/helm/oxibelt-gateway-controller/templates/_helpers.tpl");
  let data_helpers = read_repo("deploy/helm/oxibelt/templates/_helpers.tpl");
  for helpers in [&controller_helpers, &data_helpers] {
    assert!(helpers.contains("Helm 3.21.4 or 4.2.4"));
    assert!(helpers.contains("semverCompare \"=3.21.4\""));
    assert!(helpers.contains("semverCompare \"=4.2.4\""));
    assert!(helpers.contains("oxibelt.dev/feature-status"));
    assert!(helpers.contains("oxibelt.dev/kubernetes-support-policy"));
  }
  for workload in [&controller_deployment, &data_deployment] {
    assert!(workload.contains("oxibelt.dev/effective-version"));
  }
  for argument in [
    "--compatibility-mode=",
    "--compatibility-previous-version=",
    "--compatibility-deadline=",
  ] {
    assert!(
      controller_deployment.contains(argument),
      "controller chart should render {argument}"
    );
  }

  let workflow = read_repo(".github/workflows/check-oxibelt.yml");
  let rollout = read_repo("tests/scripts/run-kubernetes-immutable-rollout.sh");
  for expected in [
    "v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d",
    "v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0",
    "v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed",
  ] {
    assert!(
      workflow.contains(expected),
      "workflow should pin {expected}"
    );
    assert!(
      rollout.contains(expected),
      "rollout harness should allow {expected}"
    );
  }
  for expected in [
    "version: v3.21.4",
    "version: v4.2.4",
    "kubernetes-immutable-rollout:",
    "kubernetes-current-compatibility:",
    "configRollout.mode=kubernetes_immutable",
  ] {
    assert!(
      workflow.contains(expected),
      "workflow should include {expected}"
    );
  }
  assert!(rollout.contains("unapproved Kind node image"));
  assert!(rollout.contains("org.opencontainers.image.version"));
  assert!(rollout.contains("exact compatibility mode requires identical"));

  let support_document = read_repo("docs/KubernetesSupport.md");
  assert!(support_document.contains("Every governed feature is currently `experimental`."));
  assert!(support_document.contains("<!-- BEGIN KUBERNETES GRADUATION GENERATED -->"));
  assert!(support_document.contains("<!-- END KUBERNETES GRADUATION GENERATED -->"));
  assert!(read_repo("package.json").contains("\"kubernetes-graduation:check\""));
  assert!(read_repo("package.json").contains("\"kubernetes-graduation:verify\""));
}
