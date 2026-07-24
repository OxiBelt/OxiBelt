use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

const FEATURE_IDS: [&str; 9] = [
  "gateway-controller",
  "gateway-api-httproute",
  "gateway-api-grpcroute",
  "gateway-api-tlsroute",
  "gateway-api-tcproute",
  "gateway-api-udproute",
  "gateway-api-backendtlspolicy",
  "helm-data-plane",
  "helm-gateway-controller",
];

const REQUIRED_GATES: [&str; 24] = [
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
  assert_eq!(policy["schemaVersion"], 1);
  assert_eq!(policy["policyVersion"], 1);
  assert_eq!(policy["lifecycleAuthority"], "docs/FeatureStatus.md");
  assert_eq!(
    policy["supportContract"]["kubernetes"]["range"],
    ">=1.34.0-0 <1.37.0-0"
  );
  assert_eq!(
    strings(&policy["supportContract"]["helm"]["versions"]),
    BTreeSet::from(["3.21.3", "4.2.3"])
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
        "v1.34.8",
        "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256"
      ),
      (
        "1.35",
        "v1.35.5",
        "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95"
      ),
      (
        "1.36",
        "v1.36.1",
        "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
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
fn lifecycle_promotion_requires_complete_immutable_evidence() {
  let policy = policy();
  let status_rows = feature_statuses();
  let gates = policy["gates"]
    .as_array()
    .expect("gates should be an array");
  let gate_by_id = gates
    .iter()
    .map(|gate| {
      (
        gate["id"].as_str().expect("gate id should be a string"),
        gate,
      )
    })
    .collect::<BTreeMap<_, _>>();
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
    if status != "supported" {
      continue;
    }
    assert!(
      feature["blockerIds"]
        .as_array()
        .expect("blocker ids should be an array")
        .is_empty(),
      "supported feature {id} must not retain blockers"
    );
    for gate_id in strings(&feature["gateIds"]) {
      let gate = gate_by_id
        .get(gate_id)
        .unwrap_or_else(|| panic!("{id} references missing gate {gate_id}"));
      assert_eq!(
        gate["status"], "passed",
        "supported feature {id} requires passed gate {gate_id}"
      );
      let receipts = gate["evidenceReceipts"]
        .as_array()
        .expect("evidence receipts should be an array");
      assert!(
        !receipts.is_empty(),
        "supported feature {id} gate {gate_id} requires immutable evidence"
      );
      for receipt in receipts {
        let path = receipt
          .as_str()
          .expect("evidence receipt path should be a string");
        assert!(
          path.starts_with("evidence/kubernetes-graduation/") && path.ends_with(".json"),
          "evidence receipt must stay in the governed directory: {path}"
        );
        assert!(
          repo_root().join(path).is_file(),
          "evidence receipt should exist: {path}"
        );
      }
    }
  }
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
    assert!(helpers.contains("Helm 3.21.3 or 4.2.3"));
    assert!(helpers.contains("semverCompare \"=3.21.3\""));
    assert!(helpers.contains("semverCompare \"=4.2.3\""));
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
    "v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256",
    "v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95",
    "v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
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
    "version: v3.21.3",
    "version: v4.2.3",
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
}
