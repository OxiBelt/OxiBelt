use super::repo_root;
use std::fs;

#[test]
fn riscv_native_preflight_is_manual_bound_and_rootless() {
  let text = fs::read_to_string(repo_root().join(".github/workflows/riscv-native-preflight.yml"))
    .expect("native RISC-V preflight should exist");
  let workflow: serde_json::Value =
    serde_saphyr::from_str(&text).expect("native RISC-V preflight should parse");
  assert_eq!(workflow["on"].as_object().unwrap().len(), 1);
  assert!(workflow["on"]["workflow_dispatch"].is_object());
  assert_eq!(workflow["permissions"], serde_json::json!({}));
  let job = &workflow["jobs"]["capabilities"];
  assert_eq!(job["runs-on"], "ubuntu-24.04-riscv");
  assert_eq!(job["timeout-minutes"], 120);
  assert_eq!(job["permissions"], serde_json::json!({"contents": "read"}));
  let steps = job["steps"].as_array().unwrap();
  let checkout = steps
    .iter()
    .find(|step| step["with"]["ref"].is_string())
    .unwrap();
  assert_eq!(checkout["with"]["ref"], "${{ inputs.source_revision }}");
  assert_eq!(checkout["with"]["persist-credentials"], false);
  assert!(text.contains("[[ \"${GITHUB_SHA}\" == \"${EXPECTED_REVISION}\" ]]"));
  assert!(text.contains("[[ \"${WORKFLOW_REVISION}\" == \"${EXPECTED_REVISION}\" ]]"));
  assert!(text.contains("[[ \"${GITHUB_REF}\" == \"refs/heads/main\" ]]"));
  let probe = steps
    .iter()
    .position(|step| {
      step["run"]
        .as_str()
        .is_some_and(|run| run.contains("run-riscv-native-preflight.py"))
    })
    .unwrap();
  let upload = steps
    .iter()
    .position(|step| step["name"] == "Preserve prerequisite evidence")
    .unwrap();
  assert!(probe < upload);
  assert_eq!(steps[upload]["if"], "always()");
  let cleanup = steps
    .iter()
    .position(|step| step["name"] == "Ensure exact sandbox cleanup")
    .unwrap();
  assert!(probe < cleanup && cleanup < upload);
  assert_eq!(steps[cleanup]["if"], "always()");
  assert!(
    steps[cleanup]["run"]
      .as_str()
      .unwrap()
      .contains("--cleanup")
  );
  assert_eq!(steps[upload]["with"]["if-no-files-found"], "error");
  assert_eq!(steps[upload]["with"]["retention-days"], 7);
  assert!(
    steps
      .iter()
      .all(|step| step.get("continue-on-error").is_none())
  );
  for forbidden in [
    "GH_TOKEN",
    "secrets.",
    "sudo ",
    "docker run",
    "setup-qemu",
    "sysctl",
  ] {
    assert!(
      !text.contains(forbidden),
      "sandbox workflow must exclude {forbidden}"
    );
  }
}

#[test]
fn native_sandbox_lifecycle_regressions_are_ci_gated() {
  let text = fs::read_to_string(repo_root().join(".github/workflows/check-oxibelt.yml")).unwrap();
  let workflow: serde_json::Value = serde_saphyr::from_str(&text).unwrap();
  let steps = workflow["jobs"]["source-structure"]["steps"]
    .as_array()
    .unwrap();
  let step = steps
    .iter()
    .find(|step| step["name"] == "Test native rootless sandbox lifecycle")
    .unwrap();
  let command = step["run"].as_str().unwrap();
  for script in [
    "test-riscv-native-sandbox.py",
    "test-run-riscv-native-preflight.py",
    "test-check-riscv-rootless-enforcement.py",
  ] {
    assert!(command.contains(&format!("python3 -m unittest tests/scripts/{script}")));
  }
  assert!(step.get("continue-on-error").is_none());
  assert_eq!(step["env"]["PYTHONDONTWRITEBYTECODE"], "1");
}
