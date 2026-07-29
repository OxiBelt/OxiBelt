use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug)]
struct Job {
  needs: Vec<String>,
}

#[derive(Clone, Debug)]
struct WorkflowStep {
  job_id: String,
  step_index: usize,
  keys: BTreeSet<String>,
  parallel_children: Vec<WorkflowParallelChild>,
}

#[derive(Clone, Debug)]
struct WorkflowParallelChild {
  child_index: usize,
  keys: BTreeSet<String>,
  id: Option<String>,
  value: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
  Success,
  Failure,
  Skipped,
}

const DOCKER_INTEGRATION_JOBS: &[&str] = &[
  "docker-integration-config-runtime",
  "docker-integration-proxy",
  "docker-integration-protocol",
  "docker-integration-waf",
  "docker-integration-cache",
  "docker-integration-state-data",
  "docker-integration-ops",
  "docker-integration-security",
];

const OXIBELT_IMAGE_ARTIFACTS: &[(&str, &str, &str, &str)] = &[
  (
    "amd64v2",
    "oxibelt-alpine-musl-amd64v2-image",
    "oxibelt-alpine-musl-amd64v2.tar",
    "oxibelt:alpine-musl-amd64v2",
  ),
  (
    "amd64",
    "oxibelt-alpine-musl-amd64-image",
    "oxibelt-alpine-musl-amd64.tar",
    "oxibelt:alpine-musl-amd64",
  ),
  (
    "amd64v4",
    "oxibelt-alpine-musl-amd64v4-image",
    "oxibelt-alpine-musl-amd64v4.tar",
    "oxibelt:alpine-musl-amd64v4",
  ),
  (
    "arm64",
    "oxibelt-alpine-musl-arm64-image",
    "oxibelt-alpine-musl-arm64.tar",
    "oxibelt:alpine-musl-arm64",
  ),
  (
    "riscv64",
    "oxibelt-alpine-musl-riscv64-image",
    "oxibelt-alpine-musl-riscv64.tar",
    "oxibelt:alpine-musl-riscv64",
  ),
];

const OXIBELT_IMAGE_ROLES: &[(&str, &str)] = &[
  ("standalone", "oxibelt"),
  ("dataplane", "oxibelt-dataplane"),
  ("dataplane-strict", "oxibelt-dataplane-strict"),
  ("controller", "oxibelt-gateway-controller"),
  ("tools", "oxibelt-tools"),
  ("keysigner", "oxibelt-keysigner"),
];

const REQUIRED_NON_BENCHMARK_JOBS: &[&str] = &[
  "source-structure",
  "test",
  "rust-advisory-checks",
  "node-dependency-admission",
  "typescript-release-tooling",
  "fuzz-smoke",
  "unsafe-validation",
  "check-riscv64-cross",
  "generate-test-matrices",
  "linux-target-builds",
  "docker-alpine-musl-image-amd64",
  "docker-alpine-musl-role-image-amd64",
  "docker-alpine-musl-role-image-other",
  "docker-alpine-musl-image-other",
  "docker-alpine-musl-image-riscv64",
  "docker-image-trivy-scan",
  "docker-integration-helper-images",
  "admin-mutation-postgres",
  "admin-operation-postgres",
  "admin-audit-anchor-postgres",
  "kubernetes-immutable-rollout",
  "kubernetes-pod-lifecycle",
  "kubernetes-network-policy",
  "kubernetes-current-compatibility",
  "docker-integration-config-runtime",
  "docker-integration-proxy",
  "docker-integration-protocol",
  "docker-integration-waf",
  "docker-integration-cache",
  "docker-integration-state-data",
  "docker-integration-ops",
  "docker-integration-security",
  "remote-signer-dos-docker",
  "browser-webdriver",
];

const BENCHMARK_ONLY_JOBS: &[&str] = &[
  "docker-alpine-comparator-musl-image-amd64",
  "docker-performance-probe-image",
  "docker-external-benchmark-image",
  "docker-performance",
  "docker-performance-summary",
  "docker-aggressive-long-run",
];

const PRIMARY_RUST_GATE_NEEDS: &[&str] = &[
  "test",
  "rust-advisory-checks",
  "node-dependency-admission",
  "check-riscv64-cross",
  "fuzz-smoke",
  "unsafe-validation",
];

const CHECK_WORKFLOW_ENTRY_JOBS: &[&str] = &[
  "source-structure",
  "test",
  "rust-advisory-checks",
  "node-dependency-admission",
  "typescript-release-tooling",
  "fuzz-smoke",
  "unsafe-validation",
  "check-riscv64-cross",
];
const DEPENDABOT_ACTOR_CONDITION: &str = "github.actor != 'dependabot[bot]'";

const PERFORMANCE_WORKFLOW_EVENT_CONDITION: &str =
  "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'";
const PERFORMANCE_WORKFLOW_JOB_IF: &str =
  "if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'";
const PERFORMANCE_WORKFLOW_SUMMARY_IF: &str = "if: ${{ always() && (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') }}";

fn expected_needs(job_ids: &[&str]) -> Vec<String> {
  job_ids.iter().map(|job_id| (*job_id).to_owned()).collect()
}

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate should live under the repository root")
    .to_path_buf()
}

fn workflow_text() -> String {
  fs::read_to_string(repo_root().join(".github/workflows/check-oxibelt.yml"))
    .expect("check-oxibelt workflow should be readable")
}

fn release_workflow_text() -> String {
  fs::read_to_string(repo_root().join(".github/workflows/release.yml"))
    .expect("release workflow should be readable")
}

fn release_draft_workflow_text() -> String {
  fs::read_to_string(repo_root().join(".github/workflows/prepare-release-draft.yml"))
    .expect("release draft workflow should be readable")
}

fn release_image_arch_workflow_text() -> String {
  fs::read_to_string(repo_root().join(".github/workflows/release-image-arch.yml"))
    .expect("release image architecture workflow should be readable")
}

fn release_image_arch_scan_workflow_text() -> String {
  fs::read_to_string(repo_root().join(".github/workflows/release-image-arch-scan.yml"))
    .expect("release image architecture scan workflow should be readable")
}

fn release_rebuild_verification_workflow_text() -> String {
  fs::read_to_string(repo_root().join(".github/workflows/verify-release-rebuild.yml"))
    .expect("independent release rebuild workflow should be readable")
}

fn release_rebuild_verification_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/verify-release-rebuild.sh"))
    .expect("independent release rebuild script should be readable")
}

fn dependabot_config_text() -> String {
  fs::read_to_string(repo_root().join(".github/dependabot.yml"))
    .expect("Dependabot configuration should be readable")
}

fn dependabot_retirement_workflow_text() -> String {
  fs::read_to_string(repo_root().join(".github/workflows/close-dependabot-pull-requests.yml"))
    .expect("Dependabot retirement workflow should be readable")
}

fn workflow_job_text(workflow: &str, job_id: &str) -> String {
  let marker = format!("  {job_id}:");
  let mut lines = Vec::new();
  let mut in_job = false;

  for line in workflow.lines() {
    if line == marker {
      in_job = true;
    } else if in_job && line.starts_with("  ") && !line.starts_with("    ") && line.ends_with(':') {
      break;
    }

    if in_job {
      lines.push(line);
    }
  }

  assert!(in_job, "workflow should define job {job_id}");
  lines.join("\n")
}

fn workflow_top_level_steps(workflow: &str) -> Vec<WorkflowStep> {
  let workflow: serde_json::Value =
    serde_saphyr::from_str(workflow).expect("workflow should parse as YAML");
  let Some(jobs) = workflow.get("jobs").and_then(serde_json::Value::as_object) else {
    return Vec::new();
  };

  jobs
    .iter()
    .flat_map(|(job_id, job)| {
      job
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(step_index, step)| workflow_step_from_value(job_id, step_index + 1, step))
    })
    .collect()
}

fn workflow_step_from_value(
  job_id: &str,
  step_index: usize,
  step: &serde_json::Value,
) -> WorkflowStep {
  let keys = workflow_mapping_keys(step);
  let parallel_children = step
    .get("parallel")
    .and_then(serde_json::Value::as_array)
    .map(|children| {
      children
        .iter()
        .enumerate()
        .map(|(child_index, child)| workflow_parallel_child_from_value(child_index + 1, child))
        .collect()
    })
    .unwrap_or_default();

  WorkflowStep {
    job_id: job_id.to_owned(),
    step_index,
    keys,
    parallel_children,
  }
}

fn workflow_parallel_child_from_value(
  child_index: usize,
  child: &serde_json::Value,
) -> WorkflowParallelChild {
  WorkflowParallelChild {
    child_index,
    keys: workflow_mapping_keys(child),
    id: child
      .get("id")
      .and_then(serde_json::Value::as_str)
      .map(str::to_owned),
    value: child.clone(),
  }
}

fn workflow_mapping_keys(value: &serde_json::Value) -> BTreeSet<String> {
  value
    .as_object()
    .map(|object| object.keys().cloned().collect())
    .unwrap_or_default()
}

fn workflow_value_contains_step_output_reference(value: &serde_json::Value, step_id: &str) -> bool {
  match value {
    serde_json::Value::String(value) => {
      workflow_text_contains_step_output_reference(value, step_id)
    }
    serde_json::Value::Array(values) => values
      .iter()
      .any(|value| workflow_value_contains_step_output_reference(value, step_id)),
    serde_json::Value::Object(values) => values
      .values()
      .any(|value| workflow_value_contains_step_output_reference(value, step_id)),
    serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => false,
  }
}

fn workflow_text_contains_step_output_reference(text: &str, step_id: &str) -> bool {
  if text.contains(&format!("steps.{step_id}.outputs")) {
    return true;
  }

  let escaped_step_id = regex::escape(step_id);
  let bracket_pattern = format!(r#"steps\s*\[\s*['"]{escaped_step_id}['"]\s*\]\s*\.outputs"#);
  regex::Regex::new(&bracket_pattern)
    .expect("step output reference pattern should compile")
    .is_match(text)
}

fn workflow_step_validation_errors(workflow: &str) -> Vec<String> {
  let unsupported_top_level_step_keys = ["background", "wait", "wait-all", "cancel"];
  let unsupported_parallel_child_keys = ["parallel", "background", "wait", "wait-all", "cancel"];
  workflow_top_level_steps(workflow)
    .into_iter()
    .filter_map(|step| {
      let unsupported_keys = unsupported_top_level_step_keys
        .iter()
        .filter(|key| step.keys.contains(**key))
        .copied()
        .collect::<Vec<_>>();
      let is_executable = step.keys.contains("run") || step.keys.contains("uses");
      let is_parallel = step.keys.contains("parallel");
      if unsupported_keys.is_empty() && is_executable && !is_parallel {
        None
      } else if unsupported_keys.is_empty() && is_parallel && !is_executable {
        let child_ids = step
          .parallel_children
          .iter()
          .filter_map(|child| child.id.as_deref())
          .collect::<Vec<_>>();
        let mut child_errors = Vec::new();
        if step.parallel_children.is_empty() {
          child_errors.push("parallel group has no child steps".to_owned());
        }
        for child in &step.parallel_children {
          let unsupported_child_keys = unsupported_parallel_child_keys
            .iter()
            .filter(|key| child.keys.contains(**key))
            .copied()
            .collect::<Vec<_>>();
          if !unsupported_child_keys.is_empty() {
            child_errors.push(format!(
              "child {} has unsupported keys {:?}",
              child.child_index, unsupported_child_keys
            ));
          }
          if !(child.keys.contains("run") || child.keys.contains("uses")) {
            child_errors.push(format!(
              "child {} has keys {:?} without run or uses",
              child.child_index, child.keys
            ));
          }
          for sibling_id in &child_ids {
            if child.id.as_deref() != Some(*sibling_id)
              && workflow_value_contains_step_output_reference(&child.value, sibling_id)
            {
              child_errors.push(format!(
                "child {} consumes sibling output steps.{sibling_id}.outputs",
                child.child_index
              ));
            }
          }
        }
        if child_errors.is_empty() {
          None
        } else {
          Some(format!(
            "jobs.{}.steps[{}] parallel group is invalid: {}",
            step.job_id,
            step.step_index,
            child_errors.join("; ")
          ))
        }
      } else {
        Some(format!(
          "jobs.{}.steps[{}] has keys {:?}; unsupported step-control keys: {:?}",
          step.job_id, step.step_index, step.keys, unsupported_keys
        ))
      }
    })
    .collect()
}

fn write_test_file(path: &Path, contents: &str) {
  fs::create_dir_all(
    path
      .parent()
      .expect("test file should have a parent directory"),
  )
  .expect("test file parent should be creatable");
  fs::write(path, contents).expect("test file should be writable");
}

fn write_executable(path: &Path, contents: &str) {
  write_test_file(path, contents);
  let mut permissions = fs::metadata(path)
    .expect("executable test file should have metadata")
    .permissions();
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o755);
  }
  fs::set_permissions(path, permissions).expect("test executable permissions should be writable");
}

fn dockerfile_text() -> String {
  fs::read_to_string(repo_root().join("source/ops/Dockerfile.alpine"))
    .expect("Alpine Dockerfile should be readable")
}

fn dockerfile_stage<'a>(dockerfile: &'a str, name: &str) -> &'a str {
  let marker = format!(" AS {name}\n");
  let (_, body) = dockerfile
    .split_once(&marker)
    .unwrap_or_else(|| panic!("Dockerfile should define stage {name}"));
  body.split("\nFROM ").next().unwrap_or(body)
}

fn comparator_dockerfile_text(comparator: &str) -> String {
  fs::read_to_string(repo_root().join(format!(
    "tests/docker/performance_comparators/Dockerfile.{comparator}"
  )))
  .unwrap_or_else(|error| panic!("performance comparator Dockerfile should be readable: {error}"))
}

fn comparator_build_script_text() -> String {
  fs::read_to_string(
    repo_root().join("tests/scripts/build-performance-comparator-image-artifact.sh"),
  )
  .expect("performance comparator build script should be readable")
}

fn docker_image_artifact_build_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/build-docker-image-artifact.sh"))
    .expect("Docker image artifact build script should be readable")
}

fn strict_dataplane_image_validator_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/validate-strict-dataplane-image.py"))
    .expect("strict data-plane image validator should be readable")
}

fn ci_image_artifact_validator_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/validate-ci-image-artifact.py"))
    .expect("CI image artifact validator should be readable")
}

fn dependency_snapshot_helper_path() -> PathBuf {
  repo_root().join("tests/scripts/prepare-ci-dependency-snapshot.py")
}

fn dependency_snapshot_helper_text() -> String {
  fs::read_to_string(dependency_snapshot_helper_path())
    .expect("CI dependency snapshot helper should be readable")
}

fn non_benchmark_summary_script_path() -> PathBuf {
  repo_root().join("tests/scripts/summarize-ci-needs.sh")
}

fn non_benchmark_summary_script_text() -> String {
  fs::read_to_string(non_benchmark_summary_script_path())
    .expect("non-benchmark summary script should be readable")
}

fn performance_probe_build_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/build-performance-probe-image-artifact.sh"))
    .expect("performance probe build script should be readable")
}

fn external_benchmark_build_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/build-external-benchmark-image-artifact.sh"))
    .expect("external benchmark build script should be readable")
}

fn performance_summary_input_script_path() -> PathBuf {
  repo_root().join("tests/scripts/copy-performance-summary-input-artifacts.sh")
}

fn performance_summary_input_script_text() -> String {
  fs::read_to_string(performance_summary_input_script_path())
    .expect("performance summary input copy script should be readable")
}

fn external_benchmark_dockerfile_text() -> String {
  fs::read_to_string(repo_root().join("tests/docker/external_benchmarks/Dockerfile"))
    .expect("external benchmark Dockerfile should be readable")
}

fn docker_integration_helper_build_script_text() -> String {
  fs::read_to_string(
    repo_root().join("tests/scripts/build-docker-integration-helper-images-artifact.sh"),
  )
  .expect("Docker integration helper image build script should be readable")
}

fn docker_pull_retry_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/retry-docker-pull.sh"))
    .expect("Docker pull retry script should be readable")
}

fn docker_integration_matrix_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/run-proxy-integration-matrix.sh"))
    .expect("Docker integration matrix script should be readable")
}

fn admin_mutation_postgres_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/run-admin-mutation-postgres.sh"))
    .expect("Admin mutation PostgreSQL script should be readable")
}

fn admin_operation_postgres_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/run-admin-operation-postgres.sh"))
    .expect("Admin operation PostgreSQL script should be readable")
}

fn admin_audit_anchor_postgres_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/run-admin-audit-anchor-postgres.sh"))
    .expect("Admin audit anchor PostgreSQL script should be readable")
}

fn kubernetes_immutable_rollout_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/run-kubernetes-immutable-rollout.sh"))
    .expect("Kubernetes immutable rollout script should be readable")
}

fn kubernetes_pod_lifecycle_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/run-kubernetes-pod-lifecycle.sh"))
    .expect("Kubernetes Pod lifecycle script should be readable")
}

fn kubernetes_network_policy_script_text() -> String {
  fs::read_to_string(repo_root().join("tests/scripts/run-kubernetes-network-policy.sh"))
    .expect("Kubernetes NetworkPolicy script should be readable")
}

fn oxibelt_main_text() -> String {
  fs::read_to_string(repo_root().join("source/src/main.rs"))
    .expect("OxiBelt binary main should be readable")
}

fn source_file_text(path: &str) -> String {
  fs::read_to_string(repo_root().join(path)).expect("source file should be readable")
}

fn workspace_members() -> Vec<String> {
  let manifest =
    fs::read_to_string(repo_root().join("Cargo.toml")).expect("root Cargo.toml should be readable");
  let manifest: toml::Value =
    toml::from_str(&manifest).expect("root Cargo.toml should parse as TOML");
  manifest["workspace"]["members"]
    .as_array()
    .expect("root workspace should declare members")
    .iter()
    .map(|member| {
      member
        .as_str()
        .expect("workspace member should be a string")
        .to_owned()
    })
    .collect()
}

fn parse_jobs(workflow: &str) -> BTreeMap<String, Job> {
  let mut jobs = BTreeMap::new();
  let mut in_jobs = false;
  let mut current_job: Option<String> = None;
  let mut collecting_needs = false;

  for raw_line in workflow.lines() {
    let line = raw_line.trim_end();
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
      continue;
    }

    let indent = line
      .chars()
      .take_while(|character| *character == ' ')
      .count();
    if !in_jobs {
      in_jobs = line == "jobs:";
      continue;
    }

    if indent == 0 {
      break;
    }

    if indent == 2 && line.ends_with(':') {
      let id = trimmed.trim_end_matches(':');
      if !id.contains(char::is_whitespace) {
        current_job = Some(id.to_owned());
        collecting_needs = false;
        jobs.insert(id.to_owned(), Job { needs: Vec::new() });
      }
      continue;
    }

    if collecting_needs && indent <= 4 {
      collecting_needs = false;
    }

    if indent == 4 && trimmed.starts_with("needs:") {
      let value = trimmed
        .strip_prefix("needs:")
        .expect("starts_with already checked")
        .trim();
      if value.is_empty() {
        collecting_needs = true;
      } else if let Some(job_id) = &current_job {
        jobs
          .get_mut(job_id)
          .expect("current job should be registered")
          .needs
          .extend(parse_inline_needs(value));
      }
      continue;
    }

    if collecting_needs
      && indent == 6
      && trimmed.starts_with("- ")
      && let Some(job_id) = &current_job
    {
      jobs
        .get_mut(job_id)
        .expect("current job should be registered")
        .needs
        .push(trim_yaml_scalar(trimmed.trim_start_matches("- ")).to_owned());
    }
  }

  jobs
}

fn parse_inline_needs(value: &str) -> Vec<String> {
  if value.starts_with('[') && value.ends_with(']') {
    value
      .trim_start_matches('[')
      .trim_end_matches(']')
      .split(',')
      .map(str::trim)
      .filter(|item| !item.is_empty())
      .map(trim_yaml_scalar)
      .map(str::to_owned)
      .collect()
  } else {
    vec![trim_yaml_scalar(value).to_owned()]
  }
}

fn trim_yaml_scalar(value: &str) -> &str {
  let value_without_comment = value
    .split_once('#')
    .map_or(value, |(before_comment, _)| before_comment)
    .trim();

  value_without_comment.trim_matches('"').trim_matches('\'')
}

fn has_transitive_need(jobs: &BTreeMap<String, Job>, job_id: &str, target: &str) -> bool {
  fn visit(
    jobs: &BTreeMap<String, Job>,
    job_id: &str,
    target: &str,
    seen: &mut BTreeSet<String>,
  ) -> bool {
    if !seen.insert(job_id.to_owned()) {
      return false;
    }

    let Some(job) = jobs.get(job_id) else {
      panic!("workflow references unknown job {job_id}");
    };

    job
      .needs
      .iter()
      .any(|need| need == target || visit(jobs, need, target, seen))
  }

  visit(jobs, job_id, target, &mut BTreeSet::new())
}

fn simulate_source_structure_failure(jobs: &BTreeMap<String, Job>, job_id: &str) -> Outcome {
  fn visit(
    jobs: &BTreeMap<String, Job>,
    job_id: &str,
    memo: &mut BTreeMap<String, Outcome>,
    visiting: &mut BTreeSet<String>,
  ) -> Outcome {
    if let Some(outcome) = memo.get(job_id) {
      return *outcome;
    }
    if !visiting.insert(job_id.to_owned()) {
      panic!("workflow dependency cycle includes {job_id}");
    }

    let outcome = if job_id == "source-structure" {
      Outcome::Failure
    } else {
      let job = jobs
        .get(job_id)
        .unwrap_or_else(|| panic!("workflow references unknown job {job_id}"));
      if job
        .needs
        .iter()
        .any(|need| visit(jobs, need, memo, visiting) != Outcome::Success)
      {
        Outcome::Skipped
      } else {
        Outcome::Success
      }
    };

    visiting.remove(job_id);
    memo.insert(job_id.to_owned(), outcome);
    outcome
  }

  visit(jobs, job_id, &mut BTreeMap::new(), &mut BTreeSet::new())
}

#[test]
fn alpine_dockerfile_builder_copies_workspace_members() {
  let dockerfile = dockerfile_text();

  for member in workspace_members() {
    let copy_instruction = format!("COPY {member} ./{member}");
    assert!(
      dockerfile.contains(&copy_instruction),
      "source/ops/Dockerfile.alpine should copy workspace member {member:?} before cargo build"
    );
  }
}

#[test]
fn alpine_runtime_uses_native_and_pinned_cross_musl_builders() {
  let dockerfile = dockerfile_text();
  let script = docker_image_artifact_build_script_text();
  let workspace_manifest = fs::read_to_string(repo_root().join("Cargo.toml"))
    .expect("workspace Cargo.toml should be readable");
  let cli_manifest = fs::read_to_string(repo_root().join("source/apps/oxibeltctl/Cargo.toml"))
    .expect("oxibeltctl Cargo.toml should be readable");

  for expected in [
    "ARG RUST_BUILDER_IMAGE=rust:1.97.1-trixie",
    "ARG OXIBELT_RUNTIME_IMAGE=alpine:3.24",
    "ARG OXIBELT_RUST_BUILDER_STAGE=builder-native",
    "ARG OXIBELT_RISCV64_TOOLCHAIN_PLATFORM=linux/amd64",
    "ARG TARGETARCH",
    "FROM --platform=$BUILDPLATFORM ${RUST_BUILDER_IMAGE} AS builder-base",
    "FROM builder-base AS builder-native",
    "FROM ${OXIBELT_RUST_BUILDER_STAGE} AS builder",
    "amd64) rust_target=x86_64-unknown-linux-musl",
    "arm64) rust_target=aarch64-unknown-linux-musl",
    "riscv64) rust_target=riscv64gc-unknown-linux-musl",
    "CC_x86_64_unknown_linux_musl=musl-gcc",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc",
    "CC_aarch64_unknown_linux_musl=musl-gcc",
    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc",
    "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_RUSTFLAGS=\"-Ctarget-feature=+crt-static\"",
    "cargo build --locked --release",
    "--target \"${OXIBELT_BUILD_RUST_TARGET}\"",
  ] {
    assert!(
      dockerfile.contains(expected),
      "Alpine runtime image should preserve its glibc-hosted musl build contract: {expected}"
    );
  }

  for expected in [
    "rust_builder_image=\"rust:${rust_toolchain_version}-trixie@sha256:1bcff4befb740599103a2c7cb51058e14479b2e35e3a34a3f0dc4ede09927488\"",
    "rust_target=\"x86_64-unknown-linux-musl\"",
    "rust_target=\"aarch64-unknown-linux-musl\"",
    "rust_target=\"riscv64gc-unknown-linux-musl\"",
    "rust_builder_stage=\"builder-riscv64\"",
    "OXIBELT_RUST_BUILDER_STAGE=${rust_builder_stage}",
    "OXIBELT_RUST_CACHE_ID=${rust_build_cache_key}",
  ] {
    assert!(
      script.contains(expected),
      "Docker artifact builder should record the explicit musl build input: {expected}"
    );
  }

  assert!(
    !dockerfile.contains("libgcc_s") && !dockerfile.contains("LIBRARY_PATH"),
    "RISC-V musl builds should not reintroduce a shared libgcc workaround"
  );

  for expected in [
    "FROM --platform=${OXIBELT_RISCV64_TOOLCHAIN_PLATFORM} ghcr.io/cross-rs/riscv64gc-unknown-linux-musl@sha256:c12165aac0b52abaee935d0be8ceaa93f63a0f0447597811377417e3120f2247 AS riscv64-cross-toolchain",
    "1d07d3f9cc465c435256f1aabc1d18024517891a",
    "FROM builder-base AS builder-riscv64",
    "COPY --from=riscv64-cross-toolchain /x-tools /x-tools",
    "COPY source/ops/riscv64-musl-toolchain.cmake /opt/oxibelt/riscv64-musl-toolchain.cmake",
    "14.3.0",
    "riscv64-unknown-linux-musl",
    "GNU ld (crosstool-NG UNKNOWN) 2.45",
    "3fe20d705129f8ba4ae6be393fd4c484479f688f576af78c0ff2bb10e59d5f86",
    "AS riscv64-musl-check",
  ] {
    assert!(
      dockerfile.contains(expected),
      "RISC-V musl builds should pin and verify the cross toolchain contract: {expected}"
    );
  }

  for forbidden in [
    "CROSS_TARGET_RUNNER",
    "QEMU_LD_PREFIX",
    "CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_MUSL_RUNNER",
    "tonistiigi/binfmt",
    "--privileged",
  ] {
    assert!(
      !dockerfile.contains(forbidden) && !script.contains(forbidden),
      "RISC-V cross compilation must not reintroduce an emulator or privileged runtime: {forbidden}"
    );
  }

  assert!(
    cli_manifest.contains(
      "cfg(all(target_arch = \"aarch64\", target_os = \"linux\", target_env = \"musl\"))"
    ) && cli_manifest.contains("openssl-sys.workspace = true")
      && workspace_manifest
        .contains("openssl-sys = { version = \"0.9.117\", features = [\"vendored\"] }"),
    "ARM64 musl should build a target-compatible vendored OpenSSL"
  );
}

#[test]
fn alpine_runtime_rootfs_is_assembled_without_target_execution() {
  let dockerfile = dockerfile_text();
  let rootfs_script = source_file_text("source/ops/prepare-alpine-rootfs.sh");

  for expected in [
    "FROM ${OXIBELT_RUNTIME_IMAGE} AS runtime-seed",
    "FROM --platform=$BUILDPLATFORM ${OXIBELT_RUNTIME_IMAGE} AS runtime-preparer",
    "COPY --from=runtime-seed / /opt/oxibelt-rootfs",
    "source/ops/prepare-alpine-rootfs.sh",
    "FROM scratch AS runtime",
  ] {
    assert!(
      dockerfile.contains(expected),
      "runtime image should preserve emulator-free target rootfs assembly: {expected}"
    );
  }

  for expected in [
    "/etc/alpine-release",
    "/etc/apk/repositories",
    "/etc/apk/keys",
    "/lib/apk/db/installed",
    "amd64) apk_arch=x86_64",
    "arm64) apk_arch=aarch64",
    "riscv64) apk_arch=riscv64",
    "--root",
    "--arch",
    "--no-scripts",
    "--no-cache",
    "upgrade",
    "ca-certificates",
    "libgcc",
    "libssl3",
    "$4 == 10001 || $4 == 10002",
  ] {
    assert!(
      rootfs_script.contains(expected),
      "rootfs preparation should validate and preserve the signed Alpine contract: {expected}"
    );
  }

  for forbidden in ["--allow-untrusted", "\nchroot ", "\neval ", "qemu-"] {
    assert!(
      !rootfs_script.contains(forbidden),
      "rootfs preparation must not weaken package trust or execute target code: {forbidden}"
    );
  }
}

#[test]
fn riscv64_cmake_toolchain_is_sysrooted_and_emulator_free() {
  let toolchain = source_file_text("source/ops/riscv64-musl-toolchain.cmake");

  for expected in [
    "CMAKE_SYSTEM_NAME Linux",
    "CMAKE_SYSTEM_PROCESSOR riscv64",
    "OXIBELT_RISCV64_TOOLCHAIN_PREFIX",
    "${OXIBELT_RISCV64_TOOLCHAIN_PREFIX}gcc",
    "${OXIBELT_RISCV64_TOOLCHAIN_PREFIX}g++",
    "${OXIBELT_RISCV64_TOOLCHAIN_PREFIX}ar",
    "${OXIBELT_RISCV64_TOOLCHAIN_PREFIX}ranlib",
    "${OXIBELT_RISCV64_TOOLCHAIN_PREFIX}strip",
    "CMAKE_SYSROOT",
    "CMAKE_FIND_ROOT_PATH",
    "-march=rv64gc",
    "-mabi=lp64d",
    "-mcmodel=medany",
  ] {
    assert!(
      toolchain.contains(expected),
      "RISC-V CMake toolchain should preserve {expected}"
    );
  }
  for forbidden in [
    "CMAKE_CROSSCOMPILING_EMULATOR",
    "qemu-",
    "/usr/include",
    "/usr/lib",
  ] {
    assert!(
      !toolchain.contains(forbidden),
      "RISC-V CMake toolchain must remain target-sysrooted and emulator-free: {forbidden}"
    );
  }
}

#[test]
fn python_docker_helpers_track_the_supported_alpine_base() {
  for dockerfile in [
    "tests/docker/mock_dns/Dockerfile",
    "tests/docker/mock_kubernetes/Dockerfile",
    "tests/docker/mock_nomad/Dockerfile",
    "tests/docker/mock_upstream/Dockerfile",
  ] {
    let contents = fs::read_to_string(repo_root().join(dockerfile))
      .unwrap_or_else(|error| panic!("{dockerfile} should be readable: {error}"));
    assert!(
      contents.starts_with("FROM python:3.14-alpine3.24\n"),
      "{dockerfile} should use the supported Python 3.14 and Alpine 3.24 base"
    );
  }
}

#[test]
fn alpine_dockerfile_bundles_operations_binaries() {
  let dockerfile = dockerfile_text();

  for (package, binary, builder) in [
    (
      "oxibelt-gateway-controller",
      "oxibelt-gateway-controller",
      "controller-builder",
    ),
    (
      "oxibelt-keysigner",
      "oxibelt-keysigner",
      "keysigner-builder",
    ),
    (
      "oxibelt-netport-switcher",
      "oxibelt-netport-switcher",
      "netport-builder",
    ),
    ("oxibeltctl", "oxibeltctl", "tools-builder"),
    (
      "oxibelt-dataplane-strict",
      "oxibelt-dataplane-strict",
      "strict-dataplane-builder",
    ),
  ] {
    assert!(
      dockerfile.contains(&format!(
        "cargo build --locked --release -p {package} --bin {binary}"
      )),
      "source/ops/Dockerfile.alpine should explicitly build {package}/{binary}"
    );
    assert!(
      dockerfile.contains(&format!("FROM builder AS {builder}")),
      "source/ops/Dockerfile.alpine should isolate the {binary} build stage"
    );
  }

  let strict_builder = dockerfile_stage(&dockerfile, "strict-dataplane-builder");
  let strict_build_command = concat!(
    "cargo build --locked --release -p oxibelt-dataplane-strict ",
    "--bin oxibelt-dataplane-strict \\\n",
    "      --no-default-features --target \"${OXIBELT_BUILD_RUST_TARGET}\"",
  );
  assert!(
    strict_builder.contains(strict_build_command),
    "the strict data-plane builder must select the exact package and binary with defaults disabled"
  );
  assert_eq!(
    strict_builder.matches("cargo build ").count(),
    1,
    "the strict data-plane builder should have one auditable Cargo build invocation"
  );
  for forbidden in ["--workspace", "--all-features"] {
    assert!(
      !strict_builder.contains(forbidden),
      "the strict data-plane builder must not broaden its graph with {forbidden}"
    );
  }

  for expected in [
    "FROM scratch AS role-metadata",
    "FROM role-metadata AS dataplane",
    "FROM scratch AS dataplane-strict",
    "FROM role-metadata AS controller",
    "FROM role-metadata AS tools",
    "FROM role-metadata AS keysigner",
    "FROM runtime AS standalone",
    "io.oxibelt.image.role=\"dataplane\"",
    "io.oxibelt.image.role=\"dataplane-strict\"",
    "io.oxibelt.image.role=\"controller\"",
    "io.oxibelt.image.role=\"tools\"",
    "io.oxibelt.image.role=\"keysigner\"",
    "io.oxibelt.image.role=\"standalone\"",
    "COPY --from=controller-builder /tmp/oxibelt-gateway-controller /usr/local/bin/oxibelt-gateway-controller",
    "COPY --from=tools-builder /tmp/oxibeltctl /usr/local/bin/oxibeltctl",
    "COPY --from=runtime --chown=10002:10002 --chmod=0770 /run/oxibelt-keysigner /run/oxibelt-keysigner",
    "COPY --from=keysigner-builder /tmp/oxibelt-keysigner /usr/local/bin/oxibelt-keysigner",
    "COPY --from=netport-builder /tmp/oxibelt-netport-switcher /usr/local/bin/oxibelt-netport-switcher",
    "sh source/ops/verify-static-elf.sh /tmp/oxibelt-gateway-controller",
    "sh source/ops/verify-static-elf.sh /tmp/oxibelt-keysigner",
    "sh source/ops/verify-static-elf.sh /tmp/oxibelt-netport-switcher",
    "sh source/ops/verify-static-elf.sh /tmp/oxibeltctl",
    "sh source/ops/verify-static-elf.sh /tmp/oxibelt ",
    "sh source/ops/verify-static-elf.sh /tmp/oxibelt-dataplane-strict",
  ] {
    assert!(
      dockerfile.contains(expected),
      "source/ops/Dockerfile.alpine should preserve role contract {expected}"
    );
  }
  assert_eq!(
    dockerfile
      .matches("sh source/ops/verify-static-elf.sh")
      .count(),
    6,
    "every release binary should retain its shared ELF identity and static-link guard"
  );

  let elf_guard = source_file_text("source/ops/verify-static-elf.sh");
  for expected in [
    "Advanced Micro Devices X86-64",
    "AArch64",
    "RISC-V",
    "expected ELF64",
    "PT_INTERP is present",
    "DT_NEEDED is present",
  ] {
    assert!(
      elf_guard.contains(expected),
      "static ELF guard should preserve {expected}"
    );
  }

  for (role, expected_binaries) in [
    (
      "dataplane",
      vec!["COPY --from=runtime-builder /tmp/oxibelt /usr/local/bin/oxibelt"],
    ),
    (
      "dataplane-strict",
      vec![
        "COPY --from=strict-dataplane-builder /tmp/oxibelt-dataplane-strict /usr/local/bin/oxibelt-dataplane-strict",
      ],
    ),
    (
      "controller",
      vec![
        "COPY --from=controller-builder /tmp/oxibelt-gateway-controller /usr/local/bin/oxibelt-gateway-controller",
      ],
    ),
    (
      "tools",
      vec!["COPY --from=tools-builder /tmp/oxibeltctl /usr/local/bin/oxibeltctl"],
    ),
    (
      "keysigner",
      vec!["COPY --from=keysigner-builder /tmp/oxibelt-keysigner /usr/local/bin/oxibelt-keysigner"],
    ),
    (
      "standalone",
      vec![
        "COPY --from=runtime-builder /tmp/oxibelt /usr/local/bin/oxibelt",
        "COPY --from=keysigner-builder /tmp/oxibelt-keysigner /usr/local/bin/oxibelt-keysigner",
        "COPY --from=netport-builder /tmp/oxibelt-netport-switcher /usr/local/bin/oxibelt-netport-switcher",
        "COPY --from=tools-builder /tmp/oxibeltctl /usr/local/bin/oxibeltctl",
      ],
    ),
  ] {
    let actual_binaries = dockerfile_stage(&dockerfile, role)
      .lines()
      .filter(|line| line.starts_with("COPY ") && line.contains(" /usr/local/bin/"))
      .collect::<Vec<_>>();
    assert_eq!(
      actual_binaries, expected_binaries,
      "Dockerfile stage {role} should contain exactly its declared executable inventory"
    );
  }
  assert!(
    dockerfile.contains(
      "ENTRYPOINT [\"/usr/local/bin/oxibelt\", \"--config\", \"/etc/oxibelt/config/oxibelt.toml\"]"
    ),
    "source/ops/Dockerfile.alpine should keep oxibelt as the container entrypoint"
  );
}

#[test]
fn alpine_dockerfile_records_canonical_build_identity_labels() {
  let dockerfile = dockerfile_text();
  let script = docker_image_artifact_build_script_text();

  assert!(
    dockerfile.contains("ARG OXIBELT_RUNTIME_IMAGE=alpine:3.24")
      && dockerfile.contains("ARG OXIBELT_BUILD_VERSION=0.0.0-dev.archive")
      && dockerfile.contains("ARG OXIBELT_BUILD_REVISION=unknown")
      && dockerfile.contains("ARG OXIBELT_BUILD_REF=unknown")
      && dockerfile.contains("ARG OXIBELT_BUILD_DIRTY=unknown")
      && dockerfile.contains("ARG OXIBELT_BUILD_KIND=source_archive")
      && dockerfile.contains("ARG OXIBELT_REF_NAME=0.0.0-dev.archive")
      && dockerfile.contains("ARG OXIBELT_REF_NAME")
      && dockerfile.contains("org.opencontainers.image.ref.name=\"${OXIBELT_REF_NAME}\""),
    "source/ops/Dockerfile.alpine should give direct archive builds an explicit non-release identity and expose the validated release tag as OCI ref.name"
  );
  for expected in [
    "OXIBELT_DOCKER_IMAGE_VERSION",
    "OXIBELT_DOCKER_IMAGE_REVISION",
    "OXIBELT_DOCKER_IMAGE_SOURCE_REF",
    "OXIBELT_DOCKER_IMAGE_SOURCE_DIRTY",
    "OXIBELT_DOCKER_IMAGE_BUILD_KIND",
    "OXIBELT_DOCKER_IMAGE_CREATED",
    "OXIBELT_DOCKER_IMAGE_SOURCE",
    "OXIBELT_DOCKER_IMAGE_REF_NAME",
    "--metadata-file \"${build_metadata_tmp}\"",
    "--build-arg \"OXIBELT_NODE_IMAGE=${node_builder_image}\"",
    "--build-arg \"OXIBELT_RUNTIME_IMAGE=${runtime_image}\"",
    "--build-arg \"OXIBELT_REF_NAME=${oxibelt_ref_name}\"",
    "--build-arg \"OXIBELT_BUILD_REF=${oxibelt_source_ref}\"",
    "--build-arg \"OXIBELT_BUILD_DIRTY=${oxibelt_source_dirty}\"",
    "--build-arg \"OXIBELT_BUILD_KIND=${oxibelt_build_kind}\"",
  ] {
    assert!(
      script.contains(expected),
      "Docker image artifact builder should support release metadata override {expected}"
    );
  }
  for removed in [
    "BUILDX_METADATA_PROVENANCE",
    "build-inputs",
    "rustToolchainVersion",
    "baseImages",
  ] {
    assert!(
      !script.contains(removed),
      "Docker image artifact builder should not retain provenance input {removed}"
    );
  }
}

#[test]
fn strict_dataplane_image_validator_is_exact_and_non_extracting() {
  let validator = strict_dataplane_image_validator_text();

  for expected in [
    "EXPECTED_FILES = {",
    "oxibelt-dataplane-strict",
    "EXPECTED_PASSWD",
    "EXPECTED_GROUP",
    "PERSON_PROOF_MARKER",
    "ADMIN_MARKERS",
    "ADMIN_CONFIG_SECTION",
    "member.isfile() or member.isdir()",
    "startswith(\".wh.\")",
    "MAXIMUM_ARCHIVE_BYTES",
    "MAXIMUM_LAYER_BYTES",
    "MAXIMUM_FILE_BYTES",
    "must have mode 0755",
    "must have mode 0644",
    r#"re.fullmatch(r"[0-9a-f]{64}/layer\.tar", normalized)"#,
  ] {
    assert!(
      validator.contains(expected),
      "strict image validator should enforce {expected}"
    );
  }
  for forbidden in ["extractall(", ".extract(", "os.system(", "subprocess."] {
    assert!(
      !validator.contains(forbidden),
      "strict image validator must not use unsafe extraction/execution primitive {forbidden}"
    );
  }
}

#[test]
fn source_structure_job_stays_independent() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let source_structure = jobs
    .get("source-structure")
    .expect("workflow should define source-structure");

  assert!(
    source_structure.needs.is_empty(),
    "source-structure should run independently, not after {:?}",
    source_structure.needs
  );

  let parsed: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("check-oxibelt workflow should parse as YAML");
  let steps = parsed["jobs"]["source-structure"]["steps"]
    .as_array()
    .expect("source-structure should define steps");
  let exact_step = |name: &str, command: &str| {
    let matches = steps
      .iter()
      .enumerate()
      .filter(|(_, step)| {
        step["name"].as_str() == Some(name) && step["run"].as_str() == Some(command)
      })
      .collect::<Vec<_>>();
    assert_eq!(
      matches.len(),
      1,
      "source-structure should define exact fail-closed step {name}"
    );
    matches[0].0
  };

  let rust_install = exact_step(
    "Install Rust toolchain",
    "rustup toolchain install 1.97.1 --profile minimal\nrustup default 1.97.1\n",
  );
  let boundary_unit_tests = exact_step(
    "Test Rust boundary tooling",
    "python3 -m unittest tests/scripts/test-check-rust-module-size.py\n\
python3 -m unittest tests/scripts/test-check-cargo-package-boundaries.py\n",
  );
  let module_boundaries = exact_step(
    "Rust module dependency boundaries",
    "cargo test -p oxibelt --test module_decomposition_contract --locked",
  );
  let package_boundaries = exact_step(
    "Data-plane Cargo package boundary",
    "bash tests/scripts/check-cargo-package-boundaries.sh",
  );
  let size_advisory = exact_step(
    "Rust module size advisory",
    "tests/scripts/check-rust-module-size.sh --warn",
  );
  exact_step(
    "Native configuration schema drift",
    "bash tests/scripts/check-native-config-schema.sh",
  );

  assert!(
    rust_install < boundary_unit_tests
      && boundary_unit_tests < module_boundaries
      && module_boundaries < package_boundaries
      && package_boundaries < size_advisory,
    "Rust installation, negative-fixture unit tests, live boundary analyzers, and the size advisory must keep their fail-closed order"
  );
  assert_eq!(
    steps[boundary_unit_tests]["env"],
    serde_json::json!({"PYTHONDONTWRITEBYTECODE": "1"}),
    "boundary analyzer unit tests should not write Python cache files into the checkout"
  );

  for (position, step) in steps.iter().enumerate() {
    if position >= boundary_unit_tests && position <= size_advisory {
      assert!(
        step.get("continue-on-error").is_none(),
        "Rust boundary step {} must fail closed",
        step["name"].as_str().unwrap_or("<unnamed>")
      );
      assert!(
        !step["run"]
          .as_str()
          .is_some_and(|command| command.contains("|| true")),
        "Rust boundary step {} must not suppress command failures",
        step["name"].as_str().unwrap_or("<unnamed>")
      );
    }
  }

  let source_structure_text = workflow_job_text(&workflow, "source-structure");
  assert!(
    !source_structure_text.contains("check-rust-module-size.sh --enforce"),
    "source-structure should keep line count advisory after dependency checks become authoritative"
  );
  assert_eq!(
    source_structure_text
      .matches("tests/scripts/check-rust-module-size.sh")
      .count(),
    1,
    "source-structure should invoke the module-size advisory exactly once"
  );
  assert!(
    source_structure_text
      .contains("python3 -m unittest tests/scripts/test-check-markdown-links.py")
      && source_structure_text
        .contains("python3 tests/scripts/check-markdown-links.py --repo-root ."),
    "source-structure should enforce documentation links and anchors"
  );
}

#[test]
fn release_image_rebuild_comparator_regressions_are_ci_gated() {
  let workflow = workflow_text();
  let parsed: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("check-oxibelt workflow should parse as YAML");
  let steps = parsed["jobs"]["source-structure"]["steps"]
    .as_array()
    .expect("source-structure should define steps");
  let command = "python3 -m unittest tests/scripts/test-compare-release-image-artifacts.py\n\
python3 -m unittest tests/scripts/test-run-riscv64-release-image-smoke.py\n";
  let matching_steps = steps
    .iter()
    .enumerate()
    .filter(|(_, step)| step["run"].as_str() == Some(command))
    .collect::<Vec<_>>();

  assert_eq!(
    matching_steps.len(),
    1,
    "source-structure should run the release-image rebuild comparator regression suite exactly once"
  );
  let (position, step) = matching_steps[0];
  assert_eq!(
    step["name"].as_str(),
    Some("Test release-image rebuild comparator")
  );
  assert_eq!(
    step["env"],
    serde_json::json!({"PYTHONDONTWRITEBYTECODE": "1"})
  );
  let checkout_position = steps
    .iter()
    .position(|step| {
      step["uses"]
        .as_str()
        .is_some_and(|uses| uses.starts_with("actions/checkout@"))
    })
    .expect("source-structure should check out the repository");
  assert!(
    checkout_position < position,
    "the release-image rebuild comparator tests require the checked-out repository"
  );
}

#[test]
fn documentation_link_checker_is_ci_gated() {
  let workflow = workflow_text();
  let parsed: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("check-oxibelt workflow should parse as YAML");
  let steps = parsed["jobs"]["source-structure"]["steps"]
    .as_array()
    .expect("source-structure should define steps");
  let unit_command = "python3 -m unittest tests/scripts/test-check-markdown-links.py";
  let check_command = "python3 tests/scripts/check-markdown-links.py --repo-root .";
  let matching_steps = steps
    .iter()
    .enumerate()
    .filter(|(_, step)| {
      step["run"].as_str().is_some_and(|run| {
        let commands = run.lines().collect::<Vec<_>>();
        commands == [unit_command, check_command]
      })
    })
    .collect::<Vec<_>>();

  assert_eq!(
    matching_steps.len(),
    1,
    "source-structure should run the documentation link unit tests and repository check together exactly once"
  );
  let (position, step) = matching_steps[0];
  assert_eq!(
    step["name"].as_str(),
    Some("Check documentation links and anchors")
  );
  assert_eq!(
    step["env"],
    serde_json::json!({"PYTHONDONTWRITEBYTECODE": "1"})
  );
  assert_eq!(
    steps
      .iter()
      .filter_map(|step| step["run"].as_str())
      .map(|run| run.matches(unit_command).count())
      .sum::<usize>(),
    1,
    "source-structure should execute the documentation link unit tests exactly once"
  );
  assert_eq!(
    steps
      .iter()
      .filter_map(|step| step["run"].as_str())
      .map(|run| run.matches(check_command).count())
      .sum::<usize>(),
    1,
    "source-structure should execute the repository documentation link check exactly once"
  );
  assert!(
    step.get("continue-on-error").is_none(),
    "the documentation link gate must fail closed"
  );
  let checkout_position = steps
    .iter()
    .position(|step| {
      step["uses"]
        .as_str()
        .is_some_and(|uses| uses.starts_with("actions/checkout@"))
    })
    .expect("source-structure should check out the repository");
  assert!(
    checkout_position < position,
    "the documentation link checker requires the checked-out repository"
  );
}

#[test]
fn check_workflow_entry_jobs_skip_dependabot() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let parsed_workflow: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("check-oxibelt workflow should parse as YAML");
  let workflow_jobs = parsed_workflow
    .get("jobs")
    .and_then(serde_json::Value::as_object)
    .expect("check-oxibelt workflow should define jobs");
  let entry_jobs = jobs
    .iter()
    .filter_map(|(job_id, job)| job.needs.is_empty().then_some(job_id.as_str()))
    .collect::<BTreeSet<_>>();
  let expected_entry_jobs = CHECK_WORKFLOW_ENTRY_JOBS
    .iter()
    .copied()
    .collect::<BTreeSet<_>>();

  assert_eq!(
    entry_jobs, expected_entry_jobs,
    "check-oxibelt entry jobs should remain explicit so new roots cannot bypass the Dependabot guard"
  );

  for job_id in CHECK_WORKFLOW_ENTRY_JOBS {
    let condition = workflow_jobs
      .get(*job_id)
      .and_then(|job| job.get("if"))
      .and_then(serde_json::Value::as_str);
    assert_eq!(
      condition,
      Some(DEPENDABOT_ACTOR_CONDITION),
      "{job_id} should skip workflow runs initiated by Dependabot"
    );
  }
}

#[test]
fn person_proof_asset_regeneration_uses_the_frozen_workspace_lockfile() {
  let source_structure = workflow_job_text(&workflow_text(), "source-structure");
  for expected in [
    "corepack install",
    "pnpm install --frozen-lockfile --ignore-scripts",
    "pnpm --filter @oxibelt/person-proof-ui build",
    "pnpm --filter @oxibelt/person-proof-ui check:openapi",
    "git diff --exit-code source/assets/person-proof-challenge.html",
  ] {
    assert!(
      source_structure.contains(expected),
      "source-structure must retain deterministic Person Proof asset check {expected}"
    );
  }
  assert!(
    !source_structure.contains("npm install --prefix ui/person-proof"),
    "Person Proof regeneration must not bypass the root pnpm lockfile"
  );
}

#[test]
fn dependabot_covers_all_rust_and_container_manifest_directories() {
  let config: serde_json::Value = serde_saphyr::from_str(&dependabot_config_text())
    .expect("Dependabot configuration should parse as YAML");
  let updates = config
    .get("updates")
    .and_then(serde_json::Value::as_array)
    .expect("Dependabot configuration should define updates");
  let update_for = |ecosystem: &str| {
    updates
      .iter()
      .find(|update| {
        update
          .get("package-ecosystem")
          .and_then(serde_json::Value::as_str)
          == Some(ecosystem)
      })
      .unwrap_or_else(|| panic!("Dependabot should define the {ecosystem} ecosystem"))
  };

  let cargo = update_for("cargo");
  assert_eq!(
    cargo.get("directories"),
    Some(&serde_json::json!(["/", "/tests/docker/*_probe"])),
    "Dependabot Cargo updates should cover the root workspace and all standalone probe workspaces"
  );
  assert_eq!(
    cargo
      .pointer("/groups/rust-dependencies/group-by")
      .and_then(serde_json::Value::as_str),
    Some("dependency-name"),
    "Dependabot should group matching Cargo updates by dependency name"
  );

  let docker = update_for("docker");
  assert_eq!(
    docker.get("directories"),
    Some(&serde_json::json!(["/source/ops", "/tests/docker/*"])),
    "Dependabot Docker updates should cover release and test Dockerfiles"
  );
  assert_eq!(
    docker
      .pointer("/groups/container-dependencies/group-by")
      .and_then(serde_json::Value::as_str),
    Some("dependency-name"),
    "Dependabot should group matching container updates by dependency name"
  );
}

#[test]
fn dependabot_retirement_uses_authenticated_privilege_separation() {
  let check_workflow = workflow_text();
  let workflow = dependabot_retirement_workflow_text();
  let parsed: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("Dependabot retirement workflow should parse as YAML");
  let triggers = parsed
    .get("on")
    .and_then(serde_json::Value::as_object)
    .expect("Dependabot retirement workflow should define mapping triggers");
  let jobs = parsed
    .get("jobs")
    .and_then(serde_json::Value::as_object)
    .expect("Dependabot retirement workflow should define jobs");

  assert_eq!(
    triggers.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from(["workflow_dispatch".to_owned(), "workflow_run".to_owned()]),
    "Dependabot retirement should expose only the authenticated automatic and confirmed backfill triggers"
  );
  assert_eq!(
    triggers["workflow_run"]["workflows"],
    serde_json::json!(["Check OxiBelt"]),
    "Dependabot retirement should follow the existing unprivileged check workflow"
  );
  assert_eq!(
    triggers["workflow_run"]["types"],
    serde_json::json!(["completed"]),
    "Dependabot retirement should authenticate completed runs regardless of their conclusion"
  );
  assert_eq!(
    triggers["workflow_dispatch"]["inputs"]["confirmation"]["required"],
    serde_json::json!(true),
    "Dependabot retirement backfill should require explicit confirmation"
  );
  assert_eq!(
    parsed["permissions"],
    serde_json::json!({}),
    "Dependabot retirement should deny token permissions by default"
  );
  assert_eq!(
    jobs.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from(["authenticate".to_owned(), "reconcile".to_owned()]),
    "Dependabot retirement should separate authentication from mutation"
  );

  let authenticate = &jobs["authenticate"];
  let reconcile = &jobs["reconcile"];
  assert_eq!(
    authenticate["permissions"],
    serde_json::json!({"pull-requests": "read"}),
    "Dependabot trigger authentication should remain read-only"
  );
  assert_eq!(
    reconcile["permissions"],
    serde_json::json!({"issues": "write", "pull-requests": "write"}),
    "Dependabot reconciliation should receive only the two required write permissions"
  );
  assert_eq!(
    reconcile["needs"],
    serde_json::json!(["authenticate"]),
    "the write-capable job should depend directly on read-only authentication"
  );
  assert_eq!(
    reconcile["if"],
    "github.repository == 'OxiBelt/OxiBelt' && needs.authenticate.outputs.authorized == 'true'",
    "the write-capable job should require the canonical repository and authenticated result"
  );
  assert_eq!(authenticate["runs-on"], "ubuntu-26.04");
  assert_eq!(authenticate["timeout-minutes"], 5);
  assert_eq!(reconcile["runs-on"], "ubuntu-26.04");
  assert_eq!(reconcile["timeout-minutes"], 10);
  assert_eq!(
    reconcile["concurrency"],
    serde_json::json!({
      "group": "dependabot-pr-retirement",
      "cancel-in-progress": false
    }),
    "Dependabot mutations should be serialized without cancelling an active reconciliation"
  );
  assert_eq!(
    authenticate["outputs"]["authorized"], "${{ steps.authenticate.outputs.result }}",
    "the read-only job should expose only its static authorization result"
  );

  let expected_action = "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0";
  assert_eq!(
    workflow
      .matches(&format!("uses: {expected_action}"))
      .count(),
    2,
    "both jobs should use the exact immutable GitHub-owned script action"
  );
  assert_eq!(
    workflow
      .matches("github-token: ${{ secrets.GITHUB_TOKEN }}")
      .count(),
    2,
    "each isolated job should use only its job-scoped GITHUB_TOKEN"
  );
  assert_eq!(
    workflow.matches("secrets.").count(),
    2,
    "Dependabot retirement should not consume any secret other than each job-scoped GITHUB_TOKEN"
  );
  assert_eq!(
    workflow
      .lines()
      .filter(|line| line.contains("uses: "))
      .count(),
    2,
    "Dependabot retirement should not add any other action dependency"
  );
  for forbidden in [
    "pull_request_target",
    "actions/checkout@",
    "actions/download-artifact@",
    "actions/cache@",
    "pnpm",
    "docker",
    "personal_access_token",
    "workflowRun.pull_requests",
    "workflow_run.pull_requests",
  ] {
    assert!(
      !workflow.contains(forbidden),
      "Dependabot retirement must not consume privileged or untrusted surface {forbidden}"
    );
  }
  assert!(
    workflow
      .lines()
      .all(|line| !line.trim_start().starts_with("run:")),
    "Dependabot retirement should keep API data out of generated shell commands"
  );

  for expected in [
    "github.event.workflow_run.event == 'pull_request'",
    "github.event.workflow_run.actor.login == 'dependabot[bot]'",
    "github.event.workflow_run.actor.id == 49699333",
    "workflowRun?.path !== checkWorkflowPath",
    "workflowRun?.repository?.id !== repository.id",
    "github.rest.users.getByUsername",
    "github.rest.repos.listPullRequestsAssociatedWithCommit",
    "commit_sha: workflowRun.head_sha",
    "context.ref !== expectedRef",
    "close-all-open-dependabot-prs",
    "needs.authenticate.outputs.authorized == 'true'",
  ] {
    assert!(
      workflow.contains(expected),
      "Dependabot retirement trigger authentication should include {expected}"
    );
  }
  assert_eq!(
    workflow
      .matches("await listTargetDependabotPullRequestNumbers()")
      .count(),
    2,
    "both reconciliation passes and final residual validation should use the trigger-scoped target set"
  );

  for expected in [
    "const maximumPasses = 3",
    "github.paginate(github.rest.pulls.list",
    "github.paginate(github.rest.issues.listForRepo",
    "const listTargetDependabotPullRequestNumbers = async () =>",
    "context.eventName === 'workflow_dispatch'",
    "commit_sha: context.payload.workflow_run.head_sha",
    "state: 'all'",
    "pullRequest.user?.login === dependabot.login",
    "pullRequest.user?.id === dependabot.id",
    "pullRequest.user?.type === 'Bot'",
    "pullRequest.base?.repo?.id === repository.id",
    "oxibelt:dependabot-pr-retirement:v1:repository=",
    "tracker_marker_owner_mismatch",
    "duplicate_tracker_markers",
    "labels: ['dependencies']",
    "!hasDependenciesLabel(readback)",
    "const finalPullRequest = await getVerifiedOpenPullRequest(pullNumber)",
    "state: 'closed'",
    "pull_close_readback_mismatch",
    "tracker_final_readback_mismatch",
    "error.issueNumber = issueNumber",
    "Residual open Dependabot pull requests",
  ] {
    assert!(
      workflow.contains(expected),
      "Dependabot reconciliation should preserve {expected}"
    );
  }
  for forbidden in [
    "pullRequest.title",
    "pullRequest.body",
    "pullRequest.head",
    "pullRequest.labels",
  ] {
    assert!(
      !workflow.contains(forbidden),
      "Dependabot-controlled metadata must not flow into issue text or commands: {forbidden}"
    );
  }
  let create_issue_position = workflow
    .find("github.rest.issues.create")
    .expect("Dependabot retirement should create a tracking issue");
  let close_pull_position = workflow
    .find("github.rest.pulls.update")
    .expect("Dependabot retirement should close the source pull request");
  assert!(
    create_issue_position < close_pull_position,
    "Dependabot retirement should make the durable issue visible before closing the pull request"
  );
  assert!(
    check_workflow.starts_with("name: Check OxiBelt\n")
      && check_workflow.contains("  pull_request:\n"),
    "the authenticated source workflow should retain its exact name and pull-request trigger"
  );
}

#[test]
fn source_structure_failure_does_not_skip_test_or_docker_ci_jobs() {
  let jobs = parse_jobs(&workflow_text());
  let security_relevant_jobs = REQUIRED_NON_BENCHMARK_JOBS
    .iter()
    .copied()
    .filter(|job_id| *job_id != "source-structure");

  assert_eq!(
    simulate_source_structure_failure(&jobs, "source-structure"),
    Outcome::Failure
  );

  for job_id in security_relevant_jobs {
    assert!(
      !has_transitive_need(&jobs, job_id, "source-structure"),
      "{job_id} must not depend on source-structure directly or transitively"
    );
    assert_eq!(
      simulate_source_structure_failure(&jobs, job_id),
      Outcome::Success,
      "{job_id} would be skipped if source-structure failed"
    );
  }
}

#[test]
fn admin_mutation_postgres_ci_is_mandatory_bounded_and_rootless() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let job = jobs
    .get("admin-mutation-postgres")
    .expect("workflow should define the Admin mutation PostgreSQL durability job");
  let job_text = workflow_job_text(&workflow, "admin-mutation-postgres");
  let script = admin_mutation_postgres_script_text();

  assert_eq!(
    job.needs,
    expected_needs(&["docker-integration-helper-images"]),
    "Admin mutation PostgreSQL tests should use the build-validated helper image"
  );
  for expected in [
    "name: Admin mutation PostgreSQL durability",
    "runs-on: ubuntu-26.04",
    "timeout-minutes: 45",
    "actions: read",
    "contents: read",
    "OXIBELT_POSTGRES_IMAGE: oxibelt/postgres:ci",
    "OXIBELT_REQUIRE_MUTATION_POSTGRES_TESTS: \"1\"",
    "tests/scripts/run-admin-mutation-postgres.sh",
  ] {
    assert!(
      job_text.contains(expected),
      "Admin mutation PostgreSQL job should preserve {expected}"
    );
  }
  for expected in [
    "set -euo pipefail",
    "docker_publish_args=(--publish 127.0.0.1::5432)",
    "docker_publish_args=()",
    "\"${docker_publish_args[@]}\"",
    "od -An -N 32 -tx1 /dev/urandom",
    "OXIBELT_REQUIRE_MUTATION_POSTGRES_TESTS=1",
    "OXIBELT_POSTGRES_CONNECT_HOST",
    "OXIBELT_TEST_MUTATION_POSTGRES_URL=",
    "NetworkSettings.Networks",
    "timeout --signal=TERM 35m",
    "cargo test --all-features --locked -p oxibelt --lib",
    "'admin_mutation::' -- --test-threads=1",
    "docker rm --force --volumes \"${container_name}\"",
    "trap cleanup EXIT",
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
  ] {
    assert!(
      script.contains(expected),
      "Admin mutation PostgreSQL harness should preserve {expected}"
    );
  }
  for forbidden in [
    "docker-rootful",
    "docker system prune",
    "docker volume prune",
    "docker network prune",
    "--privileged",
    "--network host",
    "eval ",
  ] {
    assert!(
      !script.contains(forbidden),
      "Admin mutation PostgreSQL harness must not use {forbidden}"
    );
  }
}

#[test]
fn admin_operation_postgres_ci_is_mandatory_bounded_and_rootless() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let job = jobs
    .get("admin-operation-postgres")
    .expect("workflow should define the Admin operation PostgreSQL durability job");
  let job_text = workflow_job_text(&workflow, "admin-operation-postgres");
  let script = admin_operation_postgres_script_text();

  assert_eq!(
    job.needs,
    expected_needs(&["docker-integration-helper-images"]),
    "Admin operation PostgreSQL tests should use the build-validated helper image"
  );
  for expected in [
    "name: Admin operation PostgreSQL durability",
    "runs-on: ubuntu-26.04",
    "timeout-minutes: 45",
    "actions: read",
    "contents: read",
    "OXIBELT_POSTGRES_IMAGE: oxibelt/postgres:ci",
    "OXIBELT_REQUIRE_ADMIN_OPERATION_POSTGRES_TESTS: \"1\"",
    "tests/scripts/run-admin-operation-postgres.sh",
  ] {
    assert!(
      job_text.contains(expected),
      "Admin operation PostgreSQL job should preserve {expected}"
    );
  }
  for expected in [
    "set -euo pipefail",
    "docker_publish_args=(--publish 127.0.0.1::5432)",
    "docker_publish_args=()",
    "\"${docker_publish_args[@]}\"",
    "od -An -N 32 -tx1 /dev/urandom",
    "OXIBELT_REQUIRE_ADMIN_OPERATION_POSTGRES_TESTS=1",
    "OXIBELT_POSTGRES_CONNECT_HOST",
    "OXIBELT_TEST_ADMIN_OPERATION_POSTGRES_URL=",
    "NetworkSettings.Networks",
    "timeout --signal=TERM 35m",
    "cargo test --all-features --locked -p oxibelt --lib",
    "'admin_operations::store::postgres_tests::' -- --test-threads=1",
    "docker rm --force --volumes \"${container_name}\"",
    "trap cleanup EXIT",
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
  ] {
    assert!(
      script.contains(expected),
      "Admin operation PostgreSQL harness should preserve {expected}"
    );
  }
  for forbidden in [
    "docker-rootful",
    "docker system prune",
    "docker volume prune",
    "docker network prune",
    "--privileged",
    "--network host",
    "eval ",
  ] {
    assert!(
      !script.contains(forbidden),
      "Admin operation PostgreSQL harness must not use {forbidden}"
    );
  }
}

#[test]
fn admin_audit_anchor_postgres_harness_is_dual_database_bounded_and_rootless() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let job = jobs
    .get("admin-audit-anchor-postgres")
    .expect("workflow should define the Admin audit anchor PostgreSQL job");
  let job_text = workflow_job_text(&workflow, "admin-audit-anchor-postgres");
  let script = admin_audit_anchor_postgres_script_text();

  assert_eq!(
    job.needs,
    expected_needs(&["docker-integration-helper-images"]),
    "Admin audit anchor tests should use the build-validated PostgreSQL image"
  );
  for expected in [
    "name: Admin audit external anchor PostgreSQL",
    "runs-on: ubuntu-26.04",
    "timeout-minutes: 45",
    "actions: read",
    "contents: read",
    "OXIBELT_POSTGRES_IMAGE: oxibelt/postgres:ci",
    "OXIBELT_REQUIRE_ADMIN_AUDIT_ANCHOR_POSTGRES_TESTS: \"1\"",
    "tests/scripts/run-admin-audit-anchor-postgres.sh",
  ] {
    assert!(
      job_text.contains(expected),
      "Admin audit anchor PostgreSQL job should preserve {expected}"
    );
  }

  for expected in [
    "set -euo pipefail",
    "postgres:18-alpine",
    "local_container=",
    "authority_container=",
    "docker_publish_args=(--publish 127.0.0.1::5432)",
    "docker_publish_args=()",
    "od -An -N \"${bytes}\" -tx1 /dev/urandom",
    "deploy/postgres/admin-audit-anchor-v1.sql",
    "anchor_authority_id=",
    "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT",
    "GRANT EXECUTE ON FUNCTION oxibelt_audit_anchor_v1.append_checkpoint(jsonb)",
    "GRANT EXECUTE ON FUNCTION oxibelt_audit_anchor_v1.checkpoints(text,text)",
    "OXIBELT_REQUIRE_ADMIN_AUDIT_ANCHOR_POSTGRES_TESTS=1",
    "OXIBELT_TEST_ADMIN_AUDIT_LOCAL_POSTGRES_URL=",
    "OXIBELT_TEST_ADMIN_AUDIT_ANCHOR_RUNTIME_POSTGRES_URL=",
    "OXIBELT_TEST_ADMIN_AUDIT_ANCHOR_VERIFIER_POSTGRES_URL=",
    "timeout --signal=TERM 35m",
    "cargo test --all-features --locked -p oxibelt --lib",
    "'admin_audit::anchor::postgres_tests::' -- --test-threads=1",
    "docker rm --force --volumes \"${local_container}\"",
    "docker rm --force --volumes \"${authority_container}\"",
    "trap cleanup EXIT",
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
  ] {
    assert!(
      script.contains(expected),
      "Admin audit anchor PostgreSQL harness should preserve {expected}"
    );
  }
  assert_eq!(
    script.matches("docker run --detach").count(),
    2,
    "the local audit database and external authority must use separate containers"
  );
  for forbidden in [
    "docker-rootful",
    "docker system prune",
    "docker volume prune",
    "docker network prune",
    "--privileged",
    "--network host",
    "eval ",
  ] {
    assert!(
      !script.contains(forbidden),
      "Admin audit anchor PostgreSQL harness must not use {forbidden}"
    );
  }
}

#[test]
fn check_workflow_steps_are_executable_actions_or_scripts() {
  let workflow = workflow_text();
  let invalid_steps = workflow_step_validation_errors(&workflow);

  assert!(
    invalid_steps.is_empty(),
    "workflow top-level steps must be executable run/uses steps or validated parallel groups:\n{}",
    invalid_steps.join("\n")
  );
}

#[test]
fn parallel_step_validation_rejects_sibling_output_dependencies() {
  for (name, producer_id, consumer_run) in [
    (
      "dot syntax",
      "id: producer",
      r#"echo "${{ steps.producer.outputs.value }}""#,
    ),
    (
      "YAML comment after id",
      "id: producer # innocuous comment",
      r#"echo "${{ steps.producer.outputs.value }}""#,
    ),
    (
      "single-quoted bracket syntax",
      "id: producer",
      r#"echo "${{ steps['producer'].outputs.value }}""#,
    ),
    (
      "double-quoted bracket syntax",
      "id: producer",
      r#"echo '${{ steps["producer"].outputs.value }}'"#,
    ),
    (
      "whitespace bracket syntax",
      "id: producer",
      r#"echo "${{ steps[ 'producer' ].outputs.value }}""#,
    ),
  ] {
    let workflow = format!(
      r#"
jobs:
  test:
    steps:
      - parallel:
          - {producer_id}
            run: echo "value=1" >> "$GITHUB_OUTPUT"

          - name: Consumer
            run: {consumer_run}
"#
    );
    let invalid_steps = workflow_step_validation_errors(&workflow);
    assert!(
      invalid_steps
        .iter()
        .any(|error| error.contains("child 2 consumes sibling output steps.producer.outputs")),
      "parallel sibling output dependency should be rejected for {name}: {invalid_steps:?}"
    );
  }
}

#[test]
fn test_job_runs_independent_format_checks_in_parallel() {
  let workflow = workflow_text();
  let test_job = workflow_job_text(&workflow, "test");
  let format_parallel_group = test_job
    .split_once("      - parallel:\n")
    .and_then(|(_, rest)| rest.split_once("\n      - name: Cargo clippy"))
    .map(|(group, _)| group)
    .expect("test job should run format checks in a parallel group");

  assert_eq!(
    test_job.matches("      - parallel:\n").count(),
    1,
    "test job should use one focused parallel group"
  );
  assert!(
    format_parallel_group.contains("name: Cargo fmt")
      && format_parallel_group.contains("run: cargo fmt --check")
      && format_parallel_group.contains("name: Tests rustfmt")
      && format_parallel_group.contains("run: tests/scripts/check-tests-rustfmt.sh"),
    "test job should run independent format checks in the parallel group"
  );
  for sequential_step in ["name: Cargo clippy", "name: Cargo test"] {
    assert!(
      !format_parallel_group.contains(sequential_step),
      "test job should keep {sequential_step} after the format parallel group"
    );
  }

  let install_rust = test_job
    .find("name: Install Rust toolchain")
    .expect("test job should install Rust before checks");
  let format_parallel = test_job
    .find("      - parallel:\n")
    .expect("test job should define a format parallel group");
  let cargo_clippy = test_job
    .find("name: Cargo clippy")
    .expect("test job should run cargo clippy");
  let cargo_test = test_job
    .find("name: Cargo test")
    .expect("test job should run cargo test");

  assert!(
    install_rust < format_parallel && format_parallel < cargo_clippy && cargo_clippy < cargo_test,
    "test job should install Rust, run parallel format checks, then run clippy and tests sequentially"
  );
}

#[test]
fn test_job_runs_bounded_loom_models_on_amd64() {
  let workflow = workflow_text();
  let test_job = workflow_job_text(&workflow, "test");
  let cargo_test = test_job
    .find("name: Cargo test")
    .expect("test job should run the ordinary Cargo suite");
  let loom_models = test_job
    .find("name: Loom concurrency models")
    .expect("test job should run the dedicated Loom models");

  assert!(
    cargo_test < loom_models,
    "Loom models should run after the ordinary Cargo suite"
  );
  for expected in [
    "if: matrix.runner == 'ubuntu-26.04'",
    "cargo test --all-features --locked loom_ -- --ignored --test-threads=1",
  ] {
    assert!(
      test_job.contains(expected),
      "test job should preserve bounded AMD64 Loom invocation {expected}"
    );
  }
  assert_eq!(
    test_job.matches("name: Loom concurrency models").count(),
    1,
    "Loom models should run once instead of being duplicated across the runner matrix"
  );
}

#[test]
fn unsafe_validation_runs_latest_stable_harness_as_a_primary_gate() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let job = jobs
    .get("unsafe-validation")
    .expect("workflow should define unsafe-validation");
  let job_text = workflow_job_text(&workflow, "unsafe-validation");

  assert!(
    job.needs.is_empty(),
    "unsafe validation should start alongside the other primary Rust gates"
  );
  for expected in [
    "name: Unsafe validation (stable)",
    "runs-on: ubuntu-26.04",
    "contents: read",
    "rustup toolchain install stable --profile minimal",
    "cargo +stable test -p oxibelt-unsafe-harness --lib --locked -- --test-threads=1",
  ] {
    assert!(
      job_text.contains(expected),
      "unsafe-validation should include {expected}"
    );
  }
  for forbidden in [
    "strategy:",
    "matrix.",
    "nightly",
    "rust-src",
    "Miri",
    "miri",
    "Sanitizer",
    "-Zbuild-std",
    "-Zsanitizer",
    "ASAN_OPTIONS",
    "TSAN_OPTIONS",
    "continue-on-error",
  ] {
    assert!(
      !job_text.contains(forbidden),
      "unsafe-validation should not include {forbidden}"
    );
  }
}

#[test]
fn rust_advisory_checks_run_as_independent_primary_gate() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let test_job = workflow_job_text(&workflow, "test");
  let advisory_job = jobs
    .get("rust-advisory-checks")
    .expect("workflow should define the Rust advisory check job");
  let advisory_job_text = workflow_job_text(&workflow, "rust-advisory-checks");

  assert!(
    advisory_job.needs.is_empty(),
    "Rust advisory checks should start with the primary Rust test gates, not after {:?}",
    advisory_job.needs
  );

  for expected in [
    "name: Rust dependency admission",
    "runs-on: ubuntu-26.04",
    "contents: read",
    "name: Install Rust toolchain",
    "rustup toolchain install 1.97.1 --profile minimal",
    "rustup default 1.97.1",
    "name: Install pinned Rust dependency tools",
    "cargo install cargo-audit --version 0.22.2 --locked",
    "cargo install cargo-deny --version 0.20.2 --locked",
    "cargo install cargo-vet --version 0.10.2 --locked",
    "name: Cargo audit",
    "run: cargo audit",
    "name: Cargo deny complete policy",
    "run: cargo deny check",
    "name: Cargo vet locked review evidence",
    "run: cargo vet --locked",
  ] {
    assert!(
      advisory_job_text.contains(expected),
      "Rust advisory check job should include {expected}"
    );
  }

  for forbidden in [
    "name: Install pinned Rust dependency tools",
    "run: cargo audit",
    "run: cargo deny check",
    "run: cargo vet --locked",
  ] {
    assert!(
      !test_job.contains(forbidden),
      "test job should leave {forbidden} to the independent Rust advisory job"
    );
  }

  let install_rust = advisory_job_text
    .find("name: Install Rust toolchain")
    .expect("advisory job should install Rust before advisory checks");
  let install_advisory = advisory_job_text
    .find("name: Install pinned Rust dependency tools")
    .expect("advisory job should install advisory tools");
  let cargo_audit = advisory_job_text
    .find("name: Cargo audit")
    .expect("advisory job should run cargo audit");
  let cargo_deny = advisory_job_text
    .find("name: Cargo deny complete policy")
    .expect("advisory job should run the complete cargo-deny policy");
  let cargo_vet = advisory_job_text
    .find("name: Cargo vet locked review evidence")
    .expect("advisory job should run locked cargo-vet evidence");

  assert!(
    install_rust < install_advisory
      && install_advisory < cargo_audit
      && cargo_audit < cargo_deny
      && cargo_deny < cargo_vet,
    "advisory checks should run after Rust toolchain setup inside their independent job"
  );
}

#[test]
fn node_dependency_admission_is_fail_closed_and_local_on_pull_requests() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let job = jobs
    .get("node-dependency-admission")
    .expect("workflow should define Node dependency admission");
  let job_text = workflow_job_text(&workflow, "node-dependency-admission");

  assert!(
    job.needs.is_empty(),
    "Node dependency admission should be an independent entry gate"
  );
  for expected in [
    "name: Node dependency admission",
    "contents: read",
    "corepack install",
    "pnpm install --frozen-lockfile --ignore-scripts",
    "pnpm run dependency-admission \\",
    "--license-report-path \"${LICENSE_REPORT}\" \\",
    "--audit-report-path \"${AUDIT_REPORT}\"",
    "pnpm licenses list --json --long",
    "pnpm --dir \"${audit_root}\" audit --audit-level low --json",
    "'  ignoreGhsas: []'",
    "pnpm audit signatures",
    "pnpm sbom --sbom-format cyclonedx --lockfile-only",
    "name: Upload local pnpm dependency snapshot",
    "retention-days: 7",
  ] {
    assert!(
      job_text.contains(expected),
      "Node dependency admission should include {expected}"
    );
  }
  for forbidden in [
    "contents: write",
    "id-token: write",
    "packages: write",
    "dependency-graph/snapshots",
    "gh api",
    "continue-on-error",
    "pnpm run dependency-admission -- \\",
  ] {
    assert!(
      !job_text.contains(forbidden),
      "pull-request Node admission must not contain {forbidden}"
    );
  }
}

#[test]
fn typescript_release_tooling_is_required_fail_closed_and_isolated() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let job = jobs
    .get("typescript-release-tooling")
    .expect("workflow should define TypeScript release tooling");
  let job_text = workflow_job_text(&workflow, "typescript-release-tooling");

  assert!(
    job.needs.is_empty(),
    "TypeScript release tooling should be an independent entry gate"
  );
  for expected in [
    "name: TypeScript release tooling",
    "runs-on: ubuntu-26.04",
    DEPENDABOT_ACTOR_CONDITION,
    "contents: read",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # 7.0.1",
    "corepack enable",
    "corepack install",
    "pnpm install --frozen-lockfile --ignore-scripts",
    "pnpm run lint",
    "pnpm run typecheck",
    "pnpm run test",
    "pnpm run kubernetes-graduation:check --expected-source-revision \"${GITHUB_SHA}\"",
    "pnpm run versioning:check",
    "pnpm run release-contract:check \\",
    "fetch-depth: 0",
    "OXIBELT_CHANGE_BASE",
    "--change-base \"${OXIBELT_CHANGE_BASE}\"",
    "--change-head \"${OXIBELT_CHANGE_HEAD}\"",
  ] {
    assert!(
      job_text.contains(expected),
      "TypeScript release tooling should include {expected}"
    );
  }
  for command in [
    "pnpm run lint",
    "pnpm run typecheck",
    "pnpm run test",
    "pnpm run kubernetes-graduation:check",
    "pnpm run versioning:check",
  ] {
    assert_eq!(
      job_text.matches(command).count(),
      1,
      "TypeScript release tooling should run {command} exactly once"
    );
  }
  let install = job_text
    .find("pnpm install --frozen-lockfile --ignore-scripts")
    .expect("TypeScript release tooling should install dependencies");
  let lint = job_text
    .find("pnpm run lint")
    .expect("TypeScript release tooling should lint");
  let typecheck = job_text
    .find("pnpm run typecheck")
    .expect("TypeScript release tooling should type-check");
  let test = job_text
    .find("pnpm run test")
    .expect("TypeScript release tooling should test");
  let kubernetes_graduation = job_text
    .find("name: Validate Kubernetes graduation contract")
    .expect("TypeScript release tooling should validate Kubernetes graduation evidence");
  let versioning = job_text
    .find("pnpm run versioning:check")
    .expect("TypeScript release tooling should validate committed version state");
  let release_contract = job_text
    .find("name: Validate release changelog and upgrade contract")
    .expect("TypeScript release tooling should validate the release contract");
  assert!(
    install < lint
      && lint < typecheck
      && typecheck < test
      && test < kubernetes_graduation
      && kubernetes_graduation < versioning
      && versioning < release_contract,
    "TypeScript release tooling should install, lint, type-check, test, validate Kubernetes graduation evidence, validate version state, and validate the release contract in order"
  );
  for forbidden in [
    "contents: write",
    "id-token: write",
    "packages: write",
    "continue-on-error",
    "pnpm run dependency-admission",
    "pnpm run versioning:release",
    "pnpm run kubernetes-graduation:check -- --expected-source-revision",
    "pnpm run release-contract:check -- \\",
    "actions/upload-artifact",
    "actions/download-artifact",
  ] {
    assert!(
      !job_text.contains(forbidden),
      "TypeScript release tooling must not contain {forbidden}"
    );
  }
}

#[test]
fn rust_advisory_checks_gate_downstream_build_jobs() {
  let jobs = parse_jobs(&workflow_text());

  for job_id in [
    "generate-test-matrices",
    "linux-target-builds",
    "docker-alpine-musl-image-amd64",
    "docker-alpine-musl-role-image-amd64",
    "docker-alpine-musl-role-image-other",
    "docker-alpine-musl-image-other",
    "docker-alpine-musl-image-riscv64",
    "docker-integration-helper-images",
    "kubernetes-network-policy",
  ] {
    let job = jobs
      .get(job_id)
      .unwrap_or_else(|| panic!("workflow should define {job_id}"));
    assert_eq!(
      job.needs,
      expected_needs(PRIMARY_RUST_GATE_NEEDS),
      "{job_id} should wait for all primary Rust and advisory gates"
    );
  }
}

#[test]
fn kubernetes_immutable_rollout_ci_is_isolated_and_proves_each_pod_revision() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let role_image_job = workflow_job_text(&workflow, "docker-alpine-musl-role-image-amd64");
  let job = jobs
    .get("kubernetes-immutable-rollout")
    .expect("workflow should define the Kubernetes immutable rollout job");
  let job_text = workflow_job_text(&workflow, "kubernetes-immutable-rollout");
  let script = kubernetes_immutable_rollout_script_text();
  let l4_values = fs::read_to_string(repo_root().join("tests/fixtures/gateway-api-l4-values.yaml"))
    .expect("Gateway API L4 integration values should be readable");

  assert_eq!(
    job.needs,
    vec!["docker-alpine-musl-role-image-amd64".to_owned()],
    "the Kubernetes rollout job should consume distinct AMD64 data-plane and controller artifacts"
  );
  for expected in [
    "name: Docker role image (Alpine musl, amd64, ${{ matrix.role.name }})",
    "name: dataplane",
    "artifact_prefix: oxibelt-dataplane",
    "name: dataplane-strict",
    "artifact_prefix: oxibelt-dataplane-strict",
    "name: Validate strict data-plane image inventory",
    "if: matrix.role.name == 'dataplane-strict'",
    "tests/scripts/validate-strict-dataplane-image.py",
    "name: controller",
    "artifact_prefix: oxibelt-gateway-controller",
    "name: tools",
    "artifact_prefix: oxibelt-tools",
    "name: keysigner",
    "artifact_prefix: oxibelt-keysigner",
    "tests/scripts/build-docker-image-artifact.sh",
    "\"${{ matrix.role.name }}\"",
    "name: ${{ matrix.role.artifact_prefix }}-alpine-musl-amd64-image",
  ] {
    assert!(
      role_image_job.contains(expected),
      "Kubernetes role-image CI job should include {expected}"
    );
  }
  for expected in [
    "name: Kubernetes ${{ matrix.kubernetes }} immutable Gateway rollout",
    "runs-on: ubuntu-26.04",
    "actions: read",
    "contents: read",
    "fail-fast: false",
    "kubernetes: v1.34.8",
    "kubectl: v1.34.10",
    "kubernetes: v1.35.5",
    "kubectl: v1.35.7",
    "kubernetes: v1.36.1",
    "kubectl: v1.36.3",
    "azure/setup-helm@9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310 # v5.0.1",
    "version: v3.21.3",
    "name: Validate Helm Admin configuration",
    "tests/scripts/check-helm-admin-config.sh",
    "name: Validate Helm base configuration",
    "tests/scripts/check-helm-base-config.sh",
    "name: Validate Helm edge-secure-medium profile",
    "tests/scripts/check-helm-edge-secure-medium-profile.sh",
    "name: Validate Helm strict data-plane profile",
    "tests/scripts/check-helm-strict-dataplane.sh",
    "name: Validate Helm ServiceAccount token hardening",
    "tests/scripts/check-helm-service-account-token.sh",
    "name: Validate Gateway controller high availability",
    "tests/scripts/check-helm-gateway-controller-ha.sh",
    "helm/kind-action@ef37e7f390d99f746eb8b610417061a60e82a6cc # v1.14.0",
    "version: v0.32.0",
    "kubectl_version: ${{ matrix.kubectl }}",
    "install_only: true",
    "name: oxibelt-dataplane-alpine-musl-amd64-image",
    "name: oxibelt-gateway-controller-alpine-musl-amd64-image",
    "docker load --input \"${RUNNER_TEMP}/oxibelt-dataplane-image/oxibelt-dataplane-alpine-musl-amd64.tar\"",
    "docker load --input \"${RUNNER_TEMP}/oxibelt-gateway-controller-image/oxibelt-gateway-controller-alpine-musl-amd64.tar\"",
    "OXIBELT_DATAPLANE_DOCKER_IMAGE: oxibelt-dataplane:alpine-musl-amd64",
    "OXIBELT_GATEWAY_CONTROLLER_DOCKER_IMAGE: oxibelt-gateway-controller:alpine-musl-amd64",
    "OXIBELT_KUBERNETES_KIND_NODE_IMAGE: ${{ matrix.node_image }}",
    "tests/scripts/run-kubernetes-immutable-rollout.sh",
    "timeout-minutes: 30",
  ] {
    assert!(
      job_text.contains(expected),
      "Kubernetes immutable rollout CI job should include {expected}"
    );
  }

  for expected in [
    "gateway_api_version=\"v1.6.1\"",
    "gateway_api_url=\"https://github.com/kubernetes-sigs/gateway-api/releases/download/${gateway_api_version}/standard-install.yaml\"",
    "gateway_api_sha256=\"24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73\"",
    "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256",
    "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95",
    "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
    "unapproved Kind node image",
    "sha256sum --check --status",
    "CI event values are untrusted input",
    "OXIBELT_KUBERNETES_ROLLOUT_TIMEOUT_SECONDS must be a decimal value from 60 through 900",
    "controller_readiness_revocation_timeout_seconds=45",
    "wait_for \"controller readiness revocation after Lease deletion\" \\\n  \"${controller_readiness_revocation_timeout_seconds}\" controller_pods_are_unready",
    "dataplane-image-values.yaml",
    "controller-image-values.yaml",
    "kind create cluster",
    "kind load docker-image",
    "gateway-api-l4-values.yaml",
    "registry.k8s.io/gateway-api/echo-basic:v1.6.0-dev.2@sha256:5dd376a93d8ec7cb8c15b46973bdb1c686db48135058d2606f2e0cf30f8dd63d",
    "redis_source_image=\"valkey/valkey:9-alpine@sha256:3fe38a705227d29534a199e876b38d5474dec4d3baca980ac6894df539416562\"",
    "redis_source_digest=\"${redis_source_image##*@sha256:}\"",
    "redis_kind_image=\"oxibelt-ci/valkey:sha256-${redis_source_digest}-${run_id}\"",
    "redis_kind_image_created=0",
    "docker pull \"${redis_source_image}\"",
    "valkey/valkey@${redis_source_image##*@}",
    "reviewed linux/amd64 Valkey image",
    "refusing to reuse an existing Kind-local Valkey image alias",
    "docker tag \"${redis_source_image}\" \"${redis_kind_image}\"",
    "rootless Docker did not create the reviewed Valkey Kind alias",
    "docker image rm --no-prune \"${redis_kind_image}\"",
    "crictl inspecti \"docker.io/${redis_kind_image}\"",
    "Kind CRI did not retain the reviewed Valkey image alias",
    "sed \"s|OXIBELT_REDIS_KIND_IMAGE|${redis_kind_image}|g\"",
    "oxibelt-udp-flow-redis",
    "oxibelt-udp-flow-state",
    "udp-backend-a",
    "udp-backend-b",
    "runAsUser: 65532",
    "runAsGroup: 65532",
    "kind: TCPRoute",
    "kind: UDPRoute",
    "route_conditions_match",
    ".observedGeneration == $generation",
    ".reason == $resolved_reason",
    "RefNotPermitted",
    "same-namespace TCPRoute and UDPRoute programming",
    "probe_l4_round_trips",
    "verify_udp_flow_survives_data_plane_rollout",
    "oxibelt_stream_udp_flows_restored_total",
    "l4.udp.flowState=shared_required",
    "udp_flow_state = \"shared_required\"",
    "OXIBELT_L4_EXPECTED_NAMESPACE",
    "verify_kind_node_l4_probe_runtime",
    "/usr/bin/perl",
    "IO::Socket::IP",
    "IO::Select",
    "SOCK_STREAM",
    "SOCK_DGRAM",
    "PeerPort => 9300",
    "PeerPort => 5300",
    "$selector->can_read(5)",
    "$selector->can_read(2)",
    "while (length($buffer) < 4096)",
    "my $remaining = $deadline - time()",
    "$selector->can_read($remaining)",
    "my $request = \"TEST\\n\"",
    "my $request = \"oxibelt-udp-probe\"",
    "jq -s -e",
    "length == 1",
    ".[0].namespace == env.OXIBELT_L4_EXPECTED_NAMESPACE",
    "verify_cross_namespace_l4_reference_grants",
    "cross-namespace L4 routes rejected without ReferenceGrant",
    "deployment_committed_revision_changed",
    "fail-closed immutable revision without ReferenceGrant",
    "l4_ports_fail_closed",
    "TCP listener remained reachable without ReferenceGrant",
    "cross-namespace L4 routes programmed by ReferenceGrant",
    "kind: ReferenceGrant",
    "name: oxibelt-tcp-probe",
    "name: oxibelt-udp-probe",
    "focused Gateway API TCP/UDP integration passed",
    "docker exec",
    "kind delete cluster --name \"${cluster_name}\"",
    "docker version --format '{{.Server.Version}}'",
    "docker image inspect \"${dataplane_image}\"",
    "docker image inspect \"${controller_image}\"",
    "OXIBELT_DATAPLANE_DOCKER_IMAGE",
    "OXIBELT_GATEWAY_CONTROLLER_DOCKER_IMAGE",
    "data-plane and controller tests require distinct role image references",
    "--set \"replicaCount=3\"",
    "admin-mtls-values.yaml",
    "oxibelt-admin-server",
    "oxibelt-admin-client-ca",
    "--from-file=token=",
    "openssl rand -hex 32 | tr -d '\\r\\n' >\"${work_dir}/admin-token\"",
    "grep -Eq '^[a-f0-9]{64}$' \"${work_dir}/admin-token\"",
    "verify_admin_mtls",
    "verify_admin_immutable_secret_boundary",
    "/admin/v1/config/secret-references/update",
    ".features.atomic_secret_reference_activation == false",
    "tls.remote_signer.token_env",
    "OXIBELT_IMMUTABLE_PROBE_UNUSED",
    ".error.code == \"immutable_rollout_conflict\"",
    "immutable secret-reference rejection changed config revision or rollout identity",
    "Admin listener completed an HTTP exchange without a client certificate",
    ".projected.defaultMode == 288",
    "automountServiceAccountToken == false",
    "kube-api-access",
    "serviceAccountToken.expirationSeconds == 3600",
    "default data-plane Pod template must not mount a Kubernetes API credential",
    "assert_controller_can_i",
    "auth can-i --quiet",
    "controller ServiceAccount unexpectedly has permission",
    "get secrets",
    "create services",
    "patch services",
    "update services",
    "delete services",
    "delete configmaps",
    "deployments.apps/not-the-target",
    "configRollout.mode=kubernetes_immutable",
    "rollout.target.name=${workload_name}",
    "Gateway Programmed=True after full rollout convergence",
    "all three Ready Pods must carry the exact assigned revision and digest",
    "x-oxibelt-config-revision",
    "x-oxibelt-config-digest",
    "ConfigMap raw bytes do not match the Pod-assigned digest",
    "stale_config_pod_failed_closed",
    "a failed-closed stale-config Pod",
    ".status.phase == \"Failed\"",
    ".state.terminated.reason == \"Error\"",
    "stale_config_pod_reports_digest_mismatch",
    "OXIBELT_CONFIG_DIGEST does not match the exact bytes of OXIBELT_CONFIG_REVISION_FILE",
    "stale-config-${run_id}",
    "oxibelt.dev/config-digest",
    "logs \"${controller_pod}\"",
    "--all-containers=true --prefix --previous --tail=200",
    "logs -l 'oxibelt.dev/test=stale-config'",
  ] {
    assert!(
      script.contains(expected),
      "Kubernetes immutable rollout script should preserve {expected}"
    );
  }
  for expected in [
    "tcp-probe, protocol: TCP, port: 9300, targetPort: 19300",
    "udp-probe, protocol: UDP, port: 5300, targetPort: 15300",
    "name: OXIBELT_UDP_FLOW_IDENTITY_KEY",
    "name: oxibelt-udp-flow-state",
    "udp_flow_identity_key_env = \"OXIBELT_UDP_FLOW_IDENTITY_KEY\"",
    "connection_limits_backend = \"udp-flows\"",
    "udp_flows_backend = \"udp-flows\"",
    "connection_url = \"redis://oxibelt-udp-flow-redis:6379/0\"",
    "udp_flows = \"reject_new_only\"",
  ] {
    assert!(
      l4_values.contains(expected),
      "Gateway API L4 integration values should preserve {expected}"
    );
  }
  assert_eq!(
    l4_values.matches("targetPort:").count(),
    2,
    "the focused L4 fixture should expose only its TCP and UDP probe ports"
  );
  assert!(
    !script.contains("experimental-install.yaml"),
    "the Kubernetes v1.31 rollout must not install experimental CRDs that require newer CEL libraries"
  );
  for removed_profile_claim in [
    "gateway_api_commit=",
    "gateway-api-conformance-values.yaml",
    "run_gateway_api_l4_conformance",
    "gateway_class_has_supported_features",
    "conformance_udp_limits_are_active",
    "-conformance-profiles=",
    "-supported-features",
    "-exempt-features",
    "-report-output=",
    "GOTOOLCHAIN=auto go test -c",
    "git clone --quiet --filter=blob:none",
  ] {
    assert!(
      !script.contains(removed_profile_claim),
      "the focused L4 integration must not retain unsupported profile-conformance claim {removed_profile_claim}"
    );
  }
  for expected in [
    "crd/tcproutes.gateway.networking.k8s.io",
    "crd/udproutes.gateway.networking.k8s.io",
    "crd/backendtlspolicies.gateway.networking.k8s.io",
  ] {
    assert!(
      script.contains(expected),
      "the Kubernetes rollout must wait for the Gateway API v1 Phase 6 CRD {expected}"
    );
  }
  assert!(
    !script.contains("v1alpha2") && !script.contains("kube patch crd"),
    "the Kubernetes rollout must use served Gateway API v1 resources without mutating CRD versions"
  );

  for removed in [
    "stale_config_pod_is_running_and_unready",
    "health_endpoint_is_unready",
    "check_stale_config_pod",
    "a running but unready stale-config Pod",
  ] {
    assert!(
      !script.contains(removed),
      "Kubernetes immutable rollout script must prove a stale digest fails before startup instead of preserving {removed}"
    );
  }

  for forbidden in [
    "docker-rootful",
    "docker system prune",
    "docker container prune",
    "kubectl delete --all",
    "kubectl delete namespace --all",
    "kubectl get secret",
    "kubectl describe secret",
  ] {
    assert!(
      !script.contains(forbidden),
      "Kubernetes immutable rollout script must not contain unsafe or secret-disclosing operation {forbidden}"
    );
  }
}

#[test]
fn kubernetes_immutable_rollout_lease_recovery_does_not_roll_controller() {
  let script = kubernetes_immutable_rollout_script_text();
  let cleanup = script
    .split_once("cleanup() {")
    .expect("rollout harness should define scoped cleanup")
    .1
    .split_once("\n}\ntrap cleanup EXIT")
    .expect("rollout cleanup should precede the EXIT trap")
    .0;
  let convergence = script
    .split_once("controller_has_two_ready_replicas() {")
    .expect("rollout harness should define controller convergence")
    .1
    .split_once("\n}\n\ncontroller_pod_uids() {")
    .expect("controller convergence should precede Pod UID capture")
    .0;
  let pod_uids = script
    .split_once("controller_pod_uids() {")
    .expect("rollout harness should capture controller Pod UIDs")
    .1
    .split_once("\n}\n\ncontroller_pod_runtime_identities() {")
    .expect("controller Pod UID capture should precede container identity capture")
    .0;
  let controller_phase = script
    .split_once("# Exercise the Deployment's RollingUpdate strategy.")
    .expect("rollout harness should exercise controller RollingUpdate")
    .1
    .split_once("\n\nverify_cross_namespace_l4_reference_grants")
    .expect("controller recovery should precede cross-namespace qualification")
    .0;

  for expected in [
    ".status.observedGeneration == .metadata.generation",
    ".status.replicas == 2",
    ".status.updatedReplicas == 2",
    ".status.readyReplicas == 2",
    ".status.availableReplicas == 2",
    "(.status.unavailableReplicas // 0) == 0",
    ".spec.strategy.rollingUpdate.maxUnavailable == 0",
    ".spec.strategy.rollingUpdate.maxSurge == 1",
    "($pods | length) == 2",
    ".type == \"Ready\" and .status == \"True\"",
  ] {
    assert!(
      convergence.contains(expected),
      "controller convergence must fail closed on missing invariant {expected}"
    );
  }
  assert!(
    pod_uids.contains("($pods | length) == 2")
      && pod_uids.contains(".type == \"Ready\" and .status == \"True\""),
    "controller Pod UID capture must reject a partial, unready, or surge baseline"
  );

  for expected in [
    "while IFS= read -r controller_pod",
    "get pods -l \"${controller_selector}\"",
    "logs \"${controller_pod}\"",
    "--all-containers=true --prefix --tail=200",
    "--all-containers=true --prefix --previous --tail=200",
  ] {
    assert!(
      cleanup.contains(expected),
      "controller failure diagnostics should preserve {expected}"
    );
  }
  assert!(
    !cleanup.contains("logs \"deployment/${controller_release}\""),
    "controller diagnostics must not select only one Deployment Pod"
  );

  for expected in [
    "controller_pod_uids() {",
    "controller_pod_runtime_identities() {",
    "controller_replicaset_uids() {",
    "assert_controller_can_i no create leases.coordination.k8s.io",
    "two stable Helm-reconciled controller replicas before Lease deletion",
    "controller_generation_before=",
    "controller_template_digest_before=",
    "controller_pod_uids_before=",
    "controller_pod_runtime_identities_before=",
    "controller_replicaset_uids_before=",
    "controller readiness revocation after Lease deletion",
    "\"${controller_pod_runtime_identities_before}\"",
    "two unchanged controller replicas after Lease recreation",
    "new_lease_uid",
    "controller_generation_after=",
    "controller_template_digest_after=",
    "controller_pod_uids_after=",
    "controller_pod_runtime_identities_after=",
    "controller_replicaset_uids_after=",
    ".state.running != null",
    "container_id: .containerID",
    "restart_count: .restartCount",
    "Lease recreation unexpectedly changed the controller Deployment generation",
    "Lease recreation unexpectedly changed the controller Pod template",
    "Lease recreation unexpectedly replaced a controller Pod",
    "Lease recreation unexpectedly restarted a controller container",
    "Lease recreation unexpectedly changed the controller ReplicaSet set",
    r#"[[ "${controller_generation_after}" == "${controller_generation_before}" ]]"#,
    r#"[[ "${controller_template_digest_after}" == "${controller_template_digest_before}" ]]"#,
    r#"[[ "${controller_pod_uids_after}" == "${controller_pod_uids_before}" ]]"#,
    r#"[[ "${controller_pod_runtime_identities_after}" == "${controller_pod_runtime_identities_before}" ]]"#,
    r#"[[ "${controller_replicaset_uids_after}" == "${controller_replicaset_uids_before}" ]]"#,
  ] {
    assert!(
      script.contains(expected),
      "Lease recovery isolation should preserve {expected}"
    );
  }

  for forbidden in [
    "--force",
    "kube -n \"${namespace}\" replace",
    "rollout undo",
    "kubectl.kubernetes.io/restartedAt-",
  ] {
    assert!(
      !controller_phase.contains(forbidden),
      "controller recovery must not force replacement or remove live-only rollout state with {forbidden}"
    );
  }

  assert_eq!(
    controller_phase.matches("--reuse-values").count(),
    2,
    "healthy reconciliation and Lease recovery must both reuse the reviewed release values"
  );
  assert_eq!(
    controller_phase.matches("\n  --wait \\").count(),
    2,
    "healthy reconciliation and Lease recovery must both remain fail-closed on readiness"
  );

  let restart = controller_phase
    .find("rollout restart \"deployment/${controller_release}\"")
    .expect("controller phase should start an explicit RollingUpdate");
  let healthy_reconcile = controller_phase
    .find("# Reconcile the release while the Lease is healthy, then capture the fully")
    .expect("controller phase should establish a stable live baseline while the Lease is healthy");
  let helm_upgrades = controller_phase
    .match_indices("helm upgrade \"${controller_release}\"")
    .map(|(position, _)| position)
    .collect::<Vec<_>>();
  assert_eq!(
    helm_upgrades.len(),
    2,
    "controller phase should perform one healthy reconciliation and one Lease recovery"
  );
  let healthy_helm = helm_upgrades[0];
  let recovery_helm = helm_upgrades[1];
  let baseline = controller_phase
    .find("controller_deployment_before=")
    .expect("controller phase should capture the Helm-converged baseline");
  let delete_lease = controller_phase
    .find("delete lease \"${leader_lease_name}\"")
    .expect("controller phase should revoke the Helm-owned Lease");
  let compare_identity = controller_phase
    .find("Lease recreation unexpectedly changed the controller Deployment generation")
    .expect("Lease recovery should compare the controller identity");
  assert!(
    restart < healthy_reconcile
      && healthy_reconcile < healthy_helm
      && healthy_helm < baseline
      && baseline < delete_lease
      && delete_lease < recovery_helm
      && recovery_helm < compare_identity,
    "controller restart, stable live baseline capture, Lease revocation, recovery, and no-churn comparison must remain ordered"
  );
}

#[test]
fn kubernetes_immutable_rollout_udp_flow_state_is_shared_and_restart_proven() {
  let script = kubernetes_immutable_rollout_script_text();
  let l4_values = fs::read_to_string(repo_root().join("tests/fixtures/gateway-api-l4-values.yaml"))
    .expect("Gateway API L4 integration values should be readable");
  let restart_proof = script
    .split_once("verify_udp_flow_survives_data_plane_rollout() {")
    .expect("rollout harness should define the UDP flow restart proof")
    .1
    .split_once("\n}\n\ncontroller_has_two_ready_replicas() {")
    .expect("UDP flow restart proof should precede controller readiness checks")
    .0;
  let cross_namespace_proof = script
    .split_once("verify_cross_namespace_l4_reference_grants() {")
    .expect("rollout harness should define the cross-namespace L4 proof")
    .1
    .split_once("\n}\n\nassert_controller_can_i() {")
    .expect("cross-namespace proof should precede controller permission checks")
    .0;

  for expected in [
    "openssl rand -base64 32 | tr -d '\\r\\n' >\"${work_dir}/udp-flow-identity-key\"",
    "grep -Eq '^[A-Za-z0-9+/]{43}=$' \"${work_dir}/udp-flow-identity-key\"",
    "create secret generic oxibelt-udp-flow-state",
    "--from-file=identity-key=",
    "image: OXIBELT_REDIS_KIND_IMAGE",
    "imagePullPolicy: Never",
    "--maxmemory",
    "32mb",
    "--maxmemory-policy",
    "noeviction",
    "readOnlyRootFilesystem: true",
    "emptyDir: { sizeLimit: 16Mi }",
    "rollout status deployment/oxibelt-udp-flow-redis",
    "\"${dataplane_image}\" \"${controller_image}\" \"${redis_kind_image}\"",
    "--set \"l4.idleTimeoutMs=3600000\"",
    "--set-string \"l4.udp.flowState=shared_required\"",
    "grep -Fq 'udp_flow_state = \"shared_required\"'",
    "verify_udp_flow_survives_data_plane_rollout",
  ] {
    assert!(
      script.contains(expected),
      "shared UDP flow qualification should preserve {expected}"
    );
  }
  assert_eq!(
    script
      .matches("--set-string \"l4.udp.flowState=shared_required\"")
      .count(),
    2,
    "both scoped and cross-namespace controller upgrades must retain the explicit shared UDP mode"
  );
  assert!(
    !script.contains("sha256:ee91f7a174ac4d6a6b0685b3a60e321f0a9dbbb691f9b0e285be2ba1d1be8328"),
    "the shared-state qualification must not restore the partially pulled multi-platform Valkey index"
  );
  assert!(
    !script.contains("image: valkey/valkey:9-alpine"),
    "the in-cluster shared-state backend must use the verified Kind-local Valkey alias"
  );

  for expected in [
    "OXIBELT_L4_INITIAL_POD_ADDRESS",
    "OXIBELT_L4_REPLACEMENT_TARGET_FILE",
    "my $connection = IO::Socket::IP->new(",
    "PeerPort => 15300",
    "my $source_host = $connection->sockhost",
    "my $source_port = $connection->sockport",
    "print STDOUT \"SOURCE\\t$source_host:$source_port\\n\"",
    "my $first_written = $connection->send($first_request)",
    "getaddrinfo(",
    "flags => AI_NUMERICHOST",
    "$connection->connect($addresses[0]->{addr})",
    "UDP restart probe source tuple changed across Pod replacement",
    "my $written = $connection->send($second_request)",
    "OXIBELT_L4_REPLACEMENT_POD_ADDRESS",
    "my $pending_file = \"$target_file.pending\"",
    "rename $pending_file, $target_file",
    "kube -n \"${namespace}\" rollout restart \"deployment/${workload_name}\"",
    "data_plane_pods_replaced \"${old_uids}\"",
    "data_plane_pod_logged_udp_peer \"${old_probe_pod}\" \"${source_peer}\"",
    "data_plane_pod_logged_udp_peer \"${replacement_probe_pod}\" \"${source_peer}\"",
    "second response on the same UDP client socket",
    ".[1].service == .[0].service",
    ".[1].pod == .[0].pod",
    "udp-backend-a",
    "udp-backend-b",
    "verify_udp_restore_metric \"${replacement_probe_pod}\"",
    "same-namespace TCP and UDP round trips after data-plane Pod replacement",
  ] {
    assert!(
      restart_proof.contains(expected),
      "same-socket UDP restart proof should preserve {expected}"
    );
  }
  assert!(
    !restart_proof.contains("status_service_address"),
    "the durable UDP restart proof must bypass node-originated Service NAT and control the peer tuple explicitly"
  );
  assert_eq!(
    restart_proof.matches("| select(length > 0)").count(),
    2,
    "the old and replacement Pod selectors must both fail closed when no Ready IPv4 target exists"
  );
  assert!(
    script.contains("oxibelt_stream_udp_flows_restored_total"),
    "the rollout harness must inspect the durable UDP restore metric"
  );
  for expected in [
    "patch udproute udp-probe",
    "cross-namespace TCP and UDP round trips",
    "probe_l4_round_trips \"${outside_namespace}\"",
  ] {
    assert!(
      cross_namespace_proof.contains(expected),
      "the cross-namespace proof should preserve the same-scope generation transition {expected}"
    );
  }
  assert!(
    !script.contains("udp-cross-probe")
      && !cross_namespace_proof.contains("FLUSHDB")
      && !cross_namespace_proof.contains("FLUSHALL"),
    "the durable UDP generation regression must not switch listeners or clear shared state"
  );
  assert!(
    script
      .rfind("verify_udp_flow_survives_data_plane_rollout")
      .expect("rollout harness should run the durable UDP replacement proof")
      < script
        .rfind("verify_cross_namespace_l4_reference_grants")
        .expect("rollout harness should run the cross-namespace generation proof"),
    "an active durable UDP flow must exist before the same listener changes routing generation"
  );

  for expected in [
    "name: OXIBELT_UDP_FLOW_IDENTITY_KEY",
    "valueFrom:",
    "secretKeyRef:",
    "name: oxibelt-udp-flow-state",
    "key: identity-key",
    "enabled = true",
    "redis_plaintext_policy = \"allow\"",
    "udp_flow_identity_key_env = \"OXIBELT_UDP_FLOW_IDENTITY_KEY\"",
    "connection_limits_backend = \"udp-flows\"",
    "udp_flows_backend = \"udp-flows\"",
    "udp_flows = \"reject_new_only\"",
    "connection_url = \"redis://oxibelt-udp-flow-redis:6379/0\"",
  ] {
    assert!(
      l4_values.contains(expected),
      "shared UDP flow values should preserve {expected}"
    );
  }
  assert!(
    !script.contains("GATEWAY-UDP") && !script.contains("GATEWAY-TCP"),
    "the focused restart proof must not claim a Gateway API conformance profile"
  );
}

#[test]
fn kubernetes_immutable_rollout_l4_probes_use_pinned_package_free_runtime() {
  let script = kubernetes_immutable_rollout_script_text();
  let probes = script
    .split_once("verify_kind_node_l4_probe_runtime() {")
    .expect("rollout harness should define a Kind-node L4 probe runtime preflight")
    .1
    .split_once("\n}\n\ncontroller_has_two_ready_replicas() {")
    .expect("the package-free L4 probes should precede controller readiness checks")
    .0;

  for expected in [
    "/usr/bin/perl",
    "-MIO::Socket::IP",
    "-MIO::Select",
    "-MSocket=AI_NUMERICHOST,SOCK_DGRAM,SOCK_STREAM,getaddrinfo",
    "PeerHost => $ENV{OXIBELT_L4_ADDRESS}",
    "PeerPort => 9300",
    "PeerPort => 5300",
    "Timeout => 5",
    "Timeout => 2",
    "while (length($buffer) < 4096)",
    "my $deadline = time() + $timeout",
    "my $remaining = $deadline - time()",
    "$selector->can_read($remaining)",
    "$selector->can_read(2)",
    "my $request = \"TEST\\n\"",
    "my $request = \"oxibelt-udp-probe\"",
    "my $request = \"oxibelt-udp-denied-probe\"",
    "my $peer = $connection->recv(my $response, 4096)",
    "my $peer = $udp->recv(my $response, 4096)",
    "OXIBELT_L4_EXPECTED_NAMESPACE=\"${expected_namespace}\"",
    "jq -s -e",
    "length == 1",
    ".[0].request == \"oxibelt-udp-probe\"",
    ".[0].namespace == env.OXIBELT_L4_EXPECTED_NAMESPACE",
    ".[0].service == \"tcp-backend\"",
    "$expected_services | index($service) != null",
    "TCP listener remained reachable without ReferenceGrant",
    "UDP listener remained reachable without ReferenceGrant",
  ] {
    assert!(
      probes.contains(expected),
      "package-free Kind-node L4 probes should preserve {expected}"
    );
  }
  assert_eq!(
    probes.matches("/usr/bin/perl").count(),
    6,
    "the L4 harness should preflight Perl once and use it for TCP, UDP, denied, and same-socket restart probe and handoff"
  );
  assert!(
    script
      .contains("cluster_created=1\nverify_kind_node_l4_probe_runtime\n\nkind load docker-image"),
    "the Kind-node L4 probe runtime must be verified immediately after cluster creation"
  );

  for forbidden in [
    "python3 -c",
    "apt-get",
    "apk add",
    "dnf install",
    "yum install",
    "pip install",
    "kubectl run",
  ] {
    assert!(
      !probes.contains(forbidden),
      "package-free Kind-node L4 probes must not use {forbidden}"
    );
  }
}

#[test]
fn kubernetes_immutable_rollout_admin_mtls_probe_is_connection_isolated() {
  let script = kubernetes_immutable_rollout_script_text();
  let diagnostics = script
    .split_once("print_admin_probe_diagnostics() {")
    .expect("rollout harness should define bounded Admin probe diagnostics")
    .1
    .split_once("\n}\n\nkube() {")
    .expect("Admin probe diagnostics should precede the kubectl wrapper")
    .0;
  let readiness = script
    .split_once("admin_port_forward_is_ready() {")
    .expect("rollout harness should define Admin port-forward readiness")
    .1
    .split_once("\n}\n\nstart_admin_port_forward() {")
    .expect("Admin port-forward readiness should precede startup")
    .0;
  let start = script
    .split_once("start_admin_port_forward() {")
    .expect("rollout harness should define phase-specific Admin port-forward startup")
    .1
    .split_once("\n}\n\nstop_admin_port_forward() {")
    .expect("Admin port-forward startup should precede teardown")
    .0;
  let stop = script
    .split_once("stop_admin_port_forward() {")
    .expect("rollout harness should define exact Admin port-forward teardown")
    .1
    .split_once("\n}\n\nadmin_pod_runtime_identity() {")
    .expect("Admin port-forward teardown should precede Pod identity capture")
    .0;
  let identity = script
    .split_once("admin_pod_runtime_identity() {")
    .expect("rollout harness should capture the selected Admin Pod identity")
    .1
    .split_once("\n}\n\nadmin_tls_handshake_failure_count() {")
    .expect("Admin Pod identity capture should precede TLS rejection evidence")
    .0;
  let immutable_boundary = script
    .split_once("verify_admin_immutable_secret_boundary() {")
    .expect("rollout harness should define the immutable secret-reference boundary proof")
    .1
    .split_once("\n}\n\nverify_admin_mtls() {")
    .expect("immutable secret-reference proof should precede the Admin mTLS proof")
    .0;
  let verify = script
    .split_once("verify_admin_mtls() {")
    .expect("rollout harness should define the Admin mTLS proof")
    .1
    .split_once("\n}\n\ncheck_pod_runtime_proof() {")
    .expect("Admin mTLS proof should precede the per-Pod runtime proof")
    .0;
  let no_client_certificate_probe = verify
    .split_once("  if curl ")
    .expect("Admin mTLS proof should issue a no-client-certificate curl probe")
    .1
    .split_once("\n  fi")
    .expect("no-client-certificate curl probe should be a bounded conditional")
    .0;

  assert!(
    readiness.contains("kill -0 \"${port_forward_pid}\"")
      && readiness.contains("Forwarding from 127.0.0.1:${port} -> 9092"),
    "each Admin probe must wait for both a live forwarding process and the kubectl bind message"
  );
  for expected in [
    "authenticated-before-rejection",
    "no-client-certificate",
    "authenticated-after-rejection",
    "\"pod/${pod}\" \"${port}:9092\"",
    "wait_for \"${phase} Admin port-forward bind\"",
  ] {
    assert!(
      start.contains(expected),
      "phase-specific Admin port-forward startup should preserve {expected}"
    );
  }
  assert!(
    !script.contains("\"service/${admin_service_name}\" \"${port}:9092\""),
    "Admin mTLS probes must not reuse a Service-targeted kubectl port-forward"
  );
  for expected in [
    "kill \"${port_forward_pid}\"",
    "wait \"${port_forward_pid}\"",
    "port_forward_pid=\"\"",
  ] {
    assert!(
      stop.contains(expected),
      "Admin port-forward teardown should preserve {expected}"
    );
  }

  for expected in [
    ".metadata.uid",
    "$container.containerID",
    "$container.restartCount",
    "$container.ready == true",
    "$container.state.running != null",
  ] {
    assert!(
      identity.contains(expected),
      "Admin Pod identity capture should preserve {expected}"
    );
  }
  for expected in [
    "identity_before=\"$(admin_pod_runtime_identity \"${pod}\")\"",
    "identity_after=\"$(admin_pod_runtime_identity \"${pod}\")\"",
    "[[ \"${identity_after}\" == \"${identity_before}\" ]]",
    "verify_admin_immutable_secret_boundary \"${port}\"",
    "admin_tls_rejection_observed \"${pod}\" \"${tls_failures_before}\"",
    "Admin listener did not recover after rejecting a client without a certificate",
  ] {
    assert!(
      verify.contains(expected),
      "Admin mTLS proof should preserve {expected}"
    );
  }
  for expected in [
    "admin_get_json \"${port}\" \"/admin/v1/capabilities\"",
    ".features.atomic_secret_reference_activation == false",
    "admin_get_json \"${port}\" \"/admin/v1/config/status\"",
    "field: \"tls.remote_signer.token_env\"",
    "reference: \"OXIBELT_IMMUTABLE_PROBE_UNUSED\"",
    "--header \"If-Match: ${etag}\"",
    "--header \"@${work_dir}/admin-headers.txt\"",
    "--data-binary \"@${request}\"",
    "/admin/v1/config/secret-references/update",
    "[[ \"${http_status}\" == \"409\" ]]",
    ".error.code == \"immutable_rollout_conflict\"",
    "grep -Fq -f \"${work_dir}/admin-token\"",
    "[[ \"${state_after}\" == \"${state_before}\" ]]",
  ] {
    assert!(
      immutable_boundary.contains(expected),
      "immutable secret-reference boundary proof should preserve {expected}"
    );
  }
  assert_eq!(
    immutable_boundary
      .matches("admin_get_json \"${port}\" \"/admin/v1/config/status\"")
      .count(),
    2,
    "immutable secret-reference boundary proof should capture config status before and after the rejected mutation"
  );
  assert!(
    !script.contains("docker-rootful"),
    "the Kubernetes immutable rollout harness must remain on the rootless docker CLI"
  );
  for forbidden in [
    "Authorization: Bearer",
    "--verbose",
    "--trace",
    "cat \"${work_dir}/admin-headers.txt\"",
    "cat \"${work_dir}/admin-token\"",
  ] {
    assert!(
      !immutable_boundary.contains(forbidden),
      "immutable secret-reference boundary proof must not expose credentials through {forbidden}"
    );
  }

  let phase_positions = [
    "start_admin_port_forward \"${pod}\" \"${port}\" authenticated-before-rejection",
    "start_admin_port_forward \"${pod}\" \"${port}\" no-client-certificate",
    "start_admin_port_forward \"${pod}\" \"${port}\" authenticated-after-rejection",
  ]
  .map(|phase| {
    verify
      .find(phase)
      .unwrap_or_else(|| panic!("Admin mTLS proof should start phase {phase}"))
  });
  let stop_positions = verify
    .match_indices("stop_admin_port_forward")
    .map(|(position, _)| position)
    .collect::<Vec<_>>();
  let immutable_boundary_position = verify
    .find("verify_admin_immutable_secret_boundary \"${port}\"")
    .expect("authenticated Admin phase should prove the immutable secret-reference boundary");
  assert_eq!(
    stop_positions.len(),
    3,
    "each Admin mTLS phase should stop and reap its own port-forward"
  );
  assert!(
    phase_positions[0] < stop_positions[0]
      && phase_positions[0] < immutable_boundary_position
      && immutable_boundary_position < stop_positions[0]
      && stop_positions[0] < phase_positions[1]
      && phase_positions[1] < stop_positions[1]
      && stop_positions[1] < phase_positions[2]
      && phase_positions[2] < stop_positions[2],
    "Admin mTLS phases must run in authenticated, rejected, authenticated order with isolated forwards"
  );

  assert!(
    !no_client_certificate_probe.contains("--fail")
      && !no_client_certificate_probe.contains("--cert")
      && !no_client_certificate_probe.contains("--key"),
    "the negative Admin probe must treat every HTTP response as failure and omit client credentials"
  );
  assert!(
    script.contains("grep -Fc \"admin TLS handshake failed\"")
      && script.contains("((10#${after} > 10#${before}))"),
    "the negative Admin probe must require a newly observed server-side TLS rejection"
  );
  assert!(
    script.contains("verify_admin_mtls \"${pods[0]}\""),
    "the Admin mTLS proof must target one of the exact Ready Pods proved by the rollout"
  );

  assert!(
    diagnostics.contains("tail -n 80")
      && diagnostics.contains("admin-port-forward-${phase}.log")
      && diagnostics.contains("admin-no-client-certificate-curl.log"),
    "Admin failure diagnostics must remain bounded and phase-specific"
  );
  for forbidden in ["admin-headers.txt", "admin-token", ".crt", ".key"] {
    assert!(
      !diagnostics.contains(forbidden),
      "Admin failure diagnostics must not expose credential material through {forbidden}"
    );
  }
}

#[test]
fn kubernetes_pod_lifecycle_ci_exercises_distribution_drain_and_worker_loss() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let job = jobs
    .get("kubernetes-pod-lifecycle")
    .expect("workflow should define the Kubernetes Pod lifecycle job");
  let job_text = workflow_job_text(&workflow, "kubernetes-pod-lifecycle");
  let script = kubernetes_pod_lifecycle_script_text();

  assert_eq!(
    job.needs,
    vec!["docker-alpine-musl-image-amd64".to_owned()],
    "the Kubernetes Pod lifecycle job should consume the already-scanned AMD64 OxiBelt image artifact"
  );
  for expected in [
    "name: Kubernetes Pod distribution and lifecycle",
    "runs-on: ubuntu-26.04",
    "actions: read",
    "contents: read",
    "timeout-minutes: 35",
    "azure/setup-helm@9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310 # v5.0.1",
    "version: v3.21.3",
    "name: Validate Helm Pod distribution and lifecycle",
    "tests/scripts/check-helm-pod-lifecycle.sh",
    "name: Validate Helm autoscaling configuration",
    "tests/scripts/check-helm-autoscaling.sh",
    "helm/kind-action@ef37e7f390d99f746eb8b610417061a60e82a6cc # v1.14.0",
    "version: v0.32.0",
    "kubectl_version: v1.34.10",
    "install_only: true",
    "tests/scripts/select-amd64-docker-image-artifact.sh auto",
    "docker load --input \"${RUNNER_TEMP}/oxibelt-image/${OXIBELT_IMAGE_TAR}\"",
    "OXIBELT_DOCKER_IMAGE: ${{ steps.select-amd64-image.outputs.image_tag }}",
    "OXIBELT_KUBERNETES_POD_LIFECYCLE_TIMEOUT_SECONDS: \"600\"",
    "OXIBELT_RUN_KUBERNETES_POD_LIFECYCLE: \"1\"",
    "tests/scripts/run-kubernetes-pod-lifecycle.sh",
  ] {
    assert!(
      job_text.contains(expected),
      "Kubernetes Pod lifecycle CI job should include {expected}"
    );
  }

  for expected in [
    "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256",
    "OXIBELT_KUBERNETES_POD_LIFECYCLE_TIMEOUT_SECONDS must be a decimal value from 180 through 900",
    "Skipping Kubernetes Pod lifecycle test; set OXIBELT_RUN_KUBERNETES_POD_LIFECYCLE=1 to run it.",
    "'- role: worker'",
    "Kind lifecycle cluster must expose exactly three worker nodes",
    "io.x-k8s.kind.cluster",
    "has(\"node-role.kubernetes.io/control-plane\") | not",
    "topology.kubernetes.io/zone",
    "workers_are_eligible() {",
    ".type == \"Ready\" and .status == \"True\"",
    ".spec.unschedulable != true",
    ".effect == \"NoSchedule\" or .effect == \"NoExecute\"",
    ".metadata.labels[\"topology.kubernetes.io/zone\"] == $zone",
    "wait_for \"all lifecycle-test workers to become eligible\" 120 workers_are_eligible",
    "node_eligibility_diagnostics >&2 || true",
    "get pods -o wide --ignore-not-found",
    "podDistribution.enabled=true",
    "lifecycle.preStop.enabled=true",
    "lifecycle.preStop.drainSeconds=10",
    "lifecycle.terminationGracePeriodSeconds=45",
    "podDisruptionBudget.maxUnavailable=1",
    "podDisruptionBudget.unhealthyPodEvictionPolicy=AlwaysAllow",
    "lifecycle_route_configmap=\"oxibelt-lifecycle-route\"",
    "immutable: true",
    "lifecycle-route.toml: |-",
    "name = \"lifecycle-fixture\"",
    "hosts = [\"oxibelt-lifecycle.test\"]",
    "path_prefix = \"/lifecycle-fixture\"",
    "[routes.actions.redirect]",
    "status = 308",
    "location_template = \"/lifecycle-ready\"",
    "defaultMode: 288",
    "mountPath: /etc/oxibelt/config/conf.d",
    "readOnly: true",
    "--kube-context \"kind-${cluster_name}\"",
    "topologySpreadConstraints | length) == 2",
    ".nodeTaintsPolicy == \"Honor\"",
    "rolling update reduced ready capacity below two Pods",
    "terminating Pod endpoint withdrawal before exit",
    "kubernetes.io/service-name=${service_name}",
    ".conditions.ready != false",
    "docker stop \"${worker_to_stop}\"",
    "two surviving Ready Pods after a verified worker loss",
    "docker container inspect --format '{{.State.Running}}'",
    "kind delete cluster --name \"${cluster_name}\"",
  ] {
    assert!(
      script.contains(expected),
      "Kubernetes Pod lifecycle script should preserve {expected}"
    );
  }

  assert_eq!(
    script
      .matches("has(\"node-role.kubernetes.io/control-plane\") | not")
      .count(),
    2,
    "Kubernetes Pod lifecycle worker selection must exclude an existing control-plane label in both checks"
  );
  assert!(
    !script
      .contains("(.metadata.labels[\"node-role.kubernetes.io/control-plane\"] // \"\") == \"\""),
    "Kubernetes Pod lifecycle worker selection must not treat an empty control-plane label as absent"
  );
  assert!(
    !script.contains("(.conditions.ready // true) == true"),
    "Kubernetes Pod lifecycle endpoint withdrawal must not treat explicit false readiness as true"
  );
  assert!(
    script
      .find("lifecycle-route.toml: |-")
      .expect("Kubernetes Pod lifecycle script should create its route fixture")
      < script
        .find("helm upgrade --install")
        .expect("Kubernetes Pod lifecycle script should install the Helm release"),
    "Kubernetes Pod lifecycle route fixture must exist before the Helm release starts"
  );
  let worker_labels = script
    .find("topology.kubernetes.io/zone=${zone_labels[${index}]}\"")
    .expect("Kubernetes Pod lifecycle script should label its workers by zone");
  let worker_eligibility_wait = script
    .find("wait_for \"all lifecycle-test workers to become eligible\" 120 workers_are_eligible")
    .expect("Kubernetes Pod lifecycle script should bound its worker eligibility wait");
  let helm_install = script
    .find("helm upgrade --install")
    .expect("Kubernetes Pod lifecycle script should install the Helm release");
  assert!(
    worker_labels < worker_eligibility_wait && worker_eligibility_wait < helm_install,
    "Kubernetes Pod lifecycle workers must be labeled and proved eligible before Helm installation"
  );

  for forbidden in [
    "docker-rootful",
    "docker system prune",
    "docker container prune",
    "docker network prune",
    "kubectl delete --all",
    "kubectl delete namespace --all",
    "kubectl get secret",
    "kubectl describe secret",
  ] {
    assert!(
      !script.contains(forbidden),
      "Kubernetes Pod lifecycle script must not contain unsafe or secret-disclosing operation {forbidden}"
    );
  }
}

#[test]
fn kubernetes_network_policy_ci_uses_enforcing_cnis_and_hardened_fixtures() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let job = jobs
    .get("kubernetes-network-policy")
    .expect("workflow should define the Kubernetes NetworkPolicy job");
  let job_text = workflow_job_text(&workflow, "kubernetes-network-policy");
  let script = kubernetes_network_policy_script_text();

  assert_eq!(
    job.needs,
    expected_needs(PRIMARY_RUST_GATE_NEEDS),
    "the NetworkPolicy job should wait for all primary Rust and advisory gates"
  );
  for expected in [
    "name: Kubernetes NetworkPolicy (${{ matrix.cni }})",
    "runs-on: ubuntu-26.04",
    "contents: read",
    "timeout-minutes: 35",
    "cni: [calico, cilium]",
    "azure/setup-helm@9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310 # v5.0.1",
    "version: v3.21.3",
    "name: Validate Helm NetworkPolicy configuration",
    "tests/scripts/check-helm-network-policy.sh",
    "helm/kind-action@ef37e7f390d99f746eb8b610417061a60e82a6cc # v1.14.0",
    "kubectl_version: v1.34.10",
    "install_only: true",
    "MINIKUBE_VERSION: v1.38.1",
    "MINIKUBE_SHA256: 099477eaf248bcb5bcea8ce78a2898e93ac01461c35189da1848c3de82ecd22e",
    "curl --fail --location --retry 3 --retry-all-errors --retry-delay 2",
    "sha256sum --check --status",
    "tests/scripts/run-kubernetes-network-policy.sh --cni \"${{ matrix.cni }}\"",
    "OXIBELT_NETWORK_POLICY_TIMEOUT_SECONDS: \"600\"",
  ] {
    assert!(
      job_text.contains(expected),
      "Kubernetes NetworkPolicy CI job should include {expected}"
    );
  }

  for expected in [
    "usage: $0 --cni <calico|cilium>",
    "--driver=docker",
    "--container-runtime=containerd",
    "--cni=\"${cni}\"",
    "--kubernetes-version=v1.34.10",
    "--output=json",
    "--wait-timeout=\"${timeout_seconds}s\"",
    "'\"name=rootless\"'",
    "minikube_root_compatibility=(--force)",
    "minikube-start.log",
    "Minikube did not start with the requested ${cni} CNI",
    "--show-only templates/networkpolicy.yaml",
    "--show-only templates/ciliumnetworkpolicy.yaml",
    "helm_show_only=(--show-only templates/networkpolicy.yaml)",
    "helm_show_only+=(--show-only templates/ciliumnetworkpolicy.yaml)",
    "docker network inspect \"${network}\"",
    "wait_for_distinct_docker_network_ipv4s",
    "Cilium FQDN fixtures did not receive distinct IPv4 addresses on Minikube Docker network",
    "expect_allowed \"pre-policy public source reaching metrics\"",
    "wait_for_policy_denial \"public source reaching metrics\"",
    "for attempt in {1..12}; do",
    "consecutive_denials=0",
    "consecutive_denials=\"$((consecutive_denials + 1))\"",
    "if ((consecutive_denials == 3)); then",
    "remained reachable after policy propagation",
    "expect_denied \"public source reaching Admin\"",
    "expect_allowed \"declared data-plane upstream egress\"",
    "expect_denied \"arbitrary cluster Service egress\"",
    "expect_allowed \"exact Cilium FQDN egress\"",
    "expect_denied \"undeclared Cilium FQDN egress\"",
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--label \"oxibelt.network-policy-test=${run_id}\"",
    "\"${script_dir}/retry-docker-pull.sh\" \"${agnhost_image}\"",
    "--pull=never",
    "registry.k8s.io/e2e-test-images/agnhost:2.52@sha256:",
    "quay.io/cilium/alpine-curl:v1.10.0@sha256:",
    "registry.k8s.io/coredns/coredns:v1.14.6@sha256:",
    "minikube delete --profile \"${profile_name}\"",
  ] {
    assert!(
      script.contains(expected),
      "Kubernetes NetworkPolicy script should preserve {expected}"
    );
  }

  assert!(
    script.contains(
      "if [[ \"${cni}\" == \"cilium\" ]]; then\n  helm_show_only+=(--show-only templates/ciliumnetworkpolicy.yaml)\nfi"
    ),
    "the Cilium template must only be selected for Cilium coverage"
  );

  let pre_policy_probe = script
    .find("expect_allowed \"pre-policy public source reaching metrics\"")
    .expect("NetworkPolicy harness should prove metrics reachability before applying policy");
  let policy_apply = script
    .find("apply -f \"${work_dir}/policies.yaml\"")
    .expect("NetworkPolicy harness should apply the rendered policy");
  let convergence_probe = script
    .find("wait_for_policy_denial \"public source reaching metrics\"")
    .expect("NetworkPolicy harness should wait for the first denial to converge");
  assert!(
    pre_policy_probe < policy_apply && policy_apply < convergence_probe,
    "NetworkPolicy harness must prove reachability, apply policy, and then wait for denial convergence"
  );
  assert_eq!(
    script
      .matches("wait_for_policy_denial \"public source reaching metrics\"")
      .count(),
    1,
    "only the first post-apply denial should tolerate CNI propagation"
  );

  let agnhost_netexec = "\"${agnhost_image}\" netexec --http-port=8080 --udp-port=-1";
  let agnhost_pre_pull = "\"${script_dir}/retry-docker-pull.sh\" \"${agnhost_image}\"";
  let pre_pull_position = script
    .find(agnhost_pre_pull)
    .expect("Cilium fixtures should pre-pull the pinned agnhost image with retry");
  let first_fixture_position = script
    .find(agnhost_netexec)
    .expect("Cilium fixtures should start the first agnhost container");
  assert_eq!(
    script.matches(agnhost_pre_pull).count(),
    1,
    "Cilium fixtures should pre-pull agnhost exactly once"
  );
  assert!(
    pre_pull_position < first_fixture_position,
    "the bounded agnhost pull must complete before either Cilium fixture starts"
  );
  assert_eq!(
    script
      .matches("docker run --detach \\\n    --pull=never \\")
      .count(),
    2,
    "both Cilium fixtures must use only the explicitly pre-pulled agnhost image"
  );
  assert_eq!(
    script.matches(agnhost_netexec).count(),
    2,
    "Cilium FQDN fixtures must pass netexec exactly once after the agnhost image entrypoint"
  );
  assert!(
    !script.contains("\"${agnhost_image}\" /agnhost netexec"),
    "Cilium FQDN fixtures must not duplicate the agnhost image entrypoint"
  );

  for forbidden in [
    "docker-rootful",
    "docker system prune",
    "docker container prune",
    "docker network prune",
    "kubectl delete --all",
    "kubectl delete namespace --all",
    "kubectl get secret",
    "kubectl describe secret",
  ] {
    assert!(
      !script.contains(forbidden),
      "Kubernetes NetworkPolicy script must not contain unsafe or secret-disclosing operation {forbidden}"
    );
  }
}

#[test]
fn current_kubernetes_and_helm_compatibility_is_pinned_and_isolated() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let job = jobs
    .get("kubernetes-current-compatibility")
    .expect("workflow should define current Kubernetes and Helm compatibility coverage");
  let job_text = workflow_job_text(&workflow, "kubernetes-current-compatibility");

  assert_eq!(
    job.needs,
    vec![
      "test".to_owned(),
      "rust-advisory-checks".to_owned(),
      "node-dependency-admission".to_owned(),
    ],
    "current Kubernetes compatibility should wait for all primary dependency gates"
  );
  for expected in [
    "name: Kubernetes ${{ matrix.kubernetes }} and Helm v4.2.3 compatibility",
    "runs-on: ubuntu-26.04",
    "contents: read",
    "timeout-minutes: 15",
    "fail-fast: false",
    "kubernetes: v1.34.8",
    "kube_version: 1.34.8",
    "kubectl: v1.34.10",
    "kubernetes: v1.35.5",
    "kube_version: 1.35.5",
    "kubectl: v1.35.7",
    "kubernetes: v1.36.1",
    "kube_version: 1.36.1",
    "kubectl: v1.36.3",
    "azure/setup-helm@9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310 # v5.0.1",
    "version: v4.2.3",
    "tests/scripts/check-helm-admin-config.sh",
    "tests/scripts/check-helm-base-config.sh",
    "tests/scripts/check-helm-edge-secure-medium-profile.sh",
    "tests/scripts/check-helm-service-account-token.sh",
    "tests/scripts/check-helm-gateway-controller-ha.sh",
    "tests/scripts/check-helm-pod-lifecycle.sh",
    "tests/scripts/check-helm-autoscaling.sh",
    "tests/scripts/check-helm-network-policy.sh",
    "tests/scripts/check-helm-image-digest.sh",
    "helm/kind-action@ef37e7f390d99f746eb8b610417061a60e82a6cc # v1.14.0",
    "version: v0.32.0",
    "kubectl_version: ${{ matrix.kubectl }}",
    "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256",
    "kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95",
    "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
    "KUBERNETES_VERSION: ${{ matrix.kube_version }}",
    "kind create cluster",
    "--wait 120s",
    "kubectl --context \"${context}\" version",
    "helm lint deploy/helm/oxibelt --kube-version \"${KUBERNETES_VERSION}\"",
    "helm lint deploy/helm/oxibelt-gateway-controller --kube-version \"${KUBERNETES_VERSION}\"",
    "--set-string configRollout.mode=kubernetes_immutable",
    "helm template oxibelt-gateway-controller deploy/helm/oxibelt-gateway-controller",
    "apply --dry-run=server --filename -",
    "kind delete cluster --name \"${cluster_name}\"",
  ] {
    assert!(
      job_text.contains(expected),
      "current Kubernetes and Helm compatibility job should include {expected}"
    );
  }

  for forbidden in [
    "docker-rootful",
    "docker system prune",
    "docker container prune",
    "docker network prune",
    "kubectl delete --all",
    "kubectl delete namespace --all",
    "kubectl get secret",
    "kubectl describe secret",
  ] {
    assert!(
      !job_text.contains(forbidden),
      "current Kubernetes compatibility must not contain unsafe or secret-disclosing operation {forbidden}"
    );
  }
}

#[test]
fn docker_integration_jobs_are_split_by_logical_group() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let groups = [
    (
      "docker-integration-config-runtime",
      "docker_config_runtime",
      "config-runtime",
    ),
    ("docker-integration-proxy", "docker_proxy", "proxy"),
    ("docker-integration-protocol", "docker_protocol", "protocol"),
    ("docker-integration-waf", "docker_waf", "waf"),
    ("docker-integration-cache", "docker_cache", "cache"),
    (
      "docker-integration-state-data",
      "docker_state_data",
      "state-data",
    ),
    ("docker-integration-ops", "docker_ops", "ops"),
    ("docker-integration-security", "docker_security", "security"),
  ];

  assert!(
    !jobs.contains_key("docker-integration-matrix"),
    "workflow should not keep the monolithic Docker integration matrix job"
  );

  for (job_id, output_name, group) in groups {
    let job = jobs
      .get(job_id)
      .unwrap_or_else(|| panic!("workflow should define {job_id}"));
    assert!(
      job.needs.contains(&"generate-test-matrices".to_owned())
        && job
          .needs
          .contains(&"docker-alpine-musl-image-amd64".to_owned())
        && job
          .needs
          .contains(&"docker-integration-helper-images".to_owned()),
      "{job_id} should wait for generated matrices, the AMD64 image, and helper images"
    );
    assert!(
      workflow.contains(&format!(
        "{output_name}: ${{{{ steps.matrices.outputs.{output_name} }}}}"
      )),
      "generate-test-matrices should expose {output_name}"
    );
    assert!(
      workflow.contains(&format!("write_docker_matrix {output_name} {group}")),
      "generate-test-matrices should generate the {group} Docker matrix"
    );
    assert!(
      workflow.contains(&format!(
        "matrix: ${{{{ fromJson(needs.generate-test-matrices.outputs.{output_name}) }}}}"
      )),
      "{job_id} should consume {output_name}"
    );
  }
}

#[test]
fn concurrency_fault_cases_are_registered_bounded_and_rootless() {
  let root = repo_root();
  let read = |path: &str| {
    fs::read_to_string(root.join(path))
      .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
  };
  let order = read("tests/rust/oxibelt_docker_integration_matrix/mod.rs");
  let config_runtime = read("tests/rust/oxibelt_docker_integration_matrix/config_runtime.rs");
  let proxy = read("tests/rust/oxibelt_docker_integration_matrix/proxy.rs");
  let state_data = read("tests/rust/oxibelt_docker_integration_matrix/state_data.rs");
  let docs = read("tests/README.md");
  let mock_upstream = read("tests/docker/mock_upstream/server.py");
  let mock_upstream_client = read("tests/docker/mock_upstream/client.py");
  let burst_client = read("tests/docker/mock_upstream/burst_client.py");
  let mock_upstream_dockerfile = read("tests/docker/mock_upstream/Dockerfile");
  let retry_storm_config_text = read(
    "tests/fixtures/oxibelt-docker-integration-matrix/docker/upstream-pools/retry-storm-budget/config/oxibelt.toml",
  );
  let scripts = [
    read("tests/scripts/run-bounded-http-burst.sh"),
    read(
      "tests/fixtures/oxibelt-docker-integration-matrix/docker/shared-state/redis-disconnect-reconnect/checks.sh",
    ),
    read(
      "tests/fixtures/oxibelt-docker-integration-matrix/docker/upstream-pools/retry-storm-budget/checks.sh",
    ),
    read(
      "tests/fixtures/oxibelt-docker-integration-matrix/docker/cache/collapsed-forwarding-metrics/checks.sh",
    ),
    read(
      "tests/fixtures/oxibelt-docker-integration-matrix/docker/lifecycle/process-signal-h2-h3-drain/checks.sh",
    ),
  ];

  for (catalog, category, name) in [
    (&state_data, "shared-state", "redis-disconnect-reconnect"),
    (&proxy, "upstream-pools", "retry-storm-budget"),
    (&config_runtime, "lifecycle", "process-signal-h2-h3-drain"),
  ] {
    assert!(
      catalog.contains(&format!("\"{category}\"")) && catalog.contains(&format!("\"{name}\"")),
      "{category}/{name} should remain in its logical Docker matrix group"
    );
    assert!(
      order.contains(&format!("(\"{category}\", \"{name}\")")),
      "{category}/{name} should remain in deterministic case order"
    );
    assert!(
      docs.contains(&format!("`{category}/{name}`")),
      "the concurrency invariant table should document {category}/{name}"
    );
  }
  assert!(
    docs.contains("`cache/collapsed-forwarding-metrics`")
      && docs.contains("`shared-state/redis-delay-isolation`")
      && docs.contains("`shared-state/postgres-delay-isolation`"),
    "the invariant table should retain cache stampede and backend latency coverage"
  );

  for expected in [
    "FAULT_GATE_ID_RE",
    "FAULT_GATE_LIMIT = 256",
    "FAULT_GATE_MAX_TIMEOUT_MS = 30_000",
    "header_delay_sequence",
    "prefix = \"/__fault/gates/\"",
    "release requires POST",
    "status requires GET",
  ] {
    assert!(
      mock_upstream.contains(expected),
      "the bounded mock fault gate should preserve {expected}"
    );
  }

  for script in &scripts {
    for forbidden in [
      "docker-rootful",
      "--privileged",
      "--network host",
      "docker system prune",
      "docker container prune",
      "docker network prune",
      "iptables",
      "tc qdisc",
      "eval ",
    ] {
      assert!(
        !script.contains(forbidden),
        "P2-6 fault scripts must not contain unsafe operation {forbidden}"
      );
    }
  }
  let burst = &scripts[0];
  for expected in [
    "concurrency < 1 || concurrency > 64",
    "timeout_seconds < 1 || timeout_seconds > 30",
    "docker rm -f \"${container}\"",
    "--label \"${test_label}\"",
    "container=\"oxibelt-http-burst-${burst_id}\"",
    "/opt/mock_upstream/burst_client.py",
    "--concurrency \"${concurrency}\"",
    "timeout_seconds * 2 + 5",
    "([.[].burst_index] | sort) == [range(1; $concurrency + 1)]",
    ".status as $status",
    "sort_by(.burst_index)",
    "docker cp \"${ca_file}\" \"${container}:/tmp/proxy-ca.pem\"",
  ] {
    assert!(
      burst.contains(expected),
      "bounded burst helper should preserve {expected}"
    );
  }
  for forbidden in ["containers=()", "pids=()", "/opt/mock_upstream/client.py"] {
    assert!(
      !burst.contains(forbidden),
      "bounded burst helper should not retain per-request launcher path {forbidden}"
    );
  }

  assert!(
    mock_upstream_dockerfile
      .contains("COPY server.py client.py burst_client.py /opt/mock_upstream/"),
    "the mock-upstream image should package the synchronized burst client"
  );
  assert!(
    mock_upstream_client.contains("def response_document(response, response_body_bytes):"),
    "the single-request and burst clients should share one response document serializer"
  );
  for expected in [
    "MAX_CONCURRENCY = 64",
    "MAX_TIMEOUT_SECONDS = 30",
    "barrier = threading.Barrier(args.concurrency)",
    "max_workers=args.concurrency",
    "barrier.abort()",
    "return sorted(results, key=lambda result: result[\"burst_index\"])",
  ] {
    assert!(
      burst_client.contains(expected),
      "the synchronized burst client should preserve {expected}"
    );
  }
  let burst_request = burst_client
    .split_once("def run_request(")
    .expect("burst client should define run_request")
    .1
    .split_once("\n\ndef run_burst(")
    .expect("run_request should precede run_burst")
    .0;
  let preconnect = burst_request
    .find("sock = open_socket(args)")
    .expect("burst requests should preconnect their sockets");
  let barrier = burst_request
    .find("barrier.wait(timeout=args.timeout + BARRIER_GRACE_SECONDS)")
    .expect("burst requests should wait at the launch barrier");
  let send = burst_request
    .find("response, response_body_bytes = send_request(")
    .expect("burst requests should send after synchronization");
  assert!(
    preconnect < barrier && barrier < send,
    "every burst socket must connect before the barrier releases HTTP sends"
  );

  let lifecycle = &scripts[4];
  for expected in [
    "docker exec \"${http_container}\" python /opt/mock_upstream/client.py",
    "--target-host 127.0.0.1",
    "--timeout 2",
    ".waiting == 0 and .released == false",
    "for _attempt in $(seq 1 100)",
    "signal_drain_gate_request GET",
    "signal_drain_gate_request POST",
  ] {
    assert!(
      lifecycle.contains(expected),
      "the lifecycle drain fixture should preserve bounded readiness behavior {expected}"
    );
  }
  assert!(
    !lifecycle.contains("seq 1 300"),
    "the lifecycle drain fixture should not poll beyond the upstream gate deadline"
  );
  let gate_ready = lifecycle
    .find(".waiting == 0 and .released == false")
    .expect("the lifecycle drain fixture should wait for the empty upstream gate");
  let proxy_ready = lifecycle
    .find("plain_client_request_with_headers_on_port 9091 \"proxy\" \"/ready\" 200")
    .expect("the lifecycle drain fixture should wait for proxy readiness");
  let probe_start = lifecycle
    .find("for index in 1 2 3 4")
    .expect("the lifecycle drain fixture should launch the H2 and H3 probes");
  assert!(
    gate_ready < probe_start && proxy_ready < probe_start,
    "the lifecycle drain fixture should establish mock and proxy readiness before launching probes"
  );

  let retry_storm = &scripts[2];
  let retry_storm_config: toml::Value = toml::from_str(&retry_storm_config_text)
    .expect("the retry-storm fixture config should parse as TOML");
  let retry_policy = retry_storm_config
    .get("proxy")
    .and_then(toml::Value::as_table)
    .and_then(|proxy| proxy.get("retry"))
    .and_then(toml::Value::as_table)
    .expect("the retry-storm fixture should configure proxy retry policy");
  assert_eq!(
    retry_policy
      .get("total_budget_ms")
      .and_then(toml::Value::as_integer),
    Some(5_000),
    "the retry-storm fixture should retain a five-second total retry budget"
  );
  assert_eq!(
    retry_policy
      .get("per_attempt_timeout_ms")
      .and_then(toml::Value::as_integer),
    Some(5_000),
    "the retry-storm first attempt should not expire before its total retry budget"
  );
  for expected in [
    "retry_storm_proxy_request() {",
    "docker exec \"${http_container}\" python /opt/mock_upstream/client.py",
    "--target-host proxy",
    "retry_storm_proxy_request 9090 ops.test /metrics 200",
    "retry_storm_proxy_request 9091 ops.test /live 200",
    "for _ in $(seq 1 100)",
    "10#${active_retry} > 1",
    "10#${queued_retry} != 0",
    "10#${observed_budget} > 15",
    "[[ \"${observed_budget}\" == \"15\" ]]",
    "retry storm did not reach fifteen durable budget rejections",
    "--concurrency 16",
    "--timeout-seconds 10",
    "wait \"${burst_pid}\"",
    "\"${original_attempts}\" != \"16\"",
    "\"${retry_attempts}\" != \"1\"",
    "\"${retry_rejections}\" != \"15\"",
    "\"${active_retry}\" != \"0\"",
    "\"${queued_retry}\" != \"0\"",
    "retry attempt, rejection, or final gauge invariants did not reconcile",
    ".body == \"recovered\" and .headers[\"x-sequence-index\"] == \"17\"",
  ] {
    assert!(
      retry_storm.contains(expected),
      "the retry-storm fixture should preserve deterministic budget invariant {expected}"
    );
  }
  assert!(
    !retry_storm.contains("plain_client_request_on_port")
      && !retry_storm
        .contains("[[ \"${active_retry}\" == \"1\" && \"${observed_budget}\" == \"15\" ]]"),
    "the retry-storm fixture must use its existing-container probe and must not require transient activity in the durable rejection sample"
  );
}

#[test]
fn docker_integration_helper_image_job_builds_reusable_artifact() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let helper_job = jobs
    .get("docker-integration-helper-images")
    .expect("workflow should define the Docker integration helper image job");
  let script = docker_integration_helper_build_script_text();

  assert_eq!(
    helper_job.needs,
    expected_needs(PRIMARY_RUST_GATE_NEEDS),
    "Docker integration helper image builds should follow the normal test gates"
  );
  assert!(
    workflow.contains("name: Docker integration helper images")
      && workflow.contains("tests/scripts/build-docker-integration-helper-images-artifact.sh")
      && workflow.contains("name: oxibelt-docker-integration-helper-images")
      && workflow.contains("oxibelt-docker-integration-helper-images.tar"),
    "workflow should build and upload a reusable Docker integration helper image artifact"
  );
  for image in [
    "oxibelt/mock-upstream:ci",
    "oxibelt/mock-dns:ci",
    "oxibelt/mock-kubernetes:ci",
    "oxibelt/pq-probe:ci",
    "oxibelt/protocol-probe:ci",
    "oxibelt/postgres:ci",
    "valkey/valkey:9-alpine",
  ] {
    assert!(
      script.contains(image),
      "helper image build script should include deterministic tag {image}"
    );
  }
  assert!(
    script.contains("retry_command 3 docker pull --platform \"${platform}\"")
      && script.contains("retry_command 3 docker buildx build")
      && script.contains("retry_command 3 docker save"),
    "helper image build script should retry Docker Hub pulls, builds, and image save"
  );
}

#[test]
fn docker_integration_jobs_use_prebuilt_helper_images() {
  let workflow = workflow_text();

  assert_eq!(
    workflow
      .matches("name: Download Docker integration helper image artifact")
      .count(),
    DOCKER_INTEGRATION_JOBS.len() + 3,
    "each Docker integration job plus all three Admin PostgreSQL durability jobs should download the helper image artifact"
  );
  assert_eq!(
    workflow
      .matches("name: Load Docker integration helper images")
      .count(),
    DOCKER_INTEGRATION_JOBS.len(),
    "each Docker integration job should load the helper image tar"
  );
  for value in [
    "OXIBELT_MOCK_UPSTREAM_IMAGE: oxibelt/mock-upstream:ci",
    "OXIBELT_MOCK_DNS_IMAGE: oxibelt/mock-dns:ci",
    "OXIBELT_MOCK_KUBERNETES_IMAGE: oxibelt/mock-kubernetes:ci",
    "OXIBELT_MOCK_NOMAD_IMAGE: oxibelt/mock-nomad:ci",
    "OXIBELT_PQ_PROBE_IMAGE: oxibelt/pq-probe:ci",
    "OXIBELT_PROTOCOL_PROBE_IMAGE: oxibelt/protocol-probe:ci",
    "OXIBELT_POSTGRES_IMAGE: oxibelt/postgres:ci",
    "OXIBELT_REDIS_IMAGE: valkey/valkey:9-alpine",
    "OXIBELT_REQUIRE_PRELOADED_HELPER_IMAGES: \"1\"",
  ] {
    let expected_count = if value == "OXIBELT_POSTGRES_IMAGE: oxibelt/postgres:ci" {
      DOCKER_INTEGRATION_JOBS.len() + 3
    } else {
      DOCKER_INTEGRATION_JOBS.len()
    };
    assert_eq!(
      workflow.matches(value).count(),
      expected_count,
      "each Docker integration job should pass {value}"
    );
  }
}

#[test]
fn docker_integration_matrix_cargo_invocations_are_retry_hardened() {
  let workflow = workflow_text();
  let matrix_job = workflow_job_text(&workflow, "generate-test-matrices");
  let script = docker_integration_matrix_script_text();
  let cargo_matrix_helper =
    "cargo_run_with_retry --quiet --locked -p oxibelt --bin oxibelt-docker-integration-matrix --";

  assert!(
    workflow.contains("CARGO_NET_RETRY: \"10\""),
    "workflow should raise Cargo's registry retry budget for CI network flakes"
  );
  assert!(
    matrix_job.contains("cargo_run_with_retry()")
      && matrix_job.contains("printf 'cargo run failed with status")
      && matrix_job.contains("delay=$((delay * 2))"),
    "generate-test-matrices should retry transient cargo run failures"
  );
  assert_eq!(
    matrix_job.matches(cargo_matrix_helper).count(),
    2,
    "generate-test-matrices should retry both Docker and browser matrix helper calls"
  );
  assert!(
    !matrix_job
      .contains("cargo run --quiet --locked -p oxibelt --bin oxibelt-docker-integration-matrix --"),
    "generate-test-matrices should not call the matrix helper without retry"
  );

  assert!(
    script.contains("cargo_run_with_retry()")
      && script.contains("printf 'cargo run failed with status")
      && script.contains("delay=$((delay * 2))"),
    "Docker integration matrix script should retry transient cargo run failures"
  );
  assert_eq!(
    script.matches(cargo_matrix_helper).count(),
    1,
    "Docker integration matrix materialization should use the cargo retry helper once"
  );
  assert!(
        script.contains(
            "cargo_run_with_retry --quiet --locked -p oxibelt --bin oxibelt-docker-integration-matrix -- \\\n  materialize"
        ),
        "Docker integration matrix materialization should preserve --locked and materialize arguments"
    );
  assert!(
        !script.contains(
            "\ncargo run --quiet --locked -p oxibelt --bin oxibelt-docker-integration-matrix -- \\\n  materialize"
        ),
        "Docker integration matrix materialization should not bypass the retry helper"
    );
}

#[test]
fn holding_upgrade_client_waits_for_confirmed_protocol_switch() {
  let script = docker_integration_matrix_script_text();
  let client = source_file_text("tests/docker/mock_upstream/client.py");
  let perform_upgrade = client
    .split_once("def perform_upgrade(")
    .expect("mock client should define perform_upgrade")
    .1
    .split_once("\n\ndef main()")
    .expect("perform_upgrade should precede main")
    .0;
  let upgrade_helper = script
    .split_once("start_holding_upgrade_client_request_with_headers() {")
    .expect("Docker integration script should define the holding upgrade helper")
    .1
    .split_once("start_holding_connect_tunnel_request_with_headers() {")
    .expect("holding upgrade helper should precede the holding CONNECT helper")
    .0;
  let status_check = perform_upgrade
    .find("if response.status != 101:")
    .expect("mock client should reject non-101 upgrade responses");
  let ready_signal = perform_upgrade
    .find("if args.signal_upgrade_ready:")
    .expect("mock client should support signaling an established upgrade");
  let hold = perform_upgrade
    .find("if args.hold_after_headers_ms > 0:")
    .expect("mock client should hold an established upgrade when requested");

  assert!(
    status_check < ready_signal && ready_signal < hold,
    "the mock client must signal readiness after confirming status 101 and before holding the connection"
  );
  for expected in [
    "UPGRADE_READY_PATH = \"/tmp/oxibelt-upgrade-ready\"",
    "os.O_WRONLY | os.O_CREAT | os.O_EXCL",
    "0o600",
    "--signal-upgrade-ready requires --upgrade-token",
    "--signal-upgrade-ready cannot be combined with --connect-tunnel",
  ] {
    assert!(
      client.contains(expected),
      "the mock client should include upgrade readiness invariant {expected}"
    );
  }
  for expected in [
    "--signal-upgrade-ready",
    "seq 1 150",
    "docker exec \"${HOLDING_CLIENT_CONTAINER}\" test -f \"${upgrade_ready_path}\"",
    "docker inspect -f '{{.State.Status}}'",
    "created | running",
    "exited | dead",
    "sleep 0.1",
    "timed out waiting for holding upgrade client to receive a 101 response",
  ] {
    assert!(
      upgrade_helper.contains(expected),
      "holding upgrade helper should include readiness invariant {expected}"
    );
  }
  assert!(
    !upgrade_helper.contains("sleep 1"),
    "holding upgrade readiness must not rely on a fixed one-second delay"
  );
}

#[test]
fn ambiguous_framing_client_reads_an_exact_early_error_response() {
  let workflow = workflow_text();
  let script = docker_integration_matrix_script_text();
  let client = source_file_text("tests/docker/mock_upstream/client.py");
  let fixture = source_file_text(
    "tests/fixtures/oxibelt-docker-integration-matrix/docker/security/fast-general-proxy-equivalence/checks.sh",
  );
  let send_http_request = client
    .split_once("def send_http_request(")
    .expect("mock client should define send_http_request")
    .1
    .split_once("\n\ndef send_chunked_body(")
    .expect("send_http_request should precede send_chunked_body")
    .0;

  for expected in [
    "parser.add_argument(\"--read-response-after-body-write-error\", action=\"store_true\")",
    "--read-response-after-body-write-error requires --chunked-body",
    "--expect-status in the 400-599 range",
    "response.status == args.expect_status",
  ] {
    assert!(
      client.contains(expected),
      "the mock client should preserve early-response invariant {expected}"
    );
  }
  for expected in [
    "except (BrokenPipeError, ConnectionResetError):",
    "if not read_response_after_body_write_error:",
    "return read_http_response(sock, method, hold_after_headers_ms)",
  ] {
    assert!(
      send_http_request.contains(expected),
      "body-write recovery should preserve {expected}"
    );
  }
  assert!(
    !send_http_request.contains("except OSError"),
    "body-write recovery must not suppress unrelated socket failures"
  );

  for expected in [
    "early_rejection_chunked_body_client_request() {",
    "chunked_body_client_request_impl true \"$@\"",
    "early_response_args+=(--read-response-after-body-write-error)",
  ] {
    assert!(
      script.contains(expected),
      "the Docker integration helper should preserve {expected}"
    );
  }
  assert_eq!(
    fixture
      .matches("early_rejection_chunked_body_client_request")
      .count(),
    2,
    "only the fast and general ambiguous-framing requests should opt into early-response recovery"
  );
  assert!(
    fixture.lines().all(|line| {
      let line = line.trim_start();
      !line.starts_with("chunked_body_client_request \"example.test\" \"/fast/ambiguous")
        && !line.starts_with("chunked_body_client_request \"example.test\" \"/general/ambiguous")
    }),
    "ambiguous-framing checks must use the dedicated early-rejection helper"
  );
  assert_eq!(
    script.matches("else\n    status=$?\n  fi").count(),
    3,
    "slow, split, and chunked body helpers should retain the real failed container status"
  );
  assert!(
    workflow.contains("python3 -m unittest tests/scripts/test-mock-upstream-client.py"),
    "source-structure CI should run the deterministic mock-client regression"
  );
}

#[test]
fn docker_integration_matrix_hardened_runtime_uses_readonly_fixture_volumes() {
  let script = docker_integration_matrix_script_text();

  assert!(
    script.contains("seed_hardened_fixture_volume()")
      && script.contains("docker volume create --label \"${test_label}\" \"${volume}\"")
      && script.contains("docker cp \"${source_dir}/.\" \"${seed_container}:/fixture\"")
      && script.contains("-c 'chown -R 10001:10001 /fixture'"),
    "hardened runtime fixtures should be seeded into labeled Docker volumes before container start"
  );
  for mount in [
    "--mount \"type=volume,src=${hardened_config_volume},dst=/etc/oxibelt/config,readonly\"",
    "--mount \"type=volume,src=${hardened_cert_volume},dst=/etc/oxibelt/cert,readonly\"",
    "--mount \"type=volume,src=${hardened_oxirule_volume},dst=/etc/oxibelt/oxirule,readonly\"",
  ] {
    assert!(
      script.contains(mount),
      "hardened runtime containers should include read-only fixture mount {mount}"
    );
  }
  assert!(
    script.contains("if [[ \"${CASE_HARDENED_RUNTIME}\" != \"1\" ]]; then\n  docker cp \"${case_dir}/config/.\" \"${proxy_container}:/etc/oxibelt/config\""),
    "proxy fixture docker cp should be skipped for read-only hardened runtime containers"
  );
  for forbidden in [
    "docker cp \"${case_dir}/config/.\" \"${runtime_check_container}:/etc/oxibelt/config\"",
    "docker cp \"${proxy_cert_dir}/.\" \"${runtime_check_container}:/etc/oxibelt/cert\"",
    "docker cp \"${case_dir}/oxirule/.\" \"${runtime_check_container}:/etc/oxibelt/oxirule\"",
  ] {
    assert!(
      !script.contains(forbidden),
      "runtime-check should not copy fixture files into a read-only container"
    );
  }
}

#[test]
fn oxibelt_main_builds_startup_snapshot_on_tokio_task() {
  let main = oxibelt_main_text();

  assert!(
    main.contains("build_app_handle(config, observability.into_telemetry())"),
    "startup should delegate application snapshot construction to the task-backed helper"
  );
  assert!(
    main.contains("tokio::task::spawn(async move {\n    oxibelt::state::AppSnapshot::new_with_telemetry(config, telemetry)"),
    "AppSnapshot startup construction should not be polled directly on the block_on caller stack"
  );
}

#[test]
fn tokio_runtime_builders_use_explicit_startup_stack_size() {
  let runtime = source_file_text("source/src/runtime.rs");
  let main_runtime = source_file_text("source/src/runtime/main_runtime.rs");
  let tokio_island = source_file_text("source/src/runtime/tokio_island.rs");

  assert!(
    runtime.contains("TOKIO_RUNTIME_THREAD_STACK_SIZE: usize = 32 * 1024 * 1024"),
    "runtime should centralize the startup-safe Tokio worker stack size"
  );
  for source in [main_runtime, tokio_island] {
    assert!(
      source.contains("builder.thread_stack_size(super::TOKIO_RUNTIME_THREAD_STACK_SIZE);"),
      "Tokio runtime builders should use the startup-safe worker stack size"
    );
  }
}

#[test]
fn riscv64_cross_checks_and_image_build_run_without_emulation() {
  let workflow = workflow_text();
  let alpine_dockerfile = source_file_text("source/ops/Dockerfile.alpine");
  let jobs = parse_jobs(&workflow);
  let cross_job = jobs
    .get("check-riscv64-cross")
    .expect("workflow should keep the RISC-V compile-check job");
  let riscv64_image_job = jobs
    .get("docker-alpine-musl-image-riscv64")
    .expect("workflow should define the RISC-V Docker image job");
  let other_start = workflow
    .find("  docker-alpine-musl-image-other:")
    .expect("workflow should define the non-AMD64 image job");
  let riscv_start = workflow
    .find("  docker-alpine-musl-image-riscv64:")
    .expect("workflow should define the RISC-V image job");
  let other_job = &workflow[other_start..riscv_start];
  let cross_job_text = workflow_job_text(&workflow, "check-riscv64-cross");
  let riscv64_job = workflow_job_text(&workflow, "docker-alpine-musl-image-riscv64");
  let shared_builder_start = alpine_dockerfile
    .find("FROM ${OXIBELT_RUST_BUILDER_STAGE} AS builder")
    .expect("Alpine Dockerfile should define the shared Rust builder stage");
  let riscv64_check_start = alpine_dockerfile
    .find("FROM builder AS riscv64-musl-check")
    .expect("Alpine Dockerfile should define the RISC-V musl check stage");
  let riscv64_check_end = alpine_dockerfile[riscv64_check_start + 1..]
    .find("\nFROM ")
    .map_or(alpine_dockerfile.len(), |offset| {
      riscv64_check_start + 1 + offset
    });
  let shared_builder_stage = &alpine_dockerfile[shared_builder_start..riscv64_check_start];
  let riscv64_check_stage = &alpine_dockerfile[riscv64_check_start..riscv64_check_end];
  let test_copy = "COPY tests/rust ./tests/rust";
  let test_copy_position = riscv64_check_stage
    .find(test_copy)
    .expect("RISC-V musl check stage should copy repository integration-test targets");
  let cargo_check_position = riscv64_check_stage
    .find("cargo check --all-targets --locked")
    .expect("RISC-V musl check stage should compile all targets");

  assert!(
    workflow.contains("riscv64gc-unknown-linux-gnu")
      && workflow.contains("riscv64gc-unknown-linux-musl"),
    "RISC-V cargo check coverage should keep both GNU and musl targets"
  );
  assert!(
    !shared_builder_stage.contains(test_copy),
    "shared Rust builder should not copy integration tests and invalidate every image cache"
  );
  assert_eq!(
    alpine_dockerfile.matches(test_copy).count(),
    1,
    "only the RISC-V musl check stage should copy integration tests"
  );
  assert!(
    test_copy_position < cargo_check_position,
    "RISC-V musl check stage should copy integration tests before checking all targets"
  );
  for expected in [
    "Cargo check for RISC-V GNU target",
    "cargo check --all-targets --locked --target ${{ matrix.target }}",
    "BINDGEN_EXTRA_CLANG_ARGS: --sysroot=/usr/riscv64-linux-gnu",
    "Cargo check for RISC-V musl target",
    "--platform linux/riscv64",
    "--target riscv64-musl-check",
    "--build-arg OXIBELT_RUST_CACHE_ID=riscv64gc-musl-cross-rs-c12165aa",
    "--build-arg OXIBELT_RUST_BUILDER_STAGE=builder-riscv64",
  ] {
    assert!(
      cross_job_text.contains(expected),
      "RISC-V cross-check job should preserve {expected}"
    );
  }
  assert!(
    cross_job.needs.is_empty(),
    "RISC-V cargo check should stay independent of Docker image jobs"
  );
  assert_eq!(
    riscv64_image_job.needs,
    expected_needs(PRIMARY_RUST_GATE_NEEDS),
    "RISC-V Docker image builds should still wait for normal test gates"
  );
  assert!(
    !riscv64_job.contains(PERFORMANCE_WORKFLOW_JOB_IF),
    "RISC-V Docker image artifact should run on push, pull request, scheduled, and manual workflows"
  );
  assert!(
    !other_job.contains("arch: riscv64"),
    "non-AMD64 Docker image matrix should keep the dedicated RISC-V build separate"
  );
  assert!(
    workflow.contains("\"linux/riscv64\"")
      && workflow.contains("\"riscv64\"")
      && workflow.contains("name: oxibelt-alpine-musl-riscv64-image"),
    "RISC-V Docker image job should build and upload the riscv64 artifact"
  );
  assert!(
    !cross_job_text.contains("qemu") && !riscv64_job.contains("qemu"),
    "RISC-V checks and image builds must not install or invoke emulation"
  );
}

#[test]
fn qemu_runtime_emulation_is_confined_to_the_release_smoke_job() {
  let emulator_free_workflows = [
    ("check", workflow_text()),
    ("release", release_workflow_text()),
    ("release architecture", release_image_arch_workflow_text()),
  ];

  for (name, workflow) in emulator_free_workflows {
    for forbidden in [
      "docker/setup-qemu-action",
      "tonistiigi/binfmt",
      "qemu_platforms",
      "Setup QEMU",
      "--privileged",
    ] {
      assert!(
        !workflow.contains(forbidden),
        "{name} workflow must not retain the emulation boundary {forbidden}"
      );
    }
  }

  let scan_workflow = release_image_arch_scan_workflow_text();
  let build = workflow_job_text(&scan_workflow, "build");
  let scan = workflow_job_text(&scan_workflow, "scan");
  let runtime_smoke = workflow_job_text(&scan_workflow, "runtime-smoke");
  for (name, job) in [("build", build), ("scan", scan)] {
    for forbidden in [
      "docker/setup-qemu-action",
      "tonistiigi/binfmt",
      "qemu-v",
      "Setup pinned RISC-V runtime emulation",
    ] {
      assert!(
        !job.contains(forbidden),
        "release {name} job must remain emulator-free: {forbidden}"
      );
    }
  }
  for expected in [
    "docker/setup-qemu-action@96fe6ef7f33517b61c61be40b68a1882f3264fb8 # v4.2.0",
    "docker.io/tonistiigi/binfmt:qemu-v10.2.3-68@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0",
    "platforms: riscv64",
    "reset: false",
    "cache-image: false",
    "steps.qemu.outputs.platforms",
    "*,linux/riscv64,*",
  ] {
    assert!(
      runtime_smoke.contains(expected),
      "release runtime smoke should pin and verify {expected}"
    );
  }
  assert_eq!(
    scan_workflow.matches("docker/setup-qemu-action@").count(),
    1,
    "release scanning should register QEMU in exactly one job"
  );
  assert_eq!(
    scan_workflow.matches("tonistiigi/binfmt:").count(),
    1,
    "release scanning should reference exactly one pinned binfmt image"
  );
  assert!(
    !scan_workflow.contains("--privileged"),
    "workflows must not expose a direct privileged Docker command"
  );

  let smoke_helper = source_file_text("tests/scripts/run-riscv64-release-image-smoke.py");
  for expected in [
    "ROLE_BINARIES = {",
    "ROLE_PREFIXES = {",
    "DIGEST = re.compile",
    "docker_archive_identity",
    "f\"blobs/sha256/{config_hash}\"",
    "Docker archive OCI manifest blob digest does not match ",
    "Docker archive OCI image manifest config does not match ",
    "allowed_image_ids = {",
    "runtime_image_reference",
    "\"image\", \"inspect\", \"--format\", \"{{.Id}}\", runtime_image_id",
    "inspect_rootfs_inventory",
    "parse_build_identity",
    "wait_for_service",
    "\"--pull\",\n            \"never\"",
    "\"--read-only\"",
    "\"--cap-drop\"",
    "\"no-new-privileges\"",
    "\"logs\", \"--timestamps\", \"--tail\", \"200\"",
    "docker.io/library/alpine:3.24@",
    "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
  ] {
    assert!(
      smoke_helper.contains(expected),
      "RISC-V runtime smoke helper should enforce {expected}"
    );
  }
  for forbidden in [
    "shell=True",
    "docker system prune",
    "docker container prune",
    "docker volume prune",
    "docker network prune",
    "docker-rootful",
  ] {
    assert!(
      !smoke_helper.contains(forbidden),
      "RISC-V runtime smoke helper must not use {forbidden}"
    );
  }
}

#[test]
fn amd64_docker_image_job_builds_cpu_level_artifacts() {
  let workflow = workflow_text();

  assert!(
    workflow.contains("name: Docker image (Alpine musl, amd64, ${{ matrix.target_cpu }})"),
    "AMD64 Docker image job should expose the target CPU in the job name"
  );
  for (artifact_arch, target_cpu, artifact_name) in [
    ("amd64v2", "x86-64-v2", "oxibelt-alpine-musl-amd64v2-image"),
    ("amd64", "x86-64-v3", "oxibelt-alpine-musl-amd64-image"),
    ("amd64v4", "x86-64-v4", "oxibelt-alpine-musl-amd64v4-image"),
  ] {
    assert!(
      workflow.contains(&format!("artifact_arch: {artifact_arch}")),
      "AMD64 Docker image matrix should include {artifact_arch}"
    );
    assert!(
      workflow.contains(&format!("target_cpu: {target_cpu}")),
      "AMD64 Docker image matrix should include {target_cpu}"
    );
    assert!(
      workflow.contains(&format!("artifact_name: {artifact_name}")),
      "AMD64 Docker image matrix should upload {artifact_name}"
    );
  }
  assert!(
    workflow.contains("\"${{ matrix.artifact_arch }}\""),
    "AMD64 Docker image build should pass the matrix artifact arch to the build script"
  );
}

#[test]
fn docker_image_trivy_scan_covers_built_oxibelt_image_artifacts() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let scan_job = jobs
    .get("docker-image-trivy-scan")
    .expect("workflow should define the Docker image Trivy scan job");
  let scan_job_text = workflow_job_text(&workflow, "docker-image-trivy-scan");

  assert_eq!(
    scan_job.needs,
    vec![
      "docker-alpine-musl-image-amd64".to_owned(),
      "docker-alpine-musl-role-image-amd64".to_owned(),
      "docker-alpine-musl-role-image-other".to_owned(),
      "docker-alpine-musl-image-other".to_owned(),
      "docker-alpine-musl-image-riscv64".to_owned(),
    ],
    "Trivy scans should wait for every production role image artifact"
  );
  assert!(
    scan_job_text.contains(
      "name: Docker image Trivy scan (${{ matrix.role.name }}, ${{ matrix.target.artifact_arch }})"
    ) && scan_job_text.contains("fail-fast: false"),
    "Trivy scan job should expose and independently collect every role/architecture result"
  );

  for (role, artifact_prefix) in OXIBELT_IMAGE_ROLES {
    assert!(
      scan_job_text.contains(&format!("name: {role}"))
        && scan_job_text.contains(&format!("artifact_prefix: {artifact_prefix}")),
      "Trivy scan matrix should include production role {role}"
    );
  }
  for (artifact_arch, _, _, _) in OXIBELT_IMAGE_ARTIFACTS {
    assert!(
      scan_job_text.contains(&format!("artifact_arch: {artifact_arch}")),
      "Trivy scan matrix should include architecture {artifact_arch}"
    );
  }

  for expected in [
    "--expected-source-ref \"unknown\"",
    "--expected-source-dirty \"clean\"",
    "--expected-build-kind \"git_development\"",
  ] {
    assert_eq!(
      scan_job_text.matches(expected).count(),
      1,
      "Trivy scan job should pass the trusted CI build identity exactly once: {expected}"
    );
  }
  for forbidden in [".source_ref", ".source_dirty", ".build_kind"] {
    assert!(
      !scan_job_text.contains(forbidden),
      "Trivy scan job must not derive a trusted CI build identity expectation from the downloaded artifact contract: {forbidden}"
    );
  }

  for expected in [
    "actions: read",
    "contents: read",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # 7.0.1",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # 8.0.1",
    "tests/scripts/validate-ci-image-artifact.py validate",
    "-build-metadata.json",
    "-artifact-contract.json",
    "--expected-revision \"${GITHUB_SHA}\"",
    "--expected-source \"${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}\"",
    "tests/scripts/validate-strict-dataplane-image.py",
    "if: matrix.role.name == 'dataplane-strict'",
    "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0",
    "version: v0.72.0",
    "scan-type: image",
    "image-ref: ${{ matrix.role.artifact_prefix }}:alpine-musl-${{ matrix.target.artifact_arch }}",
    "format: json",
    "vuln-type: os,library",
    "severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    "exit-code: \"0\"",
    "GITHUB_STEP_SUMMARY",
    "name: Generate local Trivy dependency snapshot",
    "format: github",
    "tests/scripts/prepare-ci-dependency-snapshot.py normalize",
    "Upload Trivy vulnerability report",
    "Upload local dependency snapshot",
  ] {
    assert!(
      scan_job_text.contains(expected),
      "Trivy scan job should include {expected}"
    );
  }
  for forbidden in [
    "contents: write",
    "github-pat:",
    "secrets.GITHUB_TOKEN",
    "gh api",
  ] {
    assert!(
      !scan_job_text.contains(forbidden),
      "pull-request image scanning must not contain write-capable operation {forbidden}"
    );
  }
}

#[test]
fn docker_image_dependency_snapshot_submits_only_on_write_events() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let snapshot_job = jobs
    .get("docker-image-dependency-snapshot-submit")
    .expect("workflow should define the trusted Docker dependency snapshot submission job");
  let snapshot_job_text = workflow_job_text(&workflow, "docker-image-dependency-snapshot-submit");

  assert_eq!(
    snapshot_job.needs,
    vec![
      "docker-image-trivy-scan".to_owned(),
      "pr-non-benchmark-summary".to_owned(),
    ],
    "external dependency submission should wait for local scans and complete validation"
  );
  assert!(
    workflow.contains("submit_dependency_snapshots:")
      && workflow
        .contains("description: Submit Docker image dependency snapshots during manual runs")
      && workflow.contains("default: false")
      && workflow.contains("type: boolean"),
    "workflow_dispatch should expose an opt-in dependency snapshot toggle that is disabled by default"
  );
  for expected in [
    "needs.pr-non-benchmark-summary.result == 'success'",
    "github.repository == 'OxiBelt/OxiBelt'",
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
    "github.event_name == 'push'",
    "github.event_name == 'schedule'",
    "github.event_name == 'workflow_dispatch' && inputs['submit_dependency_snapshots']",
  ] {
    assert!(
      snapshot_job_text.contains(expected),
      "dependency snapshot job condition should include {expected}"
    );
  }
  assert!(
    !snapshot_job_text.contains("github.event_name == 'pull_request'"),
    "external dependency snapshot submission must not run on pull requests"
  );

  for expected in [
    "actions: read",
    "contents: write",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # 8.0.1",
    "pattern: dependency-snapshot-*",
    "roles=(standalone dataplane dataplane-strict controller tools keysigner)",
    "architectures=(amd64v2 amd64 amd64v4 arm64 riscv64)",
    "[[ \"${#actual_artifacts[@]}\" -eq 30 ]]",
    "snapshot_sha=\"sha256:$(sha256sum",
    "[[ \"${job_id}\" =~ ^([^.]+)\\.([^.]+)\\.([^.]+)\\.([^.]+)$ ]]",
    "[[ \"${job_run_id}\" == \"${GITHUB_RUN_ID}\" ]]",
    "[[ \"${source_attempt}\" =~ ^[1-9][0-9]*$ ]]",
    "${#source_attempt} > ${#GITHUB_RUN_ATTEMPT}",
    "[[ \"${source_attempt}\" > \"${GITHUB_RUN_ATTEMPT}\" ]]",
    "[[ \"${job_role}\" == \"${role}\" && \"${job_arch}\" == \"${artifact_arch}\" ]]",
    "for attempt in 1 2 3 4",
    "delay=$((5 * (1 << (attempt - 1))))",
    "[[ -z \"${status_code}\" || \"${status_code}\" == \"408\" || \"${status_code}\" == \"429\" ]]",
    "10#${status_code} >= 500 && 10#${status_code} <= 599",
    "[[ \"${retryable}\" != true || \"${attempt}\" -eq 4 ]]",
    "sleep \"${delay}\"",
    "${status_code:-unavailable}",
    "gh api --include --method POST",
    "--input \"${snapshot}\" >\"${response}\" 2>\"${stderr}\" || gh_exit=$?",
    "repos/OxiBelt/OxiBelt/dependency-graph/snapshots",
    "\"${gh_exit}\" -eq 0 && \"${status_code}\" == \"201\"",
    "[[ \"${submission_succeeded}\" == true ]]",
    ".result == \"SUCCESS\"",
  ] {
    assert!(
      snapshot_job_text.contains(expected),
      "dependency snapshot job should include {expected}"
    );
  }
  for forbidden in [
    "actions/checkout@",
    "docker load",
    "aquasecurity/trivy-action@",
    "tests/scripts/",
    "github-pat:",
    "--arg job_id \"${GITHUB_RUN_ID}.${GITHUB_RUN_ATTEMPT}",
    ".job.id == $job_id",
  ] {
    assert!(
      !snapshot_job_text.contains(forbidden),
      "write-capable snapshot submission must not execute {forbidden}"
    );
  }
  assert_eq!(
    snapshot_job_text
      .matches("gh api --include --method POST")
      .count(),
    1,
    "snapshot submission should use one guarded POST call inside the bounded retry loop"
  );
}

#[test]
fn production_role_images_cover_every_role_architecture_and_bind_artifacts() {
  let workflow = workflow_text();
  let amd64_roles = workflow_job_text(&workflow, "docker-alpine-musl-role-image-amd64");
  let other_roles = workflow_job_text(&workflow, "docker-alpine-musl-role-image-other");
  let builder = docker_image_artifact_build_script_text();
  let validator = ci_image_artifact_validator_text();

  for (role, artifact_prefix) in OXIBELT_IMAGE_ROLES
    .iter()
    .copied()
    .filter(|(role, _)| *role != "standalone")
  {
    for job in [&amd64_roles, &other_roles] {
      assert!(
        job.contains(&format!("name: {role}"))
          && job.contains(&format!("artifact_prefix: {artifact_prefix}")),
        "role image job should include {role}/{artifact_prefix}"
      );
    }
  }
  for (artifact_arch, platform, runner) in [
    ("amd64v2", "linux/amd64", "ubuntu-26.04"),
    ("amd64v4", "linux/amd64", "ubuntu-26.04"),
    ("arm64", "linux/arm64", "ubuntu-26.04-arm"),
    ("riscv64", "linux/riscv64", "ubuntu-26.04"),
  ] {
    for expected in [
      format!("artifact_arch: {artifact_arch}"),
      format!("platform: {platform}"),
      format!("runner: {runner}"),
    ] {
      assert!(
        other_roles.contains(&expected),
        "non-canonical role matrix should include {expected}"
      );
    }
  }
  for job in [&amd64_roles, &other_roles] {
    assert!(
      job.contains("fail-fast: false")
        && job.contains("if: matrix.role.name == 'dataplane-strict'")
        && job.contains("tests/scripts/validate-strict-dataplane-image.py")
        && job.contains("-build-metadata.json")
        && job.contains("-artifact-contract.json")
        && job.contains("if-no-files-found: error"),
      "role images should collect all failures and upload validated identity material"
    );
  }

  for expected in [
    "artifact_contract=",
    "tests/scripts/validate-ci-image-artifact.py\" create",
    "--expected-revision \"${oxibelt_revision}\"",
    "--expected-source \"${oxibelt_source}\"",
  ] {
    assert!(
      builder.contains(expected),
      "Docker image builder should create its artifact contract with {expected}"
    );
  }
  for expected in [
    "MAXIMUM_ARCHIVE_BYTES",
    "MAXIMUM_ARCHIVE_MEMBERS",
    "safe_member_name",
    "Docker archive contains duplicate member names",
    "containerimage.config.digest",
    "containerimage.descriptor",
    "containerimage.digest",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.source",
    "io.oxibelt.image.role",
    "image_tar_sha256",
    "os.replace",
  ] {
    assert!(
      validator.contains(expected),
      "CI image artifact validator should enforce {expected}"
    );
  }
  for forbidden in ["extractall", "os.system", "eval(", "shell=True"] {
    assert!(
      !validator.contains(forbidden),
      "CI image artifact validator must not use unsafe primitive {forbidden}"
    );
  }
  assert!(
    validator.contains("subprocess.run(")
      && validator.contains("\"ls-files\"")
      && validator.contains("check=True")
      && validator.contains("capture_output=True"),
    "source inventory should use an argument-vector Git subprocess with checked, captured output"
  );
}

#[test]
fn pr_non_benchmark_summary_executes_only_trusted_helper() {
  let workflow = workflow_text();
  let parsed: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("check workflow should parse as YAML");
  let summary_job = &parsed["jobs"]["pr-non-benchmark-summary"];
  let steps = summary_job["steps"]
    .as_array()
    .expect("terminal non-benchmark summary should define steps");
  let step_names = steps
    .iter()
    .map(|step| {
      step["name"]
        .as_str()
        .expect("terminal non-benchmark summary steps should have names")
    })
    .collect::<Vec<_>>();
  assert_eq!(
    step_names,
    vec![
      "Checkout trusted non-benchmark summary helper",
      "Build non-benchmark validation summary",
      "Upload non-benchmark validation summary",
      "Enforce non-benchmark validation result",
    ],
    "terminal non-benchmark summary should contain only the trusted checkout and summary steps"
  );
  let checkout_steps = steps
    .iter()
    .enumerate()
    .filter(|(_, step)| {
      step["uses"]
        .as_str()
        .is_some_and(|uses| uses.starts_with("actions/checkout@"))
    })
    .collect::<Vec<_>>();

  assert_eq!(
    summary_job["permissions"],
    serde_json::json!({"contents": "read"}),
    "terminal summary should retain exact read-only repository permissions"
  );
  assert_eq!(
    checkout_steps.len(),
    1,
    "terminal summary should perform exactly one trusted repository checkout"
  );
  let (checkout_position, checkout) = checkout_steps[0];
  assert_eq!(
    checkout["name"].as_str(),
    Some("Checkout trusted non-benchmark summary helper")
  );
  assert_eq!(
    checkout["uses"].as_str(),
    Some("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
  );
  assert_eq!(
    checkout["with"],
    serde_json::json!({
      "repository": "${{ github.repository }}",
      "ref": "${{ github.event_name == 'pull_request' && github.event.pull_request.base.sha || github.sha }}",
      "path": "trusted-non-benchmark-summary",
      "persist-credentials": false,
      "sparse-checkout": "tests/scripts/summarize-ci-needs.sh",
      "sparse-checkout-cone-mode": false
    }),
    "terminal summary should load only the helper from the immutable PR base revision"
  );

  let summarize_position = steps
    .iter()
    .position(|step| step["id"].as_str() == Some("summarize"))
    .expect("terminal summary should define its summarization step");
  assert!(
    checkout_position < summarize_position,
    "trusted helper checkout should precede summary execution"
  );
  let summarize_run = steps[summarize_position]["run"]
    .as_str()
    .expect("terminal summary should execute a shell script");
  assert_eq!(
    summarize_run.matches("summarize-ci-needs.sh").count(),
    1,
    "terminal summary should invoke exactly one summarize-ci-needs.sh helper"
  );
  assert!(
    summarize_run.contains(
      "bash \"${GITHUB_WORKSPACE}/trusted-non-benchmark-summary/tests/scripts/summarize-ci-needs.sh\""
    ),
    "terminal summary should execute the helper only from its isolated trusted checkout"
  );
  for forbidden in [
    "bash tests/scripts/summarize-ci-needs.sh",
    "bash ./tests/scripts/summarize-ci-needs.sh",
    "${GITHUB_WORKSPACE}/tests/scripts/summarize-ci-needs.sh",
  ] {
    assert!(
      !summarize_run.contains(forbidden),
      "terminal summary must not execute a PR-controlled helper via {forbidden}"
    );
  }
  let summary_job_json =
    serde_json::to_string(summary_job).expect("terminal summary job should serialize");
  assert!(
    !summary_job_json.contains("github.event.pull_request.head.sha"),
    "terminal summary must not load executable content from the pull request head"
  );
}

#[test]
fn pr_non_benchmark_summary_is_exact_fail_closed_and_pr_concurrent() {
  let workflow = workflow_text();
  let parsed: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("check workflow should parse as YAML");
  let jobs = parse_jobs(&workflow);
  let summary = jobs
    .get("pr-non-benchmark-summary")
    .expect("workflow should define the terminal non-benchmark summary");
  let summary_text = workflow_job_text(&workflow, "pr-non-benchmark-summary");
  let summary_script = non_benchmark_summary_script_text();

  assert_eq!(
    summary.needs,
    expected_needs(REQUIRED_NON_BENCHMARK_JOBS),
    "terminal non-benchmark summary should depend on the exact required job set"
  );
  for expected in [
    "github.event_name == 'pull_request' && 'PR non-benchmark summary'",
    "if: ${{ always() && github.actor != 'dependabot[bot]' }}",
    "OXIBELT_NEEDS_JSON: ${{ toJSON(needs) }}",
    "tests/scripts/summarize-ci-needs.sh",
    "name: Upload non-benchmark validation summary",
    "if: always()",
    "name: Enforce non-benchmark validation result",
  ] {
    assert!(
      summary_text.contains(expected),
      "terminal non-benchmark summary should include {expected}"
    );
  }
  for job_id in REQUIRED_NON_BENCHMARK_JOBS {
    assert!(
      summary_script.contains(&format!("  {job_id}\n")),
      "summary helper should require {job_id}"
    );
  }
  for job_id in BENCHMARK_ONLY_JOBS
    .iter()
    .copied()
    .chain(["docker-image-dependency-snapshot-submit"])
  {
    assert!(
      !summary.needs.contains(&job_id.to_owned()),
      "terminal non-benchmark summary must not depend on {job_id}"
    );
  }
  for job_id in BENCHMARK_ONLY_JOBS {
    assert!(
      has_transitive_need(&jobs, job_id, "pr-non-benchmark-summary"),
      "scheduled/manual benchmark job {job_id} should wait for the same-run non-benchmark summary"
    );
  }
  for forbidden in [".outputs", "eval", "source ", "contents: write"] {
    assert!(
      !summary_script.contains(forbidden) && !summary_text.contains("contents: write"),
      "terminal summary must not expose or execute dependency data via {forbidden}"
    );
  }

  let pull_request = parsed
    .pointer("/on/pull_request")
    .expect("check workflow should run on pull requests");
  assert!(
    pull_request.is_null()
      || pull_request.as_object().is_some_and(
        |trigger| !trigger.contains_key("paths") && !trigger.contains_key("paths-ignore")
      ),
    "pull-request trigger must not use path filtering"
  );
  for expected in [
    "format('{0}-pr-{1}', github.workflow, github.event.pull_request.number)",
    "format('{0}-run-{1}', github.workflow, github.run_id)",
    "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
  ] {
    assert!(
      workflow.contains(expected),
      "workflow should preserve PR-only superseded-run cancellation with {expected}"
    );
  }

  let parsed_jobs = parsed
    .get("jobs")
    .and_then(serde_json::Value::as_object)
    .expect("check workflow should contain jobs");
  for job_id in REQUIRED_NON_BENCHMARK_JOBS {
    let job = parsed_jobs
      .get(*job_id)
      .unwrap_or_else(|| panic!("workflow should define required job {job_id}"));
    let condition = job.get("if").and_then(serde_json::Value::as_str);
    if CHECK_WORKFLOW_ENTRY_JOBS.contains(job_id) {
      assert_eq!(condition, Some(DEPENDABOT_ACTOR_CONDITION));
    } else {
      assert!(
        condition.is_none(),
        "ordinary PR job {job_id} must not have a top-level skip condition"
      );
    }
  }
}

#[test]
fn non_benchmark_summary_helper_reports_success_and_rejects_incomplete_results() {
  let temp_dir = tempfile::Builder::new()
    .prefix("oxibelt-non-benchmark-summary-")
    .tempdir()
    .expect("summary helper temp directory should be creatable");
  let script = non_benchmark_summary_script_path();
  let mut needs = serde_json::Map::new();
  for job_id in REQUIRED_NON_BENCHMARK_JOBS {
    needs.insert(
      (*job_id).to_owned(),
      serde_json::json!({
        "result": "success",
        "outputs": {"must_not_leak": "synthetic-secret-output"}
      }),
    );
  }

  let run_case = |label: &str, value: &serde_json::Value| {
    let input = temp_dir.path().join(format!("{label}-needs.json"));
    let summary = temp_dir.path().join(format!("{label}-summary.json"));
    let markdown = temp_dir.path().join(format!("{label}-summary.md"));
    fs::write(
      &input,
      serde_json::to_vec(value).expect("summary fixture should serialize"),
    )
    .expect("summary fixture should be writable");
    let output = Command::new("bash")
      .arg(&script)
      .arg(&input)
      .arg(&summary)
      .arg(&markdown)
      .current_dir(repo_root())
      .env("GITHUB_REPOSITORY", "OxiBelt/OxiBelt")
      .env("GITHUB_EVENT_NAME", "pull_request")
      .env("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
      .env("GITHUB_REF", "refs/pull/1/merge")
      .env("GITHUB_RUN_ID", "123")
      .env("GITHUB_RUN_ATTEMPT", "1")
      .output()
      .unwrap_or_else(|error| panic!("summary helper case {label} should execute: {error}"));
    (output, summary, markdown)
  };

  let success_value = serde_json::Value::Object(needs.clone());
  let (success, summary_path, markdown_path) = run_case("success", &success_value);
  assert!(
    success.status.success(),
    "all-success summary should pass: {}",
    String::from_utf8_lossy(&success.stderr)
  );
  let summary_text = fs::read_to_string(&summary_path).expect("success summary should be readable");
  let summary: serde_json::Value =
    serde_json::from_str(&summary_text).expect("success summary should be JSON");
  assert_eq!(summary["schema"], 1);
  assert_eq!(summary["overall"], "success");
  assert_eq!(summary["jobs"].as_array().map(Vec::len), Some(34));
  assert_eq!(summary["unexpected"], serde_json::json!([]));
  assert!(!summary_text.contains("synthetic-secret-output"));
  assert!(
    fs::read_to_string(markdown_path)
      .expect("success Markdown should be readable")
      .contains("Non-benchmark validation summary")
  );

  for result in ["failure", "cancelled", "skipped", "unexpected"] {
    let mut failed = needs.clone();
    failed.insert(
      "typescript-release-tooling".to_owned(),
      serde_json::json!({"result": result, "outputs": {}}),
    );
    let (output, summary_path, _) = run_case(result, &serde_json::Value::Object(failed));
    assert!(
      !output.status.success(),
      "summary helper must reject required result {result}"
    );
    let summary: serde_json::Value = serde_json::from_slice(
      &fs::read(&summary_path).expect("failed summary should still be written"),
    )
    .expect("failed summary should be valid JSON");
    assert_eq!(summary["overall"], "failure");
    assert_eq!(summary["unexpected"][0]["result"], result);
  }

  let mut extra = needs.clone();
  extra.insert(
    "unexpected-extra-job".to_owned(),
    serde_json::json!({"result": "success", "outputs": {}}),
  );
  let (output, summary_path, _) = run_case("extra", &serde_json::Value::Object(extra));
  assert!(
    !output.status.success(),
    "summary helper must reject an unexpected extra job"
  );
  let summary: serde_json::Value = serde_json::from_slice(
    &fs::read(summary_path).expect("extra-job summary should still be written"),
  )
  .expect("extra-job summary should be valid JSON");
  assert_eq!(
    summary["extra_jobs"],
    serde_json::json!(["unexpected-extra-job"])
  );

  let mut missing = needs;
  missing.remove("typescript-release-tooling");
  let (output, summary_path, _) = run_case("missing", &serde_json::Value::Object(missing));
  assert!(
    !output.status.success(),
    "summary helper must reject a missing required job"
  );
  let summary: serde_json::Value = serde_json::from_slice(
    &fs::read(summary_path).expect("missing-job summary should still be written"),
  )
  .expect("missing-job summary should be valid JSON");
  assert_eq!(
    summary["missing_jobs"],
    serde_json::json!(["typescript-release-tooling"])
  );

  let malformed_input = temp_dir.path().join("malformed-needs.json");
  let malformed_summary = temp_dir.path().join("malformed-summary.json");
  let malformed_markdown = temp_dir.path().join("malformed-summary.md");
  fs::write(&malformed_input, b"{").expect("malformed fixture should be writable");
  let output = Command::new("bash")
    .arg(&script)
    .arg(&malformed_input)
    .arg(&malformed_summary)
    .arg(&malformed_markdown)
    .current_dir(repo_root())
    .output()
    .expect("summary helper malformed-input case should execute");
  assert!(
    !output.status.success(),
    "summary helper must reject malformed JSON"
  );
  assert!(
    !malformed_summary.exists() && !malformed_markdown.exists(),
    "malformed input must not produce misleading summary artifacts"
  );
}

#[test]
fn dependency_snapshot_helper_normalizes_package_free_reports() {
  let temp_dir = tempfile::Builder::new()
    .prefix("oxibelt-dependency-snapshot-")
    .tempdir()
    .expect("dependency snapshot temp directory should be creatable");
  let helper = dependency_snapshot_helper_path();
  let revision = "0123456789abcdef0123456789abcdef01234567";
  let git_ref = "refs/heads/main";
  let run_id = "123";
  let run_attempt = "1";
  let html_url = "https://github.com/OxiBelt/OxiBelt/actions/runs/123";

  let run_normalize = |label: &str, raw: &serde_json::Value| {
    let case_dir = temp_dir.path().join(label);
    fs::create_dir_all(&case_dir).expect("snapshot case directory should be creatable");
    let input = case_dir.join("raw.json");
    let snapshot = case_dir.join("dependency-snapshot-dataplane-amd64.json");
    let contract = case_dir.join("dependency-snapshot-dataplane-amd64-contract.json");
    fs::write(
      &input,
      serde_json::to_vec(raw).expect("raw Trivy snapshot fixture should serialize"),
    )
    .expect("raw Trivy snapshot fixture should be writable");
    let output = Command::new("python3")
      .arg(&helper)
      .arg("normalize")
      .arg("--input")
      .arg(&input)
      .arg("--snapshot")
      .arg(&snapshot)
      .arg("--contract")
      .arg(&contract)
      .arg("--role")
      .arg("dataplane")
      .arg("--artifact-arch")
      .arg("amd64")
      .arg("--revision")
      .arg(revision)
      .arg("--ref")
      .arg(git_ref)
      .arg("--run-id")
      .arg(run_id)
      .arg("--run-attempt")
      .arg(run_attempt)
      .arg("--html-url")
      .arg(html_url)
      .current_dir(repo_root())
      .output()
      .unwrap_or_else(|error| panic!("dependency snapshot case {label} should execute: {error}"));
    (output, snapshot, contract)
  };

  let package_free_raw = serde_json::json!({
    "version": 0,
    "detector": {
      "name": "trivy",
      "version": "0.72.0",
      "url": "https://github.com/aquasecurity/trivy"
    },
    "scanned": "2026-07-21T03:56:06Z"
  });
  let (output, snapshot, contract) = run_normalize("missing-manifests", &package_free_raw);
  assert!(
    output.status.success(),
    "a package-free Trivy snapshot should normalize: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  let normalized: serde_json::Value = serde_json::from_slice(
    &fs::read(&snapshot).expect("normalized package-free snapshot should be readable"),
  )
  .expect("normalized package-free snapshot should be valid JSON");
  assert_eq!(normalized["manifests"], serde_json::json!({}));
  assert_eq!(
    normalized["job"]["correlator"],
    "oxibelt-image:dataplane:amd64"
  );

  let validation = Command::new("python3")
    .arg(&helper)
    .arg("validate")
    .arg("--snapshot")
    .arg(&snapshot)
    .arg("--contract")
    .arg(&contract)
    .arg("--role")
    .arg("dataplane")
    .arg("--artifact-arch")
    .arg("amd64")
    .arg("--revision")
    .arg(revision)
    .arg("--ref")
    .arg(git_ref)
    .arg("--run-id")
    .arg(run_id)
    .arg("--run-attempt")
    .arg(run_attempt)
    .arg("--html-url")
    .arg(html_url)
    .current_dir(repo_root())
    .output()
    .expect("normalized package-free snapshot should be validatable");
  assert!(
    validation.status.success(),
    "normalized package-free snapshot should pass validation: {}",
    String::from_utf8_lossy(&validation.stderr)
  );

  let populated_manifests = serde_json::json!({
    "oxibelt:alpine-musl-amd64 (alpine 3.24.1)": {
      "name": "alpine",
      "resolved": {}
    }
  });
  let mut populated_raw = package_free_raw.clone();
  populated_raw
    .as_object_mut()
    .expect("raw snapshot fixture should be an object")
    .insert("manifests".to_owned(), populated_manifests.clone());
  let (output, snapshot, _) = run_normalize("populated-manifests", &populated_raw);
  assert!(
    output.status.success(),
    "a populated Trivy snapshot should normalize: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  let normalized: serde_json::Value = serde_json::from_slice(
    &fs::read(snapshot).expect("normalized populated snapshot should be readable"),
  )
  .expect("normalized populated snapshot should be valid JSON");
  assert_eq!(normalized["manifests"], populated_manifests);

  for (label, invalid_manifests) in [
    ("null-manifests", serde_json::Value::Null),
    ("array-manifests", serde_json::json!([])),
    ("string-manifests", serde_json::json!("invalid")),
    ("number-manifests", serde_json::json!(0)),
  ] {
    let mut invalid_raw = package_free_raw.clone();
    invalid_raw
      .as_object_mut()
      .expect("raw snapshot fixture should be an object")
      .insert("manifests".to_owned(), invalid_manifests);
    let (output, snapshot, contract) = run_normalize(label, &invalid_raw);
    assert!(
      !output.status.success(),
      "dependency snapshot helper should reject {label}"
    );
    assert!(
      String::from_utf8_lossy(&output.stderr)
        .contains("Trivy snapshot manifests must be an object"),
      "dependency snapshot helper should explain {label}: {}",
      String::from_utf8_lossy(&output.stderr)
    );
    assert!(
      !snapshot.exists() && !contract.exists(),
      "invalid snapshot input must not produce bound artifacts"
    );
  }
}

#[test]
fn dependency_snapshot_helper_is_local_bounded_and_schema_exact() {
  let helper = dependency_snapshot_helper_text();
  for expected in [
    "MAXIMUM_SNAPSHOT_BYTES",
    "SNAPSHOT_KEYS",
    "CONTRACT_KEYS",
    "oxibelt-image:{role}:{artifact_arch}",
    "snapshot_sha256",
    "os.replace",
  ] {
    assert!(
      helper.contains(expected),
      "dependency snapshot helper should enforce {expected}"
    );
  }
  for forbidden in [
    "subprocess",
    "requests",
    "urllib",
    "socket",
    "gh api",
    "github-pat",
    "eval(",
  ] {
    assert!(
      !helper.contains(forbidden),
      "local dependency snapshot helper must not use {forbidden}"
    );
  }
}

#[test]
fn release_publication_requires_exact_non_benchmark_source_validation() {
  let check_workflow = workflow_text();
  let release_workflow = release_workflow_text();
  let parsed_check: serde_json::Value =
    serde_saphyr::from_str(&check_workflow).expect("check workflow should parse as YAML");
  let parsed_release: serde_json::Value =
    serde_saphyr::from_str(&release_workflow).expect("release workflow should parse as YAML");
  let release_jobs = parse_jobs(&release_workflow);

  assert!(
    parsed_check["on"].get("workflow_call").is_none(),
    "the canonical check workflow must remain direct so write-capable jobs retain their own permissions"
  );
  assert!(
    !check_workflow.contains("release_validation")
      && !check_workflow.contains("inputs.source_ref")
      && !check_workflow.contains("inputs.source_revision"),
    "release-only inputs must not alter the canonical check workflow"
  );

  for job_id in CHECK_WORKFLOW_ENTRY_JOBS {
    let condition = parsed_check["jobs"][job_id]["if"]
      .as_str()
      .unwrap_or_else(|| panic!("entry job {job_id} should define a condition"));
    assert_eq!(
      condition, DEPENDABOT_ACTOR_CONDITION,
      "canonical entry-job actor handling should remain unchanged in {job_id}"
    );
  }
  let check_jobs = parsed_check["jobs"]
    .as_object()
    .expect("check workflow should define jobs");
  for (job_id, job) in check_jobs {
    let Some(steps) = job.get("steps").and_then(serde_json::Value::as_array) else {
      continue;
    };
    for step in steps {
      if step["name"].as_str() == Some("Checkout") {
        assert_eq!(
          step["with"]["ref"], "${{ github.sha }}",
          "source checkout in {job_id} should remain bound to the workflow commit"
        );
      }
    }
  }

  assert_eq!(
    release_jobs.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from([
      "enforce-source-validation".to_owned(),
      "ghcr-index-attest".to_owned(),
      "ghcr-index-promote".to_owned(),
      "ghcr-index-sbom".to_owned(),
      "ghcr-index-verify".to_owned(),
      "ghcr-manifest-publish".to_owned(),
      "prepare-release".to_owned(),
      "release-contract".to_owned(),
      "release-image-arch".to_owned(),
      "release-image-arch-scan".to_owned(),
      "release-vulnerability-gate".to_owned(),
      "resolve-release-source".to_owned(),
      "source-validation".to_owned(),
    ]),
    "release publication should contain an explicit source-resolution and fail-closed validation chain"
  );
  let resolver_text = workflow_job_text(&release_workflow, "resolve-release-source");
  for forbidden in [
    "pnpm ",
    "cargo ",
    "tests/scripts/",
    "actions/upload-artifact@",
    "packages: write",
    "id-token: write",
  ] {
    assert!(
      !resolver_text.contains(forbidden),
      "source resolver must not execute or publish through {forbidden}"
    );
  }

  let validation = &parsed_release["jobs"]["source-validation"];
  assert_eq!(validation["runs-on"], "ubuntu-26.04");
  assert_eq!(
    validation["needs"],
    serde_json::json!(["resolve-release-source"])
  );
  assert_eq!(
    validation["permissions"],
    serde_json::json!({"actions": "read", "checks": "read", "contents": "read"})
  );
  assert_eq!(
    validation["outputs"],
    serde_json::json!({
      "validated_ref": "${{ steps.verify.outputs.validated_ref }}",
      "validated_revision": "${{ steps.verify.outputs.validated_revision }}"
    })
  );
  assert!(
    validation.get("uses").is_none()
      && validation.get("with").is_none()
      && validation.get("secrets").is_none(),
    "release source validation must be a normal job without reusable-workflow inputs or secrets"
  );
  let validation_steps = validation["steps"]
    .as_array()
    .expect("source validation should define steps");
  assert_eq!(
    validation_steps.len(),
    1,
    "source validation should only query trusted GitHub metadata"
  );
  let verifier = &validation_steps[0];
  assert_eq!(
    verifier["uses"],
    "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"
  );
  assert_eq!(verifier["with"]["github-token"], "${{ github.token }}");
  assert_eq!(
    verifier["env"],
    serde_json::json!({
      "OXIBELT_CANONICAL_BRANCH": "${{ github.event.repository.default_branch }}",
      "OXIBELT_CANONICAL_REPOSITORY": "OxiBelt/OxiBelt",
      "OXIBELT_CANONICAL_WORKFLOW": ".github/workflows/check-oxibelt.yml",
      "OXIBELT_EXPECTED_APP_ID": "15368",
      "OXIBELT_EXPECTED_APP_SLUG": "github-actions",
      "OXIBELT_EXPECTED_REF": "${{ needs.resolve-release-source.outputs.release_ref }}",
      "OXIBELT_EXPECTED_REVISION": "${{ needs.resolve-release-source.outputs.revision }}",
      "OXIBELT_EXPECTED_SUMMARY": "Non-benchmark validation summary"
    })
  );
  let verifier_script = verifier["with"]["script"]
    .as_str()
    .expect("source validation should execute a GitHub API verifier");
  for expected in [
    "github.rest.actions.listWorkflowRuns",
    "workflow_id: canonicalWorkflow",
    "branch: canonicalBranch",
    "event: 'push'",
    "head_sha: expectedRevision",
    "run.path === canonicalWorkflow",
    "run.repository?.full_name === canonicalRepository",
    "run.head_repository?.full_name === canonicalRepository",
    "canonicalRuns.sort((left, right) => right.id - left.id)",
    "github.rest.actions.listJobsForWorkflowRunAttempt",
    "attempt_number: run.run_attempt",
    "summaries.length !== 1",
    "summary.status !== 'completed'",
    "summary.conclusion !== 'success'",
    "summary.head_sha !== expectedRevision",
    "github.rest.checks.get",
    "check.app?.id !== expectedAppId",
    "check.app?.slug !== expectedAppSlug",
    "check.details_url !== summary.html_url",
    "github.rest.actions.getWorkflowRun",
    "finalRun.data.run_attempt !== run.run_attempt",
    "changed identity or attempt during validation",
    "core.setOutput('validated_ref', expectedRef)",
    "core.setOutput('validated_revision', expectedRevision)",
  ] {
    assert!(
      verifier_script.contains(expected),
      "exact-revision canonical-run verifier should contain {expected}"
    );
  }
  let validation_text = workflow_job_text(&release_workflow, "source-validation");
  for forbidden in [
    "actions/checkout@",
    "packages: write",
    "id-token: write",
    "uses: ./.github/workflows/check-oxibelt.yml",
    "secrets:",
  ] {
    assert!(
      !validation_text.contains(forbidden),
      "source-validation metadata query must not use {forbidden}"
    );
  }

  let ruleset_text =
    fs::read_to_string(repo_root().join("devops/config/github-release-tag-ruleset.json"))
      .expect("release-tag ruleset desired state should be readable");
  let ruleset: serde_json::Value =
    serde_json::from_str(&ruleset_text).expect("release-tag ruleset should parse as JSON");
  assert_eq!(
    ruleset,
    serde_json::json!({
      "name": "release-tags-require-complete-validation",
      "target": "tag",
      "enforcement": "active",
      "bypass_actors": [],
      "conditions": {
        "ref_name": {
          "include": ["refs/tags/[0-9]*.[0-9]*.[0-9]*"],
          "exclude": []
        }
      },
      "rules": [
        {
          "type": "required_status_checks",
          "parameters": {
            "do_not_enforce_on_create": false,
            "required_status_checks": [{
              "context": "Non-benchmark validation summary",
              "integration_id": 15368
            }],
            "strict_required_status_checks_policy": false
          }
        },
        {"type": "update"},
        {"type": "deletion"}
      ]
    }),
    "tracked tag-ruleset desired state must stay exact and bypass-free"
  );
  assert!(
    !ruleset["rules"]
      .as_array()
      .expect("ruleset should define rules")
      .iter()
      .any(|rule| rule["type"] == "creation"),
    "the ruleset must gate rather than universally block release-tag creation"
  );
  let required_check = &ruleset["rules"][0]["parameters"]["required_status_checks"][0];
  assert_eq!(
    required_check["context"],
    verifier["env"]["OXIBELT_EXPECTED_SUMMARY"]
  );
  assert_eq!(
    required_check["integration_id"]
      .as_u64()
      .expect("required check integration id should be numeric")
      .to_string(),
    verifier["env"]["OXIBELT_EXPECTED_APP_ID"]
      .as_str()
      .expect("verifier app id should be a string")
  );
  assert!(
    check_workflow.contains(
      "github.event_name == 'pull_request' && 'PR non-benchmark summary' || 'Non-benchmark validation summary'"
    ),
    "the ruleset and release verifier must name the canonical non-PR summary check"
  );

  let enforcement_text = workflow_job_text(&release_workflow, "enforce-source-validation");
  for expected in [
    "if: always()",
    "permissions: {}",
    "needs.resolve-release-source.result",
    "needs.source-validation.result",
    "needs.source-validation.outputs.validated_ref",
    "needs.source-validation.outputs.validated_revision",
    "Release source validation passed",
  ] {
    assert!(
      enforcement_text.contains(expected),
      "fail-closed source-validation enforcement should contain {expected}"
    );
  }

  assert_eq!(
    release_jobs["prepare-release"].needs,
    expected_needs(&[
      "resolve-release-source",
      "enforce-source-validation",
      "release-contract"
    ])
  );
  assert_eq!(
    release_jobs["release-image-arch-scan"].needs,
    expected_needs(&["prepare-release", "enforce-source-validation"])
  );
  assert_eq!(
    release_jobs["release-vulnerability-gate"].needs,
    expected_needs(&["prepare-release", "release-image-arch-scan"])
  );
  assert_eq!(
    release_jobs["release-image-arch"].needs,
    expected_needs(&["prepare-release", "release-vulnerability-gate"])
  );
  for job_id in [
    "release-image-arch-scan",
    "release-vulnerability-gate",
    "release-image-arch",
    "ghcr-manifest-publish",
    "ghcr-index-sbom",
    "ghcr-index-attest",
    "ghcr-index-verify",
    "ghcr-index-promote",
  ] {
    assert!(
      has_transitive_need(&release_jobs, job_id, "enforce-source-validation"),
      "release publication job {job_id} must transitively require successful source validation"
    );
    assert!(
      has_transitive_need(&release_jobs, job_id, "release-contract"),
      "release publication job {job_id} must transitively require the exact changelog and published-note contract"
    );
  }

  let release_contract_text = workflow_job_text(&release_workflow, "release-contract");
  for expected in [
    "name: Verify release changelog and published notes",
    "permissions:",
    "contents: read",
    "persist-credentials: false",
    "pnpm install --frozen-lockfile --ignore-scripts",
    "pnpm run release-contract:candidate \\",
    "build tags must not have or publish from a GitHub Release",
    "Read published stable or beta release",
    "github.rest.repos.getReleaseByTag",
    "pnpm run release-contract:verify \\",
    "--expected-state published",
    "Upload verified release contract",
  ] {
    assert!(
      release_contract_text.contains(expected),
      "release-contract publication gate should contain {expected}"
    );
  }
  for forbidden in [
    "contents: write",
    "packages: write",
    "id-token: write",
    "pnpm run release-contract:candidate -- \\",
    "pnpm run release-contract:verify -- \\",
  ] {
    assert!(
      !release_contract_text.contains(forbidden),
      "release-contract publication gate must not contain {forbidden}"
    );
  }

  let prepare_text = workflow_job_text(&release_workflow, "prepare-release");
  let metadata_upload = prepare_text
    .find("name: Upload release metadata")
    .expect("release preparation should upload metadata");
  let identity_check = prepare_text
    .find("name: Validate release ref matches checkout")
    .expect("release preparation should revalidate the release identity");
  assert!(
    identity_check < metadata_upload,
    "release identity must be revalidated before release metadata is uploaded"
  );
  assert!(
    !prepare_text.contains("Revalidate Node dependency admission"),
    "canonical source validation should own Node dependency admission"
  );
}

#[test]
fn stable_and_beta_tags_prepare_conflict_safe_drafts_without_publishing() {
  let workflow = release_draft_workflow_text();
  let parsed: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("release draft workflow should parse as YAML");
  let jobs = parse_jobs(&workflow);

  assert_eq!(
    parsed["on"]["push"]["tags"],
    serde_json::json!(["*.*.*"]),
    "the draft workflow should inspect release-shaped tag pushes"
  );
  assert_eq!(
    parsed["concurrency"]["cancel-in-progress"],
    serde_json::json!(false),
    "draft preparation must not cancel an in-flight run for an immutable tag"
  );
  assert_eq!(
    jobs.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from([
      "prepare-draft".to_owned(),
      "validate-release-contract".to_owned(),
    ])
  );
  assert!(jobs["validate-release-contract"].needs.is_empty());
  assert_eq!(
    jobs["prepare-draft"].needs,
    expected_needs(&["validate-release-contract"])
  );
  assert_eq!(
    parsed["jobs"]["validate-release-contract"]["permissions"],
    serde_json::json!({"contents": "read"})
  );
  assert_eq!(
    parsed["jobs"]["prepare-draft"]["permissions"],
    serde_json::json!({"contents": "write"})
  );
  assert_eq!(
    parsed["jobs"]["prepare-draft"]["if"],
    "needs.validate-release-contract.outputs.kind == 'stable' || needs.validate-release-contract.outputs.kind == 'beta'",
    "build tags must not enter the GitHub Release writer"
  );

  let validation = workflow_job_text(&workflow, "validate-release-contract");
  for expected in [
    "Checkout exact tag",
    "fetch-depth: 0",
    "persist-credentials: false",
    "pnpm install --frozen-lockfile --ignore-scripts",
    "pnpm run release-contract:candidate \\",
    "--ref \"${GITHUB_REF}\"",
    "--revision \"${GITHUB_SHA}\"",
    "Upload exact-tag release contract",
  ] {
    assert!(
      validation.contains(expected),
      "draft release validation should contain {expected}"
    );
  }
  for forbidden in [
    "contents: write",
    "packages: write",
    "id-token: write",
    "pnpm run release-contract:candidate -- \\",
  ] {
    assert!(
      !validation.contains(forbidden),
      "draft release validation must not contain {forbidden}"
    );
  }

  let draft = workflow_job_text(&workflow, "prepare-draft");
  for expected in [
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # 8.0.1",
    "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9.0.0",
    "github.rest.repos.getReleaseByTag",
    "github.rest.git.getRef",
    "github.rest.git.getTag",
    "tagObject.sha !== receipt.revision",
    "receipt.bodySha256 !== bodyDigest",
    "existing.draft === true",
    "refusing to overwrite it",
    "github.rest.repos.createRelease",
    "target_commitish: receipt.revision",
    "draft: true",
    "prerelease",
  ] {
    assert!(
      draft.contains(expected),
      "draft release writer should contain {expected}"
    );
  }
  for forbidden in [
    "github.rest.repos.updateRelease",
    "draft: false",
    "generate_release_notes",
    "packages: write",
    "id-token: write",
  ] {
    assert!(
      !draft.contains(forbidden),
      "draft release writer must not contain {forbidden}"
    );
  }
}

#[test]
fn release_workflows_use_global_vulnerability_gate_with_scoped_publish_permissions() {
  let workflow = release_workflow_text();
  let scan_workflow = release_image_arch_scan_workflow_text();
  let arch_workflow = release_image_arch_workflow_text();
  let parsed: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("release workflow should parse as YAML");
  let parsed_scan: serde_json::Value =
    serde_saphyr::from_str(&scan_workflow).expect("scan reusable workflow should parse as YAML");
  let parsed_arch: serde_json::Value =
    serde_saphyr::from_str(&arch_workflow).expect("publish reusable workflow should parse as YAML");
  let jobs = parse_jobs(&workflow);
  let scan_jobs = parse_jobs(&scan_workflow);
  let arch_jobs = parse_jobs(&arch_workflow);

  assert_eq!(
    jobs.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from([
      "enforce-source-validation".to_owned(),
      "ghcr-index-attest".to_owned(),
      "ghcr-index-promote".to_owned(),
      "ghcr-index-sbom".to_owned(),
      "ghcr-index-verify".to_owned(),
      "ghcr-manifest-publish".to_owned(),
      "prepare-release".to_owned(),
      "release-contract".to_owned(),
      "release-image-arch".to_owned(),
      "release-image-arch-scan".to_owned(),
      "release-vulnerability-gate".to_owned(),
      "resolve-release-source".to_owned(),
      "source-validation".to_owned(),
    ])
  );
  assert_eq!(
    scan_jobs.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from([
      "build".to_owned(),
      "runtime-smoke".to_owned(),
      "scan".to_owned(),
    ])
  );
  assert_eq!(
    arch_jobs.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from([
      "attest".to_owned(),
      "promote".to_owned(),
      "publish".to_owned(),
      "verify".to_owned(),
    ])
  );
  assert_eq!(
    jobs["release-image-arch-scan"].needs,
    expected_needs(&["prepare-release", "enforce-source-validation"])
  );
  assert_eq!(
    jobs["release-vulnerability-gate"].needs,
    expected_needs(&["prepare-release", "release-image-arch-scan"])
  );
  assert_eq!(
    jobs["release-image-arch"].needs,
    expected_needs(&["prepare-release", "release-vulnerability-gate"])
  );
  assert_eq!(
    jobs["ghcr-index-promote"].needs,
    expected_needs(&[
      "prepare-release",
      "ghcr-manifest-publish",
      "ghcr-index-verify"
    ])
  );
  assert!(scan_jobs["build"].needs.is_empty());
  assert_eq!(scan_jobs["scan"].needs, vec!["build".to_owned()]);
  assert_eq!(scan_jobs["runtime-smoke"].needs, vec!["build".to_owned()]);
  assert!(arch_jobs["publish"].needs.is_empty());
  assert_eq!(arch_jobs["attest"].needs, vec!["publish".to_owned()]);
  assert_eq!(
    arch_jobs["verify"].needs,
    vec!["publish".to_owned(), "attest".to_owned()]
  );
  assert_eq!(
    arch_jobs["promote"].needs,
    vec!["publish".to_owned(), "verify".to_owned()]
  );
  for job_id in [
    "release-image-arch",
    "ghcr-manifest-publish",
    "ghcr-index-sbom",
    "ghcr-index-attest",
    "ghcr-index-verify",
    "ghcr-index-promote",
  ] {
    assert!(has_transitive_need(
      &jobs,
      job_id,
      "release-vulnerability-gate"
    ));
  }

  for job_id in ["release-image-arch-scan", "release-image-arch"] {
    let matrix = &parsed["jobs"][job_id]["strategy"]["matrix"];
    assert_eq!(
      matrix["image_role"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<BTreeSet<_>>(),
      BTreeSet::from([
        "controller",
        "dataplane",
        "dataplane-strict",
        "keysigner",
        "standalone",
        "tools",
      ])
    );
    assert_eq!(
      matrix["artifact_arch"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<BTreeSet<_>>(),
      BTreeSet::from(["amd64", "amd64v2", "amd64v4", "arm64", "riscv64"])
    );
    assert_eq!(parsed["jobs"][job_id]["strategy"]["fail-fast"], false);
  }
  let expected_role_rows = BTreeSet::from([
    (
      "standalone".to_owned(),
      "ghcr.io/oxibelt/oxibelt".to_owned(),
      "oxibelt".to_owned(),
    ),
    (
      "dataplane".to_owned(),
      "ghcr.io/oxibelt/oxibelt-dataplane".to_owned(),
      "oxibelt-dataplane".to_owned(),
    ),
    (
      "dataplane-strict".to_owned(),
      "ghcr.io/oxibelt/oxibelt-dataplane-strict".to_owned(),
      "oxibelt-dataplane-strict".to_owned(),
    ),
    (
      "controller".to_owned(),
      "ghcr.io/oxibelt/oxibelt-gateway-controller".to_owned(),
      "oxibelt-gateway-controller".to_owned(),
    ),
    (
      "tools".to_owned(),
      "ghcr.io/oxibelt/oxibelt-tools".to_owned(),
      "oxibelt-tools".to_owned(),
    ),
    (
      "keysigner".to_owned(),
      "ghcr.io/oxibelt/oxibelt-keysigner".to_owned(),
      "oxibelt-keysigner".to_owned(),
    ),
  ]);
  for job_id in [
    "release-image-arch-scan",
    "release-image-arch",
    "ghcr-manifest-publish",
    "ghcr-index-sbom",
    "ghcr-index-attest",
    "ghcr-index-verify",
    "ghcr-index-promote",
  ] {
    let includes = parsed["jobs"][job_id]["strategy"]["matrix"]["include"]
      .as_array()
      .unwrap_or_else(|| panic!("{job_id} should define a matrix include list"));
    let actual_role_rows = includes
      .iter()
      .filter(|row| row.get("image_role").is_some())
      .map(|row| {
        (
          row["image_role"].as_str().unwrap().to_owned(),
          row["image"].as_str().unwrap().to_owned(),
          row["artifact_prefix"].as_str().unwrap().to_owned(),
        )
      })
      .collect::<BTreeSet<_>>();
    assert_eq!(
      actual_role_rows, expected_role_rows,
      "{job_id} should cover exactly the six release image roles"
    );
  }

  assert_eq!(
    parsed["jobs"]["release-image-arch-scan"]["permissions"],
    serde_json::json!({"actions": "read", "contents": "read"})
  );
  assert_eq!(
    parsed["jobs"]["release-vulnerability-gate"]["permissions"],
    serde_json::json!({"actions": "read"})
  );
  assert_eq!(
    parsed["jobs"]["release-image-arch"]["permissions"],
    serde_json::json!({
      "actions": "read",
      "attestations": "write",
      "contents": "read",
      "id-token": "write",
      "packages": "write"
    })
  );
  let transport_artifact_name = "${{ format('release-{0}-{1}-alpine-musl-{2}-image', github.run_id, matrix.artifact_prefix, matrix.artifact_arch) }}";
  for job_id in ["release-image-arch-scan", "release-image-arch"] {
    assert_eq!(
      parsed["jobs"][job_id]["with"]["transport_artifact_name"].as_str(),
      Some(transport_artifact_name),
      "{job_id} should consume the run-scoped transport artifact across reruns"
    );
  }
  assert_eq!(
    parsed["jobs"]["release-image-arch"]["with"]["vulnerability_decision_artifact_name"].as_str(),
    Some(
      "${{ format('release-vulnerability-decision-{0}-{1}', github.run_id, github.run_attempt) }}"
    ),
    "release admission evidence should remain attempt-scoped"
  );
  assert!(parsed_scan["on"]["workflow_call"].get("secrets").is_none());
  assert_eq!(
    parsed_arch["on"]["workflow_call"]["inputs"]["vulnerability_decision_artifact_name"]["required"],
    true
  );
  for job_id in ["build", "scan", "runtime-smoke"] {
    assert_eq!(
      parsed_scan["jobs"][job_id]["permissions"],
      serde_json::json!({"actions": "read", "contents": "read"})
    );
  }
  for (job_id, expected) in [
    (
      "ghcr-manifest-publish",
      serde_json::json!({"actions": "read", "contents": "read", "packages": "write"}),
    ),
    (
      "ghcr-index-sbom",
      serde_json::json!({"actions": "read", "contents": "read"}),
    ),
    (
      "ghcr-index-attest",
      serde_json::json!({
        "actions": "read",
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
        "packages": "read"
      }),
    ),
    (
      "ghcr-index-verify",
      serde_json::json!({
        "actions": "read",
        "attestations": "read",
        "contents": "read",
        "packages": "read"
      }),
    ),
    (
      "ghcr-index-promote",
      serde_json::json!({"actions": "read", "contents": "read", "packages": "write"}),
    ),
  ] {
    assert_eq!(
      parsed["jobs"][job_id]["permissions"], expected,
      "main release job {job_id} should keep exact least-privilege permissions"
    );
  }
  for (job_id, expected) in [
    (
      "publish",
      serde_json::json!({"actions": "read", "contents": "read", "packages": "write"}),
    ),
    (
      "attest",
      serde_json::json!({
        "actions": "read",
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
        "packages": "read"
      }),
    ),
    (
      "verify",
      serde_json::json!({
        "actions": "read",
        "attestations": "read",
        "contents": "read",
        "packages": "read"
      }),
    ),
    (
      "promote",
      serde_json::json!({"actions": "read", "contents": "read", "packages": "write"}),
    ),
  ] {
    assert_eq!(
      parsed_arch["jobs"][job_id]["permissions"], expected,
      "publish reusable job {job_id} should keep exact least-privilege permissions"
    );
  }

  let prepare = workflow_job_text(&workflow, "prepare-release");
  for expected in [
    "pnpm run image-vulnerability-policy:check",
    "devops/sources/image_vulnerability_policy.ts",
    "image_vulnerability_policy.mjs",
    "validate-policy",
    "supply-chain/image-vulnerability-policy.json",
    "${metadata_root}/policy/image-vulnerability-policy.json",
    "run-riscv64-release-image-smoke.py",
    "validate-strict-dataplane-image.py",
    "riscv64-release-image-smoke/oxibelt.toml",
    "riscv64-release-image-smoke/controller-empty-list.json",
  ] {
    assert!(
      prepare.contains(expected),
      "prepare-release should include {expected}"
    );
  }

  let build = workflow_job_text(&scan_workflow, "build");
  for expected in [
    "Checkout release revision",
    "Validate immutable release checkout",
    "tests/scripts/build-docker-image-artifact.sh",
    "validate-strict-dataplane-image.py",
    "Upload Docker image artifact",
    "overwrite: true",
  ] {
    assert!(build.contains(expected));
  }
  assert_eq!(
    build.matches("overwrite: true").count(),
    1,
    "a full rerun should replace only its run-scoped transport artifact"
  );
  for forbidden in [
    "packages: write",
    "GITHUB_TOKEN",
    "docker login",
    "docker push",
  ] {
    assert!(!build.contains(forbidden));
  }

  let scan = workflow_job_text(&scan_workflow, "scan");
  for expected in [
    "Docker archive config path is not content addressed ",
    "\"by its digest\"",
    "f\"blobs/sha256/{config_hash}\"",
    "Docker image tar digest does not match the artifact contract",
    "Docker archive repository tag does not match the release plan",
    "Docker archive OCI manifest descriptor does not match ",
    "Docker archive OCI manifest blob digest does not match ",
    "Docker archive OCI image manifest config does not match ",
    "docker image inspect --format '{{.Id}}' \"${image_reference}\"",
    "docker image inspect --format '{{.Id}}' \"${image_id}\"",
    "loaded image ID ${image_id} is not bound to the validated archive",
    "image-ref: ${{ steps.trivy-image.outputs.image_id }}",
    "severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    "exit-code: \"0\"",
    "image_vulnerability_policy.mjs\" bind-scan",
    "--image-id \"${IMAGE_ID}\"",
    "--manifest-digest \"${MANIFEST_DIGEST}\"",
    "trivy-release-${{ github.run_id }}-${{ github.run_attempt }}-",
    "scan-contract-${{ env.OXIBELT_ARTIFACT_PREFIX }}-${{ env.OXIBELT_ARTIFACT_ARCH }}.json",
    "if: always()",
    "if-no-files-found: warn",
    "retention-days: 7",
  ] {
    assert!(scan.contains(expected), "scan should include {expected}");
  }
  assert_eq!(
    scan
      .matches("image-ref: ${{ steps.trivy-image.outputs.image_id }}")
      .count(),
    2
  );
  for forbidden in [
    "packages:",
    "ghcr_token",
    "GITHUB_TOKEN",
    "docker login",
    "docker push",
    ".trivyignore",
    "ignore-unfixed",
  ] {
    assert!(
      !scan.contains(forbidden),
      "scan must not include {forbidden}"
    );
  }

  let runtime_smoke = workflow_job_text(&scan_workflow, "runtime-smoke");
  assert_eq!(
    parsed_scan["jobs"]["runtime-smoke"]["if"],
    "${{ github.repository == 'OxiBelt/OxiBelt' && inputs.artifact_arch == 'riscv64' }}"
  );
  assert_eq!(parsed_scan["jobs"]["runtime-smoke"]["timeout-minutes"], 15);
  for expected in [
    "Run immutable RISC-V release image smoke",
    "run-riscv64-release-image-smoke.py",
    "--artifact-contract",
    "--build-metadata",
    "--image-tar",
    "--strict-validator",
    "--expected-version",
    "--expected-revision",
    "--expected-source-ref",
    "Upload RISC-V runtime smoke evidence",
    "if: always()",
    "if-no-files-found: warn",
    "retention-days: 7",
  ] {
    assert!(
      runtime_smoke.contains(expected),
      "RISC-V runtime smoke should include {expected}"
    );
  }
  for forbidden in [
    "actions/checkout",
    "packages:",
    "attestations:",
    "id-token:",
    "GITHUB_TOKEN",
    "ghcr_token",
    "docker login",
    "docker push",
    "continue-on-error",
  ] {
    assert!(
      !runtime_smoke.contains(forbidden),
      "RISC-V runtime smoke must not include {forbidden}"
    );
  }

  let gate = workflow_job_text(&workflow, "release-vulnerability-gate");
  for expected in [
    "if: ${{ always() && needs.prepare-release.result == 'success' }}",
    "pattern: trivy-release-${{ github.run_id }}-*",
    "merge-multiple: false",
    "find \"${SCAN_ROOT}\" -mindepth 1 -maxdepth 1 -print0",
    "image_vulnerability_policy.mjs\" evaluate",
    "--scan-bundle",
    "--output \"${DECISION}\"",
    "--markdown-output \"${DECISION_MARKDOWN}\"",
    "Upload controlled vulnerability gate decision",
    "retention-days: 7",
    "Enforce vulnerability gate result",
    "steps.evaluate.outcome",
    "needs.release-image-arch-scan.result",
    ".decision == \"allow\"",
  ] {
    assert!(
      gate.contains(expected),
      "global gate should include {expected}"
    );
  }
  assert!(
    gate
      .find("Upload controlled vulnerability gate decision")
      .unwrap()
      < gate.find("Enforce vulnerability gate result").unwrap()
  );
  for forbidden in [
    "packages:",
    "attestations:",
    "id-token:",
    "actions/checkout",
    "docker login",
    "pattern: trivy-release-${{ github.run_id }}-${{ github.run_attempt }}-*",
    "merge-multiple: true",
    "--scan-contract",
    "--scan-report",
  ] {
    assert!(!gate.contains(forbidden));
  }

  let package_boundaries = [
    (
      workflow_job_text(&arch_workflow, "publish"),
      "Verify platform subject was admitted by the global vulnerability gate",
    ),
    (
      workflow_job_text(&arch_workflow, "promote"),
      "Revalidate admitted platform subject before promotion",
    ),
    (
      workflow_job_text(&workflow, "ghcr-manifest-publish"),
      "Validate admitted manifest children before registry login",
    ),
    (
      workflow_job_text(&workflow, "ghcr-index-promote"),
      "Revalidate admitted index children before promotion",
    ),
  ];
  for (job, verification) in package_boundaries {
    for expected in [
      "packages: write",
      "Download controlled vulnerability gate decision",
      "image_vulnerability_policy.mjs\" verify-subject",
      "--manifest-digest",
      "docker login ghcr.io",
      "docker buildx imagetools",
    ] {
      assert!(
        job.contains(expected),
        "package boundary should include {expected}"
      );
    }
    assert!(
      job.find(verification).unwrap() < job.find("docker login ghcr.io").unwrap(),
      "{verification} must precede registry login"
    );
  }
  let manifest = workflow_job_text(&workflow, "ghcr-manifest-publish");
  assert!(manifest.contains("for artifact_arch in amd64 arm64 riscv64"));
  assert!(!manifest.contains("aquasecurity/trivy-action@"));
  assert!(
    workflow_job_text(&workflow, "ghcr-index-promote")
      .contains(".children[] | [.artifactArch, .digest] | @tsv")
  );

  assert_eq!(scan_workflow.matches("packages: write").count(), 0);
  assert_eq!(arch_workflow.matches("packages: write").count(), 2);
  assert_eq!(workflow.matches("packages: write").count(), 3);
  assert_eq!(
    workflow.matches("push-to-registry: false").count()
      + arch_workflow.matches("push-to-registry: false").count(),
    6,
    "every attestation action must keep bundles in the GitHub Attestations API"
  );
  assert_eq!(
    workflow
      .matches("actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4.2.0")
      .count()
      + arch_workflow
        .matches("actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4.2.0")
        .count(),
    6
  );
}

#[test]
fn release_vulnerability_gate_preserves_attestation_and_digest_publication_chain() {
  let workflow = release_workflow_text();
  let scan_workflow = release_image_arch_scan_workflow_text();
  let arch_workflow = release_image_arch_workflow_text();
  let publish = workflow_job_text(&arch_workflow, "publish");
  let attest = workflow_job_text(&arch_workflow, "attest");
  let verify = workflow_job_text(&arch_workflow, "verify");
  let promote = workflow_job_text(&arch_workflow, "promote");
  let manifest = workflow_job_text(&workflow, "ghcr-manifest-publish");
  let index_sbom = workflow_job_text(&workflow, "ghcr-index-sbom");
  let index_attest = workflow_job_text(&workflow, "ghcr-index-attest");
  let index_verify = workflow_job_text(&workflow, "ghcr-index-verify");
  let index_promote = workflow_job_text(&workflow, "ghcr-index-promote");

  for expected in [
    "Validate Docker image artifact for publish",
    "Docker image tar digest does not match the artifact contract",
    "Docker archive OCI manifest blob digest does not match ",
    "Docker archive OCI image manifest config does not match ",
    "manifest_digest=\"$(jq -er '.manifestDigest' \"${PUBLISH_IDENTITY}\")\"",
    "refusing to replace preexisting Docker image reference ${local_tag}",
    "loaded image ID ${image_id} is not bound to the validated archive",
    "expected_digest=\"$(jq -er '.manifestDigest' \"${PUBLISH_IDENTITY}\")\"",
    "refusing to replace canonical tag",
    "docker push \"${canonical_tag}\"",
    "retry_command 3 docker buildx imagetools inspect \"${canonical_tag}\"",
    "registry digest ${digest} does not match Buildx digest ${expected_digest}",
  ] {
    assert!(
      publish.contains(expected),
      "platform publication should retain {expected}"
    );
  }
  for forbidden in [
    "actions/checkout",
    "tests/scripts/build-docker-image-artifact.sh",
    "validate-strict-dataplane-image.py",
  ] {
    assert!(
      !publish.contains(forbidden)
        && !promote.contains(forbidden)
        && !manifest.contains(forbidden)
        && !index_promote.contains(forbidden),
      "registry mutation jobs must not execute build surface {forbidden}"
    );
  }

  for expected in [
    "attestations: write",
    "id-token: write",
    "packages: read",
    "Validate immutable platform attestation subject",
    "canonical platform tag ${canonical_tag} resolved to ${resolved_digest}, expected ${DIGEST}",
    "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4.2.0",
    "Publish signed platform provenance",
    "Publish signed platform SBOM",
    "Publish signed platform rebuild recipe",
    "push-to-registry: false",
  ] {
    assert!(
      attest.contains(expected),
      "platform attestation should retain {expected}"
    );
  }
  for forbidden in ["actions/checkout", "release_sbom.mjs", "packages: write"] {
    assert!(
      !attest.contains(forbidden),
      "OIDC-bearing platform attestation must not include {forbidden}"
    );
  }

  for expected in [
    "attestations: read",
    "packages: read",
    "gh attestation verify",
    "--signer-workflow OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml",
    "--signer-digest \"${RELEASE_REVISION}\"",
    "--source-digest \"${RELEASE_REVISION}\"",
    "--source-ref \"${RELEASE_REF}\"",
    "--cert-oidc-issuer https://token.actions.githubusercontent.com",
    "--deny-self-hosted-runners",
    "--predicate-type https://slsa.dev/provenance/v1",
    "--predicate-type https://cyclonedx.org/bom",
    "--workflow-path .github/workflows/release.yml",
  ] {
    assert!(
      verify.contains(expected),
      "platform attestation verification should retain {expected}"
    );
  }
  for forbidden in [
    "packages: write",
    "attestations: write",
    "id-token: write",
    "--cert-identity",
    "--bundle-from-oci",
  ] {
    assert!(
      !verify.contains(forbidden),
      "platform attestation verification must not include {forbidden}"
    );
  }

  for expected in [
    "def expected_artifact_tags(arch):",
    ".manifests[] | select(.role == $role) | .canonicalGhcrTag",
    "sourceRefs: $source_refs",
    "actual_descriptors=",
    "expected_descriptors=",
    "child_descriptors=",
    "refusing to replace canonical index",
    "canonical index ${canonical_tag} resolved to ${canonical_digest}, expected ${digest}",
    "{schemaVersion: 2, role: $role, image: $image, digest: $digest, children: $children}",
  ] {
    assert!(
      manifest.contains(expected),
      "multi-arch manifest publication should retain {expected}"
    );
  }

  for expected in [
    "Download platform SBOMs",
    "merge-multiple: true",
    "release_sbom.mjs\" index",
    "Upload index SBOM",
  ] {
    assert!(
      index_sbom.contains(expected),
      "index SBOM composition should retain {expected}"
    );
  }
  for forbidden in [
    "packages: read",
    "packages: write",
    "attestations:",
    "id-token:",
  ] {
    assert!(
      !index_sbom.contains(forbidden),
      "index SBOM composition must not expose {forbidden}"
    );
  }

  for expected in [
    "attestations: write",
    "id-token: write",
    "packages: read",
    "Validate immutable index attestation subject",
    "[.children[].artifactArch] == [\"amd64\", \"arm64\", \"riscv64\"]",
    "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4.2.0",
    "Publish signed index provenance",
    "Publish signed index SBOM",
    "Publish signed index rebuild recipe",
    "push-to-registry: false",
  ] {
    assert!(
      index_attest.contains(expected),
      "index attestation should retain {expected}"
    );
  }
  for forbidden in ["actions/checkout", "release_sbom.mjs", "packages: write"] {
    assert!(
      !index_attest.contains(forbidden),
      "OIDC-bearing index attestation must not include {forbidden}"
    );
  }

  for expected in [
    "attestations: read",
    "packages: read",
    "gh attestation verify",
    "--signer-workflow OxiBelt/OxiBelt/.github/workflows/release.yml",
    "--source-ref \"${RELEASE_REF}\"",
    "--deny-self-hosted-runners",
    "--predicate-type https://slsa.dev/provenance/v1",
    "--predicate-type https://cyclonedx.org/bom",
    "--workflow-path .github/workflows/release.yml",
  ] {
    assert!(
      index_verify.contains(expected),
      "index attestation verification should retain {expected}"
    );
  }
  for forbidden in [
    "packages: write",
    "attestations: write",
    "id-token: write",
    "--cert-identity",
    "--bundle-from-oci",
  ] {
    assert!(
      !index_verify.contains(forbidden),
      "index attestation verification must not include {forbidden}"
    );
  }

  for forbidden in [
    "actions/attest-sbom",
    "sigstore/cosign-installer",
    "cosign sign",
    "cosign verify",
    "push-to-registry: true",
    "--bundle-from-oci",
    "--cert-identity",
  ] {
    assert!(
      !workflow.contains(forbidden)
        && !scan_workflow.contains(forbidden)
        && !arch_workflow.contains(forbidden),
      "release workflows must not restore superseded supply-chain surface {forbidden}"
    );
  }
}

#[test]
fn release_workflows_cover_oxibelt_image_artifact_pipeline() {
  let workflow = release_workflow_text();
  let scan_workflow = release_image_arch_scan_workflow_text();
  let arch_workflow = release_image_arch_workflow_text();
  let caller_job_text = workflow_job_text(&workflow, "release-image-arch");

  for (artifact_arch, _, _, _) in OXIBELT_IMAGE_ARTIFACTS {
    assert!(
      caller_job_text.contains(&format!("artifact_arch: {artifact_arch}")),
      "release-image-arch matrix should declare {artifact_arch}"
    );
  }

  for (image_role, artifact_prefix) in [
    ("standalone", "oxibelt"),
    ("dataplane", "oxibelt-dataplane"),
    ("dataplane-strict", "oxibelt-dataplane-strict"),
    ("controller", "oxibelt-gateway-controller"),
    ("tools", "oxibelt-tools"),
    ("keysigner", "oxibelt-keysigner"),
  ] {
    assert!(
      caller_job_text.contains(&format!("image_role: {image_role}"))
        && caller_job_text.contains(&format!("artifact_prefix: {artifact_prefix}")),
      "release-image-arch matrix should declare {image_role}"
    );
  }

  for expected in [
    "OXIBELT_DOCKER_IMAGE_VERSION",
    "OXIBELT_DOCKER_IMAGE_REVISION",
    "OXIBELT_DOCKER_IMAGE_SOURCE_REF",
    "OXIBELT_DOCKER_IMAGE_SOURCE_DIRTY",
    "OXIBELT_DOCKER_IMAGE_BUILD_KIND",
    "OXIBELT_DOCKER_IMAGE_CREATED",
    "OXIBELT_DOCKER_IMAGE_REF_NAME",
    "OXIBELT_DOCKER_IMAGE_SOURCE",
    "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # 4.2.0",
    "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0",
    "release-image-arch",
    "Publish canonical GHCR image",
    "Push canonical arch-specific GHCR tag",
    "Validate release binaries",
    "Generate CycloneDX platform SBOM",
    "Publish signed platform provenance",
    "Publish signed platform SBOM",
    "Publish signed platform rebuild recipe",
    "Verify GitHub API platform attestations",
    "Promote canonical GHCR aliases",
    "ghcr-manifest-publish",
    "Publish canonical multi-arch manifests",
    "ghcr-index-sbom",
    "Compose multi-arch index SBOM",
    "ghcr-index-attest",
    "Publish signed index provenance",
    "Publish signed index SBOM",
    "Publish signed index rebuild recipe",
    "ghcr-index-verify",
    "Verify GitHub API index attestations",
    "ghcr-index-promote",
    "Promote canonical multi-arch aliases",
    "if plan[\"schemaVersion\"] != 8:",
    "release plan must contain exactly 30 unique role/architecture artifacts",
    "release plan must contain exactly 12 unique role manifests",
    "{schemaVersion: 2, role: $role, image: $image, digest: $digest, children: $children}",
    "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4.2.0",
    "https://oxibelt.dev/attestations/rebuild/v1",
    "rebuild_recipe.mjs",
    "push-to-registry: false",
    ":latest",
    r#"aliases = [f"{image}:{major}-alpine-musl-{arch}"] if kind == "stable" else []"#,
  ] {
    assert!(
      workflow.contains(expected)
        || scan_workflow.contains(expected)
        || arch_workflow.contains(expected),
      "release workflows should include {expected}"
    );
  }
  assert!(
    !workflow.contains("pattern: oxibelt-alpine-musl-*-image"),
    "release workflow should not download every image tar during manifest publishing"
  );
  for removed in [
    "ghcr-index-admission-verify",
    "cosign",
    "push-to-registry: true",
    "--bundle-from-oci",
  ] {
    assert!(
      !workflow.contains(removed)
        && !scan_workflow.contains(removed)
        && !arch_workflow.contains(removed),
      "release workflows should not retain {removed}"
    );
  }
}

#[test]
fn independent_release_rebuild_is_read_only_rootless_and_producer_independent() {
  let workflow = release_rebuild_verification_workflow_text();
  let script = release_rebuild_verification_script_text();
  let parsed: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("independent rebuild workflow should parse as YAML");
  let jobs = parsed["jobs"]
    .as_object()
    .expect("independent rebuild workflow should define jobs");

  assert_eq!(
    jobs.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from(["resolve".to_owned(), "verify".to_owned()]),
    "independent rebuild workflow should separate immutable planning from rebuild verification"
  );
  assert_eq!(
    parsed["permissions"],
    serde_json::json!({
      "actions": "read",
      "attestations": "read",
      "contents": "read",
      "packages": "read"
    }),
    "independent rebuild workflow must remain globally read-only"
  );
  assert_eq!(
    jobs["resolve"]["runs-on"], "ubuntu-26.04",
    "independent rebuild planning should retain its reviewed runner"
  );
  assert_eq!(
    jobs["verify"]["runs-on"], "ubuntu-24.04",
    "independent rebuild containers should run on the stable hosted runner"
  );

  for expected in [
    "workflows: [\"Release OxiBelt images\"]",
    "github.event.workflow_run.conclusion == 'success'",
    "github.event.workflow_run.event == 'release'",
    "successful release run must resolve to exactly one stable or beta tag",
    "pnpm run versioning:release",
    "expected_count=30",
    "persist-credentials: false",
    "docker/setup-docker-action@77e84dbf09b47d1e29270283c22f16145aa85ca1 # v5.4.0",
    "version: v29.6.2",
    "rootless: true",
    "daemon-config: |",
    "\"exec-opts\": [\"native.cgroupdriver=cgroupfs\"]",
    "index(\"name=rootless\") != null",
    "index(\"name=cgroupns\") != null",
    "index(\"name=seccomp,profile=builtin\") != null",
    "docker info --format '{{.CgroupDriver}}'",
    "rootless verifier must use no host cgroup resource controller",
    "moby/buildkit:buildx-stable-1@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
    "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # 4.2.0",
    "aquasecurity/setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567 # v0.3.1",
    "pnpm install --frozen-lockfile --ignore-scripts",
    "tests/scripts/verify-release-rebuild.sh",
    "--release-ref \"${RELEASE_REF}\"",
    "--revision \"${RELEASE_REVISION}\"",
    "Upload independent rebuild receipt",
  ] {
    assert!(
      workflow.contains(expected),
      "independent rebuild workflow should include {expected}"
    );
  }
  for forbidden in [
    "actions/download-artifact",
    "oxibelt-release-metadata",
    "attestations: write",
    "contents: write",
    "id-token: write",
    "packages: write",
    "docker-rootful",
    "continue-on-error",
  ] {
    assert!(
      !workflow.contains(forbidden),
      "independent rebuild workflow must not contain {forbidden}"
    );
  }

  for expected in [
    "--workspace-path \"${rebuilt_root}\"",
    "--manifest-path Cargo.toml",
    "--lockfile-path Cargo.lock",
  ] {
    assert!(
      script.contains(expected),
      "independent rebuild versioning should use workspace-relative path argument {expected}"
    );
  }
  for expected in [
    "x86_64:amd64v2) target_cpu=\"x86-64-v2\"",
    "x86_64:amd64) target_cpu=\"x86-64-v3\"",
    "x86_64:amd64v4) target_cpu=\"x86-64-v4\"",
    "\"${rebuilt_root}/tests/scripts/select-amd64-docker-image-artifact.sh\"",
    "GITHUB_OUTPUT='' bash",
    "--allow-unsupported",
    "AMD64 selector returned invalid supported status",
  ] {
    assert!(
      script.contains(expected),
      "independent rebuild binary validation should include {expected}"
    );
  }
  for forbidden in [
    "--manifest-path \"${rebuilt_root}/Cargo.toml\"",
    "--lockfile-path \"${rebuilt_root}/Cargo.lock\"",
  ] {
    assert!(
      !script.contains(forbidden),
      "independent rebuild versioning must not pass rejected absolute path argument {forbidden}"
    );
  }
  assert!(
    !script.contains("x86_64:amd64v2|x86_64:amd64|x86_64:amd64v4"),
    "independent rebuild execution must not treat every x86-64 CPU level as supported based only on uname"
  );
  let selector_position = script
    .find("GITHUB_OUTPUT='' bash")
    .expect("independent rebuild should query the AMD64 CPU selector");
  let native_gate_position = script
    .find("if [[ \"${native}\" == \"true\" ]]")
    .expect("independent rebuild should gate native execution");
  let version_execution_position = script
    .find("version_output=\"$(docker run --rm --entrypoint")
    .expect("independent rebuild should retain native --version execution");
  assert!(
    selector_position < native_gate_position && native_gate_position < version_execution_position,
    "independent rebuild must query CPU support and gate native --version execution in order"
  );
}

#[test]
fn docker_buildx_setup_prepulls_buildkit_image_with_retry() {
  let workflow = workflow_text();
  let script = docker_pull_retry_script_text();
  let setup_marker = "\n      - name: Setup Docker Buildx\n        uses: docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # 4.2.0";
  let prepull_step_name = "name: Pre-pull Docker BuildKit image";
  let prepull_command = "tests/scripts/retry-docker-pull.sh \"${OXIBELT_BUILDKIT_IMAGE}\"";
  let pinned_image = "OXIBELT_BUILDKIT_IMAGE: moby/buildkit:buildx-stable-1@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec";
  let pinned_driver = "driver-opts: image=${{ env.OXIBELT_BUILDKIT_IMAGE }}";
  let setup_count = workflow.matches(setup_marker).count();

  assert_eq!(
    setup_count, 10,
    "workflow should keep pre-pull coverage aligned with every Buildx setup"
  );
  assert_eq!(
    workflow.matches(prepull_step_name).count(),
    setup_count,
    "each Buildx setup should have one BuildKit pre-pull step"
  );
  assert_eq!(
    workflow.matches(prepull_command).count(),
    setup_count,
    "each BuildKit pre-pull step should use the shared retry helper"
  );
  assert!(
    workflow.contains(pinned_image),
    "BuildKit must be pinned to the reviewed multi-architecture index digest"
  );
  assert_eq!(
    workflow.matches(pinned_driver).count(),
    setup_count,
    "each Buildx builder should use the digest-pinned BuildKit driver"
  );
  assert!(
    script.contains("retry_command 3 docker pull \"${image}\""),
    "BuildKit pre-pull helper should retry Docker Hub pulls"
  );

  let mut search_start = 0;
  while let Some(relative_position) = workflow[search_start..].find(setup_marker) {
    let setup_position = search_start + relative_position;
    let previous_step_start = workflow[..setup_position]
      .rfind("\n      - name: ")
      .expect("Buildx setup should have a previous workflow step");
    let previous_step = &workflow[previous_step_start..setup_position];
    assert!(
      previous_step.contains(prepull_step_name) && previous_step.contains(prepull_command),
      "Buildx setup at byte offset {setup_position} should be immediately preceded by the BuildKit pre-pull step"
    );
    search_start = setup_position + setup_marker.len();
  }
}

#[test]
fn docker_retry_helpers_preserve_failed_command_status() {
  let repo = repo_root();
  let temp_dir = tempfile::Builder::new()
    .prefix("oxibelt-docker-retry-")
    .tempdir()
    .expect("temporary directory should be creatable");
  let bin_dir = temp_dir.path().join("bin");
  write_executable(
    &bin_dir.join("docker"),
    "#!/usr/bin/env bash\nprintf 'fake docker called: %s\\n' \"$*\" >&2\nexit 42\n",
  );
  write_executable(
    &bin_dir.join("sleep"),
    "#!/usr/bin/env bash\nprintf 'fake sleep skipped: %s\\n' \"$*\" >&2\nexit 0\n",
  );
  let original_path = std::env::var_os("PATH").unwrap_or_default();
  let shimmed_path = format!("{}:{}", bin_dir.display(), original_path.to_string_lossy());
  let cases = [
    (
      "BuildKit pre-pull helper",
      repo.join("tests/scripts/retry-docker-pull.sh"),
      vec!["synthetic/image:fail".to_owned()],
    ),
    (
      "performance probe image helper",
      repo.join("tests/scripts/build-performance-probe-image-artifact.sh"),
      vec![
        "linux/amd64".to_owned(),
        temp_dir
          .path()
          .join("performance-probe-output")
          .display()
          .to_string(),
      ],
    ),
    (
      "Docker integration helper image helper",
      repo.join("tests/scripts/build-docker-integration-helper-images-artifact.sh"),
      vec![
        "linux/amd64".to_owned(),
        temp_dir
          .path()
          .join("integration-helper-output")
          .display()
          .to_string(),
      ],
    ),
  ];

  for (label, script, args) in cases {
    let output = Command::new("bash")
      .arg(&script)
      .args(&args)
      .current_dir(&repo)
      .env("PATH", &shimmed_path)
      .output()
      .unwrap_or_else(|error| panic!("{label} should execute: {error}"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
      output.status.code(),
      Some(42),
      "{label} should propagate failed docker status: stderr={stderr}"
    );
    assert!(
      stderr.contains("Command failed with status 42"),
      "{label} should log the real failed docker status: stderr={stderr}"
    );
    assert!(
      !stderr.contains("Command failed with status 0"),
      "{label} should not mask failed docker status as success: stderr={stderr}"
    );
  }
}

#[test]
fn amd64_comparator_image_job_builds_cpu_level_artifacts() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let comparator_job = jobs
    .get("docker-alpine-comparator-musl-image-amd64")
    .expect("workflow should define the AMD64 comparator image job");
  let script = comparator_build_script_text();
  let nginx_dockerfile = comparator_dockerfile_text("nginx");
  let caddy_dockerfile = comparator_dockerfile_text("caddy");
  let openresty_dockerfile = comparator_dockerfile_text("openresty");

  assert_eq!(
    comparator_job.needs,
    expected_needs(&["pr-non-benchmark-summary"]),
    "comparator image builds should wait for complete non-benchmark validation"
  );
  assert!(
        workflow.contains("name: Docker comparator image (Alpine musl, amd64, ${{ matrix.comparator }}, ${{ matrix.target_cpu }})"),
        "comparator image job should expose the comparator and target CPU in the job name"
    );
  for (comparator, target_cpu, artifact_name, image_tar) in [
    (
      "nginx",
      "x86-64-v2",
      "oxibelt-performance-nginx-x86-64-v2-image",
      "oxibelt-performance-nginx-x86-64-v2.tar",
    ),
    (
      "nginx",
      "x86-64-v3",
      "oxibelt-performance-nginx-x86-64-v3-image",
      "oxibelt-performance-nginx-x86-64-v3.tar",
    ),
    (
      "caddy",
      "x86-64-v2",
      "oxibelt-performance-caddy-x86-64-v2-image",
      "oxibelt-performance-caddy-x86-64-v2.tar",
    ),
    (
      "caddy",
      "x86-64-v3",
      "oxibelt-performance-caddy-x86-64-v3-image",
      "oxibelt-performance-caddy-x86-64-v3.tar",
    ),
    (
      "openresty",
      "x86-64-v2",
      "oxibelt-performance-openresty-x86-64-v2-image",
      "oxibelt-performance-openresty-x86-64-v2.tar",
    ),
    (
      "openresty",
      "x86-64-v3",
      "oxibelt-performance-openresty-x86-64-v3-image",
      "oxibelt-performance-openresty-x86-64-v3.tar",
    ),
  ] {
    assert!(
      workflow.contains(&format!("comparator: {comparator}")),
      "comparator image matrix should include {comparator}"
    );
    assert!(
      workflow.contains(&format!("target_cpu: {target_cpu}")),
      "comparator image matrix should include {target_cpu}"
    );
    assert!(
      workflow.contains(&format!("artifact_name: {artifact_name}")),
      "comparator image matrix should upload {artifact_name}"
    );
    assert!(
      workflow.contains(&format!("image_tar: {image_tar}")),
      "comparator image matrix should name {image_tar}"
    );
  }
  assert!(
    workflow.contains("tests/scripts/build-performance-comparator-image-artifact.sh"),
    "workflow should use the comparator image artifact builder"
  );
  assert!(
    script.contains("image_tag=\"oxibelt/performance-${comparator}:alpine-${target_cpu}\"")
      && script.contains(
        "image_tar=\"${output_dir%/}/oxibelt-performance-${comparator}-${target_cpu}.tar\""
      ),
    "comparator build script should produce deterministic tags and tar names"
  );
  assert!(
    nginx_dockerfile.contains("ARG NGINX_VERSION=1.31.3")
      && nginx_dockerfile.contains(
        "ARG NGINX_SHA256=a7657c50811c2d92d9895395e8b873ef60398142c4db21eb647811c38f6dd525"
      )
      && script.contains("--build-arg \"NGINX_VERSION=1.31.3\"")
      && nginx_dockerfile.contains("ARG NGINX_RUNTIME_IMAGE=alpine:3.24")
      && nginx_dockerfile.contains("FROM alpine:3.24 AS builder")
      && nginx_dockerfile.contains("sha256sum -c -")
      && nginx_dockerfile.contains("--with-http_v3_module")
      && nginx_dockerfile
        .contains(r#"org.oxibelt.performance.amd64_target_cpu="${NGINX_TARGET_CPU}""#),
    "nginx comparator image should pin and verify mainline nginx, build HTTP/3 on Alpine 3.24, and record the target CPU metadata"
  );
  let expected_nginx_cc_opt = r#"--with-cc-opt="-O2 -pipe \
        -fPIE -pie \
        -fstack-protector-strong \
        -fstack-clash-protection \
        -fcf-protection=full \
        -fvisibility=hidden \
        -U_FORTIFY_SOURCE \
        -D_FORTIFY_SOURCE=3 \
        -D_GLIBCXX_ASSERTIONS \
        -flto=auto \
        -ftrapv \
        -Wall -Wextra \
        -Wformat -Wformat-security -Werror=format-security""#;
  assert!(
    nginx_dockerfile.contains(expected_nginx_cc_opt),
    "nginx comparator image should use the expected GCC compilation options"
  );
  assert!(
    !nginx_dockerfile.contains("-fstack-protector-explicit"),
    "nginx comparator image should not weaken stack protection with explicit-only mode"
  );
  for flag in ["-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack", "-pie"] {
    assert!(
      nginx_dockerfile.contains(flag),
      "nginx comparator image should include GCC hardening flag {flag}"
    );
  }
  assert!(
    caddy_dockerfile.contains("ARG CADDY_VERSION=2.11.4")
      && caddy_dockerfile.contains("FROM caddy:${CADDY_VERSION}-builder-alpine AS builder")
      && caddy_dockerfile.contains("export GOAMD64=v2")
      && caddy_dockerfile.contains("export GOAMD64=v3"),
    "Caddy comparator image should pin Caddy and map OxiBelt target CPUs to GOAMD64 levels"
  );
  assert!(
    openresty_dockerfile.contains("ARG OPENRESTY_VERSION=1.31.1.1")
      && openresty_dockerfile.contains("ARG OPENRESTY_IMAGE_VERSION=2")
      && script.contains("--build-arg \"OPENRESTY_IMAGE_VERSION=2\"")
      && openresty_dockerfile.contains(
        "FROM openresty/openresty:${OPENRESTY_VERSION}-${OPENRESTY_IMAGE_VERSION}-alpine"
      )
      && openresty_dockerfile
        .contains(r#"org.oxibelt.performance.amd64_target_cpu="${OPENRESTY_TARGET_CPU}""#),
    "OpenResty comparator image should pin OpenResty, wrap the official Alpine image, and record target CPU metadata"
  );
}

#[test]
fn docker_performance_probe_image_job_builds_reusable_artifact() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let probe_job = jobs
    .get("docker-performance-probe-image")
    .expect("workflow should define the performance probe image job");
  let script = performance_probe_build_script_text();

  assert_eq!(
    probe_job.needs,
    expected_needs(&["pr-non-benchmark-summary"]),
    "performance probe image builds should wait for complete non-benchmark validation"
  );
  assert!(
    workflow.contains("name: Docker performance probe image"),
    "probe image job should have a clear display name"
  );
  assert!(
    workflow.contains("tests/scripts/build-performance-probe-image-artifact.sh")
      && workflow.contains("name: oxibelt-performance-probe-image")
      && workflow.contains("oxibelt-performance-probe.tar"),
    "probe image job should build and upload a reusable tar artifact"
  );
  assert!(
    script.contains("image_tag=\"oxibelt/perf-probe:ci\"")
      && script.contains("image_tar=\"${output_dir%/}/oxibelt-performance-probe.tar\""),
    "probe build script should produce a deterministic tag and tar name"
  );
  assert!(
    script.contains("retry_command 3 docker pull --platform \"${platform}\"")
      && script.contains("retry_command 3 docker buildx build"),
    "probe build script should retry Docker Hub pulls and the BuildKit image build"
  );
}

#[test]
fn docker_external_benchmark_image_job_builds_reusable_artifact() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let external_job = jobs
    .get("docker-external-benchmark-image")
    .expect("workflow should define the external benchmark image job");
  let script = external_benchmark_build_script_text();
  let dockerfile = external_benchmark_dockerfile_text();

  assert_eq!(
    external_job.needs,
    expected_needs(&["pr-non-benchmark-summary"]),
    "external benchmark image builds should wait for complete non-benchmark validation"
  );
  assert!(
    workflow.contains("name: Docker external benchmark image"),
    "external benchmark image job should have a clear display name"
  );
  assert!(
    workflow.contains("tests/scripts/build-external-benchmark-image-artifact.sh")
      && workflow.contains("name: oxibelt-external-benchmark-image")
      && workflow.contains("oxibelt-external-benchmark-image.tar"),
    "external benchmark image job should build and upload a reusable tar artifact"
  );
  assert!(
    script.contains("image_tag=\"oxibelt/external-benchmarks:ci\"")
      && script.contains("image_tar=\"${output_dir%/}/oxibelt-external-benchmark-image.tar\""),
    "external benchmark build script should produce a deterministic tag and tar name"
  );
  for expected in [
    "h2load --version",
    "h2load --help | grep -q -- '--h3'",
    "ldd \"$(command -v h2load)\" | grep -q libnghttp3",
    "ldd \"$(command -v h2load)\" | grep -q libngtcp2",
    "oha --version",
    "wrk --version",
  ] {
    assert!(
      dockerfile.contains(expected),
      "external benchmark Dockerfile should self-check {expected}"
    );
  }
  assert!(
    dockerfile.contains("ARG OHA_VERSION=1.15.0")
      && dockerfile.contains("ARG WRK_COMMIT=a211dd5a7050b1f9e8a9870b95513060e72ac4a0")
      && dockerfile.contains(
        "ARG WRK_SHA256=172dd2788b22b210d37a68f11c91e82fdba6583d2a544f04b398a66507031229"
      )
      && dockerfile.contains("ARG NGHTTP2_VERSION=1.69.0")
      && dockerfile.contains(
        "ARG NGHTTP2_SHA256=1fb324b6ec2c56f6bde0658f4139ffd8209fa9e77ce98fd7a5f63af8d0e508ad"
      )
      && dockerfile.contains("ARG NGHTTP3_VERSION=1.17.0")
      && dockerfile.contains(
        "ARG NGHTTP3_SHA256=e8b798272b9282045cb83577dcf7bd7fcd22bb3a43aec0eb1a24f675b4cef0b8"
      )
      && dockerfile.contains("ARG NGTCP2_VERSION=1.24.0")
      && dockerfile.contains(
        "ARG NGTCP2_SHA256=7fa5ec2be0f0cbed8bc4ec89c0787dfa9d8ce678f1ed9477c52f30eb1a591207"
      )
      && dockerfile.matches("sha256sum -c -").count() == 4
      && dockerfile.contains("./configure --prefix=/opt/nghttp2 --enable-app --enable-http3")
      && dockerfile.contains("cargo install oha")
      && dockerfile.contains("nghttp2")
      && dockerfile.contains("ngtcp2")
      && dockerfile.contains("nghttp3")
      && dockerfile.contains("github.com/wg/wrk"),
    "external benchmark Dockerfile should include h2load with HTTP/3 support, oha, and wrk"
  );
}

#[test]
fn performance_summary_input_helper_copies_only_aggregate_inputs() {
  let script = performance_summary_input_script_text();
  for expected in [
    "results.json",
    "external-results.json",
    "profile-results.json",
    "iteration-status.json",
    "unsupported-cpu.json",
  ] {
    assert!(
      script.contains(expected),
      "summary input helper should allow-list {expected}"
    );
  }

  let temp_dir = tempfile::Builder::new()
    .prefix("oxibelt-summary-input-")
    .tempdir()
    .expect("temporary directory should be creatable");
  let source_dir = temp_dir.path().join("source");
  let destination_dir = temp_dir.path().join("destination");
  let run_dir = source_dir.join("x86-64-v3/run-1");

  for file_name in [
    "results.json",
    "external-results.json",
    "profile-results.json",
    "iteration-status.json",
  ] {
    write_test_file(&run_dir.join(file_name), "[]\n");
  }
  write_test_file(&source_dir.join("unsupported-cpu.json"), "{}\n");
  write_test_file(&run_dir.join("results.jsonl"), "{}\n");
  write_test_file(
    &run_dir.join("profiles/cpu/nginx-h2.perf.data.zst"),
    "raw perf data\n",
  );
  write_test_file(
    &run_dir.join("profiles/memory/nginx-h2.resource.json"),
    "{}\n",
  );
  write_test_file(&run_dir.join("external-h2load/nginx-h2.txt"), "h2load\n");
  write_test_file(&run_dir.join("logs/oxibelt.log"), "log\n");
  write_test_file(&run_dir.join("configs/oxibelt.toml"), "config\n");

  let output = Command::new("bash")
    .arg(performance_summary_input_script_path())
    .arg(&source_dir)
    .arg(&destination_dir)
    .output()
    .expect("summary input copy helper should execute");
  assert!(
    output.status.success(),
    "summary input copy helper should succeed: stderr={}",
    String::from_utf8_lossy(&output.stderr)
  );

  for expected in [
    "x86-64-v3/run-1/results.json",
    "x86-64-v3/run-1/external-results.json",
    "x86-64-v3/run-1/profile-results.json",
    "x86-64-v3/run-1/iteration-status.json",
    "unsupported-cpu.json",
  ] {
    assert!(
      destination_dir.join(expected).exists(),
      "summary helper should copy {expected}"
    );
  }
  for raw_artifact in [
    "x86-64-v3/run-1/results.jsonl",
    "x86-64-v3/run-1/profiles/cpu/nginx-h2.perf.data.zst",
    "x86-64-v3/run-1/profiles/memory/nginx-h2.resource.json",
    "x86-64-v3/run-1/external-h2load/nginx-h2.txt",
    "x86-64-v3/run-1/logs/oxibelt.log",
    "x86-64-v3/run-1/configs/oxibelt.toml",
  ] {
    assert!(
      !destination_dir.join(raw_artifact).exists(),
      "summary helper should not copy raw artifact {raw_artifact}"
    );
  }
}

#[test]
fn docker_performance_jobs_are_scheduled_and_manual_only() {
  let workflow = workflow_text();

  assert!(
    workflow.contains("push:")
      && workflow.contains("pull_request:")
      && workflow.contains("schedule:")
      && workflow.contains("cron: \"0 0 * * *\"")
      && workflow.contains("workflow_dispatch:"),
    "normal CI should keep push and pull request triggers while performance jobs use cron/manual gates"
  );
  assert!(
    PERFORMANCE_WORKFLOW_JOB_IF.contains(PERFORMANCE_WORKFLOW_EVENT_CONDITION)
      && PERFORMANCE_WORKFLOW_SUMMARY_IF.contains(PERFORMANCE_WORKFLOW_EVENT_CONDITION),
    "performance workflow assertions should use the shared schedule/manual condition"
  );

  for job_id in [
    "docker-alpine-comparator-musl-image-amd64",
    "docker-performance-probe-image",
    "docker-external-benchmark-image",
    "docker-performance",
  ] {
    let job = workflow_job_text(&workflow, job_id);
    assert!(
      job.contains(PERFORMANCE_WORKFLOW_JOB_IF),
      "{job_id} should run only on scheduled or manual workflows"
    );
  }

  let summary_job = workflow_job_text(&workflow, "docker-performance-summary");
  assert!(
    summary_job.contains(PERFORMANCE_WORKFLOW_SUMMARY_IF),
    "docker-performance-summary should preserve always() semantics only on scheduled or manual workflows"
  );

  for job_id in [
    "docker-alpine-musl-image-amd64",
    "docker-integration-proxy",
    "docker-alpine-musl-image-riscv64",
  ] {
    let job = workflow_job_text(&workflow, job_id);
    assert!(
      !job.contains(PERFORMANCE_WORKFLOW_JOB_IF),
      "{job_id} should keep running on push and pull request workflows"
    );
  }
}

#[test]
fn docker_performance_job_uses_sharded_repeated_sampling() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let performance_job = workflow
    .split_once("  docker-performance:\n")
    .and_then(|(_, rest)| rest.split_once("\n  docker-performance-summary:"))
    .map(|(job, _)| job)
    .expect("workflow should contain docker-performance before its summary job");
  let summary_input_prepare_step = performance_job
    .split_once("      - name: Prepare Docker performance summary input artifact")
    .and_then(|(_, rest)| {
      rest.split_once("\n      - name: Upload Docker performance summary input artifact")
    })
    .map(|(step, _)| step)
    .expect("docker-performance should prepare summary input before upload");
  let (_, after_selection_parallel_marker) = performance_job
    .split_once("      - parallel:\n")
    .expect("docker-performance should start artifact setup with a parallel group");
  let (artifact_selection_parallel_group, after_download_parallel_marker) =
    after_selection_parallel_marker
      .split_once("\n      - parallel:\n")
      .expect("docker-performance should have a second parallel group for artifact downloads");
  let (artifact_download_parallel_group, _) = after_download_parallel_marker
    .split_once("\n      - name: Load AMD64 v2 OxiBelt Docker image")
    .expect("docker-performance should load Docker images after parallel artifact downloads");
  let artifact_selection_parallel_start = performance_job
    .find("      - parallel:\n")
    .expect("docker-performance should define artifact selection parallel group");
  let artifact_download_parallel_start = performance_job
    .find("\n      - parallel:\n          - name: Download AMD64 v2 Docker image artifact")
    .expect("docker-performance should define artifact download parallel group");
  let artifact_load_start = performance_job
    .find("\n      - name: Load AMD64 v2 OxiBelt Docker image")
    .expect("docker-performance should load Docker images after artifact downloads");

  assert!(
    workflow.contains("performance_iterations:"),
    "workflow_dispatch should expose the Docker performance iteration count"
  );
  assert!(
    workflow.contains("performance_h2_profile:"),
    "workflow_dispatch should expose the opt-in H2 profiling toggle"
  );
  assert!(
    workflow.contains("performance_profile_label:")
      && workflow.contains("- oxibelt-h1-keepalive")
      && workflow.contains("- oxibelt-h2")
      && workflow.contains("- oxibelt-h3"),
    "workflow_dispatch should expose exact H1/H2/H3 profiling labels"
  );
  assert!(
        workflow.contains("PERFORMANCE_ITERATIONS: ${{ github.event_name == 'workflow_dispatch' && inputs['performance_iterations'] || '5' }}"),
        "docker-performance should default to five iterations outside manual dispatch"
    );
  assert!(
        workflow.contains("PERFORMANCE_H2_PROFILE: ${{ github.event_name == 'workflow_dispatch' && inputs['performance_h2_profile'] || false }}"),
        "docker-performance should keep H2 profiling disabled outside explicit manual dispatch"
    );
  assert!(
        workflow.contains("PERFORMANCE_PROFILE_LABEL: ${{ github.event_name == 'workflow_dispatch' && inputs['performance_profile_label'] || 'none' }}"),
        "docker-performance should keep exact profiling labels disabled outside manual dispatch"
    );
  let legacy_apt_flamegraph_packages = [
    "linux-tools-common",
    "linux-tools-generic",
    "zstd",
    "flamegraph",
    "heaptrack",
  ]
  .join(" ");
  assert!(
    workflow.contains("name: Install Linux perf and heap tooling for performance profiling")
      && workflow.contains("linux-tools-common")
      && workflow.contains("linux-tools-generic")
      && workflow.contains("heaptrack")
      && workflow.contains("zstd")
      && workflow.contains("41fee1f99f9276008b7cd112fca19dc3ea84ac32")
      && workflow.contains("088f82e6848a4f12a56e1e8e8170ee6761fccf12e5615cd64630f6b087c99ea7")
      && workflow.contains("74faa47a29d8df07cb06731dfd8bb94dc4c165b9d811ac6b4c9449eea2ac25d8")
      && workflow.contains("/usr/local/bin/flamegraph.pl")
      && workflow.contains("/usr/local/bin/stackcollapse-perf.pl")
      && workflow.contains("sha256sum --check --status")
      && !workflow.contains(&legacy_apt_flamegraph_packages)
      && workflow.contains("sudo sysctl kernel.perf_event_paranoid=-1"),
    "performance profiling should prepare host perf, compression, verified FlameGraph scripts, and heap tooling"
  );
  assert!(
    performance_job.contains("selected_profile_label=\"${PERFORMANCE_PROFILE_LABEL}\"")
      && performance_job.contains("selected_profile_label=\"oxibelt-h2\"")
      && performance_job.contains("none|oxibelt-h1-keepalive|oxibelt-h2|oxibelt-h3")
      && performance_job.contains("OXIBELT_PERF_PROFILE_LABEL=\"${selected_profile_label}\"")
      && performance_job.contains(r#"&& "${target_cpu}" == "x86-64-v3""#)
      && performance_job.contains(r#"&& "${iteration}" == "1""#),
    "profiling env should be scoped to one exact first x86-64-v3 smoke sample"
  );
  assert!(
    performance_job.contains("diagnostic_profile_env=()")
      && performance_job.contains(r#"if [[ "${PERFORMANCE_PROFILE}" == "smoke" ]]; then"#)
      && performance_job.contains("OXIBELT_PERF_DIAGNOSTIC_PROFILES=1")
      && performance_job.contains("OXIBELT_PERF_DIAGNOSTIC_PROFILE_MODE=cpu-memory")
      && performance_job.contains("OXIBELT_PERF_DIAGNOSTIC_FREQUENCY=49")
      && performance_job
        .contains("OXIBELT_PERF_DIAGNOSTIC_GATE_MODE=\"${OXIBELT_PERF_DIAGNOSTIC_GATE_MODE}\""),
    "smoke performance runs should enable diagnostic CPU and memory profiling artifacts separately from primary rows"
  );
  assert!(
    !workflow.contains("background:")
      && !workflow.contains("wait:")
      && !workflow.contains("wait-all:")
      && !workflow.contains("cancel:"),
    "workflow should keep service lifecycle step-control primitives out of CI gates"
  );
  assert!(
    workflow.contains("timeout-minutes: 360"),
    "docker-performance should allow repeated smoke and benchmark samples"
  );

  assert!(
    workflow.contains("serving_type:"),
    "docker-performance should define a serving-type matrix axis"
  );
  for shard in 1..=20 {
    assert!(
      workflow.contains(&format!("          - {shard}")),
      "docker-performance should include shard {shard}"
    );
  }
  for serving_type in [
    "reverse-proxy",
    "static-files",
    "oxibelt-features",
    "oxibelt-soak-stress",
    "accept-multipliers",
    "remote-signer",
    "runtime-direct-h1",
    "metrics-mode",
  ] {
    assert!(
      workflow.contains(&format!("          - {serving_type}")),
      "docker-performance should include serving type {serving_type}"
    );
  }

  assert!(
    workflow.contains("PERFORMANCE_SHARD: ${{ matrix.shard }}"),
    "docker-performance should expose the current shard to the run loop"
  );
  assert!(
    workflow.contains("PERFORMANCE_SERVING_TYPE: ${{ matrix.serving_type }}"),
    "docker-performance should expose the current serving type to the run loop"
  );
  assert!(
    workflow.contains("OXIBELT_PERF_REGRESSION_GATE_MODE: warn"),
    "docker-performance should defer noisy per-iteration regression gates to the summary job"
  );
  assert!(
    workflow.contains("performance_accepted_regression_reason"),
    "workflow_dispatch should expose an explicit accepted-regression reason input"
  );
  assert!(
    jobs
      .get("docker-performance")
      .expect("workflow should define docker-performance")
      .needs
      .contains(&"docker-alpine-comparator-musl-image-amd64".to_owned()),
    "docker-performance should wait for target-specific comparator images"
  );
  assert!(
    jobs
      .get("docker-performance")
      .expect("workflow should define docker-performance")
      .needs
      .contains(&"docker-performance-probe-image".to_owned()),
    "docker-performance should wait for the reusable probe image"
  );
  assert!(
    jobs
      .get("docker-performance")
      .expect("workflow should define docker-performance")
      .needs
      .contains(&"docker-external-benchmark-image".to_owned()),
    "docker-performance should wait for the reusable external benchmark image"
  );
  let performance_needs = &jobs
    .get("docker-performance")
    .expect("workflow should define docker-performance")
    .needs;
  for job_id in DOCKER_INTEGRATION_JOBS {
    assert!(
      performance_needs
        .iter()
        .any(|need| need.as_str() == *job_id),
      "docker-performance should wait for {job_id}"
    );
  }
  for target_cpu in ["x86-64-v2", "x86-64-v3"] {
    assert!(
      performance_job.contains(&format!(
        "tests/scripts/select-amd64-docker-image-artifact.sh {target_cpu} --allow-unsupported"
      )),
      "docker-performance should select the {target_cpu} artifact with unsupported-runner handling"
    );
  }
  assert_eq!(
    performance_job.matches("      - parallel:\n").count(),
    2,
    "docker-performance should use focused parallel groups for selection and download setup"
  );
  assert!(
    artifact_selection_parallel_start < artifact_download_parallel_start
      && artifact_download_parallel_start < artifact_load_start,
    "docker-performance should use selection outputs only after the selection parallel group completes"
  );
  assert!(
    !artifact_selection_parallel_group.contains("steps.select-amd64-")
      && artifact_download_parallel_group.contains("steps.select-amd64-v2.outputs.supported")
      && artifact_download_parallel_group.contains("steps.select-amd64-v2.outputs.artifact_name")
      && artifact_download_parallel_group.contains("steps.select-amd64-v3.outputs.supported")
      && artifact_download_parallel_group.contains("steps.select-amd64-v3.outputs.artifact_name"),
    "download steps should consume selection outputs only in the later parallel group"
  );
  assert!(
    artifact_selection_parallel_group.contains("name: Select AMD64 v2 Docker image artifact")
      && artifact_selection_parallel_group.contains(
        "tests/scripts/select-amd64-docker-image-artifact.sh x86-64-v2 --allow-unsupported"
      )
      && artifact_selection_parallel_group.contains("name: Select AMD64 v3 Docker image artifact")
      && artifact_selection_parallel_group.contains(
        "tests/scripts/select-amd64-docker-image-artifact.sh x86-64-v3 --allow-unsupported"
      ),
    "docker-performance should select independent AMD64 artifacts in one parallel group"
  );
  assert_eq!(
    artifact_download_parallel_group
      .matches("uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # 8.0.1")
      .count(),
    10,
    "docker-performance should keep exactly ten artifact downloads in the parallel group"
  );
  for expected in [
    "name: Download AMD64 v2 Docker image artifact",
    "name: Download AMD64 v3 Docker image artifact",
    "name: Download AMD64 v2 nginx comparator image artifact",
    "name: Download AMD64 v2 Caddy comparator image artifact",
    "name: Download AMD64 v2 OpenResty comparator image artifact",
    "name: Download AMD64 v3 nginx comparator image artifact",
    "name: Download AMD64 v3 Caddy comparator image artifact",
    "name: Download AMD64 v3 OpenResty comparator image artifact",
    "name: Download performance probe image artifact",
    "name: Download external benchmark image artifact",
  ] {
    assert!(
      artifact_download_parallel_group.contains(expected),
      "docker-performance should keep {expected} inside the artifact download parallel group"
    );
  }
  assert!(
    !performance_job.contains("x86-64-v4"),
    "docker-performance should not include x86-64-v4 in its benchmark target set"
  );
  assert!(
    workflow.contains("unsupported-cpu.json"),
    "docker-performance should upload unsupported CPU markers instead of benchmark rows"
  );
  for target_cpu in ["v2", "v3"] {
    assert!(
      performance_job.contains(&format!(
        "steps.select-amd64-{target_cpu}.outputs.supported == 'true'"
      )),
      "docker-performance should only download and load supported AMD64 {target_cpu} artifacts"
    );
  }
  assert!(
    performance_job.contains("for target_cpu in x86-64-v2 x86-64-v3; do"),
    "docker-performance should run each supported AMD64 ISA target in the same matrix job"
  );
  assert!(
    performance_job.contains("OXIBELT_AMD64_TARGET_CPU=\"${target_cpu}\""),
    "docker-performance should record each AMD64 target CPU in per-run summaries"
  );
  for (comparator, target_cpu) in [
    ("nginx", "x86-64-v2"),
    ("caddy", "x86-64-v2"),
    ("openresty", "x86-64-v2"),
    ("nginx", "x86-64-v3"),
    ("caddy", "x86-64-v3"),
    ("openresty", "x86-64-v3"),
  ] {
    assert!(
      performance_job.contains(&format!(
        "oxibelt-performance-{comparator}-{target_cpu}-image"
      )),
      "docker-performance should download the {comparator} {target_cpu} comparator artifact"
    );
    assert!(
      performance_job.contains(&format!(
        "oxibelt/performance-{comparator}:alpine-{target_cpu}"
      )),
      "docker-performance should pass the {comparator} {target_cpu} image tag"
    );
  }
  assert!(
    performance_job.contains("OXIBELT_NGINX_IMAGE=\"${nginx_image_tag}\"")
      && performance_job.contains("OXIBELT_CADDY_IMAGE=\"${caddy_image_tag}\"")
      && performance_job.contains("OXIBELT_OPENRESTY_IMAGE=\"${openresty_image_tag}\"")
      && performance_job.contains("OXIBELT_PERF_PROBE_IMAGE=oxibelt/perf-probe:ci")
      && performance_job
        .contains("OXIBELT_EXTERNAL_BENCHMARK_IMAGE=oxibelt/external-benchmarks:ci")
      && performance_job.contains(
        "OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE=\"${OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE}\""
      )
      && performance_job
        .contains("OXIBELT_PERF_DIAGNOSTIC_GATE_MODE=\"${OXIBELT_PERF_DIAGNOSTIC_GATE_MODE}\"")
      && performance_job.contains("OXIBELT_NGINX_H3_MODE=required")
      && performance_job.contains("--comparators oxibelt,nginx,caddy,openresty")
      && performance_job.contains("unset OXIBELT_ACTIONS_VARS_JSON")
      && performance_job.contains("env -u OXIBELT_ACTIONS_VARS_JSON"),
    "docker-performance should compare target-specific images, reuse probe and external images, pass diagnostic gate mode, require nginx HTTP/3 in CI, include OpenResty, and keep the full vars JSON out of repository scripts"
  );
  assert!(
        performance_job.contains("name: Download performance probe image artifact")
            && performance_job.contains("docker load --input \"${RUNNER_TEMP}/oxibelt-performance-probe-image/oxibelt-performance-probe.tar\""),
        "docker-performance should download and load the prebuilt probe image before iterations"
    );
  assert!(
        performance_job.contains("name: Download external benchmark image artifact")
            && performance_job.contains("docker load --input \"${RUNNER_TEMP}/oxibelt-external-benchmark-image/oxibelt-external-benchmark-image.tar\""),
        "docker-performance should download and load the prebuilt external benchmark image before iterations"
    );
  assert!(
    workflow.contains("seq 1 \"${PERFORMANCE_ITERATIONS}\""),
    "docker-performance should loop over the configured iteration count"
  );
  assert!(
    workflow.contains("failed_iterations=()"),
    "docker-performance should aggregate failed iterations instead of stopping early"
  );
  assert!(
    workflow.contains("|| status=$?"),
    "docker-performance should record iteration failures and continue the shard"
  );
  assert!(
    workflow.contains("failed_iterations+=(\"${target_cpu}:${iteration}:${status}\")"),
    "docker-performance should keep a shard-local list of failed target iterations"
  );
  assert!(
    workflow.contains("if (( ${#failed_iterations[@]} > 0 )); then"),
    "docker-performance should summarize failed iterations after all configured iterations have run"
  );
  assert!(
    workflow.contains("run_dir=\"${target_artifact_dir}/run-${iteration}\"")
      && workflow.contains("OXIBELT_TEST_ARTIFACT_DIR=\"${run_dir}\""),
    "docker-performance should isolate artifacts by serving type, shard, target CPU, and iteration"
  );
  assert!(
    workflow.contains("iteration-status.json")
      && workflow.contains("schema_version: 1")
      && workflow.contains("target_cpu: $target_cpu")
      && workflow.contains("exit_code: $exit_code")
      && workflow.contains("diagnostic_warnings: $diagnostic_warnings"),
    "docker-performance should capture per-iteration status without relying on job-level failure"
  );
  assert!(
    workflow.contains("diagnostic_warning_count=0")
      && workflow.contains("diagnostic_warning_count=\"$(jq '[.[] | select((.diagnostic // false) == true and (.diagnostic_status // \"\") != \"pass\")] | length'")
      && workflow.contains("iteration_status=\"diagnostic_warning\"")
      && workflow.contains("completed with ${diagnostic_warning_count} diagnostic performance warning(s)"),
    "docker-performance should distinguish non-blocking diagnostic warnings from primary iteration failures"
  );
  assert!(
    workflow.contains("::warning title=Docker performance iteration failed::")
      && workflow.contains("Docker performance recorded %d failed iteration(s)")
      && !workflow.contains("Docker performance failed in %d iteration(s)"),
    "docker-performance matrix shards should warn about failed iterations and leave pass/fail ownership to the summary job"
  );
  assert!(
        workflow.contains(
            "oxibelt-docker-performance-${{ env.PERFORMANCE_PROFILE }}-${{ matrix.serving_type }}-shard-${{ matrix.shard }}"
        ),
        "docker-performance raw artifact names should include the serving type and shard"
    );
  assert!(
        workflow.contains("path: ${{ runner.temp }}/oxibelt-performance/${{ matrix.serving_type }}/shard-${{ matrix.shard }}"),
        "docker-performance should upload one grouped raw artifact per serving type and shard"
    );
  assert!(
        summary_input_prepare_step.contains("PERFORMANCE_SHARD: ${{ matrix.shard }}")
            && summary_input_prepare_step
                .contains("tests/scripts/copy-performance-summary-input-artifacts.sh")
            && summary_input_prepare_step.contains("raw_artifact_name=\"oxibelt-docker-performance-${PERFORMANCE_PROFILE}-${PERFORMANCE_SERVING_TYPE}-shard-${PERFORMANCE_SHARD}\"")
            && summary_input_prepare_step
                .contains("\"${RUNNER_TEMP}/oxibelt-performance-summary-input/${raw_artifact_name}\""),
        "docker-performance should prepare a slim summary input tree with the raw artifact directory shape"
    );
  assert!(
        workflow.contains("name: oxibelt-docker-performance-summary-input-${{ env.PERFORMANCE_PROFILE }}-${{ matrix.serving_type }}-shard-${{ matrix.shard }}")
            && workflow.contains("path: ${{ runner.temp }}/oxibelt-performance-summary-input"),
        "docker-performance should upload a separate summary input artifact for aggregation"
    );
  assert!(
    workflow.contains("--serving-type \"${PERFORMANCE_SERVING_TYPE}\""),
    "docker-performance should pass the serving-type matrix value into the performance script"
  );
}

#[test]
fn docker_performance_summary_aggregates_uploaded_artifacts() {
  let workflow = workflow_text();
  let summary_job = workflow
    .split_once("  docker-performance-summary:\n")
    .and_then(|(_, rest)| rest.split_once("\n  docker-aggressive-long-run:"))
    .map(|(job, _)| job)
    .expect("workflow should contain docker-performance-summary before aggressive long-run");
  let jobs = parse_jobs(&workflow);
  let summary = jobs
    .get("docker-performance-summary")
    .expect("workflow should define docker-performance-summary");

  assert_eq!(
    summary.needs,
    vec!["docker-performance".to_owned()],
    "docker-performance-summary should run after the performance matrix"
  );
  assert!(
    workflow.contains("name: Docker performance summary"),
    "summary job should have a clear display name"
  );
  assert!(
    summary_job.contains(PERFORMANCE_WORKFLOW_SUMMARY_IF),
    "summary job should run even when performance matrix entries fail on scheduled or manual workflows"
  );
  assert!(
    summary_job.contains(
      "pattern: oxibelt-docker-performance-summary-input-${{ env.PERFORMANCE_PROFILE }}-*"
    ) && summary_job.contains("merge-multiple: true")
      && !summary_job
        .contains("pattern: oxibelt-docker-performance-${{ env.PERFORMANCE_PROFILE }}-*"),
    "summary job should download only slim summary input artifacts and merge their preserved raw artifact directories"
  );
  assert!(
        summary_job.contains(
            "NEEDS_DOCKER_PERFORMANCE_RESULT: ${{ needs.docker-performance.result }}"
        ) && summary_job.contains("no Docker performance summary input artifacts were downloaded because docker-performance was skipped; skipping aggregation and regression gates")
            && summary_job.contains("no Docker performance summary input artifacts were downloaded after docker-performance result")
            && summary_job.contains("steps.performance-artifacts.outputs.found == 'true'")
            && summary_job.contains(
                "if: always() && steps.performance-artifacts.outputs.found == 'true'"
            ),
        "summary job should skip aggregation only when docker-performance was skipped and keep missing inputs failing otherwise"
    );
  assert!(
    workflow.contains("actions: read"),
    "summary job should have permission to inspect prior workflow artifacts"
  );
  assert!(
    workflow.contains("name: Download previous Docker performance comparison"),
    "summary job should look for the previous successful branch comparison artifact"
  );
  assert!(
    workflow.contains("baseline_report=${comparison_dir}/performance-comparison.json"),
    "summary job should expose the downloaded baseline report path"
  );
  assert!(
    workflow.contains("baseline_context=${baseline_dir}/baseline-context.json")
      && workflow.contains("same_branch:${CURRENT_REF_NAME}")
      && workflow.contains("base_branch:${PR_BASE_REF}")
      && workflow.contains("default_branch:${DEFAULT_BRANCH}"),
    "summary job should record the selected baseline source and fallback order"
  );
  assert!(
    workflow
      .contains("cargo run --quiet --locked -p oxibelt --bin oxibelt-performance-aggregate --"),
    "summary job should run the Rust aggregate binary"
  );
  assert!(
    workflow.contains("--input-dir \"${RUNNER_TEMP}/oxibelt-performance-artifacts\""),
    "summary job should pass the downloaded artifact directory"
  );
  assert!(
    workflow.contains("--output-dir \"${RUNNER_TEMP}/oxibelt-performance-comparison\""),
    "summary job should pass the comparison output directory"
  );
  assert!(
    workflow.contains("--expected-shards 20"),
    "summary job should expect the expanded 20-shard performance matrix"
  );
  assert!(
    summary_job.contains("--expected-target-cpus x86-64-v2,x86-64-v3"),
    "summary job should expect the benchmarked AMD64 target CPUs"
  );
  assert!(
    !summary_job.contains("--expected-target-cpus x86-64-v2,x86-64-v3,x86-64-v4"),
    "summary job should not require x86-64-v4 benchmark artifacts"
  );
  assert!(
    workflow.contains("--baseline-report \"${BASELINE_REPORT}\""),
    "summary job should pass the previous report to the aggregate binary when available"
  );
  assert!(
    workflow.contains("--baseline-context \"${BASELINE_CONTEXT}\""),
    "summary job should pass baseline selection metadata to the aggregate binary"
  );
  assert!(
        summary_job.contains("PERFORMANCE_ACCEPTED_REGRESSION_REASON:")
            && summary_job
                .contains("inputs['performance_accepted_regression_reason']")
            && summary_job
                .contains("aggregate_args+=(--accepted-regression-reason \"${PERFORMANCE_ACCEPTED_REGRESSION_REASON}\")"),
        "summary job should pass explicit accepted-regression reasons to the aggregate binary"
    );
  assert!(
    workflow.contains("name: Evaluate Docker performance regression gates"),
    "summary job should evaluate median regression gates after aggregation"
  );
  assert!(
    workflow.contains("gate_status=\"$(jq -r '.regression_gates.status // \"unknown\"'"),
    "summary job should read the regression gate status from the comparison JSON"
  );
  assert!(
        workflow.contains("OXIBELT_ACTIONS_VARS_JSON: ${{ toJSON(vars) }}")
            && workflow.contains("actions_var_or_default()")
            && workflow.contains("OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE=\"$(actions_var_or_default OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE warn)\"")
            && !workflow.contains("vars['OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE']")
            && workflow.matches("unset OXIBELT_ACTIONS_VARS_JSON").count() >= 2
            && workflow.contains("external_diagnostic_count=\"$(jq -r '[.external_benchmarks[]? | select((.classification // \"\") == \"benchmark_infrastructure_diagnostic\")")
            && workflow.contains("::warning title=External benchmark diagnostic::")
            && workflow.contains("external_failure_count=\"$(jq -r '[.external_benchmarks[]? | select((.classification // \"\") != \"benchmark_infrastructure_diagnostic\") | (.fail_count // 0)] | add // 0'")
            && workflow.contains("::warning title=External benchmark validation::")
            && workflow.contains("::error title=External benchmark validation gate::")
            && workflow.contains("if [[ \"${OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE}\" == \"fail\" ]]; then"),
        "summary job should split cross-comparator external diagnostics from real external benchmark failures"
    );
  assert!(
        workflow.contains("OXIBELT_PERF_DIAGNOSTIC_GATE_MODE=\"$(actions_var_or_default OXIBELT_PERF_DIAGNOSTIC_GATE_MODE warn)\"")
            && !workflow.contains("vars['OXIBELT_PERF_DIAGNOSTIC_GATE_MODE']")
            && summary_job.contains("unset OXIBELT_ACTIONS_VARS_JSON")
            && workflow.contains("profile_environment_count=\"$(jq -r '[.profiling[]? | select((.classification // \"\") == \"profiling_environment_unavailable\")")
            && workflow.contains("profiling unavailable in the current environment for ${profile_environment_count} comparator group(s): perf record failed with status 255")
            && workflow.contains("profile_failure_count=\"$(jq -r '[.profiling[]? | select((.classification // \"\") != \"profiling_environment_unavailable\") | (.fail_count // 0)] | add // 0'")
            && workflow.contains("::warning title=Docker performance diagnostic profiling::Docker performance diagnostic profiling reported ${profile_failure_count} unavailable sample(s); see performance-comparison.md")
            && workflow.contains("::error title=Docker performance diagnostic profiling gate::")
            && workflow.contains("if [[ \"${OXIBELT_PERF_DIAGNOSTIC_GATE_MODE}\" == \"fail\" ]]; then")
            && !workflow.contains(".profiling[]? | select((.fail_count // 0) > 0) | \"::warning title=Docker performance diagnostic profiling::\" + .comparator"),
        "summary job should split profiling environment diagnostics from real diagnostic profiling failures"
    );
  assert!(
        workflow.contains("missing_expected_count=\"$(jq -r '(.artifact_discovery.missing_expected_paths // []) | length'")
            && workflow.contains("::warning title=Docker performance missing expected result::")
            && workflow.contains("sample quorum decides whether this blocks"),
        "summary job should keep missing expected paths as warning evidence and let quorum decide whether they block"
    );
  assert!(
    workflow.contains("quorum_status=\"$(jq -r '.quorum.status // \"unknown\"'")
      && workflow.contains("::error title=Docker performance insufficient evidence::")
      && workflow.contains("Docker performance sample quorum failed with status"),
    "summary job should fail on insufficient evidence reported by sample quorum"
  );
  assert!(
    workflow.contains(".artifact_discovery.unsupported_cpu.count // 0"),
    "summary job should surface unsupported AMD64 v3 benchmark runner counts"
  );
  assert!(
    workflow.contains("Docker performance produced no results.json files"),
    "summary job should fail when every benchmark runner produced only unsupported CPU markers"
  );
  assert!(
    workflow.contains("Docker performance regression gates failed with status"),
    "summary job should fail when median regression gates report violations"
  );
  assert!(
        workflow.contains("cat \"${RUNNER_TEMP}/oxibelt-performance-comparison/performance-comparison.md\" >> \"${GITHUB_STEP_SUMMARY}\""),
        "summary job should append the markdown comparison to the run summary"
    );
  assert!(
    workflow.contains("performance-delta.md"),
    "summary job should append and upload the baseline delta report when it is produced"
  );
  assert!(
    workflow.contains("name: oxibelt-docker-performance-${{ env.PERFORMANCE_PROFILE }}-comparison"),
    "summary job should upload a profile-scoped comparison artifact"
  );
}

#[test]
fn docker_aggressive_long_run_is_scheduled_and_manual_only() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let long_run = jobs
    .get("docker-aggressive-long-run")
    .expect("workflow should define docker-aggressive-long-run");

  assert!(
    workflow.contains("schedule:") && workflow.contains("cron: \"0 0 * * *\""),
    "workflow should schedule the aggressive long-run at 00:00 UTC"
  );
  for input in [
    "aggressive_long_run:",
    "aggressive_long_run_seconds:",
    "aggressive_long_run_concurrency:",
  ] {
    assert!(
      workflow.contains(input),
      "workflow_dispatch should expose {input}"
    );
  }
  assert_eq!(
    long_run.needs,
    vec!["docker-performance".to_owned()],
    "aggressive long-run should start after the Docker performance matrix"
  );
  assert!(
        workflow.contains("if: needs.docker-performance.result == 'success' && (github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs['aggressive_long_run']))"),
        "aggressive long-run should run only after successful Docker performance on schedule or explicit manual dispatch"
    );
  assert!(
    workflow.contains("timeout-minutes: 360"),
    "aggressive long-run should fit within GitHub-hosted runner limits"
  );
  assert!(
        workflow.contains("AGGRESSIVE_LONG_RUN_SECONDS: ${{ github.event_name == 'workflow_dispatch' && inputs['aggressive_long_run_seconds'] || '18000' }}"),
        "aggressive long-run should default to a five-hour scheduled soak"
    );
  assert!(
    workflow.contains("OXIBELT_PERF_OXIBELT_AGGRESSIVE_SCENARIO: baseline-aggressive-long-run"),
    "aggressive long-run should use the connect-stable OxiBelt fixture"
  );
  assert!(
    workflow.contains("tests/scripts/select-amd64-docker-image-artifact.sh x86-64-v3"),
    "aggressive long-run should force the x86-64-v3 image artifact"
  );
  assert!(
    workflow.contains("manually rerun this job to get a different runner"),
    "aggressive long-run should fail loudly and ask for a rerun when v3 is unavailable"
  );
  assert!(
    workflow
      .contains("OXIBELT_AMD64_TARGET_CPU: ${{ steps.select-amd64-image.outputs.target_cpu }}"),
    "aggressive long-run should record the AMD64 target CPU in its summary"
  );
  assert!(
    workflow.contains("--serving-type oxibelt-aggressive-long-run"),
    "aggressive long-run should call the dedicated performance serving type"
  );
  assert!(
    workflow.contains(
      "cat \"${RUNNER_TEMP}/oxibelt-aggressive-long-run/summary.md\" >> \"${GITHUB_STEP_SUMMARY}\""
    ),
    "aggressive long-run should append its run summary to the GitHub step summary"
  );
  assert!(
    workflow.contains("name: oxibelt-docker-aggressive-long-run-${{ github.run_id }}"),
    "aggressive long-run should upload a dedicated artifact"
  );
  assert!(
    !workflow.contains("          - oxibelt-aggressive-long-run"),
    "aggressive long-run should not be part of the default docker-performance matrix"
  );
}
