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

const PRIMARY_RUST_GATE_NEEDS: &[&str] = &[
  "test",
  "rust-advisory-checks",
  "check-riscv64-cross",
  "fuzz-smoke",
  "unsafe-validation",
];

const CHECK_WORKFLOW_ENTRY_JOBS: &[&str] = &[
  "source-structure",
  "test",
  "rust-advisory-checks",
  "fuzz-smoke",
  "unsafe-validation",
  "check-riscv64-cross",
];
const DEPENDABOT_ACTOR_CONDITION: &str = "github.actor != 'dependabot[bot]'";

const PERFORMANCE_WORKFLOW_EVENT_CONDITION: &str =
  "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'";
const PERFORMANCE_WORKFLOW_JOB_IF: &str =
  "if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'";
const PERFORMANCE_WORKFLOW_SUMMARY_IF: &str =
  "if: always() && (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')";

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

fn release_image_arch_workflow_text() -> String {
  fs::read_to_string(repo_root().join(".github/workflows/release-image-arch.yml"))
    .expect("release image architecture workflow should be readable")
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
    "ARG RUST_BUILDER_IMAGE=rust:1.97.0-trixie",
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
    "rust_builder_image=\"rust:${rust_toolchain_version}-trixie\"",
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
fn alpine_dockerfile_records_release_ref_name_label() {
  let dockerfile = dockerfile_text();
  let script = docker_image_artifact_build_script_text();

  assert!(
    dockerfile.contains("ARG OXIBELT_RUNTIME_IMAGE=alpine:3.24")
      && dockerfile.contains("ARG OXIBELT_VERSION=0.0.0")
      && dockerfile.contains("ARG OXIBELT_REF_NAME=0.0.0")
      && dockerfile.contains("ARG OXIBELT_REF_NAME")
      && dockerfile.contains("org.opencontainers.image.ref.name=\"${OXIBELT_REF_NAME}\""),
    "source/ops/Dockerfile.alpine should default direct image builds to 0.0.0 and expose the validated release tag as an OCI ref.name label"
  );
  for expected in [
    "OXIBELT_DOCKER_IMAGE_VERSION",
    "OXIBELT_DOCKER_IMAGE_REVISION",
    "OXIBELT_DOCKER_IMAGE_CREATED",
    "OXIBELT_DOCKER_IMAGE_SOURCE",
    "OXIBELT_DOCKER_IMAGE_REF_NAME",
    "--metadata-file \"${build_metadata_tmp}\"",
    "--build-arg \"OXIBELT_NODE_IMAGE=${node_builder_image}\"",
    "--build-arg \"OXIBELT_RUNTIME_IMAGE=${runtime_image}\"",
    "--build-arg \"OXIBELT_REF_NAME=${oxibelt_ref_name}\"",
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
  assert!(
    workflow.contains("tests/scripts/check-rust-module-size.sh"),
    "source-structure should keep running Rust module size checks"
  );
  assert!(
    workflow.contains("bash tests/scripts/check-cargo-package-boundaries.sh"),
    "source-structure should enforce the data-plane Cargo package boundary"
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
    "corepack prepare pnpm@11.13.1 --activate",
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
  let mut security_relevant_jobs = vec![
    "test",
    "rust-advisory-checks",
    "check-riscv64-cross",
    "unsafe-validation",
    "generate-test-matrices",
    "linux-target-builds",
    "docker-alpine-musl-image-amd64",
    "docker-alpine-musl-kubernetes-role-image-amd64",
    "docker-alpine-comparator-musl-image-amd64",
    "docker-performance-probe-image",
    "docker-external-benchmark-image",
    "docker-integration-helper-images",
    "admin-mutation-postgres",
    "admin-operation-postgres",
    "kubernetes-immutable-rollout",
    "kubernetes-pod-lifecycle",
    "kubernetes-network-policy",
    "kubernetes-current-compatibility",
    "docker-alpine-musl-image-other",
    "docker-alpine-musl-image-riscv64",
    "docker-image-trivy-scan",
    "docker-image-dependency-snapshot",
    "remote-signer-dos-docker",
    "browser-webdriver",
    "docker-performance",
    "docker-performance-summary",
    "docker-aggressive-long-run",
  ];
  security_relevant_jobs.extend(DOCKER_INTEGRATION_JOBS.iter().copied());

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
fn unsafe_validation_runs_pinned_miri_and_sanitizers_as_a_primary_gate() {
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
    "name: Unsafe validation (${{ matrix.check }})",
    "runs-on: ubuntu-26.04",
    "contents: read",
    "fail-fast: false",
    "- miri",
    "- address",
    "- thread",
    "nightly-2026-07-16",
    "rustup component add miri --toolchain nightly-2026-07-16",
    "cargo +nightly-2026-07-16 miri test -p oxibelt-unsafe-harness --lib miri_contracts --locked",
    "RUSTFLAGS: -Zsanitizer=address",
    "ASAN_OPTIONS: detect_leaks=1:halt_on_error=1",
    "-Zbuild-std test --target x86_64-unknown-linux-gnu -p oxibelt-unsafe-harness --lib syscall_ --locked",
    "RUSTFLAGS: -Zsanitizer=thread",
    "TSAN_OPTIONS: halt_on_error=1",
    "--lib concurrent_tcp_info_reads_use_borrowed_fd_without_races --locked",
  ] {
    assert!(
      job_text.contains(expected),
      "unsafe-validation should include {expected}"
    );
  }
  assert!(
    !job_text.contains("continue-on-error"),
    "unsafe-validation must not soften Miri or sanitizer failures"
  );
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
    "name: Rust advisory checks",
    "runs-on: ubuntu-26.04",
    "contents: read",
    "name: Install Rust toolchain",
    "rustup toolchain install 1.97.0 --profile minimal",
    "rustup default 1.97.0",
    "name: Install Rust advisory tools",
    "cargo install cargo-audit --locked",
    "cargo install cargo-deny --locked",
    "name: Cargo audit",
    "run: cargo audit",
    "name: Cargo deny advisories",
    "run: cargo deny check advisories",
  ] {
    assert!(
      advisory_job_text.contains(expected),
      "Rust advisory check job should include {expected}"
    );
  }

  for forbidden in [
    "name: Install Rust advisory tools",
    "run: cargo audit",
    "run: cargo deny check advisories",
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
    .find("name: Install Rust advisory tools")
    .expect("advisory job should install advisory tools");
  let cargo_audit = advisory_job_text
    .find("name: Cargo audit")
    .expect("advisory job should run cargo audit");
  let cargo_deny = advisory_job_text
    .find("name: Cargo deny advisories")
    .expect("advisory job should run cargo deny advisories");

  assert!(
    install_rust < install_advisory && install_advisory < cargo_audit && cargo_audit < cargo_deny,
    "advisory checks should run after Rust toolchain setup inside their independent job"
  );
}

#[test]
fn rust_advisory_checks_gate_downstream_build_jobs() {
  let jobs = parse_jobs(&workflow_text());

  for job_id in [
    "generate-test-matrices",
    "linux-target-builds",
    "docker-alpine-musl-image-amd64",
    "docker-alpine-musl-kubernetes-role-image-amd64",
    "docker-alpine-comparator-musl-image-amd64",
    "docker-performance-probe-image",
    "docker-external-benchmark-image",
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
  let role_image_job =
    workflow_job_text(&workflow, "docker-alpine-musl-kubernetes-role-image-amd64");
  let job = jobs
    .get("kubernetes-immutable-rollout")
    .expect("workflow should define the Kubernetes immutable rollout job");
  let job_text = workflow_job_text(&workflow, "kubernetes-immutable-rollout");
  let script = kubernetes_immutable_rollout_script_text();

  assert_eq!(
    job.needs,
    vec!["docker-alpine-musl-kubernetes-role-image-amd64".to_owned()],
    "the Kubernetes rollout job should consume distinct AMD64 data-plane and controller artifacts"
  );
  for expected in [
    "name: Docker Kubernetes role image (Alpine musl, amd64, ${{ matrix.role }})",
    "role: dataplane",
    "artifact_prefix: oxibelt-dataplane",
    "role: dataplane-strict",
    "artifact_prefix: oxibelt-dataplane-strict",
    "name: Validate strict data-plane image inventory",
    "if: matrix.role == 'dataplane-strict'",
    "tests/scripts/validate-strict-dataplane-image.py",
    "role: controller",
    "artifact_prefix: oxibelt-gateway-controller",
    "tests/scripts/build-docker-image-artifact.sh",
    "\"${{ matrix.role }}\"",
    "name: ${{ matrix.artifact_prefix }}-alpine-musl-amd64-image",
  ] {
    assert!(
      role_image_job.contains(expected),
      "Kubernetes role-image CI job should include {expected}"
    );
  }
  for expected in [
    "name: Kubernetes immutable Gateway rollout",
    "runs-on: ubuntu-26.04",
    "actions: read",
    "contents: read",
    "azure/setup-helm@9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310 # v5.0.1",
    "version: v3.16.4",
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
    "version: v0.31.0",
    "kubectl_version: v1.31.14",
    "install_only: true",
    "name: oxibelt-dataplane-alpine-musl-amd64-image",
    "name: oxibelt-gateway-controller-alpine-musl-amd64-image",
    "docker load --input \"${RUNNER_TEMP}/oxibelt-dataplane-image/oxibelt-dataplane-alpine-musl-amd64.tar\"",
    "docker load --input \"${RUNNER_TEMP}/oxibelt-gateway-controller-image/oxibelt-gateway-controller-alpine-musl-amd64.tar\"",
    "OXIBELT_DATAPLANE_DOCKER_IMAGE: oxibelt-dataplane:alpine-musl-amd64",
    "OXIBELT_GATEWAY_CONTROLLER_DOCKER_IMAGE: oxibelt-gateway-controller:alpine-musl-amd64",
    "tests/scripts/run-kubernetes-immutable-rollout.sh",
    "timeout-minutes: 70",
  ] {
    assert!(
      job_text.contains(expected),
      "Kubernetes immutable rollout CI job should include {expected}"
    );
  }

  for expected in [
    "gateway_api_version=\"v1.6.1\"",
    "gateway_api_commit=\"8bb74df00e56ec8f944d48c25e6c1c9c2f6848e3\"",
    "gateway_api_url=\"https://github.com/kubernetes-sigs/gateway-api/releases/download/${gateway_api_version}/standard-install.yaml\"",
    "gateway_api_sha256=\"24d931f22abd8e40c973264319ead7cfa09d0fb7716b7ab1ee2ff174cb063a73\"",
    "kindest/node:v1.31.14@sha256:6f86cf509dbb42767b6e79debc3f2c32e4ee01386f0489b3b2be24b0a55aac2b",
    "sha256sum --check --status",
    "CI event values are untrusted input",
    "OXIBELT_KUBERNETES_ROLLOUT_TIMEOUT_SECONDS must be a decimal value from 60 through 900",
    "dataplane-image-values.yaml",
    "controller-image-values.yaml",
    "kind create cluster",
    "kind load docker-image",
    "gateway-api-conformance-values.yaml",
    "run_gateway_api_l4_conformance",
    "-conformance-profiles=GATEWAY-TCP,GATEWAY-UDP",
    "-skip-provisional-tests=false",
    "GOTOOLCHAIN=auto go test -c",
    "docker exec",
    "implementation_version=\"$(git -C \"${repo_root}\" rev-parse --verify 'HEAD^{commit}')\"",
    "-version=\"${implementation_version}\"",
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
    "logs \"deployment/${controller_release}\"",
    "--all-containers=true --prefix --previous --tail=200",
    "logs -l 'oxibelt.dev/test=stale-config'",
  ] {
    assert!(
      script.contains(expected),
      "Kubernetes immutable rollout script should preserve {expected}"
    );
  }
  assert!(
    !script.contains("experimental-install.yaml"),
    "the Kubernetes v1.31 rollout must not install experimental CRDs that require newer CEL libraries"
  );
  assert!(
    !script.contains("-skip-tests="),
    "the Gateway API TCP/UDP profile run must not hide incompatible conformance cases"
  );
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
    "admin_tls_rejection_observed \"${pod}\" \"${tls_failures_before}\"",
    "Admin listener did not recover after rejecting a client without a certificate",
  ] {
    assert!(
      verify.contains(expected),
      "Admin mTLS proof should preserve {expected}"
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
  assert_eq!(
    stop_positions.len(),
    3,
    "each Admin mTLS phase should stop and reap its own port-forward"
  );
  assert!(
    phase_positions[0] < stop_positions[0]
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
    "version: v3.16.4",
    "name: Validate Helm Pod distribution and lifecycle",
    "tests/scripts/check-helm-pod-lifecycle.sh",
    "name: Validate Helm autoscaling configuration",
    "tests/scripts/check-helm-autoscaling.sh",
    "helm/kind-action@ef37e7f390d99f746eb8b610417061a60e82a6cc # v1.14.0",
    "version: v0.31.0",
    "kubectl_version: v1.31.14",
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
    "kindest/node:v1.31.14@sha256:6f86cf509dbb42767b6e79debc3f2c32e4ee01386f0489b3b2be24b0a55aac2b",
    "OXIBELT_KUBERNETES_POD_LIFECYCLE_TIMEOUT_SECONDS must be a decimal value from 180 through 900",
    "Skipping Kubernetes Pod lifecycle test; set OXIBELT_RUN_KUBERNETES_POD_LIFECYCLE=1 to run it.",
    "'- role: worker'",
    "Kind lifecycle cluster must expose exactly three worker nodes",
    "io.x-k8s.kind.cluster",
    "has(\"node-role.kubernetes.io/control-plane\") | not",
    "topology.kubernetes.io/zone",
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
    "version: v3.16.4",
    "name: Validate Helm NetworkPolicy configuration",
    "tests/scripts/check-helm-network-policy.sh",
    "helm/kind-action@ef37e7f390d99f746eb8b610417061a60e82a6cc # v1.14.0",
    "kubectl_version: v1.31.14",
    "install_only: true",
    "MINIKUBE_VERSION: v1.38.1",
    "MINIKUBE_SHA256: 099477eaf248bcb5bcea8ce78a2898e93ac01461c35189da1848c3de82ecd22e",
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
    "--kubernetes-version=v1.31.14",
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
    vec!["test".to_owned(), "rust-advisory-checks".to_owned()],
    "current Kubernetes compatibility should wait for the primary native and advisory gates"
  );
  for expected in [
    "name: Kubernetes v1.36.1 and Helm v4.2.3 compatibility",
    "runs-on: ubuntu-26.04",
    "contents: read",
    "timeout-minutes: 15",
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
    "kubectl_version: v1.36.2",
    "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
    "kind create cluster",
    "--wait 120s",
    "kubectl --context \"${context}\" version",
    "helm lint deploy/helm/oxibelt",
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
  ] {
    assert!(
      burst.contains(expected),
      "bounded burst helper should preserve {expected}"
    );
  }

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
    DOCKER_INTEGRATION_JOBS.len() + 2,
    "each Docker integration job plus both Admin PostgreSQL durability jobs should download the helper image artifact"
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
      DOCKER_INTEGRATION_JOBS.len() + 2
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
fn build_and_release_workflows_do_not_expose_qemu_or_binfmt() {
  let workflows = [
    ("check", workflow_text()),
    ("release", release_workflow_text()),
    ("release architecture", release_image_arch_workflow_text()),
  ];

  for (name, workflow) in workflows {
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
      "docker-alpine-musl-image-other".to_owned(),
      "docker-alpine-musl-image-riscv64".to_owned(),
    ],
    "Trivy scans should wait for every OxiBelt release image artifact"
  );
  assert!(
    scan_job_text.contains("name: Docker image Trivy scan (${{ matrix.artifact_arch }})"),
    "Trivy scan job should expose the scanned artifact arch"
  );

  for (artifact_arch, artifact_name, image_tar, image_tag) in OXIBELT_IMAGE_ARTIFACTS {
    for expected in [
      format!("artifact_arch: {artifact_arch}"),
      format!("artifact_name: {artifact_name}"),
      format!("image_tar: {image_tar}"),
      format!("image_tag: {image_tag}"),
    ] {
      assert!(
        scan_job_text.contains(&expected),
        "Trivy scan matrix should include {expected}"
      );
    }
  }

  for expected in [
    "actions: read",
    "contents: read",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # 8.0.1",
    "docker load --input \"${RUNNER_TEMP}/oxibelt-image/${OXIBELT_ARTIFACT_ARCH}/${OXIBELT_IMAGE_TAR}\"",
    "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0",
    "version: v0.72.0",
    "scan-type: image",
    "image-ref: ${{ matrix.image_tag }}",
    "format: json",
    "vuln-type: os,library",
    "severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    "exit-code: \"0\"",
    "GITHUB_STEP_SUMMARY",
    "Upload Trivy vulnerability report",
  ] {
    assert!(
      scan_job_text.contains(expected),
      "Trivy scan job should include {expected}"
    );
  }
}

#[test]
fn docker_image_dependency_snapshot_submits_only_on_write_events() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let snapshot_job = jobs
    .get("docker-image-dependency-snapshot")
    .expect("workflow should define the Docker image dependency snapshot job");
  let snapshot_job_text = workflow_job_text(&workflow, "docker-image-dependency-snapshot");

  assert_eq!(
    snapshot_job.needs,
    vec![
      "docker-alpine-musl-image-amd64".to_owned(),
      "docker-alpine-musl-image-other".to_owned(),
      "docker-alpine-musl-image-riscv64".to_owned(),
    ],
    "dependency snapshots should wait for every OxiBelt release image artifact"
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
    "github.repository == 'OxiBelt/OxiBelt'",
    "github.event_name == 'push'",
    "github.event_name == 'schedule'",
    "github.event_name == 'pull_request' && github.event['pull_request']['head']['repo']['full_name'] == github.repository",
    "github.event_name == 'workflow_dispatch' && inputs['submit_dependency_snapshots']",
  ] {
    assert!(
      snapshot_job_text.contains(expected),
      "dependency snapshot job condition should include {expected}"
    );
  }
  assert!(
    !snapshot_job_text.contains("github.event_name != 'pull_request'"),
    "dependency snapshot job should not use a broad non-PR condition"
  );

  for (artifact_arch, artifact_name, image_tar, image_tag) in OXIBELT_IMAGE_ARTIFACTS {
    for expected in [
      format!("artifact_arch: {artifact_arch}"),
      format!("artifact_name: {artifact_name}"),
      format!("image_tar: {image_tar}"),
      format!("image_tag: {image_tag}"),
    ] {
      assert!(
        snapshot_job_text.contains(&expected),
        "dependency snapshot matrix should include {expected}"
      );
    }
  }

  for expected in [
    "actions: read",
    "contents: write",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # 8.0.1",
    "docker load --input \"${RUNNER_TEMP}/oxibelt-image/${OXIBELT_ARTIFACT_ARCH}/${OXIBELT_IMAGE_TAR}\"",
    "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0",
    "version: v0.72.0",
    "scan-type: image",
    "image-ref: ${{ matrix.image_tag }}",
    "format: github",
    "github-pat: ${{ secrets.GITHUB_TOKEN }}",
  ] {
    assert!(
      snapshot_job_text.contains(expected),
      "dependency snapshot job should include {expected}"
    );
  }
}

#[test]
fn release_workflows_use_reusable_arch_pipeline_with_scoped_publish_permissions() {
  let workflow = release_workflow_text();
  let arch_workflow = release_image_arch_workflow_text();
  let parsed_workflow: serde_json::Value =
    serde_saphyr::from_str(&workflow).expect("release workflow should parse as YAML");
  let parsed_arch_workflow: serde_json::Value = serde_saphyr::from_str(&arch_workflow)
    .expect("release image architecture workflow should parse as YAML");
  let jobs = parse_jobs(&workflow);
  let arch_jobs = parse_jobs(&arch_workflow);

  assert_eq!(
    jobs.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from([
      "ghcr-index-promote".to_owned(),
      "ghcr-index-attest".to_owned(),
      "ghcr-index-sbom".to_owned(),
      "ghcr-index-verify".to_owned(),
      "ghcr-manifest-publish".to_owned(),
      "release-image-arch".to_owned(),
      "validate".to_owned(),
    ]),
    "release workflow should contain only validation and the attestation-gated platform/index release chains"
  );
  assert_eq!(
    arch_jobs.keys().cloned().collect::<BTreeSet<_>>(),
    BTreeSet::from([
      "build".to_owned(),
      "attest".to_owned(),
      "promote".to_owned(),
      "publish".to_owned(),
      "scan".to_owned(),
      "verify".to_owned(),
    ]),
    "reusable architecture workflow should contain the attestation-gated platform release chain"
  );

  let validate_job = jobs
    .get("validate")
    .expect("release workflow should define validate");
  let arch_caller_job = jobs
    .get("release-image-arch")
    .expect("release workflow should define release-image-arch");
  let manifest_job = jobs
    .get("ghcr-manifest-publish")
    .expect("release workflow should define ghcr-manifest-publish");
  let index_promote_job = jobs
    .get("ghcr-index-promote")
    .expect("release workflow should define ghcr-index-promote");
  let index_sbom_job = jobs
    .get("ghcr-index-sbom")
    .expect("release workflow should define ghcr-index-sbom");
  let index_attest_job = jobs
    .get("ghcr-index-attest")
    .expect("release workflow should define ghcr-index-attest");
  let index_verify_job = jobs
    .get("ghcr-index-verify")
    .expect("release workflow should define ghcr-index-verify");
  let build_job = arch_jobs
    .get("build")
    .expect("reusable release image workflow should define build");
  let scan_job = arch_jobs
    .get("scan")
    .expect("reusable release image workflow should define scan");
  let publish_job = arch_jobs
    .get("publish")
    .expect("reusable release image workflow should define publish");
  let promote_job = arch_jobs
    .get("promote")
    .expect("reusable release image workflow should define promote");
  let attest_job = arch_jobs
    .get("attest")
    .expect("reusable release image workflow should define attest");
  let verify_job = arch_jobs
    .get("verify")
    .expect("reusable release image workflow should define verify");

  assert!(validate_job.needs.is_empty());
  assert_eq!(arch_caller_job.needs, vec!["validate".to_owned()]);
  assert_eq!(
    manifest_job.needs,
    vec!["validate".to_owned(), "release-image-arch".to_owned()]
  );
  assert!(build_job.needs.is_empty());
  assert_eq!(scan_job.needs, vec!["build".to_owned()]);
  assert_eq!(publish_job.needs, vec!["scan".to_owned()]);
  assert_eq!(attest_job.needs, vec!["publish".to_owned()]);
  assert_eq!(
    verify_job.needs,
    vec!["publish".to_owned(), "attest".to_owned()]
  );
  assert_eq!(
    promote_job.needs,
    vec!["publish".to_owned(), "verify".to_owned()]
  );
  assert_eq!(
    index_sbom_job.needs,
    vec!["validate".to_owned(), "ghcr-manifest-publish".to_owned()]
  );
  assert_eq!(
    index_attest_job.needs,
    vec![
      "validate".to_owned(),
      "ghcr-manifest-publish".to_owned(),
      "ghcr-index-sbom".to_owned()
    ]
  );
  assert_eq!(
    index_verify_job.needs,
    vec![
      "validate".to_owned(),
      "ghcr-manifest-publish".to_owned(),
      "ghcr-index-attest".to_owned()
    ]
  );
  assert_eq!(
    index_promote_job.needs,
    vec![
      "ghcr-manifest-publish".to_owned(),
      "ghcr-index-verify".to_owned()
    ]
  );

  let validate_job_text = workflow_job_text(&workflow, "validate");
  let arch_caller_job_text = workflow_job_text(&workflow, "release-image-arch");
  let manifest_job_text = workflow_job_text(&workflow, "ghcr-manifest-publish");
  let index_promote_job_text = workflow_job_text(&workflow, "ghcr-index-promote");
  let index_sbom_job_text = workflow_job_text(&workflow, "ghcr-index-sbom");
  let index_attest_job_text = workflow_job_text(&workflow, "ghcr-index-attest");
  let index_verify_job_text = workflow_job_text(&workflow, "ghcr-index-verify");
  let build_job_text = workflow_job_text(&arch_workflow, "build");
  let scan_job_text = workflow_job_text(&arch_workflow, "scan");
  let publish_job_text = workflow_job_text(&arch_workflow, "publish");
  let promote_job_text = workflow_job_text(&arch_workflow, "promote");
  let attest_job_text = workflow_job_text(&arch_workflow, "attest");
  let verify_job_text = workflow_job_text(&arch_workflow, "verify");

  let caller_matrix = &parsed_workflow["jobs"]["release-image-arch"]["strategy"]["matrix"];
  let caller_roles = caller_matrix["image_role"]
    .as_array()
    .expect("release caller should define an image_role axis")
    .iter()
    .map(|role| role.as_str().expect("image roles should be strings"))
    .collect::<BTreeSet<_>>();
  let caller_arches = caller_matrix["artifact_arch"]
    .as_array()
    .expect("release caller should define an artifact_arch axis")
    .iter()
    .map(|arch| arch.as_str().expect("artifact arches should be strings"))
    .collect::<BTreeSet<_>>();
  assert_eq!(
    caller_roles,
    BTreeSet::from([
      "controller",
      "dataplane",
      "dataplane-strict",
      "keysigner",
      "standalone",
      "tools"
    ])
  );
  assert_eq!(
    caller_arches,
    BTreeSet::from(["amd64", "amd64v2", "amd64v4", "arm64", "riscv64"])
  );

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
    "release-image-arch",
    "ghcr-manifest-publish",
    "ghcr-index-sbom",
    "ghcr-index-attest",
    "ghcr-index-verify",
    "ghcr-index-promote",
  ] {
    let includes = parsed_workflow["jobs"][job_id]["strategy"]["matrix"]["include"]
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

  assert!(
    workflow.contains("release:")
      && workflow.contains("types: [published]")
      && workflow.contains("push:")
      && workflow.contains("- \"*.*.*-build.*\"")
      && workflow.contains("workflow_dispatch:")
      && workflow.contains("15.2.0-build.4f43abcd")
      && !workflow.contains("v1.2.3")
  );
  for expected in [
    "corepack prepare pnpm@11.13.1 --activate",
    "pnpm install --frozen-lockfile",
    "pnpm exec tsc devops/sources/release_sbom.ts",
    "--ignoreConfig",
    "--module NodeNext",
    "--types node",
    "release_sbom.mjs",
    "OXIBELT_RELEASE_HELPER=\"file://${helper_root}/release_sbom.mjs\"",
    "await import(process.env.OXIBELT_RELEASE_HELPER)",
    "pnpm run versioning:release",
    "git rev-parse \"${release_ref}^{commit}\"",
    "releases must run from ${release_ref}@${tag_commit}",
    "if plan[\"schemaVersion\"] != 6:",
    "expected_roles = {",
    "release plan must contain exactly 30 unique role/architecture artifacts",
    "release plan must contain exactly 12 unique role manifests",
    "if artifact != expected_artifact:",
    "if manifests[(role, name)] != expected_manifest:",
    "image-plan.json",
    "install -D -m 0644 Cargo.toml \"${workspace_root}/Cargo.toml\"",
    "cargo metadata --locked --no-deps --format-version 1",
    "${metadata_root}/helper/release_sbom.mjs",
  ] {
    assert!(
      validate_job_text.contains(expected),
      "release validate job should include {expected}"
    );
  }

  for expected in [
    "name: Release image (${{ matrix.image_role }}/${{ matrix.artifact_arch }})",
    "uses: ./.github/workflows/release-image-arch.yml",
    "fail-fast: false",
    "artifact_arch: ${{ matrix.artifact_arch }}",
    "artifact_name: ${{ format('{0}-alpine-musl-{1}-image', matrix.artifact_prefix, matrix.artifact_arch) }}",
    "artifact_prefix: ${{ matrix.artifact_prefix }}",
    "image_role: ${{ matrix.image_role }}",
    "image: ${{ matrix.image }}",
    "release_ref: ${{ needs.validate.outputs.release_ref }}",
    "release_revision: ${{ needs.validate.outputs.revision }}",
    "release_version: ${{ needs.validate.outputs.version }}",
    "ghcr_token: ${{ secrets.GITHUB_TOKEN }}",
  ] {
    assert!(
      arch_caller_job_text.contains(expected),
      "release image matrix caller should include {expected}"
    );
  }

  for expected in [
    "workflow_call:",
    "artifact_arch:",
    "artifact_name:",
    "artifact_prefix:",
    "image_role:",
    "image:",
    "platform:",
    "runner:",
    "release_ref:",
    "release_created:",
    "release_kind:",
    "release_revision:",
    "release_version:",
    "source_url:",
    "ghcr_token:",
  ] {
    assert!(
      arch_workflow.contains(expected),
      "reusable workflow should expose input or secret {expected}"
    );
  }
  assert!(!arch_workflow.contains("github_token:"));

  for expected in [
    "actions: read",
    "contents: read",
    "Checkout release revision",
    "ref: ${{ inputs.release_revision }}",
    "Validate immutable release checkout",
    "if [[ ! \"${EXPECTED_REVISION}\" =~ ^[0-9a-f]{40}$ ]]",
    "actual_revision=\"$(git rev-parse HEAD)\"",
    "if [[ \"${actual_revision}\" != \"${EXPECTED_REVISION}\" ]]",
    "Apply release metadata",
    "tests/scripts/build-docker-image-artifact.sh",
    "Validate Docker image artifact",
    "Upload Docker image artifact",
    "-build-metadata.json",
    "io.oxibelt.image.role",
    "if plan[\"schemaVersion\"] != 6:",
    "validate-strict-dataplane-image.py",
  ] {
    assert!(
      build_job_text.contains(expected),
      "reusable build job should include {expected}"
    );
  }
  let strict_validation_position = build_job_text
    .find("tests/scripts/validate-strict-dataplane-image.py")
    .expect("reusable build job should validate strict dataplane images");
  let artifact_upload_position = build_job_text
    .find("Upload Docker image artifact")
    .expect("reusable build job should upload its validated image artifact");
  assert!(
    strict_validation_position < artifact_upload_position,
    "strict dataplane validation should run before the unprivileged build uploads its artifact"
  );
  assert!(
    !build_job_text.contains("ref: ${{ inputs.release_ref }}"),
    "reusable build checkout must not re-resolve the mutable release ref"
  );
  let build_steps = parsed_arch_workflow["jobs"]["build"]["steps"]
    .as_array()
    .expect("reusable build job should define steps");
  assert_eq!(
    build_steps[0]["name"].as_str(),
    Some("Checkout release revision")
  );
  assert_eq!(
    build_steps[1]["name"].as_str(),
    Some("Validate immutable release checkout"),
    "immutable checkout validation must run immediately after checkout"
  );
  for removed in [
    "packages: write",
    "GITHUB_TOKEN",
    "docker login ghcr.io",
    "docker push",
    "-build-inputs.json",
    "BUILDX_METADATA_PROVENANCE",
  ] {
    assert!(
      !build_job_text.contains(removed),
      "reusable build job should remain unprivileged and provenance-free: {removed}"
    );
  }

  for expected in [
    "actions: read",
    "contents: read",
    "Download Docker image artifact",
    "Load image for scanning",
    "docker load --input \"${IMAGE_TAR}\"",
    "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0",
    "version: v0.72.0",
    "scan-type: image",
    "format: json",
    "vuln-type: os,library",
    "severity: UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    "exit-code: \"0\"",
    "Generate CycloneDX platform SBOM",
    "format: cyclonedx",
    "-raw.cdx.json",
    "Validate release binaries",
    "container_id=\"$(docker create \"${IMAGE_REF}\")\"",
    "docker cp",
    "expected_machine=\"Advanced Micro Devices X86-64\"",
    "expected_machine=\"AArch64\"",
    "expected_machine=\"RISC-V\"",
    "readelf -hW \"${binary_path}\"",
    "readelf -lW \"${binary_path}\"",
    "readelf -dW \"${binary_path}\"",
    "must not request a program interpreter",
    "must not declare dynamic shared-library dependencies",
    "select(.role == $role) | .binaries[]",
    "{schemaVersion: 1, binaries: $binaries}",
    "Validate and enrich platform SBOM",
    "release_sbom.mjs\" platform",
    "--image-digest \"${image_digest}\"",
    "--artifact-arch \"${OXIBELT_ARTIFACT_ARCH}\"",
    "Upload Trivy vulnerability report",
    "Upload platform SBOM",
    "-release-sbom-${{ env.OXIBELT_ARTIFACT_ARCH }}",
  ] {
    assert!(
      scan_job_text.contains(expected),
      "reusable scan job should include {expected}"
    );
  }
  assert_eq!(
    scan_job_text.matches("version: v0.72.0").count(),
    2,
    "release workflow should run one vulnerability scan and one CycloneDX inventory scan"
  );
  assert!(
    !scan_job_text.contains("docker start") && !scan_job_text.contains("docker run"),
    "release binary validation must inspect copied files without starting target containers"
  );
  for removed in [
    "packages: read",
    "packages: write",
    "GITHUB_TOKEN",
    "docker login ghcr.io",
    "docker push",
  ] {
    assert!(
      !scan_job_text.contains(removed),
      "reusable scan job should remain registry-unprivileged: {removed}"
    );
  }

  for expected in [
    "packages: write",
    "Validate Docker image artifact for publish",
    "if plan[\"schemaVersion\"] != 6:",
    "GHCR_TOKEN: ${{ secrets.ghcr_token }}",
    "docker login ghcr.io",
    r#"jq -c --arg role "${OXIBELT_IMAGE_ROLE}" --arg arch "${OXIBELT_ARTIFACT_ARCH}" '.artifacts[] | select(.role == $role and .artifactArch == $arch)'"#,
    "expected_digest=\"$(jq -r '.\"containerimage.digest\"' \"${BUILD_METADATA}\")\"",
    "refusing to replace canonical tag",
    "docker push \"${canonical_tag}\"",
    "retry_command()",
    "local delay=5",
    "delay=$((delay * 2))",
    "retry_command 3 docker buildx imagetools inspect \"${canonical_tag}\"",
    "retry_command 3 docker buildx imagetools inspect \"${OXIBELT_GHCR_IMAGE}@${digest}\"",
    "echo \"digest=${digest}\" >> \"${GITHUB_OUTPUT}\"",
  ] {
    assert!(
      publish_job_text.contains(expected),
      "reusable publish job should include {expected}"
    );
  }
  for removed in [
    "Checkout release revision",
    "actions/checkout",
    "tests/scripts/build-docker-image-artifact.sh",
    "tests/scripts/validate-strict-dataplane-image.py",
  ] {
    assert!(!publish_job_text.contains(removed));
  }

  for expected in [
    "attestations: write",
    "id-token: write",
    "packages: read",
    "Download platform SBOM",
    "Validate immutable platform attestation subject",
    "canonical platform tag ${canonical_tag} resolved to ${resolved_digest}, expected ${DIGEST}",
    "and ([.metadata.component.properties[].name] | length == 9 and (unique | length == 9))",
    "actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1",
    "Publish signed platform provenance",
    "Publish signed platform SBOM",
    "subject-name: ${{ inputs.image }}",
    "subject-digest: ${{ needs.publish.outputs.digest }}",
    "sbom-path:",
    "push-to-registry: false",
  ] {
    assert!(
      attest_job_text.contains(expected),
      "platform attestation job should include {expected}"
    );
  }
  for removed in [
    "actions/checkout",
    "release_sbom.mjs",
    "node ",
    "packages: write",
  ] {
    assert!(
      !attest_job_text.contains(removed),
      "OIDC-bearing platform attestation job must not include {removed}"
    );
  }

  for expected in [
    "attestations: read",
    "packages: read",
    "Verify GitHub API platform attestations",
    "for attempt in 1 2 3 4",
    "local attempt delay=5",
    "delay=$((delay * 2))",
    "gh attestation verify",
    "--repo OxiBelt/OxiBelt",
    "--signer-workflow OxiBelt/OxiBelt/.github/workflows/release-image-arch.yml",
    "--signer-digest \"${RELEASE_REVISION}\"",
    "--source-digest \"${RELEASE_REVISION}\"",
    "--source-ref \"${RELEASE_REF}\"",
    "--cert-oidc-issuer https://token.actions.githubusercontent.com",
    "--deny-self-hosted-runners",
    "--limit 100",
    "--format json",
    "--predicate-type https://slsa.dev/provenance/v1",
    "--predicate-type https://cyclonedx.org/bom",
    "--workflow-path .github/workflows/release.yml",
    "release_sbom.mjs\" \"${args[@]}\"",
  ] {
    assert!(
      verify_job_text.contains(expected),
      "platform verification job should include {expected}"
    );
  }
  for removed in [
    "packages: write",
    "attestations: write",
    "id-token: write",
    "--cert-identity",
    "--bundle-from-oci",
  ] {
    assert!(
      !verify_job_text.contains(removed),
      "platform verification job must not include {removed}"
    );
  }

  for expected in [
    "packages: write",
    ".aliasGhcrTags[]",
    "docker buildx imagetools create --prefer-index=false --tag",
    "alias ${alias_tag} resolved to ${alias_digest}, expected ${DIGEST}",
  ] {
    assert!(
      promote_job_text.contains(expected),
      "platform promotion job should include {expected}"
    );
  }

  for expected in [
    "packages: write",
    "if plan[\"schemaVersion\"] != 6:",
    "def expected_artifact_tags(arch):",
    "if artifact[\"canonicalGhcrTag\"] != expected_tag or artifact[\"aliasGhcrTags\"] != expected_aliases:",
    "if manifest[\"canonicalGhcrTag\"] != canonical_tag or manifest[\"aliasGhcrTags\"] != alias_tags:",
    ".manifests[] | select(.role == $role) | .canonicalGhcrTag",
    "docker buildx imagetools create --tag",
    "refusing to replace canonical index",
    "actual_descriptors=",
    "expected_descriptors=",
    "child_descriptors=",
    "os: .platform.os",
    "architecture: .platform.architecture",
    "variant: (.platform.variant // null)",
    "canonical index ${canonical_tag} resolved to ${canonical_digest}, expected ${digest}",
    "name: ${{ matrix.artifact_prefix }}-release-index-metadata",
    "{schemaVersion: 2, role: $role, image: $image, digest: $digest, children: $children}",
  ] {
    assert!(
      manifest_job_text.contains(expected),
      "GHCR manifest publish job should include {expected}"
    );
  }

  for expected in [
    "actions: read",
    "contents: read",
    "Download release metadata",
    "Download immutable index metadata",
    "Download platform SBOMs",
    "pattern: ${{ matrix.artifact_prefix }}-release-sbom-*",
    "merge-multiple: true",
    "Validate platform SBOMs and compose index SBOM",
    "release_sbom.mjs\" index",
    "--platform-sbom \"${PLATFORM_SBOMS}/${OXIBELT_ARTIFACT_PREFIX}-release-amd64.cdx.json\"",
    "--platform-sbom \"${PLATFORM_SBOMS}/${OXIBELT_ARTIFACT_PREFIX}-release-arm64.cdx.json\"",
    "--platform-sbom \"${PLATFORM_SBOMS}/${OXIBELT_ARTIFACT_PREFIX}-release-riscv64.cdx.json\"",
    "Upload index SBOM",
    "-release-index-sbom",
  ] {
    assert!(
      index_sbom_job_text.contains(expected),
      "index SBOM job should include {expected}"
    );
  }
  for removed in [
    "packages: read",
    "packages: write",
    "attestations:",
    "id-token:",
  ] {
    assert!(
      !index_sbom_job_text.contains(removed),
      "index SBOM composition must remain unprivileged: {removed}"
    );
  }

  for expected in [
    "attestations: write",
    "id-token: write",
    "packages: read",
    "Validate immutable index attestation subject",
    ".schemaVersion == 2",
    "[.children[].artifactArch] == [\"amd64\", \"arm64\", \"riscv64\"]",
    "dependsOn: [$index[0].children[].digest | $image + \"@\" + .]",
    "release index requires exactly two canonical tags",
    "canonical index tag ${canonical_tag} resolved to ${resolved_digest}, expected ${digest}",
    "actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1",
    "Publish signed index provenance",
    "Publish signed index SBOM",
    "subject-name: ${{ matrix.image }}",
    "subject-digest: ${{ steps.identity.outputs.digest }}",
    "push-to-registry: false",
  ] {
    assert!(
      index_attest_job_text.contains(expected),
      "index attestation job should include {expected}"
    );
  }
  for removed in [
    "actions/checkout",
    "release_sbom.mjs",
    "node ",
    "packages: write",
  ] {
    assert!(
      !index_attest_job_text.contains(removed),
      "OIDC-bearing index attestation job must not include {removed}"
    );
  }

  for expected in [
    "attestations: read",
    "packages: read",
    "Verify GitHub API index attestations",
    "for attempt in 1 2 3 4",
    "gh attestation verify",
    "--signer-workflow OxiBelt/OxiBelt/.github/workflows/release.yml",
    "--signer-digest \"${RELEASE_REVISION}\"",
    "--source-digest \"${RELEASE_REVISION}\"",
    "--source-ref \"${RELEASE_REF}\"",
    "--cert-oidc-issuer https://token.actions.githubusercontent.com",
    "--deny-self-hosted-runners",
    "--limit 100",
    "--format json",
    "--predicate-type https://slsa.dev/provenance/v1",
    "--predicate-type https://cyclonedx.org/bom",
    "--workflow-path .github/workflows/release.yml",
    "release_sbom.mjs\" \"${args[@]}\"",
  ] {
    assert!(
      index_verify_job_text.contains(expected),
      "index verification job should include {expected}"
    );
  }
  for removed in [
    "packages: write",
    "attestations: write",
    "id-token: write",
    "--cert-identity",
    "--bundle-from-oci",
  ] {
    assert!(
      !index_verify_job_text.contains(removed),
      "index verification job must not include {removed}"
    );
  }

  for expected in [
    "packages: write",
    "Download immutable index metadata",
    ".schemaVersion == 2",
    ".role == $role",
    ".image == $image",
    ".digest | test(\"^sha256:[0-9a-f]{64}$\")",
    "select(.role == $role) | .aliasGhcrTags[]",
    "docker buildx imagetools create --prefer-index=true --tag",
    "alias ${alias_tag} resolved to ${alias_digest}, expected ${DIGEST}",
  ] {
    assert!(
      index_promote_job_text.contains(expected),
      "index promotion job should include {expected}"
    );
  }

  assert_eq!(
    workflow.matches("packages: write").count(),
    3,
    "main release workflow should delegate package-write only to the reusable pipeline, index publish, and index promotion"
  );
  assert_eq!(
    arch_workflow.matches("packages: write").count(),
    2,
    "reusable workflow should grant package-write only to canonical publish and alias promotion"
  );

  assert_eq!(
    parsed_workflow["jobs"]["release-image-arch"]["permissions"],
    serde_json::json!({
      "actions": "read",
      "attestations": "write",
      "contents": "read",
      "id-token": "write",
      "packages": "write"
    }),
    "the reusable caller should expose only the permission ceiling required by its inner jobs"
  );
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
      parsed_workflow["jobs"][job_id]["permissions"], expected,
      "main release job {job_id} should keep exact least-privilege permissions"
    );
  }
  for (job_id, expected) in [
    (
      "build",
      serde_json::json!({"actions": "read", "contents": "read"}),
    ),
    (
      "scan",
      serde_json::json!({"actions": "read", "contents": "read"}),
    ),
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
      parsed_arch_workflow["jobs"][job_id]["permissions"], expected,
      "reusable release job {job_id} should keep exact least-privilege permissions"
    );
  }

  for (job_name, job_text) in [
    ("platform build", &build_job_text),
    ("platform scan", &scan_job_text),
  ] {
    assert!(
      !job_text.contains("packages: write"),
      "{job_name} must not receive package-write permission"
    );
  }
  for (job_name, job_text) in [
    ("platform publish", &publish_job_text),
    ("platform promote", &promote_job_text),
    ("index publish", &manifest_job_text),
    ("index promote", &index_promote_job_text),
  ] {
    assert!(
      job_text.contains("packages: write"),
      "{job_name} should be an isolated package-writing boundary"
    );
  }

  assert_eq!(
    workflow
      .matches("actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1")
      .count()
      + arch_workflow
        .matches("actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1")
        .count(),
    4,
    "the two workflow templates should publish provenance and SBOM attestations for platform and index matrices"
  );
  assert_eq!(
    workflow.matches("push-to-registry: false").count()
      + arch_workflow.matches("push-to-registry: false").count(),
    4,
    "every attestation action must keep bundles in the GitHub Attestations API"
  );

  for removed in [
    "actions/attest-sbom",
    "sigstore/cosign-installer",
    "cosign sign",
    "cosign verify",
    "push-to-registry: true",
    "--bundle-from-oci",
    "--cert-identity",
    "sbom_artifact_name",
    "sbom_file",
    ".supplyChain",
    "ghcr-index-admission-verify",
    "tests/scripts/check-image-admission-policy.sh",
    "tests/scripts/run-image-admission-policy.sh",
  ] {
    assert!(
      !workflow.contains(removed) && !arch_workflow.contains(removed),
      "release workflows should not retain the superseded or prohibited supply-chain surface: {removed}"
    );
  }

  for removed in [
    "actions/checkout",
    "Checkout release revision",
    "tests/scripts/build-docker-image-artifact.sh",
  ] {
    assert!(
      !manifest_job_text.contains(removed)
        && !index_promote_job_text.contains(removed)
        && !promote_job_text.contains(removed),
      "registry mutation jobs must not execute release build code: {removed}"
    );
  }
}
#[test]
fn release_workflows_cover_oxibelt_image_artifact_pipeline() {
  let workflow = release_workflow_text();
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
    "Verify GitHub API platform attestations",
    "Promote canonical GHCR aliases",
    "ghcr-manifest-publish",
    "Publish canonical multi-arch manifests",
    "ghcr-index-sbom",
    "Compose multi-arch index SBOM",
    "ghcr-index-attest",
    "Publish signed index provenance",
    "Publish signed index SBOM",
    "ghcr-index-verify",
    "Verify GitHub API index attestations",
    "ghcr-index-promote",
    "Promote canonical multi-arch aliases",
    "if plan[\"schemaVersion\"] != 6:",
    "release plan must contain exactly 30 unique role/architecture artifacts",
    "release plan must contain exactly 12 unique role manifests",
    "{schemaVersion: 2, role: $role, image: $image, digest: $digest, children: $children}",
    "actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1",
    "push-to-registry: false",
    ":latest",
    r#"aliases = [f"{image}:{major}-alpine-musl-{arch}"] if kind == "stable" else []"#,
  ] {
    assert!(
      workflow.contains(expected) || arch_workflow.contains(expected),
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
      !workflow.contains(removed) && !arch_workflow.contains(removed),
      "release workflows should not retain {removed}"
    );
  }
}

#[test]
fn docker_buildx_setup_prepulls_buildkit_image_with_retry() {
  let workflow = workflow_text();
  let script = docker_pull_retry_script_text();
  let setup_marker = "\n      - name: Setup Docker Buildx\n        uses: docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c # 4.2.0";
  let prepull_step_name = "name: Pre-pull Docker BuildKit image";
  let prepull_command = "tests/scripts/retry-docker-pull.sh moby/buildkit:buildx-stable-1";
  let setup_count = workflow.matches(setup_marker).count();

  assert_eq!(
    setup_count, 9,
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
    expected_needs(PRIMARY_RUST_GATE_NEEDS),
    "comparator image builds should run in parallel with OxiBelt AMD64 image builds"
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
    expected_needs(PRIMARY_RUST_GATE_NEEDS),
    "performance probe image builds should follow the normal test gates"
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
    expected_needs(PRIMARY_RUST_GATE_NEEDS),
    "external benchmark image builds should follow the normal test gates"
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
