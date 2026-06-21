use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug)]
struct Job {
  needs: Vec<String>,
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
  "test-riscv64-qemu",
  "fuzz-smoke",
];

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
fn alpine_dockerfile_bundles_operations_binaries() {
  let dockerfile = dockerfile_text();

  assert!(
    dockerfile.contains("--bin oxibeltctl"),
    "source/ops/Dockerfile.alpine should build the oxibeltctl operations CLI"
  );
  assert!(
    dockerfile.contains("--bin oxibelt-netport-switcher"),
    "source/ops/Dockerfile.alpine should build the privileged netport switcher"
  );
  assert!(
    dockerfile.contains("cp \"target/${OXIBELT_RUST_TARGET}/release/oxibeltctl\" /tmp/oxibeltctl")
      && dockerfile.contains("cp target/release/oxibeltctl /tmp/oxibeltctl"),
    "source/ops/Dockerfile.alpine should stage oxibeltctl for target and host builds"
  );
  assert!(
        dockerfile.contains(
            "cp \"target/${OXIBELT_RUST_TARGET}/release/oxibelt-netport-switcher\" /tmp/oxibelt-netport-switcher"
        ) && dockerfile
            .contains("cp target/release/oxibelt-netport-switcher /tmp/oxibelt-netport-switcher"),
        "source/ops/Dockerfile.alpine should stage oxibelt-netport-switcher for target and host builds"
    );
  assert!(
    dockerfile.contains("COPY --from=builder /tmp/oxibeltctl /usr/local/bin/oxibeltctl"),
    "source/ops/Dockerfile.alpine should copy oxibeltctl into the runtime image"
  );
  assert!(
    dockerfile.contains(
      "COPY --from=builder /tmp/oxibelt-netport-switcher /usr/local/bin/oxibelt-netport-switcher"
    ),
    "source/ops/Dockerfile.alpine should copy oxibelt-netport-switcher into the runtime image"
  );
  assert!(
    dockerfile.contains("chmod 0755 /usr/local/bin/oxibeltctl"),
    "source/ops/Dockerfile.alpine should make oxibeltctl executable"
  );
  assert!(
    dockerfile.contains("chmod 0755 /usr/local/bin/oxibelt-netport-switcher"),
    "source/ops/Dockerfile.alpine should make oxibelt-netport-switcher executable"
  );
  assert!(
    dockerfile.contains(
      "ENTRYPOINT [\"/usr/local/bin/oxibelt\", \"--config\", \"/etc/oxibelt/config/oxibelt.toml\"]"
    ),
    "source/ops/Dockerfile.alpine should keep oxibelt as the container entrypoint"
  );
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
}

#[test]
fn source_structure_failure_does_not_skip_test_or_docker_ci_jobs() {
  let jobs = parse_jobs(&workflow_text());
  let mut security_relevant_jobs = vec![
    "test",
    "rust-advisory-checks",
    "test-riscv64-qemu",
    "generate-test-matrices",
    "linux-target-builds",
    "docker-alpine-musl-image-amd64",
    "docker-alpine-comparator-musl-image-amd64",
    "docker-performance-probe-image",
    "docker-external-benchmark-image",
    "docker-integration-helper-images",
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
    "runs-on: ubuntu-latest",
    "contents: read",
    "name: Install Rust toolchain",
    "rustup toolchain install 1.96.0 --profile minimal",
    "rustup default 1.96.0",
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
    "docker-alpine-comparator-musl-image-amd64",
    "docker-performance-probe-image",
    "docker-external-benchmark-image",
    "docker-alpine-musl-image-other",
    "docker-alpine-musl-image-riscv64",
    "docker-integration-helper-images",
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
    "valkey/valkey:8-alpine",
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
    DOCKER_INTEGRATION_JOBS.len(),
    "each Docker integration job should download the helper image artifact"
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
    "OXIBELT_REDIS_IMAGE: valkey/valkey:8-alpine",
    "OXIBELT_REQUIRE_PRELOADED_HELPER_IMAGES: \"1\"",
  ] {
    assert_eq!(
      workflow.matches(value).count(),
      DOCKER_INTEGRATION_JOBS.len(),
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
fn riscv64_docker_image_artifact_runs_on_push_pr_schedule_and_manual() {
  let workflow = workflow_text();
  let jobs = parse_jobs(&workflow);
  let qemu_job = jobs
    .get("test-riscv64-qemu")
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

  assert!(
    workflow.contains("riscv64gc-unknown-linux-gnu")
      && workflow.contains("riscv64gc-unknown-linux-musl"),
    "RISC-V cargo check coverage should keep both GNU and musl targets"
  );
  assert!(
    workflow.contains("BINDGEN_EXTRA_CLANG_ARGS: --sysroot=/usr/riscv64-linux-gnu"),
    "RISC-V musl cargo check should expose the cross libc sysroot to bindgen"
  );
  assert!(
    qemu_job.needs.is_empty(),
    "RISC-V cargo check should stay independent of Docker image jobs"
  );
  assert_eq!(
    riscv64_image_job.needs,
    expected_needs(PRIMARY_RUST_GATE_NEEDS),
    "RISC-V Docker image builds should still wait for normal test gates"
  );
  assert!(
    !workflow
      .contains("if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"),
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
fn docker_buildx_setup_prepulls_buildkit_image_with_retry() {
  let workflow = workflow_text();
  let script = docker_pull_retry_script_text();
  let setup_marker = "\n      - name: Setup Docker Buildx\n        uses: docker/setup-buildx-action@d7f5e7f509e45cec5c76c4d5afdd7de93d0b3df5 # 4.1.0";
  let prepull_step_name = "name: Pre-pull Docker BuildKit image";
  let prepull_command = "tests/scripts/retry-docker-pull.sh moby/buildkit:buildx-stable-1";
  let setup_count = workflow.matches(setup_marker).count();

  assert_eq!(
    setup_count, 7,
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
    nginx_dockerfile.contains("ARG NGINX_VERSION=1.31.1")
      && nginx_dockerfile.contains("--with-http_v3_module")
      && nginx_dockerfile
        .contains(r#"org.oxibelt.performance.amd64_target_cpu="${NGINX_TARGET_CPU}""#),
    "nginx comparator image should pin mainline nginx, build HTTP/3, and record the target CPU metadata"
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
    caddy_dockerfile.contains("ARG CADDY_VERSION=2.11.2")
      && caddy_dockerfile.contains("FROM caddy:${CADDY_VERSION}-builder-alpine AS builder")
      && caddy_dockerfile.contains("export GOAMD64=v2")
      && caddy_dockerfile.contains("export GOAMD64=v3"),
    "Caddy comparator image should pin Caddy and map OxiBelt target CPUs to GOAMD64 levels"
  );
  assert!(
    openresty_dockerfile.contains("ARG OPENRESTY_VERSION=1.31.1.1")
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
  for expected in ["h2load --h3 --version", "oha --version", "wrk --version"] {
    assert!(
      dockerfile.contains(expected),
      "external benchmark Dockerfile should self-check {expected}"
    );
  }
  assert!(
    dockerfile.contains("cargo install oha")
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
      && workflow.contains("completed with ${diagnostic_warning_count} diagnostic comparator warning(s)"),
    "docker-performance should distinguish non-blocking diagnostic comparator warnings from primary iteration failures"
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
    workflow.contains("if: always()"),
    "summary job should run even when performance matrix entries fail"
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
