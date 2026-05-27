use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

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

fn workspace_members() -> Vec<String> {
    let manifest = fs::read_to_string(repo_root().join("Cargo.toml"))
        .expect("root Cargo.toml should be readable");
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
                jobs.get_mut(job_id)
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
            jobs.get_mut(job_id)
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

        job.needs
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
fn alpine_dockerfile_bundles_oxibeltctl() {
    let dockerfile = dockerfile_text();

    assert!(
        dockerfile.contains("--bin oxibeltctl"),
        "source/ops/Dockerfile.alpine should build the oxibeltctl operations CLI"
    );
    assert!(
        dockerfile
            .contains("cp \"target/${OXIBELT_RUST_TARGET}/release/oxibeltctl\" /tmp/oxibeltctl")
            && dockerfile.contains("cp target/release/oxibeltctl /tmp/oxibeltctl"),
        "source/ops/Dockerfile.alpine should stage oxibeltctl for target and host builds"
    );
    assert!(
        dockerfile.contains("COPY --from=builder /tmp/oxibeltctl /usr/local/bin/oxibeltctl"),
        "source/ops/Dockerfile.alpine should copy oxibeltctl into the runtime image"
    );
    assert!(
        dockerfile.contains("chmod 0755 /usr/local/bin/oxibeltctl"),
        "source/ops/Dockerfile.alpine should make oxibeltctl executable"
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
    let security_relevant_jobs = [
        "test",
        "test-riscv64-qemu",
        "generate-test-matrices",
        "linux-target-builds",
        "docker-alpine-musl-image-amd64",
        "docker-alpine-comparator-musl-image-amd64",
        "docker-alpine-musl-image-other",
        "docker-integration-matrix",
        "remote-signer-dos-docker",
        "browser-webdriver",
        "docker-performance",
        "docker-performance-summary",
        "docker-aggressive-long-run",
    ];

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
fn amd64_comparator_image_job_builds_cpu_level_artifacts() {
    let workflow = workflow_text();
    let jobs = parse_jobs(&workflow);
    let comparator_job = jobs
        .get("docker-alpine-comparator-musl-image-amd64")
        .expect("workflow should define the AMD64 comparator image job");
    let script = comparator_build_script_text();
    let nginx_dockerfile = comparator_dockerfile_text("nginx");
    let caddy_dockerfile = comparator_dockerfile_text("caddy");

    assert_eq!(
        comparator_job.needs,
        vec![
            "test".to_owned(),
            "test-riscv64-qemu".to_owned(),
            "fuzz-smoke".to_owned()
        ],
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
            && nginx_dockerfile.contains("-march=${NGINX_TARGET_CPU}"),
        "nginx comparator image should pin mainline nginx, build HTTP/3, and use the requested target CPU"
    );
    assert!(
        caddy_dockerfile.contains("ARG CADDY_VERSION=2.11.2")
            && caddy_dockerfile.contains("FROM caddy:${CADDY_VERSION}-builder-alpine AS builder")
            && caddy_dockerfile.contains("export GOAMD64=v2")
            && caddy_dockerfile.contains("export GOAMD64=v3"),
        "Caddy comparator image should pin Caddy and map OxiBelt target CPUs to GOAMD64 levels"
    );
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

    assert!(
        workflow.contains("performance_iterations:"),
        "workflow_dispatch should expose the Docker performance iteration count"
    );
    assert!(
        workflow.contains("PERFORMANCE_ITERATIONS: ${{ github.event_name == 'workflow_dispatch' && inputs.performance_iterations || '5' }}"),
        "docker-performance should default to five iterations outside manual dispatch"
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
        jobs.get("docker-performance")
            .expect("workflow should define docker-performance")
            .needs
            .contains(&"docker-alpine-comparator-musl-image-amd64".to_owned()),
        "docker-performance should wait for target-specific comparator images"
    );
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
        ("nginx", "x86-64-v3"),
        ("caddy", "x86-64-v3"),
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
            && performance_job.contains("OXIBELT_NGINX_H3_MODE=required"),
        "docker-performance should compare against target-specific comparator images and require nginx HTTP/3 in CI"
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
        "docker-performance should fail after all configured iterations have run"
    );
    assert!(
        workflow.contains("OXIBELT_TEST_ARTIFACT_DIR=\"${target_artifact_dir}/run-${iteration}\""),
        "docker-performance should isolate artifacts by serving type, shard, target CPU, and iteration"
    );
    assert!(
        workflow.contains(
            "oxibelt-docker-performance-${{ env.PERFORMANCE_PROFILE }}-${{ matrix.serving_type }}-shard-${{ matrix.shard }}"
        ),
        "docker-performance artifact names should include the serving type and shard"
    );
    assert!(
        workflow.contains("path: ${{ runner.temp }}/oxibelt-performance/${{ matrix.serving_type }}/shard-${{ matrix.shard }}"),
        "docker-performance should upload one grouped artifact per serving type and shard"
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
        workflow.contains("pattern: oxibelt-docker-performance-${{ env.PERFORMANCE_PROFILE }}-*"),
        "summary job should download all profile-scoped performance artifacts"
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
        workflow.contains("baseline_report=${baseline_dir}/comparison/performance-comparison.json"),
        "summary job should expose the downloaded baseline report path"
    );
    assert!(
        workflow.contains(
            "cargo run --quiet --locked -p oxibelt --bin oxibelt-performance-aggregate --"
        ),
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
        workflow.contains("name: Evaluate Docker performance regression gates"),
        "summary job should evaluate median regression gates after aggregation"
    );
    assert!(
        workflow.contains("gate_status=\"$(jq -r '.regression_gates.status // \"unknown\"'"),
        "summary job should read the regression gate status from the comparison JSON"
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
        workflow
            .contains("name: oxibelt-docker-performance-${{ env.PERFORMANCE_PROFILE }}-comparison"),
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
        workflow.contains("if: needs.docker-performance.result == 'success' && (github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.aggressive_long_run))"),
        "aggressive long-run should run only after successful Docker performance on schedule or explicit manual dispatch"
    );
    assert!(
        workflow.contains("timeout-minutes: 360"),
        "aggressive long-run should fit within GitHub-hosted runner limits"
    );
    assert!(
        workflow.contains("AGGRESSIVE_LONG_RUN_SECONDS: ${{ github.event_name == 'workflow_dispatch' && inputs.aggressive_long_run_seconds || '18000' }}"),
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
        workflow.contains(
            "OXIBELT_AMD64_TARGET_CPU: ${{ steps.select-amd64-image.outputs.target_cpu }}"
        ),
        "aggressive long-run should record the AMD64 target CPU in its summary"
    );
    assert!(
        workflow.contains("--serving-type oxibelt-aggressive-long-run"),
        "aggressive long-run should call the dedicated performance serving type"
    );
    assert!(
        workflow.contains("cat \"${RUNNER_TEMP}/oxibelt-aggressive-long-run/summary.md\" >> \"${GITHUB_STEP_SUMMARY}\""),
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
