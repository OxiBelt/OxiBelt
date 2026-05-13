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
        "docker-alpine-musl-image-other",
        "docker-integration-matrix",
        "remote-signer-dos-docker",
        "browser-webdriver",
        "docker-performance",
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
