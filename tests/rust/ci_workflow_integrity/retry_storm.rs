use super::repo_root;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::Command;

const RETRY_STORM_CHECKS: &str = "tests/fixtures/oxibelt-docker-integration-matrix/docker/upstream-pools/retry-storm-budget/checks.sh";

fn valid_responses() -> Vec<Value> {
  [8, 1, 15, 3, 12, 6, 16, 4, 10, 2, 14, 7, 11, 5, 13, 9]
    .into_iter()
    .map(|burst_index| {
      json!({
        "burst_index": burst_index,
        "status": if burst_index == 9 { 504 } else { 503 },
      })
    })
    .collect()
}

fn set_one_status(responses: &mut [Value], from: i64, to: i64) {
  let response = responses
    .iter_mut()
    .find(|response| response["status"] == from)
    .expect("fixture response set should contain the requested status");
  response["status"] = json!(to);
}

fn validate_responses(response_file: &Path) -> std::process::Output {
  Command::new("bash")
    .args([
      "-c",
      r#"set -euo pipefail
source "$1"
retry_storm_validate_responses "$2"
"#,
      "retry-storm-response-validator",
    ])
    .arg(repo_root().join(RETRY_STORM_CHECKS))
    .arg(response_file)
    .current_dir(repo_root())
    .output()
    .expect("retry-storm response validator should execute under Bash")
}

fn write_responses(path: &Path, responses: &[Value]) {
  fs::write(
    path,
    serde_json::to_vec(responses).expect("fixture responses should serialize"),
  )
  .expect("fixture response file should be writable");
}

#[test]
fn retry_storm_response_validator_accepts_shuffled_expected_mix() {
  let temp_dir = tempfile::tempdir().expect("retry-storm fixture directory should be creatable");
  let response_file = temp_dir.path().join("responses.json");
  write_responses(&response_file, &valid_responses());

  let output = validate_responses(&response_file);
  assert!(
    output.status.success(),
    "the response validator should accept a shuffled fifteen-503, one-504 mix: {}",
    String::from_utf8_lossy(&output.stderr)
  );
}

#[test]
fn retry_storm_response_validator_rejects_invalid_response_sets() {
  let temp_dir = tempfile::tempdir().expect("retry-storm fixture directory should be creatable");
  let cases = [
    ("all-503", {
      let mut responses = valid_responses();
      set_one_status(&mut responses, 504, 503);
      responses
    }),
    ("multiple-504", {
      let mut responses = valid_responses();
      set_one_status(&mut responses, 503, 504);
      responses
    }),
    ("unexpected-status", {
      let mut responses = valid_responses();
      set_one_status(&mut responses, 503, 502);
      responses
    }),
    ("missing-response", {
      let mut responses = valid_responses();
      responses.pop();
      responses
    }),
    ("client-error", {
      let mut responses = valid_responses();
      let response = responses
        .iter_mut()
        .find(|response| response["status"] == 503)
        .expect("fixture response set should contain a 503");
      response["error"] = json!({"kind": "TimeoutError", "message": "timed out"});
      responses
    }),
  ];

  for (case_name, responses) in cases {
    let response_file = temp_dir.path().join(format!("{case_name}.json"));
    write_responses(&response_file, &responses);
    let output = validate_responses(&response_file);
    assert!(
      !output.status.success(),
      "the response validator should reject {case_name}"
    );
  }

  let malformed_file = temp_dir.path().join("malformed.json");
  fs::write(&malformed_file, "not-json").expect("malformed fixture should be writable");
  let output = validate_responses(&malformed_file);
  assert!(
    !output.status.success(),
    "the response validator should reject malformed JSON"
  );
}
