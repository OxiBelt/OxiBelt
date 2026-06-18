use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use oxibelt::config::{Config, MetricsDetail};
use oxibelt::routes::RouteTable;
use oxibelt::waf::WafEngine;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("source crate should live under the repository root")
        .to_path_buf()
}

fn performance_script_path() -> PathBuf {
    repo_root().join("tests/scripts/run-proxy-performance.sh")
}

fn performance_script_text() -> String {
    fs::read_to_string(performance_script_path()).expect("performance script should be readable")
}

fn perf_probe_source_text() -> String {
    fs::read_to_string(repo_root().join("tests/docker/perf_probe/src/main.rs"))
        .expect("perf probe source should be readable")
}

fn oxibelt_performance_fixture_root() -> PathBuf {
    repo_root().join("tests/fixtures/oxibelt-docker-performance/oxibelt")
}

struct HarnessTempDir {
    dir: tempfile::TempDir,
}

impl HarnessTempDir {
    fn new(prefix: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir()
            .expect("temporary harness directory should be creatable");
        Self { dir }
    }

    fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.dir.path().join(path)
    }
}

fn extract_bash_function(script: &str, function_name: &str) -> String {
    let signature = format!("{function_name}() {{");
    let mut collecting = false;
    let mut function = Vec::new();

    for line in script.lines() {
        if !collecting && line == signature {
            collecting = true;
        }

        if collecting {
            function.push(line);
            if line == "}" {
                return function.join("\n");
            }
        }
    }

    panic!("missing Bash function {function_name}");
}

struct HarnessRun {
    output: Output,
    events: String,
}

fn run_common_loads_harness(h3_mode: &str, probe_result: &str) -> HarnessRun {
    let function = extract_bash_function(&performance_script_text(), "run_common_loads");
    let temp_dir = HarnessTempDir::new("oxibelt-performance-gate-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    write_harness(&harness_path, &function);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("H3_MODE", h3_mode)
        .env("PROBE_RESULT", probe_result)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn run_static_loads_harness(profile: &str, h3_mode: &str, probe_result: &str) -> HarnessRun {
    run_static_loads_harness_for("oxibelt", profile, h3_mode, probe_result)
}

fn run_static_loads_harness_for(
    comparator: &str,
    profile: &str,
    h3_mode: &str,
    probe_result: &str,
) -> HarnessRun {
    let functions = format!(
        "{}\n\n{}",
        extract_bash_function(&performance_script_text(), "run_static_h3_load"),
        extract_bash_function(&performance_script_text(), "run_static_loads")
    );
    let temp_dir = HarnessTempDir::new("oxibelt-performance-static-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    write_static_loads_harness(&harness_path, &functions);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("COMPARATOR", comparator)
        .env("EVENTS_FILE", &events_path)
        .env("PROFILE", profile)
        .env("H3_MODE", h3_mode)
        .env("PROBE_RESULT", probe_result)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn nginx_h3_mode_harness(mode: &str, supported: &str) -> HarnessRun {
    let function = extract_bash_function(&performance_script_text(), "resolve_nginx_h3_mode");
    let temp_dir = HarnessTempDir::new("oxibelt-performance-nginx-h3-mode-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    write_nginx_h3_mode_harness(&harness_path, &function);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("NGINX_H3_MODE", mode)
        .env("NGINX_H3_SUPPORTED", supported)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn accept_multiplier_profile_harness(probe_result: &str) -> HarnessRun {
    let functions = format!(
        "{}\n\n{}",
        extract_bash_function(
            &performance_script_text(),
            "run_accept_multiplier_common_loads"
        ),
        extract_bash_function(&performance_script_text(), "run_accept_multiplier_profile")
    );
    let temp_dir = HarnessTempDir::new("oxibelt-performance-accept-multipliers-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    write_accept_multiplier_harness(&harness_path, &functions);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("PROBE_RESULT", probe_result)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn run_load_profile_harness(profile_label: &str, load_label: &str) -> HarnessRun {
    let script = performance_script_text();
    let functions = format!(
        "{}\n\n{}",
        extract_bash_function(&script, "should_profile_load"),
        extract_bash_function(&script, "run_load")
    );
    let temp_dir = HarnessTempDir::new("oxibelt-performance-profile-load-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    write_run_load_profile_harness(&harness_path, &functions);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("PROFILE_LABEL", profile_label)
        .env("LOAD_LABEL", load_label)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn profile_pid_harness(
    active_container: &str,
    docker_pid: &str,
    docker_running: &str,
) -> HarnessRun {
    let function = extract_bash_function(&performance_script_text(), "active_oxibelt_host_pid");
    let temp_dir = HarnessTempDir::new("oxibelt-performance-profile-pid-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    write_profile_pid_harness(&harness_path, &function);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("ACTIVE_PROXY_CONTAINER", active_container)
        .env("DOCKER_PID", docker_pid)
        .env("DOCKER_RUNNING", docker_running)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn assert_result_harness(probe_json: &str, max_load_errors_per_million: &str) -> HarnessRun {
    let functions = format!(
        "{}\n\n{}",
        extract_bash_function(&performance_script_text(), "load_errors_within_budget"),
        extract_bash_function(&performance_script_text(), "assert_result")
    );
    let temp_dir = HarnessTempDir::new("oxibelt-performance-assert-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    write_assert_result_harness(&harness_path, &functions);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("PROBE_JSON", probe_json)
        .env("MAX_LOAD_ERRORS_PER_MILLION", max_load_errors_per_million)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn resource_drift_harness(
    before: &str,
    after: &str,
    max_memory_delta: &str,
    max_fd_delta: &str,
    max_task_delta: &str,
) -> HarnessRun {
    let functions = extract_bash_function(&performance_script_text(), "assert_resource_drift");
    let temp_dir = HarnessTempDir::new("oxibelt-performance-resource-drift-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    let snapshots_path = temp_dir.join("resource-snapshots.jsonl");
    fs::write(&snapshots_path, format!("{before}\n{after}\n"))
        .expect("resource snapshots fixture should be writable");
    write_resource_drift_harness(&harness_path, &functions);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("RESOURCE_SNAPSHOTS_JSONL", &snapshots_path)
        .env("RESOURCE_DRIFT_JSON", temp_dir.join("resource-drift.json"))
        .env("SUMMARY_MD", temp_dir.join("summary.md"))
        .env("MAX_MEMORY_DELTA", max_memory_delta)
        .env("MAX_FD_DELTA", max_fd_delta)
        .env("MAX_TASK_DELTA", max_task_delta)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn static_16k_ratio_harness(rows: &[&str], min_ratio: &str) -> HarnessRun {
    let functions = format!(
        "{}\n\n{}",
        extract_bash_function(
            &performance_script_text(),
            "handle_regression_gate_violation"
        ),
        extract_bash_function(
            &performance_script_text(),
            "assert_static_16k_h1c_caddy_ratio",
        )
    );
    let temp_dir = HarnessTempDir::new("oxibelt-performance-static-ratio-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    let results_path = temp_dir.join("results.jsonl");
    fs::write(&results_path, format!("{}\n", rows.join("\n")))
        .expect("results fixture should be writable");
    write_static_16k_ratio_harness(&harness_path, &functions);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("RESULTS_JSONL", &results_path)
        .env("MIN_RATIO", min_ratio)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn waf_crs_gate_harness(
    rows: &[&str],
    waf_min_rps: &str,
    crs_min_rps: &str,
    max_p99_ratio: &str,
) -> HarnessRun {
    let functions = format!(
        "{}\n\n{}",
        extract_bash_function(
            &performance_script_text(),
            "handle_regression_gate_violation"
        ),
        extract_bash_function(
            &performance_script_text(),
            "assert_waf_crs_regression_gates",
        )
    );
    let temp_dir = HarnessTempDir::new("oxibelt-performance-waf-crs-gate-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    let results_path = temp_dir.join("results.jsonl");
    fs::write(&results_path, format!("{}\n", rows.join("\n")))
        .expect("results fixture should be writable");
    write_waf_crs_gate_harness(&harness_path, &functions);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("RESULTS_JSONL", &results_path)
        .env("WAF_MIN_RPS", waf_min_rps)
        .env("CRS_MIN_RPS", crs_min_rps)
        .env("MAX_P99_RATIO", max_p99_ratio)
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn external_benchmark_failure_harness(gate_mode: &str) -> HarnessRun {
    let function = extract_bash_function(
        &performance_script_text(),
        "handle_external_benchmark_failure",
    );
    let temp_dir = HarnessTempDir::new("oxibelt-performance-external-gate-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    write_external_benchmark_failure_harness(&harness_path, &function);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("GATE_MODE", gate_mode)
        .env_remove("GITHUB_ACTIONS")
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn external_h2load_h3_zero_flush_harness(gate_mode: &str, rows: &[&str]) -> HarnessRun {
    let script = performance_script_text();
    let functions = format!(
        "{}\n\n{}",
        extract_bash_function(&script, "handle_external_benchmark_failure"),
        extract_bash_function(&script, "flush_external_h2load_h3_zero_failures")
    );
    let temp_dir = HarnessTempDir::new("oxibelt-performance-external-h2load-h3-zero-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    let results_path = temp_dir.join("external-results.jsonl");
    fs::write(&results_path, format!("{}\n", rows.join("\n")))
        .expect("external results fixture should be writable");
    write_external_h2load_h3_zero_flush_harness(&harness_path, &functions);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("RESULTS_JSONL", &results_path)
        .env("GATE_MODE", gate_mode)
        .env_remove("GITHUB_ACTIONS")
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn diagnostic_profile_failure_harness(gate_mode: &str) -> HarnessRun {
    let script = performance_script_text();
    let functions = format!(
        "{}\n\n{}",
        extract_bash_function(&script, "handle_diagnostic_profile_failure"),
        extract_bash_function(&script, "flush_diagnostic_profile_warnings")
    );
    let temp_dir = HarnessTempDir::new("oxibelt-performance-diagnostic-profile-gate-");
    let harness_path = temp_dir.join("harness.sh");
    let events_path = temp_dir.join("events.log");
    write_diagnostic_profile_failure_harness(&harness_path, &functions);

    let output = Command::new("bash")
        .arg(&harness_path)
        .env("EVENTS_FILE", &events_path)
        .env("GATE_MODE", gate_mode)
        .env("GITHUB_ACTIONS", "true")
        .output()
        .expect("Bash harness should execute");
    let events = fs::read_to_string(&events_path).unwrap_or_default();

    HarnessRun { output, events }
}

fn write_harness(path: &Path, run_common_loads: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

duration_seconds=1
concurrency=1
events="${{EVENTS_FILE:?}}"
probe_result="${{PROBE_RESULT:?}}"

run_load() {{
  printf 'LOAD %s %s %s %s %s %s\n' "$@" >>"${{events}}"
}}

record_skip() {{
  printf 'SKIP %s %s %s %s\n' "$1" "$2" "$3" "$4" >>"${{events}}"
}}

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

h3_probe_succeeds() {{
  printf 'PROBE %s\n' "$1" >>"${{events}}"
  [[ "${{probe_result}}" == "success" ]]
}}

{run_common_loads}

run_common_loads oxibelt oxibelt "${{H3_MODE:?}}"
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_static_loads_harness(path: &Path, functions: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

profile="${{PROFILE:?}}"
duration_seconds=1
concurrency=1
events="${{EVENTS_FILE:?}}"
probe_result="${{PROBE_RESULT:?}}"

run_load() {{
  printf 'LOAD %s %s %s %s %s %s\n' "$@" >>"${{events}}"
}}

record_skip() {{
  printf 'SKIP %s %s %s %s\n' "$1" "$2" "$3" "$4" >>"${{events}}"
}}

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

h3_probe_succeeds() {{
  printf 'PROBE %s\n' "$1" >>"${{events}}"
  [[ "${{probe_result}}" == "success" ]]
}}

{functions}

run_static_loads "${{COMPARATOR:?}}" "${{COMPARATOR:?}}" "${{H3_MODE:?}}"
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_nginx_h3_mode_harness(path: &Path, resolve_nginx_h3_mode: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

events="${{EVENTS_FILE:?}}"
nginx_image=nginx-test
nginx_h3_mode_override="${{NGINX_H3_MODE:?}}"
nginx_h3_supported="${{NGINX_H3_SUPPORTED:?}}"

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

{resolve_nginx_h3_mode}

resolved="$(resolve_nginx_h3_mode)"
printf 'MODE %s\n' "${{resolved}}" >>"${{events}}"
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_accept_multiplier_harness(path: &Path, functions: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

duration_seconds=1
concurrency=1
events="${{EVENTS_FILE:?}}"
probe_result="${{PROBE_RESULT:?}}"

start_oxibelt() {{
  printf 'START %s %s\n' "$1" "$2" >>"${{events}}"
}}

run_load() {{
  printf 'LOAD %s %s %s %s %s %s\n' "$@" >>"${{events}}"
}}

run_handshake() {{
  printf 'HANDSHAKE %s %s %s\n' "$@" >>"${{events}}"
}}

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

h3_probe_succeeds() {{
  printf 'PROBE %s\n' "$1" >>"${{events}}"
  [[ "${{probe_result}}" == "success" ]]
}}

{functions}

run_accept_multiplier_profile accept-0_5 baseline waf-enforcing crs-enforcing
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_run_load_profile_harness(path: &Path, functions: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

profile_label="${{PROFILE_LABEL:-}}"
duration_seconds=1
warmup_seconds=0
concurrency=1
events="${{EVENTS_FILE:?}}"

run_probe_json() {{
  printf 'PROBE %s\n' "$*" >>"${{events}}"
  printf '{{"type":"load","label":"%s","requests":1,"rps":1,"p99_ms":1,"errors":0}}\n' "${{LOAD_LABEL:?}}"
}}

run_profiled_probe_json() {{
  printf 'PROFILE %s %s\n' "$1" "$2" >>"${{events}}"
  shift 2
  run_probe_json "$@"
}}

append_result() {{
  printf 'APPEND %s\n' "$1" >>"${{events}}"
}}

assert_result() {{
  printf 'ASSERT %s\n' "$1" >>"${{events}}"
}}

sample_stats() {{
  printf 'STATS %s\n' "$1" >>"${{events}}"
}}

plain_proxy_fast_path_gate_protocol() {{
  return 0
}}

static_fast_path_gate_label() {{
  return 1
}}

{functions}

run_load "${{LOAD_LABEL:?}}" h2 oxibelt "/perf/h2?body=ok" 1 1
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_probe_json_fallback_harness(
    path: &Path,
    function: &str,
    tls_dir: &Path,
    probe_logs_dir: &Path,
    events_path: &Path,
    json_path: &Path,
) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

run_id=test
test_label=perf-test
network_name=perf-net
perf_probe_image=perf-probe
tls_dir="{tls_dir}"
probe_logs_dir="{probe_logs_dir}"

mkdir -p "${{tls_dir}}" "${{probe_logs_dir}}"
printf 'cert\n' >"${{tls_dir}}/fullchain.pem"

docker() {{
  printf 'DOCKER %s\n' "$*" >>"{events_path}"
  case "$1" in
    create|cp|rm)
      return 0
      ;;
    start)
      return 0
      ;;
    logs)
      printf '%s\n' '{{"type":"load","label":"ready-oxibelt","requests":1,"rps":1,"errors":0}}'
      return 0
      ;;
  esac
  return 1
}}

{function}

run_probe_json load --label ready-oxibelt >"{json_path}"
"#,
        tls_dir = tls_dir.display(),
        probe_logs_dir = probe_logs_dir.display(),
        events_path = events_path.display(),
        json_path = json_path.display(),
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_profile_pid_harness(path: &Path, active_oxibelt_host_pid: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

events="${{EVENTS_FILE:?}}"
active_proxy_container="${{ACTIVE_PROXY_CONTAINER:-}}"

docker() {{
  if [[ "$1" == "inspect" && "$2" == "-f" && "$3" == "{{{{.State.Pid}}}}" ]]; then
    printf '%s\n' "${{DOCKER_PID:-}}"
    return 0
  fi
  if [[ "$1" == "inspect" && "$2" == "-f" && "$3" == "{{{{.State.Running}}}}" ]]; then
    printf '%s\n' "${{DOCKER_RUNNING:-false}}"
    return 0
  fi
  return 1
}}

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

{active_oxibelt_host_pid}

pid="$(active_oxibelt_host_pid oxibelt-h2)"
printf 'PID %s\n' "${{pid}}" >>"${{events}}"
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_static_16k_ratio_harness(path: &Path, functions: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

events="${{EVENTS_FILE:?}}"
results_jsonl="${{RESULTS_JSONL:?}}"
regression_gate_mode="fail"
static_16k_h1c_min_caddy_ratio="${{MIN_RATIO:?}}"

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

{functions}

assert_static_16k_h1c_caddy_ratio
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_waf_crs_gate_harness(path: &Path, functions: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

events="${{EVENTS_FILE:?}}"
results_jsonl="${{RESULTS_JSONL:?}}"
regression_gate_mode="fail"
waf_enforcing_min_rps="${{WAF_MIN_RPS:?}}"
crs_enforcing_min_rps="${{CRS_MIN_RPS:?}}"
waf_crs_max_enforce_p99_ratio="${{MAX_P99_RATIO:?}}"

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

{functions}

assert_waf_crs_regression_gates
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_external_benchmark_failure_harness(path: &Path, function: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

events="${{EVENTS_FILE:?}}"
external_benchmark_gate_mode="${{GATE_MODE:?}}"

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

{function}

handle_external_benchmark_failure "synthetic external benchmark failure"
printf 'CONTINUE\n' >>"${{events}}"
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_external_h2load_h3_zero_flush_harness(path: &Path, functions: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

events="${{EVENTS_FILE:?}}"
external_results_jsonl="${{RESULTS_JSONL:?}}"
external_benchmark_gate_mode="${{GATE_MODE:?}}"
external_h2load_h3_zero_deferred=1

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

{functions}

flush_external_h2load_h3_zero_failures
printf 'CONTINUE\n' >>"${{events}}"
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_diagnostic_profile_failure_harness(path: &Path, function: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

events="${{EVENTS_FILE:?}}"
diagnostic_profile_gate_mode="${{GATE_MODE:?}}"
diagnostic_profile_warning_count=0

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

{function}

handle_diagnostic_profile_failure "diagnostic profiling failed for synthetic-profile-a: perf record failed with status 255"
handle_diagnostic_profile_failure "diagnostic profiling failed for synthetic-profile-b: perf record failed with status 255"
flush_diagnostic_profile_warnings
printf 'CONTINUE\n' >>"${{events}}"
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_assert_result_harness(path: &Path, functions: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

events="${{EVENTS_FILE:?}}"
json="${{PROBE_JSON:?}}"
max_p99_ms=10000
max_load_errors_per_million="${{MAX_LOAD_ERRORS_PER_MILLION:?}}"

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

{functions}

assert_result "${{json}}"
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

fn write_resource_drift_harness(path: &Path, functions: &str) {
    let harness = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

events="${{EVENTS_FILE:?}}"
resource_snapshots_jsonl="${{RESOURCE_SNAPSHOTS_JSONL:?}}"
resource_drift_json="${{RESOURCE_DRIFT_JSON:?}}"
summary_md="${{SUMMARY_MD:?}}"
resource_max_memory_delta_bytes="${{MAX_MEMORY_DELTA:?}}"
resource_max_fd_delta="${{MAX_FD_DELTA:?}}"
resource_max_task_delta="${{MAX_TASK_DELTA:?}}"
: >"${{summary_md}}"

fail_with_diagnostics() {{
  printf 'FAIL %s\n' "$1" >>"${{events}}"
  echo "$1" >&2
  exit 1
}}

{functions}

assert_resource_drift aggressive-before aggressive-after
"#
    );
    fs::write(path, harness).expect("Bash harness should be writable");
}

#[test]
fn required_h3_probe_failure_fails_closed_without_skip() {
    let run = run_common_loads_harness("required", "failure");

    assert!(
        !run.output.status.success(),
        "required HTTP/3 probe failure should fail the performance gate"
    );
    assert!(
        String::from_utf8_lossy(&run.output.stderr)
            .contains("mandatory HTTP/3 probe failed for oxibelt"),
        "failure should include a mandatory HTTP/3 diagnostic"
    );
    assert!(run.events.contains("LOAD oxibelt-h1-keepalive h1 oxibelt"));
    assert!(run.events.contains("LOAD oxibelt-h2 h2 oxibelt"));
    assert!(run.events.contains("PROBE oxibelt"));
    assert!(
        run.events
            .contains("FAIL mandatory HTTP/3 probe failed for oxibelt")
    );
    assert!(
        !run.events.contains("SKIP oxibelt-h3"),
        "required HTTP/3 failures must not be downgraded to skips"
    );
    assert!(
        !run.events.contains("LOAD oxibelt-h3 h3"),
        "failed readiness probe should not continue into the HTTP/3 load"
    );
}

#[test]
fn optional_h3_probe_failure_records_skip() {
    let run = run_common_loads_harness("optional", "failure");

    assert!(
        run.output.status.success(),
        "optional HTTP/3 probe failure should not fail the comparator"
    );
    assert!(run.events.contains("PROBE oxibelt"));
    assert!(
        run.events.contains(
            "SKIP oxibelt-h3 load h3 optional HTTP/3 support was detected, but a functional QUIC probe did not complete"
        ),
        "optional HTTP/3 probe failures should remain explicit skips"
    );
    assert!(!run.events.contains("LOAD oxibelt-h3 h3"));
}

#[test]
fn disabled_h3_records_skip_without_probe() {
    let run = run_common_loads_harness("disabled", "failure");

    assert!(
        run.output.status.success(),
        "disabled HTTP/3 should only record an unavailable row"
    );
    assert!(
        !run.events.contains("PROBE"),
        "disabled HTTP/3 should not run a functional probe"
    );
    assert!(
        run.events
            .contains("SKIP oxibelt-h3 load h3 HTTP/3 is not available for this comparator image"),
        "disabled HTTP/3 should record a clear unavailable skip"
    );
}

#[test]
fn smoke_static_loads_use_cleartext_h1_without_h3_probe() {
    let run = run_static_loads_harness("smoke", "required", "failure");

    assert!(run.output.status.success(), "smoke static h1c should run");
    assert!(
        run.events
            .contains("LOAD oxibelt-static-16k-h1c h1c oxibelt /static/16k.bin")
    );
    assert!(
        !run.events.contains("PROBE oxibelt"),
        "smoke static sanity row should not require an H3 probe"
    );
}

#[test]
fn serving_type_defaults_to_all_and_usage_documents_matrix_values() {
    let script = performance_script_text();

    assert!(
        script.contains("serving_type=\"all\""),
        "performance script should default to the legacy combined serving type"
    );
    assert!(
        script.contains(
            "--serving-type all|reverse-proxy|static-files|oxibelt-features|oxibelt-soak-stress|accept-multipliers|remote-signer|oxibelt-aggressive-long-run"
        ),
        "usage should document every supported serving type"
    );
    for serving_type in [
        "all",
        "reverse-proxy",
        "static-files",
        "oxibelt-features",
        "oxibelt-soak-stress",
        "accept-multipliers",
        "remote-signer",
        "oxibelt-aggressive-long-run",
    ] {
        assert!(
            script.contains(serving_type),
            "performance script should recognize serving type {serving_type}"
        );
    }
}

#[test]
fn aggressive_long_run_serving_type_runs_expected_phases() {
    let script = performance_script_text();
    let aggressive_function = extract_bash_function(&script, "run_oxibelt_aggressive_long_run");
    let soak_function = extract_bash_function(&script, "run_oxibelt_soak_and_stress");

    assert!(
        aggressive_function.contains("start_oxibelt \"${oxibelt_aggressive_scenario}\" oxibelt"),
        "aggressive long-run should use the connect-stable OxiBelt fixture"
    );
    assert!(
        soak_function.contains("start_oxibelt \"${oxibelt_baseline_scenario}\" oxibelt"),
        "regular soak/stress should keep using the baseline OxiBelt fixture"
    );

    for expected in [
        "run_oxibelt_aggressive_long_run",
        "oxibelt-aggressive-long-run)",
        "OXIBELT_PERF_OXIBELT_AGGRESSIVE_SCENARIO",
        "baseline-aggressive-long-run",
        "warm_oxibelt_aggressive_resource_baseline",
        "sample_resource_snapshot \"aggressive-before\"",
        "run_load \"oxibelt-aggressive-soak-h1\" h1",
        "run_load \"oxibelt-aggressive-soak-h2\" h2",
        "run_load \"oxibelt-aggressive-soak-h3\" h3",
        "run_stress \"oxibelt-aggressive-slow-post\" slow-post",
        "run_stress \"oxibelt-aggressive-slow-response\" slow-response",
        "run_stress \"oxibelt-aggressive-h2-rapid-stream-churn\" h2-rapid-stream-churn",
        "run_stress \"oxibelt-aggressive-h2-cl0-data\" h2-cl0-data",
        "run_stress \"oxibelt-aggressive-h3-cl0-data\" h3-cl0-data",
        "assert_resource_drift \"aggressive-before\" \"aggressive-after\"",
    ] {
        assert!(
            script.contains(expected),
            "aggressive long-run should contain {expected:?}"
        );
    }
}

#[test]
fn oxibelt_aggressive_long_run_fixture_pins_connect_stability_profile() {
    let path = oxibelt_performance_fixture_root()
        .join("baseline-aggressive-long-run")
        .join("config/oxibelt.toml");
    let config_text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let value: toml::Value = toml::from_str(&config_text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));

    let retry = value
        .get("proxy")
        .and_then(toml::Value::as_table)
        .and_then(|proxy| proxy.get("retry"))
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("{} should contain proxy.retry", path.display()));
    assert_eq!(
        retry.get("enabled").and_then(toml::Value::as_bool),
        Some(true),
        "{} should enable retry for aggressive long-run connect stability",
        path.display()
    );
    assert_eq!(
        retry.get("tries").and_then(toml::Value::as_integer),
        Some(3),
        "{} should retry transient upstream connect failures",
        path.display()
    );
    assert_eq!(
        retry
            .get("retry_non_idempotent")
            .and_then(toml::Value::as_bool),
        Some(false),
        "{} should avoid retrying non-idempotent stress requests",
        path.display()
    );
    let retry_on: Vec<&str> = retry
        .get("on")
        .and_then(toml::Value::as_array)
        .expect("proxy.retry.on should be an array")
        .iter()
        .map(|value| value.as_str().expect("retry condition should be a string"))
        .collect();
    assert_eq!(
        retry_on,
        vec!["connect_error"],
        "{} should only mask transient upstream connect churn",
        path.display()
    );

    let upstream = value
        .get("upstreams")
        .and_then(toml::Value::as_array)
        .and_then(|upstreams| upstreams.first())
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("{} should contain an upstream", path.display()));
    let minimum_slow_post_timeout_ms = 240_000;
    for timeout_key in ["request_timeout_ms", "first_byte_timeout_ms"] {
        let timeout = upstream
            .get(timeout_key)
            .and_then(toml::Value::as_integer)
            .unwrap_or_else(|| panic!("{} should set upstream {timeout_key}", path.display()));
        assert!(
            timeout >= minimum_slow_post_timeout_ms,
            "{} should keep upstream {timeout_key} at least {minimum_slow_post_timeout_ms}ms so the 180s slow-post stress reaches resource checks instead of the default 30s timeout",
            path.display()
        );
    }
    assert_eq!(
        upstream
            .get("pool_max_idle_per_host")
            .and_then(toml::Value::as_integer),
        Some(256),
        "{} should keep enough idle H1 upstream connections for long-run concurrency without exceeding the FD drift gate",
        path.display()
    );
}

#[test]
fn resource_drift_gate_passes_within_limits() {
    let run = resource_drift_harness(
        r#"{"sample":"aggressive-before","memory_rss_bytes":1000,"fd_count":10,"task_count":4,"thread_count":4}"#,
        r#"{"sample":"aggressive-after","memory_rss_bytes":1250,"fd_count":12,"task_count":5,"thread_count":5}"#,
        "512",
        "4",
        "2",
    );

    assert!(
        run.output.status.success(),
        "resource drift within limits should pass"
    );
}

#[test]
fn resource_drift_gate_fails_above_limits() {
    let run = resource_drift_harness(
        r#"{"sample":"aggressive-before","memory_rss_bytes":1000,"fd_count":10,"task_count":4,"thread_count":4}"#,
        r#"{"sample":"aggressive-after","memory_rss_bytes":2048,"fd_count":12,"task_count":5,"thread_count":5}"#,
        "512",
        "4",
        "2",
    );

    assert!(
        !run.output.status.success(),
        "resource drift above limits should fail"
    );
    assert!(
        run.events.contains("RSS drift exceeded gate"),
        "failure should identify the RSS drift gate"
    );
}

#[test]
fn accept_multiplier_profile_runs_required_rows() {
    let run = accept_multiplier_profile_harness("success");

    assert!(
        run.output.status.success(),
        "accept multiplier profile should run when HTTP/3 is ready"
    );
    for expected in [
        "START baseline oxibelt",
        "LOAD oxibelt-accept-0_5-h1-keepalive h1 oxibelt /perf/h1?body=ok",
        "LOAD oxibelt-accept-0_5-h2 h2 oxibelt /perf/h2?body=ok",
        "LOAD oxibelt-accept-0_5-h3 h3 oxibelt /perf/h3?body=ok",
        "LOAD oxibelt-accept-0_5-static-16k-h1c h1c oxibelt /static/16k.bin",
        "HANDSHAKE oxibelt-accept-0_5-tls-handshake-h2 h2 oxibelt",
        "START waf-enforcing oxibelt",
        "LOAD oxibelt-accept-0_5-waf-enforcing h2 oxibelt /perf/waf?body=ok",
        "START crs-enforcing oxibelt",
        "LOAD oxibelt-accept-0_5-crs-enforcing h2 oxibelt /perf/crs?body=ok",
    ] {
        assert!(
            run.events.contains(expected),
            "missing accept multiplier event {expected:?}; events:\n{}",
            run.events
        );
    }
}

#[test]
fn accept_multiplier_required_h3_probe_failure_fails_closed() {
    let run = accept_multiplier_profile_harness("failure");

    assert!(
        !run.output.status.success(),
        "accept multiplier HTTP/3 probe failure should fail closed"
    );
    assert!(
        run.events
            .contains("FAIL mandatory HTTP/3 probe failed for oxibelt-accept-0_5"),
        "failure should identify the accept multiplier HTTP/3 row"
    );
    assert!(
        !run.events
            .contains("HANDSHAKE oxibelt-accept-0_5-tls-handshake-h2"),
        "failed readiness probe should stop the profile before later rows"
    );
}

#[test]
fn remote_signer_profile_runs_local_key_and_remote_signer_pairs() {
    let script = performance_script_text();

    for expected in [
        "run_remote_signer_group",
        "start_oxibelt baseline oxibelt",
        "run_load \"oxibelt-local-key-h1-keepalive\"",
        "run_load \"oxibelt-local-key-h2\"",
        "run_load \"oxibelt-local-key-h3\"",
        "start_oxibelt remote-signer oxibelt",
        "run_load \"oxibelt-remote-signer-h1-keepalive\"",
        "run_load \"oxibelt-remote-signer-h2\"",
        "run_load \"oxibelt-remote-signer-h3\"",
        "start_oxibelt baseline-accept-1 oxibelt",
        "run_handshake \"oxibelt-local-key-tls-handshake-h2\"",
        "start_oxibelt remote-signer-accept-1 oxibelt",
        "run_handshake \"oxibelt-remote-signer-tls-handshake-h2\"",
        "append_remote_signer_overhead_summary",
    ] {
        assert!(
            script.contains(expected),
            "remote signer profile should contain {expected:?}"
        );
    }
}

#[test]
fn oxibelt_performance_fixtures_pin_worker_profile() {
    for (scenario, expected_accept) in [
        ("baseline", 0.5),
        ("baseline-aggressive-long-run", 0.5),
        ("baseline-no-http3", 0.5),
        ("baseline-h2-adaptive-window", 0.5),
        ("baseline-upstream-h2", 0.5),
        ("baseline-upstream-h2c", 0.5),
        ("cache", 0.5),
        ("crs-enforcing", 0.5),
        ("crs-monitor", 0.5),
        ("waf-enforcing", 0.5),
        ("waf-monitor", 0.5),
        ("remote-signer", 0.5),
        ("baseline-accept-1", 1.0),
        ("baseline-classical-kx", 1.0),
        ("crs-enforcing-accept-1", 1.0),
        ("remote-signer-accept-1", 1.0),
        ("tls-resumption-off", 1.0),
        ("tls-resumption-stateless-tickets-2", 1.0),
        ("tls-resumption-stateful-tickets-1", 1.0),
        ("tls-resumption-stateful-tickets-2", 1.0),
        ("waf-enforcing-accept-1", 1.0),
    ] {
        let path = oxibelt_performance_fixture_root()
            .join(scenario)
            .join("config/oxibelt.toml");
        let config_text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let value: toml::Value = toml::from_str(&config_text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        let worker_multipliers = value
            .get("runtime")
            .and_then(toml::Value::as_table)
            .and_then(|runtime| runtime.get("worker_multipliers"))
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| {
                panic!(
                    "{} should contain runtime.worker_multipliers",
                    path.display()
                )
            });

        assert_eq!(
            worker_multipliers
                .get("runtime")
                .and_then(toml::Value::as_float),
            Some(1.0),
            "{} should pin runtime worker multiplier",
            path.display()
        );
        assert_eq!(
            worker_multipliers
                .get("accept")
                .and_then(toml::Value::as_float),
            Some(expected_accept),
            "{} should pin accept worker multiplier",
            path.display()
        );
        assert_eq!(
            worker_multipliers
                .get("quic_socket")
                .and_then(toml::Value::as_float),
            Some(1.0),
            "{} should pin QUIC socket worker multiplier",
            path.display()
        );
    }
}

#[test]
fn oxibelt_performance_fixtures_pin_h2_window_profile() {
    for entry in fs::read_dir(oxibelt_performance_fixture_root())
        .expect("OxiBelt performance fixture root should be readable")
    {
        let entry = entry.expect("fixture directory entry should be readable");
        let file_type = entry
            .file_type()
            .expect("fixture directory entry type should be readable");
        if !file_type.is_dir() {
            continue;
        }

        let scenario = entry
            .file_name()
            .into_string()
            .expect("fixture directory should use UTF-8 name");
        let path = entry.path().join("config/oxibelt.toml");
        if !path.exists() {
            continue;
        }

        let config_text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let value: toml::Value = toml::from_str(&config_text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        let http2 = value
            .get("proxy")
            .and_then(toml::Value::as_table)
            .and_then(|proxy| proxy.get("http2"))
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| panic!("{} should contain proxy.http2", path.display()));

        if scenario == "baseline-h2-adaptive-window" {
            assert_eq!(
                http2.get("adaptive_window").and_then(toml::Value::as_bool),
                Some(true),
                "{} should keep the adaptive-window diagnostic fixture",
                path.display()
            );
            for key in [
                "initial_stream_window_bytes",
                "initial_connection_window_bytes",
                "max_frame_size_bytes",
            ] {
                assert!(
                    !http2.contains_key(key),
                    "{} should not pin manual {key} in the adaptive-window diagnostic fixture",
                    path.display()
                );
            }
        } else {
            assert_eq!(
                http2.get("adaptive_window").and_then(toml::Value::as_bool),
                Some(false),
                "{} should use the fixed HTTP/2 performance baseline",
                path.display()
            );
            assert_eq!(
                http2
                    .get("initial_stream_window_bytes")
                    .and_then(toml::Value::as_integer),
                Some(1_048_576),
                "{} should pin initial stream window",
                path.display()
            );
            assert_eq!(
                http2
                    .get("initial_connection_window_bytes")
                    .and_then(toml::Value::as_integer),
                Some(16_777_216),
                "{} should pin initial connection window",
                path.display()
            );
            assert_eq!(
                http2
                    .get("max_frame_size_bytes")
                    .and_then(toml::Value::as_integer),
                if scenario == "baseline" {
                    Some(131_072)
                } else {
                    Some(65_535)
                },
                "{} should pin max frame size",
                path.display()
            );
        }
    }
}

#[test]
fn remote_signer_performance_fixtures_remove_local_private_key() {
    for scenario in ["remote-signer", "remote-signer-accept-1"] {
        let path = oxibelt_performance_fixture_root()
            .join(scenario)
            .join("config/oxibelt.toml");
        let config_text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let value: toml::Value = toml::from_str(&config_text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        let tls = value
            .get("tls")
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| panic!("{} should contain tls table", path.display()));
        assert!(
            !tls.contains_key("private_key"),
            "{scenario} should not configure a local private key"
        );
        let remote_signer = tls
            .get("remote_signer")
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| panic!("{scenario} should configure tls.remote_signer"));
        assert_eq!(
            remote_signer.get("enabled").and_then(toml::Value::as_bool),
            Some(true),
            "{scenario} should enable tls.remote_signer"
        );
    }
}

#[test]
fn oxibelt_tls_resumption_performance_fixtures_pin_modes_and_metrics() {
    for (scenario, mode, ticket_count) in [
        ("tls-resumption-off", "off", 2),
        ("tls-resumption-stateless-tickets-2", "stateless", 2),
        ("tls-resumption-stateful-tickets-1", "stateful", 1),
        ("tls-resumption-stateful-tickets-2", "stateful", 2),
    ] {
        let path = oxibelt_performance_fixture_root()
            .join(scenario)
            .join("config/oxibelt.toml");
        let config_text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let value: toml::Value = toml::from_str(&config_text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        let resumption = value
            .get("tls")
            .and_then(toml::Value::as_table)
            .and_then(|tls| tls.get("resumption"))
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| panic!("{} should contain tls.resumption", path.display()));
        assert_eq!(
            resumption.get("mode").and_then(toml::Value::as_str),
            Some(mode),
            "{} should pin the expected TLS resumption mode",
            path.display()
        );
        assert_eq!(
            resumption
                .get("tls13_ticket_count")
                .and_then(toml::Value::as_integer),
            Some(ticket_count),
            "{} should pin the expected TLS 1.3 ticket count",
            path.display()
        );
        assert_eq!(
            value
                .get("metrics")
                .and_then(toml::Value::as_table)
                .and_then(|metrics| metrics.get("enabled"))
                .and_then(toml::Value::as_bool),
            Some(true),
            "{} should enable metrics for server-session-storage diagnostics",
            path.display()
        );
    }
}

#[test]
fn oxibelt_baseline_fixture_enables_h1_fast_path_metrics() {
    let path = oxibelt_performance_fixture_root()
        .join("baseline")
        .join("config/oxibelt.toml");
    let config_text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let config: Config = toml::from_str(&config_text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));

    assert!(config.metrics.enabled, "baseline should expose /metrics");
    assert_eq!(
        config.metrics.detail,
        MetricsDetail::Basic,
        "baseline should avoid detailed metrics on the measured fast path"
    );

    let waf = WafEngine::new(&config).expect("WAF engine should build");
    let table = RouteTable::new_with_waf(&config, &waf);
    let resolved = table
        .resolve("example.test", "/perf/h1", &config.upstreams)
        .expect("/perf/h1 should resolve");

    assert_eq!(resolved.route.name, "main-route");
    assert!(
        resolved.execution_plan.fast_path.plain_proxy_h1,
        "/perf/h1 should keep the H1 plain-proxy fast-path plan"
    );
}

#[test]
fn oxibelt_no_http3_fixture_keeps_metrics_gate_reachable() {
    let path = oxibelt_performance_fixture_root()
        .join("baseline-no-http3")
        .join("config/oxibelt.toml");
    let config_text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let config: Config = toml::from_str(&config_text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));

    assert!(
        !config.listeners.http3,
        "negative HTTP/3 fixture should keep downstream HTTP/3 disabled"
    );
    assert!(
        config.metrics.enabled,
        "negative HTTP/3 fixture should expose /metrics for fast-path gate evidence"
    );
    assert_eq!(
        config.metrics.detail,
        MetricsDetail::Basic,
        "negative HTTP/3 fixture should avoid detailed metrics on the measured fast path"
    );
}

#[test]
fn static_16k_h1c_ratio_gate_passes_when_oxibelt_is_close_to_caddy() {
    let run = static_16k_ratio_harness(
        &[
            r#"{"type":"load","label":"oxibelt-static-16k-h1c","requests":1000,"rps":900,"p99_ms":3}"#,
            r#"{"type":"load","label":"caddy-static-16k-h1c","requests":1000,"rps":1000,"p99_ms":3}"#,
        ],
        "0.85",
    );

    assert!(
        run.output.status.success(),
        "OxiBelt at 0.90x Caddy should pass the static regression gate"
    );
    assert!(
        !run.events.contains("FAIL"),
        "passing static ratio should not trip diagnostics"
    );
}

#[test]
fn static_16k_h1c_ratio_gate_fails_below_threshold() {
    let run = static_16k_ratio_harness(
        &[
            r#"{"type":"load","label":"oxibelt-static-16k-h1c","requests":1000,"rps":800,"p99_ms":3}"#,
            r#"{"type":"load","label":"caddy-static-16k-h1c","requests":1000,"rps":1000,"p99_ms":3}"#,
        ],
        "0.85",
    );

    assert!(
        !run.output.status.success(),
        "OxiBelt below 0.85x Caddy should fail the static regression gate"
    );
    assert!(
        run.events
            .contains("FAIL OxiBelt static-16k-h1c regression gate failed"),
        "failure should identify the static 16KiB H1C gate"
    );
}

#[test]
fn static_16k_h1c_ratio_gate_ignores_missing_comparator_data() {
    let run = static_16k_ratio_harness(
        &[
            r#"{"type":"load","label":"oxibelt-static-16k-h1c","requests":1000,"rps":800,"p99_ms":3}"#,
        ],
        "0.85",
    );

    assert!(
        run.output.status.success(),
        "the static ratio gate should wait for Caddy data before comparing"
    );
    assert!(
        !run.events.contains("FAIL"),
        "missing comparator data should not trip diagnostics"
    );
}

#[test]
fn waf_crs_regression_gate_passes_when_rps_and_p99_are_within_limits() {
    let run = waf_crs_gate_harness(
        &[
            r#"{"type":"load","label":"oxibelt-waf-monitor","requests":1000,"rps":13000,"p99_ms":10}"#,
            r#"{"type":"load","label":"oxibelt-waf-enforcing","requests":1000,"rps":12000,"p99_ms":12}"#,
            r#"{"type":"load","label":"oxibelt-crs-monitor","requests":1000,"rps":10500,"p99_ms":20}"#,
            r#"{"type":"load","label":"oxibelt-crs-enforcing","requests":1000,"rps":9000,"p99_ms":24}"#,
        ],
        "12000",
        "9000",
        "1.20",
    );

    assert!(
        run.output.status.success(),
        "WAF/CRS rows at the configured RPS floors and p99 ratio ceiling should pass"
    );
    assert!(
        !run.events.contains("FAIL"),
        "passing WAF/CRS rows should not trip diagnostics"
    );
}

#[test]
fn waf_crs_regression_gate_fails_below_waf_enforcing_rps_floor() {
    let run = waf_crs_gate_harness(
        &[
            r#"{"type":"load","label":"oxibelt-waf-monitor","requests":1000,"rps":13000,"p99_ms":10}"#,
            r#"{"type":"load","label":"oxibelt-waf-enforcing","requests":1000,"rps":11999,"p99_ms":12}"#,
            r#"{"type":"load","label":"oxibelt-crs-monitor","requests":1000,"rps":10500,"p99_ms":20}"#,
            r#"{"type":"load","label":"oxibelt-crs-enforcing","requests":1000,"rps":9000,"p99_ms":24}"#,
        ],
        "12000",
        "9000",
        "1.20",
    );

    assert!(
        !run.output.status.success(),
        "WAF enforcing below the configured RPS floor should fail"
    );
    assert!(
        run.events
            .contains("FAIL OxiBelt WAF enforcing regression gate failed"),
        "failure should identify the WAF enforcing RPS gate"
    );
}

#[test]
fn waf_crs_regression_gate_fails_below_crs_enforcing_rps_floor() {
    let run = waf_crs_gate_harness(
        &[
            r#"{"type":"load","label":"oxibelt-waf-monitor","requests":1000,"rps":13000,"p99_ms":10}"#,
            r#"{"type":"load","label":"oxibelt-waf-enforcing","requests":1000,"rps":12000,"p99_ms":12}"#,
            r#"{"type":"load","label":"oxibelt-crs-monitor","requests":1000,"rps":10500,"p99_ms":20}"#,
            r#"{"type":"load","label":"oxibelt-crs-enforcing","requests":1000,"rps":8999,"p99_ms":24}"#,
        ],
        "12000",
        "9000",
        "1.20",
    );

    assert!(
        !run.output.status.success(),
        "CRS enforcing below the configured RPS floor should fail"
    );
    assert!(
        run.events
            .contains("FAIL OxiBelt CRS enforcing regression gate failed"),
        "failure should identify the CRS enforcing RPS gate"
    );
}

#[test]
fn waf_crs_regression_gate_fails_when_waf_enforcing_p99_regresses() {
    let run = waf_crs_gate_harness(
        &[
            r#"{"type":"load","label":"oxibelt-waf-monitor","requests":1000,"rps":13000,"p99_ms":10}"#,
            r#"{"type":"load","label":"oxibelt-waf-enforcing","requests":1000,"rps":12000,"p99_ms":12.1}"#,
            r#"{"type":"load","label":"oxibelt-crs-monitor","requests":1000,"rps":10500,"p99_ms":20}"#,
            r#"{"type":"load","label":"oxibelt-crs-enforcing","requests":1000,"rps":9000,"p99_ms":24}"#,
        ],
        "12000",
        "9000",
        "1.20",
    );

    assert!(
        !run.output.status.success(),
        "WAF enforcing p99 above the monitor ratio ceiling should fail"
    );
    assert!(
        run.events
            .contains("FAIL OxiBelt WAF p99 regression gate failed"),
        "failure should identify the WAF p99 ratio gate"
    );
}

#[test]
fn waf_crs_regression_gate_fails_when_crs_enforcing_p99_regresses() {
    let run = waf_crs_gate_harness(
        &[
            r#"{"type":"load","label":"oxibelt-waf-monitor","requests":1000,"rps":13000,"p99_ms":10}"#,
            r#"{"type":"load","label":"oxibelt-waf-enforcing","requests":1000,"rps":12000,"p99_ms":12}"#,
            r#"{"type":"load","label":"oxibelt-crs-monitor","requests":1000,"rps":10500,"p99_ms":20}"#,
            r#"{"type":"load","label":"oxibelt-crs-enforcing","requests":1000,"rps":9000,"p99_ms":24.1}"#,
        ],
        "12000",
        "9000",
        "1.20",
    );

    assert!(
        !run.output.status.success(),
        "CRS enforcing p99 above the monitor ratio ceiling should fail"
    );
    assert!(
        run.events
            .contains("FAIL OxiBelt CRS p99 regression gate failed"),
        "failure should identify the CRS p99 ratio gate"
    );
}

#[test]
fn waf_crs_regression_gate_fails_when_required_rows_are_missing() {
    let run = waf_crs_gate_harness(
        &[
            r#"{"type":"load","label":"oxibelt-waf-monitor","requests":1000,"rps":13000,"p99_ms":10}"#,
            r#"{"type":"load","label":"oxibelt-waf-enforcing","requests":1000,"rps":12000,"p99_ms":12}"#,
            r#"{"type":"load","label":"oxibelt-crs-enforcing","requests":1000,"rps":9000,"p99_ms":24}"#,
        ],
        "12000",
        "9000",
        "1.20",
    );

    assert!(
        !run.output.status.success(),
        "missing required WAF/CRS rows should fail closed"
    );
    assert!(
        run.events
            .contains("FAIL missing OxiBelt WAF/CRS performance result: oxibelt-crs-monitor"),
        "failure should identify the missing WAF/CRS row"
    );
}

#[test]
fn invalid_serving_type_fails_with_usage_before_docker_setup() {
    let output = Command::new("bash")
        .arg(performance_script_path())
        .arg("--serving-type")
        .arg("not-a-serving-type")
        .output()
        .expect("performance script should execute");

    assert!(
        !output.status.success(),
        "invalid serving types should fail before the Docker harness starts"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("usage: tests/scripts/run-proxy-performance.sh"),
        "invalid serving type should print usage, got: {stderr}"
    );
}

#[test]
fn benchmark_static_required_h3_probe_failure_fails_closed() {
    let run = run_static_loads_harness("benchmark", "required", "failure");

    assert!(
        !run.output.status.success(),
        "required static HTTP/3 probe failure should fail the performance gate"
    );
    assert!(
        run.events
            .contains("LOAD oxibelt-static-1k-h1c h1c oxibelt /static/1k.bin")
    );
    assert!(
        run.events
            .contains("LOAD oxibelt-static-1k-h1 h1 oxibelt /static/1k.bin")
    );
    assert!(
        run.events
            .contains("LOAD oxibelt-static-1k-h2 h2 oxibelt /static/1k.bin")
    );
    assert!(run.events.contains("PROBE oxibelt"));
    assert!(
        run.events
            .contains("FAIL mandatory HTTP/3 probe failed for oxibelt static files")
    );
}

#[test]
fn benchmark_static_caddy_required_h3_probe_failure_fails_closed() {
    let run = run_static_loads_harness_for("caddy", "benchmark", "required", "failure");

    assert!(
        !run.output.status.success(),
        "Caddy static HTTP/3 probe failure should fail because it is mandatory"
    );
    assert!(
        run.events
            .contains("FAIL mandatory HTTP/3 probe failed for caddy static files")
    );
    assert!(
        !run.events.contains("SKIP caddy-static-1k-h3"),
        "mandatory Caddy static HTTP/3 failures must not be downgraded to skips"
    );
}

#[test]
fn benchmark_static_nginx_optional_h3_probe_failure_records_skip() {
    let run = run_static_loads_harness_for("nginx", "benchmark", "optional", "failure");

    assert!(
        run.output.status.success(),
        "nginx static HTTP/3 probe failure should be skipped when support is optional"
    );
    assert!(run.events.contains("PROBE nginx"));
    assert!(
        run.events.contains(
            "SKIP nginx-static-1k-h3 load h3 optional HTTP/3 support was detected, but a functional QUIC probe did not complete"
        ),
        "optional nginx static HTTP/3 probe failures should remain explicit skips"
    );
    assert!(!run.events.contains("LOAD nginx-static-1k-h3 h3"));
}

#[test]
fn nginx_required_h3_mode_fails_when_module_is_missing() {
    let run = nginx_h3_mode_harness("required", "0");

    assert!(
        !run.output.status.success(),
        "required nginx HTTP/3 mode should fail when the image lacks the module"
    );
    assert!(
        run.events.contains(
            "FAIL OXIBELT_NGINX_H3_MODE=required but nginx image nginx-test does not report --with-http_v3_module"
        ),
        "required mode failure should identify the missing nginx HTTP/3 module"
    );
}

#[test]
fn nginx_auto_h3_mode_preserves_existing_optional_behavior() {
    let run = nginx_h3_mode_harness("auto", "1");

    assert!(run.output.status.success());
    assert!(
        run.events.contains("MODE optional"),
        "auto mode should keep nginx HTTP/3 optional when the module is present"
    );
}

#[test]
fn high_volume_load_error_inside_budget_is_allowed() {
    let run = assert_result_harness(
        r#"{"type":"load","label":"oxibelt-smoke-soak","requests":1500000,"errors":1,"p99_ms":3}"#,
        "1",
    );

    assert!(
        run.output.status.success(),
        "one load transport error across more than one million requests should stay inside the configured budget"
    );
    assert!(
        !run.events.contains("FAIL"),
        "in-budget load errors should not trip the failure hook"
    );
}

#[test]
fn observed_smoke_soak_reconnect_burst_inside_default_budget_is_allowed() {
    let run = assert_result_harness(
        r#"{"type":"load","label":"oxibelt-smoke-soak","requests":1479776,"errors":2,"p99_ms":3}"#,
        "100",
    );

    assert!(
        run.output.status.success(),
        "two load transport errors across the observed smoke-soak volume should stay inside the default CI budget"
    );
    assert!(
        !run.events.contains("FAIL"),
        "observed in-budget smoke soak reconnects should not trip the failure hook"
    );
}

#[test]
fn load_errors_above_relaxed_default_budget_still_fail() {
    let run = assert_result_harness(
        r#"{"type":"load","label":"oxibelt-smoke-soak","requests":1000000,"errors":101,"p99_ms":3}"#,
        "100",
    );

    assert!(
        !run.output.status.success(),
        "load errors above the relaxed CI budget should still fail the performance gate"
    );
    assert!(
        run.events
            .contains("FAIL performance probe reported request errors: oxibelt-smoke-soak")
    );
}

#[test]
fn load_error_above_budget_fails() {
    let run = assert_result_harness(
        r#"{"type":"load","label":"oxibelt-smoke-soak","requests":500000,"errors":1,"p99_ms":3}"#,
        "1",
    );

    assert!(
        !run.output.status.success(),
        "load errors above the per-million budget should fail the performance gate"
    );
    assert!(
        String::from_utf8_lossy(&run.output.stderr)
            .contains("performance probe reported request errors: oxibelt-smoke-soak")
    );
}

#[test]
fn strict_zero_load_error_budget_still_fails_any_load_error() {
    let run = assert_result_harness(
        r#"{"type":"load","label":"oxibelt-smoke-soak","requests":1500000,"errors":1,"p99_ms":3}"#,
        "0",
    );

    assert!(
        !run.output.status.success(),
        "setting the budget to zero should restore strict no-error behavior"
    );
    assert!(
        run.events
            .contains("FAIL performance probe reported request errors: oxibelt-smoke-soak")
    );
}

#[test]
fn handshake_errors_are_not_covered_by_load_error_budget() {
    let run = assert_result_harness(
        r#"{"type":"handshake","label":"oxibelt-tls-handshake-h2","handshakes":1500000,"errors":1,"p99_ms":3}"#,
        "1",
    );

    assert!(
        !run.output.status.success(),
        "handshake errors should remain strict failures"
    );
    assert!(
        run.events
            .contains("FAIL performance probe reported request errors: oxibelt-tls-handshake-h2")
    );
}

#[test]
fn performance_probe_image_override_skips_local_probe_build() {
    let script = performance_script_text();

    assert!(
        script.contains("OXIBELT_PERF_PROBE_IMAGE         prebuilt perf-probe image to reuse; built locally when unset"),
        "usage should document the reusable perf-probe image override"
    );
    assert!(
        script.contains(
            "perf_probe_image=\"${OXIBELT_PERF_PROBE_IMAGE:-oxibelt/perf-probe:${run_id}}\""
        ),
        "performance harness should prefer the prebuilt probe image when provided"
    );
    assert!(
        script.contains("if [[ -n \"${OXIBELT_PERF_PROBE_IMAGE:-}\" ]]; then\n    return 0\n  fi"),
        "performance harness should skip local probe builds when the override is set"
    );
    assert!(
        script.contains("if [[ \"${remove_perf_probe_image}\" == \"1\" ]]; then")
            && script.contains("docker rmi -f \"${perf_probe_image}\""),
        "performance harness should not delete externally provided probe images"
    );
}

#[test]
fn run_probe_json_uses_container_logs_when_attach_output_is_blank() {
    let function = extract_bash_function(&performance_script_text(), "run_probe_json");
    let temp_dir = HarnessTempDir::new("oxibelt-probe-json-fallback-");
    let harness_path = temp_dir.join("harness.sh");
    let tls_dir = temp_dir.join("tls");
    let probe_logs_dir = temp_dir.join("probe-logs");
    let events_path = temp_dir.join("events.log");
    let json_path = temp_dir.join("result.json");

    write_probe_json_fallback_harness(
        &harness_path,
        &function,
        &tls_dir,
        &probe_logs_dir,
        &events_path,
        &json_path,
    );

    let output = Command::new("bash")
        .arg(&harness_path)
        .output()
        .expect("fallback harness should run");
    assert!(
        output.status.success(),
        "fallback harness failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json = fs::read_to_string(&json_path).expect("probe JSON should be written");
    assert!(
        json.contains(r#""label":"ready-oxibelt""#),
        "container log JSON should be returned when attached output is blank: {json}"
    );
    let probe_log = fs::read_to_string(probe_logs_dir.join("ready-oxibelt.log"))
        .expect("probe log should be written");
    assert!(
        probe_log.contains("Attached output:\n") && probe_log.contains("\nContainer logs:\n"),
        "probe log should show attached output and container log sections: {probe_log}"
    );
    assert!(
        probe_log.contains(r#""requests":1"#),
        "probe log should include the fallback container logs: {probe_log}"
    );
}

#[test]
fn external_benchmark_failures_warn_by_default_and_can_fail_closed() {
    let warn = external_benchmark_failure_harness("warn");
    assert!(
        warn.output.status.success(),
        "warn mode should continue after an external benchmark failure"
    );
    assert!(
        warn.events.contains("CONTINUE"),
        "warn mode should continue the harness after recording the warning"
    );
    assert!(
        String::from_utf8_lossy(&warn.output.stderr).contains(
            "External benchmark validation warning: synthetic external benchmark failure"
        ),
        "warn mode should emit a local warning diagnostic"
    );

    let fail = external_benchmark_failure_harness("fail");
    assert!(
        !fail.output.status.success(),
        "fail mode should stop after an external benchmark failure"
    );
    assert!(
        fail.events
            .contains("FAIL synthetic external benchmark failure"),
        "fail mode should route through normal diagnostics"
    );
    assert!(
        !fail.events.contains("CONTINUE"),
        "fail mode should not continue the harness"
    );
}

#[test]
fn external_h2load_h3_zero_flush_suppresses_cross_comparator_diagnostics() {
    let run = external_h2load_h3_zero_flush_harness(
        "warn",
        &[
            r#"{"tool":"h2load","protocol":"h3","status":"fail","reason":"h2load produced no completed requests","requests":0,"comparator":"oxibelt","scenario":"h3","amd64_target_cpu":"x86-64-v3"}"#,
            r#"{"tool":"h2load","protocol":"h3","status":"fail","reason":"h2load produced no completed requests","requests":0,"comparator":"nginx","scenario":"h3","amd64_target_cpu":"x86-64-v3"}"#,
            r#"{"tool":"h2load","protocol":"h3","status":"fail","reason":"h2load produced no completed requests","requests":0,"comparator":"caddy","scenario":"h3","amd64_target_cpu":"x86-64-v3"}"#,
        ],
    );

    assert!(
        run.output.status.success(),
        "cross-comparator h2load h3 zero-request diagnostics should not fail the shard harness"
    );
    assert!(
        run.events.contains("CONTINUE"),
        "cross-comparator diagnostics should let the harness continue"
    );
    assert!(
        !String::from_utf8_lossy(&run.output.stderr)
            .contains("External benchmark validation warning"),
        "cross-comparator zero-request diagnostics should be annotated by aggregation, not per shard"
    );
}

#[test]
fn external_h2load_h3_zero_flush_keeps_single_comparator_failures_visible() {
    let row = r#"{"tool":"h2load","protocol":"h3","status":"fail","reason":"h2load produced no completed requests","requests":0,"comparator":"oxibelt","scenario":"h3","amd64_target_cpu":"x86-64-v3"}"#;
    let warn = external_h2load_h3_zero_flush_harness("warn", &[row]);
    assert!(
        warn.output.status.success(),
        "warn mode should continue after an OxiBelt-specific h2load h3 failure"
    );
    assert!(
        String::from_utf8_lossy(&warn.output.stderr).contains(
            "External benchmark validation warning: h2load h3 external benchmark failed for oxibelt: h2load produced no completed requests"
        ),
        "warn mode should keep the single-comparator failure visible"
    );

    let fail = external_h2load_h3_zero_flush_harness("fail", &[row]);
    assert!(
        !fail.output.status.success(),
        "fail mode should stop on an OxiBelt-specific h2load h3 failure"
    );
    assert!(
        fail.events.contains(
            "FAIL h2load h3 external benchmark failed for oxibelt: h2load produced no completed requests"
        ),
        "fail mode should route the single-comparator failure through normal diagnostics"
    );
}

#[test]
fn external_benchmark_layer_keeps_primary_results_separate() {
    let script = performance_script_text();

    for expected in [
        "OXIBELT_EXTERNAL_BENCHMARKS      run h2load/oha/wrk validation rows, 1 or 0 (default: 1)",
        "OXIBELT_EXTERNAL_BENCHMARK_TOOLS comma-separated h2load,oha,wrk subset (default: h2load,oha,wrk)",
        "OXIBELT_EXTERNAL_BENCHMARK_IMAGE prebuilt external benchmark image to reuse; built locally when unset",
        "OXIBELT_EXTERNAL_BENCHMARK_GATE_MODE",
        "OXIBELT_EXTERNAL_OHA_QPS",
        "OXIBELT_EXTERNAL_OHA_MAX_P99_MS",
        "OXIBELT_EXTERNAL_OHA_MAX_ERROR_RATE",
    ] {
        assert!(
            script.contains(expected),
            "usage should document {expected:?}"
        );
    }
    assert!(
        script.contains("external_results_jsonl=\"${work_dir}/external-results.jsonl\"")
            && script.contains("external_results_json=\"${work_dir}/external-results.json\"")
            && script.contains("external_h2load_dir=\"${work_dir}/external-h2load\"")
            && script.contains("external_oha_dir=\"${work_dir}/external-oha\"")
            && script.contains("external_wrk_dir=\"${work_dir}/external-wrk\""),
        "external benchmark artifacts should live beside the primary performance artifacts"
    );
    assert!(
        script.contains("external_benchmark_image=\"${OXIBELT_EXTERNAL_BENCHMARK_IMAGE:-oxibelt/external-benchmarks:${run_id}}\"")
            && script.contains("external_benchmark_serving_type_enabled()")
            && script.contains("all|reverse-proxy) return 0")
            && script.contains("if [[ -n \"${OXIBELT_EXTERNAL_BENCHMARK_IMAGE:-}\" ]]; then\n    return 0\n  fi")
            && script.contains("if [[ \"${remove_external_benchmark_image}\" == \"1\" ]]; then")
            && script.contains("docker rmi -f \"${external_benchmark_image}\""),
        "external benchmark image overrides should skip local builds and avoid deleting provided images"
    );
    assert!(
        script.contains("DNS.7 = example.test"),
        "generated TLS material should include the normal external benchmark authority"
    );
    assert!(
        script.contains("jq -s '.' \"${external_results_jsonl}\" >\"${external_results_json}\""),
        "performance script should finalize external-results.json separately from results.json"
    );
    assert!(
        script.contains("append_external_result()")
            && script.contains("printf '%s\\n' \"${json}\" >>\"${external_results_jsonl}\""),
        "external rows should be appended to external-results.jsonl, not the primary results.jsonl append path"
    );
    assert!(
        script.contains("run_external_benchmarks_for_comparator oxibelt oxibelt required")
            && script.contains(
                "run_external_benchmarks_for_comparator nginx nginx \"${nginx_h3_mode}\""
            )
            && script.contains("run_external_benchmarks_for_comparator caddy caddy required"),
        "reverse-proxy comparators should reuse active fixtures for external validation"
    );
}

#[test]
fn diagnostic_profile_layer_keeps_primary_results_separate() {
    let script = performance_script_text();

    for expected in [
        "OXIBELT_PERF_DIAGNOSTIC_PROFILES   run separate profile-only replay rows, 1 or 0 (default: 0)",
        "OXIBELT_PERF_DIAGNOSTIC_PROFILE_MODE",
        "OXIBELT_PERF_DIAGNOSTIC_EVENT      perf event for diagnostic CPU replay (default: cpu-clock)",
        "OXIBELT_PERF_DIAGNOSTIC_FREQUENCY  perf frequency for diagnostic CPU replay (default: 49)",
        "OXIBELT_PERF_DIAGNOSTIC_GATE_MODE  fail or warn for diagnostic profiling failures (default: warn)",
        "OXIBELT_PERF_DIAGNOSTIC_COMPRESS   compress bulky perf artifacts with zstd, 1 or 0 (default: 1)",
    ] {
        assert!(
            script.contains(expected),
            "usage should document {expected:?}"
        );
    }
    assert!(
        script.contains("profile_results_jsonl=\"${work_dir}/profile-results.jsonl\"")
            && script.contains("profile_results_json=\"${work_dir}/profile-results.json\"")
            && script.contains("profile_cpu_dir=\"${profiles_dir}/cpu\"")
            && script.contains("profile_memory_dir=\"${profiles_dir}/memory\""),
        "diagnostic profile artifacts should live beside the primary performance artifacts"
    );
    assert!(
        script.contains("append_profile_result()")
            && script.contains("printf '%s\\n' \"${json}\" >>\"${profile_results_jsonl}\"")
            && script
                .contains("jq -s '.' \"${profile_results_jsonl}\" >\"${profile_results_json}\""),
        "diagnostic profile rows should be finalized separately from primary results.json"
    );
    assert!(
        script.contains("diagnostic_profile_warning_count=0")
            && script.contains("flush_diagnostic_profile_warnings")
            && script.contains("reported ${diagnostic_profile_warning_count} unavailable sample(s); see profile-results.json and profiles/"),
        "diagnostic profile shard failures should be summarized once per script run"
    );
    assert!(
        !script.contains("::warning title=Docker performance diagnostic profiling::${message}"),
        "diagnostic profile shard failures should not emit per-sample GitHub annotations"
    );
    assert!(
        script.contains("run_diagnostic_profile_replay \"${label}\" \"${duration}\" \"${protocol}\"")
            && script.contains("run_diagnostic_profile_replay \"${label}\" \"${duration_seconds}\" \"${protocol}\" handshake")
            && script.contains("run_diagnostic_profile_replay \"${label}\" \"${duration}\" \"${mode}\" stress"),
        "load, handshake, and stress rows should get separate diagnostic replay hooks"
    );
    for expected in [
        "profiles/cpu/",
        "profiles/memory/",
        ".perf.data",
        ".perf.report.txt",
        ".perf.script.txt",
        ".flamegraph.svg",
        ".resource.json",
        "/heap",
        "unsupported_heap_reason",
    ] {
        assert!(
            script.contains(expected),
            "diagnostic profile artifact contract should contain {expected:?}"
        );
    }
}

#[test]
fn local_performance_probe_build_retries_base_pulls_and_build() {
    let script = performance_script_text();

    assert!(
        script.contains("for base_image in rust:1.96.0-trixie debian:trixie-slim; do")
            && script.contains("retry_command 3 docker pull \"${base_image}\"")
            && script.contains("retry_command 3 docker build"),
        "local probe image builds should retry Docker Hub base-image pulls and the Docker build"
    );
    assert!(
        script.contains(
            "fail_with_diagnostics \"failed to pull performance probe base image ${base_image}\""
        ) && script.contains(
            "fail_with_diagnostics \"failed to build performance probe image ${perf_probe_image}\""
        ),
        "probe image build failures should copy normal performance diagnostics"
    );
}

#[test]
fn local_external_benchmark_build_retries_base_pulls_and_build() {
    let script = performance_script_text();

    assert!(
        script
            .contains("for base_image in rust:1.96.0-trixie debian:trixie debian:trixie-slim; do")
            && script.contains("retry_command 3 docker pull \"${base_image}\"")
            && script.contains("retry_command 3 docker build")
            && script.contains("tests/docker/external_benchmarks/Dockerfile"),
        "local external benchmark image builds should retry every base-image pull and the Docker build"
    );
    assert!(
        script.contains(
            "fail_with_diagnostics \"failed to pull external benchmark base image ${base_image}\""
        ) && script.contains(
            "fail_with_diagnostics \"failed to build external benchmark image ${external_benchmark_image}\""
        ),
        "external benchmark image build failures should copy normal performance diagnostics"
    );
}

#[test]
fn diagnostic_profile_failures_warn_without_github_annotation_and_can_fail_closed() {
    let warn = diagnostic_profile_failure_harness("warn");
    assert!(
        warn.output.status.success(),
        "warn mode should continue after a diagnostic profiling failure"
    );
    assert!(
        warn.events.contains("CONTINUE"),
        "warn mode should continue the harness after recording the diagnostic"
    );
    let warn_stderr = String::from_utf8_lossy(&warn.output.stderr);
    assert!(
        warn_stderr
            .matches("Docker performance diagnostic profiling reported")
            .count()
            == 1,
        "warn mode should emit one summarized diagnostic profiling warning"
    );
    assert!(
        warn_stderr.contains(
            "Docker performance diagnostic profiling reported 2 unavailable sample(s); see profile-results.json and profiles/"
        ),
        "warn mode should point reviewers to profile evidence instead of repeating per-sample reasons"
    );
    assert!(
        !warn_stderr.contains("perf record failed with status 255"),
        "warn mode should not repeat per-sample perf failures in the shard step log"
    );
    assert!(
        !warn_stderr.contains("::warning title=Docker performance diagnostic profiling::"),
        "warn mode should not create per-sample GitHub annotations in shard jobs"
    );

    let fail = diagnostic_profile_failure_harness("fail");
    assert!(
        !fail.output.status.success(),
        "fail mode should stop after a diagnostic profiling failure"
    );
    assert!(
        fail.events.contains(
            "FAIL diagnostic profiling failed for synthetic-profile-a: perf record failed with status 255"
        ),
        "fail mode should route through normal diagnostics"
    );
    assert!(
        !fail.events.contains("CONTINUE"),
        "fail mode should not continue the harness"
    );
}

#[test]
fn diagnostic_perf_profile_is_noop_without_matching_label() {
    let no_label = run_load_profile_harness("", "oxibelt-h2");
    assert!(
        no_label.output.status.success(),
        "profile-disabled harness should still run the load"
    );
    assert!(
        no_label.events.contains("PROBE load --label oxibelt-h2"),
        "normal load probe should run without diagnostic profiling"
    );
    assert!(
        !no_label.events.contains("PROFILE "),
        "profiling should stay disabled when OXIBELT_PERF_PROFILE_LABEL is unset"
    );

    let near_miss = run_load_profile_harness("oxibelt-h2", "oxibelt-h2-upstream-h2");
    assert!(
        near_miss.output.status.success(),
        "near-miss label harness should still run the load"
    );
    assert!(
        !near_miss.events.contains("PROFILE "),
        "profiling should require an exact label match"
    );
}

#[test]
fn diagnostic_perf_profile_runs_only_for_exact_label() {
    let run = run_load_profile_harness("oxibelt-h2", "oxibelt-h2");

    assert!(
        run.output.status.success(),
        "exact label harness should run successfully"
    );
    assert!(
        run.events.contains("PROFILE oxibelt-h2 1"),
        "run_load should route the exact matching label through diagnostic profiling"
    );
    assert!(
        run.events.contains("PROBE load --label oxibelt-h2"),
        "profiled loads should still execute the normal probe arguments"
    );
}

#[test]
fn diagnostic_perf_profile_fails_when_oxibelt_pid_is_missing() {
    let no_container = profile_pid_harness("", "1234", "true");
    assert!(
        !no_container.output.status.success(),
        "profiling should fail when no OxiBelt container is active"
    );
    assert!(no_container.events.contains(
        "FAIL profiling requested for oxibelt-h2, but no active OxiBelt container is running"
    ));

    let missing_pid = profile_pid_harness("oxibelt-perf-baseline-test", "0", "true");
    assert!(
        !missing_pid.output.status.success(),
        "profiling should fail closed when docker inspect does not return a usable host PID"
    );
    assert!(missing_pid.events.contains(
        "FAIL profiling requested for oxibelt-h2, but OxiBelt host PID was not available"
    ));
}

#[test]
fn handshake_resumption_diagnostic_runs_without_replacing_cold_row() {
    let script = performance_script_text();
    let cold_call = r#"run_handshake "oxibelt-tls-handshake-h2" h2 oxibelt"#;
    let nginx_cold_call = r#"run_handshake "nginx-tls-handshake-h2" h2 nginx"#;
    let caddy_cold_call = r#"run_handshake "caddy-tls-handshake-h2" h2 caddy"#;
    let diagnostic_call = r#"run_handshake_resumption_diagnostic "oxibelt-tls-handshake-h2-resumption-diagnostic" h2 oxibelt"#;

    assert_eq!(
        script.matches(cold_call).count(),
        2,
        "reverse-proxy and all serving types should keep the cold handshake row"
    );
    assert_eq!(
        script.matches(nginx_cold_call).count(),
        2,
        "reverse-proxy and all serving types should add the nginx cold handshake comparator row"
    );
    assert_eq!(
        script.matches(caddy_cold_call).count(),
        2,
        "reverse-proxy and all serving types should add the Caddy cold handshake comparator row"
    );
    assert_eq!(
        script.matches(diagnostic_call).count(),
        2,
        "reverse-proxy and all serving types should add the resumption diagnostic row"
    );
    assert!(
        script.contains("run_handshake_with_options \"$1\" \"$2\" \"$3\" fresh 0 strict none"),
        "default handshake wrapper should preserve fresh cold-handshake behavior"
    );
    assert!(
        script
            .contains("run_handshake_with_options \"$1\" \"$2\" \"$3\" worker 25 diagnostic none"),
        "diagnostic handshake wrapper should reuse worker TLS state and observe tickets without replacing the strict cold row"
    );
    assert!(
        script.contains("assert_diagnostic_result"),
        "diagnostic rows should require useful output without turning client-side port pressure into a hard gate"
    );
}

#[test]
fn tls_resumption_mode_handshake_rows_run_as_fresh_oxibelt_only_smoke_rows() {
    let script = performance_script_text();

    assert_eq!(
        script
            .matches("run_oxibelt_tls_resumption_handshake_rows")
            .count(),
        3,
        "function definition plus reverse-proxy and all serving types should run resumption rows"
    );
    assert!(
        script
            .contains("run_handshake_with_options \"$1\" \"$2\" \"$3\" fresh 0 strict tls-storage"),
        "storage diagnostic wrapper should preserve fresh cold-handshake behavior"
    );
    for label in [
        "oxibelt-tls-handshake-h2-resumption-off",
        "oxibelt-tls-handshake-h2-resumption-stateless-tickets-2",
        "oxibelt-tls-handshake-h2-resumption-stateful-tickets-1",
        "oxibelt-tls-handshake-h2-resumption-stateful-tickets-2",
    ] {
        let call = format!("run_handshake_with_storage_diagnostics \"{label}\" h2 oxibelt");
        assert!(
            script.contains(&call),
            "missing fresh H2 resumption diagnostic row call for {label}"
        );
    }
    assert!(
        script.contains("server_session_storage_delta"),
        "resumption rows should attach server-side session storage counter deltas"
    );
}

#[test]
fn h1_h2_and_h3_rows_attach_fast_path_hit_rate() {
    let script = performance_script_text();

    assert!(
        script.contains("OXIBELT_PERF_H1_FAST_PATH_MIN_HIT_RATE"),
        "performance script should expose the fast-path hit-rate threshold"
    );
    assert!(
        script.contains("plain_proxy_fast_path_delta"),
        "performance script should compute fast-path counter deltas"
    );
    assert!(
        script.contains("direct_h1_transport_delta"),
        "performance script should compute direct-H1 transport counter deltas"
    );
    assert!(
        script.contains("oxibelt-h1-keepalive:h1"),
        "oxibelt-h1-keepalive rows should be selected for H1 fast-path gating"
    );
    assert!(
        script.contains("oxibelt-h2:h2"),
        "oxibelt-h2 rows should be selected for H2 fast-path gating"
    );
    assert!(
        script.contains("oxibelt-h3:h3"),
        "oxibelt-h3 rows should be selected for H3 fast-path gating"
    );
    assert!(
        script.contains("{($protocol): $fast_path}"),
        "gated rows should include protocol-keyed fast-path evidence"
    );
    assert!(
        script.contains("assert_plain_proxy_fast_path_hit_rate"),
        "performance script should gate the fast-path hit rate"
    );
    assert!(
        script.contains("assert_direct_h1_transport_hit_rate"),
        "performance script should gate the direct-H1 transport hit rate"
    );
}

#[test]
fn mandatory_and_optional_call_sites_are_explicit() {
    let script = performance_script_text();

    assert!(
        script.contains("run_common_loads oxibelt oxibelt required"),
        "OxiBelt HTTP/3 performance coverage must be mandatory"
    );
    assert!(
        script.contains("run_common_loads caddy caddy required"),
        "Caddy HTTP/3 performance coverage must be mandatory"
    );
    assert!(
        script.contains("OXIBELT_NGINX_H3_MODE")
            && script.contains("resolve_nginx_h3_mode")
            && script.contains("nginx_h3_mode=\"$(resolve_nginx_h3_mode)\""),
        "nginx HTTP/3 mode should be explicitly configurable while preserving auto detection"
    );
    assert!(
        script.contains("OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO"),
        "static 16KiB H1C regression threshold should be configurable"
    );
    assert!(
        script.contains("OXIBELT_PERF_OXIBELT_HANDSHAKE_SCENARIO"),
        "TLS handshake rows should be able to use an explicit fixture override"
    );
    assert!(
        script.contains("run_accept_multiplier_profile accept-0_5 baseline waf-enforcing crs-enforcing")
            && script.contains("run_accept_multiplier_profile accept-1_0 baseline-accept-1 waf-enforcing-accept-1 crs-enforcing-accept-1"),
        "accept multiplier comparison should run both fixture profiles"
    );
    assert!(
        script.contains("run_common_loads nginx nginx \"${nginx_h3_mode}\""),
        "nginx should use the resolved HTTP/3 mode"
    );
    assert!(
        !script.contains("run_common_loads oxibelt oxibelt 1")
            && !script.contains("run_common_loads caddy caddy 1"),
        "mandatory HTTP/3 comparators must not use the legacy boolean supports_h3 flag"
    );
}

#[test]
fn perf_probe_h3_client_disables_grease_for_comparator_interop() {
    let source = perf_probe_source_text();
    assert_eq!(
        source.matches("builder.send_grease(false);").count(),
        2,
        "perf-probe should disable HTTP/3 GREASE in load and stress clients so nginx comparator required H3 smoke measures proxy behavior instead of GREASE interop"
    );
}
