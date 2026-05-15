use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("source crate should live under the repository root")
        .to_path_buf()
}

fn performance_script_text() -> String {
    fs::read_to_string(repo_root().join("tests/scripts/run-proxy-performance.sh"))
        .expect("performance script should be readable")
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
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after epoch")
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!(
        "oxibelt-performance-gate-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir).expect("temporary harness directory should be creatable");
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
    fs::remove_dir_all(&temp_dir).ok();

    HarnessRun { output, events }
}

fn assert_result_harness(probe_json: &str, max_load_errors_per_million: &str) -> HarnessRun {
    let functions = format!(
        "{}\n\n{}",
        extract_bash_function(&performance_script_text(), "load_errors_within_budget"),
        extract_bash_function(&performance_script_text(), "assert_result")
    );
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after epoch")
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!(
        "oxibelt-performance-assert-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir_all(&temp_dir).expect("temporary harness directory should be creatable");
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
    fs::remove_dir_all(&temp_dir).ok();

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
        script.contains("nginx_h3_mode=optional"),
        "nginx HTTP/3 should only be optional after image support is detected"
    );
    assert!(
        script.contains("run_common_loads nginx nginx \"${nginx_h3_mode}\""),
        "nginx should use the explicit optional/disabled HTTP/3 mode"
    );
    assert!(
        !script.contains("run_common_loads oxibelt oxibelt 1")
            && !script.contains("run_common_loads caddy caddy 1"),
        "mandatory HTTP/3 comparators must not use the legacy boolean supports_h3 flag"
    );
}
