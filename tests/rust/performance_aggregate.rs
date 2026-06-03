use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

struct TempDir {
    dir: tempfile::TempDir,
}

impl TempDir {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("oxibelt-performance-aggregate-")
            .tempdir()
            .expect("temp directory should be created");
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

fn aggregate_binary() -> &'static str {
    env!("CARGO_BIN_EXE_oxibelt-performance-aggregate")
}

fn run_aggregate(input_dir: &Path, output_dir: &Path) -> Value {
    run_aggregate_with_args(input_dir, output_dir, &[])
}

fn run_aggregate_with_args(input_dir: &Path, output_dir: &Path, extra_args: &[String]) -> Value {
    let mut command = Command::new(aggregate_binary());
    command
        .arg("--input-dir")
        .arg(input_dir)
        .arg("--output-dir")
        .arg(output_dir);
    for name in [
        "OXIBELT_PERF_H1_KEEPALIVE_MIN_NGINX_RATIO",
        "OXIBELT_PERF_H2_MIN_NGINX_RATIO",
        "OXIBELT_PERF_H3_MIN_NGINX_RATIO",
        "OXIBELT_PERF_STATIC_16K_H1C_MIN_CADDY_RATIO",
        "OXIBELT_PERF_STATIC_16K_H1C_MIN_NGINX_RATIO",
        "OXIBELT_PERF_REMOTE_SIGNER_HANDSHAKE_MIN_LOCAL_RATIO",
        "OXIBELT_PERF_WAF_ENFORCING_MIN_RPS",
        "OXIBELT_PERF_CRS_ENFORCING_MIN_RPS",
        "OXIBELT_PERF_WAF_CRS_MAX_ENFORCE_P99_RATIO",
    ] {
        command.env_remove(name);
    }
    for arg in extra_args {
        command.arg(arg);
    }
    let output = command.output().expect("aggregate binary should run");
    assert!(
        output.status.success(),
        "aggregate binary failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let markdown_path = output_dir.join("performance-comparison.md");
    let markdown = fs::read_to_string(&markdown_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", markdown_path.display()));
    for heading in [
        "## Summary",
        "## Reverse proxy comparison",
        "## Static file comparison",
        "## Accept multiplier comparison",
        "## AMD64 ISA comparison",
        "## OxiBelt-only results",
        "## Skipped/missing comparator rows",
        "## Regression gates",
        "## Warnings",
    ] {
        assert!(
            markdown.contains(heading),
            "markdown report should contain {heading}"
        );
    }

    let json_path = output_dir.join("performance-comparison.json");
    let raw = fs::read_to_string(&json_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", json_path.display()));
    serde_json::from_str(&raw).expect("comparison JSON should parse")
}

fn write_results_array(dir: &Path, rows: Vec<Value>) {
    fs::create_dir_all(dir).expect("result directory should be created");
    fs::write(
        dir.join("results.json"),
        serde_json::to_string_pretty(&rows).expect("rows should serialize"),
    )
    .expect("results should be written");
    fs::write(dir.join("summary.md"), "# summary\n").expect("summary should be written");
    fs::write(dir.join("docker-stats.jsonl"), "{}\n").expect("stats should be written");
}

fn load_row(label: &str, protocol: &str, rps: f64, p50_ms: f64, p99_ms: f64) -> Value {
    json!({
        "type": "load",
        "label": label,
        "protocol": protocol,
        "requests": 1000,
        "rps": rps,
        "p50_ms": p50_ms,
        "p90_ms": p50_ms + 1.0,
        "p95_ms": p50_ms + 2.0,
        "p99_ms": p99_ms,
        "errors": 1
    })
}

fn with_target_cpu(mut row: Value, target_cpu: &str) -> Value {
    row.as_object_mut()
        .expect("row should be a JSON object")
        .insert(
            "amd64_target_cpu".to_owned(),
            Value::String(target_cpu.to_owned()),
        );
    row
}

fn load_row_without_rps(label: &str, protocol: &str, p50_ms: f64, p99_ms: f64) -> Value {
    json!({
        "type": "load",
        "label": label,
        "protocol": protocol,
        "requests": 1000,
        "p50_ms": p50_ms,
        "p90_ms": p50_ms + 1.0,
        "p95_ms": p50_ms + 2.0,
        "p99_ms": p99_ms,
        "errors": 0
    })
}

fn load_row_without_p99(label: &str, protocol: &str, rps: f64, p50_ms: f64) -> Value {
    json!({
        "type": "load",
        "label": label,
        "protocol": protocol,
        "requests": 1000,
        "rps": rps,
        "p50_ms": p50_ms,
        "p90_ms": p50_ms + 1.0,
        "p95_ms": p50_ms + 2.0,
        "errors": 0
    })
}

fn handshake_row(label: &str, protocol: &str, rps: f64, p50_ms: f64, p99_ms: f64) -> Value {
    json!({
        "type": "handshake",
        "label": label,
        "protocol": protocol,
        "handshakes": 1000,
        "handshake_per_sec": rps,
        "p50_ms": p50_ms,
        "p90_ms": p50_ms + 1.0,
        "p95_ms": p50_ms + 2.0,
        "p99_ms": p99_ms,
        "errors": 0
    })
}

fn skipped_row(label: &str, protocol: &str, reason: &str) -> Value {
    json!({
        "type": "load",
        "label": label,
        "protocol": protocol,
        "skipped": true,
        "reason": reason
    })
}

fn aggregate_row(comparator: &str, scenario: &str, group: &str, rps: f64, p99_ms: f64) -> Value {
    json!({
        "label": format!("{comparator}-{scenario}"),
        "comparator": comparator,
        "scenario": scenario,
        "group": group,
        "result_type": "load",
        "protocol_or_mode": "h1",
        "sample_count": 1,
        "median_rps": rps,
        "min_rps": rps,
        "max_rps": rps,
        "p25_rps": rps,
        "p75_rps": rps,
        "median_p50_ms": 1.0,
        "median_p90_ms": 2.0,
        "median_p95_ms": 3.0,
        "median_p99_ms": p99_ms,
        "total_errors": 0,
        "skipped_count": 0,
        "skip_reasons": [],
        "source_files": ["baseline/results.json"]
    })
}

fn write_baseline_report(path: &Path, aggregates: Vec<Value>) {
    fs::write(
        path,
        serde_json::to_string_pretty(&json!({ "aggregates": aggregates }))
            .expect("baseline should serialize"),
    )
    .expect("baseline should be written");
}

fn write_reverse_proxy_h2(input_dir: &Path, oxibelt_rps: f64, nginx_rps: f64, oxibelt_p99: f64) {
    write_reverse_proxy_h2_with_p99(input_dir, oxibelt_rps, nginx_rps, oxibelt_p99, 10.0);
}

fn write_reverse_proxy_h2_with_p99(
    input_dir: &Path,
    oxibelt_rps: f64,
    nginx_rps: f64,
    oxibelt_p99: f64,
    nginx_p99: f64,
) {
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/run-1"),
        vec![
            load_row("oxibelt-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("nginx-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("oxibelt-h2", "h2", oxibelt_rps, 1.0, oxibelt_p99),
            load_row("nginx-h2", "h2", nginx_rps, 1.0, nginx_p99),
            load_row("oxibelt-h3", "h3", 100.0, 1.0, 4.0),
            load_row("nginx-h3", "h3", 100.0, 1.0, 4.0),
        ],
    );
}

fn write_reverse_proxy_h3_with_p99(
    input_dir: &Path,
    oxibelt_rps: f64,
    nginx_rps: f64,
    oxibelt_p99: f64,
    nginx_p99: f64,
) {
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/run-1"),
        vec![
            load_row("oxibelt-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("nginx-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("oxibelt-h2", "h2", 100.0, 1.0, 4.0),
            load_row("nginx-h2", "h2", 100.0, 1.0, 4.0),
            load_row("oxibelt-h3", "h3", oxibelt_rps, 1.0, oxibelt_p99),
            load_row("nginx-h3", "h3", nginx_rps, 1.0, nginx_p99),
        ],
    );
}

fn write_reverse_proxy_h1_with_p99(
    input_dir: &Path,
    oxibelt_rps: f64,
    nginx_rps: f64,
    oxibelt_p99: f64,
    nginx_p99: f64,
) {
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/run-1"),
        vec![
            load_row("oxibelt-h1-keepalive", "h1", oxibelt_rps, 1.0, oxibelt_p99),
            load_row("nginx-h1-keepalive", "h1", nginx_rps, 1.0, nginx_p99),
            load_row("oxibelt-h2", "h2", 100.0, 1.0, 4.0),
            load_row("nginx-h2", "h2", 100.0, 1.0, 4.0),
            load_row("oxibelt-h3", "h3", 100.0, 1.0, 4.0),
            load_row("nginx-h3", "h3", 100.0, 1.0, 4.0),
        ],
    );
}

fn write_h1_baseline_report(
    path: &Path,
    oxibelt_rps: f64,
    nginx_rps: f64,
    oxibelt_p99: f64,
    nginx_p99: f64,
) {
    write_baseline_report(
        path,
        vec![
            aggregate_row(
                "oxibelt",
                "h1-keepalive",
                "reverse-proxy",
                oxibelt_rps,
                oxibelt_p99,
            ),
            aggregate_row(
                "nginx",
                "h1-keepalive",
                "reverse-proxy",
                nginx_rps,
                nginx_p99,
            ),
        ],
    );
}

fn write_static_gate_rows(input_dir: &Path, oxibelt_rps: f64, nginx_rps: f64, caddy_rps: f64) {
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-static-files-shard-1/run-1"),
        vec![
            load_row("oxibelt-static-16k-h1c", "h1c", oxibelt_rps, 1.0, 10.0),
            load_row("nginx-static-16k-h1c", "h1c", nginx_rps, 1.0, 10.0),
            load_row("caddy-static-16k-h1c", "h1c", caddy_rps, 1.0, 10.0),
        ],
    );
}

fn write_remote_signer_gate_rows(input_dir: &Path, remote_rps: f64, local_rps: f64) {
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-remote-signer-shard-1/run-1"),
        vec![
            handshake_row(
                "oxibelt-local-key-tls-handshake-h2",
                "h2",
                local_rps,
                3.0,
                10.0,
            ),
            handshake_row(
                "oxibelt-remote-signer-tls-handshake-h2",
                "h2",
                remote_rps,
                3.0,
                10.0,
            ),
        ],
    );
}

fn write_feature_gate_rows(
    input_dir: &Path,
    waf_enforcing_rps: f64,
    crs_enforcing_rps: f64,
    monitor_p99: f64,
    enforcing_p99: f64,
) {
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-oxibelt-features-shard-1/run-1"),
        vec![
            load_row("oxibelt-waf-monitor", "h2", 13000.0, 1.0, monitor_p99),
            load_row(
                "oxibelt-waf-enforcing",
                "h2",
                waf_enforcing_rps,
                1.0,
                enforcing_p99,
            ),
            load_row("oxibelt-crs-monitor", "h2", 10000.0, 1.0, monitor_p99),
            load_row(
                "oxibelt-crs-enforcing",
                "h2",
                crs_enforcing_rps,
                1.0,
                enforcing_p99,
            ),
        ],
    );
}

fn find_aggregate<'a>(report: &'a Value, comparator: &str, scenario: &str) -> &'a Value {
    report["aggregates"]
        .as_array()
        .expect("aggregates should be an array")
        .iter()
        .find(|aggregate| {
            aggregate["comparator"] == comparator && aggregate["scenario"] == scenario
        })
        .unwrap_or_else(|| panic!("missing aggregate for {comparator}/{scenario}"))
}

fn find_aggregate_for_target<'a>(
    report: &'a Value,
    target_cpu: &str,
    comparator: &str,
    scenario: &str,
) -> &'a Value {
    report["aggregates"]
        .as_array()
        .expect("aggregates should be an array")
        .iter()
        .find(|aggregate| {
            aggregate["amd64_target_cpu"] == target_cpu
                && aggregate["comparator"] == comparator
                && aggregate["scenario"] == scenario
        })
        .unwrap_or_else(|| panic!("missing aggregate for {target_cpu}/{comparator}/{scenario}"))
}

fn find_isa_comparison<'a>(report: &'a Value, scenario: &str) -> &'a Value {
    report["amd64_isa_comparisons"]
        .as_array()
        .expect("AMD64 ISA comparisons should be an array")
        .iter()
        .find(|comparison| comparison["scenario"] == scenario)
        .unwrap_or_else(|| panic!("missing AMD64 ISA comparison for {scenario}"))
}

fn find_delta<'a>(report: &'a Value, group: &str, scenario: &str, comparator: &str) -> &'a Value {
    report["rows"]
        .as_array()
        .expect("delta rows should be an array")
        .iter()
        .find(|row| {
            row["group"] == group && row["scenario"] == scenario && row["comparator"] == comparator
        })
        .unwrap_or_else(|| panic!("missing delta for {group}/{scenario}/{comparator}"))
}

fn find_comparison<'a>(report: &'a Value, group: &str, scenario: &str) -> &'a Value {
    report["comparisons"][group]
        .as_array()
        .expect("comparison group should be an array")
        .iter()
        .find(|comparison| comparison["scenario"] == scenario)
        .unwrap_or_else(|| panic!("missing {group} comparison for {scenario}"))
}

fn find_accept_comparison<'a>(report: &'a Value, scenario: &str) -> &'a Value {
    report["accept_multiplier_comparisons"]
        .as_array()
        .expect("accept multiplier comparisons should be an array")
        .iter()
        .find(|comparison| comparison["scenario"] == scenario)
        .unwrap_or_else(|| panic!("missing accept multiplier comparison for {scenario}"))
}

fn find_remote_signer_comparison<'a>(report: &'a Value, scenario: &str) -> &'a Value {
    report["remote_signer_comparisons"]
        .as_array()
        .expect("remote signer comparisons should be an array")
        .iter()
        .find(|comparison| comparison["scenario"] == scenario)
        .unwrap_or_else(|| panic!("missing remote signer comparison for {scenario}"))
}

fn find_regression_violation<'a>(report: &'a Value, gate: &str, scenario: &str) -> &'a Value {
    report["regression_gates"]["violations"]
        .as_array()
        .expect("regression gate violations should be an array")
        .iter()
        .find(|violation| violation["gate"] == gate && violation["scenario"] == scenario)
        .unwrap_or_else(|| panic!("missing regression gate violation for {gate}/{scenario}"))
}

fn find_regression_advisory<'a>(report: &'a Value, gate: &str, scenario: &str) -> &'a Value {
    report["regression_gates"]["advisories"]
        .as_array()
        .expect("regression gate advisories should be an array")
        .iter()
        .find(|advisory| advisory["gate"] == gate && advisory["scenario"] == scenario)
        .unwrap_or_else(|| panic!("missing regression gate advisory for {gate}/{scenario}"))
}

fn assert_close(actual: f64, expected: f64) {
    let difference = (actual - expected).abs();
    assert!(
        difference < 0.000_001,
        "expected {actual} to be close to {expected}, difference {difference}"
    );
}

#[test]
fn aggregates_repeated_samples_ratios_and_partial_rows() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    for shard in 1..=5 {
        for run in 1..=5 {
            let sample = ((shard - 1) * 5 + run) as f64;
            write_results_array(
                &input_dir.join(format!(
                    "oxibelt-docker-performance-smoke-reverse-proxy-shard-{shard}/run-{run}"
                )),
                vec![
                    load_row("oxibelt-h1-keepalive", "h1", 100.0 + sample, 1.0, 5.0),
                    load_row("nginx-h1-keepalive", "h1", 200.0 + sample, 2.0, 6.0),
                    load_row("caddy-h1-keepalive", "h1", 150.0 + sample, 3.0, 7.0),
                    load_row("oxibelt-h2", "h2", 190.0 + sample, 1.0, 5.0),
                    load_row("nginx-h2", "h2", 200.0 + sample, 2.0, 6.0),
                    load_row("caddy-h2", "h2", 180.0 + sample, 3.0, 7.0),
                    handshake_row("oxibelt-tls-handshake-h2", "h2", 1000.0 + sample, 6.0, 10.0),
                    handshake_row("nginx-tls-handshake-h2", "h2", 1250.0 + sample, 7.0, 11.0),
                    handshake_row("caddy-tls-handshake-h2", "h2", 900.0 + sample, 8.0, 12.0),
                    load_row("oxibelt-h3", "h3", 70.0 + sample, 4.0, 8.0),
                    skipped_row(
                        "nginx-h3",
                        "h3",
                        "HTTP/3 is not available for this comparator image",
                    ),
                    load_row("caddy-h3", "h3", 90.0 + sample, 5.0, 9.0),
                ],
            );

            write_results_array(
                &input_dir.join(format!(
                    "oxibelt-docker-performance-smoke-static-files-shard-{shard}/run-{run}"
                )),
                vec![
                    load_row("oxibelt-static-16k-h1c", "h1c", 300.0 + sample, 1.0, 4.0),
                    load_row("nginx-static-16k-h1c", "h1c", 600.0 + sample, 2.0, 5.0),
                    load_row("caddy-static-16k-h1c", "h1c", 250.0 + sample, 3.0, 6.0),
                ],
            );
        }
    }

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-oxibelt-features-shard-1/run-1"),
        vec![load_row("oxibelt-waf-monitor", "h2", 42.0, 3.0, 12.0)],
    );

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-accept-multipliers-shard-1/run-1"),
        vec![
            load_row("oxibelt-accept-0_5-h1-keepalive", "h1", 100.0, 1.0, 5.0),
            load_row("oxibelt-accept-1_0-h1-keepalive", "h1", 110.0, 1.0, 4.0),
            load_row("oxibelt-accept-0_5-h2", "h2", 120.0, 1.0, 5.0),
            load_row("oxibelt-accept-1_0-h2", "h2", 130.0, 1.0, 4.0),
            load_row("oxibelt-accept-0_5-h3", "h3", 90.0, 2.0, 8.0),
            load_row("oxibelt-accept-1_0-h3", "h3", 95.0, 2.0, 7.0),
            load_row("oxibelt-accept-0_5-static-16k-h1c", "h1c", 300.0, 1.0, 3.0),
            load_row("oxibelt-accept-1_0-static-16k-h1c", "h1c", 280.0, 1.0, 4.0),
            handshake_row("oxibelt-accept-0_5-tls-handshake-h2", "h2", 714.0, 3.0, 9.0),
            handshake_row(
                "oxibelt-accept-1_0-tls-handshake-h2",
                "h2",
                1571.88,
                2.0,
                5.0,
            ),
            load_row("oxibelt-accept-0_5-waf-enforcing", "h2", 12000.0, 2.0, 8.0),
            load_row("oxibelt-accept-1_0-waf-enforcing", "h2", 11800.0, 2.0, 9.0),
            load_row("oxibelt-accept-0_5-crs-enforcing", "h2", 9000.0, 3.0, 10.0),
            load_row("oxibelt-accept-1_0-crs-enforcing", "h2", 8800.0, 3.0, 11.0),
        ],
    );

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-remote-signer-shard-1/run-1"),
        vec![
            load_row("oxibelt-local-key-h1-keepalive", "h1", 1000.0, 1.0, 5.0),
            load_row("oxibelt-remote-signer-h1-keepalive", "h1", 900.0, 1.0, 7.5),
            load_row("oxibelt-local-key-h2", "h2", 1100.0, 1.0, 6.0),
            load_row("oxibelt-remote-signer-h2", "h2", 990.0, 1.0, 8.4),
            load_row("oxibelt-local-key-h3", "h3", 800.0, 2.0, 10.0),
            load_row("oxibelt-remote-signer-h3", "h3", 720.0, 2.0, 13.0),
            handshake_row("oxibelt-local-key-tls-handshake-h2", "h2", 700.0, 3.0, 12.0),
            handshake_row(
                "oxibelt-remote-signer-tls-handshake-h2",
                "h2",
                350.0,
                6.0,
                24.0,
            ),
        ],
    );

    let jsonl_dir = input_dir.join("jsonl-artifact/run-1");
    fs::create_dir_all(&jsonl_dir).expect("jsonl fixture directory should be created");
    let jsonl = [
        json!({
            "type": "load",
            "label": "oxibelt-cache-hit",
            "protocol": "h2",
            "requests": 100,
            "rps": 500.0,
            "p50_ms": 1.0,
            "p90_ms": 2.0,
            "p99_ms": 3.0,
            "errors": 0
        })
        .to_string(),
        "not-json".to_owned(),
        json!({
            "type": "load",
            "protocol": "h2",
            "requests": 100,
            "rps": 1.0
        })
        .to_string(),
        json!({
            "type": "load",
            "label": "oxibelt-cache-noncacheable-miss",
            "protocol": "h2",
            "requests": 100,
            "p50_ms": 1.0,
            "p99_ms": 3.0,
            "errors": 0
        })
        .to_string(),
        json!({
            "type": "load",
            "label": "oxibelt-cache-cold-fill",
            "protocol": "h2",
            "requests": 100,
            "rps": 250.0,
            "p50_ms": 1.0,
            "p99_ms": 3.0,
            "errors": 0
        })
        .to_string(),
    ]
    .join("\n");
    fs::write(jsonl_dir.join("results.json"), jsonl).expect("jsonl results should be written");

    let report = run_aggregate(&input_dir, &output_dir);

    assert_eq!(report["schema_version"], 9);
    assert_eq!(report["primary_target_cpu"], "x86-64-v3");

    let oxibelt_h1 = find_aggregate(&report, "oxibelt", "h1-keepalive");
    assert_eq!(oxibelt_h1["sample_count"], 25);
    assert_close(
        oxibelt_h1["median_rps"]
            .as_f64()
            .expect("median should exist"),
        113.0,
    );
    assert_close(
        oxibelt_h1["p25_rps"].as_f64().expect("p25 should exist"),
        107.0,
    );
    assert_close(
        oxibelt_h1["p75_rps"].as_f64().expect("p75 should exist"),
        119.0,
    );
    assert_eq!(oxibelt_h1["total_errors"], 25);
    assert_close(
        oxibelt_h1["median_p95_ms"]
            .as_f64()
            .expect("median p95 should exist"),
        3.0,
    );

    let h1_comparison = find_comparison(&report, "reverse_proxy", "h1-keepalive");
    assert_close(
        h1_comparison["oxibelt_vs_nginx"]["ratio"]
            .as_f64()
            .expect("nginx ratio should exist"),
        113.0 / 213.0,
    );
    assert_close(
        h1_comparison["oxibelt_vs_caddy"]["ratio"]
            .as_f64()
            .expect("caddy ratio should exist"),
        113.0 / 163.0,
    );

    let static_comparison = find_comparison(&report, "static_files", "static-16k-h1c");
    assert_close(
        static_comparison["oxibelt_vs_nginx"]["ratio"]
            .as_f64()
            .expect("static nginx ratio should exist"),
        313.0 / 613.0,
    );
    assert_close(
        static_comparison["oxibelt_vs_caddy"]["ratio"]
            .as_f64()
            .expect("static caddy ratio should exist"),
        313.0 / 263.0,
    );

    let h3_comparison = find_comparison(&report, "reverse_proxy", "h3");
    assert_eq!(h3_comparison["oxibelt_vs_nginx"]["status"], "skipped");
    assert!(
        h3_comparison["oxibelt_vs_nginx"]["reason"]
            .as_str()
            .expect("skip reason should be present")
            .contains("HTTP/3 is not available")
    );

    let handshake_comparison = find_comparison(&report, "reverse_proxy", "tls-handshake-h2");
    assert_close(
        handshake_comparison["oxibelt_vs_nginx"]["ratio"]
            .as_f64()
            .expect("handshake nginx ratio should exist"),
        1013.0 / 1263.0,
    );
    assert_close(
        handshake_comparison["oxibelt_vs_caddy"]["ratio"]
            .as_f64()
            .expect("handshake caddy ratio should exist"),
        1013.0 / 913.0,
    );
    assert_eq!(handshake_comparison["oxibelt"]["result_type"], "handshake");

    let accept_tls = find_accept_comparison(&report, "tls-handshake-h2");
    assert_close(
        accept_tls["accept_1_0_vs_0_5"]["ratio"]
            .as_f64()
            .expect("accept multiplier ratio should exist"),
        1571.88 / 714.0,
    );
    assert_close(
        accept_tls["accept_0_5"]["median_rps"]
            .as_f64()
            .expect("accept = 0.5 median should exist"),
        714.0,
    );
    assert_close(
        accept_tls["accept_1_0"]["median_rps"]
            .as_f64()
            .expect("accept = 1.0 median should exist"),
        1571.88,
    );

    let remote_signer_h2 = find_remote_signer_comparison(&report, "h2");
    assert_close(
        remote_signer_h2["remote_signer_vs_local_key"]["throughput_ratio"]
            .as_f64()
            .expect("remote signer h2 throughput ratio should exist"),
        990.0 / 1100.0,
    );
    assert_close(
        remote_signer_h2["remote_signer_vs_local_key"]["p99_ratio"]
            .as_f64()
            .expect("remote signer h2 p99 ratio should exist"),
        8.4 / 6.0,
    );

    let remote_signer_tls = find_remote_signer_comparison(&report, "tls-handshake-h2");
    assert_eq!(remote_signer_tls["local_key"]["result_type"], "handshake");
    assert_close(
        remote_signer_tls["remote_signer_vs_local_key"]["throughput_ratio"]
            .as_f64()
            .expect("remote signer handshake throughput ratio should exist"),
        350.0 / 700.0,
    );
    assert_eq!(
        report["summary"]["remote_signer"]["valid_comparisons"],
        serde_json::json!(4)
    );

    let oxibelt_only_labels = report["oxibelt_only_results"]
        .as_array()
        .expect("oxibelt-only results should be an array")
        .iter()
        .map(|row| row["label"].as_str().expect("label should be a string"))
        .collect::<Vec<_>>();
    assert!(oxibelt_only_labels.contains(&"oxibelt-waf-monitor"));
    assert!(oxibelt_only_labels.contains(&"oxibelt-cache-hit"));
    assert!(oxibelt_only_labels.contains(&"oxibelt-cache-noncacheable-miss"));
    assert!(oxibelt_only_labels.contains(&"oxibelt-cache-cold-fill"));
    assert!(!oxibelt_only_labels.contains(&"oxibelt-h1-keepalive"));
    assert!(!oxibelt_only_labels.contains(&"oxibelt-tls-handshake-h2"));
    assert!(!oxibelt_only_labels.contains(&"oxibelt-accept-0_5-tls-handshake-h2"));
    assert!(!oxibelt_only_labels.contains(&"oxibelt-remote-signer-h2"));

    let missing_rows = report["skipped_or_missing_comparator_rows"]
        .as_array()
        .expect("missing rows should be an array");
    assert!(missing_rows.iter().any(|row| {
        row["scenario"] == "h3" && row["comparator"] == "nginx" && row["status"] == "skipped"
    }));

    let warnings = report["warnings"]
        .as_array()
        .expect("warnings should be an array")
        .iter()
        .map(|warning| warning.as_str().expect("warning should be text"))
        .collect::<Vec<_>>();
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("failed to parse") && warning.contains("line 2")),
        "malformed JSONL lines should produce a warning: {warnings:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("missing string field label")),
        "missing labels should produce a warning: {warnings:?}"
    );
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("missing rps or handshake_per_sec")),
        "missing throughput fields should produce a warning: {warnings:?}"
    );
}

#[test]
fn regression_gates_pass_when_median_recovers_from_low_samples() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-static-files-shard-1/run-1"),
        vec![
            load_row("oxibelt-static-16k-h1c", "h1c", 90.0, 1.0, 4.0),
            load_row("nginx-static-16k-h1c", "h1c", 94.0, 1.0, 4.0),
            load_row("caddy-static-16k-h1c", "h1c", 100.0, 1.0, 4.0),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/run-1"),
        vec![
            load_row("oxibelt-h1-keepalive", "h1", 83.0, 1.0, 4.0),
            load_row("nginx-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("oxibelt-h2", "h2", 83.0, 1.0, 4.0),
            load_row("nginx-h2", "h2", 100.0, 1.0, 4.0),
            load_row("oxibelt-h3", "h3", 83.0, 1.0, 4.0),
            load_row("nginx-h3", "h3", 100.0, 1.0, 4.0),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-remote-signer-shard-1/run-1"),
        vec![
            handshake_row(
                "oxibelt-local-key-tls-handshake-h2",
                "h2",
                1000.0,
                3.0,
                12.0,
            ),
            handshake_row(
                "oxibelt-remote-signer-tls-handshake-h2",
                "h2",
                950.0,
                3.5,
                13.0,
            ),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-oxibelt-features-shard-1/run-1"),
        vec![
            load_row("oxibelt-waf-monitor", "h2", 13000.0, 1.0, 10.0),
            load_row("oxibelt-waf-enforcing", "h2", 12000.0, 1.0, 11.0),
            load_row("oxibelt-crs-monitor", "h2", 10000.0, 1.0, 10.0),
            load_row("oxibelt-crs-enforcing", "h2", 8600.0, 1.0, 11.0),
            load_row("oxibelt-crs-enforcing", "h2", 8700.0, 1.0, 11.0),
            load_row("oxibelt-crs-enforcing", "h2", 9200.0, 1.0, 11.0),
            load_row("oxibelt-crs-enforcing", "h2", 9300.0, 1.0, 11.0),
            load_row("oxibelt-crs-enforcing", "h2", 9400.0, 1.0, 11.0),
        ],
    );

    let report = run_aggregate(&input_dir, &output_dir);
    assert_eq!(report["regression_gates"]["status"], "pass");
    assert_close(
        report["regression_gates"]["thresholds"]["h1_keepalive_min_nginx_ratio"]
            .as_f64()
            .expect("H1 keep-alive threshold should be emitted"),
        0.80,
    );
    assert_close(
        report["regression_gates"]["thresholds"]["h2_min_nginx_ratio"]
            .as_f64()
            .expect("H2 threshold should be emitted"),
        0.80,
    );
    assert_close(
        report["regression_gates"]["thresholds"]["h3_min_nginx_ratio"]
            .as_f64()
            .expect("H3 threshold should be emitted"),
        0.80,
    );
    assert_close(
        report["regression_gates"]["thresholds"]["static_16k_h1c_min_nginx_ratio"]
            .as_f64()
            .expect("static nginx threshold should be emitted"),
        0.90,
    );
    assert_close(
        report["regression_gates"]["thresholds"]["remote_signer_handshake_min_local_ratio"]
            .as_f64()
            .expect("remote signer threshold should be emitted"),
        0.90,
    );
    assert_eq!(
        report["regression_gates"]["violations"]
            .as_array()
            .expect("violations should be an array")
            .len(),
        0
    );
    assert_close(
        find_aggregate(&report, "oxibelt", "crs-enforcing")["median_rps"]
            .as_f64()
            .expect("CRS median RPS should exist"),
        9200.0,
    );
}

#[test]
fn separates_amd64_target_cpus_and_reports_isa_deltas() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    for (target, oxibelt_rps) in [
        ("x86-64-v2", 10.0),
        ("x86-64-v3", 90.0),
        ("x86-64-v4", 120.0),
    ] {
        write_results_array(
            &input_dir.join(format!(
                "oxibelt-docker-performance-smoke-reverse-proxy-shard-1/{target}/run-1"
            )),
            vec![
                with_target_cpu(
                    load_row("oxibelt-h1-keepalive", "h1", 90.0, 1.0, 4.0),
                    target,
                ),
                with_target_cpu(
                    load_row("nginx-h1-keepalive", "h1", 100.0, 1.0, 4.0),
                    target,
                ),
                with_target_cpu(load_row("oxibelt-h2", "h2", oxibelt_rps, 1.0, 4.0), target),
                with_target_cpu(load_row("nginx-h2", "h2", 100.0, 1.0, 4.0), target),
                with_target_cpu(load_row("oxibelt-h3", "h3", 90.0, 1.0, 4.0), target),
                with_target_cpu(load_row("nginx-h3", "h3", 100.0, 1.0, 4.0), target),
            ],
        );
    }

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-static-files-shard-1/x86-64-v3/run-1"),
        vec![
            with_target_cpu(
                load_row("oxibelt-static-16k-h1c", "h1c", 100.0, 1.0, 4.0),
                "x86-64-v3",
            ),
            with_target_cpu(
                load_row("nginx-static-16k-h1c", "h1c", 100.0, 1.0, 4.0),
                "x86-64-v3",
            ),
            with_target_cpu(
                load_row("caddy-static-16k-h1c", "h1c", 100.0, 1.0, 4.0),
                "x86-64-v3",
            ),
        ],
    );
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--primary-target-cpu".to_owned(),
            "x86-64-v3".to_owned(),
            "--expected-target-cpus".to_owned(),
            "x86-64-v2,x86-64-v3,x86-64-v4".to_owned(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "pass");
    assert_eq!(
        find_aggregate_for_target(&report, "x86-64-v2", "oxibelt", "h2")["sample_count"],
        1
    );
    assert_eq!(
        find_aggregate_for_target(&report, "x86-64-v3", "oxibelt", "h2")["sample_count"],
        1
    );

    let h2 = find_isa_comparison(&report, "h2");
    let variants = h2["variants"]
        .as_array()
        .expect("ISA variants should be an array");
    let v2 = variants
        .iter()
        .find(|variant| variant["amd64_target_cpu"] == "x86-64-v2")
        .expect("v2 ISA comparison should exist");
    let v4 = variants
        .iter()
        .find(|variant| variant["amd64_target_cpu"] == "x86-64-v4")
        .expect("v4 ISA comparison should exist");
    assert_close(
        v2["rps_delta_percent_vs_primary"]
            .as_f64()
            .expect("v2 RPS delta should exist"),
        ((10.0 - 90.0) / 90.0) * 100.0,
    );
    assert_close(
        v4["rps_delta_percent_vs_primary"]
            .as_f64()
            .expect("v4 RPS delta should exist"),
        ((120.0 - 90.0) / 90.0) * 100.0,
    );

    let markdown = fs::read_to_string(output_dir.join("performance-comparison.md"))
        .expect("markdown report should be readable");
    assert!(markdown.contains("## AMD64 ISA comparison"));
    assert!(markdown.contains("| `reverse-proxy` | `h2` | `x86-64-v2` |"));
}

#[test]
fn h2_ratio_gate_advises_when_baseline_gap_is_stable() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h2(&input_dir, 135.0, 205.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_baseline_report(
        &baseline_path,
        vec![
            aggregate_row("oxibelt", "h2", "reverse-proxy", 136.0, 10.0),
            aggregate_row("nginx", "h2", "reverse-proxy", 206.0, 10.0),
        ],
    );

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "pass");
    let advisory = find_regression_advisory(&report, "h2_min_nginx_ratio", "h2");
    assert_eq!(advisory["disposition"], "advisory");
    assert_close(
        advisory["observed"]
            .as_f64()
            .expect("advisory ratio should exist"),
        135.0 / 205.0,
    );
    assert!(
        advisory["message"]
            .as_str()
            .expect("message should be present")
            .contains("baseline-stable ratio gap")
    );

    let markdown = fs::read_to_string(output_dir.join("performance-comparison.md"))
        .expect("markdown report should be readable");
    assert!(markdown.contains("### Advisories"));
    assert!(markdown.contains("`h2_min_nginx_ratio`"));
}

#[test]
fn h1_keepalive_ratio_gate_blocks_when_target_misses() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/run-1"),
        vec![
            load_row("oxibelt-h1-keepalive", "h1", 79.0, 1.0, 4.0),
            load_row("nginx-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("oxibelt-h2", "h2", 100.0, 1.0, 4.0),
            load_row("nginx-h2", "h2", 100.0, 1.0, 4.0),
            load_row("oxibelt-h3", "h3", 100.0, 1.0, 4.0),
            load_row("nginx-h3", "h3", 100.0, 1.0, 4.0),
        ],
    );
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);

    let report = run_aggregate(&input_dir, &output_dir);

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    assert_eq!(violation["comparator"], "nginx");
    assert_close(
        violation["observed"]
            .as_f64()
            .expect("H1 keep-alive ratio should exist"),
        0.79,
    );
}

#[test]
fn h1_keepalive_ratio_gate_advises_when_near_target_baseline_remains_stable() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h1_with_p99(&input_dir, 22579.750, 28253.3125, 1.6795, 1.437);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_h1_baseline_report(&baseline_path, 23115.9375, 28388.5, 1.5535, 1.3895);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "pass");
    let advisory =
        find_regression_advisory(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(advisory["disposition"], "advisory");
    assert_close(
        advisory["observed"]
            .as_f64()
            .expect("advisory ratio should exist"),
        22579.750 / 28253.3125,
    );
    let message = advisory["message"]
        .as_str()
        .expect("message should be present");
    assert!(message.contains("near-target ratio miss"));
    assert!(message.contains("baseline RPS ratio"));

    let markdown = fs::read_to_string(output_dir.join("performance-comparison.md"))
        .expect("markdown report should be readable");
    assert!(markdown.contains("### Advisories"));
    assert!(markdown.contains("`h1_keepalive_min_nginx_ratio`"));
}

#[test]
fn h1_keepalive_near_target_miss_blocks_without_baseline_report() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    write_reverse_proxy_h1_with_p99(&input_dir, 79.91894755703424, 100.0, 10.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);

    let report = run_aggregate(&input_dir, &output_dir);

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    let message = violation["message"]
        .as_str()
        .expect("message should be present");
    assert!(message.contains("baseline-aware advisory unavailable"));
    assert!(message.contains("no baseline performance report was provided"));
}

#[test]
fn h1_keepalive_near_target_miss_blocks_when_baseline_also_misses() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h1_with_p99(&input_dir, 79.91894755703424, 100.0, 10.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_h1_baseline_report(&baseline_path, 79.0, 100.0, 10.0, 10.0);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("did not qualify for baseline-stable advisory pass")
    );
}

#[test]
fn h1_keepalive_near_target_miss_blocks_when_ratio_regresses() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h1_with_p99(&input_dir, 79.91894755703424, 100.0, 10.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_h1_baseline_report(&baseline_path, 83.0, 100.0, 10.0, 10.0);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("did not qualify for baseline-stable advisory pass")
    );
}

#[test]
fn h1_keepalive_near_target_miss_blocks_when_relative_p99_regresses() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h1_with_p99(&input_dir, 79.91894755703424, 100.0, 10.6, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_h1_baseline_report(&baseline_path, 81.0, 100.0, 10.0, 10.0);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("did not qualify for baseline-stable advisory pass")
    );
}

#[test]
fn h1_keepalive_ratio_gate_advises_when_comparator_shift_keeps_oxibelt_stable() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h1_with_p99(&input_dir, 22811.125, 28942.3125, 1.6205, 1.356);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_h1_baseline_report(&baseline_path, 23115.9375, 28388.5, 1.5535, 1.3895);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "pass");
    let advisory =
        find_regression_advisory(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(advisory["disposition"], "advisory");
    assert_close(
        advisory["observed"]
            .as_f64()
            .expect("advisory ratio should exist"),
        22811.125 / 28942.3125,
    );
    let message = advisory["message"]
        .as_str()
        .expect("message should be present");
    assert!(message.contains("comparator-shift ratio miss"));
    assert!(message.contains("comparator RPS"));
}

#[test]
fn h1_keepalive_comparator_shift_miss_blocks_below_floor() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h1_with_p99(&input_dir, 78.4, 100.0, 10.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_h1_baseline_report(&baseline_path, 81.0, 100.0, 10.0, 10.0);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("below comparator-shift advisory floor")
    );
}

#[test]
fn h1_keepalive_comparator_shift_miss_blocks_without_baseline_report() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    write_reverse_proxy_h1_with_p99(&input_dir, 78.8, 100.0, 10.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);

    let report = run_aggregate(&input_dir, &output_dir);

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    let message = violation["message"]
        .as_str()
        .expect("message should be present");
    assert!(message.contains("baseline-aware advisory unavailable"));
    assert!(message.contains("no baseline performance report was provided"));
}

#[test]
fn h1_keepalive_comparator_shift_miss_blocks_when_baseline_also_misses() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h1_with_p99(&input_dir, 78.8, 100.0, 10.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_h1_baseline_report(&baseline_path, 79.0, 100.0, 10.0, 10.0);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("did not qualify for baseline-stable advisory pass")
    );
}

#[test]
fn h1_keepalive_comparator_shift_miss_blocks_when_oxibelt_rps_regresses() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h1_with_p99(&input_dir, 78.8, 100.0, 10.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_h1_baseline_report(&baseline_path, 82.0, 100.0, 10.0, 10.0);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("OxiBelt RPS -3.9%")
    );
}

#[test]
fn h1_keepalive_comparator_shift_miss_blocks_when_oxibelt_p99_regresses() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h1_with_p99(&input_dir, 78.8, 100.0, 10.6, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_h1_baseline_report(&baseline_path, 81.0, 100.0, 10.0, 10.0);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation =
        find_regression_violation(&report, "h1_keepalive_min_nginx_ratio", "h1-keepalive");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("OxiBelt p99 +6.0%")
    );
}

#[test]
fn h2_ratio_gate_advises_current_ci_shape_until_target_ratio_recovers() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h2_with_p99(&input_dir, 12617.6875, 18083.0625, 2.531, 2.039);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_baseline_report(
        &baseline_path,
        vec![
            aggregate_row("oxibelt", "h2", "reverse-proxy", 13463.5625, 2.361),
            aggregate_row("nginx", "h2", "reverse-proxy", 19575.9375, 1.982),
        ],
    );

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "pass");
    let advisory = find_regression_advisory(&report, "h2_min_nginx_ratio", "h2");
    assert_close(
        advisory["observed"]
            .as_f64()
            .expect("advisory ratio should exist"),
        12617.6875 / 18083.0625,
    );
    let message = advisory["message"]
        .as_str()
        .expect("message should be present");
    assert!(message.contains("baseline-stable ratio gap"));
}

#[test]
fn h3_ratio_gate_advises_when_baseline_gap_is_stable() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h3_with_p99(&input_dir, 14201.375, 18953.750, 2.701, 2.201);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_baseline_report(
        &baseline_path,
        vec![
            aggregate_row("oxibelt", "h3", "reverse-proxy", 14187.1875, 2.690),
            aggregate_row("nginx", "h3", "reverse-proxy", 19008.6875, 2.190),
        ],
    );

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "pass");
    let advisory = find_regression_advisory(&report, "h3_min_nginx_ratio", "h3");
    assert_eq!(advisory["disposition"], "advisory");
    assert_close(
        advisory["observed"]
            .as_f64()
            .expect("advisory ratio should exist"),
        14201.375 / 18953.750,
    );
    assert!(
        advisory["message"]
            .as_str()
            .expect("message should be present")
            .contains("baseline-stable ratio gap")
    );
}

#[test]
fn h3_ratio_gate_advises_when_comparator_p99_improvement_moves_relative_tail_ratio() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h3_with_p99(&input_dir, 14114.375, 18552.750, 2.806, 2.106);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_baseline_report(
        &baseline_path,
        vec![
            aggregate_row("oxibelt", "h3", "reverse-proxy", 12892.4375, 2.864),
            aggregate_row("nginx", "h3", "reverse-proxy", 16683.8125, 2.264),
        ],
    );

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "pass");
    let advisory = find_regression_advisory(&report, "h3_min_nginx_ratio", "h3");
    assert_eq!(advisory["disposition"], "advisory");
    assert_close(
        advisory["observed"]
            .as_f64()
            .expect("advisory ratio should exist"),
        14114.375 / 18552.750,
    );
    let message = advisory["message"]
        .as_str()
        .expect("message should be present");
    assert!(message.contains("baseline-stable ratio gap"));
    assert!(message.contains("OxiBelt p99 -2.0%"));
    assert!(message.contains("comparator p99 -7.0%"));
}

#[test]
fn h2_ratio_gate_blocks_when_baseline_passes_and_current_misses() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h2(&input_dir, 100.0, 140.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_baseline_report(
        &baseline_path,
        vec![
            aggregate_row("oxibelt", "h2", "reverse-proxy", 100.0, 10.0),
            aggregate_row("nginx", "h2", "reverse-proxy", 100.0, 10.0),
        ],
    );

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation = find_regression_violation(&report, "h2_min_nginx_ratio", "h2");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("baseline evidence from")
    );
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("did not qualify for advisory pass")
    );
}

#[test]
fn h2_ratio_gate_blocks_when_ratio_regresses_against_low_baseline() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h2(&input_dir, 90.0, 150.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_baseline_report(
        &baseline_path,
        vec![
            aggregate_row("oxibelt", "h2", "reverse-proxy", 100.0, 10.0),
            aggregate_row("nginx", "h2", "reverse-proxy", 150.0, 10.0),
        ],
    );

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation = find_regression_violation(&report, "h2_min_nginx_ratio", "h2");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("baseline evidence from")
    );
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("did not qualify for advisory pass")
    );
}

#[test]
fn h2_ratio_gate_blocks_when_relative_p99_regresses_against_low_baseline() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h2(&input_dir, 99.0, 149.0, 11.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_baseline_report(
        &baseline_path,
        vec![
            aggregate_row("oxibelt", "h2", "reverse-proxy", 100.0, 10.0),
            aggregate_row("nginx", "h2", "reverse-proxy", 150.0, 10.0),
        ],
    );

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation = find_regression_violation(&report, "h2_min_nginx_ratio", "h2");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("baseline evidence from")
    );
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("did not qualify for advisory pass")
    );
}

#[test]
fn static_and_remote_signer_ratio_gates_become_advisories_when_baseline_gap_is_stable() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h2(&input_dir, 100.0, 100.0, 10.0);
    write_static_gate_rows(&input_dir, 88.5, 99.5, 111.5);
    write_remote_signer_gate_rows(&input_dir, 885.0, 995.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);
    write_baseline_report(
        &baseline_path,
        vec![
            aggregate_row("oxibelt", "static-16k-h1c", "static-files", 89.0, 10.0),
            aggregate_row("nginx", "static-16k-h1c", "static-files", 100.0, 10.0),
            aggregate_row("caddy", "static-16k-h1c", "static-files", 112.0, 10.0),
            aggregate_row(
                "oxibelt",
                "remote-signer-tls-handshake-h2",
                "remote-signer",
                890.0,
                10.0,
            ),
            aggregate_row(
                "oxibelt",
                "local-key-tls-handshake-h2",
                "remote-signer",
                1000.0,
                10.0,
            ),
        ],
    );

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "pass");
    find_regression_advisory(&report, "static_16k_h1c_min_caddy_ratio", "static-16k-h1c");
    find_regression_advisory(&report, "static_16k_h1c_min_nginx_ratio", "static-16k-h1c");
    find_regression_advisory(
        &report,
        "remote_signer_handshake_min_local_ratio",
        "tls-handshake-h2",
    );
}

#[test]
fn oxibelt_only_rps_and_p99_gates_become_advisories_when_baseline_stable() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_reverse_proxy_h2(&input_dir, 100.0, 100.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 9900.0, 7900.0, 8.0, 11.0);
    write_baseline_report(
        &baseline_path,
        vec![
            aggregate_row("oxibelt", "waf-monitor", "oxibelt-only", 13000.0, 10.0),
            aggregate_row("oxibelt", "waf-enforcing", "oxibelt-only", 9900.0, 11.0),
            aggregate_row("oxibelt", "crs-monitor", "oxibelt-only", 10000.0, 10.0),
            aggregate_row("oxibelt", "crs-enforcing", "oxibelt-only", 7900.0, 11.0),
        ],
    );

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "pass");
    find_regression_advisory(&report, "waf_enforcing_min_rps", "waf-enforcing");
    find_regression_advisory(&report, "crs_enforcing_min_rps", "crs-enforcing");
    find_regression_advisory(&report, "waf_enforce_p99_ratio", "waf-enforcing");
    find_regression_advisory(&report, "crs_enforce_p99_ratio", "crs-enforcing");
}

#[test]
fn threshold_misses_remain_blocking_when_baseline_report_is_unreadable() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("missing-performance-comparison.json");

    write_reverse_proxy_h2(&input_dir, 70.0, 100.0, 10.0);
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);

    let report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &[
            "--baseline-report".to_owned(),
            baseline_path.display().to_string(),
        ],
    );

    assert_eq!(report["regression_gates"]["status"], "fail");
    let violation = find_regression_violation(&report, "h2_min_nginx_ratio", "h2");
    assert_eq!(violation["disposition"], "blocking");
    assert!(
        violation["message"]
            .as_str()
            .expect("message should be present")
            .contains("baseline-aware advisory unavailable")
    );
    let warnings = report["warnings"]
        .as_array()
        .expect("warnings should be an array")
        .iter()
        .map(|warning| warning.as_str().expect("warning should be text"))
        .collect::<Vec<_>>();
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("failed to read baseline performance report")),
        "unreadable baseline should produce a warning: {warnings:?}"
    );
}

#[test]
fn h2_and_h3_ratio_misses_remain_blocking_without_baseline_report() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/run-1"),
        vec![
            load_row("oxibelt-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("nginx-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("oxibelt-h2", "h2", 70.0, 1.0, 4.0),
            load_row("nginx-h2", "h2", 100.0, 1.0, 4.0),
            load_row("oxibelt-h3", "h3", 74.0, 1.0, 4.0),
            load_row("nginx-h3", "h3", 100.0, 1.0, 4.0),
        ],
    );
    write_static_gate_rows(&input_dir, 100.0, 100.0, 100.0);
    write_remote_signer_gate_rows(&input_dir, 1000.0, 1000.0);
    write_feature_gate_rows(&input_dir, 12000.0, 9200.0, 10.0, 10.0);

    let report = run_aggregate(&input_dir, &output_dir);

    assert_eq!(report["regression_gates"]["status"], "fail");
    for (gate, scenario) in [("h2_min_nginx_ratio", "h2"), ("h3_min_nginx_ratio", "h3")] {
        let violation = find_regression_violation(&report, gate, scenario);
        assert_eq!(violation["disposition"], "blocking");
        let message = violation["message"]
            .as_str()
            .expect("message should be present");
        assert!(message.contains("baseline-aware advisory unavailable"));
        assert!(message.contains("no baseline performance report was provided"));
    }

    let warnings = report["warnings"]
        .as_array()
        .expect("warnings should be an array")
        .iter()
        .map(|warning| warning.as_str().expect("warning should be text"))
        .collect::<Vec<_>>();
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("baseline performance report was not provided")),
        "missing baseline should produce a warning: {warnings:?}"
    );
}

#[test]
fn regression_gates_fail_closed_when_static_comparator_is_missing() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-static-files-shard-1/run-1"),
        vec![load_row("oxibelt-static-16k-h1c", "h1c", 800.0, 1.0, 4.0)],
    );

    let report = run_aggregate(&input_dir, &output_dir);
    assert_eq!(report["regression_gates"]["status"], "fail");

    let static_missing =
        find_regression_violation(&report, "static_16k_h1c_min_caddy_ratio", "static-16k-h1c");
    assert_eq!(static_missing["metric"], "median_rps");
    assert_eq!(static_missing["observed"], Value::Null);
    assert_eq!(static_missing["comparator"], "caddy");
    assert!(
        static_missing["message"]
            .as_str()
            .expect("message should be present")
            .contains("missing Caddy static-16k-h1c median RPS")
    );
}

#[test]
fn regression_gates_fail_closed_when_required_metrics_are_malformed() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-static-files-shard-1/run-1"),
        vec![
            load_row("oxibelt-static-16k-h1c", "h1c", 900.0, 1.0, 4.0),
            load_row_without_rps("caddy-static-16k-h1c", "h1c", 1.0, 4.0),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-oxibelt-features-shard-1/run-1"),
        vec![
            load_row_without_p99("oxibelt-waf-monitor", "h2", 13000.0, 1.0),
            load_row("oxibelt-waf-enforcing", "h2", 12000.0, 1.0, 11.0),
            load_row("oxibelt-crs-monitor", "h2", 10000.0, 1.0, 10.0),
            load_row("oxibelt-crs-enforcing", "h2", 9200.0, 1.0, 11.0),
        ],
    );

    let report = run_aggregate(&input_dir, &output_dir);
    assert_eq!(report["regression_gates"]["status"], "fail");

    let static_missing =
        find_regression_violation(&report, "static_16k_h1c_min_caddy_ratio", "static-16k-h1c");
    assert_eq!(static_missing["observed"], Value::Null);
    assert_eq!(static_missing["comparator"], "caddy");

    let waf_p99 = find_regression_violation(&report, "waf_enforce_p99_ratio", "waf-enforcing");
    assert_eq!(waf_p99["metric"], "median_p99_ms");
    assert_eq!(waf_p99["observed"], Value::Null);
    assert_eq!(waf_p99["comparator"], "waf-monitor");
    assert!(
        waf_p99["message"]
            .as_str()
            .expect("message should be present")
            .contains("missing OxiBelt waf-monitor median p99")
    );
}

#[test]
fn regression_gates_fail_closed_when_no_samples_are_available() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    fs::create_dir_all(&input_dir).expect("input directory should be created");

    let report = run_aggregate(&input_dir, &output_dir);
    assert_eq!(report["regression_gates"]["status"], "fail");
    assert!(
        report["regression_gates"]["violations"]
            .as_array()
            .expect("violations should be an array")
            .len()
            >= 9,
        "every required regression gate should fail closed when no samples exist"
    );

    let static_missing =
        find_regression_violation(&report, "static_16k_h1c_min_caddy_ratio", "static-16k-h1c");
    assert_eq!(static_missing["observed"], Value::Null);
    assert_eq!(static_missing["comparator"], "oxibelt");
}

#[test]
fn regression_gates_fail_closed_when_required_metrics_are_non_positive() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-static-files-shard-1/run-1"),
        vec![
            load_row("oxibelt-static-16k-h1c", "h1c", 900.0, 1.0, 4.0),
            load_row("caddy-static-16k-h1c", "h1c", 0.0, 1.0, 4.0),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-oxibelt-features-shard-1/run-1"),
        vec![
            load_row("oxibelt-waf-monitor", "h2", 13000.0, 1.0, 0.0),
            load_row("oxibelt-waf-enforcing", "h2", 12000.0, 1.0, 11.0),
            load_row("oxibelt-crs-monitor", "h2", 10000.0, 1.0, 10.0),
            load_row("oxibelt-crs-enforcing", "h2", 9200.0, 1.0, 11.0),
        ],
    );

    let report = run_aggregate(&input_dir, &output_dir);
    assert_eq!(report["regression_gates"]["status"], "fail");

    let static_invalid =
        find_regression_violation(&report, "static_16k_h1c_min_caddy_ratio", "static-16k-h1c");
    assert_close(
        static_invalid["observed"]
            .as_f64()
            .expect("invalid Caddy RPS should be recorded"),
        0.0,
    );
    assert_eq!(static_invalid["comparator"], "caddy");

    let waf_p99 = find_regression_violation(&report, "waf_enforce_p99_ratio", "waf-enforcing");
    assert_close(
        waf_p99["observed"]
            .as_f64()
            .expect("invalid monitor p99 should be recorded"),
        0.0,
    );
    assert_eq!(waf_p99["comparator"], "waf-monitor");
}

#[test]
fn regression_gates_report_static_crs_and_p99_violations() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-static-files-shard-1/run-1"),
        vec![
            load_row("oxibelt-static-16k-h1c", "h1c", 79.0, 1.0, 4.0),
            load_row("nginx-static-16k-h1c", "h1c", 100.0, 1.0, 4.0),
            load_row("caddy-static-16k-h1c", "h1c", 100.0, 1.0, 4.0),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/run-1"),
        vec![
            load_row("oxibelt-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("nginx-h1-keepalive", "h1", 100.0, 1.0, 4.0),
            load_row("oxibelt-h2", "h2", 74.0, 1.0, 4.0),
            load_row("nginx-h2", "h2", 100.0, 1.0, 4.0),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-remote-signer-shard-1/run-1"),
        vec![
            handshake_row(
                "oxibelt-local-key-tls-handshake-h2",
                "h2",
                1000.0,
                3.0,
                12.0,
            ),
            handshake_row(
                "oxibelt-remote-signer-tls-handshake-h2",
                "h2",
                890.0,
                4.0,
                14.0,
            ),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-oxibelt-features-shard-1/run-1"),
        vec![
            load_row("oxibelt-waf-monitor", "h2", 13000.0, 1.0, 10.0),
            load_row("oxibelt-waf-enforcing", "h2", 12000.0, 1.0, 14.0),
            load_row("oxibelt-crs-monitor", "h2", 10000.0, 1.0, 10.0),
            load_row("oxibelt-crs-enforcing", "h2", 7900.0, 1.0, 14.0),
        ],
    );

    let report = run_aggregate(&input_dir, &output_dir);
    assert_eq!(report["regression_gates"]["status"], "fail");
    let markdown = fs::read_to_string(output_dir.join("performance-comparison.md"))
        .expect("markdown report should be readable");
    assert!(markdown.contains("`h2_min_nginx_ratio`"));
    assert!(markdown.contains("`static_16k_h1c_min_nginx_ratio`"));
    assert!(markdown.contains("`remote_signer_handshake_min_local_ratio`"));

    let static_ratio =
        find_regression_violation(&report, "static_16k_h1c_min_caddy_ratio", "static-16k-h1c");
    assert_eq!(static_ratio["metric"], "median_rps_ratio");
    assert_close(
        static_ratio["observed"]
            .as_f64()
            .expect("static ratio should exist"),
        0.79,
    );

    let h2_ratio = find_regression_violation(&report, "h2_min_nginx_ratio", "h2");
    assert_eq!(h2_ratio["metric"], "median_rps_ratio");
    assert_close(
        h2_ratio["observed"]
            .as_f64()
            .expect("H2 ratio should exist"),
        0.74,
    );
    assert_eq!(h2_ratio["comparator"], "nginx");

    let static_nginx_ratio =
        find_regression_violation(&report, "static_16k_h1c_min_nginx_ratio", "static-16k-h1c");
    assert_eq!(static_nginx_ratio["metric"], "median_rps_ratio");
    assert_close(
        static_nginx_ratio["observed"]
            .as_f64()
            .expect("static nginx ratio should exist"),
        0.79,
    );
    assert_eq!(static_nginx_ratio["comparator"], "nginx");

    let remote_signer_ratio = find_regression_violation(
        &report,
        "remote_signer_handshake_min_local_ratio",
        "tls-handshake-h2",
    );
    assert_eq!(remote_signer_ratio["metric"], "median_rps_ratio");
    assert_close(
        remote_signer_ratio["observed"]
            .as_f64()
            .expect("remote signer handshake ratio should exist"),
        0.89,
    );
    assert_eq!(remote_signer_ratio["comparator"], "local-key");

    let crs_min = find_regression_violation(&report, "crs_enforcing_min_rps", "crs-enforcing");
    assert_eq!(crs_min["metric"], "median_rps");
    assert_close(
        crs_min["observed"].as_f64().expect("CRS RPS should exist"),
        7900.0,
    );

    let waf_p99 = find_regression_violation(&report, "waf_enforce_p99_ratio", "waf-enforcing");
    assert_eq!(waf_p99["metric"], "median_p99_ratio");
    assert_close(
        waf_p99["observed"]
            .as_f64()
            .expect("WAF p99 ratio should exist"),
        1.4,
    );

    let crs_p99 = find_regression_violation(&report, "crs_enforce_p99_ratio", "crs-enforcing");
    assert_eq!(crs_p99["metric"], "median_p99_ratio");
    assert_close(
        crs_p99["observed"]
            .as_f64()
            .expect("CRS p99 ratio should exist"),
        1.4,
    );
}

#[test]
fn baseline_delta_classifies_comparator_shift_and_oxibelt_regression() {
    let temp_dir = TempDir::new();
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("output");
    let baseline_path = temp_dir.path().join("baseline-performance-comparison.json");

    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-static-files-shard-1/run-1"),
        vec![
            load_row("oxibelt-static-16k-h1c", "h1c", 105.0, 1.0, 4.0),
            load_row("nginx-static-16k-h1c", "h1c", 125.0, 2.0, 5.0),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/run-1"),
        vec![
            load_row("oxibelt-h1-keepalive", "h1", 90.0, 1.0, 6.0),
            load_row("nginx-h1-keepalive", "h1", 100.0, 2.0, 5.0),
        ],
    );
    fs::write(
        &baseline_path,
        serde_json::to_string_pretty(&json!({
            "aggregates": [
                aggregate_row("oxibelt", "static-16k-h1c", "static-files", 100.0, 4.0),
                aggregate_row("nginx", "static-16k-h1c", "static-files", 100.0, 5.0),
                aggregate_row("oxibelt", "h1-keepalive", "reverse-proxy", 100.0, 4.0),
                aggregate_row("nginx", "h1-keepalive", "reverse-proxy", 100.0, 5.0)
            ]
        }))
        .expect("baseline should serialize"),
    )
    .expect("baseline should be written");

    let baseline_arg = baseline_path.display().to_string();
    let _report = run_aggregate_with_args(
        &input_dir,
        &output_dir,
        &["--baseline-report".to_owned(), baseline_arg],
    );
    let delta_path = output_dir.join("performance-delta.json");
    let raw = fs::read_to_string(&delta_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", delta_path.display()));
    let delta: Value = serde_json::from_str(&raw).expect("delta JSON should parse");

    let static_nginx = find_delta(&delta, "static-files", "static-16k-h1c", "nginx");
    assert_eq!(static_nginx["classification"], "comparator_shift");
    assert!(
        static_nginx["reason"]
            .as_str()
            .expect("reason should be present")
            .contains("comparator rose")
    );
    assert_close(
        static_nginx["oxibelt_rps_delta_percent"]
            .as_f64()
            .expect("OxiBelt delta should exist"),
        5.0,
    );
    assert_close(
        static_nginx["comparator_rps_delta_percent"]
            .as_f64()
            .expect("comparator delta should exist"),
        25.0,
    );

    let h1_nginx = find_delta(&delta, "reverse-proxy", "h1-keepalive", "nginx");
    assert_eq!(h1_nginx["classification"], "oxibelt_regression");
    assert_close(
        h1_nginx["oxibelt_rps_delta_percent"]
            .as_f64()
            .expect("OxiBelt delta should exist"),
        -10.0,
    );

    let markdown = fs::read_to_string(output_dir.join("performance-delta.md"))
        .expect("delta markdown should be written");
    assert!(markdown.contains("## Scenario deltas"));
    assert!(markdown.contains("`comparator_shift`"));
}
