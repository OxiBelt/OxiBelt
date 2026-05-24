use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "oxibelt-performance-aggregate-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp directory should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
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
        "OXIBELT_PERF_H2_MIN_NGINX_RATIO",
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

    assert_eq!(report["schema_version"], 4);

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
            load_row("oxibelt-h2", "h2", 83.0, 1.0, 4.0),
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
        report["regression_gates"]["thresholds"]["h2_min_nginx_ratio"]
            .as_f64()
            .expect("H2 threshold should be emitted"),
        0.80,
    );
    assert_close(
        report["regression_gates"]["thresholds"]["static_16k_h1c_min_nginx_ratio"]
            .as_f64()
            .expect("static nginx threshold should be emitted"),
        0.95,
    );
    assert_close(
        report["regression_gates"]["thresholds"]["remote_signer_handshake_min_local_ratio"]
            .as_f64()
            .expect("remote signer threshold should be emitted"),
        0.95,
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
            >= 8,
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
            load_row("oxibelt-static-16k-h1c", "h1c", 80.0, 1.0, 4.0),
            load_row("nginx-static-16k-h1c", "h1c", 100.0, 1.0, 4.0),
            load_row("caddy-static-16k-h1c", "h1c", 100.0, 1.0, 4.0),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-reverse-proxy-shard-1/run-1"),
        vec![
            load_row("oxibelt-h2", "h2", 75.0, 1.0, 4.0),
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
                900.0,
                4.0,
                14.0,
            ),
        ],
    );
    write_results_array(
        &input_dir.join("oxibelt-docker-performance-smoke-oxibelt-features-shard-1/run-1"),
        vec![
            load_row("oxibelt-waf-monitor", "h2", 13000.0, 1.0, 10.0),
            load_row("oxibelt-waf-enforcing", "h2", 12000.0, 1.0, 13.0),
            load_row("oxibelt-crs-monitor", "h2", 10000.0, 1.0, 10.0),
            load_row("oxibelt-crs-enforcing", "h2", 8700.0, 1.0, 13.0),
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
        0.8,
    );

    let h2_ratio = find_regression_violation(&report, "h2_min_nginx_ratio", "h2");
    assert_eq!(h2_ratio["metric"], "median_rps_ratio");
    assert_close(
        h2_ratio["observed"]
            .as_f64()
            .expect("H2 ratio should exist"),
        0.75,
    );
    assert_eq!(h2_ratio["comparator"], "nginx");

    let static_nginx_ratio =
        find_regression_violation(&report, "static_16k_h1c_min_nginx_ratio", "static-16k-h1c");
    assert_eq!(static_nginx_ratio["metric"], "median_rps_ratio");
    assert_close(
        static_nginx_ratio["observed"]
            .as_f64()
            .expect("static nginx ratio should exist"),
        0.8,
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
        0.9,
    );
    assert_eq!(remote_signer_ratio["comparator"], "local-key");

    let crs_min = find_regression_violation(&report, "crs_enforcing_min_rps", "crs-enforcing");
    assert_eq!(crs_min["metric"], "median_rps");
    assert_close(
        crs_min["observed"].as_f64().expect("CRS RPS should exist"),
        8700.0,
    );

    let waf_p99 = find_regression_violation(&report, "waf_enforce_p99_ratio", "waf-enforcing");
    assert_eq!(waf_p99["metric"], "median_p99_ratio");
    assert_close(
        waf_p99["observed"]
            .as_f64()
            .expect("WAF p99 ratio should exist"),
        1.3,
    );

    let crs_p99 = find_regression_violation(&report, "crs_enforce_p99_ratio", "crs-enforcing");
    assert_eq!(crs_p99["metric"], "median_p99_ratio");
    assert_close(
        crs_p99["observed"]
            .as_f64()
            .expect("CRS p99 ratio should exist"),
        1.3,
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
