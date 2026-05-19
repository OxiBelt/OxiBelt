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
    let output = Command::new(aggregate_binary())
        .arg("--input-dir")
        .arg(input_dir)
        .arg("--output-dir")
        .arg(output_dir)
        .output()
        .expect("aggregate binary should run");
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
            "label": "oxibelt-cache-miss",
            "protocol": "h2",
            "requests": 100,
            "p50_ms": 1.0,
            "p99_ms": 3.0,
            "errors": 0
        })
        .to_string(),
    ]
    .join("\n");
    fs::write(jsonl_dir.join("results.json"), jsonl).expect("jsonl results should be written");

    let report = run_aggregate(&input_dir, &output_dir);

    assert_eq!(report["schema_version"], 2);

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

    let oxibelt_only_labels = report["oxibelt_only_results"]
        .as_array()
        .expect("oxibelt-only results should be an array")
        .iter()
        .map(|row| row["label"].as_str().expect("label should be a string"))
        .collect::<Vec<_>>();
    assert!(oxibelt_only_labels.contains(&"oxibelt-waf-monitor"));
    assert!(oxibelt_only_labels.contains(&"oxibelt-cache-hit"));
    assert!(oxibelt_only_labels.contains(&"oxibelt-cache-miss"));
    assert!(!oxibelt_only_labels.contains(&"oxibelt-h1-keepalive"));
    assert!(!oxibelt_only_labels.contains(&"oxibelt-accept-0_5-tls-handshake-h2"));

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
