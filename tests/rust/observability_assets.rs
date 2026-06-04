use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

const OBSERVABILITY_DIR: &str = "deploy/observability";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("source crate should have a repository parent")
        .to_path_buf()
}

fn read_repo(path: &str) -> String {
    let full_path = repo_root().join(path);
    fs::read_to_string(&full_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", full_path.display()))
}

fn read_observability(path: &str) -> String {
    read_repo(&format!("{OBSERVABILITY_DIR}/{path}"))
}

#[test]
fn grafana_dashboard_is_valid_json_with_oxibelt_promql() {
    let raw = read_observability("grafana/dashboards/oxibelt-overview.json");
    let dashboard: Value =
        serde_json::from_str(&raw).expect("OxiBelt Grafana dashboard should parse as JSON");

    assert_eq!(
        dashboard["title"].as_str(),
        Some("OxiBelt Operator Overview")
    );
    assert!(
        dashboard["panels"]
            .as_array()
            .is_some_and(|panels| panels.len() >= 8),
        "dashboard should include the operator overview panels"
    );

    let mut expressions = Vec::new();
    collect_promql_expressions(&dashboard, &mut expressions);
    assert!(
        expressions.len() >= 8,
        "dashboard should contain Prometheus expressions"
    );
    for expression in expressions {
        assert!(
            expression.contains("oxibelt_"),
            "dashboard expression should use OxiBelt metrics: {expression}"
        );
    }
}

#[test]
fn observability_bundle_wires_prometheus_and_grafana_assets() {
    let prometheus = read_observability("prometheus.yml");
    assert!(prometheus.contains("metrics_path: /metrics"));
    assert!(prometheus.contains("oxibelt:9090"));

    let collector = read_observability("otel-collector.yaml");
    assert!(collector.contains("0.0.0.0:4318"));
    assert!(collector.contains("traces:"));

    let dashboards = read_observability("grafana/provisioning/dashboards/oxibelt.yml");
    assert!(dashboards.contains("/etc/grafana/provisioning/dashboards/oxibelt"));

    let datasource = read_observability("grafana/provisioning/datasources/oxibelt.yml");
    assert!(datasource.contains("url: http://prometheus:9090"));
}

#[test]
fn observability_docs_keep_opt_in_private_defaults() {
    let docs = read_repo("docs/Observability.md");
    assert!(docs.contains("bind = \"127.0.0.1:9090\""));
    assert!(docs.contains("bind = \"127.0.0.1:9091\""));
    assert!(docs.contains("private Docker or"));
    assert!(docs.contains("propagate_trace_context = false"));
    assert!(docs.contains("GET /admin/v1/waf/rule-hits"));
}

#[test]
fn public_observability_assets_avoid_sensitive_examples() {
    let mut scanned = Vec::new();
    collect_files(&repo_root().join(OBSERVABILITY_DIR), &mut scanned);
    scanned.push(repo_root().join("docs/Observability.md"));

    let forbidden = [
        "Request.Headers.getAll('Authorization')",
        "Request.Headers.getAll(\"Authorization\")",
        "Request.Headers.getAll('Cookie')",
        "Request.Headers.getAll(\"Cookie\")",
        "Request.Headers.getAll('Set-Cookie')",
        "Request.Headers.getAll(\"Set-Cookie\")",
        "bearer_token",
        "admin token",
        "rule_name",
        "rule_id",
        "obs-cost-rule",
        "obs-cost-tag",
    ];

    for path in scanned {
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for needle in forbidden {
            assert!(
                !raw.contains(needle),
                "{} should not contain sensitive public observability example `{needle}`",
                path.display()
            );
        }
    }
}

fn collect_promql_expressions<'a>(value: &'a Value, expressions: &mut Vec<&'a str>) {
    match value {
        Value::Object(object) => {
            if let Some(expression) = object.get("expr").and_then(Value::as_str) {
                expressions.push(expression);
            }
            for child in object.values() {
                collect_promql_expressions(child, expressions);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_promql_expressions(child, expressions);
            }
        }
        _ => {}
    }
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()))
    {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, files);
        } else {
            files.push(path);
        }
    }
}
