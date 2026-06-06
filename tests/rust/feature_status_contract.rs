use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use oxibelt::config::{
    CRLITE_COVERAGE_POLICY_WIRE_VALUES, CRLITE_FAILURE_POLICY_WIRE_VALUES, CRLITE_MODE_WIRE_VALUES,
    HTTP_POOL_LOAD_BALANCING_ALGORITHM_WIRE_VALUES, OCSP_MODE_WIRE_VALUES,
    OUTBOUND_OCSP_MODE_WIRE_VALUES, SNI_FORWARD_PROTOCOL_WIRE_VALUES,
    STICKY_COOKIE_FALLBACK_ALGORITHM_WIRE_VALUES, UPSTREAM_DISCOVERY_PROVIDER_WIRE_VALUES,
    UPSTREAM_POOL_SERVER_STATE_WIRE_VALUES,
};
use oxibelt::server::{
    ADMIN_CAPABILITY_FEATURE_KEYS, ADMIN_OPERATION_KIND_WIRE_VALUES,
    ADMIN_OPERATION_STATE_WIRE_VALUES,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("source crate should live under the repository root")
        .to_path_buf()
}

fn read_repo_file(path: &str) -> String {
    fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
}

fn openapi() -> Value {
    serde_json::from_str(&read_repo_file("docs/admin-openapi.json"))
        .expect("Admin OpenAPI document should parse as JSON")
}

#[test]
fn feature_matrix_uses_known_lifecycle_statuses_and_required_ids() {
    let statuses = feature_statuses();
    let allowed_statuses = string_set(&["supported", "experimental", "reserved", "removed"]);
    for (feature_id, status) in &statuses {
        assert!(
            allowed_statuses.contains(status),
            "{feature_id} uses unsupported lifecycle status {status}"
        );
    }

    for (feature_id, expected_status) in [
        ("downstream-http-protocols", "supported"),
        ("upstream-http-protocols", "supported"),
        ("route-matchers", "supported"),
        ("route-actions", "supported"),
        ("upstream-pool-algorithms", "supported"),
        ("upstream-discovery", "supported"),
        ("upstream-pool-runtime-state", "supported"),
        ("tls-ocsp", "supported"),
        ("tls-remote-signer", "supported"),
        ("tls-mtls-client-auth", "supported"),
        ("upstream-ech", "supported"),
        ("stream-listener-tcp", "supported"),
        ("sni-forward", "supported"),
        ("oxirule-request-response", "supported"),
        ("crs-request-response", "supported"),
        ("person-proof", "supported"),
        ("cache", "supported"),
        ("admin-api-runtime-control", "supported"),
        ("observability", "supported"),
        ("gateway-controller", "experimental"),
        ("gateway-api-httproute", "experimental"),
        ("gateway-api-tlsroute", "experimental"),
        ("helm-gateway-controller", "experimental"),
        ("acme", "reserved"),
        ("crlite", "experimental"),
        ("downstream-ech", "reserved"),
        ("stream-proxy-udp", "reserved"),
        ("crs-stream-payload", "reserved"),
        ("general-scripting", "reserved"),
        ("legacy-admin-rbac", "removed"),
        ("legacy-pool-algorithm-aliases", "removed"),
    ] {
        assert_eq!(
            statuses.get(feature_id).map(String::as_str),
            Some(expected_status),
            "docs/FeatureStatus.md must list {feature_id} as {expected_status}"
        );
    }
}

#[test]
fn reserved_sections_do_not_reclassify_supported_features() {
    for path in ["README.md", "docs/Specification.md"] {
        let text = read_repo_file(path);
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("reserved") || lower.contains("deferred") {
                assert!(
                    !lower.contains("sticky-cookie"),
                    "{path} reserved text must not list sticky-cookie as reserved: {line}"
                );
                assert!(
                    !lower.contains("live ocsp"),
                    "{path} reserved text must not list live OCSP as reserved: {line}"
                );
                assert!(
                    !lower.contains("live_fetch"),
                    "{path} reserved text must not list live_fetch as reserved: {line}"
                );
            }
        }
    }
}

#[test]
fn config_wire_values_are_documented_in_config_reference_and_feature_matrix() {
    let configuration = read_repo_file("docs/Configuration.md");
    let feature_status = read_repo_file("docs/FeatureStatus.md");

    for values in [
        HTTP_POOL_LOAD_BALANCING_ALGORITHM_WIRE_VALUES,
        STICKY_COOKIE_FALLBACK_ALGORITHM_WIRE_VALUES,
        OCSP_MODE_WIRE_VALUES,
        OUTBOUND_OCSP_MODE_WIRE_VALUES,
        CRLITE_MODE_WIRE_VALUES,
        CRLITE_FAILURE_POLICY_WIRE_VALUES,
        CRLITE_COVERAGE_POLICY_WIRE_VALUES,
        SNI_FORWARD_PROTOCOL_WIRE_VALUES,
        UPSTREAM_DISCOVERY_PROVIDER_WIRE_VALUES,
        UPSTREAM_POOL_SERVER_STATE_WIRE_VALUES,
    ] {
        assert_values_appear("docs/Configuration.md", &configuration, values);
        assert_values_appear("docs/FeatureStatus.md", &feature_status, values);
    }
}

#[test]
fn admin_openapi_enums_match_runtime_wire_contracts() {
    let spec = openapi();
    assert_eq!(
        schema_enum(&spec, "AdminOperationKind"),
        string_set(ADMIN_OPERATION_KIND_WIRE_VALUES)
    );
    assert_eq!(
        schema_enum(&spec, "AdminOperationState"),
        string_set(ADMIN_OPERATION_STATE_WIRE_VALUES)
    );
    assert_eq!(
        schema_enum(&spec, "UpstreamPoolServerState"),
        string_set(UPSTREAM_POOL_SERVER_STATE_WIRE_VALUES)
    );

    let features = &spec["components"]["schemas"]["AdminCapabilities"]["properties"]["features"];
    let required =
        json_string_array_set(&features["required"], "AdminCapabilities.features.required");
    let properties = features["properties"]
        .as_object()
        .expect("AdminCapabilities.features.properties should be an object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = string_set(ADMIN_CAPABILITY_FEATURE_KEYS);
    assert_eq!(required, expected);
    assert_eq!(properties, expected);
}

#[test]
fn admin_wire_values_are_documented_in_feature_matrix() {
    let feature_status = read_repo_file("docs/FeatureStatus.md");
    for values in [
        ADMIN_CAPABILITY_FEATURE_KEYS,
        ADMIN_OPERATION_KIND_WIRE_VALUES,
        ADMIN_OPERATION_STATE_WIRE_VALUES,
    ] {
        assert_values_appear("docs/FeatureStatus.md", &feature_status, values);
    }
}

fn feature_statuses() -> BTreeMap<String, String> {
    let mut statuses = BTreeMap::new();
    for line in read_repo_file("docs/FeatureStatus.md").lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        let cells = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        if cells.len() < 4 || cells[0] == "Feature ID" || cells[0].starts_with("---") {
            continue;
        }

        let feature_id = markdown_code_value(cells[0]);
        let status = markdown_code_value(cells[1]);
        assert!(
            statuses.insert(feature_id.clone(), status).is_none(),
            "docs/FeatureStatus.md must not duplicate feature ID {feature_id}"
        );
    }
    statuses
}

fn markdown_code_value(value: &str) -> String {
    value.trim().trim_matches('`').to_string()
}

fn assert_values_appear(path: &str, text: &str, values: &[&str]) {
    for value in values {
        assert!(text.contains(value), "{path} must document `{value}`");
    }
}

fn schema_enum(spec: &Value, schema_name: &str) -> BTreeSet<String> {
    json_string_array_set(
        &spec["components"]["schemas"][schema_name]["enum"],
        &format!("{schema_name}.enum"),
    )
}

fn json_string_array_set(value: &Value, label: &str) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{label} should be an array"))
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{label} entries should be strings"))
                .to_string()
        })
        .collect()
}

fn string_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}
