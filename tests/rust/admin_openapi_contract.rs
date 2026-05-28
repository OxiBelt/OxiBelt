use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("source crate should live under the repository root")
        .to_path_buf()
}

fn openapi() -> Value {
    let raw = fs::read_to_string(repo_root().join("docs/admin-openapi.json"))
        .expect("Admin OpenAPI document should be readable");
    serde_json::from_str(&raw).expect("Admin OpenAPI document should parse as JSON")
}

#[test]
fn admin_openapi_is_31_and_covers_current_v1_paths() {
    let spec = openapi();
    assert_eq!(spec["openapi"], "3.1.0");

    let expected = expected_operations();
    let documented = documented_operations(&spec);
    assert_eq!(
        documented, expected,
        "docs/admin-openapi.json must cover every current /admin/v1 operation exactly"
    );
}

#[test]
fn admin_metadata_operations_declare_bearer_security() {
    let spec = openapi();
    for path in [
        "/admin/v1/openapi.json",
        "/admin/v1/capabilities",
        "/admin/v1/version",
    ] {
        let security = spec["paths"][path]["get"]["security"]
            .as_array()
            .unwrap_or_else(|| panic!("{path} must declare operation-level security"));
        assert!(
            security
                .iter()
                .any(|entry| entry.get("bearerAuth").is_some()),
            "{path} must declare bearerAuth security"
        );
    }
}

#[test]
fn admin_error_responses_use_json_envelope_and_headers() {
    let spec = openapi();
    for name in [
        "BadRequest",
        "Unauthorized",
        "Forbidden",
        "Conflict",
        "NotFound",
        "PreconditionFailed",
        "PreconditionRequired",
        "PayloadTooLarge",
        "MethodNotAllowed",
        "ServiceUnavailable",
        "InternalError",
    ] {
        let response = &spec["components"]["responses"][name];
        assert_eq!(
            response["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/AdminErrorEnvelope",
            "{name} must use the Admin error envelope"
        );
        assert!(
            response["headers"].get("X-OxiBelt-Request-Id").is_some(),
            "{name} must declare X-OxiBelt-Request-Id"
        );
        assert!(
            response["headers"].get("X-OxiBelt-API-Version").is_some(),
            "{name} must declare X-OxiBelt-API-Version"
        );
    }
}

#[test]
fn dynamic_policy_and_upstream_mutations_declare_etag_preconditions() {
    let spec = openapi();
    for (method, path) in [
        ("post", "/admin/v1/dynamic-policies"),
        ("post", "/admin/v1/dynamic-policies/import"),
        ("patch", "/admin/v1/dynamic-policies/{id}"),
        ("delete", "/admin/v1/dynamic-policies/{id}"),
        ("post", "/admin/v1/upstream-pools/{pool}/servers"),
        (
            "patch",
            "/admin/v1/upstream-pools/{pool}/servers/{server_id}",
        ),
        (
            "delete",
            "/admin/v1/upstream-pools/{pool}/servers/{server_id}",
        ),
    ] {
        let operation = &spec["paths"][path][method];
        assert!(
            operation["parameters"]
                .as_array()
                .is_some_and(|parameters| {
                    parameters
                        .iter()
                        .any(|parameter| parameter["$ref"] == "#/components/parameters/IfMatch")
                }),
            "{method} {path} must require If-Match"
        );
        assert!(
            operation["responses"].get("412").is_some(),
            "{method} {path} must document stale If-Match"
        );
        assert!(
            operation["responses"].get("428").is_some(),
            "{method} {path} must document missing If-Match"
        );
    }

    let apply = &spec["paths"]["/admin/v1/dynamic-policies/apply"]["post"];
    assert!(
        apply["parameters"].as_array().is_some_and(|parameters| {
            parameters
                .iter()
                .any(|parameter| parameter["$ref"] == "#/components/parameters/IfMatchOptional")
        }),
        "dynamic-policy apply must document optional If-Match"
    );
    assert!(
        apply["responses"].get("412").is_some(),
        "dynamic-policy apply must document stale optional If-Match"
    );
    assert!(
        apply["responses"].get("428").is_none(),
        "dynamic-policy apply must not require If-Match"
    );
}

fn documented_operations(spec: &Value) -> BTreeSet<(String, String)> {
    let paths = spec["paths"]
        .as_object()
        .expect("OpenAPI paths should be an object");
    let mut documented = BTreeSet::new();
    for (path, item) in paths {
        if !path.starts_with("/admin/v1/") {
            continue;
        }
        let item = item.as_object().expect("path item should be an object");
        for method in ["get", "post", "patch", "delete"] {
            if item.contains_key(method) {
                documented.insert((method.to_string(), path.to_string()));
            }
        }
    }
    documented
}

fn expected_operations() -> BTreeSet<(String, String)> {
    [
        ("get", "/admin/v1/openapi.json"),
        ("get", "/admin/v1/capabilities"),
        ("get", "/admin/v1/version"),
        ("get", "/admin/v1/audit"),
        ("get", "/admin/v1/config/status"),
        ("get", "/admin/v1/config/effective"),
        ("post", "/admin/v1/config/validate"),
        ("post", "/admin/v1/config/diff"),
        ("post", "/admin/v1/config/load"),
        ("post", "/admin/v1/config/rollback"),
        ("get", "/admin/v1/tls/downstream"),
        ("post", "/admin/v1/tls/downstream/reload"),
        ("post", "/admin/v1/files/sync"),
        ("post", "/admin/v1/cache/key-explain"),
        ("post", "/admin/v1/cache/warm"),
        ("post", "/admin/v1/cache/purge"),
        ("get", "/admin/v1/waf/rule-hits"),
        ("get", "/admin/v1/waf/rule-costs"),
        ("get", "/admin/v1/waf/crs/compatibility"),
        ("get", "/admin/v1/waf/rulepacks"),
        ("post", "/admin/v1/waf/oxirule/check"),
        ("post", "/admin/v1/waf/oxirule/cost"),
        ("post", "/admin/v1/waf/oxirule/test"),
        ("post", "/admin/v1/waf/oxirule/explain"),
        ("post", "/admin/v1/waf/oxirule/replay"),
        ("get", "/admin/v1/waf/oxirule/templates"),
        ("post", "/admin/v1/waf/oxirule/templates/render"),
        ("post", "/admin/v1/waf/oxirule/false-positive"),
        ("get", "/admin/v1/lifecycle"),
        ("post", "/admin/v1/lifecycle/drain"),
        ("post", "/admin/v1/lifecycle/undrain"),
        ("get", "/admin/v1/diagnostics/preflight"),
        ("post", "/admin/v1/diagnostics/preflight"),
        ("get", "/admin/v1/diagnostics/support-bundle"),
        ("get", "/admin/v1/runtime/snapshot"),
        ("get", "/admin/v1/runtime/introspection"),
        ("get", "/admin/v1/ipm/status"),
        ("get", "/admin/v1/ipm/principals"),
        ("post", "/admin/v1/ipm/principals"),
        ("get", "/admin/v1/ipm/principals/{id}"),
        ("patch", "/admin/v1/ipm/principals/{id}"),
        ("delete", "/admin/v1/ipm/principals/{id}"),
        ("get", "/admin/v1/ipm/credentials"),
        ("post", "/admin/v1/ipm/credentials"),
        ("get", "/admin/v1/ipm/credentials/{id}"),
        ("patch", "/admin/v1/ipm/credentials/{id}"),
        ("delete", "/admin/v1/ipm/credentials/{id}"),
        ("post", "/admin/v1/ipm/credentials/{id}/rotate"),
        ("post", "/admin/v1/ipm/credentials/{id}/revoke"),
        ("get", "/admin/v1/ipm/policies"),
        ("post", "/admin/v1/ipm/policies"),
        ("get", "/admin/v1/ipm/policies/{id}"),
        ("patch", "/admin/v1/ipm/policies/{id}"),
        ("delete", "/admin/v1/ipm/policies/{id}"),
        ("get", "/admin/v1/ipm/bindings"),
        ("post", "/admin/v1/ipm/bindings"),
        ("delete", "/admin/v1/ipm/bindings/{id}"),
        ("get", "/admin/v1/ipm/audit"),
        ("post", "/admin/v1/ipm/simulate"),
        ("get", "/admin/v1/dynamic-policies"),
        ("post", "/admin/v1/dynamic-policies"),
        ("get", "/admin/v1/dynamic-policies/status"),
        ("post", "/admin/v1/dynamic-policies/apply"),
        ("get", "/admin/v1/dynamic-policies/audit"),
        ("get", "/admin/v1/dynamic-policies/export"),
        ("post", "/admin/v1/dynamic-policies/import"),
        ("get", "/admin/v1/dynamic-policies/{id}"),
        ("patch", "/admin/v1/dynamic-policies/{id}"),
        ("delete", "/admin/v1/dynamic-policies/{id}"),
        ("get", "/admin/v1/upstream-pools"),
        ("get", "/admin/v1/upstream-pools/status"),
        ("get", "/admin/v1/upstream-pools/{pool}"),
        ("post", "/admin/v1/upstream-pools/{pool}/servers"),
        (
            "patch",
            "/admin/v1/upstream-pools/{pool}/servers/{server_id}",
        ),
        (
            "delete",
            "/admin/v1/upstream-pools/{pool}/servers/{server_id}",
        ),
    ]
    .into_iter()
    .map(|(method, path)| (method.to_string(), path.to_string()))
    .collect()
}
