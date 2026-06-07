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

#[test]
fn ipm_simulation_documents_non_secret_claim_key_response() {
    let spec = openapi();
    let response_ref = &spec["paths"]["/admin/v1/ipm/simulate"]["post"]["responses"]["200"]["content"]
        ["application/json"]["schema"]["$ref"];
    assert_eq!(
        response_ref, "#/components/schemas/IpmSimulationResponse",
        "IPM simulation should document its concrete response shape"
    );

    let context = &spec["components"]["schemas"]["IpmSimulationResponse"]["properties"]["context"];
    assert!(
        context["properties"].get("claim_keys").is_some(),
        "simulation response context should expose non-secret claim keys"
    );
    assert!(
        context["properties"].get("claims").is_none(),
        "simulation response context must not document echoed claim values"
    );
}

#[test]
fn person_proof_admin_schemas_stay_hash_only() {
    let spec = openapi();
    let schemas = &spec["components"]["schemas"];
    let schema_text = [
        "PersonProofAdminStatus",
        "PersonProofAdminClearance",
        "PersonProofAdminClearanceList",
        "PersonProofAdminRevokeRequest",
        "PersonProofAdminRevokeResponse",
    ]
    .into_iter()
    .map(|name| {
        serde_json::to_string(&schemas[name])
            .unwrap_or_else(|error| panic!("{name} schema should serialize: {error}"))
    })
    .collect::<Vec<_>>()
    .join("\n")
    .to_ascii_lowercase();
    for sensitive in [
        r#""token""#,
        r#""secret""#,
        r#""session""#,
        "clearance.v2",
        "reuse_key",
        r#""mac""#,
        r#""cookie""#,
        r#""authorization""#,
    ] {
        assert!(
            !schema_text.contains(sensitive),
            "Person proof Admin schemas must not expose sensitive field {sensitive}"
        );
    }
}

#[test]
fn downstream_tls_status_documents_bounded_crlite_status() {
    let spec = openapi();
    let schema = &spec["paths"]["/admin/v1/tls/downstream"]["get"]["responses"]["200"]["content"]["application/json"]
        ["schema"];
    let required = json_string_set(&schema["required"], "/admin/v1/tls/downstream.required");

    assert!(
        required.contains("crlite_mode"),
        "downstream TLS status should document crlite_mode"
    );
    assert!(
        required.contains("crlite"),
        "downstream TLS status should document crlite status"
    );

    let crlite = &schema["properties"]["crlite"];
    let crlite_required = json_string_set(
        &crlite["required"],
        "/admin/v1/tls/downstream.crlite.required",
    );
    for field in [
        "status",
        "enabled",
        "filter_present",
        "filter_loaded",
        "filter_stale",
        "last_checked_at",
        "last_error_code",
        "result",
        "failure_policy",
        "coverage_policy",
        "managed",
        "storage",
        "cache_present",
        "cache_fresh",
        "last_refresh_at",
        "next_refresh_at",
        "last_success_at",
        "last_error_kind",
    ] {
        assert!(
            crlite_required.contains(field),
            "CRLite status should require {field}"
        );
    }

    let properties = crlite["properties"]
        .as_object()
        .expect("CRLite status properties should be an object");
    for sensitive in [
        "sni",
        "issuer",
        "issuer_name",
        "serial",
        "fingerprint",
        "filter_file",
        "filter_sha256",
        "filter_id",
        "cache_dir",
        "tmpfs_dir",
        "url",
    ] {
        assert!(
            !properties.contains_key(sensitive),
            "CRLite status must not document sensitive field {sensitive}"
        );
    }
}

#[test]
fn upstream_tls_status_documents_bounded_revocation_status() {
    let spec = openapi();
    let schema = &spec["paths"]["/admin/v1/tls/upstream"]["get"]["responses"]["200"]["content"]["application/json"]
        ["schema"];
    let required = json_string_set(&schema["required"], "/admin/v1/tls/upstream.required");
    assert!(
        required.contains("revocation"),
        "upstream TLS status should document revocation status"
    );

    let revocation = &schema["properties"]["revocation"];
    let revocation_required = json_string_set(
        &revocation["required"],
        "/admin/v1/tls/upstream.revocation.required",
    );
    for field in [
        "enabled",
        "ocsp_mode",
        "crlite_mode",
        "ocsp_cache_entries",
        "ocsp_fetch_in_flight",
        "last_ocsp_error_code",
        "crlite_managed_filters",
        "last_crlite_error_code",
    ] {
        assert!(
            revocation_required.contains(field),
            "upstream revocation status should require {field}"
        );
    }

    let schema_text = serde_json::to_string(revocation).expect("schema should serialize");
    for sensitive in [
        "responder_url",
        "server_name",
        "sni",
        "issuer",
        "serial",
        "fingerprint",
        "filter_file",
        "filter_sha256",
        "cache_dir",
        "tmpfs_dir",
    ] {
        assert!(
            !schema_text.contains(sensitive),
            "upstream revocation status must not document sensitive field {sensitive}"
        );
    }
}

#[test]
fn operational_lists_document_pagination_filter_and_sort_parameters() {
    let spec = openapi();
    for path in [
        "/admin/v1/dynamic-policies",
        "/admin/v1/ipm/principals",
        "/admin/v1/ipm/credentials",
        "/admin/v1/ipm/policies",
        "/admin/v1/ipm/bindings",
    ] {
        let names = operation_parameter_names(&spec, path, "get");
        for required in ["limit", "cursor", "sort", "order"] {
            assert!(
                names.contains(required),
                "{path} must document {required} list parameter"
            );
        }
        assert!(
            names.iter().any(|name| name.starts_with("filter[")),
            "{path} must document at least one filter[...] parameter"
        );
        assert!(
            spec["paths"][path]["get"]["responses"].get("400").is_some(),
            "{path} must document invalid list query responses"
        );
    }
}

fn json_string_set(value: &Value, label: &str) -> BTreeSet<String> {
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

fn operation_parameter_names(spec: &Value, path: &str, method: &str) -> BTreeSet<String> {
    spec["paths"][path][method]["parameters"]
        .as_array()
        .unwrap_or_else(|| panic!("{method} {path} must document parameters"))
        .iter()
        .map(|parameter| {
            if let Some(name) = parameter["name"].as_str() {
                return name.to_string();
            }
            let reference = parameter["$ref"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} parameter must have name or $ref"));
            let component = reference
                .strip_prefix("#/components/parameters/")
                .unwrap_or_else(|| panic!("{method} {path} parameter ref must target components"));
            spec["components"]["parameters"][component]["name"]
                .as_str()
                .unwrap_or_else(|| panic!("{reference} must resolve to a named parameter"))
                .to_string()
        })
        .collect()
}

fn expected_operations() -> BTreeSet<(String, String)> {
    [
        ("get", "/admin/v1/openapi.json"),
        ("get", "/admin/v1/capabilities"),
        ("get", "/admin/v1/version"),
        ("get", "/admin/v1/audit"),
        ("get", "/admin/v1/operations"),
        ("post", "/admin/v1/operations"),
        ("get", "/admin/v1/operations/{id}"),
        ("delete", "/admin/v1/operations/{id}"),
        ("get", "/admin/v1/operations/{id}/events"),
        ("get", "/admin/v1/operations/{id}/events/ws"),
        ("get", "/admin/v1/config/status"),
        ("get", "/admin/v1/config/effective"),
        ("post", "/admin/v1/config/validate"),
        ("post", "/admin/v1/config/diff"),
        ("post", "/admin/v1/config/load"),
        ("post", "/admin/v1/config/rollback"),
        ("get", "/admin/v1/tls/downstream"),
        ("post", "/admin/v1/tls/downstream/reload"),
        ("get", "/admin/v1/tls/upstream"),
        ("post", "/admin/v1/tls/upstream/refresh"),
        ("post", "/admin/v1/files/sync"),
        ("post", "/admin/v1/cache/key-explain"),
        ("post", "/admin/v1/cache/warm"),
        ("post", "/admin/v1/cache/purge"),
        ("get", "/admin/v1/waf/rule-hits"),
        ("get", "/admin/v1/waf/rule-costs"),
        ("get", "/admin/v1/waf/crs/compatibility"),
        ("get", "/admin/v1/waf/rulepacks"),
        ("get", "/admin/v1/waf/person-proof/status"),
        ("get", "/admin/v1/waf/person-proof/clearances"),
        ("post", "/admin/v1/waf/person-proof/clearances/revoke"),
        ("post", "/admin/v1/waf/oxirule/check"),
        ("post", "/admin/v1/waf/oxirule/cost"),
        ("post", "/admin/v1/waf/oxirule/test"),
        ("post", "/admin/v1/waf/oxirule/explain"),
        ("post", "/admin/v1/waf/oxirule/replay"),
        ("post", "/admin/v1/waf/oxirule/analyze"),
        ("post", "/admin/v1/waf/oxirule/hardening-plan"),
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
