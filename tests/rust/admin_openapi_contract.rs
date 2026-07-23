use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use oxibelt::server::ADMIN_ERROR_CODE_VALUES;
use serde_json::Value;

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate should live under the repository root")
    .to_path_buf()
}

fn openapi() -> Value {
  let raw = fs::read_to_string(repo_root().join("source/assets/admin-openapi.json"))
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
    "source/assets/admin-openapi.json must cover every current /admin/v1 operation exactly"
  );

  let operation_ids = documented_operation_ids(&spec);
  assert_eq!(
    operation_ids.len(),
    documented.len(),
    "every current /admin/v1 operation must have one unique nonempty operationId"
  );
}

#[test]
fn admin_version_documents_embedded_asset_identity() {
  let spec = openapi();
  let schema = &spec["components"]["schemas"]["AdminVersion"];
  let required = json_string_set(&schema["required"], "AdminVersion.required");
  for field in [
    "api_version",
    "package_name",
    "package_version",
    "source_revision",
    "source_ref",
    "source_dirty",
    "build_kind",
    "person_proof_api_version",
    "person_proof_asset_sha256",
    "admin_openapi_sha256",
  ] {
    assert!(
      required.contains(field),
      "AdminVersion must require {field}"
    );
  }
  assert_eq!(
    schema["properties"]["person_proof_api_version"]["const"],
    oxibelt::waf::PERSON_PROOF_API_VERSION
  );
  for field in ["person_proof_asset_sha256", "admin_openapi_sha256"] {
    assert_eq!(
      schema["properties"][field]["pattern"], "^[a-f0-9]{64}$",
      "AdminVersion.{field} must be a lowercase SHA-256 digest"
    );
  }
  assert_eq!(schema["additionalProperties"], false);
  assert_eq!(
    json_string_set(
      &schema["properties"]["source_dirty"]["enum"],
      "AdminVersion.source_dirty.enum"
    ),
    BTreeSet::from([
      "clean".to_string(),
      "dirty".to_string(),
      "unknown".to_string(),
    ])
  );
  assert_eq!(
    json_string_set(
      &schema["properties"]["build_kind"]["enum"],
      "AdminVersion.build_kind.enum"
    ),
    BTreeSet::from([
      "git_development".to_string(),
      "official_release".to_string(),
      "source_archive".to_string(),
      "tagged_development".to_string(),
    ])
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
    "ImmutableRolloutConflict",
    "SecretReferenceActivationConflict",
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

  let error_enum = &spec["components"]["schemas"]["AdminError"]["properties"]["code"]["enum"];
  let documented_error_codes = json_string_set(error_enum, "AdminError.code.enum");
  let runtime_error_codes = ADMIN_ERROR_CODE_VALUES
    .iter()
    .map(|value| (*value).to_string())
    .collect::<BTreeSet<_>>();
  assert_eq!(
    error_enum
      .as_array()
      .expect("AdminError.code.enum must be an array")
      .len(),
    documented_error_codes.len(),
    "AdminError.code.enum must not contain duplicate values"
  );
  assert_eq!(
    ADMIN_ERROR_CODE_VALUES.len(),
    runtime_error_codes.len(),
    "runtime Admin error allowlist must not contain duplicate values"
  );
  assert_eq!(
    documented_error_codes, runtime_error_codes,
    "AdminError.code must exactly match the runtime finalizer allowlist"
  );
}

#[test]
fn config_tooling_models_match_the_admin_runtime_contract() {
  let spec = openapi();

  let payload =
    &spec["components"]["requestBodies"]["ConfigPayload"]["content"]["application/json"]["schema"];
  assert_eq!(
    json_string_set(&payload["required"], "ConfigPayload.required"),
    BTreeSet::from(["config".to_string()])
  );
  let payload_fields = payload["properties"]
    .as_object()
    .expect("ConfigPayload.properties must be an object")
    .keys()
    .cloned()
    .collect::<BTreeSet<_>>();
  assert_eq!(
    payload_fields,
    BTreeSet::from(["config".to_string(), "format".to_string()])
  );
  assert_eq!(payload["properties"]["format"]["default"], "toml");
  assert_eq!(payload["properties"]["config"]["maxLength"], 1_048_576);
  assert_eq!(
    json_string_set(
      &payload["properties"]["format"]["enum"],
      "ConfigPayload.format.enum"
    ),
    BTreeSet::from(["toml".to_string()])
  );

  let validate = &spec["paths"]["/admin/v1/config/validate"]["post"];
  assert_eq!(
    validate["responses"]["200"]["$ref"],
    "#/components/responses/ConfigValidationReport"
  );
  let validation = &spec["components"]["schemas"]["ConfigValidationReport"];
  assert_eq!(
    validation["properties"]["report_schema_version"]["const"],
    1
  );
  assert_eq!(validation["properties"]["native_schema_epoch"]["const"], 1);

  let explain = &spec["paths"]["/admin/v1/config/explain"]["get"];
  assert_eq!(
    explain["responses"]["200"]["$ref"],
    "#/components/responses/ConfigExplainReport"
  );
  let parameters = explain["parameters"]
    .as_array()
    .expect("config explain parameters must be an array");
  assert_eq!(parameters.len(), 1);
  assert_eq!(parameters[0]["name"], "field_path");
  assert_eq!(parameters[0]["in"], "query");
  assert_eq!(parameters[0]["required"], true);
  assert_eq!(parameters[0]["schema"]["maxLength"], 512);
  let explain_report = &spec["components"]["schemas"]["ConfigExplainReport"];
  assert_eq!(
    explain_report["properties"]["report_schema_version"]["const"],
    1
  );
  assert_eq!(
    explain_report["properties"]["native_schema_epoch"]["const"],
    1
  );
  assert_eq!(explain_report["properties"]["ok"]["const"], true);
  assert_eq!(
    explain_report["properties"]["constraints"]["$ref"],
    "#/components/schemas/ConfigExplainConstraints"
  );

  let diagnostic = &spec["components"]["schemas"]["ConfigDiagnostic"];
  assert_eq!(
    json_string_set(
      &diagnostic["properties"]["severity"]["enum"],
      "ConfigDiagnostic.severity.enum"
    ),
    BTreeSet::from([
      "deprecation".to_string(),
      "fatal".to_string(),
      "unsupported".to_string(),
      "warning".to_string(),
    ])
  );
  assert_eq!(
    json_string_set(
      &spec["components"]["schemas"]["ConfigExplainConstraints"]["properties"]["secret_class"]["enum"],
      "ConfigExplainConstraints.secret_class.enum"
    ),
    BTreeSet::from([
      "credential_bearing_url".to_string(),
      "environment_reference".to_string(),
      "file_reference".to_string(),
      "literal".to_string(),
      "none".to_string(),
    ])
  );

  let report_variants = spec["components"]["schemas"]["AdminError"]["properties"]["details"]
    ["properties"]["config_report"]["oneOf"]
    .as_array()
    .expect("AdminError.details.config_report must enumerate report contracts")
    .iter()
    .map(|entry| {
      entry["$ref"]
        .as_str()
        .expect("config report variant must be a reference")
        .to_string()
    })
    .collect::<BTreeSet<_>>();
  assert_eq!(
    report_variants,
    BTreeSet::from([
      "#/components/schemas/ConfigExplainReport".to_string(),
      "#/components/schemas/ConfigValidationReport".to_string(),
    ])
  );
}

#[test]
fn immutable_rollout_status_and_mutation_boundaries_are_documented() {
  let spec = openapi();
  let status = &spec["paths"]["/admin/v1/config/status"]["get"];
  let rollout =
    &status["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["rollout"];
  assert_eq!(
    rollout["$ref"], "#/components/schemas/ConfigRolloutStatus",
    "config status must expose additive immutable rollout identity"
  );
  let operational_profile = &status["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
    ["operational_profile"];
  assert_eq!(
    operational_profile["$ref"], "#/components/schemas/OperationalProfileStatus",
    "config status must expose a selected operational profile when present"
  );

  let operational_profile_schema = &spec["components"]["schemas"]["OperationalProfileStatus"];
  assert_eq!(
    operational_profile_schema["properties"]["version"]["minimum"],
    1
  );

  let rollout_schema = &spec["components"]["schemas"]["ConfigRolloutStatus"];
  assert_eq!(
    rollout_schema["properties"]["rollout_mode"]["enum"][1],
    "kubernetes_immutable"
  );
  assert_eq!(
    rollout_schema["properties"]["apply_state"]["enum"][2],
    "applied"
  );
  assert_eq!(
    rollout_schema["properties"]["digest"]["pattern"],
    "^[a-f0-9]{64}$"
  );

  for path in [
    "/admin/v1/config/load",
    "/admin/v1/config/rollback",
    "/admin/v1/files/sync",
    "/admin/v1/tls/downstream/reload",
  ] {
    let operation = &spec["paths"][path]["post"];
    assert!(
      operation["summary"]
        .as_str()
        .is_some_and(|summary| summary.contains("Kubernetes immutable rollout mode")),
      "{path} must explain the immutable rollout mutation boundary"
    );
    assert_eq!(
      operation["responses"]["409"]["$ref"], "#/components/responses/ImmutableRolloutConflict",
      "{path} must document immutable rollout conflict"
    );
  }
}

#[test]
fn secret_reference_activation_contract_is_strict_and_conditional() {
  let spec = openapi();
  let operation = &spec["paths"]["/admin/v1/config/secret-references/update"]["post"];
  assert_eq!(operation["operationId"], "updateSecretReference");
  assert_eq!(
    operation["responses"]
      .as_object()
      .expect("secret-reference responses must be an object")
      .keys()
      .cloned()
      .collect::<BTreeSet<_>>(),
    [
      "200", "400", "401", "403", "409", "412", "413", "428", "503",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
  );
  assert_eq!(
    operation["responses"]["200"]["$ref"],
    "#/components/responses/SecretReferenceActivationResult"
  );
  assert_eq!(
    operation["responses"]["409"]["$ref"],
    "#/components/responses/SecretReferenceActivationConflict"
  );
  for response_name in [
    "SecretReferenceActivationResult",
    "SecretReferenceActivationConflict",
  ] {
    let headers = spec["components"]["responses"][response_name]["headers"]
      .as_object()
      .unwrap_or_else(|| panic!("{response_name} headers must be an object"));
    for header in [
      "X-OxiBelt-Request-Id",
      "X-OxiBelt-API-Version",
      "X-OxiBelt-Mutation-Request-Id",
      "X-OxiBelt-Mutation-Revision",
      "X-OxiBelt-Idempotent-Replay",
    ] {
      assert!(
        headers.contains_key(header),
        "{response_name} must declare {header}"
      );
    }
  }
  let conflict = &spec["components"]["responses"]["SecretReferenceActivationConflict"];
  assert_eq!(
    conflict["content"]["application/json"]["schema"]["$ref"],
    "#/components/schemas/AdminErrorEnvelope"
  );
  let conflict_description = conflict["description"]
    .as_str()
    .expect("secret-reference conflict must describe its broad boundary");
  for value in [
    "immutable rollout",
    "target or material",
    "runtime preflight",
    "validation evidence",
    "snapshot",
    "mutation claim",
  ] {
    assert!(
      conflict_description.contains(value),
      "secret-reference conflict must mention {value}"
    );
  }
  let description = operation["description"]
    .as_str()
    .expect("secret-reference activation must describe rollout availability");
  for value in [
    "mutable",
    "admin_cluster",
    "Kubernetes immutable",
    "immutable_rollout_conflict",
    "atomic_secret_reference_activation",
  ] {
    assert!(
      description.contains(value),
      "secret-reference activation description must mention {value}"
    );
  }

  let result = &spec["components"]["schemas"]["SecretReferenceActivationResult"]["oneOf"];
  let variants = result
    .as_array()
    .expect("SecretReferenceActivationResult.oneOf must be an array");
  assert_eq!(variants.len(), 2);
  let first = &variants[0];
  assert_eq!(first["additionalProperties"], false);
  assert_eq!(
    json_string_set(&first["required"], "first activation result required"),
    [
      "ok",
      "request_id",
      "config_logical_revision",
      "reference_set_digest",
      "runtime_snapshot_revision",
      "target_revision",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
  );
  assert_eq!(
    first["properties"]
      .as_object()
      .expect("first activation result properties must be an object")
      .keys()
      .cloned()
      .collect::<BTreeSet<_>>(),
    json_string_set(&first["required"], "first activation result required")
  );
  assert_eq!(first["properties"]["ok"]["const"], true);
  assert_eq!(
    first["properties"]["reference_set_digest"]["pattern"],
    "^sha256:[a-f0-9]{64}$"
  );
  assert!(first["properties"].get("token_recoverable").is_none());

  let replay = &variants[1];
  assert_eq!(replay["additionalProperties"], false);
  assert_eq!(
    json_string_set(&replay["required"], "replayed activation result required"),
    ["ok", "token_recoverable"]
      .into_iter()
      .map(str::to_string)
      .collect()
  );
  assert_eq!(replay["properties"]["ok"]["const"], true);
  assert_eq!(replay["properties"]["token_recoverable"]["const"], false);
  assert_eq!(replay["properties"]["state"]["const"], "committed");
  assert_eq!(
    replay["properties"]
      .as_object()
      .expect("replayed activation result properties must be an object")
      .keys()
      .cloned()
      .collect::<BTreeSet<_>>(),
    [
      "ok",
      "token_recoverable",
      "state",
      "request_id",
      "config_logical_revision",
      "reference_set_digest",
      "runtime_snapshot_revision",
      "target_revision",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
  );

  let capability = &spec["components"]["schemas"]["AdminCapabilities"]["properties"]["features"]["properties"]
    ["atomic_secret_reference_activation"];
  let description = capability["description"]
    .as_str()
    .expect("atomic secret-reference capability must describe availability");
  for value in ["mutable", "admin_cluster", "kubernetes_immutable"] {
    assert!(
      description.contains(value),
      "atomic secret-reference capability must mention {value}"
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
    ("post", "/admin/v1/stream-pools/{pool}/servers"),
    ("patch", "/admin/v1/stream-pools/{pool}/servers/{server_id}"),
    (
      "delete",
      "/admin/v1/stream-pools/{pool}/servers/{server_id}",
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
fn ipm_mutations_declare_etag_preconditions() {
  let spec = openapi();
  for (method, path) in [
    ("post", "/admin/v1/ipm/principals"),
    ("patch", "/admin/v1/ipm/principals/{id}"),
    ("delete", "/admin/v1/ipm/principals/{id}"),
    ("post", "/admin/v1/ipm/credentials"),
    ("patch", "/admin/v1/ipm/credentials/{id}"),
    ("delete", "/admin/v1/ipm/credentials/{id}"),
    ("post", "/admin/v1/ipm/credentials/{id}/rotate"),
    ("post", "/admin/v1/ipm/credentials/{id}/revoke"),
    ("post", "/admin/v1/ipm/policies"),
    ("patch", "/admin/v1/ipm/policies/{id}"),
    ("delete", "/admin/v1/ipm/policies/{id}"),
    ("post", "/admin/v1/ipm/bindings"),
    ("delete", "/admin/v1/ipm/bindings/{id}"),
  ] {
    let names = operation_parameter_names(&spec, path, method);
    assert!(
      names.contains("If-Match"),
      "{method} {path} must require If-Match"
    );
    let operation = &spec["paths"][path][method];
    assert!(
      operation["responses"].get("412").is_some(),
      "{method} {path} must document stale If-Match"
    );
    assert!(
      operation["responses"].get("428").is_some(),
      "{method} {path} must document missing If-Match"
    );
  }
}

#[test]
fn high_risk_mutations_declare_signed_replay_contract() {
  let spec = openapi();
  for (method, path) in [
    ("post", "/admin/v1/config/load"),
    ("post", "/admin/v1/config/rollback"),
    ("post", "/admin/v1/config/secret-references/update"),
    ("post", "/admin/v1/files/sync"),
    ("post", "/admin/v1/tls/downstream/reload"),
    ("post", "/admin/v1/keys/rotate"),
    ("post", "/admin/v1/ipm/principals"),
    ("patch", "/admin/v1/ipm/principals/{id}"),
    ("delete", "/admin/v1/ipm/principals/{id}"),
    ("post", "/admin/v1/ipm/credentials"),
    ("patch", "/admin/v1/ipm/credentials/{id}"),
    ("delete", "/admin/v1/ipm/credentials/{id}"),
    ("post", "/admin/v1/ipm/credentials/{id}/rotate"),
    ("post", "/admin/v1/ipm/credentials/{id}/revoke"),
    ("post", "/admin/v1/ipm/policies"),
    ("patch", "/admin/v1/ipm/policies/{id}"),
    ("delete", "/admin/v1/ipm/policies/{id}"),
    ("post", "/admin/v1/ipm/bindings"),
    ("delete", "/admin/v1/ipm/bindings/{id}"),
    ("post", "/admin/v1/break-glass/activations"),
    ("post", "/admin/v1/break-glass/activations/{id}/revoke"),
  ] {
    let names = operation_parameter_names(&spec, path, method);
    assert!(
      names.contains("If-Match"),
      "{method} {path} must require If-Match"
    );
    assert!(
      names.contains("X-OxiBelt-Mutation"),
      "{method} {path} must declare the mode-dependent signed mutation envelope"
    );

    let operation = &spec["paths"][path][method];
    for status in ["409", "428", "503"] {
      assert!(
        operation["responses"].get(status).is_some(),
        "{method} {path} must document protected-mutation status {status}"
      );
    }

    let success = operation["responses"]
      .get("200")
      .or_else(|| operation["responses"].get("201"))
      .unwrap_or_else(|| panic!("{method} {path} must document a terminal success"));
    let expected_response = if path == "/admin/v1/config/secret-references/update" {
      "#/components/responses/SecretReferenceActivationResult"
    } else {
      "#/components/responses/MutationResult"
    };
    assert_eq!(
      success["$ref"], expected_response,
      "{method} {path} must use its protected-mutation result headers"
    );
  }

  let parameter = &spec["components"]["parameters"]["MutationEnvelope"];
  assert_eq!(parameter["name"], "X-OxiBelt-Mutation");
  assert_eq!(parameter["in"], "header");
  assert_eq!(parameter["required"], false);
  let description = parameter["description"]
    .as_str()
    .expect("MutationEnvelope must describe mode-dependent enforcement");
  for phrase in [
    "required when",
    "optional mode",
    "normalized strong If-Match",
  ] {
    assert!(
      description.contains(phrase),
      "MutationEnvelope must mention {phrase}"
    );
  }

  let response_headers = spec["components"]["responses"]["MutationResult"]["headers"]
    .as_object()
    .expect("MutationResult headers must be an object");
  for name in [
    "X-OxiBelt-Mutation-Request-Id",
    "X-OxiBelt-Mutation-Revision",
    "X-OxiBelt-Idempotent-Replay",
  ] {
    assert!(
      response_headers.contains_key(name),
      "MutationResult must declare {name}"
    );
  }
}

#[test]
fn mutation_envelope_and_redacted_receipt_are_strict() {
  let spec = openapi();
  let envelope = &spec["components"]["schemas"]["MutationEnvelope"];
  assert_eq!(envelope["additionalProperties"], false);
  let required = json_string_set(&envelope["required"], "MutationEnvelope.required");
  for field in [
    "version",
    "signer_id",
    "request_id",
    "issued_at",
    "expires_at",
    "expected_previous_revision",
    "new_revision",
    "content_digest",
    "target",
    "signature",
  ] {
    assert!(
      required.contains(field),
      "MutationEnvelope must require {field}"
    );
  }
  assert_eq!(
    envelope["properties"]["content_digest"]["pattern"],
    "^sha256:[a-f0-9]{64}$"
  );
  let signature_pattern = envelope["properties"]["signature"]["pattern"]
    .as_str()
    .expect("signature pattern must be text");
  for suite in ["ed25519", "ed25519_ml_dsa_44"] {
    assert!(
      signature_pattern.contains(suite),
      "signature must document {suite}"
    );
  }

  let receipt = serde_json::to_string(&spec["components"]["schemas"]["MutationReceipt"])
    .expect("MutationReceipt should serialize");
  for forbidden in [r#""token""#, r#""secret""#, r#""signature""#, r#""body""#] {
    assert!(
      !receipt.to_ascii_lowercase().contains(forbidden),
      "MutationReceipt must not expose sensitive field {forbidden}"
    );
  }
  assert!(receipt.contains("token_recoverable"));
}

#[test]
fn mutation_receipts_instances_and_typed_activation_routes_are_documented() {
  let spec = openapi();
  assert_eq!(
    spec["paths"]["/admin/v1/mutations/{request_id}"]["get"]["responses"]["200"]["$ref"],
    "#/components/responses/MutationReceipt"
  );
  assert_eq!(
    spec["paths"]["/admin/v1/config/instances"]["get"]["responses"]["200"]["content"]["application/json"]
      ["schema"]["properties"]["instances"]["items"]["$ref"],
    "#/components/schemas/ConfigInstance"
  );

  let receipt = &spec["components"]["schemas"]["MutationReceipt"];
  let receipt_required = json_string_set(&receipt["required"], "MutationReceipt.required");
  let receipt_properties = receipt["properties"]
    .as_object()
    .expect("MutationReceipt.properties must be an object")
    .keys()
    .cloned()
    .collect::<BTreeSet<_>>();
  assert_eq!(receipt_required, receipt_properties);
  assert_eq!(
    json_string_set(
      &receipt["properties"]["state"]["enum"],
      "MutationReceipt.state.enum"
    ),
    [
      "claimed",
      "validating",
      "applying",
      "canary_applying",
      "canary_healthy",
      "expanding",
      "fully_applied",
      "anchor_pending",
      "committed",
      "failed",
      "rolling_back",
      "rolled_back",
      "rollback_failed",
      "indeterminate",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
  );

  let instances_response = &spec["paths"]["/admin/v1/config/instances"]["get"]["responses"]["200"]
    ["content"]["application/json"]["schema"];
  assert_eq!(
    json_string_set(
      &instances_response["required"],
      "instances response required"
    ),
    [
      "configured_members",
      "membership_revision",
      "authority",
      "active_rollouts",
      "logical_revisions",
      "live_members_truncated",
      "instances",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
  );
  assert_eq!(
    instances_response["properties"]["active_rollouts"]["maxItems"],
    32
  );
  assert_eq!(
    instances_response["properties"]["authority"]["additionalProperties"],
    false
  );
  let instance = &spec["components"]["schemas"]["ConfigInstance"];
  let instance_required = json_string_set(&instance["required"], "ConfigInstance.required");
  let instance_properties = instance["properties"]
    .as_object()
    .expect("ConfigInstance.properties must be an object")
    .keys()
    .cloned()
    .collect::<BTreeSet<_>>();
  assert_eq!(instance_required, instance_properties);

  let key_request = &spec["components"]["schemas"]["KeyRotationRequest"];
  assert!(key_request["properties"].get("reference").is_some());
  assert!(key_request["properties"].get("private_key").is_none());
  assert_eq!(
    json_string_set(
      &key_request["properties"]["target"]["enum"],
      "KeyRotationRequest.target"
    ),
    ["downstream_tls_default", "downstream_tls_sni"]
      .into_iter()
      .map(str::to_string)
      .collect()
  );
  let secret_request = &spec["components"]["schemas"]["SecretReferenceUpdateRequest"];
  assert!(secret_request["properties"].get("reference").is_some());
  assert!(secret_request["properties"].get("value").is_none());
}

#[test]
fn mutation_authorization_actions_and_resources_are_documented() {
  let admin_api = fs::read_to_string(repo_root().join("docs/AdminAPI.md"))
    .expect("Admin API documentation should be readable");
  let configuration = fs::read_to_string(repo_root().join("docs/Configuration.md"))
    .expect("configuration documentation should be readable");
  for value in [
    "admin:ReadMutations",
    "mutation/<request_id>",
    "config:GetInstances",
    "instances/current",
    "config:RotateKey",
    "key/<target>/<name-or-default>",
    "config:UpdateSecretReference",
    "secret-reference/<encoded-field>",
    "ipm:GetBreakGlassActivation",
    "ipm:ActivateBreakGlass",
    "break-glass/principal/<principal>",
    "ipm:RevokeBreakGlass",
    "break-glass/activation/<activation_id>",
  ] {
    assert!(
      admin_api.contains(value),
      "docs/AdminAPI.md must document {value}"
    );
    assert!(
      configuration.contains(value),
      "docs/Configuration.md must document {value}"
    );
  }
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
fn person_proof_revocation_documents_its_narrow_idempotency_contract() {
  let spec = openapi();
  let operation = &spec["paths"]["/admin/v1/waf/person-proof/clearances/revoke"]["post"];
  assert_eq!(
    operation["parameters"][0]["$ref"],
    "#/components/parameters/PersonProofRevocationIdempotencyKey"
  );
  let parameter = &spec["components"]["parameters"]["PersonProofRevocationIdempotencyKey"];
  assert_eq!(parameter["in"], "header");
  assert_eq!(parameter["required"], false);
  assert_eq!(parameter["schema"]["minLength"], 1);
  assert_eq!(parameter["schema"]["maxLength"], 128);
  assert_eq!(
    operation["responses"]["409"]["$ref"],
    "#/components/responses/Conflict"
  );
  assert_eq!(
    operation["responses"]["503"]["$ref"],
    "#/components/responses/ServiceUnavailable"
  );
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
fn waf_rulepack_list_documents_optional_provenance_fields() {
  let spec = openapi();
  let response_schema = &spec["paths"]["/admin/v1/waf/rulepacks"]["get"]["responses"]["200"]["content"]
    ["application/json"]["schema"];
  assert_eq!(
    response_schema["$ref"], "#/components/schemas/WafRulepackList",
    "rulepack list response should use an explicit schema"
  );
  let summary = &spec["components"]["schemas"]["WafRulepackSummary"];
  let required = json_string_set(&summary["required"], "WafRulepackSummary.required");
  let properties = summary["properties"]
    .as_object()
    .expect("WafRulepackSummary properties should be an object");
  assert!(
    required.contains("exceptions"),
    "WafRulepackSummary exceptions count must be required"
  );
  assert!(
    properties.contains_key("exceptions"),
    "WafRulepackSummary should document exceptions count"
  );
  for field in [
    "source_url",
    "source_sha256",
    "source_openpgp_signature_url",
    "source_openpgp_signer_fingerprint",
  ] {
    assert!(
      properties.contains_key(field),
      "WafRulepackSummary should document optional {field}"
    );
    assert!(
      !required.contains(field),
      "WafRulepackSummary {field} must remain optional"
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
      item
        .as_str()
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

fn documented_operation_ids(spec: &Value) -> BTreeSet<String> {
  let paths = spec["paths"]
    .as_object()
    .expect("OpenAPI paths should be an object");
  let mut operation_ids = BTreeSet::new();
  for (path, item) in paths {
    if !path.starts_with("/admin/v1/") {
      continue;
    }
    let item = item.as_object().expect("path item should be an object");
    for method in ["get", "post", "patch", "delete"] {
      let Some(operation) = item.get(method) else {
        continue;
      };
      let operation_id = operation["operationId"]
        .as_str()
        .unwrap_or_else(|| panic!("{method} {path} must have an operationId"));
      assert!(
        !operation_id.trim().is_empty(),
        "{method} {path} operationId must not be empty"
      );
      assert!(
        operation_ids.insert(operation_id.to_string()),
        "{method} {path} duplicates operationId {operation_id}"
      );
    }
  }
  operation_ids
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
    ("get", "/admin/v1/mutations/{request_id}"),
    ("get", "/admin/v1/operations"),
    ("post", "/admin/v1/operations"),
    ("get", "/admin/v1/operations/{id}"),
    ("delete", "/admin/v1/operations/{id}"),
    ("get", "/admin/v1/operations/{id}/events"),
    ("get", "/admin/v1/operations/{id}/events/ws"),
    ("get", "/admin/v1/config/status"),
    ("get", "/admin/v1/config/instances"),
    ("get", "/admin/v1/config/effective"),
    ("get", "/admin/v1/config/explain"),
    ("post", "/admin/v1/config/validate"),
    ("post", "/admin/v1/config/diff"),
    ("post", "/admin/v1/config/load"),
    ("post", "/admin/v1/config/rollback"),
    ("post", "/admin/v1/config/secret-references/update"),
    ("get", "/admin/v1/tls/downstream"),
    ("post", "/admin/v1/tls/downstream/reload"),
    ("post", "/admin/v1/keys/rotate"),
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
    ("post", "/admin/v1/waf/rulepacks/plan"),
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
    ("get", "/admin/v1/break-glass/activations/self"),
    ("post", "/admin/v1/break-glass/activations"),
    ("post", "/admin/v1/break-glass/activations/{id}/revoke"),
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
    ("get", "/admin/v1/stream-pools"),
    ("get", "/admin/v1/stream-pools/status"),
    ("get", "/admin/v1/stream-pools/{pool}"),
    ("post", "/admin/v1/stream-pools/{pool}/servers"),
    ("patch", "/admin/v1/stream-pools/{pool}/servers/{server_id}"),
    (
      "delete",
      "/admin/v1/stream-pools/{pool}/servers/{server_id}",
    ),
  ]
  .into_iter()
  .map(|(method, path)| (method.to_string(), path.to_string()))
  .collect()
}
