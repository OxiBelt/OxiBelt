#[path = "common/mod.rs"]
mod common;

use std::fs;
use std::path::PathBuf;

use oxibelt::config::{
  Config, ConfigOriginKind, NativeConfigActivation, NativeConfigSecretClass, explain_native_config,
  generate_native_config_schema, load_native_config_document, native_config_field_metadata,
  native_config_schema, validate_native_config, validate_native_schema_instance,
};

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate should live under the repository root")
    .to_path_buf()
}

fn schema_node_for_metadata_path<'a>(
  schema: &'a serde_json::Value,
  path: &str,
) -> &'a serde_json::Value {
  let mut current = schema;
  for segment in path.split('.') {
    let (key, array_item) = segment
      .strip_suffix("[]")
      .map_or((segment, false), |key| (key, true));
    current = current
      .get("properties")
      .and_then(|properties| properties.get(key))
      .unwrap_or_else(|| panic!("native schema is missing `{path}` at `{segment}`"));
    if array_item {
      current = current
        .get("items")
        .unwrap_or_else(|| panic!("native schema field `{segment}` is not an array"));
    }
  }
  current
}

#[test]
fn checked_metadata_generator_matches_the_embedded_versioned_schema() {
  let generated = generate_native_config_schema().expect("native schema should generate");
  let committed =
    fs::read_to_string(repo_root().join("source/assets/oxibelt-config-v1.schema.json"))
      .expect("versioned native schema should be readable");
  assert_eq!(generated, committed, "regenerate the native config schema");
  assert_eq!(
    native_config_schema(1).expect("schema epoch 1 should be embedded"),
    committed
  );
}

#[test]
fn helm_inline_toml_points_to_the_same_native_schema_epoch() {
  let values_schema: serde_json::Value = serde_json::from_str(
    &fs::read_to_string(repo_root().join("deploy/helm/oxibelt/values.schema.json"))
      .expect("Helm values schema should be readable"),
  )
  .expect("Helm values schema should be JSON");
  let inline = &values_schema["properties"]["config"]["properties"]["inline"];
  assert_eq!(inline["contentMediaType"], "application/toml");
  assert_eq!(inline["x-oxibelt-native-schema-epoch"], 1);
  assert_eq!(
    inline["x-oxibelt-native-schema"],
    "../../../source/assets/oxibelt-config-v1.schema.json"
  );
}

#[test]
fn editor_and_documentation_surfaces_publish_the_epoch_one_contract() {
  let taplo = fs::read_to_string(repo_root().join(".taplo.toml"))
    .expect("Taplo configuration should be readable");
  assert!(taplo.contains("source/assets/oxibelt-config-v1.schema.json"));
  assert!(taplo.contains("source/config/**/*.toml"));

  let configuration = fs::read_to_string(repo_root().join("docs/Configuration.md"))
    .expect("configuration reference should be readable");
  for contract in [
    "oxibeltctl config schema --epoch 1",
    "oxibeltctl config validate",
    "oxibeltctl config explain",
    "oxibeltctl config migrate",
    "Config::load` plus `Config::validate",
  ] {
    assert!(
      configuration.contains(contract),
      "configuration reference must retain {contract}"
    );
  }

  let specification = fs::read_to_string(repo_root().join("docs/Specification.md"))
    .expect("technical specification should be readable");
  assert!(specification.contains("machine-readable JSON Schema"));
  assert!(specification.contains("incompatible shape changes require a new epoch"));
}

#[test]
fn example_configuration_matches_the_structural_schema() {
  let example = repo_root().join("source/config/oxibelt.toml");
  let document = load_native_config_document(&example)
    .expect("example configuration and production include semantics should load");
  let errors = validate_native_schema_instance(&document.value)
    .expect("native schema should compile and validate");
  assert!(
    errors.is_empty(),
    "schema rejected the example: {errors:#?}"
  );
}

#[test]
fn discovery_instance_schema_is_typed_and_bounded() {
  let schema = generate_native_config_schema().expect("native schema should generate");
  let schema: serde_json::Value =
    serde_json::from_str(&schema).expect("generated schema should be JSON");
  let id = schema_node_for_metadata_path(&schema, "upstream_pools[].discovery[].id");
  assert_eq!(id["type"], "string");
  let discoveries = schema_node_for_metadata_path(&schema, "upstream_pools[].discovery");
  assert_eq!(discoveries["type"], "array");
  assert_eq!(discoveries["maxItems"], 64);
  let multiplier =
    schema_node_for_metadata_path(&schema, "upstream_pools[].discovery[].weight_multiplier");
  assert_eq!(multiplier["type"], "integer");
  assert_eq!(multiplier["minimum"], 1);
  assert_eq!(multiplier["maximum"], u64::from(u32::MAX));
  assert_eq!(multiplier["default"], 1);
}

#[test]
fn request_mirror_body_schema_publishes_the_runtime_admission_unit() {
  let schema = generate_native_config_schema().expect("native schema should generate");
  let schema: serde_json::Value =
    serde_json::from_str(&schema).expect("generated schema should be JSON");
  let max_body =
    schema_node_for_metadata_path(&schema, "routes[].actions.request_mirrors[].max_body_bytes");
  assert_eq!(max_body["type"], "integer");
  assert_eq!(max_body["minimum"], 0);
  assert_eq!(max_body["maximum"], 16_777_216);
}

#[test]
fn upstream_tls_subject_alt_names_schema_is_typed_and_bounded() {
  let schema = generate_native_config_schema().expect("native schema should generate");
  let schema: serde_json::Value =
    serde_json::from_str(&schema).expect("generated schema should be JSON");
  for path in [
    "upstreams[].tls.subject_alt_names",
    "upstream_pools[].servers[].tls.subject_alt_names",
    "upstream_pools[].discovery[].tls.subject_alt_names",
  ] {
    let subject_alt_names = schema_node_for_metadata_path(&schema, path);
    assert_eq!(
      subject_alt_names["type"], "array",
      "unexpected type at {path}"
    );
    assert_eq!(
      subject_alt_names["maxItems"], 5,
      "unexpected bound at {path}"
    );
    assert_eq!(
      subject_alt_names["items"]["additionalProperties"], false,
      "unexpected item shape at {path}"
    );
    assert_eq!(
      subject_alt_names["items"]["required"],
      serde_json::json!(["type", "value"]),
      "unexpected required fields at {path}"
    );
    assert_eq!(
      subject_alt_names["items"]["properties"]["type"]["enum"],
      serde_json::json!(["dns", "uri"]),
      "unexpected SAN types at {path}"
    );
    assert_eq!(
      subject_alt_names["items"]["properties"]["value"]["minLength"], 1,
      "unexpected minimum length at {path}"
    );
    assert_eq!(
      subject_alt_names["items"]["properties"]["value"]["maxLength"], 253,
      "unexpected maximum length at {path}"
    );
  }
}

#[test]
fn secret_reference_metadata_covers_runtime_credential_boundaries() {
  for (path, expected) in [
    (
      "admin.mutations.artifact_key_env",
      NativeConfigSecretClass::EnvironmentReference,
    ),
    (
      "admin.audit.anchor.signer.token_file",
      NativeConfigSecretClass::FileReference,
    ),
    (
      "cache.external_handlers[0].token_env",
      NativeConfigSecretClass::EnvironmentReference,
    ),
    (
      "database.mitigation.connection_url",
      NativeConfigSecretClass::CredentialBearingUrl,
    ),
    (
      "ipm.credentials[0].break_glass_access_token_hash",
      NativeConfigSecretClass::Literal,
    ),
    (
      "shared_state.backends[0].redis_auth.password_file",
      NativeConfigSecretClass::FileReference,
    ),
    (
      "shared_state.udp_flow_identity_key_env",
      NativeConfigSecretClass::EnvironmentReference,
    ),
    (
      "tls.certificates[0].private_key",
      NativeConfigSecretClass::FileReference,
    ),
    (
      "upstream_pools[0].sticky_cookie.secret_env",
      NativeConfigSecretClass::EnvironmentReference,
    ),
    (
      "webrtc_turn_listeners[0].auth.static_credentials[0].password_env",
      NativeConfigSecretClass::EnvironmentReference,
    ),
  ] {
    assert_eq!(
      native_config_field_metadata(path).secret_class,
      expected,
      "{path} must remain classified for redacted explain output"
    );
  }
  assert_eq!(
    native_config_field_metadata("tls.certificates[0].private_key").reference_activation,
    NativeConfigActivation::DownstreamTlsReload
  );
  assert_eq!(
    native_config_field_metadata("admin.mutations.artifact_key_env").reference_activation,
    NativeConfigActivation::RestartRequired
  );
}

#[test]
fn startup_owned_fields_are_explicitly_restart_classified() {
  for path in [
    "runtime.hardening.landlock.mode",
    "runtime.hot_reload.mode",
    "runtime.netport_switcher.enabled",
    "runtime.unprivileged_mode",
    "crypto.tls_provider",
    "logging.level",
    "metrics.enabled",
    "metrics.bind",
    "health.enabled",
    "health.bind",
    "admin.operations.enabled",
  ] {
    assert_eq!(
      native_config_field_metadata(path).config_activation,
      NativeConfigActivation::RestartRequired,
      "{path} must not be published by an in-process snapshot replacement"
    );
  }
}

#[test]
fn generated_schema_preserves_metadata_through_array_items() {
  let schema: serde_json::Value =
    serde_json::from_str(&generate_native_config_schema().expect("native schema should generate"))
      .expect("generated native schema should be JSON");

  for path in [
    "admin.tls.certificates[].private_key",
    "cache.external_handlers[].token_env",
    "external_auth[].client_secret_env",
    "ipm.credentials[].bearer_token_env",
    "ipm.credentials[].break_glass_access_token_hash",
    "webrtc_turn_listeners[].auth.rest_shared_secret",
    "webrtc_turn_listeners[].auth.rest_shared_secret_env",
    "webrtc_turn_listeners[].auth.static_credentials[].password",
    "webrtc_turn_listeners[].auth.static_credentials[].password_env",
    "webrtc_turn_listeners[].tls.private_key",
    "tls.certificates[].ocsp.responder_url",
    "tls.certificates[].private_key",
    "upstreams[].origin",
    "upstream_pools[].servers[].origin",
    "stream_upstream_pools[].servers[].origin",
    "turn_upstream_pools[].servers[].origin",
    "upstream_pools[].discovery[].token_env",
    "upstream_pools[].discovery[].token_file",
    "upstream_pools[].sticky_cookie.secret_env",
  ] {
    let node = schema_node_for_metadata_path(&schema, path);
    let metadata = native_config_field_metadata(path);
    assert_ne!(
      metadata.secret_class,
      NativeConfigSecretClass::None,
      "test inventory must contain only secret metadata paths: {path}"
    );
    assert_eq!(
      node["x-oxibelt-secret-class"],
      serde_json::to_value(metadata.secret_class).expect("secret class should serialize"),
      "generated schema must preserve the secret class for {path}"
    );
    assert_eq!(
      node["description"],
      format!("OxiBelt native field `{path}`. Production Rust validation is authoritative."),
      "generated schema must publish the canonical array path for {path}"
    );
  }

  let non_array_control = "database.mitigation.connection_url";
  let control = schema_node_for_metadata_path(&schema, non_array_control);
  assert_eq!(
    control["x-oxibelt-secret-class"], "credential_bearing_url",
    "non-array secret metadata must remain unchanged"
  );

  let oxirule = schema_node_for_metadata_path(&schema, "routes[].waf");
  assert_eq!(oxirule["x-oxibelt-config-activation"], "oxi_rule_reload");
  assert_eq!(oxirule["x-oxibelt-reference-activation"], "oxi_rule_reload");

  let deprecated = schema_node_for_metadata_path(&schema, "upstream_pools[].health_check.rise");
  assert_eq!(deprecated["deprecated"], true);
  assert_eq!(deprecated["x-oxibelt-introduced-epoch"], 0);
  assert_eq!(deprecated["x-oxibelt-deprecated-epoch"], 1);
  assert_eq!(
    deprecated["x-oxibelt-replacement"],
    "upstream_pools[].health_check.healthy_threshold"
  );

  let udp_flow_state = schema_node_for_metadata_path(&schema, "stream_listeners[].udp_flow_state");
  assert_eq!(
    udp_flow_state["enum"],
    serde_json::json!(["local", "shared_required"])
  );
  assert_eq!(udp_flow_state["default"], "local");

  let udp_failure_policy =
    schema_node_for_metadata_path(&schema, "shared_state.failure_policies.udp_flows");
  assert_eq!(
    udp_failure_policy["enum"],
    serde_json::json!(["reject_new_only"])
  );
  assert_eq!(udp_failure_policy["default"], "reject_new_only");

  let identity_key =
    schema_node_for_metadata_path(&schema, "shared_state.udp_flow_identity_key_env");
  assert_eq!(identity_key["default"], "OXIBELT_UDP_FLOW_IDENTITY_KEY");
  assert_eq!(
    identity_key["x-oxibelt-secret-class"],
    "environment_reference"
  );
}

#[test]
fn validation_reports_unknown_fields_with_a_stable_suggestion() {
  let temp_dir = common::TempDir::new("native-config-diagnostics");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  fs::create_dir_all(&config_dir).unwrap();
  fs::create_dir_all(&cert_dir).unwrap();
  let (cert, key) = common::create_self_signed_cert(&cert_dir, "diagnostics.example");
  let raw = common::minimal_config_toml_with_paths(
    cert.file_name().unwrap().to_str().unwrap(),
    key.file_name().unwrap().to_str().unwrap(),
  )
  .replace(
    "[listeners]",
    "[config]\nstrict_unknown_fields = false\n\n[listeners]",
  );
  let raw = raw.replace("http1 =", "httpl =");
  let entry = config_dir.join("oxibelt.toml");
  fs::write(&entry, raw).expect("diagnostic fixture should be writable");

  let report = validate_native_config(&entry);
  assert!(
    report.ok,
    "non-strict unknown fields should remain warnings: {report:#?}"
  );
  let diagnostic = report
    .diagnostics
    .iter()
    .find(|diagnostic| diagnostic.code == "CFG_UNKNOWN_FIELD")
    .expect("unknown field diagnostic should be present");
  assert_eq!(diagnostic.field_path, "listeners.httpl");
  assert_eq!(diagnostic.source.file, "oxibelt.toml");
  assert_eq!(
    diagnostic.suggestions.first().map(String::as_str),
    Some("http1")
  );
}

#[test]
fn explain_tracks_include_origin_and_never_returns_private_key_material() {
  let temp_dir = common::TempDir::new("native-config-explain");
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  fs::create_dir_all(&config_dir).unwrap();
  fs::create_dir_all(&cert_dir).unwrap();
  let (cert, key) = common::create_self_signed_cert(&cert_dir, "explain.example");
  let included = config_dir.join("logging.toml");
  fs::write(&included, "[logging]\nlevel = \"debug\"\n")
    .expect("include fixture should be writable");
  let entry = config_dir.join("oxibelt.toml");
  let base = common::minimal_config_toml_with_paths(
    cert.file_name().unwrap().to_str().unwrap(),
    key.file_name().unwrap().to_str().unwrap(),
  )
  .replacen("[logging]\nlevel = \"info\"\n\n", "", 1);
  let raw = format!("include = [\"logging.toml\"]\n{base}");
  fs::write(&entry, raw).expect("entry fixture should be writable");

  Config::load(&entry).unwrap_or_else(|error| panic!("fixture load failed: {error:#}"));
  let validation = validate_native_config(&entry);
  assert!(
    validation.ok,
    "explain fixture must validate: {validation:#?}"
  );

  let logging =
    explain_native_config(&entry, "logging.level").expect("included field should be explainable");
  assert_eq!(logging.source.kind, ConfigOriginKind::Include);
  assert_eq!(logging.source.file.as_deref(), Some("logging.toml"));
  let runtime_resolution = logging
    .runtime_resolution
    .as_ref()
    .expect("offline explain should include a preflight runtime plan");
  assert_eq!(runtime_resolution["basis"], "preflight");
  assert_eq!(runtime_resolution["activated"], false);
  assert_eq!(runtime_resolution["canonical_preset"], "hybrid_compio");

  let private_key = explain_native_config(&entry, "tls.private_key")
    .expect("private key field should be explainable");
  assert!(private_key.redacted);
  assert!(private_key.effective_value.is_none());
  assert!(
    !serde_json::to_string(&private_key)
      .unwrap()
      .contains(&key.display().to_string())
  );
}
