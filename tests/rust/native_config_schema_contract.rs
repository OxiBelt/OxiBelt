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
