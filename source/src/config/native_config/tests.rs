use super::*;

fn document(input: &str) -> NativeConfigDocument {
  NativeConfigDocument {
    value: toml::from_str(input).unwrap(),
    files: Vec::new(),
    origins: ConfigOriginIndex::default(),
  }
}

#[test]
fn parses_indexed_field_paths() {
  let value: toml::Value = toml::from_str("[[routes]]\nname = 'main'\n").unwrap();
  assert_eq!(
    lookup_toml_value(&value, "routes[0].name").and_then(toml::Value::as_str),
    Some("main")
  );
}

#[test]
fn converts_json_pointer_indexes_to_native_paths() {
  assert_eq!(
    json_pointer_to_field_path("/routes/0/tls/min_version"),
    "routes[0].tls.min_version"
  );
}

#[test]
fn retained_runtime_compatibility_aliases_keep_stable_codes() {
  let document = document(
    r#"
[runtime]
worker_threads = "auto"

[runtime.workers]
tokio = 3

[runtime.worker_multipliers]
runtime = 1.5
"#,
  );
  let mut diagnostics = Vec::new();
  append_runtime_compatibility_diagnostics(Path::new("oxibelt.toml"), &document, &mut diagnostics);

  assert_eq!(diagnostics.len(), 2);
  assert_eq!(diagnostics[0].field_path, "runtime.worker_threads");
  assert_eq!(
    diagnostics[1].field_path,
    "runtime.worker_multipliers.runtime"
  );
  assert!(
    diagnostics
      .iter()
      .all(|diagnostic| diagnostic.severity == ConfigDiagnosticSeverity::Warning)
  );
}

#[test]
fn removed_runtime_fields_get_fatal_source_aware_diagnostics_when_permissive() {
  let document = document(
    r#"
[config]
strict_unknown_fields = false

[runtime]
direct_h1_io = "compio"

[runtime.workers]
compio_direct_h1 = 2
"#,
  );
  let diagnostics = load_error_diagnostics(
    Path::new("oxibelt.toml"),
    &document,
    "configuration contains removed field(s): runtime.direct_h1_io, runtime.workers.compio_direct_h1",
  );
  assert_eq!(diagnostics.len(), 2);
  assert!(diagnostics.iter().all(|diagnostic| {
    diagnostic.severity == ConfigDiagnosticSeverity::Fatal
      && diagnostic.code == "CFG_REMOVED_FIELD"
      && diagnostic.stage == ConfigDiagnosticStage::Schema
      && diagnostic.source.file == "oxibelt.toml"
  }));
  assert!(
    diagnostics
      .iter()
      .any(|d| d.field_path == "runtime.direct_h1_io")
  );
  assert!(
    diagnostics
      .iter()
      .any(|d| d.field_path == "runtime.workers.compio_direct_h1")
  );
}

#[test]
fn malformed_removed_runtime_value_is_fatal_at_its_field() {
  let document = document(
    r#"
[config]
strict_unknown_fields = false

[runtime]
main_runtime = "unknown"
"#,
  );
  let diagnostics = load_error_diagnostics(
    Path::new("oxibelt.toml"),
    &document,
    "runtime.main_runtime has an invalid legacy enum value",
  );
  assert_eq!(diagnostics.len(), 1);
  assert_eq!(diagnostics[0].code, "CFG_REMOVED_FIELD_INVALID");
  assert_eq!(diagnostics[0].field_path, "runtime.main_runtime");
  assert_eq!(diagnostics[0].severity, ConfigDiagnosticSeverity::Fatal);
}

#[test]
fn reports_legacy_seccomp_mapping_with_a_stable_diagnostic() {
  let document = document(
    r#"
[runtime.hardening.seccomp]
mode = "enforce"
"#,
  );
  let mut diagnostics = Vec::new();
  append_runtime_compatibility_diagnostics(Path::new("oxibelt.toml"), &document, &mut diagnostics);

  assert_eq!(diagnostics.len(), 1);
  assert_eq!(
    diagnostics[0].code,
    "CFG_RUNTIME_SECCOMP_MODE_COMPATIBILITY_ALIAS"
  );
  assert_eq!(
    diagnostics[0].replacement.as_deref(),
    Some("runtime.hardening.seccomp.expectation")
  );
  assert!(
    diagnostics[0]
      .message
      .contains("expectation = \"required\"")
  );
}
