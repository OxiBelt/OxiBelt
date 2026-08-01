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
fn reports_runtime_compatibility_aliases_with_stable_codes() {
  let document = document(
    r#"
[runtime]
main_runtime = "compio"
worker_threads = "auto"

[runtime.workers]
tokio = 3

[runtime.worker_multipliers]
runtime = 1.5
compio_direct_h1 = 0.5
"#,
  );
  let mut diagnostics = Vec::new();
  append_runtime_compatibility_diagnostics(Path::new("oxibelt.toml"), &document, &mut diagnostics);

  assert_eq!(diagnostics.len(), 3);
  assert_eq!(
    diagnostics[0].code,
    "CFG_RUNTIME_MAIN_RUNTIME_COMPATIBILITY_ALIAS"
  );
  assert_eq!(diagnostics[0].field_path, "runtime.main_runtime");
  assert_eq!(
    diagnostics[1].code,
    "CFG_RUNTIME_WORKER_THREADS_COMPATIBILITY_ALIAS"
  );
  assert_eq!(diagnostics[1].field_path, "runtime.worker_threads");
  assert_eq!(
    diagnostics[2].code,
    "CFG_RUNTIME_WORKER_THREADS_COMPATIBILITY_ALIAS"
  );
  assert_eq!(
    diagnostics[2].field_path,
    "runtime.worker_multipliers.runtime"
  );
  assert!(
    diagnostics
      .iter()
      .all(|diagnostic| diagnostic.severity == ConfigDiagnosticSeverity::Warning)
  );
}

#[test]
fn canonical_runtime_fields_do_not_emit_compatibility_warnings() {
  let document = document(
    r#"
[runtime]
main_runtime = "hybrid_compio"
topology_policy = "require_exact"

[runtime.workers]
tokio = 3
compio_direct_h1 = 2

[runtime.worker_multipliers]
tokio = 1.0
compio_direct_h1 = 0.5
"#,
  );
  let mut diagnostics = Vec::new();
  append_runtime_compatibility_diagnostics(Path::new("oxibelt.toml"), &document, &mut diagnostics);

  assert!(diagnostics.is_empty());
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
