use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use super::loader::{load_toml_with_includes, load_toml_with_includes_and_overrides};
use super::{
  Config, ConfigOriginIndex, ConfigOriginKind, ConfigValueOrigin,
  NATIVE_CONFIG_REPORT_SCHEMA_VERSION, NATIVE_CONFIG_SCHEMA_EPOCH, NativeConfigActivation,
  NativeConfigSecretClass, allowed_config_keys, native_config_field_metadata,
  native_config_schema_value, normalize_field_path,
};

#[derive(Debug, Clone)]
pub struct NativeConfigDocument {
  pub value: toml::Value,
  pub files: Vec<PathBuf>,
  pub origins: ConfigOriginIndex,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigDiagnosticSeverity {
  Warning,
  Deprecation,
  Unsupported,
  Fatal,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigDiagnosticStage {
  Parse,
  Include,
  Schema,
  Decode,
  Semantic,
  Migration,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ConfigDiagnosticSource {
  pub kind: ConfigOriginKind,
  pub file: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub line: Option<u32>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub column: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigDiagnostic {
  pub code: String,
  pub severity: ConfigDiagnosticSeverity,
  pub stage: ConfigDiagnosticStage,
  pub field_path: String,
  pub source: ConfigDiagnosticSource,
  pub message: String,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub suggestions: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub replacement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigValidationReport {
  pub report_schema_version: u32,
  pub native_schema_epoch: u32,
  pub ok: bool,
  pub diagnostics: Vec<ConfigDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigExplainSource {
  pub kind: ConfigOriginKind,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigExplainConstraints {
  pub schema: Value,
  pub introduced_epoch: u32,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub deprecated_epoch: Option<u32>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub replacement: Option<String>,
  pub secret_class: NativeConfigSecretClass,
  pub config_activation: NativeConfigActivation,
  pub reference_activation: NativeConfigActivation,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigExplainReport {
  pub report_schema_version: u32,
  pub native_schema_epoch: u32,
  pub ok: bool,
  pub field_path: String,
  pub source: ConfigExplainSource,
  pub redacted: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub effective_value: Option<Value>,
  pub constraints: ConfigExplainConstraints,
}

pub fn load_native_config_document(path: &Path) -> anyhow::Result<NativeConfigDocument> {
  let loaded = load_toml_with_includes(path)?;
  Ok(NativeConfigDocument {
    value: loaded.value,
    files: loaded.files,
    origins: loaded.origins,
  })
}

pub fn validate_native_config(path: &Path) -> ConfigValidationReport {
  validate_native_config_inner(path, &HashMap::new())
}

/// Validates an in-memory overlay with the same include and relative-path base
/// as the production entrypoint. Migration tooling uses this to avoid copying
/// certificates, keys, rules, or other referenced assets into review output.
pub fn validate_native_config_with_overrides(
  path: &Path,
  overrides: &HashMap<PathBuf, Option<String>>,
) -> ConfigValidationReport {
  validate_native_config_inner(path, overrides)
}

fn validate_native_config_inner(
  path: &Path,
  overrides: &HashMap<PathBuf, Option<String>>,
) -> ConfigValidationReport {
  let entry = logical_entry(path);
  let loaded = match load_toml_with_includes_and_overrides(path, overrides) {
    Ok(loaded) => loaded,
    Err(error) => {
      let error_text = error.to_string();
      let stage = if error_text.contains("include") {
        ConfigDiagnosticStage::Include
      } else {
        ConfigDiagnosticStage::Parse
      };
      return report(vec![diagnostic(
        if stage == ConfigDiagnosticStage::Include {
          "CFG_INCLUDE_INVALID"
        } else {
          "CFG_PARSE_TOML"
        },
        ConfigDiagnosticSeverity::Fatal,
        stage,
        "$",
        ConfigDiagnosticSource {
          kind: ConfigOriginKind::Entry,
          file: entry,
          line: None,
          column: None,
        },
        if stage == ConfigDiagnosticStage::Include {
          "configuration include processing failed"
        } else {
          "configuration TOML could not be parsed"
        },
      )]);
    }
  };
  let document = NativeConfigDocument {
    value: loaded.value,
    files: loaded.files,
    origins: loaded.origins,
  };

  let mut diagnostics = schema_diagnostics(path, &document);
  match Config::load_with_config_file_overrides(path, overrides) {
    Ok(config) => {
      if let Err(_error) = config.validate() {
        diagnostics.push(diagnostic(
          "CFG_SEMANTIC_INVALID",
          ConfigDiagnosticSeverity::Fatal,
          ConfigDiagnosticStage::Semantic,
          "$",
          source_for_path(path, &document.origins, "$"),
          "configuration failed production semantic validation",
        ));
      }
    }
    Err(error) => diagnostics.extend(load_error_diagnostics(path, &document, &error.to_string())),
  }
  append_deprecations(path, &document, &mut diagnostics);
  sort_diagnostics(&mut diagnostics);
  diagnostics.dedup();
  report(diagnostics)
}

pub fn explain_native_config(path: &Path, field_path: &str) -> anyhow::Result<ConfigExplainReport> {
  let field_path = validate_field_path(field_path)?;
  let report = validate_native_config(path);
  if !report.ok {
    anyhow::bail!("configuration must validate before it can be explained");
  }
  let document = load_native_config_document(path)?;
  let effective = Config::load_effective_toml_redacted(path)?;
  let value = lookup_toml_value(&effective, &field_path)
    .ok_or_else(|| anyhow::anyhow!("unknown native configuration field path {field_path}"))?;
  let metadata = native_config_field_metadata(&field_path);
  let redacted = metadata.secret_class != NativeConfigSecretClass::None;
  let entry_root = absolute_entry_parent(path);
  let origin = document.origins.get(&field_path);
  let source = origin
    .map(|origin| ConfigExplainSource {
      kind: origin.kind,
      file: origin.logical_file(&entry_root),
    })
    .unwrap_or(ConfigExplainSource {
      kind: ConfigOriginKind::Default,
      file: None,
    });
  Ok(ConfigExplainReport {
    report_schema_version: NATIVE_CONFIG_REPORT_SCHEMA_VERSION,
    native_schema_epoch: NATIVE_CONFIG_SCHEMA_EPOCH,
    ok: true,
    field_path: field_path.clone(),
    source,
    redacted,
    effective_value: if redacted {
      None
    } else {
      Some(serde_json::to_value(value)?)
    },
    constraints: ConfigExplainConstraints {
      schema: schema_for_field(&field_path).unwrap_or(Value::Object(Default::default())),
      introduced_epoch: metadata.introduced_epoch,
      deprecated_epoch: metadata.deprecated_epoch,
      replacement: metadata.replacement.map(ToOwned::to_owned),
      secret_class: metadata.secret_class,
      config_activation: metadata.config_activation,
      reference_activation: metadata.reference_activation,
    },
  })
}

fn report(diagnostics: Vec<ConfigDiagnostic>) -> ConfigValidationReport {
  let ok = !diagnostics.iter().any(|diagnostic| {
    matches!(
      diagnostic.severity,
      ConfigDiagnosticSeverity::Unsupported | ConfigDiagnosticSeverity::Fatal
    )
  });
  ConfigValidationReport {
    report_schema_version: NATIVE_CONFIG_REPORT_SCHEMA_VERSION,
    native_schema_epoch: NATIVE_CONFIG_SCHEMA_EPOCH,
    ok,
    diagnostics,
  }
}

fn load_error_diagnostics(
  entry: &Path,
  document: &NativeConfigDocument,
  error: &str,
) -> Vec<ConfigDiagnostic> {
  if let Some(paths) = error.strip_prefix("configuration contains unknown field(s): ") {
    return paths
      .split(',')
      .map(str::trim)
      .map(|path| ConfigDiagnostic {
        code: "CFG_UNKNOWN_FIELD".to_string(),
        severity: if strict_unknown_fields(&document.value) {
          ConfigDiagnosticSeverity::Fatal
        } else {
          ConfigDiagnosticSeverity::Warning
        },
        stage: ConfigDiagnosticStage::Schema,
        field_path: path.to_string(),
        source: source_for_path(entry, &document.origins, path),
        message: format!("unknown native configuration field `{path}`"),
        suggestions: suggestions_for(path),
        replacement: None,
      })
      .collect();
  }
  vec![diagnostic(
    "CFG_DECODE_INVALID",
    ConfigDiagnosticSeverity::Fatal,
    ConfigDiagnosticStage::Decode,
    "$",
    source_for_path(entry, &document.origins, "$"),
    "configuration failed production decoding or path validation",
  )]
}

fn schema_diagnostics(entry: &Path, document: &NativeConfigDocument) -> Vec<ConfigDiagnostic> {
  #[cfg(feature = "config-tooling")]
  {
    let strict = strict_unknown_fields(&document.value);
    let mut unknown = Vec::new();
    super::shape::collect_unknown_keys(&document.value, "", &mut unknown);
    let mut diagnostics = unknown
      .into_iter()
      .map(|field_path| ConfigDiagnostic {
        code: "CFG_UNKNOWN_FIELD".to_string(),
        severity: if strict {
          ConfigDiagnosticSeverity::Fatal
        } else {
          ConfigDiagnosticSeverity::Warning
        },
        stage: ConfigDiagnosticStage::Schema,
        source: source_for_path(entry, &document.origins, &field_path),
        message: format!("unknown native configuration field `{field_path}`"),
        suggestions: suggestions_for(&field_path),
        replacement: None,
        field_path,
      })
      .collect::<Vec<_>>();
    diagnostics.extend(
      super::validate_native_schema_instance(&document.value)
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, schema_path, _)| !schema_path.ends_with("/additionalProperties"))
        .map(|(path, _schema_path, _message)| {
          let field_path = json_pointer_to_field_path(&path);
          ConfigDiagnostic {
            code: "CFG_SCHEMA_INVALID".to_string(),
            severity: if strict {
              ConfigDiagnosticSeverity::Fatal
            } else {
              ConfigDiagnosticSeverity::Warning
            },
            stage: ConfigDiagnosticStage::Schema,
            field_path: field_path.clone(),
            source: source_for_path(entry, &document.origins, &field_path),
            message: "configuration value does not match the native structural schema".to_string(),
            suggestions: suggestions_for(&field_path),
            replacement: None,
          }
        }),
    );
    diagnostics
  }
  #[cfg(not(feature = "config-tooling"))]
  {
    let _ = (entry, document);
    Vec::new()
  }
}

fn append_deprecations(
  entry: &Path,
  document: &NativeConfigDocument,
  diagnostics: &mut Vec<ConfigDiagnostic>,
) {
  if !warn_on_deprecated_fields(&document.value) {
    return;
  }
  for path in document.origins.keys() {
    let metadata = native_config_field_metadata(path);
    if metadata.deprecated_epoch.is_none() {
      continue;
    }
    diagnostics.push(ConfigDiagnostic {
      code: "CFG_DEPRECATED_FIELD".to_string(),
      severity: ConfigDiagnosticSeverity::Deprecation,
      stage: ConfigDiagnosticStage::Schema,
      field_path: path.clone(),
      source: source_for_path(entry, &document.origins, path),
      message: format!("native configuration field `{path}` is deprecated"),
      suggestions: Vec::new(),
      replacement: metadata.replacement.map(ToOwned::to_owned),
    });
  }
}

fn diagnostic(
  code: &str,
  severity: ConfigDiagnosticSeverity,
  stage: ConfigDiagnosticStage,
  field_path: &str,
  source: ConfigDiagnosticSource,
  message: &str,
) -> ConfigDiagnostic {
  ConfigDiagnostic {
    code: code.to_string(),
    severity,
    stage,
    field_path: field_path.to_string(),
    source,
    message: message.to_string(),
    suggestions: Vec::new(),
    replacement: None,
  }
}

fn source_for_path(
  entry: &Path,
  origins: &ConfigOriginIndex,
  field_path: &str,
) -> ConfigDiagnosticSource {
  let root = absolute_entry_parent(entry);
  origins
    .get(field_path)
    .or_else(|| parent_origin(origins, field_path))
    .map(|origin| source_from_origin(origin, &root, entry))
    .unwrap_or(ConfigDiagnosticSource {
      kind: ConfigOriginKind::Entry,
      file: logical_entry(entry),
      line: None,
      column: None,
    })
}

fn parent_origin<'a>(
  origins: &'a ConfigOriginIndex,
  field_path: &str,
) -> Option<&'a ConfigValueOrigin> {
  let mut parent = field_path;
  while let Some(index) = parent.rfind(['.', '[']) {
    parent = &parent[..index];
    if let Some(origin) = origins.get(parent) {
      return Some(origin);
    }
  }
  None
}

fn source_from_origin(
  origin: &ConfigValueOrigin,
  root: &Path,
  entry: &Path,
) -> ConfigDiagnosticSource {
  ConfigDiagnosticSource {
    kind: origin.kind,
    file: origin
      .logical_file(root)
      .unwrap_or_else(|| logical_entry(entry)),
    line: origin.line,
    column: origin.column,
  }
}

fn suggestions_for(path: &str) -> Vec<String> {
  let normalized = normalize_field_path(path);
  let (parent, key) = normalized
    .rsplit_once('.')
    .map_or(("", normalized.as_str()), |(parent, key)| (parent, key));
  let parent = parent.replace("[]", "");
  let Some(keys) = allowed_config_keys(&parent) else {
    return Vec::new();
  };
  let mut scored = keys
    .into_iter()
    .map(|candidate| (strsim::damerau_levenshtein(key, candidate), candidate))
    .filter(|(distance, candidate)| *distance <= 3 || candidate.starts_with(key))
    .collect::<Vec<_>>();
  scored.sort();
  scored
    .into_iter()
    .take(3)
    .map(|(_, candidate)| candidate.to_string())
    .collect()
}

fn strict_unknown_fields(value: &toml::Value) -> bool {
  value
    .get("config")
    .and_then(|config| config.get("strict_unknown_fields"))
    .and_then(toml::Value::as_bool)
    .unwrap_or(true)
}

fn warn_on_deprecated_fields(value: &toml::Value) -> bool {
  value
    .get("config")
    .and_then(|config| config.get("warn_on_deprecated_fields"))
    .and_then(toml::Value::as_bool)
    .unwrap_or(true)
}

fn validate_field_path(path: &str) -> anyhow::Result<String> {
  if path.is_empty() || path.len() > 512 || path.contains(['\n', '\r', '\0']) {
    anyhow::bail!("native configuration field path is empty or invalid");
  }
  if path.starts_with('.') || path.ends_with('.') || path.contains("..") {
    anyhow::bail!("native configuration field path has invalid separators");
  }
  let mut bracket_depth = 0_u8;
  for ch in path.chars() {
    match ch {
      '[' => bracket_depth = bracket_depth.saturating_add(1),
      ']' if bracket_depth > 0 => bracket_depth -= 1,
      ']' => anyhow::bail!("native configuration field path has an unmatched bracket"),
      _ => {}
    }
  }
  if bracket_depth != 0 {
    anyhow::bail!("native configuration field path has an unmatched bracket");
  }
  Ok(path.to_string())
}

fn lookup_toml_value<'a>(value: &'a toml::Value, path: &str) -> Option<&'a toml::Value> {
  let mut current = value;
  for segment in path.split('.') {
    let (key, indexes) = split_indexes(segment)?;
    current = current.get(key)?;
    for index in indexes {
      current = current.as_array()?.get(index)?;
    }
  }
  Some(current)
}

fn split_indexes(segment: &str) -> Option<(&str, Vec<usize>)> {
  let key_end = segment.find('[').unwrap_or(segment.len());
  let key = &segment[..key_end];
  if key.is_empty() {
    return None;
  }
  let mut indexes = Vec::new();
  let mut rest = &segment[key_end..];
  while !rest.is_empty() {
    let contents = rest.strip_prefix('[')?.split_once(']')?;
    indexes.push(contents.0.parse().ok()?);
    rest = contents.1;
  }
  Some((key, indexes))
}

fn schema_for_field(path: &str) -> Option<Value> {
  let mut current = native_config_schema_value(NATIVE_CONFIG_SCHEMA_EPOCH).ok()?;
  for segment in path.split('.') {
    let (key, indexes) = split_indexes(segment)?;
    current = current.get("properties")?.get(key)?.clone();
    for _ in indexes {
      current = current.get("items")?.clone();
    }
  }
  Some(current)
}

#[cfg(any(feature = "config-tooling", test))]
fn json_pointer_to_field_path(path: &str) -> String {
  if path.is_empty() || path == "/" {
    return "$".to_string();
  }
  path
    .trim_start_matches('/')
    .split('/')
    .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
    .fold(String::new(), |mut field, segment| {
      if segment.bytes().all(|byte| byte.is_ascii_digit()) {
        field.push('[');
        field.push_str(&segment);
        field.push(']');
      } else {
        if !field.is_empty() {
          field.push('.');
        }
        field.push_str(&segment);
      }
      field
    })
}

fn logical_entry(path: &Path) -> String {
  path
    .file_name()
    .unwrap_or(path.as_os_str())
    .to_string_lossy()
    .to_string()
}

fn absolute_entry_parent(path: &Path) -> PathBuf {
  let absolute = if path.is_absolute() {
    path.to_path_buf()
  } else {
    std::env::current_dir()
      .unwrap_or_else(|_| PathBuf::from("."))
      .join(path)
  };
  absolute
    .parent()
    .unwrap_or_else(|| Path::new("."))
    .to_path_buf()
}

fn sort_diagnostics(diagnostics: &mut [ConfigDiagnostic]) {
  diagnostics.sort_by(|left, right| {
    left
      .source
      .file
      .cmp(&right.source.file)
      .then(left.field_path.cmp(&right.field_path))
      .then(left.code.cmp(&right.code))
  });
}

#[cfg(test)]
mod tests {
  use super::*;

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
}
