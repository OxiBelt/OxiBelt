//! Stable Admin response envelopes for native configuration tooling.

use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};

use crate::config::{
  ConfigDiagnostic, ConfigDiagnosticSeverity, ConfigDiagnosticSource, ConfigDiagnosticStage,
  ConfigExplainConstraints, ConfigExplainReport, ConfigExplainSource, ConfigOriginKind,
  ConfigValidationReport, ConfigValueOrigin, NATIVE_CONFIG_REPORT_SCHEMA_VERSION,
  NATIVE_CONFIG_SCHEMA_EPOCH, NativeConfigSecretClass, native_config_field_metadata,
  native_config_schema_value,
};

const MAX_FIELD_PATH_BYTES: usize = 512;
const MAX_FIELD_PATH_SEGMENTS: usize = 64;
const MAX_EXPLAIN_QUERY_BYTES: usize = MAX_FIELD_PATH_BYTES * 3 + 64;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct ConfigFieldPath {
  raw: String,
  segments: Vec<ConfigFieldPathSegment>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ConfigFieldPathSegment {
  Key(String),
  Index(usize),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum ConfigExplainQueryError {
  MissingFieldPath,
  DuplicateFieldPath,
  UnexpectedParameter,
  FieldPathTooLong,
  FieldPathTooDeep,
  InvalidFieldPath,
}

impl ConfigExplainQueryError {
  pub(super) const fn code(self) -> &'static str {
    match self {
      Self::MissingFieldPath => "CFG_EXPLAIN_FIELD_PATH_MISSING",
      Self::DuplicateFieldPath => "CFG_EXPLAIN_FIELD_PATH_DUPLICATE",
      Self::UnexpectedParameter => "CFG_EXPLAIN_QUERY_PARAMETER_UNSUPPORTED",
      Self::FieldPathTooLong => "CFG_EXPLAIN_FIELD_PATH_TOO_LONG",
      Self::FieldPathTooDeep => "CFG_EXPLAIN_FIELD_PATH_TOO_DEEP",
      Self::InvalidFieldPath => "CFG_EXPLAIN_FIELD_PATH_INVALID",
    }
  }

  pub(super) const fn message(self) -> &'static str {
    match self {
      Self::MissingFieldPath => "field_path is required",
      Self::DuplicateFieldPath => "field_path must be provided exactly once",
      Self::UnexpectedParameter => "only field_path is supported",
      Self::FieldPathTooLong => "field_path exceeds the maximum length",
      Self::FieldPathTooDeep => "field_path exceeds the maximum depth",
      Self::InvalidFieldPath => "field_path is invalid",
    }
  }
}

impl ConfigFieldPath {
  pub(super) fn parse_query(query: Option<&str>) -> Result<Self, ConfigExplainQueryError> {
    let query = query.unwrap_or_default();
    if query.len() > MAX_EXPLAIN_QUERY_BYTES {
      return Err(ConfigExplainQueryError::FieldPathTooLong);
    }
    let mut field_path = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
      if key != "field_path" {
        return Err(ConfigExplainQueryError::UnexpectedParameter);
      }
      if field_path.replace(value.into_owned()).is_some() {
        return Err(ConfigExplainQueryError::DuplicateFieldPath);
      }
    }
    let raw = field_path.ok_or(ConfigExplainQueryError::MissingFieldPath)?;
    Self::parse(raw)
  }

  fn parse(raw: String) -> Result<Self, ConfigExplainQueryError> {
    if raw.is_empty() {
      return Err(ConfigExplainQueryError::MissingFieldPath);
    }
    if raw.len() > MAX_FIELD_PATH_BYTES {
      return Err(ConfigExplainQueryError::FieldPathTooLong);
    }

    let mut segments = Vec::new();
    for component in raw.split('.') {
      parse_component(component, &mut segments)?;
      if segments.len() > MAX_FIELD_PATH_SEGMENTS {
        return Err(ConfigExplainQueryError::FieldPathTooDeep);
      }
    }
    Ok(Self { raw, segments })
  }

  pub(super) fn as_str(&self) -> &str {
    &self.raw
  }

  pub(super) fn value<'a>(&self, root: &'a toml::Value) -> Option<&'a toml::Value> {
    let mut current = root;
    for segment in &self.segments {
      current = match segment {
        ConfigFieldPathSegment::Key(key) => current.as_table()?.get(key)?,
        ConfigFieldPathSegment::Index(index) => current.as_array()?.get(*index)?,
      };
    }
    Some(current)
  }

  fn schema(&self, root: &Value) -> Value {
    let mut current = root;
    for segment in &self.segments {
      let next = match segment {
        ConfigFieldPathSegment::Key(key) => current
          .get("properties")
          .and_then(|properties| properties.get(key)),
        ConfigFieldPathSegment::Index(_) => current.get("items"),
      };
      let Some(next) = next else {
        return Value::Object(Default::default());
      };
      current = next;
    }
    current.clone()
  }
}

fn parse_component(
  component: &str,
  segments: &mut Vec<ConfigFieldPathSegment>,
) -> Result<(), ConfigExplainQueryError> {
  let key_len = component.find('[').unwrap_or(component.len());
  let key = &component[..key_len];
  if key.is_empty()
    || !key
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
  {
    return Err(ConfigExplainQueryError::InvalidFieldPath);
  }
  segments.push(ConfigFieldPathSegment::Key(key.to_string()));

  let mut suffix = &component[key_len..];
  while !suffix.is_empty() {
    let Some(after_open) = suffix.strip_prefix('[') else {
      return Err(ConfigExplainQueryError::InvalidFieldPath);
    };
    let Some(close) = after_open.find(']') else {
      return Err(ConfigExplainQueryError::InvalidFieldPath);
    };
    let raw_index = &after_open[..close];
    if raw_index.is_empty() || !raw_index.bytes().all(|byte| byte.is_ascii_digit()) {
      return Err(ConfigExplainQueryError::InvalidFieldPath);
    }
    let index = raw_index
      .parse::<usize>()
      .map_err(|_| ConfigExplainQueryError::InvalidFieldPath)?;
    segments.push(ConfigFieldPathSegment::Index(index));
    suffix = &after_open[close + 1..];
  }
  Ok(())
}

pub(super) fn validation_success() -> ConfigValidationReport {
  ConfigValidationReport {
    report_schema_version: NATIVE_CONFIG_REPORT_SCHEMA_VERSION,
    native_schema_epoch: NATIVE_CONFIG_SCHEMA_EPOCH,
    ok: true,
    diagnostics: Vec::new(),
  }
}

pub(super) fn validation_failure(error: &str) -> Value {
  let (code, stage, diagnostic_message) = validation_error_contract(error);
  let report = failure_report(code, stage, "$", diagnostic_message);
  config_error_response(diagnostic_message, &report)
}

pub(super) fn explain_query_failure(error: ConfigExplainQueryError) -> Value {
  let report = failure_report(
    error.code(),
    ConfigDiagnosticStage::Schema,
    "$",
    error.message(),
  );
  config_error_response(error.message(), &report)
}

pub(super) fn explain_not_found(field_path: &str) -> Value {
  let message = "field path was not found in the active configuration";
  let report = failure_report(
    "CFG_EXPLAIN_FIELD_NOT_FOUND",
    ConfigDiagnosticStage::Schema,
    field_path,
    message,
  );
  config_error_response(message, &report)
}

pub(super) fn explain_success(
  field_path: &ConfigFieldPath,
  value: &toml::Value,
  origin: Option<&ConfigValueOrigin>,
  config_entry: Option<&Path>,
  fallback_origin_kind: ConfigOriginKind,
) -> ConfigExplainReport {
  let metadata = native_config_field_metadata(field_path.as_str());
  let redacted =
    metadata.secret_class != NativeConfigSecretClass::None || value.as_str() == Some("<redacted>");
  let schema = native_config_schema_value(NATIVE_CONFIG_SCHEMA_EPOCH)
    .map(|schema| field_path.schema(&schema))
    .unwrap_or_else(|_| Value::Object(Default::default()));
  let source = origin
    .map(|origin| ConfigExplainSource {
      kind: origin.kind,
      file: logical_origin_file(origin, config_entry),
    })
    .unwrap_or(ConfigExplainSource {
      kind: fallback_origin_kind,
      file: None,
    });
  ConfigExplainReport {
    report_schema_version: NATIVE_CONFIG_REPORT_SCHEMA_VERSION,
    native_schema_epoch: NATIVE_CONFIG_SCHEMA_EPOCH,
    ok: true,
    field_path: field_path.as_str().to_string(),
    source,
    redacted,
    effective_value: if redacted {
      None
    } else {
      serde_json::to_value(value).ok()
    },
    runtime_resolution: None,
    constraints: ConfigExplainConstraints {
      schema,
      introduced_epoch: metadata.introduced_epoch,
      deprecated_epoch: metadata.deprecated_epoch,
      replacement: metadata.replacement.map(ToOwned::to_owned),
      secret_class: metadata.secret_class,
      config_activation: metadata.config_activation,
      reference_activation: metadata.reference_activation,
    },
  }
}

fn validation_error_contract(error: &str) -> (&'static str, ConfigDiagnosticStage, &'static str) {
  if error.contains("failed to parse inline TOML") || error.contains("TOML parse error") {
    return (
      "CFG_PARSE_TOML",
      ConfigDiagnosticStage::Parse,
      "configuration TOML could not be parsed",
    );
  }
  if error.contains("include") {
    return (
      "CFG_INCLUDE_INVALID",
      ConfigDiagnosticStage::Include,
      "inline Admin configuration must not contain includes",
    );
  }
  if error.contains("unknown field") {
    return (
      "CFG_UNKNOWN_FIELD",
      ConfigDiagnosticStage::Schema,
      "configuration contains an unknown field",
    );
  }
  if error.contains("failed to decode") {
    return (
      "CFG_DECODE_INVALID",
      ConfigDiagnosticStage::Decode,
      "configuration failed production decoding or path validation",
    );
  }
  (
    "CFG_SEMANTIC_INVALID",
    ConfigDiagnosticStage::Semantic,
    "configuration failed production semantic validation",
  )
}

fn failure_report(
  code: &str,
  stage: ConfigDiagnosticStage,
  field_path: &str,
  message: &str,
) -> ConfigValidationReport {
  ConfigValidationReport {
    report_schema_version: NATIVE_CONFIG_REPORT_SCHEMA_VERSION,
    native_schema_epoch: NATIVE_CONFIG_SCHEMA_EPOCH,
    ok: false,
    diagnostics: vec![ConfigDiagnostic {
      code: code.to_string(),
      severity: ConfigDiagnosticSeverity::Fatal,
      stage,
      field_path: field_path.to_string(),
      source: ConfigDiagnosticSource {
        kind: ConfigOriginKind::Admin,
        file: "admin:inline".to_string(),
        line: None,
        column: None,
      },
      message: message.to_string(),
      suggestions: Vec::new(),
      replacement: None,
    }],
  }
}

fn logical_origin_file(origin: &ConfigValueOrigin, config_entry: Option<&Path>) -> Option<String> {
  let file = origin.file.as_deref()?;
  let relative = config_entry
    .and_then(Path::parent)
    .and_then(|root| file.strip_prefix(root).ok())
    .or_else(|| file.file_name().map(Path::new))?;
  Some(relative.to_string_lossy().replace('\\', "/"))
}

fn config_error_response(message: &str, report: &impl Serialize) -> Value {
  json!({
    "error": message,
    "details": {
      "config_report": report,
    },
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn field_path_query_is_bounded_and_rejects_untrusted_shapes() {
    assert_eq!(
      ConfigFieldPath::parse_query(None),
      Err(ConfigExplainQueryError::MissingFieldPath)
    );
    assert_eq!(
      ConfigFieldPath::parse_query(Some("field_path=logging.level&field_path=tls")),
      Err(ConfigExplainQueryError::DuplicateFieldPath)
    );
    assert_eq!(
      ConfigFieldPath::parse_query(Some("field_path=logging.level&other=value")),
      Err(ConfigExplainQueryError::UnexpectedParameter)
    );
    for field_path in ["../secret", "tls..enabled", "routes[name]", "routes[0]tail"] {
      assert_eq!(
        ConfigFieldPath::parse_query(Some(&format!("field_path={field_path}"))),
        Err(ConfigExplainQueryError::InvalidFieldPath),
        "{field_path} must be rejected"
      );
    }
    assert_eq!(
      ConfigFieldPath::parse_query(Some(&format!("field_path={}", "a".repeat(513)))),
      Err(ConfigExplainQueryError::FieldPathTooLong)
    );
  }

  #[test]
  fn field_path_resolves_tables_and_array_indexes() {
    let value: toml::Value = toml::from_str(
      r#"
[[routes]]
name = "first"

[[routes]]
name = "second"
"#,
    )
    .expect("fixture should parse");
    let path = ConfigFieldPath::parse_query(Some("field_path=routes%5B1%5D.name"))
      .expect("field path should parse");
    assert_eq!(path.as_str(), "routes[1].name");
    assert_eq!(
      path.value(&value).and_then(toml::Value::as_str),
      Some("second")
    );
  }

  #[test]
  fn validation_error_drops_source_snippets_and_uses_a_generic_message() {
    let secret = "do-not-return-this-secret";
    let report = validation_failure(&format!(
      "TOML parse error at line 1, column 1\n1 | password = {secret}\n"
    ));
    let encoded = serde_json::to_string(&report).expect("report should serialize");
    assert!(!encoded.contains(secret));
    assert_eq!(report["error"], "configuration TOML could not be parsed");
    assert_eq!(
      report["details"]["config_report"]["diagnostics"][0]["stage"],
      "parse"
    );
  }

  #[test]
  fn explain_omits_redacted_values() {
    for (field_path, value) in [
      (
        "database.access_log.connection_url",
        "<redacted>".to_string(),
      ),
      ("admin.bearer_token_env", "OXIBELT_ADMIN_TOKEN".to_string()),
    ] {
      let path = ConfigFieldPath::parse_query(Some(&format!("field_path={field_path}")))
        .expect("field path should parse");
      let report = explain_success(
        &path,
        &toml::Value::String(value),
        None,
        None,
        ConfigOriginKind::Default,
      );
      let report = serde_json::to_value(report).expect("report should serialize");
      assert!(report.get("effective_value").is_none(), "{field_path}");
      assert_eq!(report["redacted"], true, "{field_path}");
      assert_eq!(report["source"]["kind"], "default", "{field_path}");
    }
  }
}
