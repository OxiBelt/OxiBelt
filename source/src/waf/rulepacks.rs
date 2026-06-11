//! Rulepack manifest validation, inspection, and rendering.
//! External rule files are resolved deliberately so installs cannot smuggle arbitrary paths.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde::{Deserialize, Serialize};

#[path = "rulepacks/input.rs"]
mod input;
pub use input::{
  RulepackBinding, RulepackBindingKind, RulepackDiscovery, RulepackInputMetadata, RulepackVariable,
};

use super::{
  ExternalRuleFile, ExternalRuleGroupFile, WafMode, WafPhase, WafRuleConfig, WafRuleGroupConfig,
};

pub const RULEPACK_FILE_SUFFIX: &str = ".oxirule-rulepack.toml";
const RULE_FILE_SUFFIX: &str = ".oxirule.toml";
const GROUP_FILE_SUFFIX: &str = ".oxirule-group.toml";
const SUPPORTED_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct WafRulepackSummary {
  pub name: String,
  pub version: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub description: Option<String>,
  pub targets: Vec<String>,
  pub requires: Vec<String>,
  pub default_mode: String,
  pub rules: usize,
  pub group_files: usize,
  pub loaded_files: Vec<PathBuf>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub source_commit: Option<String>,
}

#[derive(Debug)]
pub(super) struct LoadedRulepack {
  pub summary: WafRulepackSummary,
  pub rules: Vec<WafRuleConfig>,
  pub rule_groups: Vec<WafRuleGroupConfig>,
}

#[derive(Debug, Clone, Copy)]
pub struct RulepackModeOverride {
  pub mode: WafMode,
  pub force: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RulepackRenderOptions {
  pub variables: BTreeMap<String, String>,
  pub mode_override: Option<RulepackModeOverride>,
  pub source_commit: Option<String>,
  pub pin_variables: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RulepackInspection {
  pub summary: WafRulepackSummary,
  pub rendered: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct RulepackReferencedFile {
  pub kind: RulepackReferencedFileKind,
  pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RulepackReferencedFileKind {
  Rule,
  Group,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulepackDocument {
  rulepack: RulepackMetadata,
  #[serde(default)]
  variables: Vec<RulepackVariable>,
  #[serde(default)]
  bindings: Vec<RulepackBinding>,
  #[serde(default)]
  rules: Vec<RulepackRule>,
  #[serde(default)]
  group_files: Vec<RulepackGroupFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulepackMetadata {
  schema_version: u32,
  name: String,
  version: String,
  #[serde(default)]
  description: Option<String>,
  #[serde(default)]
  targets: Vec<String>,
  #[serde(default)]
  requires: Vec<String>,
  #[serde(default = "default_rulepack_mode")]
  default_mode: WafMode,
  #[serde(default)]
  source_commit: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulepackRule {
  name: String,
  phase: WafPhase,
  priority: i64,
  #[serde(default)]
  id: Option<String>,
  #[serde(default)]
  tags: Vec<String>,
  #[serde(default)]
  mode: Option<WafMode>,
  #[serde(default)]
  content: Option<String>,
  #[serde(default)]
  path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulepackGroupFile {
  #[serde(default)]
  content: Option<String>,
  #[serde(default)]
  path: Option<PathBuf>,
}

pub(super) fn load_rulepacks(
  scope: &str,
  base_dir: Option<&Path>,
  resolved_paths: &[PathBuf],
  logical_paths: &[PathBuf],
) -> anyhow::Result<Vec<LoadedRulepack>> {
  let base_dir = base_dir.ok_or_else(|| anyhow!("{scope} rulepack base directory is missing"))?;
  let mut names = HashSet::new();
  let mut loaded = Vec::new();
  for (resolved_path, logical_path) in resolved_paths.iter().zip(logical_paths.iter()) {
    let raw = std::fs::read_to_string(resolved_path).with_context(|| {
      format!(
        "failed to read OxiRule rulepack file {}",
        resolved_path.display()
      )
    })?;
    let parsed = ParsedRulepack::parse(
      &raw,
      &format!("OxiRule rulepack file {}", logical_path.display()),
      RulepackRenderOptions::default(),
    )?;
    if !names.insert(parsed.document.rulepack.name.clone()) {
      bail!(
        "{scope} contains duplicate OxiRule rulepack name {}",
        parsed.document.rulepack.name
      );
    }
    loaded.push(parsed.expand(base_dir, logical_path)?);
  }
  Ok(loaded)
}

pub fn validate_rulepack_manifest(raw: &str) -> anyhow::Result<()> {
  let parsed = ParsedRulepack::parse(
    raw,
    "OxiRule rulepack manifest",
    RulepackRenderOptions::default(),
  )?;
  parsed.validate_references(false)
}

pub fn inspect_rulepack(
  raw: &str,
  source: &str,
  options: RulepackRenderOptions,
) -> anyhow::Result<RulepackInspection> {
  let parsed = ParsedRulepack::parse(raw, source, options)?;
  Ok(RulepackInspection {
    summary: parsed.summary(Vec::new()),
    rendered: parsed.rendered,
  })
}

pub fn inspect_rulepack_inputs(raw: &str, source: &str) -> anyhow::Result<RulepackInputMetadata> {
  let value: toml::Value =
    toml::from_str(raw).with_context(|| format!("failed to parse {source}"))?;
  let document = document_from_value(value, source)?;
  validate_document_shape(&document, source)?;
  let bindings = input::effective_bindings(&document.variables, &document.bindings);
  Ok(RulepackInputMetadata {
    summary: summary_from_document(&document, Vec::new()),
    variables: document.variables,
    bindings,
  })
}

pub fn render_rulepack_for_install(
  raw: &str,
  source: &str,
  mut options: RulepackRenderOptions,
) -> anyhow::Result<String> {
  options.pin_variables = true;
  Ok(ParsedRulepack::parse(raw, source, options)?.rendered)
}

pub fn referenced_rulepack_files(
  raw: &str,
  source: &str,
  options: RulepackRenderOptions,
) -> anyhow::Result<Vec<RulepackReferencedFile>> {
  let parsed = ParsedRulepack::parse(raw, source, options)?;
  let mut files = Vec::new();
  for rule in &parsed.document.rules {
    if let Some(path) = &rule.path {
      validate_relative_rulepack_path(
        &format!(
          "OxiRule rulepack {} rule {}",
          parsed.document.rulepack.name, rule.name
        ),
        path,
        RULE_FILE_SUFFIX,
      )?;
      files.push(RulepackReferencedFile {
        kind: RulepackReferencedFileKind::Rule,
        path: path.clone(),
      });
    }
  }
  for group_file in &parsed.document.group_files {
    if let Some(path) = &group_file.path {
      validate_relative_rulepack_path(
        &format!(
          "OxiRule rulepack {} group file",
          parsed.document.rulepack.name
        ),
        path,
        GROUP_FILE_SUFFIX,
      )?;
      files.push(RulepackReferencedFile {
        kind: RulepackReferencedFileKind::Group,
        path: path.clone(),
      });
    }
  }
  Ok(files)
}

#[derive(Debug)]
struct ParsedRulepack {
  document: RulepackDocument,
  rendered: String,
  variables: BTreeMap<String, String>,
}

impl ParsedRulepack {
  fn parse(raw: &str, source: &str, options: RulepackRenderOptions) -> anyhow::Result<Self> {
    let mut value: toml::Value =
      toml::from_str(raw).with_context(|| format!("failed to parse {source}"))?;
    let initial = document_from_value(value.clone(), source)?;
    validate_document_shape(&initial, source)?;
    let variables = resolve_variables(&initial.variables, &options.variables, source)?;
    render_toml_strings(&mut value, &variables);
    apply_mode_override(&mut value, options.mode_override)?;
    if options.pin_variables {
      pin_variable_defaults(&mut value, &variables)?;
    }
    if let Some(commit) = options.source_commit {
      set_rulepack_string(&mut value, "source_commit", commit)?;
    }
    let document = document_from_value(value.clone(), source)?;
    validate_document_shape(&document, source)?;
    let rendered =
      toml::to_string_pretty(&value).with_context(|| format!("failed to render {source}"))?;
    Ok(Self {
      document,
      rendered,
      variables,
    })
  }

  fn expand(self, base_dir: &Path, manifest_path: &Path) -> anyhow::Result<LoadedRulepack> {
    self.validate_references(true)?;
    let mut loaded_files = vec![manifest_path.to_path_buf()];
    let mut rules = Vec::new();
    for rule in &self.document.rules {
      let (content, loaded_path) = rule_content(rule, base_dir, &self.variables)?;
      if let Some(path) = &loaded_path {
        loaded_files.push(path.clone());
      }
      let external: ExternalRuleFile = toml::from_str(&content).with_context(|| {
        format!(
          "failed to parse OxiRule rulepack {} rule {}",
          self.document.rulepack.name, rule.name
        )
      })?;
      rules.push(WafRuleConfig {
        name: rule.name.clone(),
        id: rule.id.clone(),
        tags: rule.tags.clone(),
        mode: Some(rule.mode.unwrap_or(self.document.rulepack.default_mode)),
        phase: rule.phase,
        priority: rule.priority,
        when: external.when,
        merge_condition_as: external.merge_condition_as,
        path: None,
        groups: external.groups,
        actions: external.actions,
        local_rule_groups: external.rule_groups,
        loaded_from_path: None,
        loaded_from_logical_path: loaded_path.or_else(|| Some(manifest_path.to_path_buf())),
      });
    }

    let mut rule_groups = Vec::new();
    for group_file in &self.document.group_files {
      let (content, loaded_path) = group_file_content(group_file, base_dir, &self.variables)?;
      if let Some(path) = &loaded_path {
        loaded_files.push(path.clone());
      }
      let external: ExternalRuleGroupFile = toml::from_str(&content).with_context(|| {
        format!(
          "failed to parse OxiRule rulepack {} group file",
          self.document.rulepack.name
        )
      })?;
      if external.rule_groups.is_empty() {
        bail!(
          "OxiRule rulepack {} group file must contain at least one [[rule_groups]] entry",
          self.document.rulepack.name
        );
      }
      rule_groups.extend(external.rule_groups);
    }

    Ok(LoadedRulepack {
      summary: self.summary(loaded_files),
      rules,
      rule_groups,
    })
  }

  fn validate_references(&self, require_base_files: bool) -> anyhow::Result<()> {
    for rule in &self.document.rules {
      validate_content_or_path(
        &format!(
          "OxiRule rulepack {} rule {}",
          self.document.rulepack.name, rule.name
        ),
        rule.content.as_deref(),
        rule.path.as_deref(),
        RULE_FILE_SUFFIX,
        require_base_files,
      )?;
    }
    for group_file in &self.document.group_files {
      validate_content_or_path(
        &format!(
          "OxiRule rulepack {} group file",
          self.document.rulepack.name
        ),
        group_file.content.as_deref(),
        group_file.path.as_deref(),
        GROUP_FILE_SUFFIX,
        require_base_files,
      )?;
    }
    Ok(())
  }

  fn summary(&self, loaded_files: Vec<PathBuf>) -> WafRulepackSummary {
    summary_from_document(&self.document, loaded_files)
  }
}

fn summary_from_document(
  document: &RulepackDocument,
  loaded_files: Vec<PathBuf>,
) -> WafRulepackSummary {
  WafRulepackSummary {
    name: document.rulepack.name.clone(),
    version: document.rulepack.version.clone(),
    description: document.rulepack.description.clone(),
    targets: document.rulepack.targets.clone(),
    requires: document.rulepack.requires.clone(),
    default_mode: document.rulepack.default_mode.as_str().to_string(),
    rules: document.rules.len(),
    group_files: document.group_files.len(),
    loaded_files,
    source_commit: document.rulepack.source_commit.clone(),
  }
}

fn document_from_value(value: toml::Value, source: &str) -> anyhow::Result<RulepackDocument> {
  value
    .try_into()
    .with_context(|| format!("failed to decode {source}"))
}

fn validate_document_shape(document: &RulepackDocument, source: &str) -> anyhow::Result<()> {
  if document.rulepack.schema_version != SUPPORTED_SCHEMA_VERSION {
    bail!(
      "{source} uses unsupported rulepack schema_version {}; only schema_version {SUPPORTED_SCHEMA_VERSION} is supported",
      document.rulepack.schema_version
    );
  }
  validate_label(source, "rulepack.name", &document.rulepack.name)?;
  validate_non_empty(source, "rulepack.version", &document.rulepack.version)?;
  for target in &document.rulepack.targets {
    validate_label(source, "rulepack.targets", target)?;
  }
  for requirement in &document.rulepack.requires {
    validate_label(source, "rulepack.requires", requirement)?;
  }
  if document.rules.is_empty() && document.group_files.is_empty() {
    bail!("{source} must contain at least one [[rules]] or [[group_files]] entry");
  }

  input::validate_rulepack_inputs(source, &document.variables, &document.bindings)?;

  let mut rule_names = HashSet::new();
  for rule in &document.rules {
    validate_label(source, "rules.name", &rule.name)?;
    if !rule_names.insert(rule.name.clone()) {
      bail!("{source} contains duplicate rule {}", rule.name);
    }
    for tag in &rule.tags {
      validate_label(source, "rules.tags", tag)?;
    }
  }
  Ok(())
}

fn validate_label(source: &str, field: &str, value: &str) -> anyhow::Result<()> {
  validate_non_empty(source, field, value)?;
  if value.len() > 128 {
    bail!("{source} {field} exceeds 128 bytes");
  }
  if !value
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
  {
    bail!("{source} {field} contains unsupported characters");
  }
  Ok(())
}

fn validate_non_empty(source: &str, field: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{source} {field} must not be empty");
  }
  Ok(())
}

fn resolve_variables(
  variables: &[RulepackVariable],
  overrides: &BTreeMap<String, String>,
  source: &str,
) -> anyhow::Result<BTreeMap<String, String>> {
  let mut values = BTreeMap::new();
  let known = variables
    .iter()
    .map(|variable| variable.name.as_str())
    .collect::<HashSet<_>>();
  for key in overrides.keys() {
    if !known.contains(key.as_str()) {
      bail!("{source} does not declare variable {key}");
    }
  }
  for variable in variables {
    let value = overrides
      .get(&variable.name)
      .cloned()
      .or_else(|| variable.default.clone());
    match value {
      Some(value) => {
        input::validate_variable_value(source, variable, &value)?;
        values.insert(variable.name.clone(), value);
      }
      None if variable.required => {
        bail!("{source} requires variable {}", variable.name);
      }
      None => {}
    }
  }
  Ok(values)
}

fn render_toml_strings(value: &mut toml::Value, variables: &BTreeMap<String, String>) {
  match value {
    toml::Value::String(text) => {
      for (name, replacement) in variables {
        *text = text.replace(&format!("{{{{{name}}}}}"), replacement);
      }
    }
    toml::Value::Array(values) => {
      for value in values {
        render_toml_strings(value, variables);
      }
    }
    toml::Value::Table(table) => {
      for (_, value) in table.iter_mut() {
        render_toml_strings(value, variables);
      }
    }
    toml::Value::Integer(_)
    | toml::Value::Float(_)
    | toml::Value::Boolean(_)
    | toml::Value::Datetime(_) => {}
  }
}

fn apply_mode_override(
  value: &mut toml::Value,
  mode_override: Option<RulepackModeOverride>,
) -> anyhow::Result<()> {
  let Some(mode_override) = mode_override else {
    return Ok(());
  };
  set_rulepack_string(
    value,
    "default_mode",
    mode_override.mode.as_str().to_string(),
  )?;
  if mode_override.force {
    let Some(rules) = value.get_mut("rules").and_then(toml::Value::as_array_mut) else {
      return Ok(());
    };
    for rule in rules {
      let Some(table) = rule.as_table_mut() else {
        bail!("rulepack rules entries must be tables");
      };
      table.insert(
        "mode".to_string(),
        toml::Value::String(mode_override.mode.as_str().to_string()),
      );
    }
  }
  Ok(())
}

fn pin_variable_defaults(
  value: &mut toml::Value,
  variables: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
  let Some(items) = value
    .get_mut("variables")
    .and_then(toml::Value::as_array_mut)
  else {
    return Ok(());
  };
  for item in items {
    let Some(table) = item.as_table_mut() else {
      bail!("rulepack variables entries must be tables");
    };
    let Some(name) = table.get("name").and_then(toml::Value::as_str) else {
      bail!("rulepack variable entry is missing name");
    };
    if let Some(value) = variables.get(name) {
      table.insert("default".to_string(), toml::Value::String(value.clone()));
      table.insert("required".to_string(), toml::Value::Boolean(false));
    }
  }
  Ok(())
}

fn set_rulepack_string(
  value: &mut toml::Value,
  key: &str,
  field_value: String,
) -> anyhow::Result<()> {
  let Some(table) = value
    .get_mut("rulepack")
    .and_then(toml::Value::as_table_mut)
  else {
    bail!("rulepack manifest is missing [rulepack]");
  };
  table.insert(key.to_string(), toml::Value::String(field_value));
  Ok(())
}

fn validate_content_or_path(
  label: &str,
  content: Option<&str>,
  path: Option<&Path>,
  suffix: &str,
  _require_base_files: bool,
) -> anyhow::Result<()> {
  match (content, path) {
    (Some(_), Some(_)) => bail!("{label} must use either content or path, not both"),
    (None, None) => bail!("{label} must include content or path"),
    (Some(content), None) => {
      if content.trim().is_empty() {
        bail!("{label} content must not be empty");
      }
      Ok(())
    }
    (None, Some(path)) => {
      validate_relative_rulepack_path(label, path, suffix)?;
      Ok(())
    }
  }
}

fn rule_content(
  rule: &RulepackRule,
  base_dir: &Path,
  variables: &BTreeMap<String, String>,
) -> anyhow::Result<(String, Option<PathBuf>)> {
  match (&rule.content, &rule.path) {
    (Some(content), None) => Ok((content.clone(), None)),
    (None, Some(path)) => {
      read_referenced_file("OxiRule rulepack rule path", base_dir, path, variables)
    }
    _ => unreachable!("rulepack rule content/path was validated"),
  }
}

fn group_file_content(
  group_file: &RulepackGroupFile,
  base_dir: &Path,
  variables: &BTreeMap<String, String>,
) -> anyhow::Result<(String, Option<PathBuf>)> {
  match (&group_file.content, &group_file.path) {
    (Some(content), None) => Ok((content.clone(), None)),
    (None, Some(path)) => {
      read_referenced_file("OxiRule rulepack group path", base_dir, path, variables)
    }
    _ => unreachable!("rulepack group content/path was validated"),
  }
}

fn read_referenced_file(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
  variables: &BTreeMap<String, String>,
) -> anyhow::Result<(String, Option<PathBuf>)> {
  let (resolved, logical) = crate::config::resolve_existing_local_config_file_path_with_logical(
    field_name, base_dir, path,
  )?;
  let mut content = std::fs::read_to_string(&resolved)
    .with_context(|| format!("failed to read {} {}", field_name, resolved.display()))?;
  for (name, replacement) in variables {
    content = content.replace(&format!("{{{{{name}}}}}"), replacement);
  }
  Ok((content, Some(logical)))
}

fn validate_relative_rulepack_path(label: &str, path: &Path, suffix: &str) -> anyhow::Result<()> {
  crate::config::resolve_local_config_file_path(label, Path::new("."), path)?;
  let Some(value) = path.to_str() else {
    bail!("{label} path is not valid UTF-8: {}", path.display());
  };
  if !value.ends_with(suffix) {
    bail!("{label} path must end with {suffix}");
  }
  Ok(())
}

fn default_rulepack_mode() -> WafMode {
  WafMode::Monitor
}

#[cfg(test)]
#[path = "rulepacks_tests.rs"]
mod tests;
