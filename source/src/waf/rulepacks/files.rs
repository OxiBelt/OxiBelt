use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use super::{
  GROUP_FILE_SUFFIX, RULE_FILE_SUFFIX, RulepackDocument, RulepackGroupFile, RulepackReferencedFile,
  RulepackReferencedFileKind, RulepackRule,
};

pub(super) fn referenced_rulepack_files(
  document: &RulepackDocument,
) -> anyhow::Result<Vec<RulepackReferencedFile>> {
  let mut files = Vec::new();
  for rule in &document.rules {
    if let Some(path) = &rule.path {
      validate_relative_rulepack_path(
        &format!(
          "OxiRule rulepack {} rule {}",
          document.rulepack.name, rule.name
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
  for group_file in &document.group_files {
    if let Some(path) = &group_file.path {
      validate_relative_rulepack_path(
        &format!("OxiRule rulepack {} group file", document.rulepack.name),
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

pub(super) fn validate_content_or_path(
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

pub(super) fn rule_content(
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

pub(super) fn group_file_content(
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
