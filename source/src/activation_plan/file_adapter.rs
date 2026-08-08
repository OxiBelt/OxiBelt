//! Feature-gated file-loading adapter for offline activation planning.

use std::collections::BTreeSet;
use std::path::Path;
#[cfg(feature = "config-tooling")]
use std::path::PathBuf;

#[cfg(feature = "config-tooling")]
use anyhow::Context as _;

use crate::config::{NativeConfigSecretClass, native_config_field_metadata};

#[cfg(feature = "config-tooling")]
use super::PlanningBasis;
use super::aggregate::{aggregate, change_limit_exceeded};
#[cfg(feature = "config-tooling")]
use super::diff::plan_toml_values;
use super::diff::{child_field_path, classify_change};
use super::{ChangeOperation, ConfigActivationReport, MAX_ACTIVATION_CHANGES};

/// Loads two files through the authoritative native configuration loader and
/// builds an offline activation plan.
#[cfg(feature = "config-tooling")]
pub fn plan_config_files(
  current_path: &Path,
  candidate_path: &Path,
) -> anyhow::Result<super::ConfigActivationReport> {
  let current = crate::config::Config::load_effective_toml_for_activation(current_path)?;
  let candidate = crate::config::Config::load_effective_toml_for_activation(candidate_path)?;
  let current_root = canonical_config_parent(current_path)?;
  let candidate_root = canonical_config_parent(candidate_path)?;
  let mut report = plan_toml_values(&current, &candidate, PlanningBasis::OfflineConfig)?;
  add_relative_file_reference_root_changes(
    &mut report,
    &current,
    &candidate,
    &current_root,
    &candidate_root,
  );
  Ok(report)
}

#[cfg(feature = "config-tooling")]
fn canonical_config_parent(path: &Path) -> anyhow::Result<PathBuf> {
  let canonical = std::fs::canonicalize(path)
    .with_context(|| format!("failed to canonicalize config file {}", path.display()))?;
  canonical.parent().map(Path::to_path_buf).ok_or_else(|| {
    anyhow::anyhow!(
      "config file {} does not have a parent directory",
      path.display()
    )
  })
}

pub(super) fn add_relative_file_reference_root_changes(
  report: &mut ConfigActivationReport,
  current: &toml::Value,
  candidate: &toml::Value,
  current_root: &Path,
  candidate_root: &Path,
) {
  if current_root == candidate_root || !report.is_success() {
    return;
  }
  let mut root_sensitive_paths = BTreeSet::new();
  collect_identical_relative_file_references("", current, candidate, &mut root_sensitive_paths);
  let existing = report
    .changes
    .iter()
    .map(|change| change.path.as_str())
    .collect::<BTreeSet<_>>();
  root_sensitive_paths.retain(|path| !existing.contains(path.as_str()));
  if report
    .changes
    .len()
    .saturating_add(root_sensitive_paths.len())
    > MAX_ACTIVATION_CHANGES
  {
    *report = ConfigActivationReport::new(report.basis, false, Vec::new(), change_limit_exceeded());
    return;
  }
  report.changes.extend(
    root_sensitive_paths
      .into_iter()
      .map(|path| classify_change(&path, ChangeOperation::Change)),
  );
  report.changes.sort_by(|left, right| {
    left
      .path
      .cmp(&right.path)
      .then_with(|| left.op.cmp(&right.op))
  });
  report.activation_plan = aggregate(&report.changes);
}

fn collect_identical_relative_file_references(
  path: &str,
  current: &toml::Value,
  candidate: &toml::Value,
  paths: &mut BTreeSet<String>,
) {
  match (current, candidate) {
    (toml::Value::Table(current), toml::Value::Table(candidate)) => {
      for name in current
        .keys()
        .chain(candidate.keys())
        .collect::<BTreeSet<_>>()
      {
        if let (Some(current), Some(candidate)) = (current.get(name), candidate.get(name)) {
          collect_identical_relative_file_references(
            &child_field_path(path, name),
            current,
            candidate,
            paths,
          );
        }
      }
    }
    (toml::Value::Array(current), toml::Value::Array(candidate)) => {
      for (index, (current, candidate)) in current.iter().zip(candidate).enumerate() {
        collect_identical_relative_file_references(
          &format!("{path}[{index}]"),
          current,
          candidate,
          paths,
        );
      }
    }
    (toml::Value::String(current), toml::Value::String(candidate))
      if current == candidate
        && Path::new(current).is_relative()
        && native_config_field_metadata(path).secret_class
          == NativeConfigSecretClass::FileReference =>
    {
      paths.insert(path.to_string());
    }
    _ => {}
  }
}
