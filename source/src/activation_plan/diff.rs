use std::collections::BTreeSet;

use crate::config::{
  NativeConfigActivation, NativeConfigSecretClass, native_config_field_metadata,
  normalize_field_path,
};

use super::MAX_ACTIVATION_CHANGES;
use super::aggregate::{aggregate, change_limit_exceeded};
use super::model::{
  ActivationPrerequisite, ActivationReasonCode, ChangeOperation, ConfigActivationChange,
  ConfigActivationReport, MetadataProvenance, NativeActivation, PlanningBasis,
  ResolvedActivationOperation, RollbackKind,
};
use super::secret::{ConfigComparisonKey, ConfigComparisonProjection};

/// Plans activation from two validated TOML documents without side effects.
pub fn plan_toml_values(
  current: &toml::Value,
  candidate: &toml::Value,
  basis: PlanningBasis,
) -> anyhow::Result<ConfigActivationReport> {
  let key = ConfigComparisonKey::generate()?;
  let current = ConfigComparisonProjection::from_value(current, &key);
  let candidate = ConfigComparisonProjection::from_value(candidate, &key);
  Ok(plan_config_projections(&current, &candidate, basis))
}

/// Compares opaque projections created with the same process-local key.
pub fn plan_config_projections(
  current: &ConfigComparisonProjection,
  candidate: &ConfigComparisonProjection,
  basis: PlanningBasis,
) -> ConfigActivationReport {
  let mut collector = DiffCollector::default();
  collect_changes(
    "",
    Some(current.redacted_value()),
    Some(candidate.redacted_value()),
    current,
    candidate,
    &mut collector,
  );
  if collector.overflow {
    return ConfigActivationReport::new(basis, false, Vec::new(), change_limit_exceeded());
  }
  let activation_plan = aggregate(&collector.changes);
  ConfigActivationReport::new(basis, true, collector.changes, activation_plan)
}

#[derive(Default)]
struct DiffCollector {
  changes: Vec<ConfigActivationChange>,
  overflow: bool,
}

impl DiffCollector {
  fn push(&mut self, path: &str, op: ChangeOperation) {
    if self.changes.len() == MAX_ACTIVATION_CHANGES {
      self.overflow = true;
      return;
    }
    self.changes.push(classify_change(path, op));
  }
}

fn collect_changes(
  path: &str,
  left: Option<&toml::Value>,
  right: Option<&toml::Value>,
  left_projection: &ConfigComparisonProjection,
  right_projection: &ConfigComparisonProjection,
  collector: &mut DiffCollector,
) {
  if collector.overflow {
    return;
  }
  match (left, right) {
    (Some(toml::Value::Table(left)), Some(toml::Value::Table(right))) => {
      let keys = left.keys().chain(right.keys()).collect::<BTreeSet<_>>();
      for key in keys {
        let child_path = child_field_path(path, key);
        collect_changes(
          &child_path,
          left.get(key),
          right.get(key),
          left_projection,
          right_projection,
          collector,
        );
        if collector.overflow {
          return;
        }
      }
    }
    (Some(toml::Value::Array(left)), Some(toml::Value::Array(right))) => {
      for index in 0..left.len().max(right.len()) {
        let child_path = format!("{path}[{index}]");
        collect_changes(
          &child_path,
          left.get(index),
          right.get(index),
          left_projection,
          right_projection,
          collector,
        );
        if collector.overflow {
          return;
        }
      }
    }
    (Some(left), Some(right)) if left == right => {
      if left_projection.secret_matches(path, right_projection) == Some(false) {
        collector.push(path, ChangeOperation::Change);
      }
    }
    (None, Some(right)) => collect_one_side(path, right, ChangeOperation::Add, collector),
    (Some(left), None) => collect_one_side(path, left, ChangeOperation::Remove, collector),
    (Some(_), Some(_)) => collector.push(path, ChangeOperation::Change),
    (None, None) => {}
  }
}

fn collect_one_side(
  path: &str,
  value: &toml::Value,
  op: ChangeOperation,
  collector: &mut DiffCollector,
) {
  if collector.overflow {
    return;
  }
  match value {
    toml::Value::Table(table) if !table.is_empty() => {
      for name in table.keys().collect::<BTreeSet<_>>() {
        let Some(child) = table.get(name) else {
          continue;
        };
        let child_path = child_field_path(path, name);
        collect_one_side(&child_path, child, op, collector);
        if collector.overflow {
          return;
        }
      }
    }
    toml::Value::Array(values) if !values.is_empty() => {
      for (index, child) in values.iter().enumerate() {
        collect_one_side(&format!("{path}[{index}]"), child, op, collector);
        if collector.overflow {
          return;
        }
      }
    }
    _ => collector.push(path, op),
  }
}

pub(super) fn classify_change(path: &str, op: ChangeOperation) -> ConfigActivationChange {
  let metadata = native_config_field_metadata(path);
  let provenance = if metadata.path == "*" {
    MetadataProvenance::ConservativeDefault
  } else if metadata.path == normalize_field_path(path)
    && !metadata.path.contains("[]")
    && !metadata.path.ends_with(".*")
  {
    MetadataProvenance::Explicit
  } else {
    MetadataProvenance::Pattern
  };
  let native_activation = NativeActivation::from(metadata.config_activation);
  let (resolved_operation, reason_code, conditional, missing_prerequisites) =
    resolve_native_activation(metadata.config_activation);

  ConfigActivationChange {
    path: path.to_string(),
    op,
    secret: metadata.secret_class != NativeConfigSecretClass::None,
    native_activation,
    metadata_provenance: provenance,
    resolved_operation,
    reason_code,
    conditional,
    prerequisite_missing: !missing_prerequisites.is_empty(),
    missing_prerequisites,
    long_connections_affected: matches!(
      resolved_operation,
      ResolvedActivationOperation::FullSnapshotReload | ResolvedActivationOperation::ProcessRestart
    ),
    rollback: if resolved_operation == ResolvedActivationOperation::None {
      RollbackKind::NotApplicable
    } else {
      RollbackKind::Conditional
    },
  }
}

fn resolve_native_activation(
  activation: NativeConfigActivation,
) -> (
  ResolvedActivationOperation,
  ActivationReasonCode,
  bool,
  Vec<ActivationPrerequisite>,
) {
  match activation {
    NativeConfigActivation::None => (
      ResolvedActivationOperation::None,
      ActivationReasonCode::NoConfigurationChange,
      false,
      Vec::new(),
    ),
    NativeConfigActivation::OxiRuleReload => (
      ResolvedActivationOperation::OxiRuleReload,
      ActivationReasonCode::OxiRuleChanged,
      false,
      Vec::new(),
    ),
    NativeConfigActivation::DownstreamTlsReload => (
      ResolvedActivationOperation::DownstreamTlsReload,
      ActivationReasonCode::DownstreamTlsMaterialChanged,
      false,
      Vec::new(),
    ),
    NativeConfigActivation::FullReload => (
      ResolvedActivationOperation::FullSnapshotReload,
      ActivationReasonCode::FullSnapshotReload,
      false,
      Vec::new(),
    ),
    NativeConfigActivation::RestartRequired => (
      ResolvedActivationOperation::ProcessRestart,
      ActivationReasonCode::StartupOnlySubsystem,
      false,
      Vec::new(),
    ),
    NativeConfigActivation::Conditional => (
      ResolvedActivationOperation::FullSnapshotReload,
      ActivationReasonCode::RuntimeCapabilityContextRequired,
      true,
      vec![ActivationPrerequisite::RuntimeCapabilityContext],
    ),
  }
}

pub(super) fn child_field_path(path: &str, name: &str) -> String {
  if path.is_empty() {
    name.to_string()
  } else {
    format!("{path}.{name}")
  }
}
