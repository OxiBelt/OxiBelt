//! Side-effect-free configuration activation planning.
//!
//! This module classifies validated configuration changes. It intentionally
//! owns no filesystem, listener, runtime-snapshot, Admin authorization, or
//! deployment mutation mechanics.

mod aggregate;
mod diff;
mod model;
mod secret;

#[cfg(feature = "config-tooling")]
pub use diff::plan_config_files;
pub use diff::{plan_config_projections, plan_toml_values};
pub use model::{
  ACTIVATION_PLAN_SCHEMA_VERSION, ActivationPlan, ActivationPrerequisite,
  ActivationPrerequisiteStatus, ActivationReasonCode, ChangeOperation, ConfigActivationChange,
  ConfigActivationReport, ConfinementActivationPlan, ConfinementDifference,
  ConfinementDifferenceKind, ConfinementFit, ConnectionActivationPlan, ConnectionEffect,
  DeploymentActivationPlan, DeploymentMode, ListenerActivationPlan, MAX_CONFINEMENT_DIFFERENCES,
  MetadataProvenance, NativeActivation, PlanningBasis, PrerequisiteAvailability,
  ResolvedActivationOperation, RollbackKind,
};
pub use secret::{ConfigComparisonKey, ConfigComparisonProjection};

/// Maximum number of per-field changes emitted by one activation report.
///
/// Exceeding this bound fails closed with a typed `change_limit_exceeded`
/// result. Reports are never silently truncated.
pub const MAX_ACTIVATION_CHANGES: usize = 4_096;

#[cfg(test)]
mod tests;
