use serde::{Deserialize, Serialize};

use crate::config::{NATIVE_CONFIG_SCHEMA_EPOCH, NativeConfigActivation};

/// Schema version for the stable activation-plan JSON representation.
pub const ACTIVATION_PLAN_SCHEMA_VERSION: u32 = 3;

/// Maximum number of redacted confinement differences emitted in one plan.
///
/// The aggregate fit and digest fields remain authoritative when the bounded
/// explanatory list is truncated.
pub const MAX_CONFINEMENT_DIFFERENCES: usize = 64;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanningBasis {
  #[default]
  OfflineConfig,
  OnlineActive,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOperation {
  Add,
  Remove,
  Change,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataProvenance {
  Explicit,
  Pattern,
  ConservativeDefault,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeActivation {
  None,
  OxiRuleReload,
  DownstreamTlsReload,
  #[default]
  FullReload,
  RestartRequired,
  Conditional,
}

impl From<NativeConfigActivation> for NativeActivation {
  fn from(value: NativeConfigActivation) -> Self {
    match value {
      NativeConfigActivation::None => Self::None,
      NativeConfigActivation::OxiRuleReload => Self::OxiRuleReload,
      NativeConfigActivation::DownstreamTlsReload => Self::DownstreamTlsReload,
      NativeConfigActivation::FullReload => Self::FullReload,
      NativeConfigActivation::RestartRequired => Self::RestartRequired,
      NativeConfigActivation::Conditional => Self::Conditional,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedActivationOperation {
  #[default]
  None,
  OxiRuleReload,
  DownstreamTlsReload,
  FullSnapshotReload,
  ListenerTransition,
  GracefulDrain,
  ProcessRestart,
  KubernetesImmutableRollout,
  AdminClusterRollout,
  BlockedByConfinement,
  InvalidOrUnsupported,
}

impl ResolvedActivationOperation {
  pub(crate) const fn strength(self) -> u8 {
    match self {
      Self::None => 0,
      Self::OxiRuleReload => 1,
      Self::DownstreamTlsReload => 2,
      Self::FullSnapshotReload => 3,
      Self::ListenerTransition => 4,
      Self::GracefulDrain => 5,
      Self::ProcessRestart => 6,
      Self::KubernetesImmutableRollout => 7,
      Self::AdminClusterRollout => 8,
      Self::BlockedByConfinement => 9,
      Self::InvalidOrUnsupported => 10,
    }
  }

  pub(crate) const fn is_in_process(self) -> bool {
    matches!(
      self,
      Self::None | Self::OxiRuleReload | Self::DownstreamTlsReload | Self::FullSnapshotReload
    )
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationReasonCode {
  NoConfigurationChange,
  OxiRuleChanged,
  DownstreamTlsMaterialChanged,
  FullSnapshotReload,
  StartupOnlySubsystem,
  RuntimeCapabilityContextRequired,
  RuntimeNotResizable,
  ListenerAdded,
  ListenerRemoved,
  ListenerRebindRequired,
  ListenerBindConflict,
  GracefulDrainRequired,
  FilesystemAccessExpansion,
  FilesystemAccessUnavailable,
  LandlockPolicyExpansion,
  MountPolicyIncompatible,
  ConfinementEvidenceUnavailable,
  ExternalSeccompProfileRequired,
  SeccompExpectationUnsatisfied,
  ImmutableConfigRequiresRollout,
  DeploymentTargetUnavailable,
  AdminClusterCoordinatedRollout,
  AdminClusterMembershipEpoch,
  SignedArtifactRequired,
  DurableArtifactRequired,
  AllMembersAcknowledgementRequired,
  RollbackArtifactUnavailable,
  ChangeLimitExceeded,
  InvalidConfiguration,
  UnsupportedActivation,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationPrerequisite {
  RuntimeCapabilityContext,
  ResolvedListenerInventory,
  FilesystemManifest,
  ActiveLandlockPolicy,
  ActiveSeccompProfile,
  MountPolicyEvidence,
  DeploymentTargetIdentity,
  PriorRollbackArtifact,
  SignedMutationArtifact,
  DurableMutationArtifact,
  ProtectedWriteAuthorization,
  ClusterMembershipRevision,
  AllMembersAcknowledgement,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrerequisiteAvailability {
  Available,
  Missing,
  #[default]
  Unknown,
  NotApplicable,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivationPrerequisiteStatus {
  pub prerequisite: ActivationPrerequisite,
  pub availability: PrerequisiteAvailability,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackKind {
  Automatic,
  Manual,
  #[default]
  Conditional,
  Unavailable,
  NotApplicable,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigActivationChange {
  pub path: String,
  pub op: ChangeOperation,
  pub secret: bool,
  pub native_activation: NativeActivation,
  pub metadata_provenance: MetadataProvenance,
  pub resolved_operation: ResolvedActivationOperation,
  pub reason_code: ActivationReasonCode,
  pub conditional: bool,
  pub prerequisite_missing: bool,
  pub missing_prerequisites: Vec<ActivationPrerequisite>,
  pub long_connections_affected: bool,
  pub rollback: RollbackKind,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionEffect {
  #[default]
  Unaffected,
  GracefulDrain,
  ForceClose,
  ProcessRestart,
}

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListenerActivationPlan {
  pub unchanged: Vec<String>,
  pub additions: Vec<String>,
  pub removals: Vec<String>,
  pub rebinds: Vec<String>,
  pub bind_conflicts: Vec<String>,
  pub external_port_availability: PrerequisiteAvailability,
}

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConnectionActivationPlan {
  pub http1_keepalive: ConnectionEffect,
  pub http2: ConnectionEffect,
  pub http3: ConnectionEffect,
  pub websocket: ConnectionEffect,
  pub connect_tunnel: ConnectionEffect,
  pub webtransport: ConnectionEffect,
  pub tcp_streams: ConnectionEffect,
  pub udp_flows: ConnectionEffect,
  pub configured_drain_timeout_ms: Option<u64>,
  pub effective_force_close_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinementFit {
  Fits,
  ExpansionRequired,
  Impossible,
  #[default]
  Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinementDifferenceKind {
  PathAdded,
  RightsExpanded,
  ScopeExpanded,
  ParentAccessExpanded,
  IdentityChanged,
  PathUnavailable,
  AccessUnavailable,
  TypeMismatch,
  ParentUnavailable,
  ParentTypeMismatch,
  ParentAccessUnavailable,
  ParentScopeUnrepresentable,
  MountUnavailable,
  SeccompAssertionMismatch,
}

/// Redacted explanation of one confinement-relevant candidate difference.
///
/// Filesystem `path_id` values are ordinal identifiers scoped to this report.
/// They are deliberately not stable unkeyed path hashes, which would disclose
/// common filesystem locations through dictionary attacks. Seccomp assertions
/// are modeled separately and never receive a fabricated filesystem identity.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "subject", rename_all = "snake_case")]
pub enum ConfinementDifference {
  Filesystem {
    path_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_config_path: Option<String>,
    kind: ConfinementDifferenceKind,
  },
  Seccomp {
    assertion_id: String,
    kind: ConfinementDifferenceKind,
  },
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfinementActivationPlan {
  pub filesystem: ConfinementFit,
  pub landlock: ConfinementFit,
  pub seccomp: ConfinementFit,
  pub mount_policy: ConfinementFit,
  pub requires_policy_expansion: bool,
  pub restart_required: bool,
  /// Whether stable policy and manifest digests were withheld because they
  /// encode redacted path material.
  pub digests_withheld: bool,
  pub differences: Vec<ConfinementDifference>,
  pub differences_truncated: bool,
  pub missing_prerequisites: Vec<ActivationPrerequisite>,
}

impl Default for ConfinementActivationPlan {
  fn default() -> Self {
    Self {
      filesystem: ConfinementFit::Unknown,
      landlock: ConfinementFit::Unknown,
      seccomp: ConfinementFit::Unknown,
      mount_policy: ConfinementFit::Unknown,
      requires_policy_expansion: false,
      restart_required: false,
      digests_withheld: true,
      differences: Vec::new(),
      differences_truncated: false,
      missing_prerequisites: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
  #[default]
  Standalone,
  KubernetesImmutable,
  AdminCluster,
}

#[derive(Debug, Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeploymentActivationPlan {
  pub mode: DeploymentMode,
  pub target_count: Option<usize>,
  pub target_identities: Vec<String>,
  pub identities_withheld: bool,
  pub membership_revision: Option<String>,
  pub signed_artifact_required: bool,
  pub durable_artifact_required: bool,
  pub all_members_acknowledgement_required: bool,
  pub missing_prerequisites: Vec<ActivationPrerequisite>,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivationPlan {
  pub minimum_required_operation: ResolvedActivationOperation,
  pub selected_operation: ResolvedActivationOperation,
  pub reason_codes: Vec<ActivationReasonCode>,
  pub can_apply_in_process: bool,
  pub conditional: bool,
  pub prerequisites: Vec<ActivationPrerequisiteStatus>,
  pub listener: ListenerActivationPlan,
  pub connections: ConnectionActivationPlan,
  pub confinement: ConfinementActivationPlan,
  pub deployment: DeploymentActivationPlan,
  pub rollback: RollbackKind,
}

impl Default for ActivationPlan {
  fn default() -> Self {
    Self {
      minimum_required_operation: ResolvedActivationOperation::None,
      selected_operation: ResolvedActivationOperation::None,
      reason_codes: vec![ActivationReasonCode::NoConfigurationChange],
      can_apply_in_process: true,
      conditional: false,
      prerequisites: Vec::new(),
      listener: ListenerActivationPlan::default(),
      connections: ConnectionActivationPlan::default(),
      confinement: ConfinementActivationPlan::default(),
      deployment: DeploymentActivationPlan::default(),
      rollback: RollbackKind::NotApplicable,
    }
  }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigActivationReport {
  pub activation_plan_schema_version: u32,
  pub native_schema_epoch: u32,
  pub ok: bool,
  pub basis: PlanningBasis,
  pub changes: Vec<ConfigActivationChange>,
  pub activation_plan: ActivationPlan,
}

impl ConfigActivationReport {
  pub(crate) fn new(
    basis: PlanningBasis,
    ok: bool,
    changes: Vec<ConfigActivationChange>,
    activation_plan: ActivationPlan,
  ) -> Self {
    Self {
      activation_plan_schema_version: ACTIVATION_PLAN_SCHEMA_VERSION,
      native_schema_epoch: NATIVE_CONFIG_SCHEMA_EPOCH,
      ok,
      basis,
      changes,
      activation_plan,
    }
  }

  /// Returns whether the candidate was valid and has a supported, non-blocked plan.
  pub const fn is_success(&self) -> bool {
    self.ok
  }

  /// Builds the stable fail-closed report used when authoritative validation
  /// rejects a current or candidate document before semantic planning.
  pub fn invalid_configuration(basis: PlanningBasis) -> Self {
    Self::new(
      basis,
      false,
      Vec::new(),
      ActivationPlan {
        minimum_required_operation: ResolvedActivationOperation::InvalidOrUnsupported,
        selected_operation: ResolvedActivationOperation::InvalidOrUnsupported,
        reason_codes: vec![ActivationReasonCode::InvalidConfiguration],
        can_apply_in_process: false,
        rollback: RollbackKind::Unavailable,
        ..ActivationPlan::default()
      },
    )
  }
}
