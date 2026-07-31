use std::collections::BTreeSet;

use super::model::{
  ActivationPlan, ActivationPrerequisiteStatus, ActivationReasonCode, ConfigActivationChange,
  PrerequisiteAvailability, ResolvedActivationOperation, RollbackKind,
};

pub(super) fn aggregate(changes: &[ConfigActivationChange]) -> ActivationPlan {
  if changes.is_empty() {
    return ActivationPlan::default();
  }

  let mut selected = ResolvedActivationOperation::None;
  let mut reasons = BTreeSet::new();
  let mut prerequisites = BTreeSet::new();
  let mut has_oxirule = false;
  let mut has_tls = false;
  let mut conditional = false;

  for change in changes {
    if change.resolved_operation.strength() > selected.strength() {
      selected = change.resolved_operation;
    }
    has_oxirule |= change.resolved_operation == ResolvedActivationOperation::OxiRuleReload;
    has_tls |= change.resolved_operation == ResolvedActivationOperation::DownstreamTlsReload;
    conditional |= change.conditional;
    reasons.insert(change.reason_code);
    prerequisites.extend(change.missing_prerequisites.iter().copied());
  }

  if has_oxirule
    && has_tls
    && selected.strength() <= ResolvedActivationOperation::FullSnapshotReload.strength()
  {
    selected = ResolvedActivationOperation::FullSnapshotReload;
    reasons.insert(ActivationReasonCode::FullSnapshotReload);
  }

  ActivationPlan {
    minimum_required_operation: selected,
    selected_operation: selected,
    reason_codes: reasons.into_iter().collect(),
    can_apply_in_process: selected.is_in_process() && !conditional,
    conditional,
    prerequisites: prerequisites
      .into_iter()
      .map(|prerequisite| ActivationPrerequisiteStatus {
        prerequisite,
        availability: PrerequisiteAvailability::Unknown,
      })
      .collect(),
    rollback: if selected == ResolvedActivationOperation::None {
      RollbackKind::NotApplicable
    } else {
      RollbackKind::Conditional
    },
    ..ActivationPlan::default()
  }
}

pub(super) fn change_limit_exceeded() -> ActivationPlan {
  ActivationPlan {
    minimum_required_operation: ResolvedActivationOperation::InvalidOrUnsupported,
    selected_operation: ResolvedActivationOperation::InvalidOrUnsupported,
    reason_codes: vec![ActivationReasonCode::ChangeLimitExceeded],
    can_apply_in_process: false,
    conditional: false,
    rollback: RollbackKind::Unavailable,
    ..ActivationPlan::default()
  }
}
