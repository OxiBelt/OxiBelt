//! Pure fixed-member rollout state machine.

use super::{
  MutationRecord, MutationState, RolloutDirective, RolloutTarget, TargetState, deterministic_canary,
};

pub(super) fn classify(
  record: &MutationRecord,
  targets: &[RolloutTarget],
  membership_exact: bool,
  phase_timed_out: bool,
  rollback_timed_out: bool,
  observation_complete: bool,
  members: &[String],
) -> RolloutDirective {
  if record.state.is_terminal() {
    return RolloutDirective::Completed(record.state);
  }
  if targets.len() != members.len() {
    return RolloutDirective::FinishIndeterminate;
  }
  if !membership_exact {
    return match record.state {
      MutationState::Claimed | MutationState::Validating if !phase_timed_out => {
        RolloutDirective::AwaitMembership
      }
      MutationState::Claimed | MutationState::Validating => {
        RolloutDirective::FailBeforeApply("rollout_membership_unavailable")
      }
      MutationState::RollingBack if rollback_timed_out => RolloutDirective::FinishIndeterminate,
      _ => rollback_directive(targets),
    };
  }

  match record.state {
    MutationState::Claimed => RolloutDirective::Validate(members.to_vec()),
    MutationState::Validating => classify_validation(record, targets, phase_timed_out, members),
    MutationState::CanaryApplying => {
      let canary = deterministic_canary(&record.request_id, members);
      match target_state(targets, &canary) {
        Some(TargetState::Acked) => RolloutDirective::ObserveCanary,
        Some(TargetState::Nacked) | None => rollback_directive(targets),
        Some(_) if phase_timed_out => rollback_directive(targets),
        Some(TargetState::Validated | TargetState::ApplyAssigned | TargetState::Applying) => {
          RolloutDirective::ApplyCanary(canary)
        }
        Some(_) => rollback_directive(targets),
      }
    }
    MutationState::CanaryHealthy => {
      let canary = deterministic_canary(&record.request_id, members);
      if target_state(targets, &canary) != Some(TargetState::Acked) || phase_timed_out {
        rollback_directive(targets)
      } else if observation_complete {
        RolloutDirective::ApplyExpansion(apply_ready_targets(targets, Some(&canary)))
      } else {
        RolloutDirective::ObserveCanary
      }
    }
    MutationState::Expanding => {
      if targets
        .iter()
        .any(|target| target.state == TargetState::Nacked)
        || phase_timed_out
      {
        rollback_directive(targets)
      } else if targets
        .iter()
        .all(|target| target.state == TargetState::Acked)
      {
        RolloutDirective::Commit
      } else {
        RolloutDirective::ApplyExpansion(apply_ready_targets(targets, None))
      }
    }
    MutationState::FullyApplied => RolloutDirective::Commit,
    MutationState::RollingBack => classify_rollback(targets, rollback_timed_out),
    MutationState::Applying => RolloutDirective::FinishIndeterminate,
    MutationState::Committed
    | MutationState::Failed
    | MutationState::RolledBack
    | MutationState::RollbackFailed
    | MutationState::Indeterminate => RolloutDirective::Completed(record.state),
  }
}

fn classify_validation(
  record: &MutationRecord,
  targets: &[RolloutTarget],
  phase_timed_out: bool,
  members: &[String],
) -> RolloutDirective {
  if targets
    .iter()
    .any(|target| target.state == TargetState::Nacked)
  {
    RolloutDirective::FailBeforeApply("rollout_validation_failed")
  } else if phase_timed_out {
    RolloutDirective::FailBeforeApply("rollout_validation_timeout")
  } else if targets
    .iter()
    .all(|target| matches!(target.state, TargetState::Validated | TargetState::Applying))
  {
    let validation_matches = targets.iter().all(|target| {
      target.validation_revision.as_deref() == Some(record.new_revision.as_str())
        && target.validation_digest.is_some()
    });
    let validation_digest = targets
      .first()
      .and_then(|target| target.validation_digest.as_deref());
    let validation_converged = validation_matches
      && validation_digest.is_some()
      && targets
        .iter()
        .all(|target| target.validation_digest.as_deref() == validation_digest);
    if validation_converged {
      RolloutDirective::ApplyCanary(deterministic_canary(&record.request_id, members))
    } else {
      RolloutDirective::FailBeforeApply("rollout_validation_evidence_mismatch")
    }
  } else {
    let pending = targets
      .iter()
      .filter(|target| target.state == TargetState::Pending)
      .map(|target| target.instance_id.clone())
      .collect::<Vec<_>>();
    if pending.is_empty() {
      RolloutDirective::AwaitValidation
    } else {
      RolloutDirective::Validate(pending)
    }
  }
}

fn classify_rollback(targets: &[RolloutTarget], rollback_timed_out: bool) -> RolloutDirective {
  if targets
    .iter()
    .any(|target| target.state == TargetState::RollbackFailed)
  {
    RolloutDirective::FinishRollbackFailed
  } else if targets.iter().all(rollback_complete_for_target) {
    RolloutDirective::FinishRolledBack
  } else if rollback_timed_out {
    RolloutDirective::FinishIndeterminate
  } else {
    rollback_directive(targets)
  }
}

fn rollback_complete_for_target(target: &RolloutTarget) -> bool {
  target.state == TargetState::RolledBack
    || (target.effect_started_at.is_none()
      && matches!(
        target.state,
        TargetState::Pending
          | TargetState::Validating
          | TargetState::Validated
          | TargetState::ApplyAssigned
          | TargetState::Nacked
      ))
}

fn rollback_directive(targets: &[RolloutTarget]) -> RolloutDirective {
  RolloutDirective::RollBack(
    targets
      .iter()
      .filter(|target| {
        target.effect_started_at.is_some()
          || matches!(
            target.state,
            TargetState::Applying
              | TargetState::Acked
              | TargetState::RollbackAssigned
              | TargetState::RollingBack
          )
      })
      .map(|target| target.instance_id.clone())
      .collect(),
  )
}

fn apply_ready_targets(targets: &[RolloutTarget], exclude: Option<&str>) -> Vec<String> {
  targets
    .iter()
    .filter(|target| {
      matches!(
        target.state,
        TargetState::Validated | TargetState::ApplyAssigned | TargetState::Applying
      ) && exclude.is_none_or(|excluded| target.instance_id != excluded)
    })
    .map(|target| target.instance_id.clone())
    .collect()
}

fn target_state(targets: &[RolloutTarget], instance_id: &str) -> Option<TargetState> {
  targets
    .iter()
    .find(|target| target.instance_id == instance_id)
    .map(|target| target.state)
}
