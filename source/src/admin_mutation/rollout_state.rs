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

#[cfg(feature = "fuzzing")]
pub(super) fn fuzz_classify(data: &[u8]) {
  const MAX_MEMBERS: usize = 16;
  let byte = |index: usize| data.get(index).copied().unwrap_or_default();
  let state = match byte(0) % 13 {
    0 => MutationState::Claimed,
    1 => MutationState::Validating,
    2 => MutationState::Applying,
    3 => MutationState::CanaryApplying,
    4 => MutationState::CanaryHealthy,
    5 => MutationState::Expanding,
    6 => MutationState::FullyApplied,
    7 => MutationState::Committed,
    8 => MutationState::Failed,
    9 => MutationState::RollingBack,
    10 => MutationState::RolledBack,
    11 => MutationState::RollbackFailed,
    _ => MutationState::Indeterminate,
  };
  let record = MutationRecord {
    request_id: format!("fuzz-{:02x}", byte(1)),
    fingerprint: "fuzz-fingerprint".to_string(),
    principal: "fuzz-principal".to_string(),
    signer_id: "fuzz-signer".to_string(),
    action: "fuzz:Apply".to_string(),
    resource: "config/fuzz".to_string(),
    expected_previous_revision: "revision-old".to_string(),
    new_revision: "revision-new".to_string(),
    content_digest: "sha256:fuzz".to_string(),
    cluster_id: Some("fuzz-cluster".to_string()),
    membership_revision: Some("fuzz-membership".to_string()),
    state,
    http_status: None,
    safe_response: None,
    error_code: None,
    audit_record_id: 1,
    terminal_audit_record_id: None,
    terminal_audit_confirmed: false,
    issued_at: "2026-01-01T00:00:00Z".to_string(),
    expires_at: "2026-01-01T00:05:00Z".to_string(),
    created_at: "2026-01-01T00:00:00Z".to_string(),
    updated_at: "2026-01-01T00:00:00Z".to_string(),
  };
  let count = usize::from(byte(2) % MAX_MEMBERS as u8).saturating_add(1);
  let members = (0..count)
    .map(|index| format!("member-{index:02}"))
    .collect::<Vec<_>>();
  let targets = members
    .iter()
    .enumerate()
    .map(|(index, member)| RolloutTarget {
      instance_id: member.clone(),
      state: match byte(index.saturating_add(3)) % 11 {
        0 => TargetState::Pending,
        1 => TargetState::Validating,
        2 => TargetState::Validated,
        3 => TargetState::ApplyAssigned,
        4 => TargetState::Applying,
        5 => TargetState::Acked,
        6 => TargetState::Nacked,
        7 => TargetState::RollbackAssigned,
        8 => TargetState::RollingBack,
        9 => TargetState::RolledBack,
        _ => TargetState::RollbackFailed,
      },
      state_version: i64::from(byte(index.saturating_add(19))),
      assignment_epoch: i64::from(byte(index.saturating_add(35))),
      boot_id: None,
      instance_epoch: None,
      effect_started_at: (byte(index.saturating_add(51)) & 1 == 1)
        .then(|| "2026-01-01T00:00:01Z".to_string()),
      validation_revision: Some("revision-new".to_string()),
      validation_digest: Some("sha256:validation".to_string()),
      applied_revision: None,
      applied_digest: None,
      restored_revision: None,
      restored_digest: None,
      error_code: None,
      updated_at: "2026-01-01T00:00:01Z".to_string(),
    })
    .collect::<Vec<_>>();
  let arguments = (
    byte(67) & 1 == 1,
    byte(68) & 1 == 1,
    byte(69) & 1 == 1,
    byte(70) & 1 == 1,
  );
  let first = classify(
    &record,
    &targets,
    arguments.0,
    arguments.1,
    arguments.2,
    arguments.3,
    &members,
  );
  let second = classify(
    &record,
    &targets,
    arguments.0,
    arguments.1,
    arguments.2,
    arguments.3,
    &members,
  );
  assert_eq!(
    first, second,
    "rollout classification was not deterministic"
  );
}
