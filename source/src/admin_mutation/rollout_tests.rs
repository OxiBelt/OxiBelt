use super::*;
use sqlx::postgres::PgPoolOptions;

fn target(instance_id: &str, state: TargetState) -> RolloutTarget {
  let validated = matches!(
    state,
    TargetState::Validated
      | TargetState::ApplyAssigned
      | TargetState::Applying
      | TargetState::Acked
  );
  RolloutTarget {
    instance_id: instance_id.to_string(),
    state,
    state_version: 0,
    assignment_epoch: 0,
    boot_id: None,
    instance_epoch: None,
    effect_started_at: None,
    validation_revision: validated.then(|| "r-2".to_string()),
    validation_digest: validated.then(|| "sha256:digest".to_string()),
    applied_revision: None,
    applied_digest: None,
    restored_revision: None,
    restored_digest: None,
    error_code: None,
    updated_at: String::new(),
  }
}

fn record(state: MutationState) -> MutationRecord {
  MutationRecord {
    request_id: "00000000-0000-4000-8000-000000000001".to_string(),
    fingerprint: "sha256:fingerprint".to_string(),
    principal: "controller".to_string(),
    signer_id: "signer".to_string(),
    action: "config.apply".to_string(),
    resource: "config".to_string(),
    expected_previous_revision: "r-1".to_string(),
    new_revision: "r-2".to_string(),
    content_digest: "sha256:digest".to_string(),
    cluster_id: Some("edge".to_string()),
    membership_revision: Some("sha256:members".to_string()),
    state,
    http_status: None,
    safe_response: None,
    error_code: None,
    audit_record_id: 1,
    terminal_audit_record_id: None,
    terminal_audit_confirmed: false,
    issued_at: String::new(),
    expires_at: String::new(),
    created_at: String::new(),
    updated_at: String::new(),
  }
}

fn members() -> Vec<String> {
  ["edge-a", "edge-b", "edge-c"]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn classify_states(state: MutationState, states: &[TargetState]) -> RolloutDirective {
  let members = members();
  let targets = members
    .iter()
    .zip(states)
    .map(|(member, state)| target(member, *state))
    .collect::<Vec<_>>();
  classify(
    &record(state),
    &targets,
    true,
    false,
    false,
    false,
    &members,
  )
}

#[test]
fn validation_all_precedes_deterministic_canary() {
  let validating = classify_states(
    MutationState::Validating,
    &[
      TargetState::Validating,
      TargetState::Applying,
      TargetState::Applying,
    ],
  );
  assert_eq!(validating, RolloutDirective::AwaitValidation);

  let ready = classify_states(
    MutationState::Validating,
    &[
      TargetState::Applying,
      TargetState::Applying,
      TargetState::Applying,
    ],
  );
  let RolloutDirective::ApplyCanary(canary) = ready else {
    panic!("validated rollout must select one canary");
  };
  assert_eq!(
    canary,
    deterministic_canary("00000000-0000-4000-8000-000000000001", &members())
  );
}

#[test]
fn member_secret_reference_digest_mismatch_fails_before_canary() {
  let members = members();
  let mut targets = members
    .iter()
    .map(|member| target(member, TargetState::Validated))
    .collect::<Vec<_>>();
  targets[1].validation_digest = Some(format!("sha256:{}", "a".repeat(64)));

  assert_eq!(
    classify(
      &record(MutationState::Validating),
      &targets,
      true,
      false,
      false,
      false,
      &members,
    ),
    RolloutDirective::FailBeforeApply("rollout_validation_evidence_mismatch")
  );
}

#[test]
fn canary_observation_precedes_expansion() {
  let members = members();
  let canary = deterministic_canary(&record(MutationState::CanaryHealthy).request_id, &members);
  let targets = members
    .iter()
    .map(|member| {
      target(
        member,
        if member == &canary {
          TargetState::Acked
        } else {
          TargetState::Applying
        },
      )
    })
    .collect::<Vec<_>>();
  let observing = classify(
    &record(MutationState::CanaryHealthy),
    &targets,
    true,
    false,
    false,
    false,
    &members,
  );
  assert_eq!(observing, RolloutDirective::ObserveCanary);
  let expanding = classify(
    &record(MutationState::CanaryHealthy),
    &targets,
    true,
    false,
    false,
    true,
    &members,
  );
  let RolloutDirective::ApplyExpansion(expansion) = expanding else {
    panic!("healthy canary must expand after observation");
  };
  assert_eq!(expansion.len(), 2);
  assert!(!expansion.contains(&canary));
}

#[test]
fn nack_and_timeout_fail_closed_into_rollback() {
  let nacked = classify_states(
    MutationState::Expanding,
    &[
      TargetState::Acked,
      TargetState::Nacked,
      TargetState::Applying,
    ],
  );
  assert!(matches!(nacked, RolloutDirective::RollBack(_)));

  let members = members();
  let targets = members
    .iter()
    .map(|member| target(member, TargetState::Applying))
    .collect::<Vec<_>>();
  let timed_out = classify(
    &record(MutationState::Expanding),
    &targets,
    true,
    true,
    false,
    false,
    &members,
  );
  assert!(matches!(timed_out, RolloutDirective::RollBack(_)));
}

#[test]
fn rollback_failure_and_timeout_remain_blocking() {
  let failed = classify_states(
    MutationState::RollingBack,
    &[
      TargetState::RolledBack,
      TargetState::RollbackFailed,
      TargetState::RollingBack,
    ],
  );
  assert_eq!(failed, RolloutDirective::FinishRollbackFailed);

  let members = members();
  let targets = members
    .iter()
    .map(|member| target(member, TargetState::RollingBack))
    .collect::<Vec<_>>();
  assert_eq!(
    classify(
      &record(MutationState::RollingBack),
      &targets,
      true,
      false,
      true,
      false,
      &members,
    ),
    RolloutDirective::FinishIndeterminate
  );
}

#[test]
fn canary_nack_before_effect_requires_no_member_rollback() {
  let members = members();
  let canary = deterministic_canary(&record(MutationState::CanaryApplying).request_id, &members);
  let targets = members
    .iter()
    .map(|member| {
      target(
        member,
        if member == &canary {
          TargetState::Nacked
        } else {
          TargetState::Validated
        },
      )
    })
    .collect::<Vec<_>>();
  let RolloutDirective::RollBack(rollback) = classify(
    &record(MutationState::CanaryApplying),
    &targets,
    true,
    false,
    false,
    false,
    &members,
  ) else {
    panic!("canary NACK must enter rollback");
  };
  assert!(rollback.is_empty());
}

#[test]
fn untouched_apply_assignment_is_complete_after_central_restore() {
  assert_eq!(
    classify(
      &record(MutationState::RollingBack),
      &[
        target("edge-a", TargetState::ApplyAssigned),
        target("edge-b", TargetState::Nacked),
        target("edge-c", TargetState::Validated),
      ],
      true,
      false,
      false,
      false,
      &members(),
    ),
    RolloutDirective::FinishRolledBack
  );
}

#[test]
fn partial_expansion_rollback_accepts_untouched_validated_members() {
  let mut untouched = target("edge-a", TargetState::Validated);
  let restored = target("edge-b", TargetState::RolledBack);
  let validation_nack = target("edge-c", TargetState::Nacked);
  assert_eq!(
    classify(
      &record(MutationState::RollingBack),
      &[untouched.clone(), restored, validation_nack],
      true,
      false,
      false,
      false,
      &members(),
    ),
    RolloutDirective::FinishRolledBack
  );
  untouched.effect_started_at = Some("now".to_string());
  assert!(matches!(
    classify(
      &record(MutationState::RollingBack),
      &[
        untouched,
        target("edge-b", TargetState::RolledBack),
        target("edge-c", TargetState::Nacked)
      ],
      true,
      false,
      false,
      false,
      &members(),
    ),
    RolloutDirective::RollBack(_)
  ));
}

#[test]
fn membership_loss_before_apply_waits_then_fails_without_rollback() {
  let members = members();
  let targets = members
    .iter()
    .map(|member| target(member, TargetState::Validating))
    .collect::<Vec<_>>();
  assert_eq!(
    classify(
      &record(MutationState::Validating),
      &targets,
      false,
      false,
      false,
      false,
      &members,
    ),
    RolloutDirective::AwaitMembership
  );
  assert_eq!(
    classify(
      &record(MutationState::Validating),
      &targets,
      false,
      true,
      false,
      false,
      &members,
    ),
    RolloutDirective::FailBeforeApply("rollout_membership_unavailable")
  );
}

#[tokio::test]
async fn controller_identity_getters_expose_the_validated_local_boot() {
  let pool = PgPoolOptions::new()
    .connect_lazy("postgres://localhost/oxibelt-test")
    .expect("lazy rollout test pool");
  let store = MutationStore::new(pool, "test".to_string()).expect("rollout test store");
  let controller = AdminClusterRolloutController::new(
    store,
    RolloutSettings {
      cluster_id: "edge-cluster".to_string(),
      membership_revision: "sha256:members".to_string(),
      members: vec!["edge-b".to_string(), "edge-a".to_string()],
      instance_id: "edge-a".to_string(),
      boot_id: "boot-a".to_string(),
      build_version: "test".to_string(),
      artifact_key_fingerprint: "sha256:test-key".to_string(),
      heartbeat_interval: Duration::from_secs(5),
      stale_after: Duration::from_secs(15),
      phase_timeout: Duration::from_secs(60),
      rollback_timeout: Duration::from_secs(60),
      canary_observation: Duration::from_secs(10),
    },
    LocalRolloutStatus {
      assigned_revision: None,
      applied_revision: "r-1".to_string(),
      applied_digest: "sha256:old".to_string(),
      ready: true,
    },
  )
  .expect("rollout controller");
  assert_eq!(controller.instance_id(), "edge-a");
  assert_eq!(controller.boot_id(), "boot-a");
  assert_eq!(controller.cluster_id(), "edge-cluster");
  assert_eq!(controller.membership_revision(), "sha256:members");
  assert!(!controller.ready());
}
