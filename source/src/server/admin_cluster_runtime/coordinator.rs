use anyhow::Context;
use tokio::sync::watch;
use tokio::time::{MissedTickBehavior, interval};
use tracing::warn;

use crate::admin_audit::AdminAuditRuntime;
use crate::admin_mutation::{
  AdminMutationRuntime, MutationRecord, MutationState, RolloutDirective, RolloutTarget,
  RolloutTransitionPlan, SharedPublicationState, TargetPlan, TargetState, load_shared_publication,
};

use crate::server::admin_cluster_executor::{AdminClusterExecutor, RuntimeSharedPublisher};

use super::WORK_INTERVAL;

pub(super) async fn coordinator_loop(
  runtime: AdminMutationRuntime,
  executor: AdminClusterExecutor,
  publisher: RuntimeSharedPublisher,
  audit: AdminAuditRuntime,
  phase_timeout: i32,
  rollback_timeout: i32,
  mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
  runtime.set_cluster_worker_running(false, true);
  let result = run(
    &runtime,
    &executor,
    &publisher,
    &audit,
    phase_timeout,
    rollback_timeout,
    &mut shutdown,
  )
  .await;
  runtime.set_cluster_worker_running(false, false);
  result
}

async fn run(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  audit: &AdminAuditRuntime,
  phase_timeout: i32,
  rollback_timeout: i32,
  shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
  let mut ticker = interval(WORK_INTERVAL);
  ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_err() || *shutdown.borrow() { return Ok(()); }
      }
      _ = ticker.tick() => {
        for recovery in runtime.cluster_recoverable_mutations().await? {
          if let Err(error) = reconcile(runtime, executor, publisher, audit, &recovery.request_id, phase_timeout, rollback_timeout).await {
            warn!(error = %error, request_id = %recovery.request_id, "Admin cluster coordinator reconciliation failed");
          }
        }
      }
    }
  }
}

async fn reconcile(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  audit: &AdminAuditRuntime,
  request_id: &str,
  phase_timeout: i32,
  rollback_timeout: i32,
) -> anyhow::Result<()> {
  let record = runtime
    .load_mutation(request_id)
    .await?
    .context("cluster mutation disappeared")?;
  let targets = runtime.cluster_targets(request_id).await?;
  let mut directive = runtime.cluster_rollout_directive(&record, &targets).await?;
  let command = runtime.fetch_cluster_command(&record).await?;
  let operation = executor
    .validate(&command)
    .await
    .map_err(anyhow::Error::new)?;
  let winner_response_forward =
    operation.is_token_producing_shared() && is_forward_directive(&directive);
  let Some(fence) = runtime
    .cluster_acquire_coordinator(&record, winner_response_forward)
    .await?
  else {
    return Ok(());
  };
  if winner_response_forward && !runtime.shared_winner_response_registered(&record.request_id) {
    directive = abandoned_winner_response_directive(runtime, &record, &targets).await?;
  }
  if operation.is_shared_staged() {
    match &directive {
      RolloutDirective::ApplyCanary(_) if record.state == MutationState::CanaryApplying => {
        executor
          .publish_shared(&operation, &fence, publisher)
          .await
          .map_err(anyhow::Error::new)?;
      }
      RolloutDirective::RollBack(_) => {
        if let Some(publication) =
          load_shared_publication(runtime.store()?, &record.request_id).await?
        {
          anyhow::ensure!(
            publication.candidate_revision == record.new_revision
              && publication.candidate_digest == record.content_digest,
            "shared rollback publication conflicts with its durable mutation"
          );
          match publication.state {
            SharedPublicationState::Applied => {
              executor
                .rollback_shared(&operation, &fence, publisher)
                .await
                .map_err(anyhow::Error::new)?;
            }
            SharedPublicationState::Restored => {}
            SharedPublicationState::Applying | SharedPublicationState::Indeterminate => {
              anyhow::bail!("shared publication outcome is not safely restorable")
            }
          }
        }
      }
      _ => {}
    }
  }
  if let Some(plan) = transition_plan(
    &record,
    &targets,
    &directive,
    phase_timeout,
    rollback_timeout,
  ) {
    runtime.cluster_apply_transition_plan(&fence, &plan).await?;
    return Ok(());
  }
  let terminal = match directive {
    RolloutDirective::Commit => Some((MutationState::Committed, None)),
    RolloutDirective::FailBeforeApply(code) => {
      Some((MutationState::Failed, Some(code.to_string())))
    }
    RolloutDirective::FinishRolledBack => Some((
      MutationState::RolledBack,
      Some("rollout_rolled_back".to_string()),
    )),
    RolloutDirective::FinishRollbackFailed => Some((
      MutationState::RollbackFailed,
      Some("rollback_failed".to_string()),
    )),
    RolloutDirective::FinishIndeterminate => Some((
      MutationState::Indeterminate,
      Some("rollout_indeterminate".to_string()),
    )),
    _ => None,
  };
  if let Some((state, error)) = terminal {
    runtime
      .finish_cluster_rollout(&fence, state, error, audit)
      .await?;
  }
  Ok(())
}

fn is_forward_directive(directive: &RolloutDirective) -> bool {
  matches!(
    directive,
    RolloutDirective::AwaitMembership
      | RolloutDirective::Validate(_)
      | RolloutDirective::AwaitValidation
      | RolloutDirective::ApplyCanary(_)
      | RolloutDirective::ObserveCanary
      | RolloutDirective::ApplyExpansion(_)
      | RolloutDirective::Commit
  )
}

async fn abandoned_winner_response_directive(
  runtime: &AdminMutationRuntime,
  record: &MutationRecord,
  targets: &[RolloutTarget],
) -> anyhow::Result<RolloutDirective> {
  let publication = load_shared_publication(runtime.store()?, &record.request_id).await?;
  Ok(abandoned_winner_response_directive_for_state(
    publication.map(|value| value.state),
    targets,
  ))
}

fn abandoned_winner_response_directive_for_state(
  publication_state: Option<SharedPublicationState>,
  targets: &[RolloutTarget],
) -> RolloutDirective {
  if publication_state == Some(SharedPublicationState::Indeterminate) {
    return RolloutDirective::FinishIndeterminate;
  }
  let effect_is_durable = publication_state.is_some_and(|value| {
    matches!(
      value,
      SharedPublicationState::Applied | SharedPublicationState::Restored
    )
  });
  let affected = targets
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
    .collect::<Vec<_>>();
  if effect_is_durable || !affected.is_empty() {
    RolloutDirective::RollBack(affected)
  } else {
    RolloutDirective::FailBeforeApply("winner_response_owner_lost")
  }
}

fn transition_plan(
  record: &MutationRecord,
  targets: &[RolloutTarget],
  directive: &RolloutDirective,
  phase_timeout: i32,
  rollback_timeout: i32,
) -> Option<RolloutTransitionPlan> {
  let (next_state, canary, assignments): (
    Option<MutationState>,
    Option<String>,
    Vec<(String, TargetState)>,
  ) = match directive {
    RolloutDirective::Validate(members) => (
      (record.state == MutationState::Claimed).then_some(MutationState::Validating),
      None,
      assignments(members, TargetState::Validating),
    ),
    RolloutDirective::ApplyCanary(member) if record.state == MutationState::Validating => (
      Some(MutationState::CanaryApplying),
      Some(member.clone()),
      vec![(member.clone(), TargetState::ApplyAssigned)],
    ),
    RolloutDirective::ApplyCanary(member) => (
      None,
      Some(member.clone()),
      vec![(member.clone(), TargetState::ApplyAssigned)],
    ),
    RolloutDirective::ObserveCanary if record.state == MutationState::CanaryApplying => {
      (Some(MutationState::CanaryHealthy), None, Vec::new())
    }
    RolloutDirective::ApplyExpansion(members) if record.state == MutationState::CanaryHealthy => (
      Some(MutationState::Expanding),
      None,
      assignments(members, TargetState::ApplyAssigned),
    ),
    RolloutDirective::ApplyExpansion(members) => {
      (None, None, assignments(members, TargetState::ApplyAssigned))
    }
    RolloutDirective::Commit if record.state == MutationState::Expanding => {
      (Some(MutationState::FullyApplied), None, Vec::new())
    }
    RolloutDirective::RollBack(members) => (
      (record.state != MutationState::RollingBack).then_some(MutationState::RollingBack),
      None,
      assignments(members, TargetState::RollbackAssigned),
    ),
    _ => return None,
  };
  let targets = assignments
    .into_iter()
    .filter_map(|(instance_id, next_state)| {
      let target = targets
        .iter()
        .find(|value| value.instance_id == instance_id)?;
      target
        .state
        .may_transition_to(next_state)
        .then(|| TargetPlan {
          instance_id,
          expected_state: target.state,
          expected_state_version: target.state_version,
          next_state,
        })
    })
    .collect();
  Some(RolloutTransitionPlan {
    expected_state: record.state,
    next_state,
    canary_instance_id: canary,
    phase_timeout_seconds: phase_timeout,
    rollback_timeout_seconds: rollback_timeout,
    targets,
  })
}

fn assignments(members: &[String], state: TargetState) -> Vec<(String, TargetState)> {
  members
    .iter()
    .cloned()
    .map(|member| (member, state))
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn winner_response_forward_progress_stays_on_the_admission_origin() {
    for directive in [
      RolloutDirective::AwaitMembership,
      RolloutDirective::Validate(vec!["edge-a".to_string()]),
      RolloutDirective::AwaitValidation,
      RolloutDirective::ApplyCanary("edge-a".to_string()),
      RolloutDirective::ObserveCanary,
      RolloutDirective::ApplyExpansion(vec!["edge-b".to_string()]),
      RolloutDirective::Commit,
    ] {
      assert!(is_forward_directive(&directive), "{directive:?}");
    }
    assert!(!is_forward_directive(&RolloutDirective::RollBack(vec![])));
  }

  #[test]
  fn abandoned_winner_response_fails_before_any_effect() {
    assert!(matches!(
      abandoned_winner_response_directive_for_state(None, &[target(TargetState::Validated, false)]),
      RolloutDirective::FailBeforeApply("winner_response_owner_lost")
    ));
  }

  #[test]
  fn abandoned_winner_response_rolls_back_durable_or_started_effects() {
    assert!(matches!(
      abandoned_winner_response_directive_for_state(
        Some(SharedPublicationState::Applied),
        &[target(TargetState::ApplyAssigned, false)],
      ),
      RolloutDirective::RollBack(members) if members.is_empty()
    ));
    assert!(matches!(
      abandoned_winner_response_directive_for_state(
        None,
        &[target(TargetState::Applying, true)],
      ),
      RolloutDirective::RollBack(members) if members == vec!["edge-a".to_string()]
    ));
  }

  fn target(state: TargetState, effect_started: bool) -> RolloutTarget {
    RolloutTarget {
      instance_id: "edge-a".to_string(),
      state,
      state_version: 1,
      assignment_epoch: 1,
      boot_id: Some("boot-a".to_string()),
      instance_epoch: Some(1),
      effect_started_at: effect_started.then(|| "2026-07-18T00:00:00Z".to_string()),
      applied_revision: None,
      applied_digest: None,
      restored_revision: None,
      restored_digest: None,
      error_code: None,
      updated_at: "2026-07-18T00:00:00Z".to_string(),
    }
  }
}
