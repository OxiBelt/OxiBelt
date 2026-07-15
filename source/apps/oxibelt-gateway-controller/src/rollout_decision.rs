//! Pure immutable-rollout decisions, kept separate from Kubernetes API I/O so
//! partial convergence and recovery transitions can be exercised deterministically.

use super::rollout::{ConfigArtifact, RolloutPhase, RolloutState, WorkloadConvergence};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum ObservationDecision {
  Reject(&'static str),
  Converged,
  ConvergenceLost,
  Advance(RolloutPhase),
  Wait,
}

pub(super) fn decide_observation(
  state: &RolloutState,
  convergence: &WorkloadConvergence,
  rejected_reason: Option<&'static str>,
  timed_out: bool,
) -> ObservationDecision {
  if let Some(reason) = rejected_reason {
    return ObservationDecision::Reject(reason);
  }
  if convergence.all_replicas_converged() {
    return ObservationDecision::Converged;
  }
  if state.phase == RolloutPhase::Committed {
    return ObservationDecision::ConvergenceLost;
  }
  if timed_out {
    return ObservationDecision::Reject("RolloutTimeout");
  }
  match state.phase {
    RolloutPhase::CanaryApplying if convergence.pods.desired_ready > 0 => {
      ObservationDecision::Advance(RolloutPhase::CanaryHealthy)
    }
    RolloutPhase::CanaryHealthy => ObservationDecision::Advance(RolloutPhase::Expanding),
    _ => ObservationDecision::Wait,
  }
}

pub(super) fn mark_failed_attempt(mut state: RolloutState, active_revision: &str) -> RolloutState {
  state.failed_revision = Some(active_revision.to_string());
  state
}

pub(super) fn requires_rollback(state: &RolloutState, active_revision: &str) -> bool {
  state
    .committed_revision
    .as_deref()
    .is_some_and(|revision| revision != active_revision)
}

pub(super) fn prepare_rollback_state(
  mut failed: RolloutState,
  rollback: &ConfigArtifact,
  reason: &str,
) -> RolloutState {
  failed.phase = RolloutPhase::RollbackRequested;
  failed.desired_revision = Some(rollback.name.clone());
  failed.desired_artifact_digest = Some(rollback.artifact_digest.clone());
  failed.desired_content_digest = Some(rollback.content_digest.clone());
  failed.failure = Some(reason.to_string());
  failed
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use super::*;
  use crate::rollout::{PodConvergence, RolloutTarget, WorkloadKind};

  fn target() -> RolloutTarget {
    RolloutTarget {
      namespace: "default".to_string(),
      kind: WorkloadKind::Deployment,
      name: "edge".to_string(),
      container_name: "oxibelt".to_string(),
      volume_name: "gateway-config".to_string(),
      timeout: Duration::from_secs(300),
      config_map_prefix: "oxibelt-gateway-config".to_string(),
    }
  }

  fn artifact(revision: &str, body: &str) -> ConfigArtifact {
    let mut artifact = ConfigArtifact::new(
      &target(),
      "conf.d/gateway-api.generated.toml",
      format!("# {body}\n[[routes]]\n"),
    )
    .expect("test artifact");
    artifact.name = revision.to_string();
    artifact
  }

  fn convergence(desired_ready: usize, stale_ready: usize, complete: bool) -> WorkloadConvergence {
    WorkloadConvergence {
      observed_generation: complete,
      expected_replicas: 3,
      updated_replicas: if complete { 3 } else { desired_ready as u32 },
      ready_replicas: (desired_ready + stale_ready) as u32,
      available_replicas: (desired_ready + stale_ready) as u32,
      pods: PodConvergence {
        selected: desired_ready + stale_ready,
        ready: desired_ready + stale_ready,
        desired_ready,
        stale_ready,
      },
    }
  }

  fn committed_a() -> RolloutState {
    RolloutState {
      phase: RolloutPhase::Committed,
      desired_revision: Some("a".to_string()),
      desired_artifact_digest: Some("artifact-a".to_string()),
      desired_content_digest: Some("content-a".to_string()),
      committed_revision: Some("a".to_string()),
      committed_content_digest: Some("content-a".to_string()),
      failed_revision: None,
      started_at_unix: Some(1),
      failure: None,
    }
  }

  fn failed_candidate_rolls_back_to_a(reason: &'static str) -> RolloutState {
    let candidate_b = artifact("b", "candidate-b");
    let mut state = RolloutState::new_attempt(&candidate_b, &committed_a(), 10);
    assert_eq!(
      decide_observation(&state, &convergence(1, 2, false), None, false),
      ObservationDecision::Advance(RolloutPhase::CanaryHealthy)
    );
    state.phase = RolloutPhase::CanaryHealthy;
    assert_eq!(
      decide_observation(&state, &convergence(1, 2, false), None, false),
      ObservationDecision::Advance(RolloutPhase::Expanding)
    );
    state.phase = RolloutPhase::Expanding;
    assert_eq!(
      decide_observation(
        &state,
        &convergence(1, 2, false),
        (reason == "PodRejected").then_some(reason),
        reason == "RolloutTimeout",
      ),
      ObservationDecision::Reject(reason)
    );

    let failed = mark_failed_attempt(state, "b");
    assert!(requires_rollback(&failed, "b"));
    let rollback = prepare_rollback_state(failed, &artifact("a", "committed-a"), reason);
    assert_eq!(rollback.phase, RolloutPhase::RollbackRequested);
    assert_eq!(rollback.desired_revision.as_deref(), Some("a"));
    assert_eq!(rollback.committed_revision.as_deref(), Some("a"));
    assert_eq!(rollback.failed_revision.as_deref(), Some("b"));
    rollback
  }

  #[test]
  fn partial_candidate_rejection_rolls_back_and_blocks_only_unchanged_candidate() {
    let mut state = failed_candidate_rolls_back_to_a("PodRejected");
    assert_eq!(
      decide_observation(&state, &convergence(3, 0, true), None, false),
      ObservationDecision::Converged
    );
    state.phase = super::super::rollout_client::convergence_transition(state.phase, true);
    assert_eq!(state.phase, RolloutPhase::RolledBack);
    // The next reconciliation records the failed candidate after the previous
    // committed revision has converged again.
    state.phase = RolloutPhase::Failed;

    assert!(super::super::rollout_client::candidate_is_blocked_after_failure(&state, "b"));
    assert!(!super::super::rollout_client::candidate_is_blocked_after_failure(&state, "c"));

    let candidate_c = artifact("c", "candidate-c");
    let next = RolloutState::new_attempt(&candidate_c, &state, 20);
    assert_eq!(next.phase, RolloutPhase::CanaryApplying);
    assert_eq!(next.desired_revision.as_deref(), Some("c"));
    assert_eq!(next.committed_revision.as_deref(), Some("a"));
    assert_eq!(next.failed_revision, None);
  }

  #[test]
  fn partial_candidate_timeout_uses_the_same_recovery_path() {
    let state = failed_candidate_rolls_back_to_a("RolloutTimeout");
    assert_eq!(state.failure.as_deref(), Some("RolloutTimeout"));
  }
}
