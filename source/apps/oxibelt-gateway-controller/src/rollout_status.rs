use super::leader_election::LeadershipTerm;
use super::rollout::{RolloutPhase, RolloutState};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CommitProof {
  pub revision: String,
  pub content_digest: String,
  pub workload_uid: String,
  pub workload_generation: i64,
  pub workload_resource_version: String,
  pub owner_chain_digest: String,
  pub source_snapshot_digest: String,
  pub leadership: LeadershipTerm,
}

impl CommitProof {
  pub fn message(&self) -> String {
    format!(
      "Committed revision {} with content digest {} is proven for workload uid {}, generation {}, resourceVersion {}, owner chain {}, source snapshot {}, Lease uid {}, epoch {}, holder {}",
      self.revision,
      self.content_digest,
      self.workload_uid,
      self.workload_generation,
      self.workload_resource_version,
      self.owner_chain_digest,
      self.source_snapshot_digest,
      self.leadership.lease_uid,
      self.leadership.leader_epoch,
      self.leadership.holder_identity,
    )
  }

  #[cfg(test)]
  pub fn test() -> Self {
    Self {
      revision: "revision".to_string(),
      content_digest: "digest".to_string(),
      workload_uid: "workload-uid".to_string(),
      workload_generation: 1,
      workload_resource_version: "7".to_string(),
      owner_chain_digest: "owners".to_string(),
      source_snapshot_digest: "sources".to_string(),
      leadership: LeadershipTerm {
        lease_uid: "lease-uid".to_string(),
        leader_epoch: 1,
        holder_identity: "pod-a".to_string(),
      },
    }
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RolloutStatus {
  pub phase: RolloutPhase,
  pub desired_revision: Option<String>,
  pub desired_content_digest: Option<String>,
  pub reason: Option<String>,
  pub proof: Option<CommitProof>,
}

impl RolloutStatus {
  pub fn pending(reason: impl Into<String>) -> Self {
    Self {
      phase: RolloutPhase::Generated,
      desired_revision: None,
      desired_content_digest: None,
      reason: Some(reason.into()),
      proof: None,
    }
  }

  pub fn failed(reason: impl Into<String>) -> Self {
    Self {
      phase: RolloutPhase::Failed,
      desired_revision: None,
      desired_content_digest: None,
      reason: Some(reason.into()),
      proof: None,
    }
  }

  pub fn is_committed(&self) -> bool {
    self.phase.is_committed() && self.proof.is_some()
  }

  pub fn programmed(&self, accepted: bool) -> ProgrammedCondition {
    if !accepted {
      return ProgrammedCondition {
        programmed: false,
        reason: "Pending",
        message: "Resource is not accepted by OxiBelt".to_string(),
      };
    }
    if self.is_committed() {
      return ProgrammedCondition {
        programmed: true,
        reason: "Programmed",
        message: self
          .proof
          .as_ref()
          .expect("committed proof checked")
          .message(),
      };
    }
    if self.reason.as_deref() == Some("ConvergenceLost") {
      return ProgrammedCondition {
        programmed: false,
        reason: "ConvergenceLost",
        message: "A Ready replica no longer proves the desired immutable OxiBelt configuration"
          .to_string(),
      };
    }
    match self.phase {
      RolloutPhase::Failed => ProgrammedCondition {
        programmed: false,
        reason: "RolloutFailed",
        message: "Desired OxiBelt configuration failed immutable rollout validation or convergence".to_string(),
      },
      RolloutPhase::RollbackRequested => ProgrammedCondition {
        programmed: false,
        reason: "RollbackInProgress",
        message: "Desired OxiBelt configuration is not committed while the previous revision is restored".to_string(),
      },
      RolloutPhase::RolledBack => ProgrammedCondition {
        programmed: false,
        reason: "RollbackComplete",
        message: "Desired OxiBelt configuration was rolled back and remains blocked until its revision changes".to_string(),
      },
      _ => ProgrammedCondition {
        programmed: false,
        reason: "Pending",
        message: "Desired OxiBelt configuration is waiting for immutable workload convergence".to_string(),
      },
    }
  }
}

impl From<&RolloutState> for RolloutStatus {
  fn from(state: &RolloutState) -> Self {
    Self {
      phase: state.phase,
      desired_revision: state.desired_revision.clone(),
      desired_content_digest: state.desired_content_digest.clone(),
      reason: state.failure.clone(),
      proof: None,
    }
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProgrammedCondition {
  pub programmed: bool,
  pub reason: &'static str,
  pub message: String,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn accepted_resources_wait_for_a_committed_rollout() {
    let pending = RolloutStatus::pending("WaitingForTarget");
    assert!(!pending.programmed(true).programmed);
    let committed = RolloutStatus {
      phase: RolloutPhase::Committed,
      desired_revision: Some("revision".to_string()),
      desired_content_digest: Some("digest".to_string()),
      reason: None,
      proof: Some(CommitProof::test()),
    };
    assert!(committed.programmed(true).programmed);
  }

  #[test]
  fn lost_convergence_keeps_accepted_resources_unprogrammed() {
    let lost = RolloutStatus {
      phase: RolloutPhase::Generated,
      desired_revision: Some("revision".to_string()),
      desired_content_digest: Some("digest".to_string()),
      reason: Some("ConvergenceLost".to_string()),
      proof: None,
    };
    let condition = lost.programmed(true);
    assert!(!condition.programmed);
    assert_eq!(condition.reason, "ConvergenceLost");
  }
}
